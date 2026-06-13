"""Native-TLS fallback transport (stdlib http.client over system OpenSSL).

Some WAFs fingerprint the TLS stack itself. Imperva/Incapsula in
particular challenges BoringSSL-based clients (which is what wreq, and
therefore every Chrome/Safari/Edge emulation, is) and gives a free pass
to generic OpenSSL clients that arrive *without* ``Sec-Fetch-*`` headers
— i.e. things that look like a plain HTTP/API client rather than a
browser impersonator. A real browser passes by running the WAF's JS
sensor (reese84) to earn a token; a curl/urllib client is simply not held
to that standard.

wreq cannot produce an OpenSSL fingerprint, so wafer reaches for Python's
stdlib over system OpenSSL (same as curl) when it detects a site doing
this. We drive ``http.client`` directly rather than ``urllib.request``
because urllib leaves an unmistakable fingerprint on the wire: it emits
``Accept-Encoding: identity`` and ``Content-Length`` *before* ``Host``
(real clients send ``Host`` first) plus ``Connection: close``. Imperva
flags that the moment a request looks non-trivial (notably POSTs). Driving
http.client lets us send a curl-identical request: ``Host`` first, the
exact minimal header set in order, no urllib tells.

This is a last-resort fallback, wired in only when a challenge that wafer
would otherwise have to browser-solve is detected (see ``_async``/``_sync``
Imperva handling). It is not a general request path. A per-session cookie
jar persists WAF cookies across a multi-call flow.
"""

import gzip
import http.client
import io
import logging
import socket
import ssl
import zlib
from http.cookiejar import Cookie, CookieJar
from urllib.parse import urljoin, urlparse
from urllib.request import Request as _CookieRequest

logger = logging.getLogger("wafer")

# Max times the sticky path retries a pinned host's native request when it
# hits a transient (rate-based) Imperva challenge before giving up. Backs off
# between tries; OpenSSL is the only path that works for a pinned host, so
# retrying native beats reverting to wreq (which is always challenged).
NATIVE_MAX_RETRIES = 3

# Header name prefixes that betray a Chromium browser context.
_BROWSER_ONLY_PREFIXES = ("sec-fetch-", "sec-ch-ua")

# Exact header names to strip. Beyond the obvious navigation-only ones, this
# drops Accept-Language and Accept-Encoding: live testing on api2.realtor.ca
# showed that under WAF rate pressure Imperva challenges an OpenSSL client
# the moment it sends those browser-typical headers, while waving through the
# bare "API client" shape (curl's default: UA + Origin + Referer + Accept).
# So we present exactly that minimal set. Omitting Accept-Encoding also means
# the server replies uncompressed, so no br/zstd we couldn't decode.
_NAV_ONLY_HEADERS = (
    "upgrade-insecure-requests",
    "cache-control",
    "priority",
    "accept-language",
    "accept-encoding",
    # Stripped because we set these ourselves, in order, on the wire.
    "host",
    "content-length",
    "connection",
    "cookie",
)

_REDIRECT_CODES = (301, 302, 303, 307, 308)


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Reduce a header set to the minimal generic-HTTP-client shape.

    Strips browser-fingerprint headers (Sec-Fetch-*, Sec-Ch-Ua) and the
    browser-typical Accept-Language / Accept-Encoding / navigation headers,
    leaving the bare set (UA, Origin, Referer, Accept) that Imperva treats
    as a low-risk API client even under rate pressure. Connection-managed
    headers (Host, Content-Length, Connection, Cookie) are dropped too -
    the transport sets them itself, in the right order.
    """
    out: dict[str, str] = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl.startswith(_BROWSER_ONLY_PREFIXES):
            continue
        if kl in _NAV_ONLY_HEADERS:
            continue
        out[k] = v
    return out


def _decompress(
    raw: bytes, encoding: str, url: str = "", max_size: int | None = None
) -> bytes:
    """Decode gzip/deflate response bodies; return raw on any failure.

    When ``max_size`` is set, the *decompressed* output is bounded: at most
    ``max_size + 1`` bytes are produced, and if the decompressor yields more
    (a compression bomb that would expand a tiny body past the cap) a
    ``ResponseTooLarge`` is raised instead of buffering the full expansion.
    ``max_size is None`` leaves the output byte-identical to before.
    """
    enc = encoding.lower()
    if enc in ("gzip", "x-gzip"):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
                if max_size is None:
                    return gz.read()
                # Read at most cap+1 bytes: if the decompressor produced
                # more than that, the body is over the cap (bomb-safe -
                # the full expansion is never buffered).
                out = gz.read(max_size + 1)
                if len(out) > max_size:
                    from wafer._errors import ResponseTooLarge

                    raise ResponseTooLarge(url, len(out), max_size)
                return out
        except (gzip.BadGzipFile, EOFError, OSError):
            return raw
    if enc == "deflate":
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                if max_size is None:
                    return zlib.decompress(raw, wbits)
                # Incremental inflate with a max-length cap: decompressobj
                # lets us stop after cap+1 bytes regardless of input size.
                dec = zlib.decompressobj(wbits)
                out = dec.decompress(raw, max_size + 1)
                # Over the cap if the output already exceeds it, or if zlib
                # stopped at the cap+1 limit with input still pending
                # (unconsumed_tail) -> a larger body was being produced.
                if len(out) > max_size or dec.unconsumed_tail:
                    from wafer._errors import ResponseTooLarge

                    raise ResponseTooLarge(url, len(out), max_size)
                return out
            except zlib.error:
                continue
        return raw
    return raw


class NativeTLSTransport:
    """Blocking http.client transport over system OpenSSL with a cookie jar.

    One instance per session (created lazily). The cookie jar persists
    across requests so WAF cookies earned on the first call are replayed
    on subsequent ones. ``http.cookiejar.CookieJar`` is internally locked,
    so concurrent use from a thread pool (AsyncSession) is safe.
    """

    def __init__(
        self,
        follow_redirects: bool = True,
        proxy_url: str | None = None,
        max_redirects: int = 10,
    ):
        self._ctx = ssl.create_default_context()
        self._jar = CookieJar()
        self._follow_redirects = follow_redirects
        self._proxy_url = proxy_url
        # Hop budget for the native redirect chain. Aligned with the session
        # ``max_redirects`` so the bypass and the wreq path agree.
        self._max_redirects = max_redirects

    def add_cookies(self, cookies: list[dict]) -> None:
        """Seed the jar from Playwright-style cookie dicts.

        Lets a browser-earned WAF token (e.g. Imperva ``reese84``) replay on
        the OpenSSL path: the browser solves the challenge on the site's
        origin page, and these cookies carry the proof to the API host over
        native TLS. Each dict has ``name``/``value``/``domain`` (Playwright's
        ``BrowserContext.cookies()`` shape); ``path``/``secure``/``expires``
        are honoured when present.
        """
        for c in cookies:
            name = c.get("name")
            if not name:
                continue
            domain = c.get("domain", "") or ""
            expires = c.get("expires", -1)
            self._jar.set_cookie(
                Cookie(
                    version=0,
                    name=name,
                    value=c.get("value", ""),
                    port=None,
                    port_specified=False,
                    domain=domain,
                    domain_specified=bool(domain),
                    domain_initial_dot=domain.startswith("."),
                    path=c.get("path", "/") or "/",
                    path_specified=True,
                    secure=bool(c.get("secure", True)),
                    expires=int(expires) if expires and expires > 0 else None,
                    discard=not (expires and expires > 0),
                    comment=None,
                    comment_url=None,
                    rest={},
                    rfc2109=False,
                )
            )

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
        timeout: float = 30.0,
        max_size: int | None = None,
    ) -> tuple[int, dict[str, str], bytes, str, list[str]]:
        """Send a request via http.client.

        Returns ``(status, headers, body, url, set_cookies)`` where
        ``set_cookies`` is the final response's individual Set-Cookie
        header values (the flat ``headers`` dict joins multi-value
        headers with ``"; "``, which is lossy for Set-Cookie).

        ``headers`` is sent as-is after ``Host`` (caller sanitizes via
        ``sanitize_headers``). Follows redirects when configured. Raises
        ``WaferTimeout``/``ConnectionFailed`` on network errors; non-2xx
        HTTP responses are returned normally (not raised).

        ``max_size`` (bytes) caps the response body: an over-cap declared
        Content-Length short-circuits before reading, the wire read is
        bounded chunk-by-chunk, and the decompressor output is bounded
        too (gzip-bomb safe). ``ResponseTooLarge`` is raised when exceeded.
        ``None`` (default) = no cap, behavior byte-identical to before.
        """
        from wafer._errors import TooManyRedirects

        method = method.upper()
        # One initial request + up to max_redirects follow-ups, aligned with
        # the session's redirect budget (the wreq path uses the same cap).
        max_hops = (self._max_redirects + 1) if self._follow_redirects else 1
        requested = url
        status: int = 0
        resp_headers: dict[str, str] = {}
        raw = b""
        set_cookies: list[str] = []
        for _hop in range(max_hops):
            requested = url
            status, resp_headers, raw, set_cookies = self._send(
                method, requested, headers, body, timeout, max_size
            )
            if (
                self._follow_redirects
                and status in _REDIRECT_CODES
                and resp_headers.get("location")
            ):
                url = urljoin(requested, resp_headers["location"])
                # 301/302/303 turn a non-GET into a GET and drop the body
                # (per the Fetch spec / what browsers and curl do).
                if status in (301, 302, 303) and method not in ("GET", "HEAD"):
                    method = "GET"
                    body = None
                    headers = {
                        k: v
                        for k, v in headers.items()
                        if k.lower() != "content-type"
                    }
                continue
            return status, resp_headers, raw, requested, set_cookies
        # Hop budget exhausted while still on a redirect: a redirect loop /
        # tarpit. Raise rather than returning the dangling 3xx (mirrors the
        # wreq path, which raises TooManyRedirects). A non-redirecting final
        # response would have returned inside the loop above.
        raise TooManyRedirects(requested, self._max_redirects)

    def _send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
        max_size: int | None = None,
    ) -> tuple[int, dict[str, str], bytes, list[str]]:
        from wafer._errors import (
            ConnectionFailed,
            ResponseTooLarge,
            WaferTimeout,
        )

        parsed = urlparse(url)
        host = parsed.hostname or ""
        default_port = 443 if parsed.scheme == "https" else 80
        port = parsed.port or default_port
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        host_header = host if port == default_port else f"{host}:{port}"

        # Compute the Cookie header from the jar (browser-like replay).
        cookie_req = _CookieRequest(url)
        self._jar.add_cookie_header(cookie_req)
        cookie_header = cookie_req.get_header("Cookie")

        secure = parsed.scheme == "https"
        conn_cls = (
            http.client.HTTPSConnection if secure
            else http.client.HTTPConnection
        )
        if self._proxy_url:
            # Honor the session proxy. http.client only does plain HTTP CONNECT
            # tunnelling; for socks/https proxies it would silently leak the
            # real IP, so fail loud instead (the caller falls back to the wreq
            # path, which does honor the proxy).
            pp = urlparse(self._proxy_url)
            if pp.scheme == "http" and pp.hostname:
                ckw = {"timeout": timeout}
                if secure:
                    ckw["context"] = self._ctx
                conn = conn_cls(pp.hostname, pp.port or 80, **ckw)
                conn.set_tunnel(host, port)
            else:
                raise ConnectionFailed(
                    url,
                    f"native-TLS cannot tunnel through a {pp.scheme!r} proxy",
                )
        elif secure:
            conn = conn_cls(host, port, context=self._ctx, timeout=timeout)
        else:
            conn = conn_cls(host, port, timeout=timeout)

        logger.debug("Native-TLS %s %s", method, url)
        try:
            # Low-level so we control header order and omit urllib's tells
            # (no auto Host/Accept-Encoding). Host goes first, like a browser.
            conn.putrequest(
                method, path, skip_host=True, skip_accept_encoding=True
            )
            conn.putheader("Host", host_header)
            for k, v in headers.items():
                conn.putheader(k, v)
            if cookie_header:
                conn.putheader("Cookie", cookie_header)
            if body is not None:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(message_body=body)
            resp = conn.getresponse()
            # Extract cookies from the headers now, before the body read: if
            # read() fails mid-body, a Set-Cookie token would otherwise be lost.
            self._jar.extract_cookies(resp, cookie_req)
            # Content-Length short-circuit: if the server declared a length
            # over the cap, abort before reading the body at all.
            if max_size is not None:
                declared = resp.getheader("Content-Length")
                if declared is not None:
                    try:
                        declared_n = int(declared)
                    except (TypeError, ValueError):
                        declared_n = None
                    if declared_n is not None and declared_n > max_size:
                        raise ResponseTooLarge(url, declared_n, max_size)
            if max_size is None:
                raw = resp.read()
            else:
                # Bounded chunked read: stop the moment the running total
                # passes the cap (the wire body is never fully buffered past
                # it). Compressed length is checked here; the decompressed
                # length is bounded separately in _decompress (bomb-safe).
                chunks = []
                total = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    chunks.append(chunk)
                    if total > max_size:
                        raise ResponseTooLarge(url, total, max_size)
                raw = b"".join(chunks)
        except (socket.timeout, TimeoutError) as e:
            raise WaferTimeout(url, timeout) from e
        except (OSError, http.client.HTTPException) as e:
            raise ConnectionFailed(url, str(e)) from e
        finally:
            conn.close()

        resp_headers: dict[str, str] = {}
        set_cookies: list[str] = []
        for k, v in resp.getheaders():
            kl = k.lower()
            if kl == "set-cookie":
                # Preserve individual values: the "; "-joined dict form
                # is ambiguous (cookie attributes use the same separator).
                set_cookies.append(v)
            resp_headers[kl] = (
                resp_headers[kl] + "; " + v if kl in resp_headers else v
            )
        raw = _decompress(
            raw, resp_headers.get("content-encoding", ""), url, max_size
        )
        return resp.status, resp_headers, raw, set_cookies
