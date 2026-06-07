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
from http.cookiejar import CookieJar
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


def _decompress(raw: bytes, encoding: str) -> bytes:
    """Decode gzip/deflate response bodies; return raw on any failure."""
    enc = encoding.lower()
    if enc in ("gzip", "x-gzip"):
        try:
            return gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
        except (gzip.BadGzipFile, EOFError, OSError):
            return raw
    if enc == "deflate":
        try:
            return zlib.decompress(raw)
        except zlib.error:
            try:
                return zlib.decompress(raw, -zlib.MAX_WBITS)
            except zlib.error:
                return raw
    return raw


class NativeTLSTransport:
    """Blocking http.client transport over system OpenSSL with a cookie jar.

    One instance per session (created lazily). The cookie jar persists
    across requests so WAF cookies earned on the first call are replayed
    on subsequent ones. ``http.cookiejar.CookieJar`` is internally locked,
    so concurrent use from a thread pool (AsyncSession) is safe.
    """

    def __init__(self, follow_redirects: bool = True):
        self._ctx = ssl.create_default_context()
        self._jar = CookieJar()
        self._follow_redirects = follow_redirects

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
        timeout: float = 30.0,
    ) -> tuple[int, dict[str, str], bytes, str]:
        """Send a request via http.client. Returns (status, headers, body, url).

        ``headers`` is sent as-is after ``Host`` (caller sanitizes via
        ``sanitize_headers``). Follows redirects when configured. Raises
        ``WaferTimeout``/``ConnectionFailed`` on network errors; non-2xx
        HTTP responses are returned normally (not raised).
        """
        method = method.upper()
        max_hops = 6 if self._follow_redirects else 1
        for _hop in range(max_hops):
            status, resp_headers, raw = self._send(
                method, url, headers, body, timeout
            )
            if (
                self._follow_redirects
                and status in _REDIRECT_CODES
                and resp_headers.get("location")
            ):
                url = urljoin(url, resp_headers["location"])
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
            return status, resp_headers, raw, url
        return status, resp_headers, raw, url

    def _send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
    ) -> tuple[int, dict[str, str], bytes]:
        from wafer._errors import ConnectionFailed, WaferTimeout

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

        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(
                host, port, context=self._ctx, timeout=timeout
            )
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

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
            raw = resp.read()
        except (socket.timeout, TimeoutError) as e:
            raise WaferTimeout(url, timeout) from e
        except (OSError, http.client.HTTPException) as e:
            raise ConnectionFailed(url, str(e)) from e
        finally:
            conn.close()

        self._jar.extract_cookies(resp, cookie_req)

        resp_headers: dict[str, str] = {}
        for k, v in resp.getheaders():
            kl = k.lower()
            resp_headers[kl] = (
                resp_headers[kl] + "; " + v if kl in resp_headers else v
            )
        raw = _decompress(raw, resp_headers.get("content-encoding", ""))
        return resp.status, resp_headers, raw
