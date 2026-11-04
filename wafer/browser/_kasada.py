"""Kasada challenge solver — browser CT/ST extraction.

Kasada's challenge flow:
1. Page loads → Kasada JS runs fingerprinting
2. JS POSTs to ips.js, p.js, or /tl endpoint
3. Response contains x-kpsdk-ct (fingerprint token) and optionally
   x-kpsdk-st (server timestamp) in headers
4. We intercept ANY response with x-kpsdk-ct to extract the token

The CT token is reusable (~30 min). Per-request proof-of-work (CD)
is generated in pure Python by wafer._kasada.generate_cd().

IMPORTANT: The response listener must be attached BEFORE page.goto()
because the token response can fire during initial page load. Use
setup_kasada_listener() before navigation, then wait_for_kasada()
after navigation to collect the result.
"""

import logging
import random
import time

logger = logging.getLogger("wafer")


def setup_kasada_listener(page) -> dict:
    """Attach /tl response listener to a page BEFORE navigation.

    Returns a shared dict that will be populated with {"ct", "st"}
    when the /tl response is intercepted. Pass this dict to
    wait_for_kasada() after navigation completes.
    """
    captured: dict = {}

    def on_response(response):
        try:
            # Stop watching once we have both CT and ST
            if captured.get("ct") and captured.get("st"):
                return
            headers = response.headers
            ct = headers.get("x-kpsdk-ct", "")
            if not ct:
                return
            st_str = headers.get("x-kpsdk-st", "")
            st = int(st_str) if st_str else 0
            # First response with CT: capture it
            if "ct" not in captured:
                captured["ct"] = ct
                logger.debug(
                    "Kasada CT intercepted on %s: ct=%s...",
                    response.url[:80], ct[:20],
                )
            # Update ST if we get a better one (non-zero)
            if st and not captured.get("st"):
                captured["st"] = st
                logger.debug("Kasada ST intercepted: %d", st)
        except Exception:
            logger.debug("Kasada listener error", exc_info=True)

    page.on("response", on_response)
    # Stash for cleanup
    page._kasada_listener = on_response
    page._kasada_captured = captured
    return captured


def wait_for_kasada(solver, page, timeout_ms: int) -> bool:
    """Wait for Kasada /tl response and extract CT/ST tokens.

    If setup_kasada_listener() was called before navigation, uses
    the pre-attached listener. Otherwise attaches one now (may miss
    early /tl responses).

    Sets ``page._kasada_result`` to ``{"ct": str, "st": int}`` on
    success.

    Returns True if tokens were captured, False on timeout.
    """
    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    deadline = time.monotonic() + timeout_ms / 1000

    # Use pre-attached listener if available, otherwise set up now
    captured = getattr(page, "_kasada_captured", None)
    if captured is None:
        captured = setup_kasada_listener(page)

    # After CT is captured, wait for ST to arrive (may come on a
    # later /tl response) and a short settle for cookies.  The
    # original 10s settle was overly conservative — CT/ST typically
    # arrive within 2-3s, and cookies are set around the same time.
    # For passthrough sites (where browser returns content directly),
    # cookie timing doesn't matter at all since TLS replay requires
    # CT+CD+H headers that we don't send.
    min_settle = 3  # seconds after CT capture

    try:
        ct_time: float | None = None
        while time.monotonic() < deadline:
            if captured.get("ct") and ct_time is None:
                ct_time = time.monotonic()
            if ct_time and time.monotonic() - ct_time >= min_settle:
                page._kasada_result = captured
                return True
            solver._replay_browse_chunk(page, state, 1)
    finally:
        listener = getattr(page, "_kasada_listener", None)
        if listener:
            try:
                page.remove_listener("response", listener)
            except Exception:
                pass

    # Post-timeout: only return success if CT was captured AND settle
    # time completed. Incomplete settle means cookies may be missing.
    if captured.get("ct") and ct_time and time.monotonic() - ct_time >= min_settle:
        page._kasada_result = captured
        return True

    if captured.get("ct"):
        logger.warning(
            "Kasada CT captured but settle time incomplete "
            "(%.1fs of %ds), cookies may be missing",
            time.monotonic() - ct_time if ct_time else 0,
            min_settle,
        )

    return False


# ---------------------------------------------------------------------------
# Signed API calls
# ---------------------------------------------------------------------------
#
# Some deployments sign every protected API call rather than a page load:
# Kasada's SDK wraps the page's ``fetch``/``XMLHttpRequest`` and adds
# x-kpsdk-ct, -cd, -h and -v to each request to a configured endpoint. The
# server refuses a call without them (gdx-api.costco.com answers 429, empty
# text/plain), cookies or not, and wafer cannot mint -h outside the SDK. So the
# call is made from a page on the site's origin, through the SDK's own hook:
# that means the page's main world, since an isolated-world ``fetch`` is the
# unwrapped native one (measured 2026-11-03: main world 200 with all four
# headers, isolated world unsigned).

# Request headers a page script may not set (the Fetch spec's forbidden
# names); the browser supplies its own. Names starting ``sec-``/``proxy-`` are
# forbidden too.
_FORBIDDEN_FETCH_HEADERS = frozenset({
    "accept-charset", "accept-encoding", "access-control-request-headers",
    "access-control-request-method", "connection", "content-length",
    "cookie", "cookie2", "date", "dnt", "expect", "host", "keep-alive",
    "origin", "priority", "referer", "te", "trailer", "transfer-encoding",
    "upgrade", "user-agent", "via",
})

_SDK_READY = (
    "!!(window.KPSDK && typeof window.KPSDK.isReady === 'function'"
    " && window.KPSDK.isReady())"
)

_SIGNED_FETCH = """(async (req) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), req.timeout_ms);
    try {
        const opts = {method: req.method, headers: req.headers,
                      credentials: req.credentials, redirect: req.redirect,
                      signal: ctrl.signal};
        if (req.body_b64 != null && req.method !== 'GET'
                && req.method !== 'HEAD')
            opts.body = Uint8Array.from(atob(req.body_b64),
                                        (c) => c.charCodeAt(0));
        const r = await fetch(req.url, opts);
        if (r.type === 'opaqueredirect')
            return {status: -3, error: 'redirect not followed'};
        const headers = {};
        r.headers.forEach((value, name) => { headers[name] = value; });
        const declared = Number(r.headers.get('content-length'));
        if (req.max_size != null && Number.isFinite(declared)
                && declared > req.max_size) {
            try { await r.body.cancel(); } catch (_) {}
            return {status: r.status, too_large: true, size: declared,
                    headers, body: ''};
        }
        // Read in chunks so an undeclared or streamed body stops at the cap
        // rather than being buffered whole first.
        const parts = [];
        let size = 0;
        if (r.body && r.body.getReader) {
            const reader = r.body.getReader();
            while (true) {
                const part = await reader.read();
                if (part.done) break;
                size += part.value.byteLength;
                if (req.max_size != null && size > req.max_size) {
                    try { await reader.cancel(); } catch (_) {}
                    return {status: r.status, too_large: true, size,
                            headers, body: ''};
                }
                parts.push(part.value);
            }
        }
        let binary = '';
        for (const bytes of parts)
            for (let i = 0; i < bytes.length; i += 0x8000)
                binary += String.fromCharCode.apply(
                    null, bytes.subarray(i, i + 0x8000));
        return {status: r.status, headers, body: btoa(binary), size,
                url: r.url, redirected: r.redirected};
    } catch (e) {
        return {status: -1, error: String(e)};
    } finally {
        clearTimeout(timer);
    }
})(%s)"""


def signed_fetch_headers(headers: dict | None) -> dict[str, str]:
    """The caller's request headers a page ``fetch`` may send.

    Forbidden names are the browser's to set (it sends the page's own Origin,
    Referer, User-Agent and cookies), and Kasada's own headers are the SDK's
    to add, so neither is passed on.
    """
    allowed: dict[str, str] = {}
    for name, value in (headers or {}).items():
        lower = str(name).lower()
        if (
            lower in _FORBIDDEN_FETCH_HEADERS
            or lower.startswith(("sec-", "proxy-", "x-kpsdk"))
        ):
            continue
        allowed[str(name)] = str(value)
    return allowed


def wait_for_kasada_sdk(page, deadline: float) -> bool:
    """Wait until the page's Kasada SDK reports ready (``KPSDK.isReady()``)."""
    from wafer.browser._solver import _quiet_read

    while True:
        try:
            if _quiet_read(page, _SDK_READY):
                return True
        except Exception:
            logger.debug("Kasada readiness read failed", exc_info=True)
        if time.monotonic() + 0.25 >= deadline:
            return False
        page.wait_for_timeout(250)


def is_kasada_refusal(status: int, headers: dict) -> bool:
    """A 403/429 that names Kasada in its headers."""
    return status in (403, 429) and any(
        str(name).lower().startswith("x-kpsdk") for name in headers
    )


def kasada_api_replay(
    page,
    url: str,
    replay: dict,
    timeout_ms: int,
    max_size: int | None = None,
):
    """Make the caller's request from *page* through Kasada's fetch hook.

    Returns ``{status, headers, body: bytes, url}``, or ``None`` when the
    request could not be made (a transport error, CORS, a body that cannot be
    remade) or Kasada refused it even signed. Raises ``ResponseTooLarge`` past
    *max_size* and ``TooManyRedirects`` past the request's redirect budget.
    *timeout_ms* bounds the whole call, retry included.
    """
    import base64
    import json

    from wafer._errors import ResponseTooLarge, TooManyRedirects
    from wafer.browser._solver import _quiet_read

    if replay.get("body_unavailable"):
        logger.info(
            "Kasada signed request to %s not made: its body cannot be "
            "remade in the page",
            url,
        )
        return None
    deadline = time.monotonic() + max(0, int(timeout_ms)) / 1000.0
    follow = bool(replay.get("follow_redirects", True))
    # What the session's own loop would still follow. fetch() follows up to
    # 20 redirects and cannot be told fewer, so the hops are counted from the
    # page's requests and checked against this afterwards. None: no budget
    # given, fetch's own limit applies.
    left = replay.get("redirects_left")
    budget = replay.get("max_redirects", left)
    body_b64 = replay.get("body_b64")
    if body_b64 is None and replay.get("body") is not None:
        body_b64 = base64.b64encode(str(replay["body"]).encode("utf-8")).decode()
    arg = {
        "url": url,
        "method": str(replay.get("method") or "GET").upper(),
        "headers": signed_fetch_headers(replay.get("headers")),
        "body_b64": body_b64,
        "max_size": max_size,
        # With follow_redirects off, or no redirect left to follow, the
        # browser must not follow one; an opaque redirect cannot report its
        # Location, so it ends the replay instead.
        "redirect": "follow" if follow and (left is None or left > 0) else "manual",
        # The page's cookies for the API host go with the call, as the
        # caller's own request carried its cookies. An API whose CORS does not
        # allow credentials refuses that outright (gdx-api.costco.com's own
        # page calls it without them), so the call is then made without.
        "credentials": "include",
    }
    if replay.get("content_type") and not any(
        name.lower() == "content-type" for name in arg["headers"]
    ):
        arg["headers"]["Content-Type"] = replay["content_type"]

    hops = [0]

    def on_request(request) -> None:
        # Each hop of a followed redirect is a new request whose
        # redirected_from chain leads back to the call.
        try:
            first, n = request, 0
            while first.redirected_from is not None:
                first, n = first.redirected_from, n + 1
            if n and first.url.split("#", 1)[0] == url.split("#", 1)[0]:
                hops[0] = max(hops[0], n)
        except Exception:
            pass

    def run():
        remaining_ms = int((deadline - time.monotonic()) * 1000)
        if remaining_ms <= 0:
            return None
        arg["timeout_ms"] = min(remaining_ms, 60000)
        try:
            return _quiet_read(page, _SIGNED_FETCH % json.dumps(arg))
        except Exception:
            logger.debug("Kasada signed fetch errored for %s", url, exc_info=True)
            return None

    try:
        page.on("request", on_request)
    except Exception:
        logger.debug("Could not watch the signed request's redirects", exc_info=True)
    try:
        res = run()
        if (
            isinstance(res, dict)
            and res.get("status") == -1
            and "failed to fetch" in str(res.get("error", "")).lower()
        ):
            arg["credentials"] = "same-origin"
            res = run()
    finally:
        try:
            page.remove_listener("request", on_request)
        except Exception:
            pass
    if isinstance(res, dict) and res.get("status") == -3:
        if follow:
            # The session's own loop would have refused this redirect too.
            raise TooManyRedirects(url, int(budget or 0))
        logger.info(
            "Kasada signed request to %s was redirected with "
            "follow_redirects off; the browser cannot report the redirect",
            url,
        )
        return None
    if (
        isinstance(res, dict)
        and res.get("redirected")
        and left is not None
        and max(hops[0], 1) > left
    ):
        raise TooManyRedirects(url, int(budget or 0))
    if not isinstance(res, dict) or res.get("status", -1) < 0:
        logger.info(
            "Kasada signed fetch failed for %s (%s)",
            url,
            (res or {}).get("error") if isinstance(res, dict) else "no result",
        )
        return None
    if res.get("too_large") and max_size is not None:
        raise ResponseTooLarge(url, int(res.get("size") or max_size + 1), max_size)
    headers = {
        str(k).lower(): str(v) for k, v in (res.get("headers") or {}).items()
    }
    # fetch() hands back the decoded body; the wire's framing and compression
    # headers would describe other bytes.
    for name in ("content-encoding", "content-length", "transfer-encoding"):
        headers.pop(name, None)
    body = base64.b64decode(res.get("body") or "")
    status = int(res["status"])
    if is_kasada_refusal(status, headers) or (status in (403, 429) and not body):
        logger.info("Kasada refused the signed request too (HTTP %d)", status)
        return None
    return {
        "status": status,
        "headers": headers,
        "body": body,
        "url": res.get("url") or url,
    }
