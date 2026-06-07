"""Imperva / Incapsula challenge solver."""

import logging
import random
import time
from urllib.parse import urlparse

from wafer._cookies import registrable_domain as _registrable_domain

logger = logging.getLogger("wafer")

# Cookie names that signal a solved Imperva challenge.
# Modern: reese84 (advanced bot detection JS)
# Legacy: ___utmvc (older Incapsula)
# Classic: incap_ses_* (session cookie set after JS challenge)
_SOLVE_COOKIES = ("reese84", "___utmvc")
_CLASSIC_PREFIX = "incap_ses_"


def _is_ip_host(host: str) -> bool:
    """True for a bare IPv4/IPv6 host (no registrable domain to derive)."""
    if ":" in host:  # IPv6 (urlparse strips the brackets)
        return True
    labels = host.split(".")
    return len(labels) == 4 and all(
        lbl.isdigit() and 0 <= int(lbl) <= 255 for lbl in labels
    )


def imperva_embedder(url: str, headers: dict | None) -> str | None:
    """Pick the origin page to load for an Imperva reese84 browser solve.

    Imperva serves a *top-level navigation* to an API host (e.g.
    ``api2.realtor.ca``) its interactive "Error 15" block - no real browser
    ever navigates directly to an API host. The real flow is: load the
    site's main page (which earns the registrable-domain reese84 / incap
    cookies), then call the API via same-site XHR. So the browser solve
    must navigate the *embedder* origin, not the API URL itself.

    Returns the embedder origin URL (scheme://host/) to navigate, or
    ``None`` to keep the legacy direct-navigation behaviour (the target is
    already a normal page, e.g. www.realtor.ca / amadeus / hkbea).

    Priority:
      1. The request's ``Referer``/``Origin`` header, when it is same-site
         (same registrable domain) but a *different host* than the target -
         i.e. the API was called as a cross-host XHR. This is the actual
         embedder the consuming app uses.
      2. Heuristic ``https://www.<registrable>/`` when the target is a
         non-www subdomain (an API host) and no usable Referer/Origin was
         supplied.
    """
    target = urlparse(url)
    target_host = (target.hostname or "").lower()
    # No registrable domain for a bare IP, and an https embedder is the only
    # thing worth navigating - bail to legacy direct-nav otherwise.
    if not target_host or _is_ip_host(target_host):
        return None
    scheme = target.scheme if target.scheme in ("http", "https") else "https"
    target_root = _registrable_domain(target_host)

    # 1. Caller-supplied Referer/Origin (the real embedder). Build the origin
    #    from scheme+hostname only (drop any userinfo/port - they must never
    #    reach page.goto() or the logs) and force the target's scheme so we
    #    can't downgrade an https API call onto an http embedder.
    if headers:
        for want in ("referer", "origin"):
            for k, v in headers.items():
                if k.lower() != want or not v:
                    continue
                p = urlparse(v)
                if p.scheme not in ("http", "https"):
                    continue
                h = (p.hostname or "").lower()
                if (
                    h
                    and h != target_host
                    and _registrable_domain(h) == target_root
                ):
                    return f"{scheme}://{h}/"

    # 2. Heuristic www origin, only for non-www subdomains (API hosts).
    if target_host not in (target_root, f"www.{target_root}"):
        first_label = target_host.split(".", 1)[0]
        if first_label != "www":
            return f"{scheme}://www.{target_root}/"

    return None


def solve_imperva_embedder(solver, page, embedder: str, timeout_ms: int) -> bool:
    """Earn the registrable-domain Imperva cookies via the origin page.

    Navigates ``embedder`` (a real page that passes the WAF as a normal
    navigation), replays human-like movement so the reese84 sensor produces
    a genuine token, and waits for a solve cookie to appear. The caller then
    harvests ``context.cookies()`` - the ``.<registrable>`` reese84 / incap
    set replays cross-host (and cross-TLS) to the API host.
    """
    deadline = time.monotonic() + timeout_ms / 1000
    try:
        page.goto(
            embedder,
            wait_until="domcontentloaded",
            timeout=max(1, int((deadline - time.monotonic()) * 1000)),
        )
    except Exception:
        logger.debug(
            "Imperva embedder navigation failed for %s", embedder,
            exc_info=True,
        )
        return False

    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )

    while time.monotonic() < deadline:
        names = {c["name"] for c in page.context.cookies()}
        if any(n in names for n in _SOLVE_COOKIES) or any(
            n.startswith(_CLASSIC_PREFIX) for n in names
        ):
            # Cookie set; let the sensor settle (it may still refresh the
            # reese84 value shortly after first issue), then succeed.
            solver._replay_browse_chunk(page, state, 1)
            time.sleep(min(1.5, max(0.0, deadline - time.monotonic())))
            return True
        solver._replay_browse_chunk(page, state, 2)

    return False


# Async fetch with an AbortController timeout: identical to a real same-site
# XHR the app would make, so a 2xx is exactly the bytes a browser would get.
_XHR_JS = """async (req) => {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), req.timeout_ms);
    try {
        const opts = {method: req.method, credentials: 'include',
                      headers: {}, signal: ctrl.signal};
        if (req.content_type) opts.headers['Content-Type'] = req.content_type;
        if (req.body != null && req.method !== 'GET' && req.method !== 'HEAD')
            opts.body = req.body;
        const r = await fetch(req.url, opts);
        const text = await r.text();
        return {status: r.status, body: text,
                content_type: r.headers.get('content-type') || ''};
    } catch (e) {
        return {status: -1, body: String(e), content_type: ''};
    } finally {
        clearTimeout(t);
    }
}"""


def imperva_xhr_replay(page, url: str, replay: dict, timeout_ms: int):
    """Replay the original request as a same-site XHR from the embedder page.

    Runs in the page that just earned the WAF cookies, so the browser attaches
    the real ``Origin``/``Referer``/cookies and the WAF treats it exactly like
    the consuming app's own fetch. Returns ``{status, body, content_type}`` or
    ``None`` on a transport error - the caller turns a 2xx into a passthrough
    response and otherwise falls back to cookie replay.
    """
    arg = {
        "url": url,
        "method": (replay.get("method") or "GET").upper(),
        "body": replay.get("body"),
        "content_type": replay.get("content_type"),
        "timeout_ms": max(1000, min(timeout_ms, 30000)),
    }
    try:
        res = page.evaluate(_XHR_JS, arg)
    except Exception:
        logger.debug(
            "Imperva in-page XHR replay errored for %s", url, exc_info=True
        )
        return None
    if not res or res.get("status", -1) < 0:
        return None
    return res


def _snapshot_cookies(cookies):
    """Capture current values of solve-signal cookies."""
    snap = {}
    for c in cookies:
        if c["name"] in _SOLVE_COOKIES or c["name"].startswith(_CLASSIC_PREFIX):
            snap[c["name"]] = c["value"]
    return snap


def wait_for_imperva(solver, page, timeout_ms: int) -> bool:
    """Wait for Imperva challenge to resolve.

    Polls for solve-signal cookies:
    - ``reese84`` — modern Imperva advanced bot JS
    - ``___utmvc`` — legacy Incapsula
    - ``incap_ses_*`` — classic Incapsula session (set after JS runs)

    Imperva may set ``reese84`` via Set-Cookie on the challenge
    response itself (before JS runs), so we track value *changes*
    rather than mere presence to avoid false-positive success.
    """
    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    deadline = time.monotonic() + timeout_ms / 1000

    # Capture initial cookie values (may already be set by the
    # challenge page's Set-Cookie header before JS executes)
    initial = _snapshot_cookies(page.context.cookies())

    while time.monotonic() < deadline:
        cookies = page.context.cookies()
        current = _snapshot_cookies(cookies)

        for name, value in current.items():
            if name not in initial:
                # New cookie appeared (wasn't in initial response)
                solver._replay_browse_chunk(page, state, 1)
                return True
            if value != initial[name]:
                # Existing cookie changed value (JS updated it)
                solver._replay_browse_chunk(page, state, 1)
                return True

        solver._replay_browse_chunk(page, state, 2)

    return False
