"""Bounded Brave Search PoW solving using the site's own verified protocol."""

import json
import logging
import re
import time
from collections import deque
from urllib.parse import parse_qsl, urlparse

from wafer._brave import (
    BRAVE_COOKIES,
    BRAVE_ORIGIN,
    BRAVE_STORAGE_KEYS,
    brave_url_identity,
    is_brave_challenge,
    is_brave_search_url,
)
from wafer._errors import ResponseTooLarge
from wafer.browser._pump import idle

logger = logging.getLogger("wafer")


def brave_storage_state(replay):
    """Seed localStorage once at context creation, never on every reload.

    An init script would restore already-spent tokens again after Brave's
    reload, undoing its consumption and corrupting the spare-token pool.
    """
    config = (replay or {}).get("_brave", {})
    storage = config.get("state", {}).get("storage", [])
    return {
        "cookies": config.get("cookies", []),
        "origins": (
            [{"origin": BRAVE_ORIGIN, "localStorage": storage}] if storage else []
        ),
    }


def prepare_brave(context, page, url, replay, deadline):
    """Restore session-local spare tokens and pace first-party exchanges.

    Configuration is supplied internally by the session in its replay descriptor;
    direct BrowserSolver callers get a disposable, deadline-bounded context.
    Nothing is retained until the final search response has been validated.
    """
    config = (replay or {}).get("_brave", {})
    state = config.get("state", {})
    state.clear()
    limiter = config.get("limiter")
    counts = {"documents": 0, "pow": 0, "keys": 0}
    evidence = {"accepted": False, "rejected": False}
    pending = deque()
    stopped = False

    def cancel_pending():
        nonlocal stopped
        stopped = True
        while pending:
            try:
                pending.popleft().abort()
            except Exception:
                pass
        context.unroute_all(behavior="ignoreErrors")

    page._wafer_brave_cancel = cancel_pending

    def flush_pending():
        # A route callback must return promptly: sleeping there prevents the
        # CDP worker/iframe hardening callbacks from resuming Brave's workers.
        # Patchright keeps returned-but-unhandled routes pending until this
        # worker calls continue_()/abort() (RouteHandler._handle_internal).
        while pending:
            if time.monotonic() >= deadline or evidence["rejected"]:
                pending.popleft().abort()
                continue
            if limiter is not None and limiter._delay_for("search.brave.com") > 0:
                break
            route = pending.popleft()
            if limiter is not None:
                limiter.record("search.brave.com")
            route.continue_()

    page._wafer_brave_flush = flush_pending
    requested_identity = brave_url_identity(url)
    original_rr = "_rr" in dict(parse_qsl(urlparse(url).query))

    def route_request(route):
        if stopped:
            route.abort()
            return
        request = route.request
        parsed = urlparse(request.url)
        is_document = (
            request.is_navigation_request() and request.frame == page.main_frame
        )
        if is_document:
            counts["documents"] += 1
            if (
                not is_brave_search_url(request.url)
                or counts["documents"] > 2
                or brave_url_identity(
                    request.url,
                    allow_reload=evidence["accepted"] and not original_rr,
                )
                != requested_identity
            ):
                evidence["rejected"] = True
                route.abort()
                return
        if (
            parsed.scheme == "https"
            and parsed.hostname == "search.brave.com"
            and parsed.port in (None, 443)
        ):
            if parsed.path == "/api/captcha/pow":
                counts["pow"] += 1
                if counts["pow"] > 1:
                    route.abort()
                    evidence["rejected"] = True
                    return
            if parsed.path == "/api/tokens/keys":
                counts["keys"] += 1
                if counts["keys"] > 2:
                    route.abort()
                    evidence["rejected"] = True
                    return
            if is_document and counts["documents"] == 1:
                # prepare_brave paces this navigation before goto(), which
                # cannot return until its initial route has been released.
                if time.monotonic() >= deadline:
                    route.abort()
                    return
                if limiter is not None:
                    limiter.record("search.brave.com")
                route.continue_()
            elif len(pending) < 32:
                pending.append(route)
            else:
                evidence["rejected"] = True
                route.abort()
            return
        if time.monotonic() >= deadline:
            route.abort()
            return
        route.continue_()

    # Route every request so cross-origin main-frame redirects cannot escape
    # the original origin/route contract. CDN subresources keep normal behavior
    # and the solver's configured network egress/proxy remains authoritative.
    context.route("**/*", route_request)

    def record_pow(response):
        parsed = urlparse(response.url)
        if (
            parsed.scheme == "https"
            and parsed.hostname == "search.brave.com"
            and parsed.port in (None, 443)
            and parsed.path == "/api/captcha/pow"
        ):
            evidence["accepted"] = response.status == 200
            evidence["rejected"] = response.status != 200

    page.on("response", record_pow)
    if limiter is not None:
        while time.monotonic() < deadline:
            delay = limiter._delay_for("search.brave.com")
            if delay <= 0:
                break
            idle(min(0.2, delay, max(0, deadline - time.monotonic())))
    return state, evidence


def capture_brave_response(response, page, url, max_size, *, allow_pow_reload=False):
    """Require the exact search network document, including query and offset."""
    from wafer.browser._solver import (
        CapturedResponse,
        _is_passthrough_challenge_html,
        _response_headers,
    )

    if response is None or not is_brave_search_url(url):
        return None

    allow_reload = allow_pow_reload and "_rr" not in dict(
        parse_qsl(urlparse(url).query)
    )

    def identity(value):
        # Brave's Accepted transition reloads with _rr=1, then removes it
        # through history.replaceState. No other query changes are allowed.
        return brave_url_identity(value, allow_reload=allow_reload)

    requested = urlparse(url)
    if requested.path != "/search":
        return None
    try:
        requested_identity = identity(url)
        if (
            not 200 <= response.status < 300
            or identity(response.url) != requested_identity
            or identity(page if isinstance(page, str) else page.url)
            != requested_identity
        ):
            return None
        if callable(getattr(response, "all_headers", None)):
            headers, set_cookie = _response_headers(response)
        else:
            headers, set_cookie = dict(response.headers), list(response.set_cookie)
        if (
            headers.get("content-type", "").split(";", 1)[0].lower()
            not in {"text/html", "application/xhtml+xml"}
            or "attachment" in headers.get("content-disposition", "").lower()
        ):
            return None
        body = response.body() if callable(response.body) else response.body
    except Exception:
        return None
    if not isinstance(body, bytes):
        return None
    if max_size is not None and len(body) > max_size:
        raise ResponseTooLarge(url, len(body), max_size)
    html = body.decode("utf-8", errors="replace")
    if (
        not html
        or _is_passthrough_challenge_html(html)
        or 'id="search-page"' not in html
        or 'page:"/search"' not in html
    ):
        return None
    return CapturedResponse(
        url=response.url,
        status=response.status,
        headers=headers,
        body=body,
        set_cookie=set_cookie,
    )


def wait_for_brave(
    solver, page, url, documents, deadline, max_size, evidence, size_guard=None
):
    """Click idle Verify once; never restart running work or retry an error.

    A 200 PoW reply is intermediate evidence only. Brave still has to verify
    its blind-token proof, set the real cookie, and reload the exact search.
    """
    clicked = False
    observed = False
    manual_start = False
    last_status = None

    def action_timeout():
        return max(1, int(min(500, (deadline - time.monotonic()) * 1000)))

    while time.monotonic() < deadline:
        flush = getattr(page, "_wafer_brave_flush", None)
        if flush is not None:
            flush()
        if size_guard and size_guard["exceeded"]:
            raise ResponseTooLarge(url, int(size_guard["size"]), max_size)
        if evidence["rejected"]:
            return None, False
        # A redirect can detach the old execution context. Network responses
        # remain authoritative, and polling the new document is safe.
        response = documents[-1][2] if documents else None
        captured = capture_brave_response(
            response,
            page,
            url,
            max_size,
            allow_pow_reload=observed and evidence["accepted"],
        )
        if captured is not None:
            return captured, observed and evidence["accepted"]
        try:
            html = solver._bounded_page_content(page, max_size)
            if is_brave_challenge(html, page.url):
                observed = True
                tokens = re.search(
                    r'challengeSet:\{set_token:"[^"]+",tokens:(\[[^\]]*\])', html
                )
                if tokens:
                    try:
                        manual_start = len(json.loads(tokens[1])) > 10
                    except (ValueError, TypeError):
                        return None, False
            wrapper = page.locator(".captcha-wrapper[data-state]")
            if wrapper.count():
                observed = True
                status = wrapper.first.get_attribute(
                    "data-state", timeout=action_timeout()
                )
                if status != last_status:
                    logger.info("Brave PoW state=%s", status)
                    last_status = status
                if status == "error":
                    logger.info("Brave PoW stopped: client error or rejection")
                    return None, False
                if status == "idle" and manual_start and not clicked:
                    button = page.locator(".captcha-button-wrap button")
                    if button.count() and button.first.is_enabled():
                        # Recheck immediately before the action: small sets
                        # auto-start while their token keys are loading.
                        if (
                            wrapper.first.get_attribute(
                                "data-state", timeout=action_timeout()
                            )
                            == "idle"
                        ):
                            clicked = True
                            button.first.click(
                                timeout=max(
                                    1,
                                    int(
                                        min(1000, (deadline - time.monotonic()) * 1000)
                                    ),
                                )
                            )
                # verifying and solved are passive: await the final document.
            elif page.locator(".captcha-wrapper:not([data-state])").count():
                logger.info("Brave stopped: non-PoW captcha or failure page")
                return None, False
        except Exception:
            pass
        idle(min(0.2, max(0, deadline - time.monotonic())))
    logger.info("Brave PoW stopped: solve deadline exhausted")
    return None, False


def finish_brave(
    solver, context, page, url, documents, deadline, max_size, setup, size_guard=None
):
    from wafer.browser._solver import SolveResult

    state, evidence = setup
    captured, cleared = wait_for_brave(
        solver, page, url, documents, deadline, max_size, evidence, size_guard
    )
    if captured is None or time.monotonic() >= deadline:
        return None
    cookies = context.cookies([BRAVE_ORIGIN])
    cleared = cleared and any(c.get("name") in BRAVE_COOKIES for c in cookies)
    # Keep ONLY the anonymous spare-token keys from this exact origin. Never
    # share localStorage via BrowserSolver or persist it to the cookie cache.
    storage = context.storage_state()
    entries = []
    for origin in storage.get("origins", []):
        if origin.get("origin") == BRAVE_ORIGIN:
            entries = [
                item
                for item in origin.get("localStorage", [])
                if (
                    item.get("name") in BRAVE_STORAGE_KEYS
                    and isinstance(item.get("value"), str)
                    and len(item["value"]) <= 256_000
                )
            ]
    if time.monotonic() >= deadline:
        return None
    state["storage"] = entries
    logger.info(
        "Brave search captured (%d bytes, pow_accepted=%s)",
        len(captured.body),
        cleared,
    )
    return SolveResult(
        cookies=cookies,
        user_agent=solver._browser_ua or "",
        browser_version=solver._browser_version,
        response=captured,
        challenge_absent=not cleared,
    )
