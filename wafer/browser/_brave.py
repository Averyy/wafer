"""Bounded Brave Search PoW solving using the site's own verified protocol."""

import asyncio
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


class _BraveRoutes:
    """Release paced routes even while a synchronous page read is pending.

    Sync Patchright pumps its asyncio loop during protocol calls. A task on
    that loop can release a navigation while Runtime.evaluate waits for its
    new execution context. Polling from wait_for_brave cannot: that caller
    is itself blocked in the read. Route callbacks only enqueue work, so they
    also leave worker/iframe hardening free to resume paused targets.
    """

    def __init__(self, limiter, deadline, evidence):
        self.limiter = limiter
        self.deadline = deadline
        self.evidence = evidence
        self.pending = deque()
        self.task = None
        self.active = None
        self.stopped = False

    def enqueue(self, route, *, priority=False):
        self.pending.append((route, priority))
        logger.debug(
            "Brave route queued path=%s pending=%d",
            urlparse(route.request.url).path,
            len(self.pending),
        )
        if self.task is None:
            self.task = asyncio.get_running_loop().create_task(self._drain())

    async def _drain(self):
        try:
            while self.pending:
                remaining = self.deadline - time.monotonic()
                abort = self.stopped or self.evidence["rejected"] or remaining <= 0
                if not abort and self.limiter is not None:
                    delay = self.limiter._delay_for("search.brave.com")
                    if delay > 0:
                        await asyncio.sleep(min(delay, 0.2, remaining))
                        continue
                # Search pages can enqueue many /api/feedback requests. Keep
                # their pacing, but do not make a required key, PoW, or final
                # document wait behind telemetry for most of the solve budget.
                item = next((item for item in self.pending if item[1]), self.pending[0])
                self.pending.remove(item)
                route = item[0]
                logger.debug(
                    "Brave route %s path=%s pending=%d",
                    "abort" if abort else "release",
                    urlparse(route.request.url).path,
                    len(self.pending),
                )
                # This is the one sync/async bridge: Route's underlying async
                # implementation belongs to this same driver loop. Calling
                # the sync wrapper from this task would switch back into the
                # already-running dispatcher greenlet. Real-driver coverage
                # in live_brave_pacing.py exercises this bridge.
                self.active = route
                try:
                    if abort:
                        await route._impl_obj.abort()
                    else:
                        if self.limiter is not None:
                            self.limiter.record("search.brave.com")
                        await route._impl_obj.continue_()
                except Exception as exc:
                    self.evidence["rejected"] = True
                    logger.debug("Brave route failed (%s)", type(exc).__name__)
                finally:
                    self.active = None
        finally:
            self.task = None

    def cancel(self):
        self.stopped = True
        # Cancelling an in-flight Route.continue_ cancels its bookkeeping
        # before Patchright can finish handling the route and consume the
        # protocol result. Let that already-sent operation settle instead;
        # context close also releases its page-close race. Cancel only pacing.
        if self.task is not None and self.active is None:
            self.task.cancel()
        while self.pending:
            try:
                self.pending.popleft()[0].abort()
            except Exception:
                pass


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
    routes = _BraveRoutes(limiter, deadline, evidence)

    def cancel_pending():
        routes.cancel()
        context.unroute_all(behavior="ignoreErrors")

    page._wafer_brave_cancel = cancel_pending

    requested_identity = brave_url_identity(url)
    original_rr = "_rr" in dict(parse_qsl(urlparse(url).query))

    def route_request(route):
        if routes.stopped:
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
            elif len(routes.pending) < 32:
                routes.enqueue(
                    route,
                    priority=is_document
                    or parsed.path
                    in {
                        "/api/tokens/keys",
                        "/api/captcha/pow",
                    },
                )
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


def _is_brave_challenge_response(response, url, max_size):
    """Read gate evidence from a retained, exact-target main document.

    A spare token may replace the interstitial before the handler gets a DOM
    poll. Status alone proves nothing: require the same scoped structural
    detector used by the transport, on the actual earlier response bytes.
    """
    try:
        if (
            not is_brave_search_url(url)
            or not is_brave_search_url(response.url)
            or brave_url_identity(response.url) != brave_url_identity(url)
        ):
            return False
        headers = response.headers
        if (
            headers.get("content-type", "").split(";", 1)[0].lower()
            not in {"text/html", "application/xhtml+xml"}
            or "attachment" in headers.get("content-disposition", "").lower()
        ):
            return False
        body = response.body() if callable(response.body) else response.body
    except Exception:
        return False
    if not isinstance(body, bytes):
        return False
    if max_size is not None and len(body) > max_size:
        raise ResponseTooLarge(url, len(body), max_size)
    return is_brave_challenge(body.decode("utf-8", errors="replace"), response.url)


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
    checked_documents = 0

    def action_timeout():
        return max(1, int(min(500, (deadline - time.monotonic()) * 1000)))

    while time.monotonic() < deadline:
        if size_guard and size_guard["exceeded"]:
            raise ResponseTooLarge(url, int(size_guard["size"]), max_size)
        if evidence["rejected"]:
            return None, False
        # Small sets may finish while goto()/headless verification is still
        # pumping events. Accepted first-party work is gate evidence even if
        # the interstitial has disappeared before the first DOM poll. The
        # completed exact search document is still required below.
        observed = observed or evidence["accepted"]
        # Main-document responses survive a fast spare-token navigation even
        # when the old DOM is already gone. Inspect each at most once, before
        # deciding whether the latest successful document was challenge-free.
        while not observed and checked_documents < len(documents):
            earlier = documents[checked_documents][2]
            checked_documents += 1
            observed = _is_brave_challenge_response(earlier, url, max_size)
        if time.monotonic() >= deadline:
            break
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
        # body()/headers can pump route callbacks too. Recheck a rejection
        # observed during that read before exporting content or cookies.
        if evidence["rejected"]:
            return None, False
        if captured is not None:
            # A retained, already-verified blind token can clear the gate
            # without issuing new PoW. That is recovery too, not an absent
            # challenge. finish_brave exports only cookies still present.
            return captured, observed
        try:
            logger.debug("Brave DOM read start")
            html = solver._bounded_page_content(page, max_size)
            logger.debug("Brave DOM read complete")
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
    # The completed search can arrive before its app has prepared the cookie
    # for the NEXT navigation. In particular, headless Chrome can expose the
    # consumed/deleted cookie between response capture and app hydration.
    # Allow that site-owned handoff to settle, within the original deadline.
    settle_deadline = min(deadline, time.monotonic() + 3)
    try:
        page.wait_for_load_state(
            "domcontentloaded",
            timeout=max(1, int((settle_deadline - time.monotonic()) * 1000)),
        )
    except Exception:
        pass
    cookies = context.cookies([BRAVE_ORIGIN])
    while cleared and not any(c.get("name") in BRAVE_COOKIES for c in cookies):
        if time.monotonic() >= settle_deadline:
            break
        idle(min(0.1, max(0, settle_deadline - time.monotonic())))
        cookies = context.cookies([BRAVE_ORIGIN])
    # Recovery is established by the observed gate and validated final network
    # document. A consumed cookie need not remain in the browser afterwards;
    # it must never relabel an accepted _rr=1 recovery as challenge-absent.
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
    if time.monotonic() >= deadline or evidence["rejected"]:
        return None
    if size_guard and size_guard["exceeded"]:
        raise ResponseTooLarge(url, int(size_guard["size"]), max_size)
    if (
        capture_brave_response(
            captured, page, url, max_size, allow_pow_reload=evidence["accepted"]
        )
        is None
    ):
        return None
    state["storage"] = entries
    logger.info(
        "Brave search captured (%d bytes, cleared=%s, pow_accepted=%s)",
        len(captured.body),
        cleared,
        evidence["accepted"],
    )
    return SolveResult(
        cookies=cookies,
        user_agent=solver._browser_ua or "",
        browser_version=solver._browser_version,
        response=captured,
        challenge_absent=not cleared,
    )
