"""Cloudflare challenge solver."""

import logging
import random
import time
from urllib.parse import urlparse

from wafer._challenge import loads_cf_challenge_platform
from wafer.browser._pump import idle

logger = logging.getLogger("wafer")

# Markers that identify a CF challenge page.  The title "Just a moment"
# persists even after "Verification successful" appears, so we only
# check structural markers from the challenge scaffold. The challenge
# platform itself is matched by loads_cf_challenge_platform, which leaves out
# the JS-detections beacon Cloudflare injects into ordinary pages.
_CF_CHALLENGE_MARKERS = ("cf_chl", "chl_page")


# Statuses Cloudflare serves a challenge document under, for a document whose
# headers cannot be read.
_CHALLENGE_STATUSES = (403, 429, 503)

# How long a challenge document may sit in the main frame with no Turnstile
# iframe before the solve gives up on it. A non-interactive stage runs with no
# iframe at all, so the 3s "no iframe means it passed through" grace cannot
# apply while one is up: in fetchaller's emulated Linux image the first
# stage alone outlasted it, and the solve was reported as a pass-through in
# the middle of the challenge (stackoverflow.com, 2026-11-03).
_STALLED_CHALLENGE_SECONDS = 20.0


def _document_is_challenge(entry) -> bool:
    """Whether a main-frame ``(url, status, response)`` is a Cloudflare challenge.

    Cloudflare marks every challenge document ``cf-mitigated: challenge``,
    whatever its status (403 for a first look, 429 when it escalates). A
    document whose headers cannot be read falls back to its status.
    """
    status = entry[1] if len(entry) > 1 else None
    response = entry[2] if len(entry) > 2 else None
    if response is not None:
        try:
            headers = response.headers
        except Exception:
            headers = None
        if isinstance(headers, dict):
            return str(headers.get("cf-mitigated", "")).lower() == "challenge"
    return status in _CHALLENGE_STATUSES


def _latest_document_is_challenge(documents) -> bool:
    """Whether the newest main-frame document of this solve is a challenge."""
    entries = list(documents or ())
    return bool(entries) and _document_is_challenge(entries[-1])


def _origin(url) -> tuple:
    parsed = urlparse(str(url or ""))
    scheme = (parsed.scheme or "").lower()
    port = parsed.port or {"http": 80, "https": 443}.get(scheme)
    return scheme, (parsed.hostname or "").lower(), port


def _next_stage_on_origin(documents, origin) -> bool:
    """The newest document is a challenge on *origin*, the solve's own.

    A challenge after the site redirected to another origin is that origin's
    challenge, not a next stage of this one (www.glassdoor.com 301s to
    www.glassdoor.ca, and Cloudflare challenges both): solving it here was
    work the session then threw away, since it replays across the redirect
    with this origin's cookies and solves the other origin there.
    """
    entries = list(documents or ())
    if not entries or not _document_is_challenge(entries[-1]):
        return False
    return origin is None or _origin(entries[-1][0]) == origin


def _marked_challenge(entry) -> bool:
    """A document Cloudflare marked ``cf-mitigated: challenge`` (no fallback)."""
    response = entry[2] if len(entry) > 2 else None
    try:
        headers = response.headers if response is not None else None
    except Exception:
        return False
    return (
        isinstance(headers, dict)
        and str(headers.get("cf-mitigated", "")).lower() == "challenge"
    )


def cleared_in_passing(documents) -> bool:
    """A Cloudflare challenge document was followed by one that is not.

    *documents* is a list of main-frame ``(url, status, response)``. Only the
    ``cf-mitigated`` header counts here, never a bare status: an origin's own
    403 before a 200 earned no clearance.
    """
    entries = list(documents or ())
    if len(entries) < 2 or _document_is_challenge(entries[-1]):
        return False
    return any(_marked_challenge(entry) for entry in entries[:-1])


def _page_is_challenge(page) -> bool:
    """Check if the current page is still a CF challenge page."""
    try:
        title = page.title()
    except Exception:
        return True
    # Once the real page loads, the title changes away from the
    # CF challenge default.
    if title and "just a moment" not in title.lower():
        return False
    try:
        html = page.content()
    except Exception:
        return True
    head = html[:10000].lower()
    return any(m in head for m in _CF_CHALLENGE_MARKERS) or (
        loads_cf_challenge_platform(head)
    )


def wait_for_cloudflare(
    solver, page, timeout_ms: int, documents=None
) -> bool | None:
    """Wait for Cloudflare challenge to resolve.

    Handles both managed challenges (cType: 'managed', auto-solve
    via JS without user interaction) and interactive Turnstile
    challenges (require clicking the checkbox).

    Strategy:
    1. Click the Turnstile iframe body when found (handles
       interactive mode).  Retry every 5s in case first click
       didn't register.
    2. Poll for resolution: cf_clearance cookie OR page title/
       content changing away from the challenge page.

    *documents* is the solve's live list of main-frame
    ``(url, status, response)``. When given, ``cf_clearance`` counts only once
    the newest document is not a challenge: Cloudflare can answer the form
    POST that carries a solved first stage with a second challenge (a 429
    with Turnstile, stackoverflow.com 2026-11-03), and the first stage's
    clearance is already in the jar by then. Returning on it handed the
    session a clearance Cloudflare had just refused, so the replay was
    challenged again. Only a challenge on the solve's own origin is such a
    next stage; one after a redirect to another origin is left to the
    session's replay, as before.

    Returns ``True`` after authoritative solve evidence, ``False`` after an
    observed challenge fails to resolve, and ``None`` when no challenge iframe
    appears and (given *documents*) no challenge document is in the main
    frame. The caller may validate the successful main-document navigation
    as a pass-through only for that last, distinct outcome.
    """
    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    deadline = time.monotonic() + timeout_ms / 1000
    grace_deadline = time.monotonic() + 3.0
    iframe_seen = False
    last_click = -10.0

    rechallenge_logged = 0
    # When the newest document arrived, for the stall limit (the handler's
    # start, read once above).
    document_count = len(list(documents or ()))
    document_since = grace_deadline - 3.0
    # The origin this solve was sent for: its first main-frame document.
    origin = None

    while time.monotonic() < deadline:
        if origin is None and documents:
            origin = _origin(list(documents)[0][0])
        # cf_clearance is the solve signal, unless the newest document is a
        # challenge served after it was set on this origin (see the
        # docstring and _next_stage_on_origin).
        cookies = page.context.cookies()
        clearance = any(c["name"] == "cf_clearance" for c in cookies)
        on_challenge = documents is not None and _next_stage_on_origin(
            documents, origin
        )
        if clearance and not on_challenge:
            return True
        if clearance:
            entries = list(documents)
            if len(entries) > 1 and len(entries) != rechallenge_logged:
                # The first document is the challenge the solve was sent
                # for; a later one is Cloudflare asking again.
                rechallenge_logged = len(entries)
                logger.info(
                    "Cloudflare challenged again after clearance "
                    "(HTTP %s); solving the next stage",
                    entries[-1][1],
                )

        # Check if the challenge page has been replaced with real content
        # (title change or structural markers gone). A challenge document
        # still in the main frame is not real content, whatever its title.
        if (
            (iframe_seen or clearance)
            and not on_challenge
            and not _page_is_challenge(page)
        ):
            logger.info("Cloudflare challenge resolved (page changed)")
            return True

        # Find and interact with Turnstile iframe.
        # Click every 5s - handles both interactive (checkbox
        # needs click) and managed (click is harmless).
        cf_frame = None
        try:
            for frame in page.frames:
                if "challenges.cloudflare.com" in frame.url:
                    cf_frame = frame
                    break
        except Exception:
            pass

        if cf_frame is not None:
            iframe_seen = True
            now = time.monotonic()
            if now - last_click >= 5.0:
                try:
                    cf_frame.locator("body").click(timeout=2000)
                    last_click = time.monotonic()
                    logger.debug("Clicked Cloudflare Turnstile")
                except Exception:
                    pass

        # Early bail-out: no challenge iframe after grace period, and no
        # challenge document in the main frame either.
        if documents is not None:
            count = len(list(documents))
            if count != document_count:
                document_count = count
                document_since = time.monotonic()
        if not iframe_seen and time.monotonic() > grace_deadline:
            if not on_challenge and not clearance:
                logger.info(
                    "No Cloudflare challenge iframe after 3s, "
                    "browser likely passed through"
                )
                return None
            if (
                on_challenge
                and time.monotonic() - document_since > _STALLED_CHALLENGE_SECONDS
            ):
                logger.info(
                    "Cloudflare challenge did not move in %.0fs; giving up",
                    _STALLED_CHALLENGE_SECONDS,
                )
                return False

        solver._replay_browse_chunk(page, state, 2)

    return False


# A Turnstile widget a site runs in its own page, as its own gate (the page
# posts the token to its backend, which sets the site's cookie), as opposed to
# Cloudflare's interstitial. The page brings the widget up with its own
# scripts once it has loaded: one came up 7.4s after DOMContentLoaded on a
# Mac (2026-11-24). So the grace runs from the
# document's load, and a page that never finishes loading starts it after
# _PAGE_LOAD_CAP_SECONDS.
_PAGE_WIDGET_GRACE_SECONDS = 8.0
_PAGE_LOAD_CAP_SECONDS = 20.0

# After the token is issued, how long the page has to hand it to its backend
# and get the site's cookie back before the solve reports what it has.
_PAGE_TOKEN_SETTLE_SECONDS = 8.0

# The token's hidden field, under Turnstile's default name and id: 0 when the
# page has none, 1 while it is empty, 2 once it holds the token.
_TOKEN_FIELD_JS = (
    "() => { const fields = Array.from(document.querySelectorAll("
    "'input[name=\"cf-turnstile-response\"], input[id^=\"cf-chl-widget-\"]'));"
    " return fields.length === 0 ? 0 : fields.some((f) => !!f.value) ? 2 : 1; }"
)


def _is_cloudflare_cookie(name: str) -> bool:
    """Cloudflare's own cookies. Turnstile pre-clearance sets cf_clearance by
    itself, before the page does anything with its token, so a change to one
    of these is not the page's answer.
    """
    return name in ("cf_clearance", "__cf_bm", "_cfuvid") or name.startswith(
        "cf_chl"
    )


def _site_cookies(page, host: str) -> dict:
    """The page's own cookies for *host*, Cloudflare's left out:
    ``(name, domain, path) -> (value, http_only)``.
    """
    from wafer._cookies import browser_cookie_matches_host

    jar = {}
    for cookie in page.context.cookies():
        name = str(cookie.get("name", ""))
        if _is_cloudflare_cookie(name) or not browser_cookie_matches_host(
            str(cookie.get("domain", "")), host
        ):
            continue
        key = (name, cookie.get("domain"), cookie.get("path"))
        jar[key] = (cookie.get("value"), bool(cookie.get("httpOnly")))
    return jar


def _server_cookie_set(before: dict, now: dict) -> bool:
    """An HttpOnly cookie *now* holds that *before* did not. A page's script
    cannot set one, so it came from a response during the solve, and the
    page's answer to its own token is the response that matters here.
    """
    return any(
        http_only and before.get(key) != (value, http_only)
        for key, (value, http_only) in now.items()
    )


def _turnstile_frame(page):
    try:
        for frame in page.frames:
            if "challenges.cloudflare.com" in frame.url:
                return frame
    except Exception:
        pass
    return None


def _document_loaded(page) -> bool:
    try:
        return page.evaluate("() => document.readyState") == "complete"
    except Exception:
        return False


def _token_field(page) -> int:
    try:
        state = page.evaluate(_TOKEN_FIELD_JS)
    except Exception:
        return 0
    return state if state in (0, 1, 2) else 0


def _click_if_shown(frame, timeout_ms: int) -> bool:
    """Click the widget when it asks for interaction. In interaction-only
    mode the frame is there from the start but has no size until then, and a
    click on it would wait out its timeout.
    """
    if timeout_ms < 100:
        return False
    try:
        box = frame.frame_element().bounding_box()
        if not box or box.get("width", 0) < 1 or box.get("height", 0) < 1:
            return False
        frame.locator("body").click(timeout=min(2000, timeout_ms))
        return True
    except Exception:
        return False


def _settle(seconds: float, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining > 0:
        idle(min(seconds, remaining))


def wait_for_page_turnstile(
    solver, page, timeout_ms: int, documents=None
) -> bool:
    """Run the Turnstile widget the page itself embeds, and wait for the page
    to act on its token.

    For a Cloudflare block a site clears with its own session (see
    ``_turnstile_recovery_page`` in the session): the solve is sent to the page
    the blocked request comes from, which carries the widget. The page posts
    the token to its backend, and the cookie that answer sets is what the
    session's retry needs, so the token alone is not the end.

    Returns True once the page's own cookie for its host has changed in a way
    only the page's answer explains: an HttpOnly cookie a response set at any
    point in the solve (a script cannot set one); else, with the widget up, a
    change after its token when the token field is readable, or any change
    since just before the widget appeared when it is not (on the page this
    was built against it was not). A token with no cookie of the page's own
    within ``_PAGE_TOKEN_SETTLE_SECONDS`` also ends the wait (a rule keyed on
    Turnstile's cf_clearance needs nothing more). Returns False when the page
    shows no widget within ``_PAGE_WIDGET_GRACE_SECONDS`` of loading, when
    the page itself was refused, and at the deadline. The session's retry is
    what decides whether the block cleared.
    """
    start = time.monotonic()
    deadline = start + max(0, timeout_ms) / 1000
    entries = list(documents or ())
    if entries and isinstance(entries[-1][1], int) and entries[-1][1] >= 400:
        logger.info(
            "Page for the Turnstile solve answered HTTP %d; nothing to solve",
            entries[-1][1],
        )
        return False
    try:
        host = (urlparse(page.url).hostname or "").lower()
    except Exception:
        host = ""
    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    loaded_at = None
    widget_at = None
    token_at = None
    entry = _site_cookies(page, host)
    # The jar at the previous poll, and the one a change is measured from.
    previous = before = entry
    last_click = -10.0

    while time.monotonic() < deadline:
        now = time.monotonic()
        current = _site_cookies(page, host)
        # Checked before the widget: a widget that passes at once can be
        # gone (the page removes it) before a poll ever sees it.
        if _server_cookie_set(entry, current):
            logger.info(
                "Page's server set its own cookie %.1fs into the solve",
                now - start,
            )
            _settle(0.5, deadline)
            return True
        frame = _turnstile_frame(page)
        if widget_at is None:
            if frame is None:
                if loaded_at is None and (
                    now - start > _PAGE_LOAD_CAP_SECONDS or _document_loaded(page)
                ):
                    loaded_at = now
                if (
                    loaded_at is not None
                    and now - loaded_at > _PAGE_WIDGET_GRACE_SECONDS
                ):
                    logger.info(
                        "No Turnstile widget on the page %.0fs after it loaded",
                        _PAGE_WIDGET_GRACE_SECONDS,
                    )
                    return False
                previous = current
                solver._replay_browse_chunk(
                    page, state, min(0.5, max(0.0, deadline - time.monotonic()))
                )
                continue
            widget_at = now
            if loaded_at is None:
                logger.info("Turnstile widget on the page after %.1fs", now - start)
            else:
                logger.info(
                    "Turnstile widget on the page after %.1fs (%.1fs after load)",
                    now - start,
                    now - loaded_at,
                )
            # From the poll before the widget was seen: what the page set in
            # the interval it appeared in counts.
            before = previous

        if token_at is None:
            field = _token_field(page)
            if field == 2:
                token_at = now
                logger.info(
                    "Turnstile token issued %.1fs after the widget appeared",
                    now - widget_at,
                )
            elif field == 1:
                # The token is still coming: keep the newest jar from before
                # it, so a cookie another script sets meanwhile (analytics)
                # is not taken for the page's answer.
                before = current
            elif current != before:
                # No token field to read (the page turned off response-field
                # or renamed it): the page's own cookie changing once the
                # widget is up is the answer there is.
                logger.info(
                    "Page set its own cookie %.1fs after the widget appeared",
                    now - widget_at,
                )
                _settle(1.0, deadline)
                return True
        if token_at is not None:
            if current != before:
                logger.info(
                    "Page set its own cookie %.1fs after the token",
                    now - token_at,
                )
                _settle(0.5, deadline)
                return True
            if now - token_at > _PAGE_TOKEN_SETTLE_SECONDS:
                logger.info(
                    "Turnstile token issued; the page set no cookie of its "
                    "own within %.0fs",
                    _PAGE_TOKEN_SETTLE_SECONDS,
                )
                return True

        if (
            frame is not None
            and now - last_click >= 5.0
            and _click_if_shown(frame, int((deadline - time.monotonic()) * 1000))
        ):
            last_click = time.monotonic()
            logger.debug("Clicked the page's Turnstile widget")
        previous = current
        solver._replay_browse_chunk(
            page, state, min(0.5, max(0.0, deadline - time.monotonic()))
        )

    logger.info("Page's Turnstile did not finish before the deadline")
    return False
