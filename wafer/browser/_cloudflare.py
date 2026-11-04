"""Cloudflare challenge solver."""

import logging
import random
import time
from urllib.parse import urlparse

logger = logging.getLogger("wafer")

# Markers that identify a CF challenge page.  The title "Just a moment"
# persists even after "Verification successful" appears, so we only
# check structural markers from the challenge scaffold.
_CF_CHALLENGE_MARKERS = ("cf_chl", "challenge-platform", "chl_page")


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
    return any(m in head for m in _CF_CHALLENGE_MARKERS)


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
