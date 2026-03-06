"""Cloudflare challenge solver."""

import logging
import random
import time

logger = logging.getLogger("wafer")

# Markers that identify a CF challenge page.  The title "Just a moment"
# persists even after "Verification successful" appears, so we only
# check structural markers from the challenge scaffold.
_CF_CHALLENGE_MARKERS = ("cf_chl", "challenge-platform", "chl_page")


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


def wait_for_cloudflare(solver, page, timeout_ms: int) -> bool:
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

    Early bail-out: if no challenges.cloudflare.com iframe appears
    within 3 seconds, returns False immediately.  This handles the
    "WAF-transparent-to-browser" pattern where the browser gets 200
    instantly with no challenge.
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

    while time.monotonic() < deadline:
        # Check for cf_clearance cookie (definitive solve signal)
        cookies = page.context.cookies()
        if any(c["name"] == "cf_clearance" for c in cookies):
            return True

        # Check if the challenge page has been replaced with
        # real content (title change or structural markers gone).
        if iframe_seen and not _page_is_challenge(page):
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
            if not iframe_seen:
                from wafer.browser._solver import patch_frame_screenxy
                patch_frame_screenxy(cf_frame)
            iframe_seen = True
            now = time.monotonic()
            if now - last_click >= 5.0:
                try:
                    cf_frame.locator("body").click(timeout=2000)
                    last_click = time.monotonic()
                    logger.debug("Clicked Cloudflare Turnstile")
                except Exception:
                    pass

        # Early bail-out: no challenge iframe after grace period
        if not iframe_seen and time.monotonic() > grace_deadline:
            logger.info(
                "No Cloudflare challenge iframe after 3s, "
                "browser likely passed through"
            )
            return False

        solver._replay_browse_chunk(page, state, 2)

    return False
