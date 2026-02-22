"""Cloudflare challenge solver."""

import logging
import random
import time

logger = logging.getLogger("wafer")


def wait_for_cloudflare(solver, page, timeout_ms: int) -> bool:
    """Wait for Cloudflare challenge to resolve.

    Handles both managed challenges (auto-solve) and interactive
    Turnstile challenges (require clicking the checkbox in the
    challenges.cloudflare.com iframe).

    Polls for cf_clearance cookie as the definitive signal.
    Clicks the Turnstile body on every iteration until resolved,
    since the first click may not always register.

    Early bail-out: if no challenges.cloudflare.com iframe appears
    within 3 seconds, returns False immediately.  This handles the
    "WAF-transparent-to-browser" pattern where the browser gets 200
    instantly with no challenge — saves ~27-57s vs polling to timeout.
    """
    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    deadline = time.monotonic() + timeout_ms / 1000
    grace_deadline = time.monotonic() + 3.0
    iframe_seen = False

    while time.monotonic() < deadline:
        # Check for cf_clearance cookie (definitive solve signal)
        cookies = page.context.cookies()
        if any(c["name"] == "cf_clearance" for c in cookies):
            return True

        # Click Turnstile on every iteration (first click may
        # not register; retrying is harmless and necessary)
        try:
            for frame in page.frames:
                if "challenges.cloudflare.com" in frame.url:
                    iframe_seen = True
                    frame.locator("body").click(timeout=2000)
                    logger.debug("Clicked Cloudflare Turnstile")
                    break
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
