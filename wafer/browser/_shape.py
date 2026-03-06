"""F5 Shape challenge solver."""

import logging
import random
import time

logger = logging.getLogger("wafer")


def wait_for_shape(solver, page, timeout_ms: int) -> bool:
    """Wait for F5 Shape interstitial challenge to resolve.

    Shape serves a 200-status interstitial page containing the
    ``istlWasHere`` marker. After JS VM execution (~2-5s), the page
    navigates away from the interstitial and sets deployment-specific
    cookies. We poll for the marker to disappear from the DOM.
    """
    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    deadline = time.monotonic() + timeout_ms / 1000

    while time.monotonic() < deadline:
        try:
            content = page.content()
            if "istlwashere" not in content.lower():
                solver._replay_browse_chunk(page, state, 1)
                # Verify we landed on real content, not a block page.
                # F5 Shape redirects blocked clients to a soft-block
                # page (e.g. siteclosed.nordstrom.com/invitation.html)
                # that also lacks istlWasHere.
                url = page.url.lower()
                if "invitation" in url or "siteclosed" in url:
                    logger.warning(
                        "Shape redirected to block page: %s",
                        page.url,
                    )
                    return False
                return True
        except Exception:
            pass
        solver._replay_browse_chunk(page, state, 2)

    return False
