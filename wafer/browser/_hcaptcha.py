"""hCaptcha checkbox solver."""

import logging
import random
import time

logger = logging.getLogger("wafer")


def _find_frame(page, fragment: str):
    """Find an hCaptcha iframe by URL fragment (e.g. 'frame=checkbox')."""
    for frame in page.frames:
        if "hcaptcha" in frame.url and fragment in frame.url:
            return frame
    return None


def wait_for_hcaptcha(solver, page, timeout_ms: int) -> bool:
    """Wait for hCaptcha checkbox challenge to resolve.

    Simulates natural browsing behavior before clicking the checkbox
    to reduce hCaptcha's risk score:

    1. Browse replay (2-4s) — natural mouse/scroll while "reading" page
    2. Mouse path to checkbox — recorded human trajectory
    3. Click + poll for token or image escalation

    If the challenge escalates to an image grid, logs a warning and
    returns False (no image solver yet).
    """
    deadline = time.monotonic() + timeout_ms / 1000

    # Phase 1: Browse replay while waiting for iframe to load.
    # Natural "reading the page" behavior before interacting.
    browse_duration = random.uniform(2.0, 4.0)
    state = solver._start_browse(
        page,
        random.uniform(300, 600),
        random.uniform(200, 400),
    )
    solver._replay_browse_chunk(page, state, browse_duration)

    # Phase 2: Wait for checkbox frame to appear.
    grace_deadline = time.monotonic() + 5.0
    cb_frame = None
    while time.monotonic() < grace_deadline:
        cb_frame = _find_frame(page, "frame=checkbox")
        if cb_frame:
            break
        time.sleep(0.3)

    if not cb_frame:
        logger.info(
            "No hCaptcha checkbox iframe after wait, "
            "browser likely passed through"
        )
        return False

    # Phase 3: Move mouse naturally to checkbox, then click.
    try:
        box = cb_frame.locator("#checkbox").bounding_box(timeout=3000)
    except Exception:
        logger.debug("hCaptcha #checkbox not found in iframe")
        return False

    if not box:
        return False

    target_x = box["x"] + box["width"] / 2
    target_y = box["y"] + box["height"] / 2

    # Use recorded human mouse path to approach the checkbox
    try:
        solver._replay_path(
            page,
            state.current_x if state else random.uniform(300, 600),
            state.current_y if state else random.uniform(200, 400),
            target_x,
            target_y,
        )
    except Exception:
        # Fall back to direct move if no path recordings
        page.mouse.move(target_x, target_y)

    # Brief hover before clicking (humans don't click instantly)
    time.sleep(random.uniform(0.1, 0.3))
    page.mouse.click(target_x, target_y)
    logger.debug("Clicked hCaptcha checkbox at (%.0f, %.0f)", target_x, target_y)

    # Phase 4: Poll for token or image escalation.
    while time.monotonic() < deadline:
        # Check for solved token
        try:
            token = page.eval_on_selector(
                'textarea[name="h-captcha-response"]',
                "el => el.value",
            )
            if token:
                logger.debug("hCaptcha solved, token obtained")
                return True
        except Exception:
            pass

        # Check for image challenge escalation
        ch_frame = _find_frame(page, "frame=challenge")
        if ch_frame:
            try:
                visible = ch_frame.locator(
                    ".challenge-container"
                ).is_visible(timeout=500)
                if visible:
                    logger.warning(
                        "hCaptcha escalated to image challenge, "
                        "no image solver available"
                    )
                    return False
            except Exception:
                pass

        solver._replay_browse_chunk(page, state, 1)

    return False
