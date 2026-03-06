"""DataDome challenge solver.

Handles two DataDome interstitial types that we can reliably solve:

1. **Auto-resolve** - DD's WASM PoW (plv3) runs in the background and
   sets the ``datadome`` cookie automatically.  No interaction needed.
   This is the most common path for sites like etsy, allegro, etc.
2. **Confirm button** - A "confirm you are human" button inside the
   ``captcha-delivery`` iframe.  Clicked with mouse replay.

If DD escalates beyond these (audio captcha, puzzle slider, slide-right),
we bail out immediately.  DD's behavioral analysis detects CDP-dispatched
input events during interactive challenges - even correct answers are
rejected.  See ``docs/ref-datadome.md`` for details.
"""

import logging
import random
import time

logger = logging.getLogger("wafer")


def _find_dd_frame(page):
    """Find the DataDome captcha-delivery iframe."""
    for frame in page.frames:
        if "captcha-delivery" in frame.url:
            return frame
    return None


def _is_hard_block(dd_frame) -> bool:
    """Check if the DD iframe shows a hard block (unsolvable).

    Hard blocks show "blocked" or "restricted" text with no interactive
    challenge elements.  These cannot be solved and waiting is pointless.
    """
    try:
        text = dd_frame.evaluate("""() => {
            const el = document.querySelector(
                '[data-dd-captcha-human-title]'
            );
            return el ? el.textContent.trim().toLowerCase() : '';
        }""")
        if text and ("restricted" in text or "blocked" in text):
            return True
    except Exception:
        pass
    return False


def _try_click_confirm(solver, page, dd_frame, state) -> bool:
    """Click the DataDome confirm button if visible."""
    try:
        btn = dd_frame.locator(
            "button.captcha_display_button_submit"
        )
        if btn.is_visible(timeout=1000):
            box = btn.bounding_box(timeout=2000)
            if box:
                target_x = box["x"] + box["width"] / 2
                target_y = box["y"] + box["height"] / 2
                try:
                    solver._replay_path(
                        page,
                        state.current_x
                        if state
                        else random.uniform(400, 800),
                        state.current_y
                        if state
                        else random.uniform(200, 400),
                        target_x,
                        target_y,
                    )
                except Exception:
                    page.mouse.move(target_x, target_y)
                time.sleep(random.uniform(0.1, 0.3))
                page.mouse.click(target_x, target_y)
                logger.debug("Clicked DataDome confirm button")
                return True
            else:
                logger.debug("DD confirm button: no bounding box")
        else:
            logger.debug("DD confirm button not visible (1s timeout)")
    except Exception as e:
        logger.debug("DD confirm check error: %s", e)
    return False


def _click_element(solver, page, state, locator):
    """Click an element using human-like mouse path."""
    box = locator.bounding_box(timeout=2000)
    if not box:
        return False
    target_x = box["x"] + box["width"] / 2
    target_y = box["y"] + box["height"] / 2
    try:
        solver._replay_path(
            page,
            state.current_x if state else random.uniform(400, 800),
            state.current_y if state else random.uniform(200, 400),
            target_x,
            target_y,
        )
    except Exception:
        page.mouse.move(target_x, target_y)
    time.sleep(random.uniform(0.1, 0.3))
    page.mouse.click(target_x, target_y)
    return True


def wait_for_datadome(solver, page, timeout_ms: int) -> bool:
    """Wait for DataDome challenge to resolve.

    Returns False immediately if the page URL contains ``t=bv`` --- this
    indicates a "blocked visitor" verdict that cannot be solved.

    Early bail-out: if no captcha-delivery iframe appears within 8
    seconds, returns False (browser passed through without challenge).
    """
    # t=bv = blocked visitor, unsolvable
    try:
        if "t=bv" in page.url:
            logger.warning("DataDome t=bv (blocked visitor), skipping")
            return False
    except Exception:
        pass

    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    deadline = time.monotonic() + timeout_ms / 1000
    grace_deadline = time.monotonic() + 8.0

    # Capture initial datadome cookie value (if any) to detect change
    initial_dd = None
    for c in page.context.cookies():
        if c["name"] == "datadome":
            initial_dd = c["value"]
            break

    iframe_seen = False
    iframe_first_seen = None
    hard_block_checked = False
    confirmed = False

    while time.monotonic() < deadline:
        # Check for t=bv redirect mid-solve
        try:
            if "t=bv" in page.url:
                logger.warning(
                    "DataDome redirected to t=bv, solve failed"
                )
                return False
        except Exception:
            pass

        # Check if datadome cookie value changed (solve signal).
        # After cookie change, wait for the DD challenge iframe to
        # disappear - DD's JS redirects the page to real content.
        # If the iframe persists, the cookie change was a rejection
        # (new attempt cookie), not a clearance cookie.
        cookies = page.context.cookies()
        for c in cookies:
            if c["name"] == "datadome" and c["value"] != initial_dd:
                # Wait up to 10s for redirect to real content
                redirect_deadline = min(
                    time.monotonic() + 10, deadline
                )
                while time.monotonic() < redirect_deadline:
                    if not _find_dd_frame(page):
                        # DD iframe gone - real solve
                        solver._replay_browse_chunk(
                            page, state, 0.5
                        )
                        return True
                    solver._replay_browse_chunk(page, state, 1)
                # DD iframe persists - solve was rejected
                logger.debug(
                    "DD cookie changed but iframe persists "
                    "(rejection, not clearance)"
                )
                initial_dd = c["value"]
                confirmed = False
                break

        # Find the DD captcha-delivery iframe
        dd_frame = _find_dd_frame(page)
        if dd_frame:
            if not iframe_seen:
                iframe_first_seen = time.monotonic()
                from wafer.browser._solver import (
                    patch_frame_headless,
                    patch_frame_screenxy,
                )
                patch_frame_screenxy(dd_frame)
                if solver._headless:
                    patch_frame_headless(dd_frame)
            iframe_seen = True

            # Phase 1: click confirm button (if present)
            if not confirmed:
                if _try_click_confirm(solver, page, dd_frame, state):
                    confirmed = True
                    solver._replay_browse_chunk(page, state, 2)
                    continue

            # If DD escalates beyond confirm/PoW (audio captcha,
            # slider puzzle, slide-right), bail out.  DD's behavioral
            # analysis detects CDP-dispatched input events during
            # interactive challenges - even correct answers are
            # rejected.  Only PoW auto-resolve and confirm button
            # work reliably.  See docs/ref-datadome.md.
            if iframe_first_seen and time.monotonic() - iframe_first_seen > 5.0:
                if not hard_block_checked:
                    hard_block_checked = True
                    if _is_hard_block(dd_frame):
                        logger.warning(
                            "DataDome hard block detected "
                            "(IP/device flagged), cannot solve"
                        )
                    else:
                        logger.warning(
                            "DataDome escalated to interactive "
                            "challenge (unsolvable), bailing out"
                        )
                    return False

        # Early bail-out: no DD iframe after grace period
        if not iframe_seen and time.monotonic() > grace_deadline:
            logger.info(
                "No DataDome challenge iframe after 8s, "
                "browser likely passed through"
            )
            return False

        solver._replay_browse_chunk(page, state, 1)

    return False
