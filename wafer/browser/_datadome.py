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
from urllib.parse import urlparse

from wafer._cookies import browser_cookie_matches_host
from wafer.browser._pump import idle

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
                idle(random.uniform(0.1, 0.3))
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
    idle(random.uniform(0.1, 0.3))
    page.mouse.click(target_x, target_y)
    return True


def _let_through(page) -> bool:
    """Whether DataDome let the browser through on its first request.

    DataDome answers a request it trusts with the page itself and sets its
    ``datadome`` cookie on that response, with no challenge to watch for a
    cookie change. On mouser.com the browser was served the 200 page and the
    cookie from its first navigation while the plain client drew the 403
    (1 of 16 solves, 2026-11-04); treated as a failed solve, it threw both
    away and the request failed with the challenge.

    The status is the displayed document's own (its navigation timing entry),
    not the newest response seen: a 200 still on its way in is not what the
    page shows.
    """
    from wafer.browser._solver import _quiet_read

    try:
        host = urlparse(page.url).hostname or ""
        status = _quiet_read(
            page,
            "(performance.getEntriesByType('navigation')[0] || {}).responseStatus",
        )
        cookies = page.context.cookies()
    except Exception:
        return False
    if not host or not isinstance(status, int) or not 200 <= status < 300:
        return False
    return any(
        c.get("name") == "datadome"
        and c.get("value")
        and browser_cookie_matches_host(c.get("domain", ""), host)
        for c in cookies
    )


def wait_for_datadome(solver, page, timeout_ms: int) -> bool:
    """Wait for DataDome challenge to resolve.

    Returns False immediately if the page URL contains ``t=bv`` --- this
    indicates a "blocked visitor" verdict that cannot be solved.

    Early bail-out: if no captcha-delivery iframe appears within 8
    seconds, the browser met no challenge. That is a pass when DataDome let it
    through (the displayed document is a 2xx and a ``datadome`` cookie is set
    for the page's host), and a failure otherwise.
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
            if _let_through(page):
                logger.info(
                    "No DataDome challenge after 8s: the browser was let "
                    "through with DataDome's cookie"
                )
                return True
            logger.info(
                "No DataDome challenge iframe after 8s, "
                "browser likely passed through"
            )
            return False

        solver._replay_browse_chunk(page, state, 1)

    return False
