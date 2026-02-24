"""reCAPTCHA v2 checkbox + image grid solver."""

import logging
import random
import time

logger = logging.getLogger("wafer")


def _find_bframe(page):
    """Find the reCAPTCHA bframe (challenge iframe)."""
    for frame in page.frames:
        if "/recaptcha/api2/bframe" in frame.url:
            return frame
    return None


def _check_token(page) -> bool:
    """Check if the g-recaptcha-response token is populated."""
    try:
        token = page.eval_on_selector(
            'textarea[name="g-recaptcha-response"]',
            "el => el.value",
        )
        return bool(token)
    except Exception:
        return False


def _click_element(solver, page, state, frame, selector):
    """Click an element using mouse path replay or direct click."""
    try:
        box = frame.locator(selector).bounding_box(timeout=3000)
    except Exception:
        return False

    if not box:
        return False

    target_x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
    target_y = box["y"] + box["height"] * random.uniform(0.3, 0.7)

    try:
        solver._replay_path(
            page,
            state.current_x if state else random.uniform(300, 600),
            state.current_y if state else random.uniform(200, 400),
            target_x,
            target_y,
        )
    except Exception:
        page.mouse.move(target_x, target_y)

    time.sleep(random.uniform(0.08, 0.22))
    page.mouse.click(target_x, target_y)
    return True


def wait_for_recaptcha(solver, page, timeout_ms: int) -> bool:
    """Wait for reCAPTCHA v2 checkbox challenge to resolve.

    Clicks the checkbox in the google.com/recaptcha iframe and polls
    for the g-recaptcha-response token.  If Google escalates to an
    image challenge, solves it via the image grid solver (ONNX).

    Early bail-out: if no recaptcha iframe appears within 5 seconds,
    returns False (browser likely passed through without challenge).
    """
    # Set up payload intercept BEFORE checkbox click - the payload
    # response fires during challenge load and we need the image for
    # the grid solver.
    from wafer.browser._recaptcha_grid import _setup_payload_intercept

    payload_state = _setup_payload_intercept(page)

    def _cleanup_listener():
        try:
            payload_state["cleanup"]()
        except Exception:
            pass

    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    # Natural "reading the page" before interacting with CAPTCHA.
    solver._replay_browse_chunk(page, state, random.uniform(1.5, 3.0))
    deadline = time.monotonic() + timeout_ms / 1000
    grace_deadline = time.monotonic() + 5.0
    iframe_seen = False
    checkbox_clicked = False

    # Phase 1: Click checkbox and wait for auto-pass or bframe escalation.
    while time.monotonic() < deadline:
        if _check_token(page):
            logger.info("reCAPTCHA solved, token obtained")
            _cleanup_listener()
            return True

        # Find and click the checkbox iframe
        if not checkbox_clicked:
            try:
                for frame in page.frames:
                    is_anchor = (
                        "google.com/recaptcha" in frame.url
                        and "/recaptcha/api2/anchor" in frame.url
                    )
                    if is_anchor:
                        iframe_seen = True
                        if _click_element(
                            solver, page, state, frame,
                            ".recaptcha-checkbox-border",
                        ):
                            checkbox_clicked = True
                            logger.debug("Clicked reCAPTCHA checkbox")
                        break
            except Exception:
                pass
        else:
            # Only check for bframe AFTER checkbox click - reCAPTCHA
            # pre-loads the bframe iframe, so its URL exists before
            # the user interacts.  Detect escalation by checking if
            # the challenge content is visible inside the bframe.
            bframe = _find_bframe(page)
            if bframe:
                try:
                    visible = bframe.locator(
                        ".rc-imageselect-challenge"
                    ).is_visible(timeout=300)
                    if visible:
                        break
                except Exception:
                    pass

        if not iframe_seen and time.monotonic() > grace_deadline:
            logger.info(
                "No reCAPTCHA iframe after 5s, "
                "browser likely passed through"
            )
            _cleanup_listener()
            return False

        solver._replay_browse_chunk(page, state, 1)
    else:
        # Timed out without bframe or token
        _cleanup_listener()
        return False

    # Grab bframe reference for image grid phase
    bframe = _find_bframe(page)
    if not bframe:
        _cleanup_listener()
        return False

    # Phase 2: Solve image grid challenge.
    logger.info("reCAPTCHA escalated to image challenge")

    # Wait for bframe DOM to load (URL appears before content)
    try:
        bframe.wait_for_load_state("domcontentloaded", timeout=5000)
    except Exception:
        pass

    if time.monotonic() < deadline:
        from wafer.browser._recaptcha_grid import solve_image_grid

        if solve_image_grid(
            solver, page, bframe, state, deadline,
            payload=payload_state.get("payload"),
        ):
            _cleanup_listener()
            return True

    _cleanup_listener()
    return False
