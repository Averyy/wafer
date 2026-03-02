"""DataDome challenge solver.

Handles four DataDome interstitial types:

1. **Auto-resolve** — DD's WASM PoW runs in the background and sets
   the ``datadome`` cookie automatically.  No interaction needed.
2. **Confirm button** — A "confirm you are human" button inside the
   ``captcha-delivery`` iframe.  Clicked with mouse replay.
3. **Puzzle slider** — A jigsaw slider (forked from ArgoZhang/SliderCaptcha)
   inside ``#ddv1-captcha-container``.  CV detects the notch offset in
   the background canvas, then drags the handle to the correct position
   using mousse recordings.
4. **Slide-right** — A "slide right to secure your access" slider
   (Dec 2025+).  No canvas/puzzle - just drag the handle to the right
   end of the track.
"""

import base64
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
    except Exception:
        pass
    return False


def _extract_puzzle_images(dd_frame) -> tuple[bytes | None, bytes | None]:
    """Extract bg and piece canvas images from DD slider widget.

    The puzzle widget (ArgoZhang/SliderCaptcha) creates two canvases
    inside ``#ddv1-captcha-container``: a background with the notch
    cutout and a ``canvas.block`` with the jigsaw piece.
    """
    try:
        result = dd_frame.evaluate("""() => {
            const container = document.querySelector(
                '#ddv1-captcha-container'
            );
            if (!container) return null;
            const canvases = container.querySelectorAll('canvas');
            if (canvases.length < 2) return null;
            let bg = null, piece = null;
            for (const c of canvases) {
                if (c.classList.contains('block')) {
                    piece = c.toDataURL('image/png');
                } else if (!bg) {
                    bg = c.toDataURL('image/png');
                }
            }
            if (!bg || !piece) return null;
            return {bg, piece};
        }""")
        if not result:
            return None, None
        bg = base64.b64decode(result["bg"].split(",", 1)[1])
        piece = base64.b64decode(result["piece"].split(",", 1)[1])
        return bg, piece
    except Exception:
        logger.debug("DD puzzle image extraction failed", exc_info=True)
        return None, None


def _get_slider_dims(dd_frame) -> dict | None:
    """Get slider track and canvas dimensions from DD iframe."""
    try:
        return dd_frame.evaluate("""() => {
            const track = document.querySelector('.sliderContainer');
            const container = document.querySelector(
                '#ddv1-captcha-container'
            );
            if (!track || !container) return null;
            const bgCanvas = container.querySelector(
                'canvas:not(.block)'
            );
            if (!bgCanvas) return null;
            return {
                trackWidth: track.offsetWidth,
                canvasWidth: bgCanvas.width,
                canvasRenderedWidth:
                    bgCanvas.getBoundingClientRect().width,
            };
        }""")
    except Exception:
        return None


def _get_track_width(dd_frame) -> float | None:
    """Get the sliderContainer track width in CSS pixels."""
    try:
        return dd_frame.evaluate("""() => {
            const track = document.querySelector('.sliderContainer');
            return track ? track.offsetWidth : null;
        }""")
    except Exception:
        return None


def _check_slider_result(dd_frame) -> bool | None:
    """Check DD slider result.  True=solved, False=failed, None=pending."""
    try:
        return dd_frame.evaluate("""() => {
            const sc = document.querySelector('.sliderContainer');
            if (!sc) return null;
            const cls = sc.className || '';
            if (cls.includes('sliderContainer_success')) return true;
            if (cls.includes('sliderContainer_fail')) return false;
            return null;
        }""")
    except Exception:
        return None


def _drag_to_target(solver, page, dd_frame, state, box, end_x, end_y):
    """Move to handle center and drag to (end_x, end_y)."""
    handle_cx = box["x"] + box["width"] / 2
    handle_cy = box["y"] + box["height"] / 2

    try:
        solver._replay_path(
            page,
            state.current_x
            if state
            else random.uniform(400, 800),
            state.current_y
            if state
            else random.uniform(200, 400),
            handle_cx,
            handle_cy,
        )
    except Exception:
        page.mouse.move(handle_cx, handle_cy)

    time.sleep(random.uniform(0.1, 0.3))
    solver._replay_drag(page, handle_cx, handle_cy, end_x, end_y)

    # Check result (sliderContainer_success / _fail classes)
    for _ in range(10):
        time.sleep(0.3)
        result = _check_slider_result(dd_frame)
        if result is True:
            return True
        if result is False:
            return False

    # No clear result - let the cookie check in the main loop decide
    return True


def _try_slide_right(solver, page, dd_frame, state, box) -> bool:
    """Slide-right challenge: drag handle to right end of track."""
    track_width = _get_track_width(dd_frame)
    if not track_width:
        logger.debug("DD slide-right: could not read track width")
        return False

    handle_w = box["width"]
    # Drag to the end of the track (tiny random variance)
    travel = track_width - handle_w - random.uniform(0, 1)
    if travel <= 0:
        return False

    handle_cx = box["x"] + handle_w / 2
    handle_cy = box["y"] + box["height"] / 2
    end_x = handle_cx + travel
    end_y = handle_cy

    logger.info(
        "DD slide-right: track=%d handle=%d travel=%.1fpx "
        "(%.0f,%.0f)->(%.0f,%.0f)",
        track_width, handle_w, travel,
        handle_cx, handle_cy, end_x, end_y,
    )

    ok = _drag_to_target(solver, page, dd_frame, state, box, end_x, end_y)
    if ok:
        logger.info("DD slide-right solved!")
    else:
        logger.info("DD slide-right rejected")
    return ok


def _try_drag_slider(solver, page, dd_frame, state) -> bool:
    """Solve DataDome slider challenge.

    Handles two slider variants:

    1. **Jigsaw puzzle** (ArgoZhang/SliderCaptcha) - two canvases inside
       ``#ddv1-captcha-container``.  CV detects the notch offset, then
       drags the handle to the matching position.
    2. **Slide-right** - no canvases, just drag the handle to the right
       end of the track.
    """
    try:
        handle = dd_frame.locator(".sliderContainer .slider")
        if handle.count() == 0:
            return False
        if not handle.first.is_visible(timeout=2000):
            return False

        # Page-level handle coordinates (Playwright handles iframe offset)
        box = handle.first.bounding_box(timeout=2000)
        if not box:
            return False

        # Extract puzzle images from canvas elements
        bg_png, piece_png = _extract_puzzle_images(dd_frame)

        # No canvases -> slide-right variant
        if not bg_png or not piece_png:
            logger.debug("DD: No puzzle canvases, trying slide-right")
            return _try_slide_right(
                solver, page, dd_frame, state, box
            )

        # Jigsaw puzzle path
        logger.debug(
            "DD puzzle images: bg=%d bytes, piece=%d bytes",
            len(bg_png), len(piece_png),
        )

        # CV notch detection (reuses GeeTest's find_notch)
        from wafer.browser._cv import find_notch

        x_offset, confidence = find_notch(bg_png, piece_png)
        logger.info(
            "DD CV notch: x=%d confidence=%.3f", x_offset, confidence
        )
        if confidence < 0.10:
            logger.warning("DD CV confidence too low (%.3f)", confidence)
            return False

        # Track and canvas dimensions (widths are scale-invariant)
        dims = _get_slider_dims(dd_frame)
        if not dims:
            logger.error("DD: Could not read slider dimensions")
            return False

        canvas_native_w = dims["canvasWidth"]
        canvas_rendered_w = dims["canvasRenderedWidth"]
        handle_w = box["width"]

        # Map CV pixel offset to handle travel distance.
        # ArgoZhang: blockLeft = (w-60)/(w-40) * moveX
        # w = canvas_native_w + 2 (sliderCaptcha creates canvas w-2 wide)
        # Solve for moveX: moveX = target_x / ((w-60)/(w-40))
        w = canvas_native_w + 2
        max_slide = w - 40  # max handle travel in native units
        if max_slide <= 0:
            return False
        block_scale = (w - 60) / max_slide if max_slide > 20 else 1.0

        # Scale notch position to rendered coordinates
        x_rendered = x_offset * canvas_rendered_w / canvas_native_w
        handle_travel = (
            x_rendered / block_scale if block_scale > 0 else x_rendered
        )

        handle_cx = box["x"] + handle_w / 2
        handle_cy = box["y"] + box["height"] / 2
        end_x = handle_cx + handle_travel
        end_y = handle_cy

        logger.info(
            "DD drag: notch=%d w=%d scale=%.3f travel=%.1fpx "
            "(%.0f,%.0f)->(%.0f,%.0f)",
            x_offset, w, block_scale,
            handle_travel, handle_cx, handle_cy, end_x, end_y,
        )

        ok = _drag_to_target(
            solver, page, dd_frame, state, box, end_x, end_y
        )
        if ok:
            logger.info("DD puzzle slider solved!")
        else:
            logger.info("DD puzzle slider rejected (wrong pos)")
        return ok
    except Exception:
        logger.debug("DD slider drag failed", exc_info=True)
        return False


def wait_for_datadome(solver, page, timeout_ms: int) -> bool:
    """Wait for DataDome challenge to resolve.

    Returns False immediately if the page URL contains ``t=bv`` — this
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
    confirmed = False
    slid = False

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

        # Check if datadome cookie value changed (solve signal)
        cookies = page.context.cookies()
        for c in cookies:
            if c["name"] == "datadome" and c["value"] != initial_dd:
                solver._replay_browse_chunk(page, state, 0.5)
                return True

        # Find the DD captcha-delivery iframe
        dd_frame = _find_dd_frame(page)
        if dd_frame:
            iframe_seen = True

            # Phase 1: click confirm button
            if not confirmed:
                if _try_click_confirm(solver, page, dd_frame, state):
                    confirmed = True
                    # Wait for slider widget to load after confirm
                    solver._replay_browse_chunk(page, state, 2)
                    continue

            # Phase 2: solve puzzle slider
            if not slid:
                solver._ensure_recordings()
                if _try_drag_slider(solver, page, dd_frame, state):
                    slid = True
                    solver._replay_browse_chunk(page, state, 2)
                    continue

        # Early bail-out: no DD iframe after grace period
        if not iframe_seen and time.monotonic() > grace_deadline:
            logger.info(
                "No DataDome challenge iframe after 8s, "
                "browser likely passed through"
            )
            return False

        solver._replay_browse_chunk(page, state, 1)

    return False
