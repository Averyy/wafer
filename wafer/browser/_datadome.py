"""DataDome challenge solver.

Handles five DataDome interstitial types:

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
5. **Audio captcha** — 6 spoken digits, transcribed with faster-whisper
   (tiny model) and typed into input fields.  Preferred over slider
   when available.
"""

import base64
import logging
import os
import random
import re
import tempfile
import threading
import time
import urllib.request

logger = logging.getLogger("wafer")

# ---------------------------------------------------------------------------
# Whisper model (lazy, thread-safe) for audio captcha transcription
# ---------------------------------------------------------------------------
_whisper_model = None
_whisper_unavailable = False
_whisper_lock = threading.Lock()


def _ensure_whisper():
    """Load faster-whisper tiny model on first use. Thread-safe."""
    global _whisper_model, _whisper_unavailable
    if _whisper_unavailable or _whisper_model is not None:
        return _whisper_model
    with _whisper_lock:
        if _whisper_unavailable or _whisper_model is not None:
            return _whisper_model
        try:
            from faster_whisper import WhisperModel
            _whisper_model = WhisperModel("tiny", compute_type="int8")
            logger.debug("Whisper tiny model loaded")
        except Exception:
            logger.debug("faster-whisper unavailable", exc_info=True)
            _whisper_unavailable = True
        return _whisper_model


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
    # Drag the full track width - the handle is constrained by CSS,
    # and the mouse naturally overshoots past the end.
    travel = track_width - random.uniform(0, 2)
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

    # Swap to slide recordings for full-width confident drag profile
    orig_drags = solver._drag_recordings
    if solver._slide_recordings:
        solver._drag_recordings = solver._slide_recordings
    try:
        ok = _drag_to_target(
            solver, page, dd_frame, state, box, end_x, end_y
        )
    finally:
        solver._drag_recordings = orig_drags

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


def _try_audio_captcha(solver, page, dd_frame, state) -> bool:
    """Solve DataDome audio captcha: 6 spoken digits transcribed via Whisper.

    Returns True if digits were entered (main loop handles cookie check),
    False if audio captcha is unavailable or transcription failed.
    """
    model = _ensure_whisper()
    if model is None:
        logger.debug("DD audio: Whisper unavailable, skipping")
        return False

    # Check if audio toggle button exists
    try:
        btn = dd_frame.locator("#captcha__audio__button")
        if btn.count() == 0 or not btn.first.is_visible(timeout=2000):
            logger.debug("DD audio: toggle button not visible")
            return False
    except Exception:
        logger.debug("DD audio: toggle button check failed", exc_info=True)
        return False

    # Click the audio toggle
    try:
        if not _click_element(solver, page, state, btn.first):
            return False
        logger.debug("DD audio: clicked audio toggle")
    except Exception:
        logger.debug("DD audio: click failed", exc_info=True)
        return False

    # Wait for <audio> element to appear with a src.
    # Read the URL from the element but do NOT fetch it inside the
    # DD iframe - DD intercepts fetch/XHR and flags extra requests.
    time.sleep(random.uniform(0.8, 1.5))
    audio_url = None
    for _ in range(10):
        try:
            audio_url = dd_frame.evaluate("""() => {
                const audio = document.querySelector('audio');
                return (audio && audio.src) ? audio.src : null;
            }""")
            if audio_url:
                break
        except Exception:
            pass
        time.sleep(0.5)

    if not audio_url:
        logger.debug("DD audio: no audio element or src")
        return False

    # Click the play button so DD's JS registers normal playback.
    # Record the click time so we can wait for the full audio.
    play_start = time.monotonic()
    try:
        play_btn = dd_frame.locator("button.audio-captcha-play-button")
        if play_btn.count() > 0 and play_btn.first.is_visible(
            timeout=2000
        ):
            _click_element(solver, page, state, play_btn.first)
            logger.debug("DD audio: clicked play button")
    except Exception:
        logger.debug("DD audio: play button click failed", exc_info=True)

    # Download audio externally (outside browser) to avoid DD
    # detecting a fetch() inside its iframe.
    try:
        with urllib.request.urlopen(audio_url, timeout=10) as resp:
            audio_bytes = resp.read()
    except Exception:
        logger.debug("DD audio: external download failed", exc_info=True)
        return False

    logger.debug("DD audio: downloaded %d bytes", len(audio_bytes))

    try:
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            f.write(audio_bytes)
            tmp_path = f.name

        segments, _ = model.transcribe(
            tmp_path, language="en", beam_size=5,
            initial_prompt="0 1 2 3 4 5 6 7 8 9",
        )
        text = " ".join(seg.text for seg in segments)
        logger.debug("DD audio: transcription = %r", text)
    except Exception:
        logger.debug("DD audio: transcription failed", exc_info=True)
        return False
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    # Extract exactly 6 digits
    digits = re.findall(r"\d", text)
    if len(digits) != 6:
        logger.info(
            "DD audio: expected 6 digits, got %d from %r",
            len(digits), text,
        )
        return False

    # Wait for the audio to finish playing in the browser.  A human
    # listens to all 6 digits, then types.  DD likely tracks that the
    # <audio> element reached the end before input began.
    wav_duration = len(audio_bytes) / 32000  # 16kHz mono 16-bit
    if wav_duration < 5:
        wav_duration = 15  # fallback
    elapsed = time.monotonic() - play_start
    remaining = wav_duration - elapsed - random.uniform(0.5, 2.0)
    if remaining > 0:
        logger.debug(
            "DD audio: duration=%.1fs, elapsed=%.1fs, waiting %.1fs",
            wav_duration, elapsed, remaining,
        )
        time.sleep(remaining)

    logger.info("DD audio: entering digits %s", "".join(digits))

    # Type each digit into its input field.  Use _replay_path for the
    # first input (approach from elsewhere on page), then quick direct
    # moves between adjacent inputs (they're right next to each other).
    try:
        for i, digit in enumerate(digits):
            inp = dd_frame.locator(
                f'input.audio-captcha-inputs[data-index="{i}"]'
            )
            if inp.count() == 0:
                logger.debug("DD audio: input[%d] not found", i)
                return False

            box = inp.first.bounding_box(timeout=2000)
            if not box:
                logger.debug("DD audio: input[%d] no bbox", i)
                return False

            target_x = box["x"] + box["width"] / 2
            target_y = box["y"] + box["height"] / 2
            if i == 0:
                # First input: full replay path from current position
                _click_element(solver, page, state, inp.first)
            else:
                # Adjacent inputs: quick direct move (human-like
                # for nearby targets, ~100-200ms travel)
                page.mouse.move(target_x, target_y, steps=5)
                time.sleep(random.uniform(0.05, 0.15))
                page.mouse.click(target_x, target_y)

            time.sleep(random.uniform(0.08, 0.2))
            page.keyboard.press(f"Digit{digit}")
            # Human inter-digit pause: recalling next digit
            time.sleep(random.uniform(0.3, 0.7))
    except Exception:
        logger.debug("DD audio: typing digits failed", exc_info=True)
        return False

    # Verify digits landed in the inputs
    try:
        filled = dd_frame.evaluate("""() => {
            const inputs = document.querySelectorAll(
                'input.audio-captcha-inputs'
            );
            return Array.from(inputs).map(i => i.value).join('');
        }""")
        logger.debug("DD audio: input values = %r", filled)
    except Exception:
        pass

    # Pause before verify - human double-checks the digits
    logger.info("DD audio: all 6 digits entered, clicking verify")
    time.sleep(random.uniform(0.8, 1.5))

    # Click the Verify button (enabled after all 6 digits filled)
    try:
        verify_btn = dd_frame.locator(
            "button.audio-captcha-submit-button"
        )
        if verify_btn.count() > 0 and verify_btn.first.is_visible(
            timeout=2000
        ):
            _click_element(solver, page, state, verify_btn.first)
            logger.info("DD audio: clicked verify button")
        else:
            logger.debug("DD audio: verify button not visible")
    except Exception:
        logger.debug("DD audio: verify click failed", exc_info=True)

    return True


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
    iframe_first_seen = None
    hard_block_checked = False
    confirmed = False
    audio_attempted = False
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

        # Check if datadome cookie value changed (solve signal).
        # After cookie change, wait for the DD challenge iframe to
        # disappear — DD's JS redirects the page to real content.
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
                        # DD iframe gone — real solve
                        solver._replay_browse_chunk(
                            page, state, 0.5
                        )
                        return True
                    solver._replay_browse_chunk(page, state, 1)
                # DD iframe persists — solve was rejected, update
                # initial cookie so we can detect the next change
                logger.debug(
                    "DD cookie changed but iframe persists "
                    "(rejection, not clearance)"
                )
                initial_dd = c["value"]
                # Reset state so we retry the challenge
                slid = False
                confirmed = False
                audio_attempted = False
                break

        # Find the DD captcha-delivery iframe
        dd_frame = _find_dd_frame(page)
        if dd_frame:
            if not iframe_seen:
                iframe_first_seen = time.monotonic()
            iframe_seen = True

            # Phase 1: click confirm button
            if not confirmed:
                if _try_click_confirm(solver, page, dd_frame, state):
                    confirmed = True
                    # Wait for slider widget to load after confirm
                    solver._replay_browse_chunk(page, state, 2)
                    continue

            # Phase 1.5: try audio captcha (preferred over slider)
            if not audio_attempted and not slid:
                if _try_audio_captcha(solver, page, dd_frame, state):
                    slid = True
                    # Audio solve eats significant time (playback wait).
                    # Extend the deadline to give at least 15s for
                    # post-verify cookie detection.
                    min_remaining = time.monotonic() + 15
                    if min_remaining > deadline:
                        deadline = min_remaining
                    time.sleep(2)
                    continue
                audio_attempted = True

            # Phase 2: solve puzzle slider (fallback)
            if not slid:
                solver._ensure_recordings()
                if _try_drag_slider(solver, page, dd_frame, state):
                    slid = True
                    solver._replay_browse_chunk(page, state, 2)
                    continue

            # Hard block detection: iframe visible for 3s but no
            # solvable challenge found (no button, no slider).
            # Skip if we already attempted a solve - DD shows
            # rejection text that looks like a hard block.
            if (
                not confirmed
                and not slid
                and not hard_block_checked
                and not audio_attempted
                and iframe_first_seen
                and time.monotonic() - iframe_first_seen > 3.0
            ):
                hard_block_checked = True
                if _is_hard_block(dd_frame):
                    logger.warning(
                        "DataDome hard block detected "
                        "(IP/device flagged), cannot solve"
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
