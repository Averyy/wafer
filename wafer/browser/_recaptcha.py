"""reCAPTCHA v2 checkbox + audio solver."""

import io
import logging
import random
import re
import time

logger = logging.getLogger("wafer")

_whisper_model = None

_WORD_TO_DIGIT = {
    "zero": "0", "oh": "0", "o": "0",
    "one": "1", "two": "2", "three": "3",
    "four": "4", "five": "5", "six": "6",
    "seven": "7", "eight": "8", "nine": "9",
}


def _ensure_whisper():
    """Lazy-load Whisper tiny on first audio solve.

    Downloads the model (~39MB) on first use.  Subsequent calls are free.
    """
    global _whisper_model
    if _whisper_model is not None:
        return _whisper_model

    try:
        from faster_whisper import WhisperModel
    except ImportError:
        raise ImportError(
            "faster-whisper is required for reCAPTCHA audio solving. "
            "Install with: pip install wafer-py[audio]"
        ) from None

    _whisper_model = WhisperModel("tiny", device="cpu", compute_type="int8")
    logger.info("Whisper tiny model loaded for reCAPTCHA audio")
    return _whisper_model


def _transcribe_audio(mp3_bytes: bytes) -> str | None:
    """Transcribe reCAPTCHA audio MP3.

    Returns the transcribed text (normalized if digit-based),
    or None if transcription failed.
    """
    model = _ensure_whisper()

    segments, _ = model.transcribe(
        io.BytesIO(mp3_bytes),
        language="en",
        beam_size=5,
    )
    raw = " ".join(seg.text for seg in segments).strip()

    if not raw:
        return None

    cleaned = re.sub(r'[^\w\s]', '', raw).lower().strip()
    if not cleaned:
        return None

    tokens = cleaned.split()
    normalized = [_WORD_TO_DIGIT.get(t, t) for t in tokens]

    result = " ".join(normalized)
    logger.debug("Transcribed reCAPTCHA audio: %r → %r", raw, result)
    return result


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


def _is_doscaptcha(bframe) -> bool:
    """Check for hard rate-limit block in bframe."""
    try:
        return bframe.locator(".rc-doscaptcha-body").is_visible(timeout=300)
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
    image challenge, switches to the audio challenge, transcribes with
    Whisper, submits, and extracts the token.

    Early bail-out: if no recaptcha iframe appears within 5 seconds,
    returns False (browser likely passed through without challenge).
    """
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
            # Only check for bframe AFTER checkbox click — reCAPTCHA
            # pre-loads the bframe iframe, so its URL exists before
            # the user interacts.  Detect escalation by checking if
            # the challenge content is visible inside the bframe.
            bframe = _find_bframe(page)
            if bframe:
                try:
                    visible = bframe.locator(
                        ".rc-imageselect-challenge,"
                        ".rc-audiochallenge-control"
                    ).first.is_visible(timeout=300)
                    if visible:
                        break
                except Exception:
                    pass

        if not iframe_seen and time.monotonic() > grace_deadline:
            logger.info(
                "No reCAPTCHA iframe after 5s, "
                "browser likely passed through"
            )
            return False

        solver._replay_browse_chunk(page, state, 1)
    else:
        # Timed out without bframe or token
        return False

    # Grab bframe reference for audio phase
    bframe = _find_bframe(page)
    if not bframe:
        return False

    # Phase 2: Switch to audio challenge.
    logger.info("reCAPTCHA escalated to challenge, switching to audio")

    # Wait for bframe DOM to load (URL appears before content)
    try:
        bframe.wait_for_load_state("domcontentloaded", timeout=5000)
    except Exception:
        pass

    # Wait for audio button to render
    try:
        bframe.locator("#recaptcha-audio-button").wait_for(
            state="visible", timeout=5000,
        )
    except Exception:
        logger.warning("Audio button never appeared in bframe")
        return False

    solver._replay_browse_chunk(page, state, random.uniform(0.2, 0.5))
    if not _click_element(
        solver, page, state, bframe, "#recaptcha-audio-button",
    ):
        logger.warning("Could not click reCAPTCHA audio button")
        return False

    solver._replay_browse_chunk(page, state, random.uniform(1.0, 2.0))

    # Check for immediate doscaptcha block
    if _is_doscaptcha(bframe):
        logger.warning("reCAPTCHA audio blocked (doscaptcha)")
        return False

    # Phase 3: Audio solve loop (up to 3 attempts).
    for attempt in range(3):
        if time.monotonic() > deadline:
            break

        # Extract audio URL
        try:
            audio_src = bframe.locator("#audio-source").get_attribute(
                "src", timeout=5000,
            )
        except Exception:
            logger.debug("No #audio-source found in bframe")
            break

        if not audio_src:
            logger.debug("Audio source URL is empty")
            break

        # Download MP3
        try:
            resp = page.request.get(audio_src)
            if resp.status != 200:
                logger.debug(
                    "Audio download returned HTTP %d", resp.status,
                )
                break
            mp3_bytes = resp.body()
            if not mp3_bytes:
                logger.debug("Audio MP3 is 0 bytes")
                break
        except Exception:
            logger.debug("Failed to download reCAPTCHA audio")
            break

        logger.debug(
            "Downloaded reCAPTCHA audio (%d bytes, attempt %d)",
            len(mp3_bytes), attempt + 1,
        )

        # Transcribe
        try:
            transcription = _transcribe_audio(mp3_bytes)
        except Exception:
            logger.debug("Whisper transcription error", exc_info=True)
            transcription = None
        if not transcription:
            logger.debug("Transcription failed, reloading audio")
            _click_element(solver, page, state, bframe, "#recaptcha-reload-button")
            solver._replay_browse_chunk(page, state, random.uniform(1.5, 2.5))
            continue

        logger.info(
            "reCAPTCHA audio transcribed (attempt %d): %r",
            attempt + 1, transcription,
        )

        # Fill answer
        bframe.locator("#audio-response").fill(transcription)
        solver._replay_browse_chunk(page, state, random.uniform(0.3, 0.7))

        # Click verify
        _click_element(
            solver, page, state, bframe, "#recaptcha-verify-button",
        )

        # Poll for token (async JS populates it after verify)
        for _ in range(6):
            solver._replay_browse_chunk(page, state, 0.5)
            if _check_token(page):
                logger.info(
                    "reCAPTCHA audio solved on attempt %d",
                    attempt + 1,
                )
                return True

        if _is_doscaptcha(bframe):
            logger.warning(
                "reCAPTCHA audio blocked after verify (doscaptcha)",
            )
            return False

        # Check for soft error (wrong answer / "multiple correct solutions")
        try:
            err_visible = bframe.locator(
                ".rc-audiochallenge-error-message"
            ).is_visible(timeout=500)
            if err_visible:
                logger.debug("reCAPTCHA audio error, reloading")
                _click_element(
                    solver, page, state, bframe, "#recaptcha-reload-button",
                )
                solver._replay_browse_chunk(
                    page, state, random.uniform(1.5, 2.5),
                )
                continue
        except Exception:
            pass

    return False
