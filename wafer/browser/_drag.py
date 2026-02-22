"""Drag/slider puzzle CAPTCHA solver.

Solves GeeTest v4 slide puzzles and Alibaba Baxia NoCaptcha
slider challenges using CV notch detection (GeeTest) or
full-width drag (Baxia) + recorded human mouse replay.

Vendor detection and image extraction live here.  Mouse replay
methods are on ``BrowserSolver``.
"""

import logging
import random
import struct
import time
from urllib.parse import urlparse

logger = logging.getLogger("wafer")

# ── GeeTest v4 selectors ────────────────────────────────────────────
_GT = {
    "bg": ".geetest_bg",
    "piece": ".geetest_slice_bg",
    "handle": ".geetest_btn",
    "track": ".geetest_track",
    "box": ".geetest_box",
    "result": ".geetest_result_tips",
}
_GT_IMAGE_DOMAINS = {"static.geetest.com"}

# ── Alibaba Baxia NoCaptcha selectors ──────────────────────────────
# Live-captured from AliExpress punish page (Feb 2026).
# "slide to verify" — full-width left→right drag, no puzzle images.
_BAXIA = {
    "handle": "#nc_1_n1z",           # SPAN.nc_iconfont.btn_slide (42x30)
    "track": "#nc_1_n1t",            # DIV.nc_scale (300x34)
    "fill": "#nc_1__bg",             # DIV.nc_bg (width grows with drag)
    "wrapper": "#nc_1_wrapper",      # DIV.nc_wrapper (300x34)
    "container": "#nocaptcha",       # DIV.nc-container
    "text": ".nc-lang-cnt",          # SPAN — "Please slide to verify"
}


def detect_drag_vendor(page) -> str | None:
    """Detect which drag CAPTCHA vendor is present in the page DOM."""
    return page.evaluate("""() => {
        if (
            document.querySelector('.geetest_slider') ||
            document.querySelector('.geetest_btn_click') ||
            typeof window.initGeetest4 === 'function'
        ) return 'geetest';
        // Baxia NoCaptcha slider (#nc_1_n1z handle + #nc_1_wrapper)
        if (
            document.querySelector('#nc_1_n1z') ||
            document.querySelector('#nc_1_wrapper')
        ) return 'baxia';
        return null;
    }""")


def _image_domains(vendor: str) -> set[str]:
    if vendor == "geetest":
        return _GT_IMAGE_DOMAINS
    return set()


def setup_image_intercept(page, vendor: str) -> dict:
    """Attach network response listener to capture puzzle PNGs.

    Call BEFORE the challenge fetches its assets.  Returns a mutable
    dict populated asynchronously as images arrive::

        {"bg": bytes | None, "piece": bytes | None}
    """
    captured: dict[str, bytes | None] = {"bg": None, "piece": None}
    domains = _image_domains(vendor)
    if not domains:
        return captured

    def _on_response(response):
        try:
            host = urlparse(response.url).hostname or ""
            if not any(
                host == d or host.endswith("." + d) for d in domains
            ):
                return
            ct = response.headers.get("content-type", "")
            if "image/png" not in ct and not response.url.endswith(
                ".png"
            ):
                return
            body = response.body()
            if not body:
                return
            # bg is larger (~50-130KB), piece is smaller (~8-10KB)
            if len(body) > 20_000:
                if captured["bg"] is None:
                    captured["bg"] = body
                    logger.debug(
                        "Intercepted bg: %d bytes", len(body)
                    )
            else:
                if captured["piece"] is None:
                    captured["piece"] = body
                    logger.debug(
                        "Intercepted piece: %d bytes", len(body)
                    )
        except Exception:
            pass

    page.on("response", _on_response)
    return captured


def _extract_images_from_dom(
    page, vendor: str
) -> tuple[bytes | None, bytes | None]:
    """Extract puzzle images from DOM computed styles.

    Fallback when network intercept didn't capture images (e.g. they
    were already loaded before the listener was attached).  Fetches via
    ``page.evaluate`` using the browser's fetch API (no CORS issues for
    data URLs; CDN URLs may fail cross-origin).
    """
    if vendor == "geetest":
        bg_sel, piece_sel = _GT["bg"], _GT["piece"]
    else:
        return None, None

    result = page.evaluate(
        """([bgSel, pieceSel]) => {
        const bg = document.querySelector(bgSel);
        const piece = document.querySelector(pieceSel);
        if (!bg || !piece) return null;
        const bgUrl = getComputedStyle(bg).backgroundImage;
        const pieceUrl = getComputedStyle(piece).backgroundImage;
        if (!bgUrl || bgUrl === 'none') return null;
        if (!pieceUrl || pieceUrl === 'none') return null;
        return {
            bg: bgUrl.slice(5, -2),
            piece: pieceUrl.slice(5, -2),
        };
    }""",
        [bg_sel, piece_sel],
    )
    if not result:
        return None, None

    import base64

    images: dict[str, bytes | None] = {"bg": None, "piece": None}
    for key in ("bg", "piece"):
        url = result[key]
        if url.startswith("data:"):
            _, encoded = url.split(",", 1)
            images[key] = base64.b64decode(encoded)
        else:
            # Fetch CDN URL from page context via ArrayBuffer
            raw = page.evaluate(
                """async (url) => {
                try {
                    const r = await fetch(url);
                    const buf = await r.arrayBuffer();
                    return Array.from(new Uint8Array(buf));
                } catch { return null; }
            }""",
                url,
            )
            if raw:
                images[key] = bytes(raw)
    return images["bg"], images["piece"]


def _wait_for_puzzle(page, vendor: str, timeout_ms: int) -> bool:
    """Wait for the slide puzzle widget to become interactive."""
    if vendor == "geetest":
        try:
            page.wait_for_selector(
                _GT["bg"], state="visible", timeout=timeout_ms
            )
            time.sleep(0.5)  # settle for image render
            return True
        except Exception:
            logger.warning("GeeTest puzzle not visible within timeout")
            return False

    logger.warning("Unsupported drag vendor for wait: %s", vendor)
    return False


def _get_geometry(
    page, vendor: str
) -> tuple[dict, float, float] | None:
    """Get handle bounding box, track width, and rendered bg width.

    Returns ``(handle_box, track_width, bg_rendered_width)`` or None.
    """
    if vendor == "geetest":
        h_sel, t_sel, bg_sel = _GT["handle"], _GT["track"], _GT["bg"]
    else:
        return None

    geom = page.evaluate(
        """([hSel, tSel, bgSel]) => {
        const h = document.querySelector(hSel);
        const t = document.querySelector(tSel);
        const bg = document.querySelector(bgSel);
        if (!h || !t || !bg) return null;
        const r = h.getBoundingClientRect();
        return {
            handle: {x: r.x, y: r.y, width: r.width, height: r.height},
            trackWidth: t.offsetWidth,
            bgWidth: bg.offsetWidth,
        };
    }""",
        [h_sel, t_sel, bg_sel],
    )
    if not geom:
        return None
    return geom["handle"], geom["trackWidth"], geom["bgWidth"]


def _check_result(page, vendor: str) -> bool | None:
    """Check solve result.  Returns True/False/None (still pending)."""
    if vendor == "geetest":
        return page.evaluate(
            """() => {
            // Puzzle bg gone = widget dismissed (success or removed)
            const bg = document.querySelector('.geetest_bg');
            if (!bg || bg.offsetWidth === 0) return true;
            // Check for explicit success/fail result tips
            const el = document.querySelector('.geetest_result_tips');
            if (el) {
                const cls = el.className || '';
                if (cls.includes('success')) return true;
                if (cls.includes('fail')) return false;
            }
            return null;
        }"""
        )
    return None


def _png_width(data: bytes) -> int:
    """Read width from PNG IHDR chunk (bytes 16-19, big-endian u32)."""
    return struct.unpack(">I", data[16:20])[0]


def solve_drag(solver, page, timeout_ms: int) -> bool:
    """Solve a drag/slider puzzle CAPTCHA.

    Detects vendor (GeeTest/Alibaba), extracts puzzle images via
    network intercept, uses CV to find the notch offset, then replays
    recorded human mouse movements (idle + path + drag).

    Args:
        solver: ``BrowserSolver`` instance (provides replay methods).
        page: Playwright page with the challenge loaded.
        timeout_ms: Max time to wait for puzzle widget.

    Returns:
        True if the puzzle was solved, False otherwise.
    """
    solver._ensure_recordings()
    if not solver._drag_recordings:
        logger.error("No drag recordings loaded")
        return False

    vendor = detect_drag_vendor(page)
    if not vendor:
        logger.warning("No drag CAPTCHA vendor detected in DOM")
        return False
    logger.info("Drag CAPTCHA vendor: %s", vendor)

    # Network intercept is primary image source — captures PNGs
    # from CDN responses as the challenge loads them.
    captured = setup_image_intercept(page, vendor)

    if not _wait_for_puzzle(page, vendor, timeout_ms):
        return False

    # Give network intercept time to capture images
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if captured["bg"] and captured["piece"]:
            break
        time.sleep(0.2)

    bg_png = captured["bg"]
    piece_png = captured["piece"]

    # Fallback: extract from DOM if intercept missed them
    if not bg_png or not piece_png:
        logger.debug(
            "Network intercept incomplete, trying DOM extraction"
        )
        bg_dom, piece_dom = _extract_images_from_dom(page, vendor)
        bg_png = bg_png or bg_dom
        piece_png = piece_png or piece_dom

    if not bg_png or not piece_png:
        logger.error("Could not extract puzzle images")
        return False

    logger.debug(
        "Puzzle images: bg=%d bytes, piece=%d bytes",
        len(bg_png),
        len(piece_png),
    )

    # CV: find notch offset
    from wafer.browser._cv import find_notch

    x_offset, confidence = find_notch(bg_png, piece_png)
    logger.info("CV notch: x=%d confidence=%.3f", x_offset, confidence)

    if confidence < 0.10:
        logger.warning(
            "CV confidence too low (%.3f), skipping drag", confidence
        )
        return False

    # Slider geometry
    geom = _get_geometry(page, vendor)
    if not geom:
        logger.error("Could not read slider geometry")
        return False
    handle_box, track_width, bg_rendered_width = geom

    handle_cx = handle_box["x"] + handle_box["width"] / 2
    handle_cy = handle_box["y"] + handle_box["height"] / 2
    handle_w = handle_box["width"]
    max_slide = track_width - handle_w

    # Map CV pixel offset to slider handle distance.
    # x_offset is in native image pixels.  Scale proportionally:
    # handle_travel = x_offset / (native_bg_w - native_piece_w) * max_slide
    native_bg_w = _png_width(bg_png)
    native_piece_w = _png_width(piece_png)

    if native_bg_w <= native_piece_w:
        logger.error(
            "Invalid image dims: bg=%d, piece=%d",
            native_bg_w,
            native_piece_w,
        )
        return False

    handle_target = (
        x_offset / (native_bg_w - native_piece_w)
    ) * max_slide
    end_x = handle_cx + handle_target
    end_y = handle_cy

    logger.info(
        "Drag plan: offset=%d bg=%d piece=%d "
        "max_slide=%.0f target=%.0fpx",
        x_offset,
        native_bg_w,
        native_piece_w,
        max_slide,
        handle_target,
    )

    # ── Mouse replay sequence ────────────────────────────────────
    # Skip idle — CAPTCHA popups have a solve timeout (~15s) and
    # idle wastes 2-3s.  Just position the cursor then path to handle.
    viewport = page.viewport_size
    idle_x = viewport["width"] * random.uniform(0.3, 0.7)
    idle_y = viewport["height"] * random.uniform(0.3, 0.5)
    page.mouse.move(idle_x, idle_y)

    # 1. Path: move cursor to the slider handle
    solver._replay_path(
        page, idle_x, idle_y, handle_cx, handle_cy
    )

    # 2. Drag: slide handle to target (includes pre-drag hover)
    solver._replay_drag(page, handle_cx, handle_cy, end_x, end_y)

    # ── Verify result ────────────────────────────────────────────
    for _ in range(10):
        time.sleep(0.3)
        result = _check_result(page, vendor)
        if result is True:
            logger.info("Drag puzzle solved!")
            return True
        if result is False:
            logger.info("Drag solve rejected (wrong position)")
            return False

    logger.info("Drag solve: no clear result after 3s")
    return False


# ── Baxia NoCaptcha slider solver ─────────────────────────────────


def _find_baxia_frame(page):
    """Find the Baxia NoCaptcha frame.

    The slider can appear in two modes:
    1. Full-page block — slider is in a cross-origin iframe from
       ``acs.aliexpress.com`` with ``/_____tmd_____/punish`` path.
    2. Inline overlay — ``.baxia-dialog`` with ``#baxia-dialog-content``
       iframe.

    In both cases, the NoCaptcha widget lives inside the iframe.
    If we're already on the punish page (full-page redirect), the
    slider is in the main frame.

    Returns the frame (or page) containing ``#nc_1_n1z``.
    """
    # Check main frame first (full-page redirect to punish page)
    has_handle = page.evaluate(
        "() => !!document.querySelector('#nc_1_n1z')"
    )
    if has_handle:
        return page

    # Check child frames — first try known Baxia URLs, then all frames
    for frame in page.frames:
        if frame == page.main_frame:
            continue
        url = frame.url
        if "punish" in url or "tmd" in url or "baxia" in url:
            try:
                frame.wait_for_load_state(
                    "domcontentloaded", timeout=5000
                )
            except Exception:
                pass
            has = frame.evaluate(
                "() => !!document.querySelector('#nc_1_n1z')"
            )
            if has:
                logger.debug("Baxia slider found in frame: %s", url[:80])
                return frame

    # Fallback: check ALL child frames (URL might be obfuscated)
    for frame in page.frames:
        if frame == page.main_frame:
            continue
        try:
            has = frame.evaluate(
                "() => !!document.querySelector('#nc_1_n1z')"
            )
            if has:
                logger.debug(
                    "Baxia slider found in frame (fallback): %s",
                    frame.url[:80],
                )
                return frame
        except Exception:
            continue

    return None


def _get_baxia_geometry(frame) -> tuple[dict, float] | None:
    """Get Baxia slider handle bbox and max slide distance.

    Returns ``(handle_box, max_slide)`` or None.
    """
    geom = frame.evaluate("""() => {
        const h = document.querySelector('#nc_1_n1z');
        const t = document.querySelector('#nc_1_n1t');
        if (!h || !t) return null;
        const r = h.getBoundingClientRect();
        return {
            handle: {x: r.x, y: r.y, width: r.width, height: r.height},
            trackWidth: t.offsetWidth,
        };
    }""")
    if not geom:
        return None
    track_w = geom["trackWidth"]
    handle_w = geom["handle"]["width"]
    max_slide = track_w - handle_w
    return geom["handle"], max_slide


def _check_baxia_result(frame, *, saw_movement: bool) -> bool | None:
    """Check Baxia solve result.

    Args:
        frame: The frame containing the NoCaptcha widget.
        saw_movement: True if a previous poll observed fill bar > 0.
            Prevents false rejection on initial state (left=0, fill=0).

    Returns True (solved), False (failed/reset), or None (pending).
    """
    return frame.evaluate(
        """(sawMovement) => {
        // Check for error text anywhere on the page (Baxia shows
        // "Oops... something's wrong" when rejecting a drag)
        const body = document.body ? document.body.textContent : '';
        const bodyLc = body.toLowerCase();
        if (bodyLc.includes("something's wrong")
            || bodyLc.includes('please refresh and try again')
            || bodyLc.includes('error:')) return false;

        const handle = document.querySelector('#nc_1_n1z');
        // Widget destroyed = rejection (Baxia removes all #nc_1_*
        // elements then recreates a fresh widget after ~6s).
        if (!handle) {
            return sawMovement ? false : null;
        }
        const cls = handle.className || '';
        if (cls.includes('success')) return true;
        if (cls.includes('fail') || cls.includes('error')) return false;

        const wrapper = document.querySelector('#nc_1_wrapper');
        if (wrapper && wrapper.dataset.solved === 'true') return true;

        // Check if text changed to success message
        const text = document.querySelector('.nc-lang-cnt');
        if (text) {
            const t = text.textContent.toLowerCase();
            if (t.includes('passed') || t.includes('success')
                || t.includes('verified')) return true;
        }

        // Check if fill bar reached full width (handle at end)
        const bg = document.querySelector('#nc_1__bg');
        const track = document.querySelector('#nc_1_n1t');
        if (bg && track) {
            const bgW = bg.offsetWidth;
            const trackW = track.offsetWidth;
            if (bgW > 0 && bgW >= trackW * 0.85) return true;
        }

        // Check for error state (handle snapped back to 0).
        // Only check this AFTER we've seen movement — the initial
        // resting state also has left=0 and fill=0.
        if (sawMovement) {
            const bgEl = document.querySelector('#nc_1__bg');
            if (bgEl && bgEl.offsetWidth === 0) return false;
        }

        return null;
    }""",
        saw_movement,
    )


def _page_left_punish(page, initial_url: str) -> bool:
    """Check if the page navigated away from the punish URL."""
    try:
        url = page.url
        if url == initial_url:
            return False
        return (
            "/_____tmd_____/" not in url and "punish" not in url
        )
    except Exception:
        return False


def _attempt_baxia_drag(solver, page, frame, max_attempts: int = 3) -> bool:
    """Attempt the Baxia slider drag with retries.

    Each attempt uses a different recording and waits for the widget
    to reset between retries.
    """
    viewport = page.viewport_size
    initial_url = page.url

    for attempt in range(max_attempts):
        # Get fresh geometry (widget resets after rejection)
        geom = _get_baxia_geometry(frame)
        if not geom:
            logger.error("Could not read Baxia slider geometry")
            return False
        handle_box, max_slide = geom

        handle_cx = handle_box["x"] + handle_box["width"] / 2
        handle_cy = handle_box["y"] + handle_box["height"] / 2

        # Iframe offset for child frames
        if frame is not page:
            frame_url = frame.url
            iframe_offset = page.evaluate(
                """(frameUrl) => {
                for (const el of document.querySelectorAll('iframe')) {
                    if (el.src === frameUrl
                        || el.id === 'baxia-dialog-content') {
                        const r = el.getBoundingClientRect();
                        return {x: r.x, y: r.y};
                    }
                }
                return null;
            }""",
                frame_url,
            )
            if iframe_offset:
                handle_cx += iframe_offset["x"]
                handle_cy += iframe_offset["y"]

        end_x = handle_cx + max_slide
        end_y = handle_cy

        logger.info(
            "Baxia attempt %d/%d: handle=(%.0f, %.0f) "
            "max_slide=%.0fpx",
            attempt + 1, max_attempts,
            handle_cx, handle_cy, max_slide,
        )

        # Browse activity before approaching handle
        bx = viewport["width"] * random.uniform(0.3, 0.7)
        by = viewport["height"] * random.uniform(0.2, 0.4)
        browse_state = solver._start_browse(page, bx, by)
        settle = 1.0 + random.random() if attempt == 0 else 2.0 + random.random()
        solver._replay_browse_chunk(page, browse_state, settle)

        # Path to handle
        solver._replay_path(page, bx, by, handle_cx, handle_cy)

        # Drag: full-width slide using slide recordings
        orig_drags = solver._drag_recordings
        if solver._slide_recordings:
            solver._drag_recordings = solver._slide_recordings
        try:
            solver._replay_drag(
                page, handle_cx, handle_cy, end_x, end_y
            )
        finally:
            solver._drag_recordings = orig_drags

        # Verify result — check URL first (Baxia redirects on success)
        saw_movement = True
        for _ in range(15):
            time.sleep(0.3)
            if _page_left_punish(page, initial_url):
                logger.info(
                    "Baxia solved (page navigated to %s)",
                    page.url[:120],
                )
                return True
            try:
                result = _check_baxia_result(
                    frame, saw_movement=saw_movement
                )
            except Exception:
                if _page_left_punish(page, initial_url):
                    logger.info(
                        "Baxia solved (page navigated to %s)",
                        page.url[:120],
                    )
                    return True
                logger.info("Baxia frame detached during result check")
                return False
            if result is True:
                logger.info("Baxia slider solved!")
                return True
            if result is False:
                logger.info(
                    "Baxia slider rejected (attempt %d/%d)",
                    attempt + 1, max_attempts,
                )
                break

        if attempt < max_attempts - 1:
            # Wait for widget to reset before retrying
            logger.info("Waiting for Baxia widget to reset...")
            for _ in range(20):
                time.sleep(0.5)
                try:
                    has_handle = frame.evaluate(
                        "() => !!document.querySelector('#nc_1_n1z')"
                    )
                    if has_handle:
                        # Check it's back to initial state
                        left = frame.evaluate("""() => {
                            const h = document.querySelector('#nc_1_n1z');
                            return h ? parseInt(h.style.left) || 0 : -1;
                        }""")
                        if left == 0:
                            break
                except Exception:
                    continue

    return False


def solve_baxia(solver, page, timeout_ms: int) -> bool:
    """Solve a Baxia NoCaptcha "slide to verify" challenge.

    No CV needed — always drags the full track width (left→right).
    The challenge monitors mouse behavior (timing, wobble, speed)
    rather than position accuracy.  Retries up to 3 times on rejection.

    Args:
        solver: ``BrowserSolver`` instance (provides replay methods).
        page: Playwright page with the challenge loaded.
        timeout_ms: Max time to wait for slider widget.

    Returns:
        True if the slider was solved, False otherwise.
    """
    solver._ensure_recordings()
    recordings = solver._slide_recordings or solver._drag_recordings
    if not recordings:
        logger.error("No drag/slide recordings loaded")
        return False

    # Find the frame containing the NoCaptcha slider
    deadline = time.monotonic() + timeout_ms / 1000
    frame = None
    while time.monotonic() < deadline:
        frame = _find_baxia_frame(page)
        if frame:
            break
        time.sleep(0.5)

    if not frame:
        logger.warning("Baxia NoCaptcha slider not found")
        return False

    # Wait for handle to be visible
    try:
        frame.wait_for_selector(
            _BAXIA["handle"], state="visible", timeout=5000
        )
    except Exception:
        logger.warning("Baxia handle not visible")
        return False

    return _attempt_baxia_drag(solver, page, frame)
