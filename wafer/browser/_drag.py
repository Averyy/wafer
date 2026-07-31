"""Drag/slider puzzle CAPTCHA solver.

Solves GeeTest v4 slide puzzles and Alibaba Baxia NoCaptcha
slider challenges using CV notch detection (GeeTest) or
full-width drag (Baxia) + recorded human mouse replay.

Vendor detection and image extraction live here.  Mouse replay
methods are on ``BrowserSolver``.
"""

import logging
import os
import random
import re
import struct
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("wafer")

_BAXIA_ERROR_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
_BAXIA_MTOP_API_RE = re.compile(r"^mtop\.(alibaba|aliexpress)(?:\.[A-Za-z0-9_-]+)+$")
_BAXIA_MTOP_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
_BAXIA_PUNISH_SUFFIX = "/_____tmd_____/punish"
_NO_EVALUATE_ARGUMENT = object()


def _baxia_diagnostics_enabled() -> bool:
    """Whether invasive page-side Baxia diagnostics are explicitly enabled."""

    return os.environ.get("WAFER_BAXIA_DIAGNOSTICS") == "1"


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
    "handle": "#nc_1_n1z",  # SPAN.nc_iconfont.btn_slide (42x30)
    "track": "#nc_1_n1t",  # DIV.nc_scale (300x34)
    "fill": "#nc_1__bg",  # DIV.nc_bg (width grows with drag)
    "wrapper": "#nc_1_wrapper",  # DIV.nc_wrapper (300x34)
    "container": "#nocaptcha",  # DIV.nc-container
    "text": ".nc-lang-cnt",  # SPAN — "Please slide to verify"
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
            if not any(host == d or host.endswith("." + d) for d in domains):
                return
            ct = response.headers.get("content-type", "")
            if "image/png" not in ct and not response.url.endswith(".png"):
                return
            body = response.body()
            if not body:
                return
            # bg is larger (~50-130KB), piece is smaller (~8-10KB)
            if len(body) > 20_000:
                if captured["bg"] is None:
                    captured["bg"] = body
                    logger.debug("Intercepted bg: %d bytes", len(body))
            else:
                if captured["piece"] is None:
                    captured["piece"] = body
                    logger.debug("Intercepted piece: %d bytes", len(body))
        except Exception:
            pass

    page.on("response", _on_response)
    return captured


def _extract_images_from_dom(page, vendor: str) -> tuple[bytes | None, bytes | None]:
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
            page.wait_for_selector(_GT["bg"], state="visible", timeout=timeout_ms)
            time.sleep(0.5)  # settle for image render
            return True
        except Exception:
            logger.warning("GeeTest puzzle not visible within timeout")
            return False

    logger.warning("Unsupported drag vendor for wait: %s", vendor)
    return False


def _get_geometry(page, vendor: str) -> tuple[dict, float, float] | None:
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
    deadline = time.monotonic() + timeout_ms / 1000.0

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

    # Give network intercept time to capture images -- but never past the
    # caller's budget. _wait_for_puzzle can already have consumed most of
    # timeout_ms, and a flat 3s here (plus the CV and replay below) used to
    # push the whole solve well past the deadline the request was given.
    capture_deadline = min(time.monotonic() + 3.0, deadline)
    while time.monotonic() < capture_deadline:
        if captured["bg"] and captured["piece"]:
            break
        time.sleep(min(0.2, max(0.0, capture_deadline - time.monotonic())))

    bg_png = captured["bg"]
    piece_png = captured["piece"]

    # Fallback: extract from DOM if intercept missed them
    if not bg_png or not piece_png:
        logger.debug("Network intercept incomplete, trying DOM extraction")
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

    # CV and the mouse replay that follows are both multi-second and cannot
    # be interrupted once started, so stop here rather than overrun.
    if time.monotonic() >= deadline:
        logger.warning("Drag solve budget exhausted before CV; aborting")
        return False

    # CV: find notch offset
    from wafer.browser._cv import find_notch

    x_offset, confidence = find_notch(bg_png, piece_png)
    logger.info("CV notch: x=%d confidence=%.3f", x_offset, confidence)

    if confidence < 0.10:
        logger.warning("CV confidence too low (%.3f), skipping drag", confidence)
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

    handle_target = (x_offset / (native_bg_w - native_piece_w)) * max_slide
    end_x = handle_cx + handle_target
    end_y = handle_cy

    logger.info(
        "Drag plan: offset=%d bg=%d piece=%d max_slide=%.0f target=%.0fpx",
        x_offset,
        native_bg_w,
        native_piece_w,
        max_slide,
        handle_target,
    )

    # ── Mouse replay sequence ────────────────────────────────────
    # Skip idle — CAPTCHA popups have a solve timeout (~15s) and
    # idle wastes 2-3s.  Just position the cursor then path to handle.
    viewport = _viewport_size(page)
    idle_x = viewport["width"] * random.uniform(0.3, 0.7)
    idle_y = viewport["height"] * random.uniform(0.3, 0.5)
    page.mouse.move(idle_x, idle_y)

    # Path + drag: the path must join the recording at its first pre-drag
    # hover sample, not at the later mousedown coordinate.
    solver._replay_drag(
        page,
        handle_cx,
        handle_cy,
        end_x,
        end_y,
        approach_from=(idle_x, idle_y),
    )

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


def _frame_has_baxia_handle(
    frame,
    deadline: float | None,
    *,
    maximum_wait_ms: int = 250,
) -> bool:
    """Bound handle discovery even while a replacement frame is navigating."""

    remaining = _remaining(deadline)
    remaining_ms = (
        maximum_wait_ms
        if remaining == float("inf")
        else min(maximum_wait_ms, int(remaining * 1000))
    )
    if remaining_ms <= 0:
        return False
    try:
        frame.wait_for_selector(
            _BAXIA["handle"],
            state="attached",
            timeout=max(1, remaining_ms),
        )
        return True
    except Exception:
        return False


def _find_baxia_frame(page, deadline: float | None = None):
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
    if _frame_has_baxia_handle(page, deadline):
        return page

    # Check child frames — first try known Baxia URLs, then all frames
    for frame in page.frames:
        if frame == page.main_frame:
            continue
        url = frame.url
        if "punish" in url or "tmd" in url or "baxia" in url:
            if _frame_has_baxia_handle(frame, deadline):
                logger.debug("Baxia slider found in known challenge frame")
                return frame

    # Fallback: check ALL child frames (URL might be obfuscated)
    for frame in page.frames:
        if frame == page.main_frame:
            continue
        if _frame_has_baxia_handle(
            frame,
            deadline,
            maximum_wait_ms=100,
        ):
            logger.debug("Baxia slider found in fallback frame")
            return frame

    return None


def _baxia_evaluate(
    frame,
    expression: str,
    argument=_NO_EVALUATE_ARGUMENT,
    *,
    deadline: float | None,
    maximum_wait_ms: int = 1_000,
):
    """Evaluate with Playwright's protocol timeout on every live solve path."""

    if deadline is None:
        if argument is _NO_EVALUATE_ARGUMENT:
            return frame.evaluate(expression)
        return frame.evaluate(expression, argument)
    remaining_ms = min(maximum_wait_ms, int(_remaining(deadline) * 1000))
    if remaining_ms <= 0:
        raise TimeoutError("Baxia evaluation deadline expired")
    locator = frame.locator("html")
    if argument is _NO_EVALUATE_ARGUMENT:
        return locator.evaluate(
            expression,
            timeout=max(1, remaining_ms),
        )
    return locator.evaluate(
        expression,
        argument,
        timeout=max(1, remaining_ms),
    )


def _get_baxia_geometry(
    frame,
    deadline: float | None = None,
) -> tuple[dict, float] | None:
    """Get Baxia slider handle bbox and max slide distance.

    Returns ``(handle_box, max_slide)`` or None.
    """
    geom = _baxia_evaluate(
        frame,
        """() => {
        const h = document.querySelector('#nc_1_n1z');
        const t = document.querySelector('#nc_1_n1t');
        if (!h || !t) return null;
        const r = h.getBoundingClientRect();
        return {
            handle: {x: r.x, y: r.y, width: r.width, height: r.height},
            trackWidth: t.offsetWidth,
        };
    }""",
        deadline=deadline,
    )
    if not isinstance(geom, dict):
        return None
    handle = geom.get("handle")
    if not isinstance(handle, dict):
        return None
    track_w = geom.get("trackWidth")
    handle_w = handle.get("width")
    handle_h = handle.get("height")
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0
        for value in (track_w, handle_w, handle_h)
    ):
        # A just-reloaded Baxia iframe exposes its old handle before layout has
        # completed.  It has a zero-sized track/handle at that point; treating
        # that shell as a fresh puzzle sends the next drag to (0, 0).
        return None
    max_slide = track_w - handle_w
    if max_slide <= 0:
        return None
    return handle, max_slide


def _baxia_frame_offset(page, frame, deadline: float | None = None) -> dict | None:
    """Page-relative position of the iframe hosting the Baxia widget.

    Handle geometry comes from ``getBoundingClientRect()`` evaluated inside the
    frame, so it is relative to that frame's own viewport. Input is dispatched
    against the page, and the two only agree once the iframe's own position is
    added.

    Resolved from the frame's owning element, which is exact. The attribute
    match is kept as a fallback but cannot be relied on alone: it compares an
    element's resolved ``src`` against the frame's CURRENT url, and a challenge
    iframe that navigates after load -- the punish document redirects to load
    the NoCaptcha SDK -- makes those diverge, while the ``baxia-dialog-content``
    id only exists on the inline-overlay variant and not on the full-page one.
    """

    try:
        box = frame.frame_element().bounding_box()
    except Exception:
        logger.debug("Baxia frame element unavailable", exc_info=True)
        box = None
    if not isinstance(box, dict):
        box = _baxia_evaluate(
            page,
            """(_root, frameUrl) => {
            for (const el of document.querySelectorAll('iframe')) {
                if (el.src === frameUrl
                    || el.id === 'baxia-dialog-content') {
                    const r = el.getBoundingClientRect();
                    return {x: r.x, y: r.y};
                }
            }
            return null;
        }""",
            frame.url,
            deadline=deadline,
        )
    if not isinstance(box, dict):
        return None
    x = box.get("x")
    y = box.get("y")
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float))
        for value in (x, y)
    ):
        return None
    return {"x": float(x), "y": float(y)}


def _wait_for_baxia_geometry(page, frame, deadline: float | None):
    """Return a laid-out Baxia frame and geometry before dispatching input.

    A reload can make ``#nc_1_n1z`` observable before the replacement widget
    is visible.  The old code accepted that transient DOM node, then replayed
    a drag with a zero track.  Rediscover the frame while waiting so a replaced
    cross-origin iframe is handled as well.
    """

    while _remaining(deadline) > 0:
        try:
            geom = _get_baxia_geometry(frame, deadline)
        except Exception:
            geom = None
        if geom is not None:
            return frame, geom
        try:
            replacement = _find_baxia_frame(page, deadline)
        except Exception:
            replacement = None
        if replacement is not None:
            frame = replacement
            continue
        if not _sleep_with_deadline(deadline, 0.2):
            break
    return None


def _check_baxia_result(
    frame,
    *,
    saw_movement: bool,
    rejection: dict[str, str | None] | None = None,
    deadline: float | None = None,
) -> bool | None:
    """Check Baxia solve result.

    Args:
        frame: The frame containing the NoCaptcha widget.
        saw_movement: True if a previous poll observed fill bar > 0.
            Prevents false rejection on initial state (left=0, fill=0).

    Returns True (solved), False (failed/reset), or None (pending).
    """
    value = _baxia_evaluate(
        frame,
        r"""(_root, sawMovement) => {
        // Read only a strictly bounded code immediately after the SDK's
        // ``error:`` marker. Never return/log arbitrary page text: it may
        // contain challenge or session material.
        const body = document.body ? document.body.textContent : '';
        const bodyLc = body.toLowerCase();
        const errorCodePattern = new RegExp(
            '\\berror\\s*:\\s*([A-Za-z0-9][A-Za-z0-9_-]{0,31})'
            + '(?=$|[\\s,.;:)\\]])', 'i');
        const match = errorCodePattern.exec(body);
        if (match || bodyLc.includes("something's wrong")
            || bodyLc.includes('please refresh and try again')) {
            return {
                state: 'rejected',
                category: match ? 'sdk_error_code' : 'vendor_error_text',
                code: match ? match[1] : null,
            };
        }

        const handle = document.querySelector('#nc_1_n1z');
        // A disappearing widget is ambiguous: Baxia removes it both while
        // transitioning into an accepted redirect and after a rejection.
        // Let the caller keep polling page navigation before it decides to
        // reload a genuinely failed challenge.
        if (!handle) {
            return {state: 'pending'};
        }
        const cls = handle.className || '';
        if (cls.includes('success')) return {state: 'solved'};
        if (cls.includes('fail') || cls.includes('error')) {
            return {state: 'rejected', category: 'handle_class', code: null};
        }

        const wrapper = document.querySelector('#nc_1_wrapper');
        if (wrapper && wrapper.dataset.solved === 'true') return {state: 'solved'};

        // Check if text changed to success message
        const text = document.querySelector('.nc-lang-cnt');
        if (text) {
            const t = text.textContent.toLowerCase();
            if (t.includes('passed') || t.includes('success')
                || t.includes('verified')) return {state: 'solved'};
        }

        // Check for error state (handle snapped back to 0).
        // Only check this AFTER we've seen movement — the initial
        // resting state also has left=0 and fill=0.
        if (sawMovement) {
            const bgEl = document.querySelector('#nc_1__bg');
            if (bgEl && bgEl.offsetWidth === 0) {
                return {state: 'rejected', category: 'snapback', code: null};
            }
        }

        return {state: 'pending'};
    }""",
        saw_movement,
        deadline=deadline,
    )
    # Preserve the simple result shape for third-party/mock frames while the
    # real browser path carries the structured, bounded rejection metadata.
    if value is True or value is False or value is None:
        return value
    if not isinstance(value, dict):
        return None
    state = value.get("state")
    if state == "solved":
        return True
    if state != "rejected":
        return None
    if rejection is not None:
        category = value.get("category")
        code = value.get("code")
        rejection["category"] = (
            category
            if category
            in {"sdk_error_code", "vendor_error_text", "handle_class", "snapback"}
            else "unknown"
        )
        rejection["code"] = (
            code
            if isinstance(code, str) and _BAXIA_ERROR_CODE_RE.fullmatch(code)
            else None
        )
    return False


def _baxia_has_movement(
    frame,
    deadline: float | None = None,
) -> bool:
    """Return whether the widget itself visibly moved after the drag."""

    return bool(
        _baxia_evaluate(
            frame,
            """() => {
        const bg = document.querySelector('#nc_1__bg');
        const handle = document.querySelector('#nc_1_n1z');
        const fill = bg ? bg.offsetWidth : 0;
        const left = handle ? parseFloat(handle.style.left) || 0 : 0;
        return fill > 0 || left > 0;
    }""",
            deadline=deadline,
        )
    )


def _baxia_rejection_diagnostic(
    frame,
    rejection: dict[str, str | None] | None = None,
    deadline: float | None = None,
) -> dict[str, int | bool | str | None] | None:
    """Return bounded, non-content diagnostics for a rejected slider.

    The challenge page can contain per-session material, so diagnostics must
    never emit page text, URLs, cookies, or DOM attributes.  These fixed
    booleans and geometry values are sufficient to distinguish a rejected
    motion from a collapsed/replaced widget in production logs.
    """

    try:
        value = _baxia_evaluate(
            frame,
            r"""() => {
            const handle = document.querySelector('#nc_1_n1z');
            const fill = document.querySelector('#nc_1__bg');
            const track = document.querySelector('#nc_1_n1t');
            const text = (document.body && document.body.innerText || '')
                .toLowerCase();
            const raw = document.body && document.body.textContent || '';
            const errorCodePattern = new RegExp(
                '\\berror\\s*:\\s*([A-Za-z0-9][A-Za-z0-9_-]{0,31})'
                + '(?=$|[\\s,.;:)\\]])', 'i');
            const match = errorCodePattern.exec(raw);
            return {
                handle: !!handle,
                handleLeft: handle ? Math.max(0, Math.round(
                    parseFloat(handle.style.left) || 0
                )) : 0,
                fillWidth: fill ? Math.max(0, Math.round(fill.offsetWidth)) : 0,
                trackWidth: track ? Math.max(0, Math.round(track.offsetWidth)) : 0,
                explicitError: text.includes("something's wrong")
                    || text.includes('please refresh and try again')
                    || !!match,
                errorCategory: match ? 'sdk_error_code' : (
                    text.includes("something's wrong")
                    || text.includes('please refresh and try again')
                        ? 'vendor_error_text' : null
                ),
                errorCode: match ? match[1] : null,
            };
        }""",
            deadline=deadline,
        )
    except Exception:
        return None
    if not isinstance(value, dict):
        return None
    result: dict[str, int | bool] = {}
    for name in ("handle", "explicitError"):
        result[name] = value.get(name) is True
    for name in ("handleLeft", "fillWidth", "trackWidth"):
        raw = value.get(name)
        result[name] = raw if isinstance(raw, int) and raw >= 0 else 0
    category = (
        rejection.get("category")
        if rejection is not None
        else value.get("errorCategory")
    )
    code = rejection.get("code") if rejection is not None else value.get("errorCode")
    result["errorCategory"] = (
        category if isinstance(category, str) and len(category) <= 32 else None
    )
    result["errorCode"] = (
        code if isinstance(code, str) and _BAXIA_ERROR_CODE_RE.fullmatch(code) else None
    )
    return result


def _install_baxia_event_contract(
    frame,
    deadline: float | None = None,
) -> bool:
    """Start a bounded, content-free trace of the slider's input contract."""

    if not _baxia_diagnostics_enabled():
        return False
    try:
        return (
            _baxia_evaluate(
                frame,
                """() => {
            if (window.__waferBaxiaEventContract) return false;
            const point = e => ({
                x: Math.round(e.clientX), y: Math.round(e.clientY),
                screenX: Math.round(e.screenX), screenY: Math.round(e.screenY),
                t: Math.round(performance.now()), buttons: Number(e.buttons),
                button: Number(e.button), trusted: e.isTrusted === true,
            });
            const box = el => {
                if (!el) return null;
                const r = el.getBoundingClientRect();
                return {x: Math.round(r.x), y: Math.round(r.y),
                    width: Math.round(r.width), height: Math.round(r.height)};
            };
            const state = {
                counts: {pointerdown: 0, pointermove: 0, pointerup: 0,
                    mousedown: 0, mousemove: 0, mouseup: 0},
                pointerDown: null, lastPressedPointer: null, pointerUp: null,
                mouseDown: null, lastPressedMouse: null, mouseUp: null,
                maxHandleLeft: 0, maxFillWidth: 0, geometry: null,
            };
            const sample = () => {
                const h = document.querySelector('#nc_1_n1z');
                const f = document.querySelector('#nc_1__bg');
                const t = document.querySelector('#nc_1_n1t');
                const left = h ? Number.parseFloat(h.style.left) || 0 : 0;
                state.maxHandleLeft = Math.max(state.maxHandleLeft, Math.round(left));
                state.maxFillWidth = Math.max(
                    state.maxFillWidth, f ? Math.round(f.offsetWidth) : 0);
                state.geometry = {handle: box(h), fill: box(f), track: box(t)};
                state.raf = requestAnimationFrame(sample);
            };
            state.listeners = [];
            for (const type of Object.keys(state.counts)) {
                const listener = e => {
                    state.counts[type] += 1;
                    const p = point(e);
                    if (type === 'pointerdown') state.pointerDown = p;
                    if (type === 'pointerup') state.pointerUp = p;
                    if (type === 'mousedown') state.mouseDown = p;
                    if (type === 'mouseup') state.mouseUp = p;
                    if (type === 'pointermove' && (e.buttons & 1)) {
                        state.lastPressedPointer = p;
                    }
                    if (type === 'mousemove' && (e.buttons & 1)) {
                        state.lastPressedMouse = p;
                    }
                };
                state.listeners.push([type, listener]);
                document.addEventListener(type, listener, true);
            }
            window.__waferBaxiaEventContract = state;
            sample();
            return true;
        }""",
                deadline=deadline,
            )
            is True
        )
    except Exception:
        return False


def _clear_baxia_event_contract(
    frame,
    deadline: float | None = None,
) -> None:
    """Cancel page-side diagnostics and remove every injected listener."""

    try:
        _baxia_evaluate(
            frame,
            """() => {
            const state = window.__waferBaxiaEventContract;
            if (!state) return;
            if (state.raf) cancelAnimationFrame(state.raf);
            for (const [type, listener] of state.listeners || []) {
                document.removeEventListener(type, listener, true);
            }
            delete window.__waferBaxiaEventContract;
        }""",
            deadline=deadline,
        )
    except Exception:
        pass


def _baxia_event_contract(
    frame,
    deadline: float | None = None,
) -> dict | None:
    """Read only fixed numeric/boolean event trace fields, never DOM text."""

    try:
        value = _baxia_evaluate(
            frame,
            """() => {
            const state = window.__waferBaxiaEventContract;
            if (!state) return null;
            const hash = raw => {
                let result = 2166136261;
                for (const char of String(raw || '').slice(0, 512)) {
                    result ^= char.charCodeAt(0);
                    result = Math.imul(result, 16777619);
                }
                return (result >>> 0).toString(16).padStart(8, '0');
            };
            const since = state.pointerDown
                ? Math.max(0, state.pointerDown.t - 1000) : performance.now();
            const resources = performance.getEntriesByType('resource')
                .filter(entry => entry.startTime >= since)
                .slice(-32)
                .map(entry => {
                    let sourceHash = '00000000';
                    try {
                        const source = new URL(entry.name, document.baseURI);
                        sourceHash = hash(
                            `${source.protocol}//${source.hostname}${source.pathname}`);
                    } catch (_) {}
                    return {
                        sourceHash,
                        initiator: String(entry.initiatorType || '').slice(0, 16),
                        duration: Math.round(Number(entry.duration) || 0),
                        transfer: Math.round(Number(entry.transferSize) || 0),
                        status: Math.round(Number(entry.responseStatus) || 0),
                    };
                });
            return {...state, resources};
        }""",
            deadline=deadline,
        )
    except Exception:
        return None
    if not isinstance(value, dict):
        return None

    def number(raw) -> int:
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            return 0
        return max(-100_000, min(100_000, int(round(raw))))

    def point(raw) -> dict[str, int | bool] | None:
        if not isinstance(raw, dict):
            return None
        return {
            "x": number(raw.get("x")),
            "y": number(raw.get("y")),
            "screenX": number(raw.get("screenX")),
            "screenY": number(raw.get("screenY")),
            "t": number(raw.get("t")),
            "buttons": number(raw.get("buttons")),
            "button": number(raw.get("button")),
            "trusted": raw.get("trusted") is True,
        }

    def box(raw) -> dict[str, int] | None:
        if not isinstance(raw, dict):
            return None
        return {name: number(raw.get(name)) for name in ("x", "y", "width", "height")}

    counts = value.get("counts")
    geometry = value.get("geometry")
    resources = []
    for resource in value.get("resources", [])[:32]:
        if not isinstance(resource, dict):
            continue
        source_hash = resource.get("sourceHash")
        initiator = resource.get("initiator")
        resources.append(
            {
                "sourceHash": (
                    source_hash
                    if isinstance(source_hash, str)
                    and re.fullmatch(r"[0-9a-f]{8}", source_hash)
                    else "00000000"
                ),
                "initiator": (
                    initiator
                    if isinstance(initiator, str)
                    and re.fullmatch(r"[a-zA-Z]{0,16}", initiator)
                    else ""
                ),
                "duration": number(resource.get("duration")),
                "transfer": number(resource.get("transfer")),
                "status": number(resource.get("status")),
            }
        )
    return {
        "counts": {
            name: number(counts.get(name) if isinstance(counts, dict) else 0)
            for name in (
                "pointerdown",
                "pointermove",
                "pointerup",
                "mousedown",
                "mousemove",
                "mouseup",
            )
        },
        "pointerDown": point(value.get("pointerDown")),
        "lastPressedPointer": point(value.get("lastPressedPointer")),
        "pointerUp": point(value.get("pointerUp")),
        "mouseDown": point(value.get("mouseDown")),
        "lastPressedMouse": point(value.get("lastPressedMouse")),
        "mouseUp": point(value.get("mouseUp")),
        "maxHandleLeft": number(value.get("maxHandleLeft")),
        "maxFillWidth": number(value.get("maxFillWidth")),
        "resources": resources,
        "geometry": {
            name: box(geometry.get(name) if isinstance(geometry, dict) else None)
            for name in ("handle", "fill", "track")
        },
    }


def _baxia_structural_diagnostic(
    frame,
    deadline: float | None = None,
) -> dict | None:
    """Return bounded, content-free fingerprints for a live Baxia variant."""

    if not _baxia_diagnostics_enabled():
        return None
    try:
        value = _baxia_evaluate(
            frame,
            """() => {
            const clamp = n => Math.max(-100000, Math.min(
                100000, Math.round(Number(n) || 0)));
            const hash = raw => {
                let result = 2166136261;
                for (const char of String(raw || '').slice(0, 512)) {
                    result ^= char.charCodeAt(0);
                    result = Math.imul(result, 16777619);
                }
                return (result >>> 0).toString(16).padStart(8, '0');
            };
            const box = el => {
                const rect = el.getBoundingClientRect();
                return {
                    x: clamp(rect.x), y: clamp(rect.y),
                    width: clamp(rect.width), height: clamp(rect.height),
                };
            };
            const roots = [document];
            const elements = [];
            let shadowRoots = 0;
            for (let rootIndex = 0;
                rootIndex < roots.length && rootIndex < 64;
                rootIndex += 1) {
                const rootElements = Array.from(
                    roots[rootIndex].querySelectorAll('*')).slice(0, 5000);
                for (const element of rootElements) {
                    elements.push(element);
                    if (element.shadowRoot && roots.length < 64) {
                        roots.push(element.shadowRoot);
                        shadowRoots += 1;
                    }
                    if (elements.length >= 5000) break;
                }
                if (elements.length >= 5000) break;
            }
            const candidates = [];
            for (const element of elements) {
                const id = element.getAttribute('id') || '';
                const classes = element.getAttribute('class') || '';
                const role = element.getAttribute('role') || '';
                const token = `${id} ${classes} ${role}`.toLowerCase();
                const exact = {
                    handle: id === 'nc_1_n1z',
                    fill: id === 'nc_1__bg',
                    track: id === 'nc_1_n1t',
                };
                if (!(exact.handle || exact.fill || exact.track
                    || role.toLowerCase() === 'slider'
                    || /(captcha|slider|slide|drag|handle|nocaptcha|nc_)/.test(
                        token))) continue;
                const style = getComputedStyle(element);
                candidates.push({
                    tag: element.tagName.toLowerCase(),
                    idHash: hash(id),
                    classHash: hash(classes),
                    classCount: classes.trim()
                        ? classes.trim().split(/\\s+/).length : 0,
                    exact,
                    sliderRole: role.toLowerCase() === 'slider',
                    pointerHandler: typeof element.onpointerdown === 'function'
                        || typeof element.onmousedown === 'function',
                    visible: style.display !== 'none'
                        && style.visibility !== 'hidden'
                        && Number(style.opacity || 1) > 0,
                    box: box(element),
                });
                if (candidates.length >= 16) break;
            }
            const scripts = Array.from(document.scripts).slice(0, 64).map(
                script => {
                    if (!script.src) return {inline: true, sourceHash: null};
                    try {
                        const source = new URL(script.src, document.baseURI);
                        return {
                            inline: false,
                            sourceHash: hash(
                                `${source.protocol}//${source.hostname}${source.pathname}`),
                        };
                    } catch (_) {
                        return {inline: false, sourceHash: '00000000'};
                    }
                }).slice(0, 32);
            return {
                elementCount: elements.length,
                shadowRootCount: shadowRoots,
                iframeCount: document.querySelectorAll('iframe').length,
                canvasCount: document.querySelectorAll('canvas').length,
                svgCount: document.querySelectorAll('svg').length,
                scripts,
                candidates,
            };
        }""",
            deadline=deadline,
        )
    except Exception:
        return None
    if not isinstance(value, dict):
        return None

    def number(raw) -> int:
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            return 0
        return max(-100_000, min(100_000, int(round(raw))))

    counts = {
        name: number(value.get(name))
        for name in (
            "elementCount",
            "shadowRootCount",
            "iframeCount",
            "canvasCount",
            "svgCount",
        )
    }
    candidates = []
    allowed_tags = {
        "button",
        "canvas",
        "div",
        "input",
        "span",
        "svg",
    }
    for candidate in value.get("candidates", [])[:16]:
        if not isinstance(candidate, dict):
            continue
        exact = candidate.get("exact")
        box = candidate.get("box")
        candidates.append(
            {
                "tag": (
                    candidate.get("tag")
                    if candidate.get("tag") in allowed_tags
                    else "other"
                ),
                "idHash": (
                    candidate.get("idHash")
                    if isinstance(candidate.get("idHash"), str)
                    and re.fullmatch(r"[0-9a-f]{8}", candidate["idHash"])
                    else "00000000"
                ),
                "classHash": (
                    candidate.get("classHash")
                    if isinstance(candidate.get("classHash"), str)
                    and re.fullmatch(r"[0-9a-f]{8}", candidate["classHash"])
                    else "00000000"
                ),
                "classCount": number(candidate.get("classCount")),
                "exact": {
                    name: (isinstance(exact, dict) and exact.get(name) is True)
                    for name in ("handle", "fill", "track")
                },
                "sliderRole": candidate.get("sliderRole") is True,
                "pointerHandler": candidate.get("pointerHandler") is True,
                "visible": candidate.get("visible") is True,
                "box": {
                    name: number(box.get(name) if isinstance(box, dict) else 0)
                    for name in ("x", "y", "width", "height")
                },
            }
        )
    counts["candidates"] = candidates
    scripts = []
    for script in value.get("scripts", [])[:32]:
        if not isinstance(script, dict):
            continue
        source_hash = script.get("sourceHash")
        scripts.append(
            {
                "inline": script.get("inline") is True,
                "sourceHash": (
                    source_hash
                    if isinstance(source_hash, str)
                    and re.fullmatch(r"[0-9a-f]{8}", source_hash)
                    else None
                ),
            }
        )
    counts["scripts"] = scripts
    return counts


def _capture_baxia_diagnostic_screenshot(
    page,
    *,
    attempt: int,
    stage: str,
    deadline: float | None = None,
) -> bool:
    """Persist an opt-in screenshot without putting its path in logs."""

    if not _baxia_diagnostics_enabled():
        return False
    directory = os.environ.get("WAFER_BAXIA_DIAGNOSTIC_DIR")
    if not directory:
        return False
    path = Path(directory)
    if not path.is_absolute():
        return False
    safe_stage = (
        stage if stage in {"before", "layout", "pending", "rejected"} else "unknown"
    )
    try:
        remaining_ms = (
            2_000 if deadline is None else min(2_000, int(_remaining(deadline) * 1000))
        )
        if remaining_ms <= 0:
            return False
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        screenshot = path / (f"baxia-{time.time_ns()}-{attempt}-{safe_stage}.png")
        page.screenshot(
            path=str(screenshot),
            full_page=False,
            animations="disabled",
            timeout=max(1, remaining_ms),
        )
        screenshot.chmod(0o600)
        return True
    except Exception:
        return False


def _log_baxia_diagnostic(
    page,
    frame,
    issued_url: str,
    *,
    attempt: int,
    stage: str,
    deadline: float | None = None,
) -> None:
    """Capture one opt-in, value-free diagnostic checkpoint."""

    if not _baxia_diagnostics_enabled():
        return
    diagnostic_deadline = time.monotonic() + 2.0
    if deadline is not None:
        diagnostic_deadline = min(diagnostic_deadline, deadline)
    # A pending page is often mid-navigation or has already detached its
    # renderer. Capturing it can wedge Chrome's screenshot pipeline; the
    # bounded structural state and the pre-release screenshot retain the
    # useful evidence without consuming a browser-attempt budget.
    screenshot = (
        False
        if stage == "pending"
        else _capture_baxia_diagnostic_screenshot(
            page,
            attempt=attempt,
            stage=stage,
            deadline=diagnostic_deadline,
        )
    )
    logger.warning(
        "Baxia diagnostic stage=%s attempt=%d structure=%s transport=%s screenshot=%s",
        stage,
        attempt,
        _baxia_structural_diagnostic(frame, diagnostic_deadline),
        {
            "expectedCallback": _expected_baxia_callback(issued_url) is not None,
            "atExpectedCallback": _page_left_punish(page, issued_url),
            "atClearedApplicationTarget": _page_left_punish(
                page,
                issued_url,
                challenge_gone=True,
            ),
        },
        screenshot,
    )


def _baxia_browser_environment(
    page,
    deadline: float | None = None,
) -> dict[str, float] | None:
    """Return non-content browser geometry for a slider trace.

    The result deliberately excludes the URL, DOM text, cookies, and request
    data.  It permits safe production correlation of a challenge verdict with
    the native-window environment.
    """
    try:
        value = _baxia_evaluate(
            page,
            """() => ({
                screenX: window.screenX,
                screenY: window.screenY,
                outerWidth: window.outerWidth,
                outerHeight: window.outerHeight,
                innerWidth: window.innerWidth,
                innerHeight: window.innerHeight,
                availWidth: screen.availWidth,
                availHeight: screen.availHeight,
                dpr: window.devicePixelRatio,
            })""",
            deadline=deadline,
        )
    except Exception:
        return None
    if not isinstance(value, dict):
        return None
    fields = (
        "screenX",
        "screenY",
        "outerWidth",
        "outerHeight",
        "innerWidth",
        "innerHeight",
        "availWidth",
        "availHeight",
        "dpr",
    )
    if not all(isinstance(value.get(field), (int, float)) for field in fields):
        return None
    return {field: float(value[field]) for field in fields}


def _remaining(deadline: float | None) -> float:
    if deadline is None:
        return float("inf")
    return max(0.0, deadline - time.monotonic())


def _sleep_with_deadline(deadline: float | None, duration: float) -> bool:
    """Sleep no later than *deadline* and report whether budget remains."""

    remaining = _remaining(deadline)
    if remaining <= 0:
        return False
    time.sleep(min(duration, remaining))
    return _remaining(deadline) > 0


_BAXIA_CALLBACK_KEYS = (
    "redirect",
    "redirect_url",
    "return_url",
    "returnUrl",
    "target",
    "url",
)
_BAXIA_DENIED_CALLBACK_PARTS = (
    "/login",
    "/error",
    "/captcha",
    "/_____tmd_____/",
)


def _safe_baxia_target(issued_url: str):
    """Parse an immutable HTTPS Alibaba/AliExpress solve target."""

    try:
        target = urlparse(issued_url)
        port = target.port
    except (TypeError, ValueError):
        return None
    host = (target.hostname or "").lower()
    if (
        target.scheme != "https"
        or target.username is not None
        or target.password is not None
        or port not in (None, 443)
        or not any(
            host == family or host.endswith(f".{family}")
            for family in ("alibaba.com", "aliexpress.com")
        )
    ):
        return None
    return target


def _expected_baxia_punish_path(path: str, family: str) -> bool:
    """Validate a root or MTop-prefixed vendor punishment path.

    Live ACS responses can prefix the punishment suffix with the exact MTop
    endpoint that issued it (and can include a duplicate leading slash). Keep
    that real shape without accepting arbitrary path prefixes.
    """

    if not isinstance(path, str) or not path.startswith("/"):
        return False
    normalized = "/" + path.lstrip("/")
    candidate = normalized.rstrip("/")
    if candidate == _BAXIA_PUNISH_SUFFIX:
        return True
    if not candidate.endswith(_BAXIA_PUNISH_SUFFIX):
        return False
    prefix = candidate[: -len(_BAXIA_PUNISH_SUFFIX)]
    parts = prefix.split("/")
    if len(parts) != 4 or parts[0] or parts[1] != "h5":
        return False
    api_match = _BAXIA_MTOP_API_RE.fullmatch(parts[2])
    if api_match is None or api_match.group(1) + ".com" != family:
        return False
    return _BAXIA_MTOP_VERSION_RE.fullmatch(parts[3]) is not None


def _expected_baxia_callback(issued_url: str) -> str | None:
    """Return a safe callback carried by the immutable vendor-issued URL."""

    issued = _safe_baxia_target(issued_url)
    if issued is None:
        return None
    family = None
    issued_host = (issued.hostname or "").lower()
    for candidate in ("alibaba.com", "aliexpress.com"):
        if issued_host == candidate or issued_host.endswith("." + candidate):
            family = candidate
            break
    if family is None or not _expected_baxia_punish_path(issued.path, family):
        return None
    params = parse_qs(issued.query, keep_blank_values=False)
    for key in _BAXIA_CALLBACK_KEYS:
        values = params.get(key, [])
        if len(values) != 1:
            continue
        try:
            callback = urlparse(values[0])
            port = callback.port
        except (TypeError, ValueError):
            continue
        host = (callback.hostname or "").lower()
        path = callback.path.lower()
        if (
            callback.scheme != "https"
            or callback.username is not None
            or callback.password is not None
            or port not in (None, 443)
            or not (host == family or host.endswith("." + family))
            or any(part in path for part in _BAXIA_DENIED_CALLBACK_PARTS)
        ):
            continue
        return callback.geturl()
    return None


def _expected_baxia_application_target(issued_url: str) -> str | None:
    """Return an immutable non-punishment application solve target.

    BrowserSolver is normally issued the application URL that triggered the
    TMD response.  A successful inline Baxia solve can therefore return to
    that exact URL rather than to an encoded punishment callback.
    """

    issued = _safe_baxia_target(issued_url)
    if issued is None:
        return None
    host = (issued.hostname or "").lower()
    family = next(
        (
            candidate
            for candidate in ("alibaba.com", "aliexpress.com")
            if host == candidate or host.endswith("." + candidate)
        ),
        None,
    )
    path = issued.path.lower()
    if (
        family is None
        or host in {"acs.alibaba.com", "acs.aliexpress.com"}
        or _expected_baxia_punish_path(issued.path, family)
        or any(part in path for part in _BAXIA_DENIED_CALLBACK_PARTS)
    ):
        return None
    return issued._replace(fragment="").geturl()


def _page_left_punish(
    page,
    issued_url: str,
    *,
    challenge_gone: bool = False,
) -> bool:
    """Require the exact callback or a cleared exact application target.

    An unchanged application URL cannot alone prove success because an inline
    slider can be displayed over that URL.  Callers may recognize it only
    after independently proving the Baxia handle is gone.
    """

    expected = _expected_baxia_callback(issued_url)
    if expected is None:
        if not challenge_gone:
            return False
        expected = _expected_baxia_application_target(issued_url)
        if expected is None:
            return False
    try:
        current = urlparse(page.url)._replace(fragment="")
        target = urlparse(expected)._replace(fragment="")
        return current == target
    except Exception:
        return False


def _page_reached_baxia_target(
    page,
    issued_url: str,
    deadline: float | None,
) -> bool:
    """Recognize only a strict callback or a challenge-free exact target.

    The widget iframe disappearing is not enough. Live Alibaba failures leave
    the main document at the exact application URL with no Baxia frame while
    its DOM is still the ``_____tmd_____`` "Captcha Interception" page. Treating
    that teardown state as navigation clearance makes the outer solver import
    ordinary ``tfstk``/``arms_uid`` cookies and replay a request that is still
    challenged.
    """

    if _expected_baxia_callback(issued_url) is not None:
        if not _page_left_punish(page, issued_url):
            return False
    else:
        if not _page_left_punish(
            page,
            issued_url,
            challenge_gone=True,
        ):
            return False
        probe_deadline = time.monotonic() + 0.35
        if deadline is not None:
            probe_deadline = min(probe_deadline, deadline)
        if _remaining(probe_deadline) <= 0:
            return False
        try:
            if _find_baxia_frame(page, probe_deadline) is not None:
                return False
        except Exception:
            return False

    try:
        html = page.content()
    except Exception:
        return False
    if not isinstance(html, str) or not html:
        return False

    # This is the exact body marker used by the status-200 TMD detector. Avoid
    # calling the logging detector from a 200ms poll: a rejected document can
    # remain here for the whole clearance window and would emit dozens of
    # duplicate "Challenge detected" lines.
    return "/_____tmd_____/punish" not in html


def _baxia_clearance_signatures(
    page,
    issued_url: str,
) -> set[tuple[str, str, str]]:
    """Return value-bearing identities for target-scoped x5sec cookies.

    Values are retained only for in-memory before/after comparison and are
    never returned to callers or logs.
    """

    target = _expected_baxia_callback(issued_url)
    parsed = _safe_baxia_target(target or issued_url)
    if parsed is None:
        return set()
    host = (parsed.hostname or "").lower()
    request_path = parsed.path or "/"
    try:
        cookies = page.context.cookies()
    except Exception:
        return set()
    if not isinstance(cookies, list):
        return set()

    signatures: set[tuple[str, str, str]] = set()
    for cookie in cookies:
        if not isinstance(cookie, dict) or cookie.get("name") != "x5sec":
            continue
        try:
            domain = str(cookie.get("domain", "")).lstrip(".").lower()
            path = str(cookie.get("path", "/")) or "/"
            value = cookie.get("value")
            expires = cookie.get("expires", cookie.get("expirationDate", 0))
            expiry = float(expires) if expires not in (None, "") else 0.0
        except (TypeError, ValueError):
            continue
        domain_applies = bool(domain) and (
            host == domain or host.endswith(f".{domain}")
        )
        path_applies = request_path.startswith(path) and (
            path.endswith("/")
            or len(request_path) == len(path)
            or request_path[len(path)] == "/"
        )
        if (
            domain_applies
            and path_applies
            and isinstance(value, str)
            and bool(value)
            and (expiry <= 0 or expiry > time.time())
        ):
            signatures.add((domain, path, value))
    return signatures


def _viewport_size(
    page,
    deadline: float | None = None,
) -> dict[str, float]:
    """Return usable viewport dimensions even for no-viewport contexts.

    Patchright exposes ``page.viewport_size`` as ``None`` when the browser
    context uses the native window size. Baxia still needs coordinates for the
    pre-drag browsing motion, so read the actual DOM viewport before falling
    back to the same conservative desktop size BrowserSolver launches with.
    """
    viewport = page.viewport_size
    if isinstance(viewport, dict):
        width = viewport.get("width")
        height = viewport.get("height")
        if (
            isinstance(width, (int, float))
            and width > 0
            and isinstance(height, (int, float))
            and height > 0
        ):
            return {"width": float(width), "height": float(height)}
    try:
        measured = _baxia_evaluate(
            page,
            "() => ({width: window.innerWidth, height: window.innerHeight})",
            deadline=deadline,
        )
    except Exception:
        measured = None
    if isinstance(measured, dict):
        width = measured.get("width")
        height = measured.get("height")
        if (
            isinstance(width, (int, float))
            and width > 0
            and isinstance(height, (int, float))
            and height > 0
        ):
            return {"width": float(width), "height": float(height)}
    logger.warning("Could not read browser viewport; using 1280x720")
    return {"width": 1280.0, "height": 720.0}


def _attempt_baxia_drag(
    solver,
    page,
    frame,
    max_attempts: int = 5,
    *,
    deadline: float | None = None,
    issued_url: str,
) -> bool:
    """Attempt the Baxia slider drag with retries.

    Each attempt uses a different recording and waits for the widget
    to reset between retries.
    """
    viewport = _viewport_size(page, deadline)
    recent_recordings = getattr(
        solver,
        "_baxia_recent_drag_recordings",
        None,
    )
    used_drag_recordings = (
        set(recent_recordings) if isinstance(recent_recordings, list) else set()
    )

    for attempt in range(max_attempts):
        if _remaining(deadline) <= 0:
            return False
        # Get fresh geometry.  Baxia commonly destroys the rejected widget
        # instead of resetting it in place, so do not keep using a stale frame
        # from the previous attempt.
        if attempt:
            fresh_frame = _find_baxia_frame(page, deadline)
            if fresh_frame is not None:
                frame = fresh_frame
        ready = _wait_for_baxia_geometry(page, frame, deadline)
        if ready is None:
            logger.warning("Baxia slider never reached a usable layout")
            return False
        frame, geom = ready
        handle_box, max_slide = geom

        handle_cx = handle_box["x"] + handle_box["width"] / 2
        handle_cy = handle_box["y"] + handle_box["height"] / 2

        # Iframe offset for child frames. Without it the coordinates below are
        # frame-relative while the input is dispatched page-relative, so the
        # press lands on empty page: the widget renders, the drag runs, and the
        # handle never moves. Skip the attempt rather than dispatch into the
        # void -- a later attempt re-resolves against a freshly found frame.
        if frame is not page:
            iframe_offset = _baxia_frame_offset(page, frame, deadline)
            if iframe_offset is None:
                logger.warning(
                    "Baxia iframe offset unresolved; skipping attempt %d/%d",
                    attempt + 1,
                    max_attempts,
                )
                continue
            handle_cx += iframe_offset["x"]
            handle_cy += iframe_offset["y"]

        end_x = handle_cx + max_slide
        end_y = handle_cy

        environment = _baxia_browser_environment(page, deadline)
        if environment is not None:
            logger.info(
                "Baxia browser environment: screen=(%.0f,%.0f) "
                "outer=%.0fx%.0f inner=%.0fx%.0f avail=%.0fx%.0f dpr=%.2f",
                environment["screenX"],
                environment["screenY"],
                environment["outerWidth"],
                environment["outerHeight"],
                environment["innerWidth"],
                environment["innerHeight"],
                environment["availWidth"],
                environment["availHeight"],
                environment["dpr"],
            )

        logger.info(
            "Baxia attempt %d/%d: handle=(%.0f, %.0f) max_slide=%.0fpx",
            attempt + 1,
            max_attempts,
            handle_cx,
            handle_cy,
            max_slide,
        )
        # Browse activity before approaching handle
        bx = viewport["width"] * random.uniform(0.3, 0.7)
        by = viewport["height"] * random.uniform(0.2, 0.4)
        browse_state = solver._start_browse(page, bx, by)
        settle = 1.0 + random.random() if attempt == 0 else 2.0 + random.random()
        solver._replay_browse_chunk(
            page,
            browse_state,
            min(settle, _remaining(deadline)),
        )
        if _remaining(deadline) <= 0:
            return False

        # Drag: full-width slide using slide recordings. Page-side diagnostics
        # are invasive and therefore disabled unless explicitly requested.
        _log_baxia_diagnostic(
            page,
            frame,
            issued_url,
            attempt=attempt + 1,
            stage="before",
            deadline=deadline,
        )
        diagnostics_installed = _install_baxia_event_contract(
            frame,
            deadline,
        )
        contract = None
        orig_drags = solver._drag_recordings
        if solver._slide_recordings:
            solver._drag_recordings = solver._slide_recordings
        try:
            replayed = solver._replay_drag(
                page,
                handle_cx,
                handle_cy,
                end_x,
                end_y,
                deadline=deadline,
                telemetry_label="Baxia",
                exclude_recordings=used_drag_recordings,
                recording_pool_size=15,
                approach_from=(bx, by),
                full_track_slide=True,
            )
            selected_recording = getattr(solver, "_last_drag_recording_name", None)
            if isinstance(selected_recording, str):
                used_drag_recordings.add(selected_recording)
                if isinstance(recent_recordings, list):
                    if selected_recording in recent_recordings:
                        recent_recordings.remove(selected_recording)
                    recent_recordings.append(selected_recording)
                    del recent_recordings[:-14]
        finally:
            solver._drag_recordings = orig_drags
            if diagnostics_installed:
                contract = _baxia_event_contract(frame, deadline)
                _clear_baxia_event_contract(frame, deadline)

        if not replayed:
            return False
        if contract is not None:
            logger.info(
                "Baxia release contract: target=(%.0f,%.0f) counts=%s "
                "pointer_down=%s pointer_last=%s pointer_up=%s "
                "mouse_down=%s mouse_last=%s mouse_up=%s max_left=%s "
                "max_fill=%s geometry=%s",
                end_x,
                end_y,
                contract.get("counts"),
                contract.get("pointerDown"),
                contract.get("lastPressedPointer"),
                contract.get("pointerUp"),
                contract.get("mouseDown"),
                contract.get("lastPressedMouse"),
                contract.get("mouseUp"),
                contract.get("maxHandleLeft"),
                contract.get("maxFillWidth"),
                contract.get("geometry"),
            )
            if contract.get("resources"):
                logger.info(
                    "Baxia release resources=%s",
                    contract["resources"],
                )

        # Verify result — check URL first (Baxia redirects on success)
        try:
            saw_movement = _baxia_has_movement(frame, deadline)
        except Exception:
            saw_movement = False
        for _ in range(15):
            if not _sleep_with_deadline(deadline, 0.3):
                return False
            if _page_reached_baxia_target(page, issued_url, deadline):
                logger.info("Baxia solved via expected target navigation")
                return True
            try:
                saw_movement = saw_movement or _baxia_has_movement(
                    frame,
                    deadline,
                )
                rejection: dict[str, str | None] = {}
                result = _check_baxia_result(
                    frame,
                    saw_movement=saw_movement,
                    rejection=rejection,
                    deadline=deadline,
                )
            except Exception:
                if _page_reached_baxia_target(page, issued_url, deadline):
                    logger.info("Baxia solved via expected target navigation")
                    return True
                logger.info("Baxia frame detached during result check")
                return False
            if result is True:
                # This is intentionally intermediate evidence. The outer TMD
                # dispatcher verifies a new target-scoped x5sec before it
                # returns a solved result to the HTTP client.
                logger.info("Baxia widget reports intermediate success")
                return True
            if result is False:
                _log_baxia_diagnostic(
                    page,
                    frame,
                    issued_url,
                    attempt=attempt + 1,
                    stage="rejected",
                    deadline=deadline,
                )
                diagnostic = _baxia_rejection_diagnostic(
                    frame,
                    rejection,
                    deadline,
                )
                if diagnostic is not None:
                    logger.warning(
                        "Baxia rejection state: handle=%s left=%s "
                        "fill=%s track=%s explicit_error=%s category=%s code=%s",
                        diagnostic["handle"],
                        diagnostic["handleLeft"],
                        diagnostic["fillWidth"],
                        diagnostic["trackWidth"],
                        diagnostic["explicitError"],
                        diagnostic["errorCategory"],
                        diagnostic["errorCode"],
                    )
                logger.info(
                    "Baxia slider rejected (attempt %d/%d)",
                    attempt + 1,
                    max_attempts,
                )
                break
        else:
            _log_baxia_diagnostic(
                page,
                frame,
                issued_url,
                attempt=attempt + 1,
                stage="pending",
                deadline=deadline,
            )
            logger.warning("Baxia result remained pending after release")

        if attempt < max_attempts - 1:
            # Wait briefly for an in-place reset.  In production Baxia often
            # removes the failed widget permanently; the old ten-second wait
            # then retried a dead frame and made ``max_attempts=3`` effectively
            # a single attempt.  Reload the challenged page when no fresh
            # handle appears, and rediscover the frame before retrying.
            logger.info("Waiting for Baxia widget to reset...")
            reset_frame = None
            for _ in range(4):
                if not _sleep_with_deadline(deadline, 0.5):
                    return False
                try:
                    candidate = _find_baxia_frame(page, deadline)
                    if candidate is not None:
                        # Check it is back to the initial state rather than
                        # rediscovering the still-rejecting widget.
                        left = _baxia_evaluate(
                            candidate,
                            """() => {
                            const h = document.querySelector('#nc_1_n1z');
                            return h ? parseInt(h.style.left) || 0 : -1;
                        }""",
                            deadline=deadline,
                        )
                        if left == 0:
                            reset_frame = candidate
                            break
                except Exception:
                    continue
            if reset_frame is None:
                remaining = _remaining(deadline)
                remaining_ms = (
                    30_000 if remaining == float("inf") else int(remaining * 1000)
                )
                if remaining_ms <= 0:
                    return False
                issued_target = _safe_baxia_target(issued_url)
                issued_family = None
                if issued_target is not None:
                    issued_host = (issued_target.hostname or "").lower()
                    issued_family = next(
                        (
                            family
                            for family in ("alibaba.com", "aliexpress.com")
                            if issued_host == family
                            or issued_host.endswith("." + family)
                        ),
                        None,
                    )
                issued_is_punish = (
                    issued_target is not None
                    and issued_family is not None
                    and _expected_baxia_punish_path(
                        issued_target.path,
                        issued_family,
                    )
                )
                refresh_target = (
                    None if issued_target is None or issued_is_punish else issued_url
                )
                logger.info("Baxia widget did not reset; requesting a fresh challenge")
                try:
                    navigation_kwargs = {
                        # Baxia's challenge subresources can deliberately keep
                        # DOMContentLoaded pending. A committed replacement
                        # document is enough; bounded selector discovery below
                        # proves whether its widget actually became usable.
                        "wait_until": "commit",
                        "timeout": max(1, min(5_000, remaining_ms)),
                    }
                    if refresh_target is None:
                        page.reload(**navigation_kwargs)
                    else:
                        # A punishment URL is one-use. Reloading it commonly
                        # leaves a dead shell; revisiting the immutable,
                        # validated application URL obtains the next genuine
                        # challenge while keeping navigation in-family.
                        page.goto(refresh_target, **navigation_kwargs)
                except Exception:
                    # A navigation timeout does not necessarily mean the page
                    # failed to commit; continue with bounded frame discovery.
                    logger.debug(
                        "Baxia challenge refresh did not commit before timeout"
                    )
                rediscovery_deadline = time.monotonic() + 30.0
                if deadline is not None:
                    rediscovery_deadline = min(
                        rediscovery_deadline,
                        deadline,
                    )
                while _remaining(rediscovery_deadline) > 0:
                    if _page_left_punish(page, issued_url):
                        logger.info("Baxia solved via expected callback during reload")
                        return True
                    try:
                        reset_frame = _find_baxia_frame(
                            page,
                            rediscovery_deadline,
                        )
                    except Exception:
                        reset_frame = None
                    if reset_frame is not None:
                        break
                    if not _sleep_with_deadline(rediscovery_deadline, 0.25):
                        return False
                if reset_frame is None:
                    logger.warning("Baxia slider did not reappear after reload")
                    return False

            frame = reset_frame
            if frame is not page:
                from wafer.browser._solver import patch_frame_screenxy

                patch_frame_screenxy(
                    frame,
                    needs_patch=bool(getattr(solver, "_needs_screenxy_patch", False)),
                    timeout_ms=max(
                        1,
                        min(1_000, int(_remaining(deadline) * 1000)),
                    ),
                )

    return False


def solve_baxia(
    solver,
    page,
    timeout_ms: int,
    *,
    challenge_url: str | None = None,
) -> bool:
    """Solve a Baxia NoCaptcha "slide to verify" challenge.

    No CV needed — always drags the full track width (left→right).
    The challenge monitors mouse behavior (timing, wobble, speed)
    rather than position accuracy. A punishment document receives one drag;
    the HTTP transport may retry TMD in a fresh context with a distinct
    recording when the caller's absolute deadline can fund it.

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
        frame = _find_baxia_frame(page, deadline)
        if frame:
            break
        if not _sleep_with_deadline(deadline, 0.5):
            return False

    if not frame:
        logger.warning("Baxia NoCaptcha slider not found")
        return False

    # The main frame already receives the conditional init script in
    # BrowserSolver._prepare_page. Reapplying it here wraps MouseEvent twice
    # and can leave PointerEvent half-patched. Only an OOPIF needs a direct
    # compatibility injection.
    if frame is not page:
        from wafer.browser._solver import patch_frame_screenxy

        patch_frame_screenxy(
            frame,
            needs_patch=bool(getattr(solver, "_needs_screenxy_patch", False)),
            timeout_ms=max(
                1,
                min(1_000, int(_remaining(deadline) * 1000)),
            ),
        )

    # Wait for handle to be visible
    try:
        selector_ms = max(1, int(_remaining(deadline) * 1000))
        frame.wait_for_selector(
            _BAXIA["handle"],
            state="visible",
            timeout=min(5000, selector_ms),
        )
    except Exception:
        logger.warning("Baxia handle not visible")
        return False

    # A rejected Baxia punishment document is one-use. Transport-level TMD
    # retry creates a fresh browser context and revisits the immutable
    # application URL; retrying several recordings inside this dead document
    # cannot obtain a new authoritative clearance.
    #
    # Measured 2026-07-31, because the widget looks retryable and invites
    # this change: after a rejection Baxia destroys the widget and recreates
    # it reset in place (handle back at left == 0), so the retry loop's reset
    # poll does find a fresh handle. It is not worth taking. Across 5 live
    # gated requests at max_attempts=2, every single in-widget attempt 2/2
    # was rejected and every success came from attempt 1 in a fresh context,
    # while failures grew from ~67s to ~120s -- the retry only spent the
    # deadline that pays for the fresh context which actually works.
    return _attempt_baxia_drag(
        solver,
        page,
        frame,
        max_attempts=1,
        deadline=deadline,
        issued_url=challenge_url or page.url,
    )
