"""Live solve: GeeTest v4 slide CAPTCHA on geetest.com demo.

Navigates to the demo page, selects Slide CAPTCHA + Bind style,
triggers the puzzle, then solves using the full _drag.py pipeline
(network intercept → CV → mousse replay).

Usage:
    uv run python tests/live_geetest_demo.py
"""

import logging
import random
import time
from pathlib import Path
from urllib.parse import urlparse

from patchright.sync_api import sync_playwright

from wafer.browser._cv import find_notch
from wafer.browser._drag import (
    _check_result,
    _extract_images_from_dom,
    _get_geometry,
    _png_width,
    _wait_for_puzzle,
)
from wafer.browser._solver import BrowserSolver

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-7s %(message)s",
)
log = logging.getLogger("live_gt")

DEMO_URL = "https://www.geetest.com/en/adaptive-captcha-demo"
EXTENSION_PATH = str(Path("wafer/browser/_extensions/screenxy").resolve())


def setup_logged_intercept(page):
    """Attach network intercept with URL logging.

    Returns a mutable dict that gets populated as images arrive.
    Call ``reset()`` on the returned dict before triggering the CAPTCHA
    to discard any SDK/UI assets captured during page setup.
    """
    captured: dict[str, bytes | None] = {"bg": None, "piece": None}

    def _on_response(response):
        try:
            host = urlparse(response.url).hostname or ""
            if not (host == "static.geetest.com"
                    or host.endswith(".geetest.com")):
                return
            ct = response.headers.get("content-type", "")
            if "image/png" not in ct and not response.url.endswith(".png"):
                return
            body = response.body()
            if not body:
                return
            path = urlparse(response.url).path
            log.info(
                "[NET] PNG %s (%d bytes) from %s",
                path.split("/")[-1], len(body), host,
            )
            if len(body) > 20_000:
                captured["bg"] = body
                log.info("  -> classified as BG")
            else:
                captured["piece"] = body
                log.info("  -> classified as PIECE")
        except Exception:
            pass

    page.on("response", _on_response)
    return captured


def navigate_and_trigger(page, captured):
    """Navigate to demo, select Slide CAPTCHA + Bind, trigger."""
    log.info("Navigating to %s", DEMO_URL)
    page.goto(DEMO_URL, wait_until="domcontentloaded")
    time.sleep(5)

    # Scroll past sticky header
    page.evaluate("window.scrollBy(0, 400)")
    time.sleep(1)

    # Select "Slide CAPTCHA" tab
    log.info("Selecting Slide CAPTCHA...")
    tab = page.locator(".tab-item.tab-item-1").first
    tab.scroll_into_view_if_needed(timeout=5000)
    tab.click(timeout=5000)
    time.sleep(2)

    # Select "Bind to button" style (most reliable trigger)
    log.info("Selecting Bind style...")
    el = page.locator("text=Bind to button").first
    el.scroll_into_view_if_needed(timeout=3000)
    el.click(timeout=3000)
    time.sleep(1)

    # CRITICAL: Reset captured images before triggering.
    # SDK/UI PNGs from page setup are NOT puzzle images.
    log.info("Resetting captured images before trigger...")
    captured["bg"] = None
    captured["piece"] = None

    # Trigger CAPTCHA by clicking login
    log.info("Clicking login to trigger CAPTCHA...")
    btn = page.locator("text=login").first
    btn.scroll_into_view_if_needed(timeout=3000)
    btn.click(timeout=5000)


def solve_attempt(solver, page, captured) -> bool:
    """One solve attempt using _drag.py components directly."""
    vendor = "geetest"

    # Wait for puzzle widget
    if not _wait_for_puzzle(page, vendor, 15000):
        log.error("Puzzle not visible")
        return False

    # Wait for network intercept to capture images
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if captured["bg"] and captured["piece"]:
            break
        time.sleep(0.2)

    bg_png = captured["bg"]
    piece_png = captured["piece"]

    # Fallback: DOM extraction (same origin on geetest.com)
    if not bg_png or not piece_png:
        log.info("Network intercept incomplete, trying DOM extraction")
        bg_dom, piece_dom = _extract_images_from_dom(page, vendor)
        bg_png = bg_png or bg_dom
        piece_png = piece_png or piece_dom

    if not bg_png or not piece_png:
        log.error(
            "Could not extract images (bg=%s, piece=%s)",
            f"{len(bg_png)}B" if bg_png else "None",
            f"{len(piece_png)}B" if piece_png else "None",
        )
        return False

    log.info("Images: bg=%d bytes, piece=%d bytes", len(bg_png), len(piece_png))

    # Save images for debugging
    out = Path("recon_output/geetest/cv_debug")
    out.mkdir(parents=True, exist_ok=True)
    (out / "bg.png").write_bytes(bg_png)
    (out / "piece.png").write_bytes(piece_png)
    log.info("Saved puzzle images to %s", out)

    # Check image dimensions
    import struct
    bg_w = struct.unpack(">I", bg_png[16:20])[0]
    bg_h = struct.unpack(">I", bg_png[20:24])[0]
    piece_w = struct.unpack(">I", piece_png[16:20])[0]
    piece_h = struct.unpack(">I", piece_png[20:24])[0]
    log.info("Dimensions: bg=%dx%d, piece=%dx%d", bg_w, bg_h, piece_w, piece_h)

    # CV: find notch offset
    x_offset, confidence = find_notch(bg_png, piece_png)
    log.info("CV notch: x=%d confidence=%.3f", x_offset, confidence)

    if confidence < 0.10:
        log.warning("CV confidence too low (%.3f)", confidence)
        return False
    if confidence < 0.30:
        log.warning("CV confidence below normal (%.3f) — trying anyway", confidence)

    # Slider geometry
    geom = _get_geometry(page, vendor)
    if not geom:
        log.error("Could not read slider geometry")
        return False
    handle_box, track_width, bg_rendered_width = geom

    handle_cx = handle_box["x"] + handle_box["width"] / 2
    handle_cy = handle_box["y"] + handle_box["height"] / 2
    handle_w = handle_box["width"]
    max_slide = track_width - handle_w

    native_bg_w = _png_width(bg_png)
    native_piece_w = _png_width(piece_png)

    if native_bg_w <= native_piece_w:
        log.error("Invalid dims: bg=%d, piece=%d", native_bg_w, native_piece_w)
        return False

    handle_target = (x_offset / (native_bg_w - native_piece_w)) * max_slide
    end_x = handle_cx + handle_target
    end_y = handle_cy

    log.info(
        "Drag plan: offset=%d bg=%d piece=%d max_slide=%.0f target=%.0fpx",
        x_offset, native_bg_w, native_piece_w, max_slide, handle_target,
    )

    # Mouse replay: path → drag (skip idle — CAPTCHA popup has a
    # timeout, and idle wastes 2-3s we don't have)
    viewport = page.viewport_size
    idle_x = viewport["width"] * random.uniform(0.3, 0.7)
    idle_y = viewport["height"] * random.uniform(0.3, 0.5)
    page.mouse.move(idle_x, idle_y)

    log.info("Replaying path to handle...")
    solver._replay_path(page, idle_x, idle_y, handle_cx, handle_cy)

    log.info("Replaying drag (%.0fpx)...", handle_target)
    solver._replay_drag(page, handle_cx, handle_cy, end_x, end_y)

    # Verify result
    for _ in range(10):
        time.sleep(0.3)
        result = _check_result(page, vendor)
        if result is True:
            log.info("SOLVED!")
            return True
        if result is False:
            log.info("Rejected (wrong position)")
            return False

    log.info("No clear result after 3s")
    return False


def main():
    solver = BrowserSolver()
    solver._ensure_recordings()
    log.info(
        "Recordings: %d idle, %d path, %d drag",
        len(solver._idle_recordings or []),
        len(solver._path_recordings or []),
        len(solver._drag_recordings or []),
    )

    with sync_playwright() as p:
        browser = p.chromium.launch(
            channel="chrome",
            headless=False,
            args=[
                f"--disable-extensions-except={EXTENSION_PATH}",
                f"--load-extension={EXTENSION_PATH}",
            ],
        )
        page = browser.new_page(viewport={"width": 1280, "height": 800})

        # Set up network intercept early — catches all PNGs from
        # static.geetest.com.  We reset the dict before triggering
        # to discard SDK/UI assets captured during page setup.
        captured = setup_logged_intercept(page)

        navigate_and_trigger(page, captured)

        success = solve_attempt(solver, page, captured)

        if success:
            log.info("=== SUCCESS ===")
        else:
            log.info("=== FAILED ===")
            # Save screenshot for debugging
            page.screenshot(path="recon_output/geetest/screenshots/fail_live.png")
            log.info("Failure screenshot saved")

        time.sleep(5)
        browser.close()


if __name__ == "__main__":
    main()
