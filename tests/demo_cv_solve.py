"""Demo: solve the GeeTest slide mock using CV + mousse recordings.

Opens the mock HTML in a real browser, uses BrowserSolver's human
mouse replay (idle, path, drag) to interact realistically.

Usage:
    uv run python tests/demo_cv_solve.py
"""

import base64
import random
import time
from pathlib import Path

from patchright.sync_api import sync_playwright

from wafer.browser._cv import find_notch
from wafer.browser._solver import BrowserSolver

MOCK_PATH = Path(__file__).parent / "mocks" / "geetest" / "slide.html"
MOCK_URL = f"file://{MOCK_PATH.resolve()}"


def extract_png(page, selector: str) -> bytes:
    """Extract raw PNG bytes from a CSS background-image data URL."""
    data_url = page.evaluate(f"""
        getComputedStyle(document.querySelector('{selector}'))
            .backgroundImage.slice(5, -2)
    """)
    _, encoded = data_url.split(",", 1)
    return base64.b64decode(encoded)


def solve_attempt(solver: BrowserSolver, page) -> bool:
    """Run one CV + drag attempt on the visible puzzle."""
    # --- Idle: human looks at puzzle before acting ---
    viewport = page.viewport_size
    idle_x = viewport["width"] * random.uniform(0.3, 0.7)
    idle_y = viewport["height"] * random.uniform(0.3, 0.5)
    print("  Idle: replaying mouse movement...")
    solver._replay_idle(page, idle_x, idle_y)

    # --- CV: extract images and find notch ---
    bg_png = extract_png(page, "#gt-bg")
    piece_png = extract_png(page, "#gt-piece-bg")

    x_offset, confidence = find_notch(bg_png, piece_png)
    true_x = page.evaluate("targetX")
    print(
        f"  CV: x={x_offset} (truth={true_x}, "
        f"err={abs(x_offset - true_x)}px, conf={confidence:.3f})"
    )

    if confidence < 0.3:
        print("  Low confidence, skipping drag")
        return False

    # --- Path: move mouse from idle position to slider handle ---
    handle = page.locator("#gt-handle")
    handle.wait_for(state="visible", timeout=5000)
    hbox = handle.bounding_box()
    handle_cx = hbox["x"] + hbox["width"] / 2
    handle_cy = hbox["y"] + hbox["height"] / 2

    print("  Path: moving to handle...")
    solver._replay_path(page, idle_x, idle_y, handle_cx, handle_cy)
    time.sleep(random.uniform(0.1, 0.3))

    # --- Drag: use mousse recording for realistic motion ---
    track_w = page.evaluate(
        "document.getElementById('gt-track').offsetWidth"
    )
    handle_w_px = hbox["width"]
    max_slide = track_w - handle_w_px
    piece_size = page.evaluate("PIECE_SIZE")
    native_bg_w = page.evaluate("BG_W")

    handle_target = (x_offset / (native_bg_w - piece_size)) * max_slide
    end_x = handle_cx + handle_target
    end_y = handle_cy

    print(f"  Drag: {handle_target:.0f}px via mousse recording...")
    solver._replay_drag(page, handle_cx, handle_cy, end_x, end_y)
    time.sleep(1)

    # --- Check result ---
    is_solved = page.evaluate("solved")
    result_text = page.locator("#gt-result").text_content() or ""
    print(f"  Result: {'SOLVED' if is_solved else 'FAIL'} — {result_text}")
    return is_solved


def main():
    print(f"Mock: {MOCK_PATH.name}\n")

    solver = BrowserSolver()
    solver._ensure_recordings()
    n_idle = len(solver._idle_recordings or [])
    n_path = len(solver._path_recordings or [])
    n_drag = len(solver._drag_recordings or [])
    print(f"Recordings: {n_idle} idle, {n_path} path, {n_drag} drag\n")

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=False)
        page = browser.new_page(viewport={"width": 800, "height": 700})
        page.goto(MOCK_URL, wait_until="domcontentloaded")
        time.sleep(0.5)

        # Remove debug overlay
        page.evaluate("""
            document.getElementById('debug').remove();
            document.getElementById('canvas').remove();
        """)

        # Trigger CAPTCHA once — the mock resets puzzle in-place on failure
        page.click("#login-btn")
        page.locator(".geetest_box.geetest_show").wait_for(
            state="visible", timeout=10000
        )
        time.sleep(1)

        for attempt in range(1, 6):
            print(f"Attempt {attempt}:")

            # Wait for puzzle to be ready (fresh or after reset)
            page.evaluate("void 0")  # sync
            ready = False
            for _ in range(20):
                ready = page.evaluate("isReady")
                if ready:
                    break
                time.sleep(0.25)
            if not ready:
                print("  Puzzle not ready, waiting...")
                time.sleep(2)

            if solve_attempt(solver, page):
                print("\nSolved!")
                time.sleep(3)
                break

            print("  Waiting for puzzle reset...\n")
            time.sleep(2)
        else:
            print("\nFailed after 5 attempts")

        browser.close()


if __name__ == "__main__":
    main()
