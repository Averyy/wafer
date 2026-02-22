"""Demo: solve the Baxia NoCaptcha mock using slide recordings.

Opens the mock HTML in a real browser, uses BrowserSolver's human
mouse replay (path + slide drag) to solve the "slide to verify" slider.

Usage:
    uv run python tests/demo_baxia_solve.py
"""

import logging
import time
from pathlib import Path

from patchright.sync_api import sync_playwright

from wafer.browser._drag import solve_baxia
from wafer.browser._solver import BrowserSolver

logging.basicConfig(
    level=logging.INFO,
    format="%(name)s %(levelname)s %(message)s",
)

MOCK_PATH = Path(__file__).parent / "mocks" / "baxia" / "slide.html"
MOCK_URL = f"file://{MOCK_PATH.resolve()}"


def main():
    print(f"Mock: {MOCK_PATH.name}\n")

    solver = BrowserSolver()
    solver._ensure_recordings()
    n_path = len(solver._path_recordings or [])
    n_drag = len(solver._drag_recordings or [])
    n_slide = len(solver._slide_recordings or [])
    print(f"Recordings: {n_path} path, {n_drag} drag, {n_slide} slide\n")

    if not n_slide:
        print("ERROR: No slide recordings found!")
        return

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=False)
        page = browser.new_page(viewport={"width": 1280, "height": 720})
        page.goto(MOCK_URL, wait_until="domcontentloaded")
        time.sleep(0.5)

        print("Solving Baxia slider...")
        result = solve_baxia(solver, page, timeout_ms=15000)

        status_text = page.locator("#solve-status").text_content() or ""
        if result:
            print(f"\nSOLVED! {status_text}")
        else:
            print(f"\nFAILED — {status_text}")

        time.sleep(3)
        browser.close()


if __name__ == "__main__":
    main()
