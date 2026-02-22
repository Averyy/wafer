"""Visual test: PX captcha solver against realistic local mock.

Run with: uv run python tests/test_px_captcha_local.py

Starts a local HTTP server, loads px_captcha_local.html (which
matches the real PX challenge structure captured from wayfair/zillow),
and runs the full PX solver flow.

Hard 1-minute limit. If it doesn't solve on first attempt, it's a fail.
"""

import logging
import signal
import sys
import time

from tests.px_mock_server import start_server
from wafer.browser._solver import BrowserSolver

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)


def timeout_handler(signum, frame):
    print("\n\nTIMEOUT: 1 minute limit reached. FAIL.")
    sys.exit(1)


def main():
    # Hard 1 minute limit
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(60)

    base_url = start_server()
    url = f"{base_url}/px_captcha_local.html"
    print(f"Mock server at {base_url}")
    print(f"Loading {url}\n")

    solver = BrowserSolver(headless=False, solve_timeout=60)

    if not solver._ensure_recordings():
        print("ERROR: No recordings found!")
        return

    solver._ensure_browser()
    context = solver._create_context()
    page = context.new_page()

    page.goto(url, wait_until="domcontentloaded")

    print("--- Running _solve_perimeterx (1 min limit) ---")
    try:
        result = solver._solve_perimeterx(page, 60000)
    except Exception as e:
        result = f"exception: {e}"
    print(f"\nSolver returned: {result}")

    # Cancel alarm on success
    signal.alarm(0)

    time.sleep(1)
    try:
        log_text = page.evaluate(
            "document.getElementById('debug').textContent"
        )
        print(f"\n--- PAGE LOG ---\n{log_text}")
    except Exception:
        print("(page closed or debug element removed)")

    if result is True:
        print("\nPASS")
    else:
        print("\nFAIL")

    time.sleep(3)
    context.close()
    solver.close()


if __name__ == "__main__":
    main()
