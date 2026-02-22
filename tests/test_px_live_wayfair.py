"""Live test: PX press-and-hold solver.

Run with: uv run python tests/test_px_live_wayfair.py [url]

Hammers the target URL with repeated refreshes until PX challenge
triggers, then runs the solver.
"""

import logging
import signal
import sys
import time

from wafer.browser._solver import BrowserSolver

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("px_live")


def timeout_handler(signum, frame):
    print("\n\nTIMEOUT reached. FAIL.")
    sys.exit(1)


def main():
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(300)  # 5 min overall limit

    url = sys.argv[1] if len(sys.argv) > 1 else "https://www.wayfair.com/v/account/authentication/login"

    solver = BrowserSolver(headless=False, solve_timeout=90)
    if not solver._ensure_recordings():
        print("ERROR: No recordings found!")
        return

    solver._ensure_browser()
    context = solver._create_context()
    page = context.new_page()

    # Hammer the URL with refreshes until PX triggers
    max_attempts = 20
    for attempt in range(1, max_attempts + 1):
        logger.info("--- Attempt %d: %s ---", attempt, url)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=15000)
        except Exception as e:
            logger.info("Navigation error: %s", e)

        # Wait for PX to potentially appear
        for wait in range(8):  # check for 4 seconds
            time.sleep(0.5)
            if solver._has_px_challenge(page):
                break

        has_challenge = solver._has_px_challenge(page)
        logger.info(
            "Attempt %d: challenge=%s frames=%d",
            attempt,
            has_challenge,
            len(page.frames),
        )

        if has_challenge:
            print(f"\nPX CHALLENGE TRIGGERED on attempt {attempt}!")
            print("Running solver...\n")

            result = solver._solve_perimeterx(page, 90000)
            if result:
                print("\nSOLVED!")
                try:
                    cookies = context.cookies()
                    px_cookies = [
                        c for c in cookies
                        if c["name"].startswith("_px")
                    ]
                    for c in px_cookies:
                        print(f"  {c['name']} = {c['value'][:40]}...")
                except Exception:
                    pass
            else:
                print("\nFAIL: solver returned False")

            signal.alarm(0)
            time.sleep(3)
            context.close()
            solver.close()
            return

    signal.alarm(0)
    print(f"\nNo challenge triggered after {max_attempts} attempts.")
    time.sleep(2)
    context.close()
    solver.close()


if __name__ == "__main__":
    main()
