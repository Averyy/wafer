"""Live test: Kasada cookie replay on Chewy.

Verifies that after browser solves Kasada once, subsequent TLS requests
reuse cookies without re-triggering challenges. Catches regressions
where cookies are cleared during rotation or fingerprint is changed
after browser solve.

Usage:
    uv run python tests/live_chewy_kasada.py
    uv run python tests/live_chewy_kasada.py --headless
"""

import argparse
import logging
import sys
import time

import wafer
from wafer.browser import BrowserSolver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("live_chewy")

# Full Chewy browsing flow: homepage, search, product pages, categories
URLS = [
    "https://www.chewy.com/",
    "https://www.chewy.com/s?query=hills+science+diet",
    "https://www.chewy.com/hills-science-diet-adult-chicken/dp/37832",
    "https://www.chewy.com/s?query=purina+pro+plan",
    "https://www.chewy.com/b/dry-food-288",
    "https://www.chewy.com/s?query=blue+buffalo+wilderness",
]

# After the first browser solve, all subsequent requests should
# reuse cookies via TLS (no browser solve, <5s each).
MAX_COOKIE_REPLAY_TIME = 5.0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--headless", action="store_true")
    args = parser.parse_args()

    results = []
    solver = BrowserSolver(headless=args.headless)

    with wafer.SyncSession(browser_solver=solver) as session:
        for i, url in enumerate(URLS):
            logger.info(
                "--- Request %d/%d: %s", i + 1, len(URLS), url
            )
            start = time.monotonic()
            try:
                resp = session.get(url)
                elapsed = time.monotonic() - start
                is_challenge = resp.challenge_type is not None
                has_content = (
                    len(resp.text) > 1024 if resp.text else False
                )
                ok = (
                    resp.status_code == 200
                    and has_content
                    and not is_challenge
                )
                results.append({
                    "url": url,
                    "status": resp.status_code,
                    "challenge": resp.challenge_type,
                    "size": len(resp.content) if resp.content else 0,
                    "elapsed": elapsed,
                    "ok": ok,
                })
                logger.info(
                    "  status=%d size=%d elapsed=%.1fs ok=%s",
                    resp.status_code,
                    len(resp.content) if resp.content else 0,
                    elapsed,
                    ok,
                )
            except Exception as e:
                elapsed = time.monotonic() - start
                results.append({
                    "url": url,
                    "elapsed": elapsed,
                    "ok": False,
                    "error": str(e),
                })
                logger.error("  FAILED: %s (%.1fs)", e, elapsed)

            if i < len(URLS) - 1:
                time.sleep(8)

    # Summary
    logger.info("=" * 60)
    logger.info("RESULTS (headless=%s)", args.headless)
    logger.info("=" * 60)

    passed = sum(1 for r in results if r["ok"])
    cookie_replay_ok = True

    for i, r in enumerate(results):
        tag = "PASS" if r["ok"] else "FAIL"
        logger.info(
            "  [%s] %s elapsed=%.1fs %s",
            tag,
            r.get("status", "ERR"),
            r["elapsed"],
            r["url"],
        )
        # Requests after the first should use cookie replay (<5s)
        if i > 0 and r["ok"] and r["elapsed"] > MAX_COOKIE_REPLAY_TIME:
            logger.warning(
                "  ^ Cookie replay likely failed (%.1fs > %.1fs)",
                r["elapsed"],
                MAX_COOKIE_REPLAY_TIME,
            )
            cookie_replay_ok = False

    logger.info("%d/%d requests passed", passed, len(results))
    if not cookie_replay_ok:
        logger.error(
            "COOKIE REPLAY REGRESSION: requests after browser solve "
            "should complete in <%.0fs via TLS cookie replay",
            MAX_COOKIE_REPLAY_TIME,
        )

    if passed < len(results) or not cookie_replay_ok:
        sys.exit(1)
    logger.info("ALL PASSED")


if __name__ == "__main__":
    main()
