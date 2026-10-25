"""Real headless Brave first-party pacing probe; no PoW success is inferred.

uv run python tests/live_brave_pacing.py

Requests one search, two public token-key responses, and an exact-URL reload.
Blocking evaluate/reload calls must complete without an outer polling loop,
while sends remain at least six seconds apart and worker hardening stays free.
Never runs on import.
"""

import logging
import time
from concurrent.futures import TimeoutError

from wafer._brave import is_brave_challenge
from wafer._ratelimit import RateLimiter
from wafer.browser import BrowserSolver
from wafer.browser._brave import prepare_brave
from wafer.browser._pump import unbind_page

logger = logging.getLogger("wafer")
URL = (
    "https://search.brave.com/search?q=Python+asyncio+documentation&source=web&offset=1"
)


class ObservedLimiter(RateLimiter):
    def __init__(self):
        super().__init__(min_interval=6)
        self.sent = []

    def record(self, domain):
        super().record(domain)
        self.sent.append(time.monotonic())
        logger.info("Pacing probe sent exchange=%d", len(self.sent))


def main():
    logging.basicConfig(level=logging.INFO)
    logger.setLevel(logging.DEBUG)
    with BrowserSolver(headless=True, solve_timeout=45) as solver:

        def probe():
            deadline = time.monotonic() + 40
            solver._ensure_browser(deadline)
            context = solver._create_context()
            page = context.new_page()
            try:
                solver._setup_headless_patches(page, challenge_type="brave")
                limiter = ObservedLimiter()
                prepare_brave(
                    context,
                    page,
                    URL,
                    {"_brave": {"state": {}, "limiter": limiter}},
                    deadline,
                )
                response = page.goto(URL, wait_until="commit", timeout=15000)
                page.wait_for_load_state("domcontentloaded", timeout=10000)
                on_gate = response.status == 429 and is_brave_challenge(
                    response.text(), response.url
                )
                if response.status != 200 and not on_gate:
                    logger.info("search_status=%s pacing=untested", response.status)
                    return 2
                if on_gate:
                    logger.info("Pacing on an issued gate; PoW recovery is not tested")
                # Intentionally await the fetches inside evaluate. The old
                # polling-only queue deadlocked here: the caller could never
                # return to the loop that released its awaited requests.
                statuses = page.evaluate("""async () => {
                    return await Promise.all([0, 1].map(async () =>
                        (await fetch('/api/tokens/keys')).status));
                }""")
                reload = page.reload(
                    wait_until="domcontentloaded",
                    timeout=max(1, int((deadline - time.monotonic()) * 1000)),
                )
                gaps = [round(b - a, 3) for a, b in zip(limiter.sent, limiter.sent[1:])]
                logger.info(
                    "search_status=%s keys_statuses=%s reload_status=%s send_gaps=%s",
                    response.status,
                    statuses,
                    reload.status,
                    gaps,
                )
                assert statuses == [200, 200], statuses
                assert reload.status == 200 or (
                    reload.status == 429
                    and is_brave_challenge(reload.text(), reload.url)
                ), reload.status
                assert len(gaps) >= 3, gaps
                assert all(gap >= 6 for gap in gaps), gaps
                return 0
            finally:
                cancel = getattr(page, "_wafer_brave_cancel", None)
                if cancel is not None:
                    cancel()
                context.close()
                unbind_page()

        future = solver._submit_on_worker(probe)
        try:
            return future.result(timeout=45)
        except TimeoutError:
            solver._recover_timed_out_worker(future)
            raise RuntimeError("Browser pacing probe exceeded 45s") from None


if __name__ == "__main__":
    raise SystemExit(main())
