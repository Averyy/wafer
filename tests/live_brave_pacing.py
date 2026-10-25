"""Real headless Brave first-party pacing probe; no PoW success is inferred.

uv run python tests/live_brave_pacing.py

Requests one search and two public token-key responses through wafer's browser.
The concurrent key requests must be released at least six seconds apart without
blocking worker/iframe hardening events. Never runs on import.
"""

import logging
import time

from wafer._ratelimit import RateLimiter
from wafer.browser import BrowserSolver
from wafer.browser._brave import prepare_brave
from wafer.browser._pump import idle, unbind_page

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


def main():
    logging.basicConfig(level=logging.INFO)
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
                while page.evaluate("document.readyState") == "loading":
                    page._wafer_brave_flush()
                    idle(0.1)
                    if time.monotonic() >= deadline:
                        raise RuntimeError("document deadline")
                if response.status != 200:
                    logger.info("search_status=%s pacing=untested", response.status)
                    return
                page.evaluate("""() => {
                    window.__wafer_key_statuses=[];
                    for(let i=0;i<2;i++) fetch('/api/tokens/keys')
                      .then(r=>window.__wafer_key_statuses.push(r.status))
                      .catch(()=>window.__wafer_key_statuses.push('error'));
                }""")
                statuses = []
                while time.monotonic() < deadline:
                    page._wafer_brave_flush()
                    idle(0.1)
                    statuses = page.evaluate("window.__wafer_key_statuses")
                    if len(statuses) == 2:
                        break
                gaps = [round(b - a, 3) for a, b in zip(limiter.sent, limiter.sent[1:])]
                logger.info(
                    "search_status=%s keys_statuses=%s send_gaps=%s",
                    response.status,
                    statuses,
                    gaps,
                )
                assert statuses == [200, 200], statuses
                assert all(gap >= 6 for gap in gaps), gaps
            finally:
                cancel = getattr(page, "_wafer_brave_cancel", None)
                if cancel is not None:
                    cancel()
                context.close()
                unbind_page()

        solver._run_on_worker(probe)


if __name__ == "__main__":
    main()
