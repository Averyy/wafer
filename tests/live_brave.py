"""Guarded Brave acceptance run through wafer; never runs on import.

uv run python tests/live_brave.py [--headless] [--cache-dir PATH]
Stops at the first unresolved response. A run without an accepted PoW exchange
is explicitly untested for solving, even if every search succeeds.
"""

import argparse
import logging
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urlparse

import wafer
from wafer._brave import BRAVE_COOKIES, BRAVE_ORIGIN
from wafer.browser import BrowserSolver

logger = logging.getLogger("wafer.live_brave")


class ObservedSolver(BrowserSolver):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.pow_statuses = []
        self.browser_searches = 0

    def _setup_headless_patches(self, page, **kwargs):
        super()._setup_headless_patches(page, **kwargs)

        def observed(response):
            if response.url.startswith(BRAVE_ORIGIN + "/api/captcha/pow?"):
                self.pow_statuses.append(response.status)
                logger.info("Real Brave PoW network status=%s", response.status)
            if response.url.startswith(BRAVE_ORIGIN + "/search?"):
                self.browser_searches += 1
                query = parse_qs(urlparse(response.url).query)
                logger.info(
                    "Browser search document status=%s offset=%s rr=%s",
                    response.status,
                    query.get("offset"),
                    query.get("_rr"),
                )

        page.on("response", observed)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--cache-dir")
    parser.add_argument("--query", default="Python asyncio documentation")
    parser.add_argument("--offset", type=int, default=1)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    urls = [
        BRAVE_ORIGIN
        + "/search?"
        + urlencode(
            {
                "q": args.query if index < 2 else args.query + " context manager",
                "source": "web",
                **({"offset": str(args.offset)} if index % 2 else {}),
            }
        )
        for index in range(4)
    ]
    with tempfile.TemporaryDirectory(prefix="wafer-brave-") as temporary:
        cache = args.cache_dir or temporary
        with ObservedSolver(headless=args.headless, solve_timeout=120) as solver:
            for restart in (False, True):
                with wafer.SyncSession(
                    browser_solver=solver,
                    max_rotations=0,
                    max_retries=0,
                    rate_limit=6,
                    cache_dir=cache,
                    timeout=150,
                ) as session:
                    for index, url in enumerate(urls[:1] if restart else urls):
                        if restart or index:
                            time.sleep(6)
                        before = solver.browser_searches
                        result = session.get(url)
                        logger.info(
                            "search restart=%s index=%d status=%d challenge=%s "
                            "bytes=%d browser_documents=%d clearance_cookie=%s",
                            restart,
                            index,
                            result.status_code,
                            result.challenge_type,
                            len(result.content),
                            solver.browser_searches - before,
                            any(
                                session.get_cookie(name, url) for name in BRAVE_COOKIES
                            ),
                        )
                        if (
                            result.status_code != 200
                            or result.challenge_type
                            or 'id="search-page"' not in result.text
                        ):
                            logger.error("Unresolved search; stopping live traffic")
                            return 1
            logger.info(
                "Search/restart flow complete; PoW solving=%s statuses=%s",
                "observed"
                if 200 in solver.pow_statuses
                else "UNTESTED (no PoW accepted)",
                solver.pow_statuses,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
