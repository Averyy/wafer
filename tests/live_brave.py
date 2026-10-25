"""Guarded Brave acceptance run through wafer; never runs on import.

uv run python tests/live_brave.py --rounds 10 --require-recovery [--headless]
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
        self.dispatches = 0
        self.recoveries = 0
        self.spare_recoveries = 0

    def _solve_on_worker(self, *args, **kwargs):
        self.dispatches += 1
        before = len(self.pow_statuses)
        result = super()._solve_on_worker(*args, **kwargs)
        if (
            result is not None
            and result.response is not None
            and not result.challenge_absent
        ):
            if 200 in self.pow_statuses[before:]:
                self.recoveries += 1
            else:
                self.spare_recoveries += 1
        logger.info(
            "Browser solve complete captured=%s cleared=%s recoveries=%d spare=%d",
            result is not None and result.response is not None,
            result is not None and not result.challenge_absent,
            self.recoveries,
            self.spare_recoveries,
        )
        return result

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
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--require-recovery", action="store_true")
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
    if not 1 <= args.rounds <= 25:
        parser.error("--rounds must be between 1 and 25")
    with tempfile.TemporaryDirectory(prefix="wafer-brave-") as temporary:
        cache = args.cache_dir or temporary
        with ObservedSolver(headless=args.headless, solve_timeout=120) as solver:

            def search(session, url, phase, index, *, native_only=False):
                before = solver.dispatches
                cookie_before = any(session.get_cookie(n, url) for n in BRAVE_COOKIES)
                started = time.monotonic()
                result = session.get(url, max_response_size=12 * 1024 * 1024)
                dispatches = solver.dispatches - before
                logger.info(
                    "search phase=%s index=%d status=%d challenge=%s "
                    "bytes=%d browser_dispatches=%d cookie_before=%s "
                    "cookie_after=%s elapsed=%.2f",
                    phase,
                    index,
                    result.status_code,
                    result.challenge_type,
                    len(result.content),
                    dispatches,
                    cookie_before,
                    any(session.get_cookie(n, url) for n in BRAVE_COOKIES),
                    time.monotonic() - started,
                )
                valid = (
                    result.status_code == 200
                    and not result.challenge_type
                    and 'id="search-page"' in result.text
                    and (not native_only or (cookie_before and dispatches == 0))
                )
                if not valid:
                    logger.error("Unresolved acceptance check; stopping live traffic")
                return valid

            config = dict(
                max_rotations=0,
                max_retries=0,
                rate_limit=6,
                cache_dir=cache,
                timeout=150,
            )
            with wafer.SyncSession(browser_solver=solver, **config) as session:
                for index, url in enumerate(urls * args.rounds):
                    if index:
                        time.sleep(6)
                    if not search(session, url, "initial", index):
                        return 1
                    if solver.recoveries:
                        break
                if not solver.recoveries:
                    logger.info(
                        "PoW recovery/replay/restart UNTESTED: no fresh gate solved"
                    )
                    return 2 if args.require_recovery else 0
                # Brave consumes/deletes the token cookie on a successful HTTP
                # read. Prove that one read without a browser, then allow its
                # own JS to consume retained spare tokens on subsequent gates.
                accepted = solver.pow_statuses.count(200)
                for index, url in enumerate(urls):
                    time.sleep(6)
                    if not search(
                        session,
                        url,
                        "HTTP/spare replay",
                        index,
                        native_only=index == 0,
                    ):
                        return 1
                    if solver.pow_statuses.count(200) != accepted:
                        logger.error("Spare-token reuse issued new PoW; stopping")
                        return 1
                if not solver.spare_recoveries:
                    logger.error("Spare-token recovery UNTESTED: no later gate")
                    return 2
                if not any(session.get_cookie(n, urls[0]) for n in BRAVE_COOKIES):
                    logger.error(
                        "Cache restart UNTESTED: no unspent cookie at shutdown"
                    )
                    return 2
            # No solver on the restarted session: a browser fallback cannot
            # hide a cookie-persistence failure. Check one unspent cached token,
            # not repeated reuse of the cookie that Brave consumes/deletes.
            with wafer.SyncSession(**config) as session:
                time.sleep(6)
                if not search(session, urls[3], "cache restart", 0, native_only=True):
                    return 1
            logger.info(
                "PASS: fresh PoW recovery, native replay, spare-token recovery, "
                "cache-restart read (Brave consumes each HTTP token cookie)"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
