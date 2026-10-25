"""Live test: AliExpress MTop token bootstrap, priming, and challenge recovery.

Protected MTop APIs can answer FAIL_SYS_USER_VALIDATE even after the browser
has supplied _baxia_sec_cookie_. Priming imports state; the product response
decides whether that state is accepted.

    uv run python tests/live_mtop_recaptcha.py solve [headless]
        cold bootstrap -> browser_solve_challenge(url, "tmd", timeout=165)
        -> signed pdp.pc.query retry
    uv run python tests/live_mtop_recaptcha.py prime [headless]
        browser_prime("https://www.aliexpress.com/") -> signed pdp.pc.query
    uv run python tests/live_mtop_recaptcha.py prime --timezone UTC --recover
        prime -> signed call -> solve any issued challenge -> signed retry

--timezone sets BrowserSolver's browser-process clock; omitted keeps the
process default. Exit status is zero only for SUCCESS plus the expected product
ID. One run at a time; leave 5s+ between requests and runs (CLAUDE.md).
See docs/ref-baxia.md.
"""

import argparse
import asyncio
import hashlib
import json
import logging
import sys
import time

import wafer
from wafer.browser import BrowserSolver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-8s %(levelname)-7s %(message)s",
)
log = logging.getLogger("live_mtop")

APP_KEY = "12574478"
API = "mtop.aliexpress.pdp.pc.query"
URL = f"https://acs.aliexpress.com/h5/{API}/1.0/"
PRODUCT = {
    "productId": "4000085910726",
    "_lang": "en_US",
    "_currency": "USD",
    "country": "US",
    "clientType": "pc",
}


def _params(token: str, data: dict) -> dict:
    t = str(int(time.time() * 1000))
    payload = json.dumps(data, separators=(",", ":"))
    sign = hashlib.md5(f"{token}&{t}&{APP_KEY}&{payload}".encode()).hexdigest()
    return {
        "jsv": "2.5.1",
        "appKey": APP_KEY,
        "t": t,
        "sign": sign,
        "api": API,
        "v": "1.0",
        "timeout": "5000",
        "type": "originaljson",
        "dataType": "json",
        "data": payload,
    }


async def _mtop(session, token: str, data: dict) -> dict:
    resp = await session.get(
        URL,
        params=_params(token, data),
        headers={"Referer": "https://www.aliexpress.com/"},
        timeout=15,
    )
    return json.loads(resp.text)


def _token(session) -> str | None:
    cookie = session.get_cookie("_m_h5_tk", URL)
    return cookie.split("_")[0] if cookie else None


async def _solve_issued(session, body: dict, started: float) -> bool:
    data = body.get("data")
    issued = data.get("url") if isinstance(data, dict) else None
    if not issued:
        return False
    token_before = _token(session)
    solved = await session.browser_solve_challenge(issued, "tmd", timeout=165)
    log.info(
        "browser_solve_challenge=%s after %.1fs; token before=%s after=%s",
        solved,
        time.monotonic() - started,
        bool(token_before),
        bool(_token(session)),
    )
    return solved


async def main(
    mode: str, headless: bool, timezone: str | None, recover: bool
) -> bool:
    solver = BrowserSolver(headless=headless, timezone=timezone)
    try:
        async with wafer.AsyncSession(
            max_rotations=0,
            max_retries=0,
            cache_dir=None,
            rate_limit=6,
            browser_solver=solver,
        ) as s:
            started = time.monotonic()
            if mode == "prime":
                primed = await s.browser_prime(
                    "https://www.aliexpress.com/", timeout=30
                )
                log.info(
                    "browser_prime returned %s after %.1fs; cookies=%s",
                    primed,
                    time.monotonic() - started,
                    sorted(c["name"] for c in s.cookie_scope_summary(URL)),
                )
                if not primed:
                    return False
            else:
                body = await _mtop(s, "undefined", {})
                data = body.get("data")
                issued = data.get("url") if isinstance(data, dict) else None
                log.info(
                    "bootstrap ret=%s punishment=%s", body.get("ret"), bool(issued)
                )
                if issued and not await _solve_issued(s, body, started):
                    return False
            token = _token(s)
            if token is None:
                await _mtop(s, "undefined", {})
                token = _token(s)
            body = await _mtop(s, token or "", PRODUCT)
            if recover and "FAIL_SYS_USER_VALIDATE" in body.get("ret", []):
                log.info("primed signed call was challenged; solving issued URL")
                if not await _solve_issued(s, body, started):
                    return False
                token = _token(s)
                if token is None:
                    await _mtop(s, "undefined", {})
                    token = _token(s)
                body = await _mtop(s, token or "", PRODUCT)
            data = body.get("data")
            result = data.get("result") if isinstance(data, dict) else None
            price = result.get("PRICE") if isinstance(result, dict) else None
            product_id = price.get("productId") if isinstance(price, dict) else None
            succeeded = (
                any(str(ret).startswith("SUCCESS::") for ret in body.get("ret", []))
                and str(product_id) == PRODUCT["productId"]
            )
            log.info(
                "signed %s ret=%s product_id=%s validated=%s total=%.1fs",
                API,
                body.get("ret"),
                product_id,
                succeeded,
                time.monotonic() - started,
            )
            return succeeded
    finally:
        solver.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("solve", "prime"))
    parser.add_argument("headless", nargs="?", choices=("headless",))
    parser.add_argument("--timezone")
    parser.add_argument("--recover", action="store_true")
    args = parser.parse_args()
    sys.exit(
        0
        if asyncio.run(
            main(args.mode, bool(args.headless), args.timezone, args.recover)
        )
        else 1
    )
