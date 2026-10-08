"""Live test: AliExpress MTop token bootstrap, its reCAPTCHA, and avoiding it.

A cold session's unsigned call to a protected MTop API is answered
FAIL_SYS_USER_VALIDATE with an action=captcharecaptcha punishment URL unless
the session holds the _baxia_sec_cookie_ AliExpress's page script sets.

    uv run python tests/live_mtop_recaptcha.py solve [headless]
        cold bootstrap -> browser_solve_challenge(url, "tmd", timeout=165)
        -> signed pdp.pc.query retry
    uv run python tests/live_mtop_recaptcha.py prime [headless]
        browser_prime("https://www.aliexpress.com/") -> signed pdp.pc.query

Each mode prints the outcome and wall time. One run at a time; leave 5s+
between runs (CLAUDE.md). See docs/ref-baxia.md.
"""

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


async def main(mode: str, headless: bool) -> None:
    solver = BrowserSolver(headless=headless)
    try:
        async with wafer.AsyncSession(max_rotations=0, browser_solver=solver) as s:
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
            else:
                body = await _mtop(s, "undefined", {})
                data = body.get("data")
                issued = data.get("url") if isinstance(data, dict) else None
                log.info(
                    "bootstrap ret=%s punishment=%s", body.get("ret"), bool(issued)
                )
                if issued:
                    solved = await s.browser_solve_challenge(
                        issued, "tmd", timeout=165
                    )
                    log.info(
                        "browser_solve_challenge=%s after %.1fs",
                        solved,
                        time.monotonic() - started,
                    )
            token = _token(s)
            if token is None:
                await _mtop(s, "undefined", {})
                token = _token(s)
            body = await _mtop(s, token or "", PRODUCT)
            log.info(
                "signed %s ret=%s total=%.1fs",
                API,
                body.get("ret"),
                time.monotonic() - started,
            )
    finally:
        solver.close()


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("solve", "prime"):
        sys.exit(__doc__)
    asyncio.run(main(sys.argv[1], "headless" in sys.argv[2:]))
