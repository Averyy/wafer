"""Rotation for a session created with a preflighted BrowserSolver.

The preflight aligns the first request to the browser's identity with a pin.
Only a browser solve's pin binds cookies, so only that one locks rotation; a
preflighted session still climbs the cross-family ladder (www.ebay.ca from
Linux refuses Chrome and serves Firefox, 2026-11-24), and every move of the
TLS identity brings its family's headers with it.
"""

import time
from unittest.mock import patch

import pytest

from tests.conftest import MockResponse, make_async_session, make_sync_session
from tests.test_browser import MockBrowserSolver
from wafer import SyncSession
from wafer._cookies import CookieCache
from wafer._fingerprint import FIREFOX_LADDER_EMULATION, emulation_family
from wafer.browser import SolveResult

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
)
BROWSER_VER = "158.0.8127.88"


def forbidden():
    return MockResponse(403, {"content-type": "text/html"}, "<html>Forbidden</html>")


def cf_challenge():
    return MockResponse(
        403,
        {"cf-mitigated": "challenge", "content-type": "text/html"},
        "<html>Just a moment...</html>",
    )


def ok():
    return MockResponse(200, {"content-type": "text/html"}, "<html>ok page</html>")


def solve_result():
    return SolveResult(
        cookies=[
            {
                "name": "cf_clearance",
                "value": "solved",
                "domain": ".example.com",
                "path": "/",
                "expires": time.time() + 3600,
                "secure": True,
                "httpOnly": True,
                "sameSite": "None",
            }
        ],
        user_agent=BROWSER_UA,
        browser_version=BROWSER_VER,
    )


def preflighted(make_session, responses, results=None, **kw):
    solver = MockBrowserSolver(results=results if results is not None else [])
    solver.browser_identity = (BROWSER_UA, BROWSER_VER)
    session, client = make_session(responses, browser_solver=solver, **kw)
    session._align_preflight_browser_identity()
    assert session._fingerprint.pinned
    assert not session._fingerprint.locks_rotation
    return session, client, solver


async def run(make_session, session, url, **kw):
    with patch("time.sleep"), patch("asyncio.sleep"):
        if make_session is make_async_session:
            return await session.get(url, **kw)
        return session.get(url, **kw)


both = pytest.mark.parametrize("make_session", [make_sync_session, make_async_session])


@pytest.mark.asyncio
@both
async def test_a_solve_after_the_firefox_rung_brings_chrome_headers(make_session):
    """Preflighted session, rotation 2 (Firefox), then a Cloudflare challenge
    solved by the Chrome browser: the pin moves TLS, UA and hints to Chrome,
    and the headers must follow (they stayed Firefox's)."""
    url = "https://www.example.com/page"
    session, client, solver = preflighted(
        make_session,
        [forbidden(), forbidden(), cf_challenge(), ok()],
        results=[solve_result()],
        max_rotations=2,
    )
    resp = await run(make_session, session, url)
    assert resp.status_code == 200
    assert solver.solve_calls == [(url, "cloudflare")]
    fp = session._fingerprint
    # TLS + UA + client hints: Chrome (the solving browser)
    assert emulation_family(fp.current) == "chrome"
    assert fp.ua_override == BROWSER_UA
    assert fp.locks_rotation
    hdrs = session._compute_client_headers()
    # Chrome's navigation Accept and Accept-Language, not Firefox's.
    assert hdrs["Accept-Language"] == "en-US,en;q=0.9", hdrs["Accept-Language"]
    assert "image/avif" in hdrs["Accept"], hdrs["Accept"]


@pytest.mark.asyncio
@both
async def test_rotation_1_keeps_a_shared_cache_the_browser_earned(
    make_session, tmp_path
):
    """Session A (preflighted) solves and persists browser cookies. Session
    B, preflighted with the same browser, gets a bare 403: rotation 1 keeps
    its identity, so it keeps the cookies earned under it."""
    cache = CookieCache(str(tmp_path))
    url = "https://www.example.com/page"
    a, _, _ = preflighted(
        make_session, [cf_challenge(), ok()], results=[solve_result()],
        cookie_cache=cache,
    )
    resp = await run(make_session, a, url)
    assert resp.status_code == 200
    assert a._fingerprint.locks_rotation
    assert [c["name"] for c in cache.load("www.example.com")] == ["cf_clearance"]

    b, _, _ = preflighted(
        make_session, [forbidden(), ok()], cookie_cache=cache, max_rotations=2
    )
    resp = await run(make_session, b, url)
    assert resp.status_code == 200
    names = [c["name"] for c in cache.load("www.example.com")]
    assert names == ["cf_clearance"], names


@pytest.mark.asyncio
@pytest.mark.parametrize("make_session", [make_sync_session, make_async_session])
@pytest.mark.parametrize("preflight", [False, True])
async def test_retiring_on_the_firefox_rung_brings_chrome_headers(
    make_session, preflight
):
    """max_failures=3: the third 403 retires the session while it is on the
    Firefox rung; the next attempt goes out as Chrome, and must carry Chrome's
    Accept-Language, not Firefox's."""
    url = "https://www.example.com/page"
    no = MockResponse(403, {"content-type": "text/html"}, "<html>Forbidden</html>")
    okr = MockResponse(200, {"content-type": "text/html"}, "<html>ok</html>")
    kw = {"max_rotations": 4, "max_failures": 3}
    if preflight:
        solver = MockBrowserSolver(results=[])
        solver.browser_identity = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
            "158.0.8127.88",
        )
        kw["browser_solver"] = solver
    session, client = make_session([no, no, no, okr], **kw)
    if preflight:
        session._align_preflight_browser_identity()
    del session._retire_session  # use the real one
    seen = []
    orig = client.request
    is_async = make_session is make_async_session

    if is_async:
        async def rec(method, u, **k):
            h = session._compute_client_headers()
            seen.append((repr(session.emulation), h.get("Accept-Language")))
            return await orig(method, u, **k)
    else:
        def rec(method, u, **k):
            h = session._compute_client_headers()
            seen.append((repr(session.emulation), h.get("Accept-Language")))
            return orig(method, u, **k)

    client.request = rec
    target = (
        "wafer._async.wreq.Client" if is_async
        else "wafer._sync.wreq.blocking.Client"
    )
    with (
        patch(target, return_value=client),
        patch("time.sleep"),
        patch("asyncio.sleep"),
    ):
        resp = await session.get(url) if is_async else session.get(url)
    assert resp.status_code == 200
    for em, lang in seen:
        if "Chrome" in em:
            assert lang == "en-US,en;q=0.9", seen


def _timeout_exc():
    import wreq

    return wreq.exceptions.TimeoutError("attempt timed out")


@pytest.mark.asyncio
@both
@pytest.mark.parametrize("site", ["403", "429", "timeout", "empty200"])
async def test_each_rotation_site_reaches_firefox(make_session, site):
    url = "https://www.example.com/page"
    kw = {"max_rotations": 2, "max_failures": None}
    if site == "403":
        responses = [forbidden(), forbidden(), ok()]
    elif site == "429":
        responses = [MockResponse(429, {"content-type": "text/html"}, "slow")] * 2
        responses = responses + [ok()]
    elif site == "timeout":
        kw["max_retries"] = 0
        responses = [_timeout_exc(), _timeout_exc(), ok()]
    else:
        kw["max_retries"] = 1
        empty = MockResponse(200, {"content-type": "text/html"}, "")
        responses = [empty, empty, empty, ok()]
    session, client, _ = preflighted(make_session, responses, **kw)
    if site == "empty200":
        session._body_capable_domains.add("www.example.com")
    resp = await run(make_session, session, url)
    assert resp.status_code == 200, site
    assert session.emulation == FIREFOX_LADDER_EMULATION, (site, session.emulation)


@pytest.mark.asyncio
@both
async def test_a_callers_browser_ua_keeps_the_session_on_chrome(make_session):
    # The caller set the browser's exact UA: that asserts the identity, and
    # rotating would send that Chrome UA over Firefox's TLS.
    url = "https://www.example.com/page"
    solver = MockBrowserSolver(results=[])
    solver.browser_identity = (BROWSER_UA, BROWSER_VER)
    session, client = make_session(
        [forbidden(), forbidden(), forbidden()], browser_solver=solver,
        max_rotations=2, max_failures=None,
    )
    user = {"User-Agent": BROWSER_UA, "Accept": "*/*", "Accept-Language": "en-US",
            "Accept-Encoding": "gzip"}
    session.headers = dict(user)
    session._chrome_headers = dict(user)
    session._user_headers = True
    session._align_preflight_browser_identity()
    assert session._fingerprint.locks_rotation
    families = []
    orig = client.request

    if make_session is make_async_session:
        async def spy(*a, **k):
            families.append(emulation_family(session._fingerprint.current))
            return await orig(*a, **k)
    else:
        def spy(*a, **k):
            families.append(emulation_family(session._fingerprint.current))
            return orig(*a, **k)

    client.request = spy
    resp = await run(make_session, session, url)
    assert resp.status_code == 403
    assert families == ["chrome", "chrome", "chrome"]


def test_a_firefox_start_is_not_pinned_to_the_preflighted_chrome():
    from wreq import Emulation

    solver = MockBrowserSolver(results=[])
    solver.browser_identity = (BROWSER_UA, BROWSER_VER)
    solver.proxy_server = None
    with SyncSession(emulation=Emulation.Firefox152, browser_solver=solver) as s:
        assert repr(s.emulation) == "Profile.Firefox152"
        assert not s._fingerprint.pinned
        assert "Firefox/152.0" in s._client_headers["User-Agent"]


def test_a_refused_session_leaves_a_shared_solvers_proxy_alone():
    calls = []

    class Solver:
        proxy_server = None
        browser_identity = (BROWSER_UA, BROWSER_VER)

        def configure_proxy(self, proxy):
            calls.append(proxy)

    with pytest.raises(ValueError, match="must exactly match"):
        SyncSession(
            browser_solver=Solver(), proxy="http://127.0.0.1:9",
            headers={"User-Agent": "Mozilla/5.0 something else"},
        )
    assert calls == []


@pytest.mark.asyncio
@both
async def test_a_request_url_that_does_not_parse_is_refused_at_once(make_session):
    session, client = make_session([ok()])
    with pytest.raises(ValueError, match="is not a URL"):
        await run(make_session, session, "https://[bad/x")
    assert client.request_count == 0
