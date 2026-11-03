"""The caller's add_cookie() cookies ride into browser renders and solves.

A render or solve runs in a fresh browser context. Before this, the browser
never saw a cookie the caller pinned: AliExpress rendered in the egress IP's
currency with a GBP pin in the jar, and its default then replaced the pin
(2026-11-02, wafer 0.7.10). These use wreq's real jar: MockJar would hide how
wreq reports host-only cookies (no domain).
"""

import ast
import asyncio
import json
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from wafer import AsyncSession, SyncSession
from wafer._brave import BRAVE_COOKIES
from wafer._cookies import is_waf_cookie
from wafer._solvers import POW_COOKIE_NAME
from wafer.browser import BrowserSolver, CapturedResponse, SolveResult
from wafer.browser._solver import _seed_context_cookies

URL = "https://www.shop.test/w/cables.html"
PIN = "cur=GBP; Domain=.shop.test; Path=/"


def _page(url=URL, body=b"<html><body>priced</body></html>"):
    return CapturedResponse(
        url=url, status=200, headers={"content-type": "text/html"}, body=body
    )


class _RenderSolver:
    """Records what each render or solve was started with."""

    def __init__(self, cookies_back=(), response=True):
        self.cookies_back = list(cookies_back)
        self.response = response
        self.render_cookies = []
        self.solve_cookies = []

    def _result(self):
        return SolveResult(
            cookies=[dict(c) for c in self.cookies_back],
            user_agent="Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36",
            response=_page() if self.response else None,
            challenge_absent=True,
        )

    def render(self, url, timeout=None, max_size=None, *, cookies=None):
        self.render_cookies.append(cookies)
        return self._result()

    def solve(self, url, challenge_type=None, timeout=None, embedder=None,
              replay=None, max_size=None, *, cookies=None):
        self.solve_cookies.append(cookies)
        return self._result()

    def close(self, timeout=None):
        pass


class _AsyncRenderSolver(_RenderSolver):
    async def arender(self, url, timeout=None, max_size=None, *, cookies=None):
        return self.render(url, timeout, max_size, cookies=cookies)


class _LegacyRenderSolver(_RenderSolver):
    """A custom solver written before cookies= existed."""

    def render(self, url, timeout=None, max_size=None):
        self.render_cookies.append("not offered")
        return self._result()


def _session(**kwargs):
    kwargs.setdefault("cache_dir", None)
    return SyncSession(**kwargs)


# ---------------------------------------------------------------------------
# What is seeded
# ---------------------------------------------------------------------------


class TestSeedSelection:
    def test_domain_cookie_seeds_with_its_scope_and_attributes(self):
        s = _session()
        s.add_cookie(
            "cur=GBP; Domain=.shop.test; Path=/; Secure; HttpOnly; "
            "SameSite=Strict; Max-Age=3600",
            URL,
        )
        [seed] = s._browser_seed_cookies(URL)
        assert seed["name"] == "cur"
        assert seed["value"] == "GBP"
        assert seed["domain"] == ".shop.test"
        assert seed["path"] == "/"
        assert seed["secure"] is True
        assert seed["httpOnly"] is True
        assert seed["sameSite"] == "Strict"
        assert time.time() + 3500 < seed["expires"] <= time.time() + 3600

    def test_host_only_cookie_seeds_on_its_exact_host(self):
        s = _session()
        s.add_cookie("lang=en; Path=/", URL)
        [seed] = s._browser_seed_cookies(URL)
        # No leading dot: Chrome keeps it host-only, so it is not promoted to
        # sibling hosts.
        assert seed["domain"] == "www.shop.test"
        assert "expires" not in seed  # a session cookie stays one
        assert "sameSite" not in seed

    def test_same_named_host_only_cookies_keep_their_own_hosts(self):
        s = _session()
        s.add_cookie("lang=en; Path=/", "https://www.shop.test/")
        s.add_cookie("lang=fr; Path=/", "https://api.shop.test/")
        seeds = {c["domain"]: c["value"] for c in s._browser_seed_cookies(URL)}
        assert seeds == {"www.shop.test": "en", "api.shop.test": "fr"}

    def test_cookies_the_session_earned_itself_are_not_seeded(self):
        """A solve's context stays fresh for everything but the caller's."""
        s = _session()
        s.add_cookie(PIN, URL)
        # What a transport response or an earlier browser solve leaves.
        s._client.cookie_jar.add("sid=server; Domain=.shop.test; Path=/", URL)
        s._record_cookie_scope("sid=server; Domain=.shop.test; Path=/", URL)
        assert [c["name"] for c in s._browser_seed_cookies(URL)] == ["cur"]

    def test_only_the_navigated_sites_cookies_are_seeded(self):
        s = _session()
        s.add_cookie(PIN, URL)
        s.add_cookie("other=1; Domain=.elsewhere.test; Path=/", "https://elsewhere.test/")
        assert [c["name"] for c in s._browser_seed_cookies(URL)] == ["cur"]
        # An embedder (solve_origin) on another site brings its own.
        names = {
            c["name"]
            for c in s._browser_seed_cookies(URL, "https://www.elsewhere.test/")
        }
        assert names == {"cur", "other"}
        assert s._browser_seed_cookies("https://unrelated.test/") == []

    def test_seeds_the_jars_current_value(self):
        """The browser carries what the session's own next request would."""
        s = _session()
        s.add_cookie(PIN, URL)
        s._client.cookie_jar.add("cur=EUR; Domain=.shop.test; Path=/", URL)
        [seed] = s._browser_seed_cookies(URL)
        assert seed["value"] == "EUR"

    def test_deleted_cookie_is_not_seeded(self):
        s = _session()
        s.add_cookie(PIN, URL)
        s.add_cookie("cur=; Domain=.shop.test; Path=/; Max-Age=0", URL)
        assert s._browser_seed_cookies(URL) == []

    @pytest.mark.parametrize(
        "raw",
        [
            "cf_clearance=caller; Domain=.shop.test; Path=/",
            "__cf_bm=caller; Domain=.shop.test; Path=/",
            "datadome=caller; Domain=.shop.test; Path=/",
            "_abck=caller; Domain=.shop.test; Path=/",
            "bm_sz=caller; Domain=.shop.test; Path=/",
            "aws-waf-token=caller; Domain=.shop.test; Path=/",
            "_px3=caller; Domain=.shop.test; Path=/",
            "_pxhd=caller; Domain=.shop.test; Path=/",
            "reese84=caller; Domain=.shop.test; Path=/",
            "incap_ses_123_456=caller; Domain=.shop.test; Path=/",
            "x5sec=caller; Domain=.shop.test; Path=/",
            "__uzma=caller; Domain=.shop.test; Path=/",
            "KP_UIDz=caller; Domain=.shop.test; Path=/",
        ],
    )
    def test_waf_cookies_are_never_seeded(self, raw):
        """A seeded clearance would fake a solve or replay a rejected token."""
        s = _session()
        s.add_cookie(raw, URL)
        assert s._browser_seed_cookies(URL) == []
        # It still rides the session's own requests.
        assert s.get_cookie(raw.split("=")[0], URL) == "caller"

    def test_reddit_session_cookies_are_held_back_only_on_reddit(self):
        s = _session()
        s.add_cookie("loid=caller; Domain=.reddit.com; Path=/", "https://www.reddit.com/")
        s.add_cookie("over18=1; Domain=.reddit.com; Path=/", "https://www.reddit.com/")
        s.add_cookie("loid=app; Domain=.shop.test; Path=/", URL)
        reddit = s._browser_seed_cookies("https://www.reddit.com/")
        assert [c["name"] for c in reddit] == ["over18"]
        assert [c["name"] for c in s._browser_seed_cookies(URL)] == ["loid"]

    def test_no_caller_cookies_means_no_jar_read(self):
        s = _session()
        s._client = MagicMock()
        assert s._browser_seed_cookies(URL) == []
        s._client.cookie_jar.get_all.assert_not_called()


# ---------------------------------------------------------------------------
# What the session does with them
# ---------------------------------------------------------------------------


class TestSessionRender:
    def test_render_starts_with_the_pin_and_keeps_it(self, tmp_path):
        seeded_back = {
            "name": "cur", "value": "GBP", "domain": ".shop.test", "path": "/",
            "expires": -1,
        }
        earned = {
            "name": "sid", "value": "browser", "domain": ".shop.test", "path": "/",
            "expires": time.time() + 600,
        }
        solver = _RenderSolver(cookies_back=[seeded_back, earned])
        s = SyncSession(cache_dir=str(tmp_path), browser_solver=solver)
        s.add_cookie(PIN, URL)

        resp = s.render(URL, timeout=5)

        assert resp.status_code == 200
        [seed] = solver.render_cookies
        assert [(c["name"], c["value"]) for c in seed] == [("cur", "GBP")]
        assert s.get_cookie("cur", URL) == "GBP"
        assert s.get_cookie("sid", URL) == "browser"
        # The pin handed back unchanged was not earned, so it is not written
        # to cache_dir as solver state for every session sharing it.
        cached = json.dumps(
            [json.loads(p.read_text()) for p in tmp_path.rglob("*.json")]
        )
        assert "sid" in cached
        assert "GBP" not in cached

    def test_a_value_the_site_changed_replaces_the_pin(self):
        """The site's answer wins, as a transport Set-Cookie would."""
        changed = {
            "name": "cur", "value": "GBP&extra=1", "domain": ".shop.test",
            "path": "/", "expires": -1,
        }
        s = _session(browser_solver=_RenderSolver(cookies_back=[changed]))
        s.add_cookie(PIN, URL)
        s.render(URL, timeout=5)
        assert s.get_cookie("cur", URL) == "GBP&extra=1"
        assert sorted(
            c.value for c in s._client.cookie_jar.get_all() if c.name == "cur"
        ) == ["GBP&extra=1"]

    def test_legacy_render_without_cookies_keyword_still_works(self):
        back = {
            "name": "cur", "value": "GBP", "domain": ".shop.test", "path": "/",
            "expires": -1,
        }
        solver = _LegacyRenderSolver(cookies_back=[back])
        s = _session(browser_solver=solver)
        s.add_cookie(PIN, URL)
        s.render(URL, timeout=5)
        assert solver.render_cookies == ["not offered"]
        # Nothing was seeded, so nothing it returned is mistaken for a seed.
        assert s.get_cookie("cur", URL) == "GBP"

    @pytest.mark.asyncio
    async def test_async_render_seeds_through_arender(self):
        solver = _AsyncRenderSolver()
        s = AsyncSession(cache_dir=None, browser_solver=solver)
        s.add_cookie(PIN, URL)
        await s.render(URL, timeout=5)
        [seed] = solver.render_cookies
        assert [c["value"] for c in seed] == ["GBP"]

    @pytest.mark.asyncio
    async def test_async_render_seeds_through_sync_render(self):
        solver = _RenderSolver()
        s = AsyncSession(cache_dir=None, browser_solver=solver)
        s.add_cookie(PIN, URL)
        await s.render(URL, timeout=5)
        [seed] = solver.render_cookies
        assert [c["value"] for c in seed] == ["GBP"]

    def test_render_without_caller_cookies_passes_none(self):
        solver = _RenderSolver()
        s = _session(browser_solver=solver)
        s.render(URL, timeout=5)
        assert solver.render_cookies == [None]


class TestSessionSolve:
    def test_solve_is_seeded(self):
        solver = _RenderSolver(
            cookies_back=[
                {"name": "x5sec", "value": "new", "domain": ".shop.test",
                 "path": "/", "expires": -1}
            ],
            response=False,
        )
        s = _session(browser_solver=solver)
        s.add_cookie(PIN, URL)
        assert s.browser_solve_challenge(URL, "tmd", timeout=5)
        [seed] = solver.solve_cookies
        assert [c["value"] for c in seed] == ["GBP"]
        assert s.get_cookie("cur", URL) == "GBP"
        assert s.get_cookie("x5sec", URL) == "new"

    @pytest.mark.asyncio
    async def test_async_solve_is_seeded(self):
        solver = _RenderSolver(
            cookies_back=[
                {"name": "x5sec", "value": "new", "domain": ".shop.test",
                 "path": "/", "expires": -1}
            ],
            response=False,
        )
        s = AsyncSession(cache_dir=None, browser_solver=solver)
        s.add_cookie(PIN, URL)
        assert await s.browser_solve_challenge(URL, "tmd", timeout=5)
        [seed] = solver.solve_cookies
        assert [c["value"] for c in seed] == ["GBP"]

    def test_prime_that_only_returns_the_seed_earned_nothing(self):
        """browser_prime's True means state was earned, not echoed back."""
        echo = {
            "name": "cur", "value": "GBP", "domain": ".shop.test", "path": "/",
            "expires": -1,
        }
        s = _session(browser_solver=_RenderSolver(cookies_back=[echo]))
        s.add_cookie(PIN, URL)
        assert s.browser_prime(URL, timeout=5) is False

    def test_seeded_cookies_never_pass_as_reddit_evidence(self):
        """A caller's Reddit cookies are not seeded, so cannot fake the bootstrap."""
        solver = _RenderSolver(response=False)
        s = _session(browser_solver=solver)
        reddit = "https://www.reddit.com/r/python.json"
        for raw in ("loid=caller", "token_v2=caller", "over18=1"):
            s.add_cookie(f"{raw}; Domain=.reddit.com; Path=/", reddit)
        seeds = s._browser_seed_cookies(reddit, "https://www.reddit.com/")
        assert [c["name"] for c in seeds] == ["over18"]


# ---------------------------------------------------------------------------
# BrowserSolver
# ---------------------------------------------------------------------------


class TestSeedContextCookies:
    def test_each_cookie_goes_in_alone_and_a_refused_one_is_skipped(self):
        context = MagicMock()
        context.add_cookies.side_effect = [None, RuntimeError("Invalid"), None]
        cookies = [
            {"name": "a", "value": "1", "domain": ".x.test", "path": "/"},
            {"name": "__Host-b", "value": "2", "domain": ".x.test", "path": "/"},
            {"name": "c", "value": "3", "domain": "www.x.test", "path": "/p"},
        ]
        assert _seed_context_cookies(context, cookies) == 2
        calls = context.add_cookies.call_args_list
        assert [call.args[0][0]["name"] for call in calls] == ["a", "__Host-b", "c"]

    def test_only_playwright_fields_and_a_named_scope_are_passed(self):
        context = MagicMock()
        cookies = [
            {"name": "a", "value": "1", "domain": ".x.test", "path": "/",
             "secure": True, "partitionKey": "x", "junk": object()},
            {"name": "b", "value": "2", "url": "https://x.test/"},  # no scope
            {"name": "", "value": "2", "domain": ".x.test", "path": "/"},
            {"name": "c", "value": None, "domain": ".x.test", "path": "/"},
            {"name": "d", "value": "4", "domain": ".", "path": "/"},
            {"name": "e", "value": "5", "domain": ".x.test", "path": "rel"},
            "not a dict",
        ]
        assert _seed_context_cookies(context, cookies) == 1
        [call] = context.add_cookies.call_args_list
        assert call.args[0] == [
            {"name": "a", "value": "1", "domain": ".x.test", "path": "/",
             "secure": True}
        ]

    def test_create_context_seeds_before_any_page(self):
        solver = BrowserSolver(solve_timeout=1)
        solver._browser = MagicMock()
        context = solver._browser.new_context.return_value
        seed = [{"name": "a", "value": "1", "domain": ".x.test", "path": "/"}]
        assert solver._create_context(cookies=seed) is context
        context.add_cookies.assert_called_once_with(seed)
        context.new_page.assert_not_called()
        solver._browser.new_context.reset_mock()
        solver._create_context()
        solver._browser.new_context.return_value.add_cookies.assert_not_called()


class _ContextRecorder:
    """Stands in for _create_context: records its kwargs, then fails the op."""

    def __init__(self):
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        raise RuntimeError("stop after context creation")


def _recording_solver():
    solver = BrowserSolver(solve_timeout=5)
    solver._browser = MagicMock()
    solver._browser.is_connected.return_value = True
    solver._browser_ua = "Chrome/154"
    solver._needs_screenxy_patch = False
    solver._ensure_browser = lambda *a, **k: None
    solver._probe_screenxy_patch = lambda: None
    recorder = _ContextRecorder()
    solver._create_context = recorder
    return solver, recorder


SEED = [{"name": "cur", "value": "GBP", "domain": ".shop.test", "path": "/"}]


class TestSolverEntryPointsForwardCookies:
    def test_solve(self):
        solver, recorder = _recording_solver()
        try:
            assert solver.solve(URL, "cloudflare", timeout=5, cookies=SEED) is None
        finally:
            solver.close(timeout=5)
        assert recorder.calls == [{"cookies": SEED}]

    def test_brave_solve_keeps_its_storage_state(self):
        solver, recorder = _recording_solver()
        try:
            solver.solve(
                "https://search.brave.com/search?q=x", "brave", timeout=5,
                cookies=SEED,
            )
        finally:
            solver.close(timeout=5)
        [call] = recorder.calls
        assert call["cookies"] == SEED
        assert "storage_state" in call

    def test_render(self):
        solver, recorder = _recording_solver()
        try:
            assert solver.render(URL, timeout=5, cookies=SEED) is None
        finally:
            solver.close(timeout=5)
        assert recorder.calls == [{"cookies": SEED}]

    def test_asolve_and_arender(self):
        solver, recorder = _recording_solver()

        async def run():
            await solver.asolve(URL, "cloudflare", timeout=5, cookies=SEED)
            await solver.arender(URL, timeout=5, cookies=SEED)

        try:
            asyncio.run(run())
        finally:
            solver.close(timeout=5)
        assert recorder.calls == [{"cookies": SEED}, {"cookies": SEED}]

    def test_overridden_solve_gets_cookies_only_if_it_takes_them(self):
        seen = []

        class Old(BrowserSolver):
            def solve(self, url, challenge_type=None, timeout=None,
                      embedder=None, replay=None):
                seen.append("old")
                return None

        class New(BrowserSolver):
            def solve(self, url, challenge_type=None, timeout=None,
                      embedder=None, replay=None, *, cookies=None):
                seen.append(cookies)
                return None

        for cls in (Old, New):
            solver = cls(solve_timeout=5)
            try:
                asyncio.run(solver.asolve(URL, "cloudflare", cookies=SEED))
            finally:
                solver.close(timeout=5)
        assert seen == ["old", SEED]


# ---------------------------------------------------------------------------
# The WAF list covers what the browser handlers read
# ---------------------------------------------------------------------------


def _handler_cookie_names() -> set[str]:
    """Cookie names a browser handler compares against, read from its source.

    ``c["name"] == "x"``, ``c.get("name") == "x"``, ``"x" in names`` and the
    tuples a handler matches with ``in``. A handler that starts polling a new
    name fails here until the name is listed in ``WAF_COOKIE_NAMES``.
    """

    def is_name_read(node) -> bool:
        if isinstance(node, ast.Subscript):
            return isinstance(node.slice, ast.Constant) and node.slice.value == "name"
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "name"
        )

    names: set[str] = set()
    root = Path(__file__).resolve().parent.parent / "wafer" / "browser"
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                sides = [node.left, *node.comparators]
                if any(is_name_read(side) for side in sides):
                    names.update(
                        side.value
                        for side in sides
                        if isinstance(side, ast.Constant)
                        and isinstance(side.value, str)
                    )
                if (
                    isinstance(node.left, ast.Constant)
                    and isinstance(node.left.value, str)
                    and isinstance(node.ops[0], ast.In)
                    and isinstance(node.comparators[0], ast.Name)
                    and "name" in node.comparators[0].id
                ):
                    names.add(node.left.value)
            if (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(t, ast.Name) and t.id.endswith("_COOKIES")
                    for t in node.targets
                )
                and isinstance(node.value, ast.Tuple)
            ):
                names.update(
                    e.value for e in node.value.elts if isinstance(e, ast.Constant)
                )
    return names


class TestWafCookieList:
    def test_every_cookie_a_handler_polls_is_listed(self):
        names = _handler_cookie_names()
        # The scan must see the handlers it guards, or it proves nothing.
        assert {"cf_clearance", "aws-waf-token", "datadome", "_abck",
                "_px3", "_pxhd", "reese84", "x5sec"} <= names
        assert sorted(n for n in names if not is_waf_cookie(n)) == []

    def test_wafer_gate_and_brave_tokens_are_listed(self):
        assert all(is_waf_cookie(name) for name in BRAVE_COOKIES)
        assert is_waf_cookie(POW_COOKIE_NAME)

    def test_reddit_evidence_names_are_listed_on_reddit(self):
        from wafer._solvers import reddit_has_cookie_evidence

        assert reddit_has_cookie_evidence({"loid", "token_v2"})
        for name in ("loid", "token_v2", "csv"):
            assert is_waf_cookie(name, ".reddit.com")
            assert not is_waf_cookie(name, "shop.test")

    @pytest.mark.parametrize(
        "name", ["cur", "aep_usuc_f", "_m_h5_tk", "over18", "session", "bmx"]
    )
    def test_app_cookies_are_not_waf_cookies(self, name):
        assert not is_waf_cookie(name, "shop.test")


# ---------------------------------------------------------------------------
# Review findings (2026-11-02)
# ---------------------------------------------------------------------------


class TestSeedEdgeCases:
    def test_equal_host_only_cookies_on_sibling_hosts_keep_their_hosts(self):
        """Same name, path and value on two hosts: one seed per host."""
        s = _session()
        s.add_cookie("lang=en; Path=/", "https://www.shop.test/")
        s.add_cookie("lang=en; Path=/", "https://api.shop.test/")
        hosts = sorted(c["domain"] for c in s._browser_seed_cookies(URL))
        assert hosts == ["api.shop.test", "www.shop.test"]

    @pytest.mark.parametrize("readd", ["https://www.shop.test/", "https://api.shop.test/"])
    def test_sibling_host_only_cookies_keep_their_own_secure_flag(self, readd):
        """Either host may be tried first; each copy keeps its own flags."""
        s = _session()
        s.add_cookie("lang=en; Path=/", "https://www.shop.test/")
        s.add_cookie("lang=en; Path=/; Secure", "https://api.shop.test/")
        # Re-recording one moves it last, so the candidate hosts are tried in
        # the other order against the same jar.
        s._remember_caller_cookie("lang=en; Path=/", readd)
        secure = {c["domain"]: c["secure"] for c in s._browser_seed_cookies(URL)}
        assert secure == {"www.shop.test": False, "api.shop.test": True}

    @pytest.mark.parametrize("readd", ["https://www.shop.test/", "https://api.shop.test/"])
    def test_sibling_host_only_cookies_keep_samesite_and_lifetime(self, readd):
        s = _session()
        s.add_cookie("lang=en; Path=/; SameSite=Strict", "https://www.shop.test/")
        s.add_cookie(
            "lang=en; Path=/; SameSite=Lax; Max-Age=3600", "https://api.shop.test/"
        )
        s._remember_caller_cookie("lang=en; Path=/", readd)
        seeds = {c["domain"]: c for c in s._browser_seed_cookies(URL)}
        assert seeds["www.shop.test"]["sameSite"] == "Strict"
        assert "expires" not in seeds["www.shop.test"]
        assert seeds["api.shop.test"]["sameSite"] == "Lax"
        assert seeds["api.shop.test"]["expires"] > time.time()

    def test_explicit_samesite_none_is_seeded_as_none(self):
        """wreq cannot report SameSite=None; Chrome would default it to Lax."""
        s = _session()
        s.add_cookie(
            "cur=GBP; Domain=.shop.test; Path=/; Secure; SameSite=None", URL
        )
        [seed] = s._browser_seed_cookies(URL)
        assert seed["sameSite"] == "None"

    def test_samesite_none_is_not_kept_once_the_value_is_replaced(self):
        s = _session()
        s.add_cookie(
            "cur=GBP; Domain=.shop.test; Path=/; Secure; SameSite=None", URL
        )
        s._client.cookie_jar.add("cur=EUR; Domain=.shop.test; Path=/; Secure", URL)
        [seed] = s._browser_seed_cookies(URL)
        assert seed["value"] == "EUR"
        assert "sameSite" not in seed


def _seed(**over):
    seed = {"name": "cur", "value": "GBP", "domain": ".shop.test", "path": "/",
            "secure": False, "httpOnly": False}
    seed.update(over)
    return seed


def _back(**over):
    cookie = {"name": "cur", "value": "GBP", "domain": ".shop.test", "path": "/",
              "secure": False, "httpOnly": False, "sameSite": "Lax", "expires": -1}
    cookie.update(over)
    return cookie


class TestUnchangedSeedFilter:
    """Only an exact echo of a seed is dropped; any reissue is the site's."""

    def _kept(self, back, seed):
        return SyncSession._without_seeded_cookies([back], [seed])

    def test_exact_echo_is_dropped(self):
        assert self._kept(_back(), _seed()) == []

    @pytest.mark.parametrize(
        "change",
        [
            {"value": "EUR"},
            {"secure": True},  # upgraded: the jar must not keep the insecure copy
            {"httpOnly": True},
            {"sameSite": "Strict"},
            {"expires": time.time() + 86400},
            {"domain": "www.shop.test"},  # a different (host-only) cookie
        ],
    )
    def test_a_reissue_with_any_difference_is_kept(self, change):
        assert self._kept(_back(**change), _seed()) != []

    def test_persistent_seed_echo_is_dropped(self):
        exp = time.time() + 3600
        assert self._kept(_back(expires=exp + 0.0004), _seed(expires=exp)) == []

    def test_chromes_400_day_cap_is_not_a_change(self):
        """Chrome shortens a seed's lifetime to 400 days by itself."""
        now = time.time()
        far = now + 3 * 365 * 86400
        capped = now + 400 * 86400 - 5
        assert self._kept(_back(expires=capped), _seed(expires=far)) == []

    def test_session_seed_made_persistent_is_kept(self):
        assert self._kept(_back(expires=time.time() + 3600), _seed()) != []

    def test_samesite_none_echo_is_dropped(self):
        back = _back(sameSite="None", secure=True)
        assert self._kept(back, _seed(sameSite="None", secure=True)) == []

    def test_secure_upgrade_replaces_the_jar_copy(self):
        """Security review: the insecure copy must not survive in the jar."""
        upgraded = _back(secure=True)
        solver = _RenderSolver(cookies_back=[upgraded])
        s = _session(browser_solver=solver)
        s.add_cookie(PIN, URL)
        s.render(URL, timeout=5)
        [cur] = [c for c in s._client.cookie_jar.get_all() if c.name == "cur"]
        assert cur.secure is True
        assert s.get_cookie("cur", "http://www.shop.test/w/cables.html") is None


class _OverridingSolver(BrowserSolver):
    """A BrowserSolver subclass whose solve/render predate cookies=."""

    def __init__(self, back):
        super().__init__(solve_timeout=5)
        self.back = back
        self.calls = []

    def _result(self):
        return SolveResult(
            cookies=[dict(self.back)],
            user_agent="Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36",
            response=_page(),
            challenge_absent=True,
        )

    def solve(self, url, challenge_type=None, timeout=None, embedder=None,
              replay=None, max_size=None):
        self.calls.append("solve")
        return self._result()

    def render(self, url, timeout=None, max_size=None):
        self.calls.append("render")
        return self._result()


class TestOverriddenSolverParity:
    """Sync and async must agree that a legacy override was not seeded."""

    def test_sync_prime_adopts_what_the_override_returned(self):
        solver = _OverridingSolver(_back())
        try:
            s = _session(browser_solver=solver)
            s.add_cookie(PIN, URL)
            assert s.browser_prime(URL, timeout=5) is True
        finally:
            solver.close(timeout=5)

    @pytest.mark.asyncio
    async def test_async_prime_adopts_what_the_override_returned(self):
        solver = _OverridingSolver(_back())
        try:
            s = AsyncSession(cache_dir=None, browser_solver=solver)
            s.add_cookie(PIN, URL)
            assert await s.browser_prime(URL, timeout=5) is True
            assert solver.calls == ["solve"]
        finally:
            solver.close(timeout=5)

    @pytest.mark.asyncio
    async def test_async_render_through_an_override_is_not_seeded(self, tmp_path):
        solver = _OverridingSolver(_back(value="GBP"))
        try:
            s = AsyncSession(cache_dir=str(tmp_path), browser_solver=solver)
            s.add_cookie(PIN, URL)
            await s.render(URL, timeout=5)
            assert solver.calls == ["render"]
        finally:
            solver.close(timeout=5)
        # Nothing was seeded, so the returned cookie is the browser's own and
        # goes where browser cookies go.
        cached = json.dumps(
            [json.loads(p.read_text()) for p in tmp_path.rglob("*.json")]
        )
        assert "GBP" in cached

    def test_base_entry_points_take_cookies(self):
        from wafer._base import _solver_takes_cookies

        solver = BrowserSolver(solve_timeout=5)
        try:
            assert _solver_takes_cookies(solver, solver.asolve, "solve")
            assert _solver_takes_cookies(solver, solver.arender, "render")
            assert _solver_takes_cookies(solver, solver.solve, "solve")
        finally:
            solver.close(timeout=5)
