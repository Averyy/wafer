"""ChallengeDetected.browser_outcome, and reading the page in the browser when a
solve got past the challenge but the HTTP retry with what it earned was
refused (case 2 of fetchaller's 2026-11-25 request)."""

import time
from unittest.mock import patch

import pytest

from tests.conftest import MockResponse, make_async_session, make_sync_session
from tests.test_browser import MockBrowserSolver
from wafer import ChallengeDetected, RequestBlocked
from wafer._base import (
    BaseSession,
    _callable_names_keyword,
    _solver_report_outcome,
)
from wafer.browser import SolveResult
from wafer.browser._solver import CapturedResponse

URL = "https://example.com/page"
PAGE_HTML = (
    "<html><head><title>Item</title></head><body>"
    + "The page the browser reached. " * 40
    + "</body></html>"
)


def _cf():
    return MockResponse(
        403,
        {"cf-mitigated": "challenge", "content-type": "text/html"},
        "<html>Just a moment...</html>",
    )


def _cleared():
    """A solve that got through and handed back only cookies."""
    return SolveResult(
        cookies=[
            {
                "name": "cf_clearance",
                "value": "earned",
                "domain": ".example.com",
                "path": "/",
                "expires": -1,
            }
        ],
        user_agent="Chrome/158",
    )


def _rendered(html=PAGE_HTML, status=200, headers=None):
    return SolveResult(
        cookies=[],
        user_agent="Chrome/158",
        response=CapturedResponse(
            url=URL,
            status=status,
            headers=headers or {"content-type": "text/html; charset=utf-8"},
            body=html.encode("utf-8"),
        ),
        challenge_absent=True,
    )


class ReportingSolver:
    """A solver that reports outcomes as BrowserSolver does, and renders."""

    def __init__(self, solves, renders=()):
        # solves: (result, report) per solve() call; renders: results.
        self._solves = list(solves)
        self._renders = list(renders)
        self.solve_kwargs = []
        self.render_calls = []

    def solve(
        self,
        url,
        challenge_type=None,
        timeout=None,
        embedder=None,
        replay=None,
        max_size=None,
        *,
        cookies=None,
        report=None,
    ):
        self.solve_kwargs.append(
            {"url": url, "embedder": embedder, "report_passed": report is not None}
        )
        result, filled = self._solves.pop(0)
        if report is not None:
            report.update(filled)
        return result

    def render(self, url, timeout=None, max_size=None):
        self.render_calls.append(url)
        return self._renders.pop(0)

    def close(self):
        pass


def _raise(session, **kwargs):
    with pytest.raises(ChallengeDetected) as info:
        session.get(URL, **kwargs)
    return info.value


class TestOutcomeOnTheError:
    @patch("time.sleep")
    def test_refused_at_this_url(self, _sleep):
        solver = ReportingSolver(
            [(None, {"navigated": True, "outcome": "refused"})]
        )
        session, _ = make_sync_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        assert _raise(session).browser_outcome == "refused"
        assert solver.solve_kwargs[0]["report_passed"]
        assert solver.render_calls == []

    @pytest.mark.parametrize(
        "report",
        [
            {"navigated": False},
            {"navigated": True, "outcome": "failed"},
            {"navigated": True, "timed_out": True},
        ],
    )
    @patch("time.sleep")
    def test_no_verdict_is_failed(self, _sleep, report):
        solver = ReportingSolver([(None, report)])
        session, _ = make_sync_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        assert _raise(session).browser_outcome == "failed"

    @patch("time.sleep")
    def test_a_solver_that_does_not_report(self, _sleep):
        session, _ = make_sync_session(
            [_cf()] * 3,
            browser_solver=MockBrowserSolver(result=None),
            max_rotations=1,
            use_cookie_jar=True,
        )
        assert _raise(session).browser_outcome is None

    @patch("time.sleep")
    def test_no_browser_solver(self, _sleep):
        session, _ = make_sync_session([_cf()] * 3, max_rotations=1)
        assert _raise(session).browser_outcome is None

    @patch("time.sleep")
    def test_solved_on_another_page(self, _sleep):
        solver = ReportingSolver([(_cleared(), {})])
        session, _ = make_sync_session(
            [_cf()] * 3,
            browser_solver=solver,
            max_rotations=1,
            use_cookie_jar=True,
            solve_origin="https://example.com/",
        )
        assert _raise(session).browser_outcome == "other_page"
        assert solver.solve_kwargs[0]["embedder"] == "https://example.com/"
        # A render of the URL is a different attempt; wafer does not make it.
        assert solver.render_calls == []

    def test_defaults(self):
        assert ChallengeDetected("akamai", URL, 403).browser_outcome is None
        blocked = RequestBlocked("cloudflare_block", URL, 403)
        assert blocked.browser_outcome is None
        assert str(blocked) == str(RequestBlocked("cloudflare_block", URL, 403))


class TestReadingThePageAfterARefusedRetry:
    @patch("time.sleep")
    def test_the_browsers_page_is_returned(self, _sleep):
        solver = ReportingSolver([(_cleared(), {})], renders=[_rendered()])
        session, client = make_sync_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        resp = session.get(URL)
        assert resp.status_code == 200
        assert "The page the browser reached." in resp.text
        assert resp.challenge_type is None
        assert len(solver.solve_kwargs) == 1
        assert solver.render_calls == [URL]

    @patch("time.sleep")
    def test_under_max_rotations_zero_too(self, _sleep):
        solver = ReportingSolver([(_cleared(), {})], renders=[_rendered()])
        session, _ = make_sync_session(
            [_cf()] * 2, browser_solver=solver, max_rotations=0, use_cookie_jar=True
        )
        resp = session.get(URL)
        assert resp.status_code == 200
        assert resp.challenge_type is None

    @patch("time.sleep")
    def test_a_render_that_lands_on_the_challenge_is_refused(self, _sleep):
        challenged = _rendered(
            html="<html><title>Just a moment...</title>"
            "<script>window._cf_chl_opt={}</script></html>",
            status=403,
            headers={"content-type": "text/html", "cf-mitigated": "challenge"},
        )
        solver = ReportingSolver([(_cleared(), {})], renders=[challenged])
        session, _ = make_sync_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        assert _raise(session).browser_outcome == "refused"
        assert len(solver.render_calls) == 1

    @patch("time.sleep")
    def test_a_render_with_no_document_stays_cleared(self, _sleep):
        solver = ReportingSolver([(_cleared(), {})], renders=[None])
        session, _ = make_sync_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        assert _raise(session).browser_outcome == "cleared"

    @patch("time.sleep")
    def test_a_post_is_not_rendered(self, _sleep):
        solver = ReportingSolver([(_cleared(), {})], renders=[_rendered()])
        session, _ = make_sync_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        with pytest.raises(ChallengeDetected) as info:
            session.post(URL, json={"q": 1})
        assert info.value.browser_outcome == "cleared"
        assert solver.render_calls == []

    @patch("time.sleep")
    def test_a_solver_that_cannot_render_stays_cleared(self, _sleep):
        session, _ = make_sync_session(
            [_cf()] * 3,
            browser_solver=MockBrowserSolver(result=_cleared()),
            max_rotations=1,
            use_cookie_jar=True,
        )
        assert _raise(session).browser_outcome == "cleared"

    @patch("time.sleep")
    def test_cookies_scoped_elsewhere_count_as_cleared(self, _sleep):
        # The browser got through but ended on another site's cookies only.
        elsewhere = SolveResult(
            cookies=[
                {
                    "name": "sid",
                    "value": "x",
                    "domain": ".other.example.net",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Chrome/158",
        )
        solver = ReportingSolver([(elsewhere, {})], renders=[_rendered()])
        session, _ = make_sync_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        assert session.get(URL).status_code == 200
        assert solver.render_calls == [URL]

    @patch("time.sleep")
    def test_once_per_request(self, _sleep):
        solver = ReportingSolver([(_cleared(), {})], renders=[None])
        session, _ = make_sync_session(
            [_cf()] * 6, browser_solver=solver, max_rotations=3, use_cookie_jar=True
        )
        _raise(session)
        assert len(solver.render_calls) == 1


def _rendered_at(url, cookies=()):
    result = _rendered()
    result.response.url = url
    result.cookies = list(cookies)
    return result


class TestTheBrowsersPageKeepsTheRequestsContract:
    @pytest.mark.parametrize(
        "landed",
        [
            "https://other.example.net/page",
            "http://example.com/page",
            "https://example.com:8443/page",
            "https://example.com:0/page",
        ],
    )
    @patch("time.sleep")
    def test_another_origin_is_not_returned(self, _sleep, landed):
        solver = ReportingSolver(
            [(_cleared(), {})], renders=[_rendered_at(landed)]
        )
        session, _ = make_sync_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        assert _raise(session).browser_outcome == "cleared"
        assert solver.render_calls == [URL]

    @patch("time.sleep")
    def test_a_same_origin_redirect_is_returned(self, _sleep):
        solver = ReportingSolver(
            [(_cleared(), {})], renders=[_rendered_at("https://example.com/moved")]
        )
        session, _ = make_sync_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        assert session.get(URL).url == "https://example.com/moved"

    @pytest.mark.parametrize(
        "landed,returned",
        [(URL, True), (URL + "#top", True), ("https://example.com/moved", False)],
    )
    @patch("time.sleep")
    def test_without_redirects_only_the_url_itself(self, _sleep, landed, returned):
        solver = ReportingSolver(
            [(_cleared(), {})], renders=[_rendered_at(landed)]
        )
        session, _ = make_sync_session(
            [_cf()] * 3,
            browser_solver=solver,
            max_rotations=1,
            use_cookie_jar=True,
            follow_redirects=False,
        )
        if returned:
            assert session.get(URL).status_code == 200
        else:
            assert _raise(session).browser_outcome == "cleared"

    @patch("time.sleep")
    def test_nothing_reaches_cache_dir(self, _sleep, tmp_path):
        from wafer._cookies import CookieCache

        earned = {
            "name": "cf_clearance",
            "value": "rejected-over-http",
            "domain": ".example.com",
            "path": "/",
            "expires": time.time() + 3600,
        }
        solver = ReportingSolver(
            [(_cleared(), {})], renders=[_rendered_at(URL, cookies=[earned])]
        )
        session, _ = make_sync_session(
            [_cf()] * 3,
            browser_solver=solver,
            max_rotations=1,
            use_cookie_jar=True,
            cookie_cache=CookieCache(str(tmp_path)),
        )
        assert session.get(URL).status_code == 200
        assert session._cookie_cache.load("example.com") == []

    @pytest.mark.asyncio
    async def test_async_too(self, tmp_path):
        from wafer._cookies import CookieCache

        earned = {
            "name": "cf_clearance",
            "value": "rejected-over-http",
            "domain": ".example.com",
            "path": "/",
            "expires": time.time() + 3600,
        }
        solver = ReportingSolver(
            [(_cleared(), {}), (_cleared(), {})],
            renders=[
                _rendered_at("https://other.example.net/"),
                _rendered_at(URL, cookies=[earned]),
            ],
        )
        session, _ = make_async_session(
            [_cf()] * 3,
            browser_solver=solver,
            max_rotations=1,
            use_cookie_jar=True,
            cookie_cache=CookieCache(str(tmp_path)),
        )
        with patch("asyncio.sleep"), pytest.raises(ChallengeDetected) as info:
            await session.get(URL)
        assert info.value.browser_outcome == "cleared"
        second, _ = make_async_session(
            [_cf()] * 3,
            browser_solver=solver,
            max_rotations=1,
            use_cookie_jar=True,
            cookie_cache=CookieCache(str(tmp_path)),
        )
        with patch("asyncio.sleep"):
            assert (await second.get(URL)).status_code == 200
        assert second._cookie_cache.load("example.com") == []


class AsyncReportingSolver(ReportingSolver):
    """With an asolve that names report, as BrowserSolver.asolve does: the
    async session calls asolve, not solve."""

    async def asolve(
        self,
        url,
        challenge_type=None,
        timeout=None,
        embedder=None,
        replay=None,
        max_size=None,
        *,
        cookies=None,
        report=None,
    ):
        return self.solve(
            url, challenge_type, timeout, embedder, replay, max_size,
            cookies=cookies, report=report,
        )


class TestAsyncThroughAsolve:
    @pytest.mark.asyncio
    async def test_refused_at_this_url(self):
        solver = AsyncReportingSolver(
            [(None, {"navigated": True, "outcome": "refused"})]
        )
        session, _ = make_async_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        with patch("asyncio.sleep"), pytest.raises(ChallengeDetected) as info:
            await session.get(URL)
        assert info.value.browser_outcome == "refused"
        assert solver.solve_kwargs[0]["report_passed"]

    @pytest.mark.asyncio
    async def test_an_empty_cleared_solve_is_read_in_the_browser(self):
        solver = AsyncReportingSolver(
            [(None, {"navigated": True, "outcome": "cleared"})],
            renders=[_rendered()],
        )
        session, _ = make_async_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        with patch("asyncio.sleep"):
            resp = await session.get(URL)
        assert resp.status_code == 200
        assert solver.render_calls == [URL]


class TestBrowserSolverAsolveReport:
    def _run(self, solver, **kwargs):
        import asyncio

        return asyncio.run(
            solver.asolve("https://example.com/", "cloudflare", **kwargs)
        )

    def test_marks_the_report_before_an_early_return(self):
        from wafer.browser import BrowserSolver

        solver = BrowserSolver(solve_timeout=5)
        report = {"outcome": "stale"}
        try:
            with patch.object(solver, "_worker_lost", return_value=True):
                assert self._run(solver, report=report) is None
        finally:
            solver.close()
        assert report["navigated"] is False

    def test_marks_an_overrun(self):
        from wafer.browser import BrowserSolver

        solver = BrowserSolver(solve_timeout=0.2)

        def slow_worker(url, *args, report=None, **kwargs):
            report["navigated"] = True
            time.sleep(0.6)
            return None

        report = {}
        try:
            with patch.object(solver, "_solve_on_worker", side_effect=slow_worker):
                assert self._run(solver, timeout=0.2, report=report) is None
        finally:
            solver.close()
        assert report.get("timed_out") is True

    @pytest.mark.parametrize("names_report", [True, False])
    def test_an_overriding_solve_gets_it_only_if_it_names_it(self, names_report):
        from wafer.browser import BrowserSolver

        seen = []

        if names_report:
            class Override(BrowserSolver):
                def solve(self, url, challenge_type=None, timeout=None,
                          embedder=None, replay=None, max_size=None, *,
                          cookies=None, report=None):
                    seen.append(report)
                    return None
        else:
            class Override(BrowserSolver):
                def solve(self, url, challenge_type=None, timeout=None,
                          embedder=None, replay=None):
                    seen.append("called")
                    return None

        solver = Override(solve_timeout=5)
        report = {}
        try:
            assert self._run(solver, report=report) is None
        finally:
            solver.close()
        assert seen == ([report] if names_report else ["called"])


def test_browser_solver_asolve_forwards_the_report():
    import asyncio

    from wafer.browser import BrowserSolver

    solver = BrowserSolver(solve_timeout=5)

    def fake_worker(url, *args, report=None, **kwargs):
        report["navigated"] = True
        report["outcome"] = "refused"
        return None

    report = {}
    try:
        with patch.object(solver, "_solve_on_worker", side_effect=fake_worker):
            assert asyncio.run(
                solver.asolve("https://example.com/", "cloudflare", report=report)
            ) is None
    finally:
        solver.close()
    assert report == {"navigated": True, "outcome": "refused"}


class TestAsync:
    @pytest.mark.asyncio
    async def test_the_browsers_page_is_returned(self):
        solver = ReportingSolver([(_cleared(), {})], renders=[_rendered()])
        session, _ = make_async_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        with patch("asyncio.sleep"):
            resp = await session.get(URL)
        assert resp.status_code == 200
        assert "The page the browser reached." in resp.text
        assert solver.render_calls == [URL]

    @pytest.mark.asyncio
    async def test_refused_at_this_url(self):
        solver = ReportingSolver(
            [(None, {"navigated": True, "outcome": "refused"})]
        )
        session, _ = make_async_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        with patch("asyncio.sleep"), pytest.raises(ChallengeDetected) as info:
            await session.get(URL)
        assert info.value.browser_outcome == "refused"
        assert solver.solve_kwargs[0]["report_passed"]

    @pytest.mark.asyncio
    async def test_a_render_with_no_document_stays_cleared(self):
        solver = ReportingSolver([(_cleared(), {})], renders=[None])
        session, _ = make_async_session(
            [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
        )
        with patch("asyncio.sleep"), pytest.raises(ChallengeDetected) as info:
            await session.get(URL)
        assert info.value.browser_outcome == "cleared"

    @pytest.mark.asyncio
    async def test_an_asolve_wrapper_is_not_sent_the_report(self):
        # MockBrowserSolver.asolve(*args, **kwargs) forwards to a solve()
        # without the keyword: passing it on would be a TypeError.
        session, _ = make_async_session(
            [_cf()] * 3,
            browser_solver=MockBrowserSolver(result=None),
            max_rotations=1,
            use_cookie_jar=True,
        )
        with patch("asyncio.sleep"), pytest.raises(ChallengeDetected) as info:
            await session.get(URL)
        assert info.value.browser_outcome is None


class TestRenderRaise:
    def test_render_that_settles_on_a_challenge_is_refused(self):
        challenged = _rendered(
            html="<html><title>Just a moment...</title>"
            "<script>window._cf_chl_opt={}</script></html>",
            status=403,
            headers={"content-type": "text/html", "cf-mitigated": "challenge"},
        )

        class Renderer(ReportingSolver):
            pass

        session, _ = make_sync_session(
            [], browser_solver=Renderer([], renders=[challenged])
        )
        with pytest.raises(ChallengeDetected) as info:
            session.render(URL, timeout=30)
        assert info.value.browser_outcome == "refused"


class TestHelpers:
    @pytest.mark.parametrize(
        "report,reported,outcome",
        [
            ({}, False, None),
            ({"navigated": True}, True, "refused"),
            ({"navigated": False}, True, "failed"),
            ({"navigated": True, "outcome": "cleared"}, True, "cleared"),
            (
                {"navigated": True, "outcome": "refused", "timed_out": True},
                True,
                "failed",
            ),
            ({}, True, None),
        ],
    )
    def test_solver_report_outcome(self, report, reported, outcome):
        assert _solver_report_outcome(report, reported) == outcome

    def test_browser_outcome_uses_the_latest_attempt_for_the_url(self):
        log = [
            {"url": URL, "on_url": True, "result": "cleared"},
            {"url": "https://example.com/other", "on_url": True, "result": "refused"},
            {"url": URL, "on_url": True, "result": "refused"},
        ]
        assert BaseSession._browser_outcome(log, URL + "#frag") == "refused"
        assert BaseSession._browser_outcome([], URL) is None

    def test_another_page_unless_no_verdict(self):
        assert (
            BaseSession._browser_outcome(
                [{"url": URL, "on_url": False, "result": "refused"}], URL
            )
            == "other_page"
        )
        assert (
            BaseSession._browser_outcome(
                [{"url": URL, "on_url": False, "result": "failed"}], URL
            )
            == "failed"
        )

    def test_callable_names_keyword(self):
        def named(url, *, report=None):
            pass

        def wrapper(*args, **kwargs):
            pass

        assert _callable_names_keyword(named, "report")
        assert not _callable_names_keyword(wrapper, "report")


def test_elapsed_is_measured_from_the_request():
    solver = ReportingSolver([(_cleared(), {})], renders=[_rendered()])
    session, _ = make_sync_session(
        [_cf()] * 3, browser_solver=solver, max_rotations=1, use_cookie_jar=True
    )
    with patch("time.sleep"):
        t = time.monotonic()
        resp = session.get(URL)
    assert 0 <= resp.elapsed <= time.monotonic() - t + 0.01


class _LateWritingSolver:
    """Two TMD attempts: the first overruns after navigating, and its worker
    writes its own verdict while the second attempt, which never navigates,
    is running."""

    def __init__(self):
        self.reports = []

    def solve(
        self,
        url,
        challenge_type=None,
        timeout=None,
        embedder=None,
        replay=None,
        max_size=None,
        *,
        cookies=None,
        report=None,
    ):
        self.reports.append(report)
        if len(self.reports) == 1:
            report.update({"navigated": True, "timed_out": True})
            return None
        self.reports[0]["outcome"] = "refused"  # the late worker
        report["navigated"] = False
        return None

    async def asolve(self, *args, report=None, **kwargs):
        return self.solve(*args, report=report, **kwargs)

    def close(self):
        pass


class TestEachSolveAttemptHasItsOwnReport:
    def test_sync(self):
        from wafer._challenge import ChallengeType

        solver = _LateWritingSolver()
        session, _ = make_sync_session([], browser_solver=solver)
        attempt = {}
        assert session._try_browser_solve(
            ChallengeType.TMD, URL, time.monotonic() + 200, attempt=attempt
        ) is False
        assert len(solver.reports) >= 2
        assert len({id(r) for r in solver.reports}) == len(solver.reports)
        assert attempt["result"] == "failed"

    @pytest.mark.asyncio
    async def test_async(self):
        from wafer._challenge import ChallengeType

        solver = _LateWritingSolver()
        session, _ = make_async_session([], browser_solver=solver)
        attempt = {}
        assert await session._try_browser_solve(
            ChallengeType.TMD, URL, time.monotonic() + 200, attempt=attempt
        ) is False
        assert len(solver.reports) >= 2
        assert len({id(r) for r in solver.reports}) == len(solver.reports)
        assert attempt["result"] == "failed"
