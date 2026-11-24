"""A Cloudflare block a site's own page clears: page choice, session flow, wait.

A Cloudflare zone whose own pages run Turnstile, and whose ``/api/*`` routes
need the ``session`` cookie that sets (seen 2026-11-24), blocks every API call
with Cloudflare's "Sorry, you have been blocked" page until the request
carries it. Its pages run the widget in place and post the token to the
site's backend, which sets the cookie. Replayed over plain wafer, ``session``
alone got a 200; the ``cf_clearance`` the widget set did not.
"""

import pathlib
import time
from unittest.mock import patch

import pytest

from tests.conftest import MockResponse, make_async_session, make_sync_session
from tests.test_browser import MockBrowserSolver
from wafer import RequestBlocked
from wafer._challenge import (
    ChallengeType,
    detect_challenge,
    has_page_script,
    page_runs_turnstile,
)
from wafer.browser import SolveResult, _cloudflare

API = "https://www.example.org/api/items/42"
PAGE = "https://www.example.org/map"
BLOCK_BODY = (
    pathlib.Path(__file__).parent
    / "fixtures"
    / "cloudflare_waf_block_jsd_2026-11-24.html"
).read_text()
DATA = '{"id":42,"name":"example"}'
ORIGIN_403_BODY = (
    pathlib.Path(__file__).parent / "fixtures" / "cloudflare_origin_403_2026-11-24.html"
).read_text()


def _block():
    return MockResponse(
        403,
        {"server": "cloudflare", "content-type": "text/html; charset=UTF-8"},
        BLOCK_BODY,
    )


def _data():
    return MockResponse(
        200,
        {
            "server": "cloudflare",
            "content-type": "application/json",
        },
        DATA,
    )


def _session_cookie():
    return SolveResult(
        cookies=[
            {
                "name": "session",
                "value": "s3ss10n",
                "domain": "www.example.org",
                "path": "/",
                "expires": time.time() + 3600,
                "httpOnly": True,
            }
        ],
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
    )


class TestBlockPage:
    def _session(self, **kwargs):
        session, _ = make_sync_session(
            [], browser_solver=MockBrowserSolver(), **kwargs
        )
        return session

    def test_the_referer(self):
        page = self._session()._turnstile_recovery_page(API, {"Referer": PAGE})
        assert page == PAGE

    def test_origin_then_embed_origin(self):
        session = self._session()
        assert (
            session._turnstile_recovery_page(
                API, {"Origin": "https://www.example.org"}
            )
            == "https://www.example.org/"
        )
        session = self._session(embed_origin="https://www.example.org/map")
        assert (
            session._turnstile_recovery_page(API, {})
            == "https://www.example.org/map"
        )

    def test_solve_origin_first(self):
        session = self._session(solve_origin="https://www.example.org/map")
        assert (
            session._turnstile_recovery_page(API, {"Referer": PAGE})
            == "https://www.example.org/map"
        )

    def test_a_page_on_another_subdomain_of_the_site(self):
        page = "https://map.example.org/"
        assert self._session()._turnstile_recovery_page(API, {"Referer": page}) == page

    def test_never_another_site(self):
        # Its cookies never reach the blocked URL.
        session = self._session()
        assert (
            session._turnstile_recovery_page(API, {"Referer": "https://www.google.com/"})
            is None
        )

    def test_never_the_blocked_url(self):
        # A browser sent there gets the block page and nothing to solve.
        session = self._session()
        assert session._turnstile_recovery_page(API, {"Referer": API}) is None
        assert session._turnstile_recovery_page(API, {"Referer": API + "#x"}) is None

    def test_none_without_a_page_or_a_browser(self):
        assert self._session()._turnstile_recovery_page(API, {}) is None
        session, _ = make_sync_session([])
        assert session._turnstile_recovery_page(API, {"Referer": PAGE}) is None


def _origin_403():
    """The origin's own 403, behind Cloudflare (a clearance minted on another
    subdomain let the request past the edge)."""
    return MockResponse(
        403,
        {
            "server": "cloudflare",
            "cf-ray": "a5f9273a780e92c6-YYZ",
            "content-type": "text/html; charset=utf-8",
        },
        ORIGIN_403_BODY,
    )


def _widget_page():
    return MockResponse(
        200,
        {"server": "cloudflare", "content-type": "text/html; charset=utf-8"},
        "<html><head><script>window.APP_CONFIG="
        '{turnstileSitekey:"0x4AAAAAAAexampleKey00"}</script>'
        '<script src="/static/app.js"></script></head>'
        "<body>Example page</body></html>",
    )


def _plain_page():
    return MockResponse(
        200,
        {"server": "cloudflare", "content-type": "text/html; charset=utf-8"},
        "<html><body>" + "no widget here " * 50 + "</body></html>",
    )


def _urls(client):
    return [u for _m, u, _k in client.request_log]


class TestSyncFlow:
    @patch("time.sleep")
    def test_cleared_on_the_page_then_retried(self, _sleep):
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_sync_session(
            [_block(), _widget_page(), _data()],
            browser_solver=solver,
            use_cookie_jar=True,
        )
        resp = session.get(API, headers={"Referer": PAGE})
        assert resp.status_code == 200
        assert resp.text == DATA
        assert len(solver.solve_kwargs) == 1
        call = solver.solve_kwargs[0]
        assert call["challenge_type"] == "cloudflare_block"
        assert call["url"] == API
        assert call["embedder"] == PAGE
        assert _urls(client) == [API, PAGE, API]
        assert session.get_cookie("session", PAGE) == "s3ss10n"

    @patch("time.sleep")
    def test_the_origins_own_403_is_cleared_the_same_way(self, _sleep):
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_sync_session(
            [_origin_403(), _widget_page(), _data()],
            browser_solver=solver,
            use_cookie_jar=True,
        )
        resp = session.get(API, headers={"Referer": PAGE})
        assert resp.status_code == 200
        assert solver.solve_kwargs[0]["challenge_type"] == "cloudflare_block"
        assert solver.solve_kwargs[0]["embedder"] == PAGE
        assert _urls(client) == [API, PAGE, API]

    @patch("time.sleep")
    def test_a_page_with_a_csp_naming_turnstile(self, _sleep):
        page = MockResponse(
            200,
            {
                "content-type": "text/html",
                "content-security-policy": "frame-src https://challenges.cloudflare.com;",
            },
            "<html><body>" + "x" * 2000 + "</body></html>",
        )
        solver = MockBrowserSolver(result=_session_cookie())
        session, _ = make_sync_session(
            [_block(), page, _data()], browser_solver=solver, use_cookie_jar=True
        )
        assert session.get(API, headers={"Referer": PAGE}).status_code == 200
        assert len(solver.solve_kwargs) == 1

    @patch("time.sleep")
    def test_a_page_without_turnstile_gets_no_browser(self, _sleep):
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_sync_session(
            [_block(), _plain_page(), _block()],
            browser_solver=solver,
            use_cookie_jar=True,
        )
        with pytest.raises(RequestBlocked):
            session.get(API, headers={"Referer": PAGE})
        assert solver.solve_kwargs == []
        assert _urls(client) == [API, PAGE]

    @patch("time.sleep")
    def test_a_refused_page_gets_no_browser(self, _sleep):
        # A real ban: the page is blocked too.
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_sync_session(
            [_block(), _block()], browser_solver=solver, use_cookie_jar=True
        )
        with pytest.raises(RequestBlocked):
            session.get(API, headers={"Referer": PAGE})
        assert solver.solve_kwargs == []
        assert _urls(client) == [API, PAGE]

    @patch("time.sleep")
    def test_a_page_that_came_to_nothing_is_left_alone(self, _sleep):
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_sync_session(
            [_block(), _plain_page(), _block(), _block()],
            browser_solver=solver,
            use_cookie_jar=True,
        )
        for _ in range(2):
            with pytest.raises(RequestBlocked):
                session.get(API, headers={"Referer": PAGE})
        # The second request does not check the page again.
        assert _urls(client) == [API, PAGE, API]

    @patch("time.sleep")
    def test_the_page_is_checked_again_after_the_window(self, _sleep):
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_sync_session(
            [_block(), _plain_page(), _block(), _widget_page(), _data()],
            browser_solver=solver,
            use_cookie_jar=True,
        )
        with pytest.raises(RequestBlocked):
            session.get(API, headers={"Referer": PAGE})
        session._turnstile_page_misses[PAGE] -= 601
        assert session.get(API, headers={"Referer": PAGE}).status_code == 200
        assert _urls(client) == [API, PAGE, API, PAGE, API]

    @patch("time.sleep")
    def test_a_page_redirect_within_the_site_is_followed(self, _sleep):
        moved = MockResponse(
            301, {"location": "/map/", "content-type": "text/html"}, ""
        )
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_sync_session(
            [_block(), moved, _widget_page(), _data()],
            browser_solver=solver,
            use_cookie_jar=True,
        )
        page = "https://www.example.org/map"
        assert session.get(API, headers={"Referer": page}).status_code == 200
        assert _urls(client) == [API, page, page + "/", API]

    @pytest.mark.parametrize("cleared", [False, True])
    @patch("time.sleep")
    def test_a_block_that_survives_is_final(self, _sleep, cleared):
        solver = MockBrowserSolver(result=_session_cookie() if cleared else None)
        session, client = make_sync_session(
            [_block(), _widget_page()] + [_block()] * 4,
            browser_solver=solver,
            use_cookie_jar=True,
            max_retries=3,
            max_rotations=4,
        )
        with pytest.raises(RequestBlocked) as info:
            session.get(API, headers={"Referer": PAGE})
        assert info.value.challenge_type == "cloudflare_block"
        assert info.value.response.rotations == 0
        assert len(solver.solve_kwargs) == 1
        assert _urls(client) == ([API, PAGE, API] if cleared else [API, PAGE])
        assert PAGE in session._turnstile_page_misses

    @patch("time.sleep")
    def test_an_origin_403_that_survives_keeps_the_usual_403_path(self, _sleep):
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_sync_session(
            [_origin_403(), _widget_page(), _origin_403()],
            browser_solver=solver,
            use_cookie_jar=True,
            max_rotations=0,
        )
        resp = session.get(API, headers={"Referer": PAGE})
        assert resp.status_code == 403
        assert resp.challenge_type is None
        assert len(solver.solve_kwargs) == 1
        assert _urls(client) == [API, PAGE, API]

    @pytest.mark.parametrize(
        "headers",
        [{}, {"Referer": "https://www.google.com/"}, {"Referer": API}],
    )
    @patch("time.sleep")
    def test_no_page_to_clear_it_on(self, _sleep, headers):
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_sync_session(
            [_block()] * 3, browser_solver=solver, use_cookie_jar=True
        )
        with pytest.raises(RequestBlocked):
            session.get(API, headers=headers)
        assert solver.solve_kwargs == []
        assert len(client.request_log) == 1

    @patch("time.sleep")
    def test_an_origin_403_without_cloudflare_is_not_one(self, _sleep):
        plain = MockResponse(
            403, {"server": "nginx", "content-type": "text/html"}, "<h1>Forbidden</h1>"
        )
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_sync_session(
            [plain], browser_solver=solver, use_cookie_jar=True, max_rotations=0
        )
        resp = session.get(API, headers={"Referer": PAGE})
        assert resp.status_code == 403
        assert solver.solve_kwargs == []
        assert _urls(client) == [API]

    @patch("time.sleep")
    def test_without_rotations_the_cleared_answer_is_returned(self, _sleep):
        solver = MockBrowserSolver(result=_session_cookie())
        session, _ = make_sync_session(
            [_block(), _widget_page(), _data()],
            browser_solver=solver,
            use_cookie_jar=True,
            max_rotations=0,
        )
        resp = session.get(API, headers={"Referer": PAGE})
        assert resp.status_code == 200
        assert resp.challenge_type is None

    @patch("time.sleep")
    def test_without_rotations_a_surviving_block_is_returned_named(self, _sleep):
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_sync_session(
            [_block(), _widget_page(), _block()],
            browser_solver=solver,
            use_cookie_jar=True,
            max_rotations=0,
        )
        resp = session.get(API, headers={"Referer": PAGE})
        assert resp.status_code == 403
        assert resp.challenge_type == "cloudflare_block"
        assert len(client.request_log) == 3


class TestPageCheckIsAnOrdinaryRequest:
    """The page check goes to the site like any request the session sends."""

    @patch("time.sleep")
    def test_a_pinned_host_is_canonicalized(self, _sleep):
        # wreq matches resolve= pins against the URL host verbatim; a
        # mixed-case page host would miss the pin and go to real DNS.
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_sync_session(
            [_block(), _widget_page(), _data()],
            browser_solver=solver,
            use_cookie_jar=True,
            resolve={"www.example.org": ["93.184.216.34"]},
        )
        page = "https://WWW.Example.org/map"
        assert session.get(API, headers={"Referer": page}).status_code == 200
        assert _urls(client)[1] == "https://www.example.org/map"

    @patch("time.sleep")
    def test_it_is_paced_and_recorded(self, _sleep):
        class Limiter:
            def __init__(self):
                self.calls = []

            def wait_sync(self, domain, max_wait=None):
                self.calls.append(("wait", domain))
                return 0.0

            def record(self, domain):
                self.calls.append(("record", domain))

        limiter = Limiter()
        solver = MockBrowserSolver(result=_session_cookie())
        session, _ = make_sync_session(
            [_block(), _widget_page(), _data()],
            browser_solver=solver,
            use_cookie_jar=True,
            rate_limiter=limiter,
        )
        session.get(API, headers={"Referer": PAGE})
        # API, then the page, then the retry: each waited for and recorded.
        assert limiter.calls.count(("wait", "www.example.org")) == 3
        assert limiter.calls.count(("record", "www.example.org")) == 3

    @patch("time.sleep")
    def test_its_cookie_scopes_are_recorded(self, _sleep):
        moved = MockResponse(
            301, {"location": "/map", "content-type": "text/html"}, ""
        )
        solver = MockBrowserSolver(result=_session_cookie())
        session, _ = make_sync_session(
            [_block(), moved, _widget_page(), _data()],
            browser_solver=solver,
            use_cookie_jar=True,
        )
        with patch.object(
            session,
            "_record_response_cookie_scopes",
            wraps=session._record_response_cookie_scopes,
        ) as recorded:
            session.get(API, headers={"Referer": "https://www.example.org/start"})
        urls = [call.args[0] for call in recorded.call_args_list]
        assert urls == [
            API,
            "https://www.example.org/start",
            "https://www.example.org/map",
            API,
        ]

    @pytest.mark.asyncio
    async def test_async_too(self):
        class Limiter:
            def __init__(self):
                self.calls = []

            async def wait_async(self, domain, max_wait=None):
                self.calls.append(("wait", domain))
                return 0.0

            def record(self, domain):
                self.calls.append(("record", domain))

        limiter = Limiter()
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_async_session(
            [_block(), _widget_page(), _data()],
            browser_solver=solver,
            use_cookie_jar=True,
            rate_limiter=limiter,
            resolve={"www.example.org": ["93.184.216.34"]},
        )
        with patch("asyncio.sleep"):
            resp = await session.get(
                API, headers={"Referer": "https://WWW.example.org/map"}
            )
        assert resp.status_code == 200
        assert _urls(client)[1] == "https://www.example.org/map"
        assert limiter.calls.count(("record", "www.example.org")) == 3


class TestPageCheckStaysInsideTheCallersGuards:
    """The page check and the solve are requests the caller did not make, to a
    host its Referer named: they keep to the refused URL's site, scheme and
    port, to resolve= pins, and to follow_redirects."""

    def _session(self, responses=(), **kwargs):
        return make_sync_session(
            list(responses),
            browser_solver=MockBrowserSolver(result=_session_cookie()),
            use_cookie_jar=True,
            **kwargs,
        )

    @pytest.mark.parametrize(
        "page,allowed",
        [
            ("https://www.example.org/map", True),
            ("https://map.example.org/", True),
            ("https://www.example.org:443/map", True),
            ("http://www.example.org/map", False),
            ("https://www.example.org:8443/map", False),
            ("https://internal.example.org:8080/", False),
            ("https://www.example.net/map", False),
            ("ftp://www.example.org/map", False),
            ("https://www.example.org:notaport/", False),
        ],
    )
    def test_site_scheme_and_port(self, page, allowed):
        session, _ = self._session()
        assert (session._turnstile_page_target(page, API) is not None) is allowed

    @pytest.mark.parametrize(
        "page",
        [
            # urlsplit reads www.example.org; a WHATWG parser 127.0.0.1:8080.
            "https://127.0.0.1:8080\\@www.example.org/map",
            "https://www.example.org\\@127.0.0.1/",
            "https://user:pw@www.example.org/map",
            "https://www.example.org@127.0.0.1/",
            "https://www.example.org:0/map",
            "https://www.exa mple.org/map",
            "https://www.example.org/ma\tp",
            "https://www.example.org/\x00",
            "https://www.exämple.org/map",
            "https://[::1]/map",
            "https://www%2eexample.org/map",
            "https://-www.example.org/map",
        ],
    )
    def test_anything_a_parser_could_read_two_ways(self, page):
        session, _ = self._session()
        assert session._turnstile_page_target(page, API) is None

    def test_what_is_sent_is_what_was_checked(self):
        session, _ = self._session()
        target = session._turnstile_page_target(
            "https://WWW.Example.ORG.:443/map?x=1#frag", API
        )
        assert target == "https://www.example.org/map?x=1"
        assert session._turnstile_page_target(
            "https://www.example.org:8443/map", "https://www.example.org:8443/api"
        ) == "https://www.example.org:8443/map"
        assert session._turnstile_page_target("https://www.example.org", API) == (
            "https://www.example.org/"
        )

    def test_with_resolve_only_a_pinned_host(self):
        session, _ = self._session(resolve={"www.example.org": ["93.184.216.34"]})
        assert session._turnstile_page_target("https://WWW.example.org/map", API)
        internal = "https://internal.example.org/"
        assert session._turnstile_page_target(internal, API) is None
        assert (
            session._turnstile_recovery_page(
                API, {"Referer": "https://internal.example.org/admin"}
            )
            is None
        )

    @pytest.mark.parametrize(
        "referer",
        [
            # urlsplit strips tabs and newlines; the caller's own string is
            # what is checked.
            "https://www.example.org/ma\tp",
            "https://www.example.org/ma\np",
            # Malformed: must decline, not raise out of the request loop.
            "https://[bad/map",
            "https://www.example.org:99999/map",
        ],
    )
    def test_the_callers_own_string_is_checked(self, referer):
        session, _ = self._session()
        assert session._turnstile_recovery_page(API, {"Referer": referer}) is None

    @patch("time.sleep")
    def test_a_referer_urlsplit_would_clean_is_never_contacted(self, _sleep):
        session, client = self._session([_block()])
        with pytest.raises(RequestBlocked):
            session.get(API, headers={"Referer": "https://www.example.org/ma\tp"})
        assert _urls(client) == [API]

    @pytest.mark.parametrize(
        "referer",
        [
            "https://www.example.org:443/api/items/42",
            "https://WWW.EXAMPLE.ORG./api/items/42",
            "https://www.example.org/api/items/42#top",
        ],
    )
    def test_never_the_refused_url_however_spelled(self, referer):
        session, _ = self._session()
        assert session._turnstile_recovery_page(API, {"Referer": referer}) is None

    def test_never_the_refused_url_when_it_is_the_odd_spelling(self):
        session, _ = self._session()
        refused = "https://WWW.Example.org:443/api/items/42#x"
        assert session._turnstile_recovery_page(refused, {"Referer": API}) is None

    def test_the_first_http_candidate_decides(self):
        session, _ = self._session()
        headers = {"Referer": "https://www.google.com/", "Origin": PAGE}
        assert session._turnstile_recovery_page(API, headers) is None
        headers = {"Referer": "about:blank", "Origin": "https://www.example.org"}
        assert (
            session._turnstile_recovery_page(API, headers)
            == "https://www.example.org/"
        )

    def test_the_budget_is_read_after_the_pacing_wait(self):
        import time as _time

        class SlowLimiter:
            def wait_sync(self, domain, max_wait=None):
                _time.sleep(0.05)
                return 0.05

            def record(self, domain):
                pass

        session, client = self._session([_widget_page()], rate_limiter=SlowLimiter())
        assert not session._page_runs_turnstile(PAGE, API, _time.monotonic() + 0.01)
        assert client.request_log == []

    @patch("time.sleep")
    def test_an_unpinned_referer_host_is_never_contacted(self, _sleep):
        session, client = self._session(
            [_block()], resolve={"www.example.org": ["93.184.216.34"]}
        )
        with pytest.raises(RequestBlocked):
            session.get(API, headers={"Referer": "https://internal.example.org/"})
        assert _urls(client) == [API]

    @patch("time.sleep")
    def test_no_redirect_when_the_session_follows_none(self, _sleep):
        moved = MockResponse(
            301, {"location": "/map/", "content-type": "text/html"}, ""
        )
        session, client = self._session(
            [_block(), moved], follow_redirects=False
        )
        with pytest.raises(RequestBlocked):
            session.get(API, headers={"Referer": PAGE})
        assert _urls(client) == [API, PAGE]
        assert session._browser_solver.solve_kwargs == []

    @patch("time.sleep")
    def test_no_redirect_to_an_unpinned_host(self, _sleep):
        moved = MockResponse(
            302,
            {"location": "https://internal.example.org/", "content-type": "text/html"},
            "",
        )
        session, client = self._session(
            [_block(), moved], resolve={"www.example.org": ["93.184.216.34"]}
        )
        with pytest.raises(RequestBlocked):
            session.get(API, headers={"Referer": PAGE})
        assert _urls(client) == [API, PAGE]

    @patch("time.sleep")
    def test_no_redirect_to_another_port(self, _sleep):
        moved = MockResponse(
            302,
            {"location": "https://www.example.org:8443/", "content-type": "text/html"},
            "",
        )
        session, client = self._session([_block(), moved])
        with pytest.raises(RequestBlocked):
            session.get(API, headers={"Referer": PAGE})
        assert _urls(client) == [API, PAGE]

    @patch("time.sleep")
    def test_no_redirect_through_a_backslash(self, _sleep):
        moved = MockResponse(
            302,
            {
                "location": "https://127.0.0.1:8080\\@www.example.org/",
                "content-type": "text/html",
            },
            "",
        )
        session, client = self._session([_block(), moved])
        with pytest.raises(RequestBlocked):
            session.get(API, headers={"Referer": PAGE})
        assert _urls(client) == [API, PAGE]

    @patch("time.sleep")
    def test_no_redirect_through_a_protocol_relative_backslash(self, _sleep):
        # A browser resolves "\\\\host/x" against https: as //host/x; urljoin
        # makes it a path on the page's own host. Neither reading is taken.
        moved = MockResponse(
            302,
            {"location": "\\\\internal.example.org/x", "content-type": "text/html"},
            "",
        )
        session, client = self._session([_block(), moved, _widget_page()])
        with pytest.raises(RequestBlocked):
            session.get(API, headers={"Referer": PAGE})
        assert _urls(client) == [API, PAGE]

    @patch("time.sleep")
    def test_a_backslash_referer_is_never_contacted(self, _sleep):
        session, client = self._session([_block()])
        with pytest.raises(RequestBlocked):
            session.get(
                API, headers={"Referer": "https://127.0.0.1:8080\\@www.example.org/"}
            )
        assert _urls(client) == [API]
        assert session._browser_solver.solve_kwargs == []

    @patch("time.sleep")
    def test_redirects_stop_at_max_redirects(self, _sleep):
        hop = MockResponse(302, {"location": "/next", "content-type": "text/html"}, "")
        session, client = self._session([_block(), hop, hop], max_redirects=1)
        with pytest.raises(RequestBlocked):
            session.get(API, headers={"Referer": PAGE})
        assert _urls(client) == [API, PAGE, "https://www.example.org/next"]


class TestAsyncFlow:
    @pytest.mark.asyncio
    async def test_cleared_on_the_page_then_retried(self):
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_async_session(
            [_block(), _widget_page(), _data()],
            browser_solver=solver,
            use_cookie_jar=True,
        )
        with patch("asyncio.sleep"):
            resp = await session.get(API, headers={"Referer": PAGE})
        assert resp.status_code == 200
        assert solver.solve_kwargs[0]["challenge_type"] == "cloudflare_block"
        assert solver.solve_kwargs[0]["embedder"] == PAGE
        assert _urls(client) == [API, PAGE, API]

    @pytest.mark.asyncio
    async def test_the_origins_own_403_is_cleared_the_same_way(self):
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_async_session(
            [_origin_403(), _widget_page(), _data()],
            browser_solver=solver,
            use_cookie_jar=True,
        )
        with patch("asyncio.sleep"):
            resp = await session.get(API, headers={"Referer": PAGE})
        assert resp.status_code == 200
        assert _urls(client) == [API, PAGE, API]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("cleared", [False, True])
    async def test_a_block_that_survives_is_final(self, cleared):
        solver = MockBrowserSolver(result=_session_cookie() if cleared else None)
        session, client = make_async_session(
            [_block(), _widget_page()] + [_block()] * 4,
            browser_solver=solver,
            use_cookie_jar=True,
            max_rotations=4,
        )
        with patch("asyncio.sleep"), pytest.raises(RequestBlocked):
            await session.get(API, headers={"Referer": PAGE})
        assert len(solver.solve_kwargs) == 1
        assert _urls(client) == ([API, PAGE, API] if cleared else [API, PAGE])

    @pytest.mark.asyncio
    async def test_a_page_without_turnstile_gets_no_browser(self):
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_async_session(
            [_block(), _plain_page()], browser_solver=solver, use_cookie_jar=True
        )
        with patch("asyncio.sleep"), pytest.raises(RequestBlocked):
            await session.get(API, headers={"Referer": PAGE})
        assert solver.solve_kwargs == []
        assert _urls(client) == [API, PAGE]

    @pytest.mark.asyncio
    async def test_no_page_to_clear_it_on(self):
        solver = MockBrowserSolver(result=_session_cookie())
        session, client = make_async_session(
            [_block()] * 3, browser_solver=solver, use_cookie_jar=True
        )
        with patch("asyncio.sleep"), pytest.raises(RequestBlocked):
            await session.get(API)
        assert solver.solve_kwargs == []
        assert len(client.request_log) == 1


class TestClassification:
    def test_the_origins_403_is_not_a_js_challenge(self):
        """Werkzeug's stock 403 plus Cloudflare's two injects (2026-11-24)."""
        headers = {
            "server": "cloudflare",
            "cf-ray": "a5f9273a780e92c6-YYZ",
            "content-type": "text/html; charset=utf-8",
        }
        assert detect_challenge(403, headers, ORIGIN_403_BODY) is None

    @pytest.mark.parametrize(
        "body,own",
        [
            ("<html>no scripts</html>", False),
            ("<script>startChallenge()</script>", True),
            (
                '<script defer src="https://static.cloudflareinsights.com/'
                'beacon.min.js/v1" data-cf-beacon="{}"></script>',
                False,
            ),
            (
                '<script data-cfasync="false" src="/cdn-cgi/scripts/5c5dd728/'
                'cloudflare-static/email-decode.min.js"></script>',
                False,
            ),
            (
                "<script>window.__cf$cv$params={r:'1'};</script>"
                "<script>startChallenge()</script>",
                True,
            ),
            ("<script>unclosed(", True),
        ],
    )
    def test_has_page_script(self, body, own):
        assert has_page_script(body.lower()) is own

    def test_a_js_challenge_with_the_beacon_is_still_one(self):
        body = ORIGIN_403_BODY.replace(
            "</p>", "</p><script>window.runChallenge(token)</script>"
        )
        assert detect_challenge(403, {}, body) is ChallengeType.GENERIC_JS

    @pytest.mark.parametrize(
        "status,headers,body,runs",
        [
            (200, {}, '<script>C={sitekey:"0x4AAAAAAAexampleKey00"}</script>', True),
            (200, {}, '<div class="cf-turnstile" data-sitekey="x"></div>', True),
            (
                200,
                {},
                '<script src="https://challenges.cloudflare.com/turnstile/v0/'
                'api.js"></script>',
                True,
            ),
            (
                200,
                {"Content-Security-Policy": "frame-src https://challenges.cloudflare.com"},
                "",
                True,
            ),
            (200, {}, "<html>nothing</html>", False),
            # Cloudflare's own beacon path is not Turnstile.
            (200, {}, "/cdn-cgi/challenge-platform/scripts/jsd/main.js", False),
            (403, {}, '<div class="cf-turnstile"></div>', False),
            (200, {}, '<div data-sitekey="1x00000000000000000000AA"></div>', False),
        ],
    )
    def test_page_runs_turnstile(self, status, headers, body, runs):
        assert page_runs_turnstile(status, headers, body) is runs


# ---------------------------------------------------------------------------
# wait_for_page_turnstile, on a scripted page and a fake clock
# ---------------------------------------------------------------------------


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


class _Box:
    def __init__(self, page):
        self._page = page

    def bounding_box(self):
        return self._page.widget_box


class _Locator:
    def __init__(self, page):
        self._page = page

    def click(self, timeout=None):
        self._page.clicks += 1
        if self._page.click_hangs:
            # A widget that never takes the click waits out the timeout.
            self._page.advance(timeout / 1000)


class _Frame:
    def __init__(self, page):
        self._page = page
        self.url = "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/turnstile/if/ov2/av0/rcv/x"

    def frame_element(self):
        return _Box(self._page)

    def locator(self, selector):
        return _Locator(self._page)


class _Context:
    def __init__(self, page):
        self._page = page

    def cookies(self):
        return [dict(c) for c in self._page.jar]


class _Page:
    """A page whose state follows a script of ``(at_seconds, change)``."""

    def __init__(self, clock, script):
        self.url = PAGE
        self.clock = clock
        self.start = clock.now
        self.script = sorted(script, key=lambda step: step[0])
        self.ready = "interactive"
        self.widget = False
        self.widget_box = None
        self.field = 0
        self.jar = [
            {"name": "_ga", "value": "1", "domain": ".example.org", "path": "/"},
        ]
        self.clicks = 0
        self.click_hangs = False
        self.context = _Context(self)

    def advance(self, seconds):
        self.clock.now += seconds
        while self.script and self.script[0][0] <= self.clock.now - self.start:
            self.script.pop(0)[1](self)

    @property
    def frames(self):
        return [_Frame(self)] if self.widget else []

    def evaluate(self, js):
        if "readyState" in js:
            return self.ready
        return self.field


class _Solver:
    def _start_browse(self, page, x, y):
        return None

    def _replay_browse_chunk(self, page, state, duration):
        page.advance(duration)


def _set(**changes):
    def apply(page):
        for key, value in changes.items():
            setattr(page, key, value)

    return apply


def _cookie(name, value, domain="www.example.org", http_only=False):
    def apply(page):
        page.jar = [c for c in page.jar if c["name"] != name] + [
            {
                "name": name,
                "value": value,
                "domain": domain,
                "path": "/",
                "httpOnly": http_only,
            }
        ]

    return apply


def _run(script, timeout_ms=60_000, documents=None):
    clock = _Clock()
    page = _Page(clock, script)
    with patch.object(_cloudflare.time, "monotonic", clock.monotonic), patch.object(
        _cloudflare, "idle", page.advance
    ):
        result = _cloudflare.wait_for_page_turnstile(
            _Solver(), page, timeout_ms, documents=documents
        )
    return result, clock.now - page.start, page


class TestPageTurnstileWait:
    def test_widget_then_the_sites_cookie(self):
        """No readable token field; the site's ``session`` follows."""
        result, elapsed, _ = _run([
            (3.0, _set(ready="complete")),
            (10.0, _set(widget=True)),
            (12.0, _cookie("session", "s3ss10n")),
        ])
        assert result is True
        assert 12.0 <= elapsed < 15.0

    def test_the_grace_runs_from_load(self):
        # The widget came up 7.4s after DOMContentLoaded live; a page that
        # is still loading is not out of time.
        result, elapsed, _ = _run([
            (6.0, _set(ready="complete")),
            (13.0, _set(widget=True)),
            (14.0, _cookie("session", "s3ss10n")),
        ])
        assert result is True
        assert elapsed >= 14.0

    def test_no_widget(self):
        result, elapsed, _ = _run([(2.0, _set(ready="complete"))])
        assert result is False
        assert 10.0 <= elapsed < 12.0

    def test_a_page_that_never_loads_still_gives_up(self):
        result, elapsed, _ = _run([])
        expected = (
            _cloudflare._PAGE_LOAD_CAP_SECONDS
            + _cloudflare._PAGE_WIDGET_GRACE_SECONDS
        )
        assert result is False
        assert expected <= elapsed < expected + 2.0

    def test_a_refused_page_has_nothing_to_solve(self):
        result, elapsed, _ = _run(
            [(1.0, _set(ready="complete", widget=True))],
            documents=[(PAGE, 403, None)],
        )
        assert result is False
        assert elapsed == 0.0

    def test_cloudflares_own_cookie_is_not_the_pages_answer(self):
        # Pre-clearance sets cf_clearance before the page posts its token.
        result, _, _ = _run(
            [
                (1.0, _set(ready="complete", widget=True)),
                (2.0, _cookie("cf_clearance", "x", ".example.org")),
            ],
            timeout_ms=20_000,
        )
        assert result is False

    def test_another_hosts_cookie_is_not_the_pages_answer(self):
        result, _, _ = _run(
            [
                (1.0, _set(ready="complete", widget=True)),
                (2.0, _cookie("session", "x", "other.example.org")),
            ],
            timeout_ms=20_000,
        )
        assert result is False

    def test_with_a_token_field_only_a_cookie_after_the_token_counts(self):
        _, elapsed, page = _run([
            (1.0, _set(ready="complete", widget=True, field=1)),
            (2.0, _cookie("_hjSession", "a", ".example.org")),
            (4.0, _set(field=2)),
            (5.0, _cookie("session", "s3ss10n")),
        ])
        assert 5.0 <= elapsed < 7.0
        assert any(c["name"] == "session" for c in page.jar)

    def test_a_token_and_no_cookie_of_the_pages_own(self):
        # A zone keyed on Turnstile's cf_clearance needs nothing more.
        result, elapsed, _ = _run([
            (1.0, _set(ready="complete", widget=True, field=1)),
            (3.0, _set(field=2)),
            (3.5, _cookie("cf_clearance", "x", ".example.org")),
        ])
        settle = _cloudflare._PAGE_TOKEN_SETTLE_SECONDS
        assert result is True
        assert 3.0 + settle <= elapsed < 3.0 + settle + 2.0

    def test_an_interactive_widget_is_clicked(self):
        result, _, page = _run([
            (1.0, _set(ready="complete", widget=True)),
            (6.0, _set(widget_box={"x": 10, "y": 10, "width": 300, "height": 65})),
            (9.0, _cookie("session", "s3ss10n")),
        ])
        assert result is True
        assert page.clicks >= 1

    def test_an_invisible_widget_is_not_clicked(self):
        result, _, page = _run([
            (1.0, _set(ready="complete", widget=True)),
            (9.0, _cookie("session", "s3ss10n")),
        ])
        assert result is True
        assert page.clicks == 0

    def test_the_deadline(self):
        result, elapsed, _ = _run(
            [(1.0, _set(ready="complete", widget=True, field=1))],
            timeout_ms=15_000,
        )
        assert result is False
        assert 15.0 <= elapsed < 16.0

    def test_a_cookie_in_the_interval_the_widget_appeared_in(self):
        # Both land inside one poll interval; the jar measured from must be
        # the one from before the widget, or the cookie is never seen.
        result, elapsed, _ = _run(
            [
                (1.0, _set(ready="complete")),
                (3.1, _set(widget=True)),
                (3.2, _cookie("session", "s3ss10n")),
            ],
            timeout_ms=20_000,
        )
        assert result is True
        assert elapsed < 6.0

    def test_a_server_cookie_from_a_widget_never_seen(self):
        # A widget that passes at once can be removed before a poll sees it;
        # an HttpOnly cookie only a response can set is the answer anyway.
        result, elapsed, _ = _run(
            [
                (1.0, _set(ready="complete")),
                (2.1, _set(widget=True)),
                (2.2, _cookie("session", "s3ss10n", http_only=True)),
                (2.3, _set(widget=False)),
            ],
            timeout_ms=20_000,
        )
        assert result is True
        assert elapsed < 4.0

    def test_a_server_cookie_counts_even_with_an_empty_token_field(self):
        result, _, _ = _run([
            (1.0, _set(ready="complete", widget=True, field=1)),
            (3.0, _cookie("session", "s3ss10n", http_only=True)),
        ])
        assert result is True

    def test_a_click_that_hangs_stays_inside_the_budget(self):
        result, elapsed, _ = _run(
            [
                (
                    1.0,
                    _set(
                        ready="complete",
                        widget=True,
                        click_hangs=True,
                        widget_box={"x": 0, "y": 0, "width": 300, "height": 65},
                    ),
                ),
            ],
            timeout_ms=2_000,
        )
        assert result is False
        assert elapsed <= 2.0 + 1e-6

    def test_the_settle_stays_inside_the_budget(self):
        result, elapsed, _ = _run(
            [
                (1.0, _set(ready="complete", widget=True)),
                (9.4, _cookie("session", "s3ss10n")),
            ],
            timeout_ms=10_000,
        )
        assert result is True
        assert elapsed <= 10.0 + 1e-6
