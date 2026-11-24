"""Caller-supplied page URLs that do not parse.

A ``Referer`` or ``Origin`` header, ``embed_origin``, ``solve_origin``, or a
reCAPTCHA ``origin``/``referer`` can be a string ``urllib.parse`` refuses: an
unclosed ``[`` host, a port that is not a number or is out of range. A
malformed header used to make every request raise ``ValueError`` before
anything was sent, even to a URL that answers 200 (fetchaller, 2026-11-24).
"""

import logging
from unittest.mock import patch

import pytest

from tests.conftest import MockResponse, make_async_session, make_sync_session
from tests.test_browser import MockBrowserSolver
from tests.test_kasada_api import (
    API as KASADA_API,
)
from tests.test_kasada_api import (
    REFUSAL_HEADERS as KASADA_REFUSAL,
)
from tests.test_kasada_api import (
    _signed_result,
)
from wafer import AsyncSession, SyncSession, TokenMintFailed
from wafer import _recaptcha_v3 as rc

API = "https://api.example.com/v1/items"
MALFORMED = [
    "http://[bad/x",  # unclosed IPv6 bracket
    "https://[::1/x",
    "https://www.example.com:99999/",  # port out of range
    "https://www.example.com:abc/",  # port not a number
]


class TestTheRequestIsSent:
    @pytest.mark.parametrize("bad", MALFORMED)
    @patch("time.sleep")
    def test_sync(self, _sleep, bad, caplog):
        session, mock = make_sync_session([MockResponse(200, body="ok")])
        with caplog.at_level(logging.WARNING, logger="wafer"):
            resp = session.get(API, headers={"Referer": bad})
        assert resp.status_code == 200
        headers = mock.last_kwargs["headers"]
        # The caller's header goes as given; the relation is an opaque
        # origin's, as for a Referer that names no host.
        assert headers["Referer"] == bad
        assert headers["Sec-Fetch-Site"] == "cross-site"
        assert "is not a URL" in caplog.text

    @pytest.mark.parametrize("bad", MALFORMED)
    @pytest.mark.asyncio
    async def test_async(self, bad):
        session, mock = make_async_session([MockResponse(200, body="ok")])
        with patch("asyncio.sleep"):
            resp = await session.get(API, headers={"Referer": bad})
        assert resp.status_code == 200
        assert mock.last_kwargs["headers"]["Sec-Fetch-Site"] == "cross-site"

    @pytest.mark.parametrize("bad", MALFORMED)
    def test_same_as_a_referer_with_no_host(self, bad):
        session, _ = make_sync_session([])
        unparseable = session._build_headers(API, {"Referer": bad})
        hostless = session._build_headers(API, {"Referer": "not a url"})
        assert unparseable["Sec-Fetch-Site"] == hostless["Sec-Fetch-Site"]

    @pytest.mark.parametrize("bad", MALFORMED)
    def test_a_malformed_origin_header_is_sent_too(self, bad):
        session, _ = make_sync_session([])
        headers = session._build_headers(API, {"Origin": bad}, method="POST")
        assert headers["Origin"] == bad


class TestCallerPage:
    """The page an API refusal is solved on (Kasada, Akamai) is the first
    candidate that names a usable page; a malformed one names none."""

    def _session(self):
        session, _ = make_sync_session([], browser_solver=MockBrowserSolver())
        return session

    @pytest.mark.parametrize("bad", MALFORMED)
    def test_the_next_candidate_is_used(self, bad):
        page = self._session()._caller_page(
            {"Referer": bad, "Origin": "https://www.example.com"}
        )
        assert page == "https://www.example.com/"

    @pytest.mark.parametrize("bad", MALFORMED)
    def test_no_usable_candidate(self, bad):
        assert self._session()._caller_page({"Referer": bad, "Origin": bad}) is None

    @pytest.mark.parametrize("bad", MALFORMED)
    @patch("time.sleep")
    def test_a_kasada_refusal_is_solved_on_the_origin_page(self, _sleep, bad):
        solver = MockBrowserSolver(result=_signed_result())
        session, _ = make_sync_session(
            [MockResponse(429, dict(KASADA_REFUSAL), "")], browser_solver=solver
        )
        resp = session.post(
            KASADA_API,
            json={"query": "laptop"},
            headers={"Origin": "https://www.example.com", "Referer": bad},
        )
        assert resp.status_code == 200
        assert solver.solve_kwargs[0]["embedder"] == "https://www.example.com/"


class TestImpervaEmbedder:
    """An Imperva API host's solve page comes from the caller's Referer or
    Origin; a malformed one is passed over like a non-HTTP one."""

    @pytest.mark.parametrize("bad", ["http://[bad/x", "https://[::1/x"])
    def test_the_origin_header_is_used(self, bad):
        from wafer.browser._imperva import imperva_embedder

        page = imperva_embedder(
            "https://api.example.com/v1/items",
            {"Referer": bad, "Origin": "https://app.example.com"},
        )
        assert page == "https://app.example.com/"

    @pytest.mark.parametrize(
        "bad", ["https://www.example.com:99999/", "https://www.example.com:abc/"]
    )
    def test_a_bad_port_is_dropped_with_every_port(self, bad):
        # The embedder is built from scheme and host only, so the host of a
        # Referer whose port is unusable still names the page.
        from wafer.browser._imperva import imperva_embedder

        page = imperva_embedder(
            "https://api.example.com/v1/items",
            {"Referer": bad, "Origin": "https://app.example.com"},
        )
        assert page == "https://www.example.com/"

    @pytest.mark.parametrize("bad", MALFORMED)
    def test_falls_back_to_the_www_heuristic(self, bad):
        from wafer.browser._imperva import imperva_embedder

        page = imperva_embedder("https://api.example.com/v1/items", {"Referer": bad})
        assert page == "https://www.example.com/"


class TestSessionSettings:
    """embed_origin and solve_origin are refused when the session is built,
    not on every request."""

    @pytest.mark.parametrize("bad", MALFORMED)
    @pytest.mark.parametrize("name", ["embed_origin", "solve_origin"])
    @pytest.mark.parametrize("cls", [SyncSession, AsyncSession])
    def test_a_malformed_value_is_refused(self, cls, name, bad):
        with pytest.raises(ValueError, match=f"{name}=.* is not a URL"):
            cls(**{name: bad})

    @pytest.mark.parametrize(
        "bad", ["www.example.com/", "about:blank", "null", "https:///map"]
    )
    def test_solve_origin_must_be_a_page_url(self, bad):
        with pytest.raises(ValueError, match="solve_origin=.* is not a page URL"):
            SyncSession(solve_origin=bad)

    def test_an_opaque_embed_origin_is_still_allowed(self):
        # Chrome sends Origin: null from an opaque origin (a sandboxed frame).
        with SyncSession(embed_origin="null") as session:
            headers = session._build_headers(API, method="POST")
        assert headers["Origin"] == "null"
        assert headers["Sec-Fetch-Site"] == "cross-site"

    def test_page_urls_are_accepted(self):
        with SyncSession(
            embed_origin="https://www.example.com:8443",
            solve_origin="https://www.example.com/map",
        ) as session:
            assert session._solve_origin == "https://www.example.com/map"


class TestRecaptchaOrigin:
    """mint_recaptcha_v3 reports an unusable origin or referer as
    TokenMintFailed, as it already did for one with no host."""

    @pytest.mark.parametrize("bad", MALFORMED)
    def test_referer(self, bad):
        with pytest.raises(TokenMintFailed):
            rc._prepare("sitekey", "submit", None, bad, False, None)

    @pytest.mark.parametrize("bad", MALFORMED)
    def test_origin(self, bad):
        with pytest.raises(TokenMintFailed):
            rc._prepare("sitekey", "submit", bad, None, False, None)

    def test_an_explicit_port_still_counts(self):
        assert rc.compute_co("https://www.example.com:8443") != rc.compute_co(
            "https://www.example.com"
        )


class TestSolveOriginAndEmbedOriginLimits:
    """The constructor checks match what can actually be used."""

    def test_an_empty_solve_origin_is_unset(self):
        with SyncSession(solve_origin="") as session:
            assert not session._solve_origin

    @pytest.mark.parametrize(
        "bad",
        [
            "https://www.example.com:0/",
            "https://user:pw@www.example.com/",
            " https://www.example.com/",
            "https://www.example.com/a b",
        ],
    )
    def test_solve_origin_the_browser_would_refuse(self, bad):
        # BrowserSolver refuses these before every navigation, so each solve
        # of the session would have failed.
        with pytest.raises(ValueError, match="solve_origin=.* is not a page URL"):
            SyncSession(solve_origin=bad)

    @pytest.mark.parametrize(
        "bad",
        [
            "https://www.example.com\r\nX-Injected: 1",
            "\x00https://www.example.com",
            "https://www.example.com\x7f",
            "https://\ud800.example.com",
        ],
    )
    def test_an_embed_origin_no_header_can_carry(self, bad):
        # Refused either way: as no URL, or as no header value.
        refused = r"embed_origin=.*(not a URL|cannot be sent)"
        with pytest.raises(ValueError, match=refused):
            SyncSession(embed_origin=bad)

    def test_resolve_is_refused_before_a_shared_solver_is_touched(self):
        calls = []

        class Solver:
            proxy_server = None

            def configure_proxy(self, proxy):
                calls.append(proxy)

        with pytest.raises(ValueError, match="cannot be combined with a proxy"):
            SyncSession(
                browser_solver=Solver(),
                proxy="http://127.0.0.1:9",
                resolve={"www.example.com": ["93.184.216.34"]},
            )
        assert calls == []


class TestCallerPageTheBrowserWouldRefuse:
    @pytest.mark.parametrize(
        "referer",
        [
            "https://www.example.com/s?keyword=gaming laptop",  # raw space
            "https://user:pw@www.example.com/s",
            "https://www.example.com:0/s",
        ],
    )
    def test_the_origin_is_used_instead(self, referer):
        session, _ = make_sync_session([], browser_solver=MockBrowserSolver())
        page = session._caller_page(
            {"Referer": referer, "Origin": "https://www.example.com"}
        )
        assert page == "https://www.example.com/"


class TestUnparseableLocation:
    @pytest.mark.parametrize(
        "location", ["http://[bad/x", "https://www.example.com:99999/x"]
    )
    @patch("time.sleep")
    def test_following_it_is_a_connection_failure(self, _sleep, location):
        from wafer import ConnectionFailed

        session, mock = make_sync_session(
            [MockResponse(302, {"location": location}, "")]
        )
        with pytest.raises(ConnectionFailed, match="redirect Location is not a URL"):
            session.get(API)
        assert mock.request_count == 1

    @pytest.mark.parametrize(
        "location", ["http://[bad/x", "https://www.example.com:99999/x"]
    )
    @pytest.mark.asyncio
    async def test_following_it_is_a_connection_failure_async(self, location):
        from wafer import ConnectionFailed

        session, mock = make_async_session(
            [MockResponse(302, {"location": location}, "")]
        )
        with patch("asyncio.sleep"), pytest.raises(ConnectionFailed):
            await session.get(API)
        assert mock.request_count == 1

    @patch("time.sleep")
    def test_without_following_the_3xx_is_returned(self, _sleep):
        session, _ = make_sync_session(
            [MockResponse(302, {"location": "http://[bad/x"}, "")],
            follow_redirects=False,
        )
        resp = session.get(API)
        assert resp.status_code == 302
        assert resp.headers["location"] == "http://[bad/x"

    def test_helpers_read_it_as_nothing(self):
        from wafer._base import BaseSession
        from wafer._challenge import is_radware_challenge_redirect

        assert is_radware_challenge_redirect("http://[bad/x") is False
        assert BaseSession._hint_origin("https://www.example.com:99999/") is None


class TestAmazonCaptchaLinks:
    def test_an_unparseable_link_is_skipped_for_the_form(self):
        from wafer._solvers import parse_amazon_captcha

        page = (
            '<a href="http://[bad/x">Continue shopping</a>'
            '<form method="get" action="/errors/validateCaptcha">'
            '<input type="hidden" name="amzn" value="abc"></form>'
        )
        target = parse_amazon_captcha(page, "https://www.amazon.com/dp/B000")
        assert target["url"] == "https://www.amazon.com/errors/validateCaptcha"


class TestRecaptchaReferer:
    @pytest.mark.parametrize("bad", MALFORMED)
    def test_checked_when_the_origin_is_given(self, bad):
        with pytest.raises(TokenMintFailed):
            rc._prepare(
                "sitekey", "submit", "https://www.example.com", bad, False, None
            )

    def test_an_origin_that_cannot_be_encoded(self):
        with pytest.raises(TokenMintFailed):
            rc.compute_co("https://\ud800.example")


class TestRequestUrlWithABadPort:
    @patch("time.sleep")
    def test_a_referer_does_not_change_how_it_fails(self, _sleep):
        # The request URL is the caller's; with or without a Referer it goes
        # to the transport, which refuses it (ConnectionFailed live), instead
        # of the Sec-Fetch code raising ValueError first.
        session, mock = make_sync_session([MockResponse(200, body="ok")])
        url = "https://api.example.com:99999/v1"
        session.get(url, headers={"Referer": "https://www.example.com/"})
        assert mock.request_count == 1
        assert mock.last_kwargs["headers"]["Sec-Fetch-Site"] == "cross-site"
