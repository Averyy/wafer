"""Akamai's edge refusing an API call: classification, page choice, session flow.

homedepot.com's federation gateway (2026-11-05) answered a cold POST from a
Linux container with HTTP 206 from ``Server: AkamaiGHost`` and a 101-byte JSON
body; the gateway itself (``server: envoy``) never saw it. After wafer's
browser cleared Akamai on a homedepot.com page in the same container, the same
POST over wreq with that page's cookies got the product (200).
"""

import time
from unittest.mock import patch

import pytest

from tests.conftest import MockResponse, make_async_session, make_sync_session
from tests.test_browser import MockBrowserSolver
from wafer import ChallengeDetected
from wafer._challenge import ChallengeType, is_akamai_api_refusal
from wafer.browser import SolveResult

API = "https://www.example.com/federation-gateway/graphql?opname=productClientOnlyProduct"
# The body as the edge sent it, whitespace and all.
REFUSAL_BODY = (
    '{\n   "data":{\n      "GenericError":null\n   },\n'
    '   "error":[{\n      "message":"Generic errors" \n   }]\n}'
)
REFUSAL_HEADERS = {"server": "AkamaiGHost", "content-type": "application/json"}
CALLER_HEADERS = {
    "x-experience-name": "general-merchandise",
    "Origin": "https://www.example.com",
    "Referer": "https://www.example.com/p/204279858",
}
PRODUCT = '{"data":{"product":{"itemId":"204279858"}}}'


def _refusal():
    return MockResponse(206, dict(REFUSAL_HEADERS), REFUSAL_BODY)


def _product():
    headers = {"server": "envoy", "content-type": "application/json"}
    return MockResponse(200, headers, PRODUCT)


def _cleared():
    return SolveResult(
        cookies=[
            {
                "name": "_abck",
                "value": "cleared~0~",
                "domain": ".example.com",
                "path": "/",
                "expires": time.time() + 3600,
            }
        ],
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
    )


class TestClassification:
    def test_the_gateway_refusal(self):
        assert is_akamai_api_refusal(206, REFUSAL_HEADERS, REFUSAL_BODY)

    def test_server_header_in_any_case(self):
        assert is_akamai_api_refusal(206, {"Server": "AkamaiGHost"}, REFUSAL_BODY)

    def test_a_range_response_is_not_one(self):
        assert not is_akamai_api_refusal(
            206,
            {"server": "AkamaiGHost", "content-range": "bytes 0-99/1000"},
            "partial bytes of a file",
        )

    def test_the_gateways_own_answer_is_not_one(self):
        assert not is_akamai_api_refusal(206, {"server": "envoy"}, REFUSAL_BODY)

    def test_only_206(self):
        assert not is_akamai_api_refusal(200, REFUSAL_HEADERS, REFUSAL_BODY)
        assert not is_akamai_api_refusal(403, REFUSAL_HEADERS, REFUSAL_BODY)

    def test_needs_the_structure(self):
        # A GraphQL error, or the message alone, is the API answering.
        for body in (
            '{"data":{"product":null},"error":[]}',
            '{"error":[{"message":"Generic errors"}]}',
            '{"data":{"GenericError":null},"error":"Generic errors"}',
            '[{"data":{"GenericError":null},"error":[]}]',
            "Generic errors",
            "",
        ):
            assert not is_akamai_api_refusal(206, REFUSAL_HEADERS, body), body

    def test_a_large_body_is_not_parsed(self):
        padded = REFUSAL_BODY[:-1] + ', "x": "' + "a" * 5000 + '"}'
        assert not is_akamai_api_refusal(206, REFUSAL_HEADERS, padded)


class TestEmbedder:
    def _session(self, **kwargs):
        session, _ = make_sync_session([], browser_solver=MockBrowserSolver(), **kwargs)
        return session

    def _embedder(self, session, headers, kwargs=None, api_refusal=True):
        return session._solve_embedder(
            ChallengeType.AKAMAI, API, headers, kwargs or {"json": {"q": 1}},
            REFUSAL_BODY, "POST", "application/json", api_refusal=api_refusal,
        )

    def test_the_page_the_call_comes_from(self):
        assert self._embedder(self._session(), CALLER_HEADERS) == "https://www.example.com/p/204279858"

    def test_origin_then_embed_origin(self):
        assert (
            self._embedder(self._session(), {"Origin": "https://www.example.com"})
            == "https://www.example.com/"
        )
        assert (
            self._embedder(self._session(embed_origin="https://shop.example.com"), {})
            == "https://shop.example.com/"
        )

    def test_any_body_qualifies(self):
        # The page only earns the cookies; wreq still has the body to retry.
        assert (
            self._embedder(self._session(), CALLER_HEADERS, {"multipart": object()})
            == "https://www.example.com/p/204279858"
        )

    def test_an_akamai_page_challenge_keeps_solving_on_its_url(self):
        session = self._session()
        assert self._embedder(session, CALLER_HEADERS, api_refusal=False) is None

    def test_no_browser_or_no_page(self):
        session, _ = make_sync_session([])
        assert self._embedder(session, CALLER_HEADERS) is None
        assert self._embedder(self._session(), {"Referer": "about:blank"}) is None


class TestSessionFlow:
    @pytest.mark.parametrize("cleared", [False, True])
    @patch("time.sleep")
    def test_failed_recovery_stops_without_rotation(self, _sleep, cleared):
        solver = MockBrowserSolver(result=_cleared() if cleared else None)
        session, client = make_sync_session(
            [_refusal()] * 8, browser_solver=solver, use_cookie_jar=True
        )
        with pytest.raises(ChallengeDetected) as info:
            session.post(API, json={"query": "q"}, headers=CALLER_HEADERS)
        assert info.value.status_code == 206
        assert info.value.response.challenge_type == "akamai"
        assert len(solver.solve_kwargs) == 1
        assert len(client.request_log) == (2 if cleared else 1)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("cleared", [False, True])
    async def test_async_failed_recovery_stops_without_rotation(self, cleared):
        solver = MockBrowserSolver(result=_cleared() if cleared else None)
        session, client = make_async_session(
            [_refusal()] * 8, browser_solver=solver, use_cookie_jar=True
        )
        with patch("asyncio.sleep"), pytest.raises(ChallengeDetected) as info:
            await session.post(API, json={"query": "q"}, headers=CALLER_HEADERS)
        assert info.value.status_code == 206
        assert len(solver.solve_kwargs) == 1
        assert len(client.request_log) == (2 if cleared else 1)

    @patch("time.sleep")
    def test_sync_refusal_is_cleared_on_the_page_then_retried(self, _sleep):
        solver = MockBrowserSolver(result=_cleared())
        session, client = make_sync_session(
            [_refusal(), _product()], browser_solver=solver, use_cookie_jar=True
        )
        resp = session.post(API, json={"query": "q"}, headers=CALLER_HEADERS)
        assert resp.status_code == 200
        assert resp.text == PRODUCT
        assert len(solver.solve_kwargs) == 1
        call = solver.solve_kwargs[0]
        assert call["challenge_type"] == "akamai"
        assert call["embedder"] == "https://www.example.com/p/204279858"
        # Straight to the browser: no rotated request into the refusal.
        assert [str(m).rsplit(".", 1)[-1] for m, _u, _k in client.request_log] == [
            "POST",
            "POST",
        ]
        assert session.get_cookie("_abck", "https://www.example.com/") == "cleared~0~"

    @pytest.mark.asyncio
    async def test_async_refusal_is_cleared_on_the_page_then_retried(self):
        solver = MockBrowserSolver(result=_cleared())
        session, client = make_async_session(
            [_refusal(), _product()], browser_solver=solver, use_cookie_jar=True
        )
        with patch("asyncio.sleep"):
            resp = await session.post(API, json={"query": "q"}, headers=CALLER_HEADERS)
        assert resp.status_code == 200
        assert resp.text == PRODUCT
        assert solver.solve_kwargs[0]["embedder"] == "https://www.example.com/p/204279858"
        assert len(client.request_log) == 2

    @patch("time.sleep")
    def test_without_a_browser_it_is_reported_without_rotating(self, _sleep):
        # It came back as a 206 "success" with nothing in it.
        session, client = make_sync_session([_refusal()] * 8)
        with pytest.raises(ChallengeDetected) as info:
            session.post(API, json={"query": "q"}, headers=CALLER_HEADERS)
        assert info.value.challenge_type == "akamai"
        assert info.value.status_code == 206
        assert len(client.request_log) == 1

    @patch("time.sleep")
    def test_without_rotations_it_is_returned_named(self, _sleep):
        session, _ = make_sync_session([_refusal()], max_rotations=0)
        resp = session.post(API, json={"query": "q"}, headers=CALLER_HEADERS)
        assert resp.status_code == 206
        assert resp.challenge_type == "akamai"

    @pytest.mark.asyncio
    async def test_async_without_a_browser_it_is_reported_without_rotating(self):
        session, client = make_async_session([_refusal()] * 8)
        with patch("asyncio.sleep"), pytest.raises(ChallengeDetected) as info:
            await session.post(API, json={"query": "q"}, headers=CALLER_HEADERS)
        assert info.value.challenge_type == "akamai"
        assert len(client.request_log) == 1

    @patch("time.sleep")
    def test_a_graphql_error_is_still_the_apis_answer(self, _sleep):
        session, _ = make_sync_session(
            [MockResponse(200, {"server": "envoy", "content-type": "application/json"},
                          '{"data":{"product":null},"errors":[{"message":"x"}]}')],
            max_rotations=0,
        )
        resp = session.post(API, json={"query": "q"}, headers=CALLER_HEADERS)
        assert resp.status_code == 200
        assert resp.challenge_type is None
