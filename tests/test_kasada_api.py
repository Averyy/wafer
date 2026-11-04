"""Kasada-signed APIs: classification, embedder, and the in-page signed replay.

gdx-api.costco.com (2026-11-03) answers an unsigned search POST with HTTP 429,
an empty ``text/plain`` body and ``x-kpsdk-*`` headers, cookies or not. The
page's own POST carries x-kpsdk-ct/-cd/-h/-v, added by the Kasada SDK's fetch
hook; a fetch made in the page's main world gets them too and answers 200.
"""

import base64
import json
import time
from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import MockResponse, make_async_session, make_sync_session
from tests.test_browser import MockBrowserSolver
from wafer import ChallengeDetected
from wafer._challenge import ChallengeType, is_kasada_api_refusal
from wafer.browser import SolveResult
from wafer.browser._kasada import (
    is_kasada_refusal,
    kasada_api_replay,
    signed_fetch_headers,
)
from wafer.browser._solver import CapturedResponse

API = "https://gdx-api.example.com/catalog/search/api/v1/search"
REFUSAL_HEADERS = {
    "content-type": "text/plain;charset=UTF-8",
    "x-kpsdk-ct": "0fhIClSP7nZ9PZimXBApmuzYkha3Wi8c",
    "x-kpsdk-r": "1-AA",
}
CALLER_HEADERS = {
    "client_id": "USBC",
    "locale": "en-US",
    "Origin": "https://www.example.com",
    "Referer": "https://www.example.com/s?keyword=laptop",
}
RESULTS = b'{"searchResult":{"results":[{"id":"1"}]}}'


def _signed_result():
    return SolveResult(
        cookies=[],
        user_agent="Chrome/154",
        response=CapturedResponse(
            url=API,
            status=200,
            headers={"content-type": "application/json"},
            body=RESULTS,
        ),
        challenge_absent=True,
    )


class TestClassification:
    def test_plain_text_refusal_with_kasada_headers(self):
        assert is_kasada_api_refusal(429, REFUSAL_HEADERS, "text/plain")
        assert is_kasada_api_refusal(403, REFUSAL_HEADERS, "application/json")

    def test_needs_a_refusal_status(self):
        assert not is_kasada_api_refusal(200, REFUSAL_HEADERS, "text/plain")

    def test_needs_kasada_headers(self):
        assert not is_kasada_api_refusal(
            429, {"content-type": "text/plain"}, "text/plain"
        )

    def test_html_is_left_to_detect_challenge(self):
        # detect_challenge already classifies HTML; this is only the
        # exception to the non-HTML exemption.
        assert not is_kasada_api_refusal(429, REFUSAL_HEADERS, "text/html")
        assert not is_kasada_api_refusal(429, REFUSAL_HEADERS, "")


class TestEmbedder:
    def _session(self, **kwargs):
        session, _ = make_sync_session([], browser_solver=MockBrowserSolver(), **kwargs)
        return session

    def test_referer_is_the_page_the_call_comes_from(self):
        embedder = self._session()._kasada_embedder(
            ChallengeType.KASADA, API, CALLER_HEADERS, "POST", "text/plain"
        )
        assert embedder == "https://www.example.com/s?keyword=laptop"

    def test_origin_when_no_referer(self):
        embedder = self._session()._kasada_embedder(
            ChallengeType.KASADA,
            API,
            {"Origin": "https://www.example.com"},
            "POST",
            "text/plain",
        )
        assert embedder == "https://www.example.com/"

    def test_a_bare_origin_with_a_query_keeps_it(self):
        # "/" was appended to the whole string, landing in the query.
        embedder = self._session()._kasada_embedder(
            ChallengeType.KASADA,
            API,
            {"Referer": "https://www.example.com?tenant=abc#top"},
            "POST",
            "text/plain",
        )
        assert embedder == "https://www.example.com/?tenant=abc#top"

    def test_a_multipart_upload_is_not_remade_in_the_page(self):
        # wreq's Multipart cannot be read back; the signed replay would send
        # the POST without its upload.
        session = self._session()
        assert session._solve_embedder(
            ChallengeType.KASADA, API, CALLER_HEADERS, {"multipart": object()},
            None, "POST", "text/plain",
        ) is None
        assert session._solve_embedder(
            ChallengeType.KASADA, API, CALLER_HEADERS, {"json": {"q": 1}},
            None, "POST", "text/plain",
        ) == "https://www.example.com/s?keyword=laptop"

    def test_embed_origin_when_the_caller_names_neither(self):
        embedder = self._session(embed_origin="https://www.example.com")._kasada_embedder(
            ChallengeType.KASADA, API, {}, "POST", "text/plain"
        )
        assert embedder == "https://www.example.com/"

    def test_a_navigation_keeps_solving_on_its_own_url(self):
        assert self._session()._kasada_embedder(
            ChallengeType.KASADA, API, CALLER_HEADERS, "GET", "text/html"
        ) is None

    def test_other_challenges_and_no_browser(self):
        assert self._session()._kasada_embedder(
            ChallengeType.DATADOME, API, CALLER_HEADERS, "POST", "text/plain"
        ) is None
        session, _ = make_sync_session([])
        assert session._kasada_embedder(
            ChallengeType.KASADA, API, CALLER_HEADERS, "POST", "text/plain"
        ) is None

    def test_nothing_to_navigate(self):
        assert self._session()._kasada_embedder(
            ChallengeType.KASADA, API, {"Referer": "about:blank"}, "POST", "text/plain"
        ) is None


class TestSessionFlow:
    def _refusal(self):
        return MockResponse(429, dict(REFUSAL_HEADERS), "")

    @patch("time.sleep")
    def test_sync_refusal_goes_to_a_signed_replay(self, _sleep):
        solver = MockBrowserSolver(result=_signed_result())
        session, _ = make_sync_session([self._refusal()], browser_solver=solver)
        resp = session.post(API, json={"query": "laptop"}, headers=CALLER_HEADERS)
        assert resp.status_code == 200
        assert resp.content == RESULTS
        call = solver.solve_kwargs[0]
        assert call["challenge_type"] == "kasada"
        assert call["embedder"] == CALLER_HEADERS["Referer"]
        replay = call["replay"]
        assert replay["method"] == "POST"
        assert json.loads(replay["body"]) == {"query": "laptop"}
        assert replay["content_type"] == "application/json"
        assert replay["headers"]["client_id"] == "USBC"

    @pytest.mark.asyncio
    async def test_async_refusal_goes_to_a_signed_replay(self):
        solver = MockBrowserSolver(result=_signed_result())
        session, _ = make_async_session([self._refusal()], browser_solver=solver)
        with patch("asyncio.sleep"):
            resp = await session.post(
                API, json={"query": "laptop"}, headers=CALLER_HEADERS
            )
        assert resp.status_code == 200
        assert resp.content == RESULTS
        assert solver.solve_kwargs[0]["embedder"] == CALLER_HEADERS["Referer"]

    @patch("time.sleep")
    def test_session_headers_ride_the_signed_replay(self, _sleep):
        # An Authorization set on the session is part of the caller's request;
        # dropping it made the signed retry unauthenticated.
        solver = MockBrowserSolver(result=_signed_result())
        session, _ = make_sync_session([self._refusal()], browser_solver=solver)
        session.headers = {
            "Authorization": "Bearer t",
            "Referer": "https://www.example.com/app",
        }
        session._user_headers = True
        session.post(API, json={"query": "laptop"}, headers={"client_id": "USBC"})
        call = solver.solve_kwargs[0]
        assert call["embedder"] == "https://www.example.com/app"
        assert call["replay"]["headers"] == {
            "Authorization": "Bearer t",
            "Referer": "https://www.example.com/app",
            "client_id": "USBC",
        }

    def test_per_request_headers_override_session_ones_by_name(self):
        session, _ = make_sync_session([])
        session.headers = {"Client_ID": "CABC", "Accept": "*/*"}
        session._user_headers = True
        assert session._caller_headers({"client_id": "USBC"}) == {
            "Accept": "*/*",
            "client_id": "USBC",
        }

    def test_wafer_defaults_are_not_the_callers(self):
        session, _ = make_sync_session([])
        assert session._caller_headers({"client_id": "USBC"}) == {
            "client_id": "USBC"
        }

    @patch("time.sleep")
    def test_without_a_browser_it_is_reported_as_kasada(self, _sleep):
        # It was retried as a rate limit and raised RateLimited.
        session, client = make_sync_session([self._refusal()] * 8)
        with pytest.raises(ChallengeDetected) as info:
            session.post(API, json={"query": "laptop"}, headers=CALLER_HEADERS)
        assert info.value.challenge_type == "kasada"
        assert len(client.request_log) == 1

    @patch("time.sleep")
    def test_without_rotations_it_is_returned_named(self, _sleep):
        session, _ = make_sync_session([self._refusal()], max_rotations=0)
        resp = session.post(API, json={"query": "laptop"}, headers=CALLER_HEADERS)
        assert resp.status_code == 429
        assert resp.challenge_type == "kasada"

    @patch("time.sleep")
    def test_an_api_json_error_is_still_not_a_challenge(self, _sleep):
        session, _ = make_sync_session(
            [MockResponse(403, {"content-type": "application/json"}, '{"e":1}')],
            max_rotations=0,
        )
        resp = session.post(API, json={"query": "laptop"})
        assert resp.status_code == 403
        assert resp.challenge_type is None


class TestSignedFetchHeaders:
    def test_forbidden_and_kasada_headers_are_dropped(self):
        headers = signed_fetch_headers({
            "client_id": "USBC",
            "Origin": "https://www.example.com",
            "Referer": "https://www.example.com/",
            "User-Agent": "x",
            "Cookie": "a=b",
            "Sec-Fetch-Site": "same-site",
            "x-kpsdk-ct": "stale",
            "Content-Type": "application/json",
        })
        assert headers == {"client_id": "USBC", "Content-Type": "application/json"}


class TestKasadaApiReplay:
    def _reply(self, status, body=b"", headers=None, **extra):
        return {
            "status": status,
            "headers": headers or {"content-type": "application/json"},
            "body": base64.b64encode(body).decode(),
            "size": len(body),
            "url": API,
            **extra,
        }

    def _run(self, reply, max_size=None, replay=None):
        with patch("wafer.browser._solver._quiet_read", return_value=reply) as read:
            res = kasada_api_replay(
                MagicMock(),
                API,
                replay
                or {
                    "method": "POST",
                    "body": '{"query": "laptop"}',
                    "content_type": "application/json",
                    "headers": CALLER_HEADERS,
                },
                10_000,
                max_size=max_size,
            )
        return res, read

    @staticmethod
    def _sent_from(expression):
        return json.loads(expression.rsplit("})(", 1)[1][:-1])

    @classmethod
    def _sent(cls, read):
        return cls._sent_from(read.call_args[0][1])

    def test_body_bytes_go_out_exactly(self):
        # A text round trip turned b"\xff" into U+FFFD.
        raw = b"\xff\x00binary"
        _, read = self._run(
            self._reply(200, RESULTS),
            replay={
                "method": "POST",
                "body": raw.decode("utf-8", errors="replace"),
                "body_b64": base64.b64encode(raw).decode(),
                "headers": {},
            },
        )
        assert base64.b64decode(self._sent(read)["body_b64"]) == raw

    def test_decoded_body_drops_wire_framing_headers(self):
        res, _ = self._run(
            self._reply(
                200,
                RESULTS,
                {
                    "content-type": "application/json",
                    "content-encoding": "gzip",
                    "content-length": "12",
                },
            )
        )
        assert res["headers"] == {"content-type": "application/json"}

    def test_a_signed_200_comes_back_as_bytes(self):
        res, read = self._run(self._reply(200, RESULTS))
        assert res["status"] == 200
        assert res["body"] == RESULTS
        # The request goes through the page's own world, with the caller's
        # allowed headers and its content type.
        sent = self._sent(read)
        assert base64.b64decode(sent["body_b64"]) == b'{"query": "laptop"}'
        assert sent["headers"] == {
            "client_id": "USBC",
            "locale": "en-US",
            "Content-Type": "application/json",
        }

    def test_credentials_go_unless_cors_refuses_them(self):
        # gdx-api.costco.com's CORS rejects a credentialed call outright
        # ("Failed to fetch"); its own page calls it without credentials.
        replies = [
            {"status": -1, "error": "TypeError: Failed to fetch"},
            self._reply(200, RESULTS),
        ]
        with patch(
            "wafer.browser._solver._quiet_read",
            side_effect=lambda page, expr: replies.pop(0),
        ) as read:
            res = kasada_api_replay(
                MagicMock(), API, {"method": "POST", "headers": {}}, 10_000
            )
        assert res["status"] == 200
        sent = [self._sent_from(c[0][1]) for c in read.call_args_list]
        assert [s["credentials"] for s in sent] == ["include", "same-origin"]

    def test_one_credentialed_call_when_it_is_allowed(self):
        res, read = self._run(self._reply(200, RESULTS))
        assert read.call_count == 1
        assert self._sent(read)["credentials"] == "include"

    def test_follow_redirects_off_is_kept(self):
        res, read = self._run(
            {"status": -3, "error": "redirect not followed"},
            replay={"method": "POST", "headers": {}, "follow_redirects": False},
        )
        assert res is None
        assert self._sent(read)["redirect"] == "manual"
        _, read = self._run(self._reply(200, RESULTS))
        assert self._sent(read)["redirect"] == "follow"

    def test_a_body_that_cannot_be_remade_is_not_sent(self):
        res, read = self._run(
            self._reply(200, RESULTS),
            replay={"method": "POST", "headers": {}, "body_unavailable": True},
        )
        assert res is None
        read.assert_not_called()

    def test_the_retry_gets_what_is_left_of_the_budget(self):
        # The same-origin retry started with a fresh timeout, past the
        # solve's deadline.
        clock = [100.0]
        replies = [
            {"status": -1, "error": "TypeError: Failed to fetch"},
            self._reply(200, RESULTS),
        ]

        def read(page, expr):
            clock[0] += 4.0
            return replies.pop(0)

        with patch("wafer.browser._kasada.time.monotonic", lambda: clock[0]), patch(
            "wafer.browser._solver._quiet_read", side_effect=read
        ) as quiet:
            res = kasada_api_replay(
                MagicMock(), API, {"method": "POST", "headers": {}}, 5_000
            )
        assert res["status"] == 200
        sent = [self._sent_from(c[0][1])["timeout_ms"] for c in quiet.call_args_list]
        assert sent == [5000, 1000]

    def test_no_retry_once_the_budget_is_spent(self):
        clock = [100.0]

        def read(page, expr):
            clock[0] += 6.0
            return {"status": -1, "error": "TypeError: Failed to fetch"}

        with patch("wafer.browser._kasada.time.monotonic", lambda: clock[0]), patch(
            "wafer.browser._solver._quiet_read", side_effect=read
        ) as quiet:
            res = kasada_api_replay(
                MagicMock(), API, {"method": "POST", "headers": {}}, 5_000
            )
        assert res is None
        assert quiet.call_count == 1

    def test_a_short_budget_is_not_rounded_up(self):
        _, read = self._run_with_timeout(300)
        assert self._sent(read)["timeout_ms"] <= 300

    def _run_with_timeout(self, timeout_ms):
        with patch(
            "wafer.browser._solver._quiet_read", return_value=self._reply(200, RESULTS)
        ) as read:
            res = kasada_api_replay(
                MagicMock(), API, {"method": "POST", "headers": {}}, timeout_ms
            )
        return res, read

    def test_no_redirect_left_is_too_many(self):
        # max_redirects=0 (or a budget the session already spent): the
        # browser must not follow, and a redirect is what the session's own
        # loop would raise on.
        from wafer import TooManyRedirects

        replay = {
            "method": "POST", "headers": {}, "follow_redirects": True,
            "max_redirects": 0, "redirects_left": 0,
        }
        with pytest.raises(TooManyRedirects):
            self._run({"status": -3, "error": "redirect not followed"}, replay=replay)
        _, read = self._run(self._reply(200, RESULTS), replay=replay)
        assert self._sent(read)["redirect"] == "manual"

    def test_hops_past_the_budget_are_too_many(self):
        from wafer import TooManyRedirects

        page = MagicMock()
        listeners = []
        page.on.side_effect = lambda event, fn: listeners.append(fn)

        def hop(n):
            req = MagicMock(url=API, redirected_from=None)
            for i in range(n):
                req = MagicMock(url=f"{API}?hop={i}", redirected_from=req)
            return req

        def read(_page, _expr, hops):
            for fn in listeners:
                fn(hop(hops))
            return self._reply(200, RESULTS, redirected=True)

        replay = {
            "method": "POST", "headers": {}, "follow_redirects": True,
            "max_redirects": 10, "redirects_left": 2,
        }
        with patch(
            "wafer.browser._solver._quiet_read",
            side_effect=lambda p, e: read(p, e, 3),
        ), pytest.raises(TooManyRedirects):
            kasada_api_replay(page, API, replay, 10_000)
        page.remove_listener.assert_called()

        listeners.clear()
        with patch(
            "wafer.browser._solver._quiet_read",
            side_effect=lambda p, e: read(p, e, 2),
        ):
            res = kasada_api_replay(page, API, replay, 10_000)
        assert res["status"] == 200

    def test_a_refusal_even_signed_is_none(self):
        res, _ = self._run(self._reply(429, b"", {"x-kpsdk-ct": "x"}))
        assert res is None
        res, _ = self._run(self._reply(429, b""))
        assert res is None

    def test_a_transport_error_is_none(self):
        res, _ = self._run({"status": -1, "error": "TypeError: Failed to fetch"})
        assert res is None

    def test_too_large(self):
        from wafer import ResponseTooLarge

        with pytest.raises(ResponseTooLarge):
            self._run(self._reply(200, too_large=True, size=5000), max_size=10)

    def test_refusal_helper(self):
        assert is_kasada_refusal(429, {"x-kpsdk-r": "1-AA"})
        assert not is_kasada_refusal(200, {"x-kpsdk-r": "1-AA"})


class TestSolverBranch:
    def test_waits_for_the_sdk_then_replays(self):
        from wafer.browser._solver import BrowserSolver

        solver = BrowserSolver.__new__(BrowserSolver)
        solver._browser_ua = "Chrome/154"
        solver._browser_version = "154.0.8037.92"
        page = MagicMock()
        context = MagicMock()
        context.cookies.return_value = []
        replies = iter([False, True])
        with patch(
            "wafer.browser._solver._quiet_read",
            side_effect=lambda page, expr: next(replies),
        ), patch(
            "wafer.browser._kasada.kasada_api_replay",
            return_value={
                "status": 200,
                "headers": {"content-type": "application/json"},
                "body": RESULTS,
                "url": API,
            },
        ):
            result = solver._solve_kasada_api(
                context,
                page,
                API,
                "https://www.example.com/",
                {"method": "POST"},
                time.monotonic() + 10,
                None,
                {"exceeded": False},
            )
        page.goto.assert_called_once()
        assert page.goto.call_args[0][0] == "https://www.example.com/"
        assert result.response.body == RESULTS
        assert result.challenge_absent is True

    def test_the_pages_cookies_are_not_handed_back(self):
        # costco.com's consent cookie (tcm, Domain=.costco.com, a year-plus
        # expiry) came back with the signed search, went into the jar and
        # cache_dir, and ecom-api.costco.com refused every later request that
        # carried it. The page's own calls to these APIs send no cookies.
        from wafer.browser._solver import BrowserSolver

        solver = BrowserSolver.__new__(BrowserSolver)
        solver._browser_ua = "Chrome/154"
        solver._browser_version = None
        context = MagicMock()
        context.cookies.return_value = [
            {"name": "tcm", "value": '{"purposes":{}}', "domain": ".example.com"},
        ]
        with patch("wafer.browser._solver._quiet_read", return_value=True), patch(
            "wafer.browser._kasada.kasada_api_replay",
            return_value={"status": 200, "headers": {}, "body": RESULTS, "url": API},
        ):
            result = solver._solve_kasada_api(
                context, MagicMock(), API, "https://www.example.com/",
                {"method": "POST"}, time.monotonic() + 10, None,
                {"exceeded": False},
            )
        assert result.cookies == []

    @patch("time.sleep")
    def test_a_signed_response_leaves_the_jar_and_cache_alone(self, _sleep, tmp_path):
        result = _signed_result()
        result.cookies = []
        solver = MockBrowserSolver(result=result)
        session, _ = make_sync_session(
            [MockResponse(429, dict(REFUSAL_HEADERS), "")],
            browser_solver=solver,
            cache_dir=str(tmp_path),
        )
        resp = session.post(API, json={"query": "laptop"}, headers=CALLER_HEADERS)
        assert resp.status_code == 200
        assert list(tmp_path.iterdir()) == []

    def test_no_sdk_no_signed_request(self):
        from wafer.browser._solver import BrowserSolver

        solver = BrowserSolver.__new__(BrowserSolver)
        solver._browser_ua = "Chrome/154"
        solver._browser_version = None
        page = MagicMock()
        with patch("wafer.browser._solver._quiet_read", return_value=False), patch(
            "wafer.browser._kasada.kasada_api_replay"
        ) as replay:
            result = solver._solve_kasada_api(
                MagicMock(),
                page,
                API,
                "https://www.example.com/",
                {"method": "POST"},
                time.monotonic() + 0.3,
                None,
                {"exceeded": False},
            )
        assert result is None
        replay.assert_not_called()
