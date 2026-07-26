"""New Reddit anonymous-session bootstrap tests."""

import asyncio
import logging
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest

from tests.conftest import (
    AsyncMockResponse,
    MockJar,
    MockResponse,
    make_async_session,
    make_sync_session,
)
from wafer._cookies import CookieCache
from wafer._errors import WaferTimeout
from wafer._solvers import (
    REDDIT_CACHE_DOMAIN,
    REDDIT_SOLVE_ORIGIN,
    parse_reddit_verification,
    reddit_cookie_names,
    reddit_has_cookie_evidence,
    reddit_solve_origin,
)

_JSON_URL = "https://api.reddit.com/r/homelab/hot"
_OLD_JSON_URL = "https://old.reddit.com/r/homelab/hot.json?limit=1"
_TOKEN = "t" * 64
_SEED = "AbC123xYz987LmNo"

_REDDIT_GATE_BODY = (
    "<body class=theme-beta><style>:root{--rem360:22.5rem}</style>"
    "You've been blocked by network security.</body>"
)
_GATE_HEADERS = {
    "content-type": "text/html",
    "set-cookie": [
        "csv=2; Max-Age=63072000; Domain=.reddit.com; Path=/",
        "edgebucket=edge; Max-Age=63072000; "
        "Domain=.reddit.com; Path=/",
    ],
}
_SOLVED_HEADERS = {
    "set-cookie": [
        "loid=anon; Max-Age=63072000; Domain=.reddit.com; Path=/",
        "token_v2=token; Max-Age=63072000; "
        "Domain=.reddit.com; Path=/",
        "session_tracker=session; Domain=.reddit.com; Path=/",
        "csrf_token=csrf; Domain=.reddit.com; Path=/",
    ],
}


def _verification_html(
    *,
    action="/",
    method="GET",
    token=_TOKEN,
    seed=_SEED,
):
    return f"""
    <!doctype html>
    <html>
      <head><title>Reddit - Please wait for verification</title></head>
      <body>
        <form action="{action}" method="{method}">
          <input type="hidden" name="solution" value="">
          <input type="hidden" name="js_challenge" value="1">
          <input type="hidden" name="token" value="{token}">
          <input type="hidden" name="jsc_orig_r" value="">
        </form>
        <script>
          document.addEventListener("DOMContentLoaded", async () => {{
            var e = document.forms[0],
              n = await(async e=>e+e)('{seed}');
            e.elements.namedItem("solution").value = n;
            e.requestSubmit();
          }});
        </script>
      </body>
    </html>
    """


class _UnreadableResponse(MockResponse):
    def text(self):
        raise AssertionError("solver response body must not be read")

    def bytes(self):
        raise AssertionError("solver response body must not be read")

    def stream(self):
        raise AssertionError("solver response body must not be read")


class _AsyncUnreadableResponse(AsyncMockResponse):
    async def text(self):
        raise AssertionError("solver response body must not be read")

    async def bytes(self):
        raise AssertionError("solver response body must not be read")

    def stream(self):
        raise AssertionError("solver response body must not be read")


def _gate_response(body=_REDDIT_GATE_BODY):
    return MockResponse(403, _GATE_HEADERS, body)


def _solved_response():
    return _UnreadableResponse(200, _SOLVED_HEADERS)


def _async_gate_response():
    return AsyncMockResponse(403, _GATE_HEADERS, _REDDIT_GATE_BODY)


def _async_solved_response():
    return _AsyncUnreadableResponse(200, _SOLVED_HEADERS)


def _assert_submission_url(url):
    parsed = urlparse(url)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == (
        REDDIT_SOLVE_ORIGIN
    )
    assert parse_qs(parsed.query, keep_blank_values=True) == {
        "solution": [_SEED + _SEED],
        "js_challenge": ["1"],
        "token": [_TOKEN],
        "jsc_orig_r": [""],
    }


class TestRedditVerificationParser:
    @pytest.mark.parametrize(
        "url",
        [
            "https://reddit.com/r/python.json",
            "https://www.reddit.com/r/python/hot.json",
            "https://old.reddit.com/r/python/hot.json",
            "https://api.reddit.com/r/python/hot",
            "https://API.Reddit.COM./r/python/hot",
        ],
    )
    def test_all_reddit_hosts_solve_only_on_new_reddit(self, url):
        assert reddit_solve_origin(url) == REDDIT_SOLVE_ORIGIN

    @pytest.mark.parametrize(
        "url",
        [
            "https://reddit.com.evil.test/r/python.json",
            "https://notreddit.com/r/python.json",
            "https://example.com/?next=reddit.com",
            "not-a-url",
        ],
    )
    def test_non_reddit_hosts_rejected(self, url):
        assert reddit_solve_origin(url) is None

    def test_valid_document_derives_solution_without_javascript(self):
        result = parse_reddit_verification(_verification_html())
        assert result is not None
        assert result.action_url == REDDIT_SOLVE_ORIGIN
        assert dict(result.fields) == {
            "solution": _SEED + _SEED,
            "js_challenge": "1",
            "token": _TOKEN,
            "jsc_orig_r": "",
        }

    def test_safe_field_order_and_escaped_root_action_are_accepted(self):
        html = _verification_html(action="&#47;")
        first = '<input type="hidden" name="solution" value="">'
        last = '<input type="hidden" name="jsc_orig_r" value="">'
        html = html.replace(first, "__FIRST__").replace(
            last, first
        ).replace("__FIRST__", last)

        result = parse_reddit_verification(html)

        assert result is not None
        assert dict(result.fields)["solution"] == _SEED + _SEED

    @pytest.mark.parametrize(
        "html",
        [
            _verification_html(action="https://evil.test/"),
            _verification_html(action="https://old.reddit.com/"),
            _verification_html(action="/other"),
            _verification_html(action="/?next=evil"),
            _verification_html(method="POST"),
            _verification_html(token="short"),
            _verification_html(seed="not-valid!"),
            _verification_html(seed="a" * 129),
            "<html><title>Reddit</title><body>normal homepage</body></html>",
            _verification_html().replace(
                "Reddit - Please wait for verification", "Reddit"
            ),
            _verification_html().replace("<form", "<section").replace(
                "</form>", "</section>"
            ),
            _verification_html().replace(
                '<input type="hidden" name="jsc_orig_r" value="">', ""
            ),
            _verification_html().replace(
                "e.requestSubmit();", "e.submit();"
            ),
            _verification_html().replace(
                "await(async e=>e+e)", "await(async e=>e)"
            ),
            _verification_html().replace(
                "n = await(async e=>e+e)('"
                + _SEED
                + "');",
                "n = await(async e=>e+e)('"
                + _SEED
                + "') + await(async x=>x+x)('OtherSeed');",
            ),
        ],
    )
    def test_unrecognized_or_unsafe_document_is_rejected(self, html):
        assert parse_reddit_verification(html) is None

    def test_duplicate_field_is_rejected(self):
        duplicate = _verification_html().replace(
            '<input type="hidden" name="jsc_orig_r" value="">',
            '<input type="hidden" name="token" value="'
            + _TOKEN
            + '">',
        )
        assert parse_reddit_verification(duplicate) is None

    def test_cookie_evidence_is_response_scoped_and_name_only(self):
        names = reddit_cookie_names(
            [b"loid=secret; Path=/", "token_v2=secret; Path=/"]
        )
        assert names == {"loid", "token_v2"}
        assert reddit_has_cookie_evidence(names)
        assert not reddit_has_cookie_evidence({"loid"})
        assert not reddit_has_cookie_evidence({"csv", "edgebucket"})


class TestRedditBootstrapSync:
    @patch("wafer._sync.time.sleep")
    def test_cold_old_json_uses_new_reddit_then_replays_original(
        self, mock_sleep
    ):
        responses = [
            _gate_response(),
            MockResponse(200, {}, _verification_html()),
            _solved_response(),
            MockResponse(
                200,
                {"content-type": "application/json"},
                '{"kind":"Listing"}',
            ),
        ]
        session, mock = make_sync_session(
            responses, max_rotations=0
        )

        resp = session.get(_OLD_JSON_URL)

        assert resp.json()["kind"] == "Listing"
        assert resp.inline_solves == 1
        assert resp.rotations == 0
        assert [entry[1] for entry in mock.request_log[:2]] == [
            _OLD_JSON_URL,
            REDDIT_SOLVE_ORIGIN,
        ]
        _assert_submission_url(mock.request_log[2][1])
        assert mock.request_log[3][1] == _OLD_JSON_URL
        assert all(
            url == _OLD_JSON_URL or "old.reddit.com" not in url
            for _, url, _ in mock.request_log
        )

    @patch("wafer._sync.time.sleep")
    def test_origin_cookie_fast_path_does_not_read_or_submit(
        self, mock_sleep
    ):
        responses = [
            _gate_response(),
            _UnreadableResponse(200, _SOLVED_HEADERS),
            MockResponse(200, {"content-type": "application/json"}, "{}"),
        ]
        session, mock = make_sync_session(responses)

        resp = session.get(_JSON_URL)

        assert resp.status_code == 200
        assert mock.request_count == 3
        assert mock.request_log[1][1] == REDDIT_SOLVE_ORIGIN
        assert mock.request_log[2][1] == _JSON_URL

    @patch("wafer._sync.time.sleep")
    def test_malformed_verification_is_not_submitted_or_repeated(
        self, mock_sleep
    ):
        malformed = _verification_html().replace(
            "e.requestSubmit();", "e.submit();"
        )
        responses = [
            _gate_response(),
            MockResponse(200, {}, malformed),
            _gate_response(),
            MockResponse(200, {"content-type": "application/json"}, "{}"),
        ]
        session, mock = make_sync_session(responses, max_rotations=2)

        resp = session.get(_JSON_URL)

        assert resp.status_code == 200
        assert resp.inline_solves == 0
        assert resp.rotations == 2
        assert sum(
            url == REDDIT_SOLVE_ORIGIN
            for _, url, _ in mock.request_log
        ) == 1

    @patch("wafer._sync.time.sleep")
    def test_submission_requires_response_cookie_evidence(
        self, mock_sleep
    ):
        responses = [
            _gate_response(),
            MockResponse(200, {}, _verification_html()),
            _UnreadableResponse(
                200,
                {"set-cookie": "session_tracker=x; Path=/"},
            ),
            MockResponse(200, {"content-type": "application/json"}, "{}"),
        ]
        session, mock = make_sync_session(responses, max_rotations=1)

        resp = session.get(_JSON_URL)

        assert resp.status_code == 200
        assert resp.inline_solves == 0
        assert resp.rotations == 1
        assert mock.request_count == 4

    @patch("wafer._sync.time.sleep")
    def test_verification_over_internal_cap_fails_closed(
        self, mock_sleep
    ):
        oversized = _verification_html() + "x" * (33 * 1024)
        responses = [
            _gate_response(),
            MockResponse(200, {}, oversized),
            MockResponse(200, {"content-type": "application/json"}, "{}"),
        ]
        session, mock = make_sync_session(responses, max_rotations=1)

        resp = session.get(_JSON_URL)

        assert resp.status_code == 200
        assert resp.inline_solves == 0
        assert mock.request_count == 3

    def test_deadline_is_recomputed_before_submission(self):
        class SlowVerificationClient:
            cookie_jar = MockJar()

            def __init__(self):
                self.urls = []

            def get(self, url, **kwargs):
                self.urls.append(url)
                time.sleep(0.02)
                return MockResponse(200, {}, _verification_html())

        session, _ = make_sync_session([_gate_response()])
        client = SlowVerificationClient()
        session._client = client

        with pytest.raises(WaferTimeout):
            session._try_reddit_bootstrap(
                _JSON_URL,
                time.monotonic() + 0.01,
                0.01,
            )

        assert client.urls == [REDDIT_SOLVE_ORIGIN]

    def test_expired_deadline_prevents_first_verification_leg(self):
        session, mock = make_sync_session([_gate_response()])

        with pytest.raises(WaferTimeout):
            session._try_reddit_bootstrap(
                _JSON_URL,
                time.monotonic() - 1,
                0.01,
            )

        assert mock.request_count == 0

    @patch("wafer._sync.time.sleep")
    def test_transport_logs_do_not_expose_solved_values(
        self, mock_sleep, caplog
    ):
        caplog.set_level(logging.DEBUG, logger="wafer")
        responses = [
            _gate_response(),
            MockResponse(200, {}, _verification_html()),
            RuntimeError("submission transport failed"),
            MockResponse(200, {"content-type": "application/json"}, "{}"),
        ]
        session, _ = make_sync_session(responses, max_rotations=1)

        resp = session.get(_JSON_URL)

        assert resp.status_code == 200
        assert _TOKEN not in caplog.text
        assert _SEED not in caplog.text
        assert _SEED + _SEED not in caplog.text
        assert resp.history == []

    @patch("wafer._sync.time.sleep")
    def test_internal_gate_cap_does_not_change_final_response_cap(
        self, mock_sleep
    ):
        large_gate = (
            "<body class=theme-beta>"
            + "x" * (190 * 1024)
            + "You've been blocked by network security.</body>"
        )
        responses = [
            MockResponse(
                403,
                _GATE_HEADERS,
                large_gate,
                content_length=len(large_gate),
            ),
            MockResponse(200, {}, _verification_html()),
            _solved_response(),
            MockResponse(200, {"content-type": "application/json"}, "{}"),
        ]
        session, _ = make_sync_session(
            responses,
            max_response_size=1024,
        )

        resp = session.get(_JSON_URL)

        assert resp.status_code == 200
        assert len(resp.content) <= 1024

    @patch("wafer._sync.time.sleep")
    def test_durable_cookies_share_canonical_namespace(
        self, mock_sleep, tmp_path
    ):
        cache = CookieCache(str(tmp_path))
        responses = [
            _gate_response(),
            MockResponse(200, {}, _verification_html()),
            _solved_response(),
            MockResponse(200, {"content-type": "application/json"}, "{}"),
        ]
        session, _ = make_sync_session(responses, cookie_cache=cache)

        session.get(_OLD_JSON_URL)

        names = {
            cookie["name"]
            for cookie in cache.load(REDDIT_CACHE_DOMAIN)
        }
        assert names == {"csv", "edgebucket", "loid", "token_v2"}
        assert cache.load("old.reddit.com") == []

        hydrated, hydrated_mock = make_sync_session(
            [MockResponse(200, {}, "{}")],
            cookie_cache=cache,
        )
        hydrated._hydrate_jar_from_cache()
        hydrated_names = {
            cookie.name for cookie in hydrated_mock.cookie_jar.get_all()
        }
        assert hydrated_names == names

    def test_rotation_clears_all_reddit_namespaces(self, tmp_path):
        cache = CookieCache(str(tmp_path))
        durable = [
            "cookie=value; Max-Age=3600; Domain=.reddit.com; Path=/"
        ]
        for domain in (
            REDDIT_CACHE_DOMAIN,
            "old.reddit.com",
            "api.reddit.com",
        ):
            cache.save_from_headers(
                domain, durable, f"https://{domain}/"
            )
        cache.save_from_headers(
            "example.com",
            ["keep=value; Max-Age=3600; Path=/"],
            "https://example.com/",
        )
        session, _ = make_sync_session(
            [MockResponse(200, {}, "{}")],
            cookie_cache=cache,
        )

        session._clear_cached_cookies("old.reddit.com")

        assert set(cache.list_domains()) == {"example.com"}

    def test_explicit_old_reddit_login_wall_is_returned_unchanged(self):
        body = "<html><title>Log in</title>Log in to continue</html>"
        session, mock = make_sync_session(
            [MockResponse(200, {"content-type": "text/html"}, body)]
        )

        resp = session.get("https://old.reddit.com/")

        assert resp.status_code == 200
        assert resp.text == body
        assert mock.request_count == 1
        assert mock.request_log[0][1] == "https://old.reddit.com/"


class TestRedditBootstrapAsync:
    @pytest.mark.asyncio
    @patch("wafer._async.asyncio.sleep")
    async def test_cold_json_uses_new_reddit_and_does_not_read_submit_body(
        self, mock_sleep
    ):
        responses = [
            _gate_response(),
            MockResponse(200, {}, _verification_html()),
            _async_solved_response(),
            MockResponse(
                200,
                {"content-type": "application/json"},
                '{"kind":"Listing"}',
            ),
        ]
        session, mock = make_async_session(
            responses, max_rotations=0
        )

        resp = await session.get(_JSON_URL)

        assert resp.json()["kind"] == "Listing"
        assert resp.inline_solves == 1
        assert resp.rotations == 0
        assert mock.request_log[1][1] == REDDIT_SOLVE_ORIGIN
        _assert_submission_url(mock.request_log[2][1])
        assert mock.request_log[3][1] == _JSON_URL

    @pytest.mark.asyncio
    async def test_lock_wait_uses_request_deadline(self):
        session, _ = make_async_session([_gate_response()])
        await session._reddit_bootstrap_lock.acquire()
        try:
            with pytest.raises(WaferTimeout):
                await session.get(_JSON_URL, timeout=0.01)
        finally:
            session._reddit_bootstrap_lock.release()

    @pytest.mark.asyncio
    async def test_deadline_is_recomputed_before_async_submission(self):
        class SlowVerificationClient:
            cookie_jar = MockJar()

            def __init__(self):
                self.urls = []

            async def get(self, url, **kwargs):
                self.urls.append(url)
                await asyncio.sleep(0.02)
                return AsyncMockResponse(
                    200, {}, _verification_html()
                )

        session, _ = make_async_session([_gate_response()])
        client = SlowVerificationClient()
        session._client = client

        with pytest.raises(WaferTimeout):
            await session._try_reddit_bootstrap(
                _JSON_URL,
                time.monotonic() + 0.01,
                0.01,
                0,
            )

        assert client.urls == [REDDIT_SOLVE_ORIGIN]
        assert not session._reddit_bootstrap_lock.locked()

    @pytest.mark.asyncio
    async def test_cancellation_releases_bootstrap_lock(self):
        started = asyncio.Event()

        class HangingClient:
            cookie_jar = MockJar()

            async def get(self, url, **kwargs):
                started.set()
                await asyncio.Event().wait()

        session, _ = make_async_session([_gate_response()])
        session._client = HangingClient()
        task = asyncio.create_task(
            session._try_reddit_bootstrap(
                _JSON_URL, None, 30.0, 0
            )
        )
        await started.wait()

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert not session._reddit_bootstrap_lock.locked()

    @pytest.mark.asyncio
    async def test_client_replacement_restarts_on_exact_new_client(self):
        old_started = asyncio.Event()
        release_old = asyncio.Event()

        class OldClient:
            cookie_jar = MockJar()

            def __init__(self):
                self.urls = []

            async def get(self, url, **kwargs):
                self.urls.append(url)
                old_started.set()
                await release_old.wait()
                return AsyncMockResponse(
                    200, {}, _verification_html()
                )

        class NewClient:
            cookie_jar = MockJar()

            def __init__(self):
                self.urls = []

            async def get(self, url, **kwargs):
                self.urls.append(url)
                if url == REDDIT_SOLVE_ORIGIN:
                    return AsyncMockResponse(
                        200, {}, _verification_html()
                    )
                return _async_solved_response()

        old = OldClient()
        new = NewClient()
        session, _ = make_async_session([_gate_response()])
        session._client = old
        task = asyncio.create_task(
            session._try_reddit_bootstrap(
                _JSON_URL, None, 30.0, 0
            )
        )
        await old_started.wait()
        session._client = new
        session._client_generation += 1
        release_old.set()

        solved_generation = await task

        assert solved_generation == session._client_generation
        assert old.urls == [REDDIT_SOLVE_ORIGIN]
        assert new.urls[0] == REDDIT_SOLVE_ORIGIN
        _assert_submission_url(new.urls[1])

    @pytest.mark.asyncio
    @patch("wafer._async.asyncio.sleep")
    async def test_concurrent_cold_requests_share_one_bootstrap(
        self, mock_sleep
    ):
        both_gated = asyncio.Event()

        class ConcurrentClient:
            cookie_jar = MockJar()

            def __init__(self):
                self.urls = []
                self.json_gate_count = 0
                self.origin_count = 0
                self.submit_count = 0
                self.solved = False

            def _remember(self, response, url):
                for raw in response.headers.get_all("set-cookie"):
                    self.cookie_jar.add(raw.decode(), url)
                return response

            async def request(self, method, url, **kwargs):
                self.urls.append(url)
                if url == _JSON_URL:
                    if self.solved:
                        return AsyncMockResponse(
                            200,
                            {"content-type": "application/json"},
                            "{}",
                        )
                    self.json_gate_count += 1
                    if self.json_gate_count == 2:
                        both_gated.set()
                    else:
                        await both_gated.wait()
                    return self._remember(
                        _async_gate_response(), url
                    )
                raise AssertionError(f"unexpected request: {url}")

            async def get(self, url, **kwargs):
                self.urls.append(url)
                if url == REDDIT_SOLVE_ORIGIN:
                    self.origin_count += 1
                    return AsyncMockResponse(
                        200, {}, _verification_html()
                    )
                self.submit_count += 1
                self.solved = True
                return self._remember(_async_solved_response(), url)

        client = ConcurrentClient()
        session, _ = make_async_session([_gate_response()])
        session._client = client

        first, second = await asyncio.gather(
            session.get(_JSON_URL),
            session.get(_JSON_URL),
        )

        assert first.status_code == second.status_code == 200
        assert client.json_gate_count == 2
        assert client.origin_count == 1
        assert client.submit_count == 1
        assert session._reddit_bootstrap_generation == 1
