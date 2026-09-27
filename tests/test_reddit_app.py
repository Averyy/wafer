"""Reddit JSON reads through the Android app API (wafer/_reddit_app.py)."""

import asyncio
import base64
import json
import logging
import os
import stat
import time
from unittest.mock import patch

import pytest

from tests.conftest import (
    AsyncMockClient,
    AsyncMockResponse,
    MockClient,
    MockResponse,
    make_async_session,
    make_sync_session,
)
from wafer._cookies import CookieCache
from wafer._errors import ResponseTooLarge, TooManyRedirects
from wafer._reddit_app import (
    _APP_RELEASES,
    _STATE_FILE,
    REDDIT_APP_BACKOFF_SECONDS,
    REDDIT_APP_CLIENT_ID,
    REDDIT_APP_IDENTITY,
    REDDIT_APP_TOKEN_URL,
    REDDIT_APP_TRANSPORT_BACKOFF_SECONDS,
    RedditAppDevice,
    RedditAppToken,
    caller_location,
    is_gate_response,
    load_state,
    parse_token_response,
    ratelimit_reset,
    reddit_app_api_url,
    save_state,
    token_request,
    web_url,
)

_ACCESS = "eyJhbGciOiJSUzI1NiJ9." + "a" * 40
_LOID = "000000000abcdef.2.1759000000000.Z0FBQUFBQm"
_SESSION = "session-value-123"
_JSON_URL = "https://www.reddit.com/r/Python/.json?limit=1"
_API_URL = "https://oauth.reddit.com/r/Python/.json?limit=1"
_LISTING = json.dumps({"kind": "Listing", "data": {"children": []}})
_JSON = {"content-type": "application/json; charset=UTF-8"}


def _token_response(cls=MockResponse, expires_in=86399):
    body = json.dumps(
        {
            "access_token": _ACCESS,
            "expires_in": expires_in,
            "expiry_ts": 1759086399,
            "scope": ["*", "email", "pii"],
            "token_type": "bearer",
        }
    )
    headers = dict(_JSON, **{"x-reddit-loid": _LOID, "x-reddit-session": _SESSION})
    return cls(200, headers, body)


def _listing(cls=MockResponse, status=200, headers=None, body=_LISTING):
    return cls(status, dict(_JSON, **(headers or {})), body)


def _gate(cls=MockResponse):
    return cls(
        403,
        {"content-type": "text/html"},
        "<!doctype html><body class=theme-beta>blocked by network security</body>",
    )


def _store_old_token(cache_dir):
    """A saved install whose token was minted an hour ago and is still valid."""
    now = time.time()
    save_state(
        cache_dir,
        RedditAppDevice.new(),
        RedditAppToken(_ACCESS, now + 20_000, _LOID, _SESSION, minted_at=now - 3600),
    )


def _session(app_responses, web_responses=(), **kwargs):
    app = MockClient(list(app_responses))
    session, web = make_sync_session(
        list(web_responses) or [_listing()],
        reddit_app=True,
        reddit_app_client=app,
        **kwargs,
    )
    return session, app, web


def _async_session(app_responses, web_responses=(), **kwargs):
    app = AsyncMockClient(list(app_responses))
    session, web = make_async_session(
        list(web_responses) or [_listing(AsyncMockResponse)],
        reddit_app=True,
        reddit_app_client=app,
        **kwargs,
    )
    return session, app, web


class TestUrlMapping:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (_JSON_URL, _API_URL),
            ("https://reddit.com/r/Python/hot.json", "https://oauth.reddit.com/r/Python/hot.json"),
            ("https://new.reddit.com/user/x/about.json", "https://oauth.reddit.com/user/x/about.json"),
            ("https://WWW.Reddit.com./r/a/.json", "https://oauth.reddit.com/r/a/.json"),
            ("https://api.reddit.com/r/homelab/hot", "https://oauth.reddit.com/r/homelab/hot"),
            ("https://oauth.reddit.com/api/info?id=t3_x", "https://oauth.reddit.com/api/info?id=t3_x"),
            ("https://www.reddit.com/r/a/.json#frag", "https://oauth.reddit.com/r/a/.json"),
            ("https://www.reddit.com:443/r/a/.json", "https://oauth.reddit.com/r/a/.json"),
        ],
    )
    def test_json_reads_map_to_the_app_api(self, url, expected):
        assert reddit_app_api_url(url) == expected

    @pytest.mark.parametrize(
        "url",
        [
            "https://old.reddit.com/r/a/.json",
            "https://www.reddit.com/r/Python/",
            "https://www.reddit.com/r/Python/comments/x/y/",
            "http://www.reddit.com/r/a/.json",
            "https://www.reddit.com:8443/r/a/.json",
            "https://user:pw@www.reddit.com/r/a/.json",
            "https://evilreddit.com/r/a/.json",
            "https://reddit.com.evil.test/r/a/.json",
            "https://i.redd.it/x.json",
            "not a url",
        ],
    )
    def test_everything_else_stays_on_the_web_path(self, url):
        assert reddit_app_api_url(url) is None

    def test_location_is_reported_on_the_callers_host(self):
        assert (
            caller_location(_JSON_URL, _API_URL, "/r/python/.json")
            == "https://www.reddit.com/r/python/.json"
        )
        assert (
            caller_location(_JSON_URL, _API_URL, "https://oauth.reddit.com/r/x/.json")
            == "https://www.reddit.com/r/x/.json"
        )
        away = "https://www.redditinc.com/"
        assert caller_location(_JSON_URL, _API_URL, away) == away
        # A relative target off the app route is still on Reddit's own host.
        assert (
            caller_location(_JSON_URL, _API_URL, "/r/Python/")
            == "https://www.reddit.com/r/Python/"
        )

    def test_web_url_keeps_the_host_the_caller_asked_for(self):
        assert (
            web_url(_JSON_URL, "https://oauth.reddit.com/r/python/.json?limit=1")
            == "https://www.reddit.com/r/python/.json?limit=1"
        )
        assert (
            web_url("https://api.reddit.com/r/a/hot", "https://oauth.reddit.com/r/a/hot")
            == "https://api.reddit.com/r/a/hot"
        )


class TestIdentity:
    def test_new_install_is_a_real_release_on_a_supported_android(self):
        for _ in range(50):
            device = RedditAppDevice.new()
            release = next(r for r in _APP_RELEASES if r[0] == device.version)
            assert device.build == release[1]
            assert device.android >= release[2]
            assert device.user_agent == (
                f"Reddit/Version {device.version}/Build {device.build}"
                f"/Android {device.android}"
            )

    def test_headers_carry_one_stable_device_id(self):
        device = RedditAppDevice.new()
        headers = device.headers()
        assert headers["client-vendor-id"] == device.device_id
        assert headers["x-reddit-device-id"] == device.device_id
        assert headers == device.headers()
        assert "Authorization" not in headers

    def test_token_request_is_the_anonymous_grant(self):
        headers, body = token_request(RedditAppDevice.new())
        expected = base64.b64encode(f"{REDDIT_APP_CLIENT_ID}:".encode()).decode()
        assert headers["Authorization"] == f"Basic {expected}"
        assert headers["Content-Type"] == "application/json; charset=UTF-8"
        assert json.loads(body) == {"scopes": ["*", "email", "pii"]}

    def test_token_values_never_appear_in_repr(self):
        token = RedditAppToken(_ACCESS, time.time() + 100, _LOID, _SESSION)
        rendered = repr(token)
        for secret in (_ACCESS, _LOID, _SESSION):
            assert secret not in rendered


class TestTokenParsing:
    def test_grant_is_parsed_with_its_session_headers(self):
        resp = _token_response()
        token = parse_token_response(
            200,
            {"X-Reddit-Loid": _LOID, "x-reddit-session": _SESSION},
            resp._body.encode(),
            now=1000.0,
        )
        assert token.access_token == _ACCESS
        assert token.expires_at == 1000.0 + 86399
        assert token.loid == _LOID and token.session == _SESSION
        assert token.headers()["Authorization"] == f"Bearer {_ACCESS}"
        assert token.headers()["x-reddit-loid"] == _LOID

    @pytest.mark.parametrize(
        ("status", "body"),
        [
            (403, json.dumps({"access_token": _ACCESS, "expires_in": 86399})),
            (200, "<html>blocked by network security</html>"),
            (200, "[]"),
            (200, json.dumps({"access_token": "short", "expires_in": 86399})),
            (200, json.dumps({"access_token": _ACCESS + " x", "expires_in": 86399})),
            (200, json.dumps({"access_token": _ACCESS, "expires_in": True})),
            (200, json.dumps({"access_token": _ACCESS, "expires_in": "86399"})),
            (200, json.dumps({"access_token": _ACCESS, "expires_in": 10})),
            (200, json.dumps({"access_token": _ACCESS, "expires_in": 10**9})),
            (200, json.dumps({"expires_in": 86399})),
            (
                200,
                json.dumps(
                    {"access_token": _ACCESS, "pad": "x" * 20000, "expires_in": 86399}
                ),
            ),
        ],
    )
    def test_anything_but_a_grant_is_refused(self, status, body):
        assert parse_token_response(status, {}, body.encode()) is None

    def test_malformed_session_headers_are_dropped(self):
        body = json.dumps({"access_token": _ACCESS, "expires_in": 86399}).encode()
        token = parse_token_response(
            200, {"x-reddit-loid": "bad value\r\n", "x-reddit-session": ""}, body
        )
        assert token is not None
        assert token.loid == "" and token.session == ""
        assert "x-reddit-loid" not in token.headers()

    def test_freshness_keeps_a_refresh_margin(self):
        token = RedditAppToken(_ACCESS, expires_at=1000.0)
        assert token.fresh(now=0.0)
        assert not token.fresh(now=800.0)


class TestResponseClassification:
    def test_html_403_is_the_edge_gate(self):
        html = {"Content-Type": "text/html"}
        assert is_gate_response(403, html, b"  <!doctype html>")

    def test_json_403_is_the_api_answering(self):
        body = b'{"reason": "private", "message": "Forbidden", "error": 403}'
        assert not is_gate_response(403, _JSON, body)

    @pytest.mark.parametrize("status", [200, 401, 404, 429])
    def test_any_non_json_answer_is_the_edge(self, status):
        """The API answers in JSON; an HTML page (Reddit's reCAPTCHA page, an
        edge 429) is the client being turned away, never content."""
        assert is_gate_response(status, {"content-type": "text/html"}, b"<html>")
        assert is_gate_response(status, {}, b"blocked")

    @pytest.mark.parametrize(
        ("status", "headers", "body"),
        [
            (500, {"content-type": "text/html"}, b"<html>"),
            (503, {}, b"upstream"),
            (301, {"content-type": "text/html"}, b"<html>moved</html>"),
            (200, {}, b""),
            (200, _JSON, b"{}"),
            (404, _JSON, b'{"error": 404}'),
        ],
    )
    def test_server_errors_redirects_and_json_are_not_the_edge(
        self, status, headers, body
    ):
        assert not is_gate_response(status, headers, body)

    def test_json_body_without_a_content_type_is_the_api(self):
        assert not is_gate_response(200, {}, b' {"kind": "Listing"}')
        assert not is_gate_response(200, {}, b"[1]")
        assert is_gate_response(200, {"content-type": "text/plain"}, b"{}")

    def test_ratelimit_reset_only_when_the_window_is_spent(self):
        def reset(remaining, value):
            return ratelimit_reset(
                {"x-ratelimit-remaining": remaining, "x-ratelimit-reset": value}
            )

        assert reset("0.0", "42") == 42
        assert reset("3", "42") is None
        assert reset("0", "9000") is None
        assert reset("x", "1") is None
        assert ratelimit_reset({}) is None


class TestPersistence:
    def test_round_trip_is_owner_only(self, tmp_path):
        device = RedditAppDevice.new()
        token = RedditAppToken(_ACCESS, time.time() + 3600, _LOID, _SESSION)
        save_state(tmp_path, device, token)
        path = tmp_path / _STATE_FILE
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        loaded_device, loaded_token = load_state(tmp_path)
        assert loaded_device == device
        assert loaded_token == token

    def test_expired_token_is_not_loaded(self, tmp_path):
        device = RedditAppDevice.new()
        save_state(tmp_path, device, RedditAppToken(_ACCESS, time.time() + 60))
        assert load_state(tmp_path) == (device, None)

    def test_retired_release_moves_to_a_current_build(self, tmp_path):
        (tmp_path / _STATE_FILE).write_text(
            json.dumps(
                {
                    "device": {
                        "device_id": "11111111-2222-4333-8444-555555555555",
                        "version": "2024.22.1",
                        "build": 1652272,
                        "android": 13,
                        "down_rate": "24.312",
                    },
                    "token": None,
                }
            )
        )
        device, token = load_state(tmp_path)
        assert device.device_id == "11111111-2222-4333-8444-555555555555"
        assert device.version in {r[0] for r in _APP_RELEASES}
        assert token is None

    def test_damaged_token_keeps_the_install(self, tmp_path):
        device = RedditAppDevice.new()
        save_state(tmp_path, device, None)
        path = tmp_path / _STATE_FILE
        data = json.loads(path.read_text())
        data["token"] = {"access_token": _ACCESS, "expires_at": "soon"}
        path.write_text(json.dumps(data))
        assert load_state(tmp_path) == (device, None)

    def test_mint_time_round_trips(self, tmp_path):
        now = time.time()
        token = RedditAppToken(_ACCESS, now + 3600, minted_at=now - 10)
        save_state(tmp_path, RedditAppDevice.new(), token)
        loaded = load_state(tmp_path)[1]
        assert loaded.minted_at == token.minted_at
        assert loaded.recent()

    @pytest.mark.parametrize("content", ["", "{", "[]", '{"device": {}}'])
    def test_unreadable_state_starts_a_new_install(self, tmp_path, content):
        (tmp_path / _STATE_FILE).write_text(content)
        assert load_state(tmp_path) is None

    def test_state_file_is_not_read_as_a_cookie_domain(self, tmp_path):
        save_state(tmp_path, RedditAppDevice.new(), None)
        assert list(CookieCache(tmp_path).list_domains()) == []


class TestSyncRoute:
    def test_cold_read_mints_then_reads_as_the_app(self, caplog):
        caplog.set_level(logging.DEBUG, logger="wafer")
        session, app, web = _session([_token_response(), _listing()])

        resp = session.get(_JSON_URL)

        assert resp.status_code == 200
        assert resp.json()["kind"] == "Listing"
        assert resp.emulation == REDDIT_APP_IDENTITY
        assert resp.url == _JSON_URL
        assert web.request_count == 0
        mint, read = app.request_log
        (mint_method, mint_url, mint_kw), (read_method, read_url, read_kw) = mint, read
        assert (mint_method, mint_url) == ("POST", REDDIT_APP_TOKEN_URL)
        assert (read_method, read_url) == ("GET", _API_URL)
        headers = read_kw["headers"]
        assert headers["Authorization"] == f"Bearer {_ACCESS}"
        assert headers["x-reddit-loid"] == _LOID
        assert headers["x-reddit-session"] == _SESSION
        assert headers["User-Agent"].startswith("Reddit/Version ")
        assert headers["client-vendor-id"] == mint_kw["headers"]["client-vendor-id"]
        state = session.reddit_bootstrap_state()
        assert state["app_reads"] == 1
        assert state["app_token_mints"] == 1
        assert state["app_last_outcome"] == "served"
        assert state["attempts"] == 0 and state["browser_attempts"] == 0
        for secret in (_ACCESS, _LOID, _SESSION):
            assert secret not in caplog.text
            assert secret not in repr(state)

    def test_token_is_reused_across_reads_and_sessions(self, tmp_path):
        cache = CookieCache(tmp_path)
        session, app, _ = _session(
            [_token_response(), _listing(), _listing()], cookie_cache=cache
        )
        session.get(_JSON_URL)
        session.get(_JSON_URL)
        assert [m for m, _, _ in app.request_log] == ["POST", "GET", "GET"]

        again, app2, _ = _session([_listing()], cookie_cache=cache)
        again.get(_JSON_URL)
        assert [m for m, _, _ in app2.request_log] == ["GET"]
        first = app.request_log[1][2]["headers"]
        second = app2.request_log[0][2]["headers"]
        assert first["client-vendor-id"] == second["client-vendor-id"]
        assert again.reddit_bootstrap_state()["app_token_mints"] == 0

    def test_refused_older_token_is_reminted_once(self, tmp_path):
        _store_old_token(tmp_path)
        session, app, web = _session(
            [
                _listing(status=401, body='{"message": "Unauthorized", "error": 401}'),
                _token_response(),
                _listing(),
            ],
            cookie_cache=CookieCache(tmp_path),
        )
        resp = session.get(_JSON_URL)
        assert resp.status_code == 200
        assert [m for m, _, _ in app.request_log] == ["GET", "POST", "GET"]
        assert web.request_count == 0

    def test_fresh_token_refused_is_the_endpoints_answer(self):
        """An endpoint that needs an account 401s any anonymous token: the web
        path answers it, nothing is reminted, and the route stays up."""
        unauthorized = _listing(status=401, body='{"error": 401}')
        session, app, web = _session([_token_response(), unauthorized, _listing()])
        resp = session.get("https://www.reddit.com/api/v1/me.json")
        assert resp.emulation != REDDIT_APP_IDENTITY
        assert web.request_count == 1
        assert [m for m, _, _ in app.request_log] == ["POST", "GET"]
        assert session.reddit_bootstrap_state()["app_last_outcome"] == "unauthorized"
        assert session._reddit_app_backoff_until == 0.0
        session.get(_JSON_URL)
        assert [m for m, _, _ in app.request_log] == ["POST", "GET", "GET"]

    def test_edge_gate_falls_back_and_backs_off(self):
        session, app, web = _session([_token_response(), _gate()])
        first = session.get(_JSON_URL)
        assert first.emulation != REDDIT_APP_IDENTITY
        assert web.request_count == 1
        assert session._reddit_app_backoff_until - time.monotonic() > (
            REDDIT_APP_BACKOFF_SECONDS - 60
        )
        state = session.reddit_bootstrap_state()
        assert state["app_fallbacks"] == 1
        assert state["app_last_outcome"] == "gate"
        assert state["app_last_status"] == 403

        session.get(_JSON_URL)
        assert app.request_count == 2  # the backoff kept the route idle
        assert web.request_count == 2

    def test_refused_mint_falls_back_for_the_long_backoff(self):
        session, app, web = _session([_gate()])
        resp = session.get(_JSON_URL)
        assert resp.status_code == 200
        assert web.request_count == 1
        state = session.reddit_bootstrap_state()
        assert state["app_last_outcome"] == "token"
        assert state["app_last_status"] == 403
        remaining = session._reddit_app_backoff_until - time.monotonic()
        assert remaining > REDDIT_APP_BACKOFF_SECONDS - 60

    @pytest.mark.parametrize("status", [429, 500, 503])
    def test_transient_mint_answer_backs_off_briefly(self, status):
        session, app, web = _session(
            [MockResponse(status, _JSON, '{"error": %d}' % status)]
        )
        session.get(_JSON_URL)
        assert web.request_count == 1
        state = session.reddit_bootstrap_state()
        assert state["app_last_outcome"] == "token"
        assert state["app_last_status"] == status
        remaining = session._reddit_app_backoff_until - time.monotonic()
        assert 0 < remaining <= REDDIT_APP_TRANSPORT_BACKOFF_SECONDS

    def test_mint_transport_error_backs_off_briefly(self):
        session, app, web = _session(
            [_token_response(), _listing(), ConnectionError("reset")]
        )
        session.get(_JSON_URL)
        session._reddit_app_token = None  # force a second mint
        session.get(_JSON_URL)
        assert web.request_count == 1
        state = session.reddit_bootstrap_state()
        assert state["app_last_outcome"] == "token"
        assert state["app_last_status"] is None  # not the earlier read's 200
        remaining = session._reddit_app_backoff_until - time.monotonic()
        assert 0 < remaining <= REDDIT_APP_TRANSPORT_BACKOFF_SECONDS

    def test_read_transport_error_backs_off_briefly(self):
        session, app, web = _session([_token_response(), ConnectionError("reset")])
        session.get(_JSON_URL)
        assert web.request_count == 1
        assert session.reddit_bootstrap_state()["app_last_outcome"] == "transport"
        remaining = session._reddit_app_backoff_until - time.monotonic()
        assert 0 < remaining <= REDDIT_APP_TRANSPORT_BACKOFF_SECONDS

    @pytest.mark.parametrize(
        "answer",
        [
            MockResponse(
                200,
                {"content-type": "text/html"},
                "<title>Reddit - Prove your humanity</title>",
            ),
            MockResponse(429, {"content-type": "text/html"}, "<html>slow</html>"),
        ],
    )
    def test_html_from_the_api_is_the_edge_not_content(self, answer):
        session, app, web = _session([_token_response(), answer])
        resp = session.get(_JSON_URL)
        assert resp.emulation != REDDIT_APP_IDENTITY
        assert web.request_count == 1
        assert session.reddit_bootstrap_state()["app_last_outcome"] == "gate"

    def test_api_json_error_is_returned_as_is(self):
        private = '{"reason": "private", "message": "Forbidden", "error": 403}'
        session, app, web = _session(
            [_token_response(), _listing(status=403, body=private)]
        )
        resp = session.get("https://www.reddit.com/r/secret/.json")
        assert resp.status_code == 403
        assert resp.json()["reason"] == "private"
        assert resp.emulation == REDDIT_APP_IDENTITY
        assert web.request_count == 0

    def test_redirects_are_followed_and_reported_on_the_web_host(self):
        moved = MockResponse(301, {"location": "/r/Python/.json?limit=1"})
        session, app, _ = _session([_token_response(), moved, _listing()])
        resp = session.get("https://www.reddit.com/r/python/.json?limit=1")
        assert resp.url == "https://www.reddit.com/r/Python/.json?limit=1"
        assert [(h.status_code, h.url) for h in resp.history] == [
            (301, "https://www.reddit.com/r/python/.json?limit=1")
        ]
        assert app.request_log[2][1] == "https://oauth.reddit.com/r/Python/.json?limit=1"

    def test_redirect_the_app_does_not_read_goes_to_the_web_path(self):
        away = MockResponse(302, {"location": "https://www.reddit.com/r/Python/"})
        session, app, web = _session([_token_response(), away])
        session.get(_JSON_URL)
        assert web.request_count == 1
        assert web.request_log[0][1] == _JSON_URL
        assert session._reddit_app_backoff_until == 0.0

    def test_redirect_loop_is_bounded(self):
        loop = MockResponse(301, {"location": "/r/a/.json"})
        session, _, _ = _session([_token_response(), loop], max_redirects=3)
        with pytest.raises(TooManyRedirects):
            session.get("https://www.reddit.com/r/a/.json")

    @patch("wafer._sync.time.sleep")
    def test_rate_limited_read_waits_for_the_reset(self, mock_sleep):
        limited = _listing(
            status=429,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "3"},
            body='{"message": "Too Many Requests", "error": 429}',
        )
        session, app, _ = _session([_token_response(), limited, _listing()])
        resp = session.get(_JSON_URL)
        assert resp.status_code == 200
        assert resp.retries == 1
        assert any(call.args[0] >= 3 for call in mock_sleep.call_args_list)

    @patch("wafer._sync.time.sleep")
    def test_rate_limit_past_the_deadline_goes_to_the_web(self, mock_sleep):
        limited = _listing(
            status=429,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "600"},
            body='{"error": 429}',
        )
        session, app, web = _session([_token_response(), limited])
        resp = session.get(_JSON_URL, timeout=5)
        assert resp.status_code == 200
        assert resp.emulation != REDDIT_APP_IDENTITY
        assert web.request_count == 1
        state = session.reddit_bootstrap_state()
        assert state["app_last_outcome"] == "ratelimit"
        assert session._reddit_app_backoff_until == 0.0

    @patch("wafer._sync.time.sleep")
    def test_spent_window_delays_the_next_read(self, mock_sleep):
        last = _listing(
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "7"}
        )
        session, app, web = _session([_token_response(), last, _listing()])
        session.get(_JSON_URL)
        mock_sleep.reset_mock()
        resp = session.get(_JSON_URL)
        assert mock_sleep.call_args_list and mock_sleep.call_args_list[0].args[0] > 5
        assert resp.emulation == REDDIT_APP_IDENTITY
        assert app.request_count == 3
        assert web.request_count == 0

    def test_spent_window_past_the_deadline_goes_to_the_web(self):
        """Real clock: a window that will not reset in time must not burn the
        whole timeout and raise; the web path reads meanwhile."""
        last = _listing(
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "300"}
        )
        session, app, web = _session([_token_response(), last])
        session.get(_JSON_URL)
        start = time.monotonic()
        resp = session.get(_JSON_URL, timeout=3)
        assert time.monotonic() - start < 1.0
        assert resp.status_code == 200
        assert web.request_count == 1
        assert app.request_count == 2
        assert session.reddit_bootstrap_state()["app_last_outcome"] == "ratelimit"

    @patch("wafer._sync.time.sleep")
    def test_server_error_is_retried(self, mock_sleep):
        session, app, _ = _session(
            [_token_response(), _listing(status=503, body='{"error": 503}'), _listing()]
        )
        resp = session.get(_JSON_URL)
        assert resp.status_code == 200
        assert resp.retries == 1

    def test_redirect_not_followed_reports_the_callers_host(self):
        moved = MockResponse(301, {"location": "/r/Python/.json?limit=1"})
        session, app, _ = _session(
            [_token_response(), moved], follow_redirects=False
        )
        resp = session.get("https://www.reddit.com/r/python/.json?limit=1")
        assert resp.status_code == 301
        assert resp.headers["location"] == (
            "https://www.reddit.com/r/Python/.json?limit=1"
        )

    def test_response_size_cap_applies(self):
        session, _, _ = _session([_token_response(), _listing(body="x" * 5000)])
        with pytest.raises(ResponseTooLarge):
            session.get(_JSON_URL, max_response_size=1000)

    @pytest.mark.parametrize(
        ("method", "kwargs"),
        [
            ("POST", {}),
            ("GET", {"headers": {"Authorization": "Bearer mine"}}),
            ("GET", {"headers": {"cookie": "reddit_session=x"}}),
            ("GET", {"body": b"x"}),
        ],
    )
    def test_requests_for_an_account_or_with_a_body_stay_on_the_web(
        self, method, kwargs
    ):
        session, app, web = _session([_token_response(), _listing()])
        session.request(method, _JSON_URL, **kwargs)
        assert app.request_count == 0
        assert web.request_count == 1

    @pytest.mark.parametrize(
        "session_headers",
        [{"Authorization": "Bearer mine"}, {"Cookie": "reddit_session=abc"}],
    )
    def test_session_account_headers_stay_on_the_web(self, session_headers):
        session, app, web = _session([_token_response(), _listing()])
        session._user_headers = True
        session.headers = dict(session.headers, **session_headers)
        session.get(_JSON_URL)
        assert app.request_count == 0
        assert web.request_count == 1

    def test_logged_in_jar_stays_on_the_web(self):
        session, app, web = _session(
            [_token_response(), _listing()], use_cookie_jar=True
        )
        session._client.cookie_jar.add(
            "reddit_session=abc; Domain=reddit.com; Path=/", "https://www.reddit.com/"
        )
        session.get(_JSON_URL)
        assert app.request_count == 0
        assert web.request_count == 1

    def test_anonymous_jar_still_uses_the_app(self):
        session, app, web = _session(
            [_token_response(), _listing()], use_cookie_jar=True
        )
        session._client.cookie_jar.add(
            "loid=anon; Domain=reddit.com; Path=/", "https://www.reddit.com/"
        )
        session.get(_JSON_URL)
        assert app.request_count == 2
        assert web.request_count == 0

    def test_html_pages_stay_on_the_web(self):
        session, app, web = _session(
            [_token_response()],
            [MockResponse(200, {"content-type": "text/html"}, "<html>ok</html>")],
        )
        session.get("https://www.reddit.com/r/Python/")
        assert app.request_count == 0

    def test_resolve_pins_must_cover_the_app_hosts(self):
        session, app, web = _session(
            [_token_response(), _listing()],
            resolve={"www.reddit.com": ["151.101.1.140"]},
        )
        session.get(_JSON_URL)
        assert app.request_count == 0

        pinned, app2, _ = _session(
            [_token_response(), _listing()],
            resolve={
                "www.reddit.com": ["151.101.1.140"],
                "oauth.reddit.com": ["151.101.1.140"],
            },
        )
        pinned.get(_JSON_URL)
        assert app2.request_count == 2


class TestAsyncRoute:
    async def test_cold_read(self):
        session, app, web = _async_session(
            [_token_response(AsyncMockResponse), _listing(AsyncMockResponse)]
        )
        resp = await session.get(_JSON_URL)
        assert resp.status_code == 200
        assert resp.emulation == REDDIT_APP_IDENTITY
        assert web.request_count == 0
        assert session.reddit_bootstrap_state()["app_token_mints"] == 1

    async def test_concurrent_cold_reads_share_one_mint(self):
        session, app, _ = _async_session(
            [_token_response(AsyncMockResponse)]
            + [_listing(AsyncMockResponse) for _ in range(3)]
        )
        results = await asyncio.gather(*(session.get(_JSON_URL) for _ in range(3)))
        assert all(r.status_code == 200 for r in results)
        assert [m for m, _, _ in app.request_log].count("POST") == 1

    async def test_edge_gate_falls_back(self):
        session, app, web = _async_session(
            [_token_response(AsyncMockResponse), _gate(AsyncMockResponse)]
        )
        resp = await session.get(_JSON_URL)
        assert resp.emulation != REDDIT_APP_IDENTITY
        assert web.request_count == 1
        assert session.reddit_bootstrap_state()["app_last_outcome"] == "gate"

    async def test_refused_older_token_is_reminted_once(self, tmp_path):
        _store_old_token(tmp_path)
        session, app, _ = _async_session(
            [
                _listing(AsyncMockResponse, status=401, body='{"error": 401}'),
                _token_response(AsyncMockResponse),
                _listing(AsyncMockResponse),
            ],
            cookie_cache=CookieCache(tmp_path),
        )
        resp = await session.get(_JSON_URL)
        assert resp.status_code == 200
        assert [m for m, _, _ in app.request_log] == ["GET", "POST", "GET"]

    @patch("wafer._async.asyncio.sleep")
    async def test_rate_limited_read_waits_for_the_reset(self, mock_sleep):
        limited = _listing(
            AsyncMockResponse,
            status=429,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "3"},
            body='{"error": 429}',
        )
        session, app, _ = _async_session(
            [_token_response(AsyncMockResponse), limited, _listing(AsyncMockResponse)]
        )
        resp = await session.get(_JSON_URL)
        assert resp.status_code == 200
        assert resp.retries == 1

    async def test_redirects_are_followed(self):
        moved = AsyncMockResponse(301, {"location": "/r/Python/.json"})
        session, app, _ = _async_session(
            [_token_response(AsyncMockResponse), moved, _listing(AsyncMockResponse)]
        )
        resp = await session.get("https://www.reddit.com/r/python/.json")
        assert resp.url == "https://www.reddit.com/r/Python/.json"
        assert [h.status_code for h in resp.history] == [301]

    async def test_spent_window_past_the_deadline_goes_to_the_web(self):
        last = _listing(
            AsyncMockResponse,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "300"},
        )
        session, app, web = _async_session([_token_response(AsyncMockResponse), last])
        await session.get(_JSON_URL)
        start = time.monotonic()
        resp = await session.get(_JSON_URL, timeout=3)
        assert time.monotonic() - start < 1.0
        assert resp.status_code == 200
        assert web.request_count == 1
        assert session.reddit_bootstrap_state()["app_last_outcome"] == "ratelimit"

    async def test_html_from_the_api_is_the_edge(self):
        page = AsyncMockResponse(200, {"content-type": "text/html"}, "<html>x</html>")
        session, app, web = _async_session([_token_response(AsyncMockResponse), page])
        resp = await session.get(_JSON_URL)
        assert resp.emulation != REDDIT_APP_IDENTITY
        assert web.request_count == 1


class TestConstruction:
    def test_on_by_default_and_opt_out(self):
        from wafer import Profile, SyncSession

        with SyncSession() as on:
            assert on._reddit_app_enabled
        with SyncSession(reddit_app=False) as off:
            assert not off._reddit_app_enabled
            assert off._reddit_app_target("GET", _JSON_URL, None, {}) is None
        with SyncSession(profile=Profile.OPERA_MINI) as opera:
            assert not opera._reddit_app_enabled

    def test_app_client_is_chromium_android_without_browser_headers(self):
        from wafer import SyncSession

        with SyncSession(proxy="http://127.0.0.1:9") as session:
            kwargs = session._reddit_app_client_kwargs()
            assert session._proxy is not None
            assert kwargs["cookie_store"] is False
            assert kwargs["proxies"] == [session._proxy]
            assert "headers" not in kwargs
            assert "orig_headers" not in kwargs

    def test_app_client_emulation(self):
        from wreq import Platform

        from wafer import SyncSession
        from wafer._base import DEFAULT_EMULATION

        with SyncSession() as session:
            with patch("wafer._base.Emulation") as emulation:
                session._reddit_app_client_kwargs()
        emulation.assert_called_once_with(
            profile=DEFAULT_EMULATION, platform=Platform.Android, headers=False
        )
