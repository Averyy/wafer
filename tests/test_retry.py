"""Tests for retry logic, backoff, and separate counters."""

from unittest.mock import patch

import pytest

from tests.conftest import (
    MockResponse,
    make_async_session,
    make_sync_session,
)
from wafer._errors import (
    ChallengeDetected,
    ConnectionFailed,
    EmptyResponse,
    RateLimited,
    TooManyRedirects,
)
from wafer._retry import RetryState, calculate_backoff, parse_retry_after

# ---------------------------------------------------------------------------
# parse_retry_after
# ---------------------------------------------------------------------------


class TestParseRetryAfter:
    def test_integer_seconds(self):
        assert parse_retry_after("120") == 120.0

    def test_zero_seconds(self):
        assert parse_retry_after("0") == 0.0

    def test_negative_clamped_to_zero(self):
        assert parse_retry_after("-5") == 0.0

    def test_empty_string(self):
        assert parse_retry_after("") is None

    def test_garbage(self):
        assert parse_retry_after("not-a-number") is None

    def test_http_date(self):
        # Use a date in the past → clamped to 0
        result = parse_retry_after(
            "Sun, 06 Nov 1994 08:49:37 GMT"
        )
        assert result == 0.0

    def test_none_like_empty(self):
        assert parse_retry_after("") is None


# ---------------------------------------------------------------------------
# calculate_backoff
# ---------------------------------------------------------------------------


class TestCalculateBackoff:
    def test_first_attempt_near_base(self):
        with patch("wafer._retry.random.uniform", return_value=0):
            delay = calculate_backoff(0, base=1.0)
            assert delay == 1.0

    def test_exponential_growth(self):
        with patch("wafer._retry.random.uniform", return_value=0):
            assert calculate_backoff(0, base=1.0) == 1.0
            assert calculate_backoff(1, base=1.0) == 2.0
            assert calculate_backoff(2, base=1.0) == 4.0
            assert calculate_backoff(3, base=1.0) == 8.0

    def test_max_delay_cap(self):
        with patch("wafer._retry.random.uniform", return_value=0):
            delay = calculate_backoff(10, base=1.0, max_delay=30.0)
            assert delay == 30.0

    def test_jitter_adds_positive(self):
        with patch(
            "wafer._retry.random.uniform", return_value=0.25
        ):
            delay = calculate_backoff(0, base=1.0)
            assert delay == 1.25


# ---------------------------------------------------------------------------
# RetryState
# ---------------------------------------------------------------------------


class TestRetryState:
    def test_initial_state(self):
        state = RetryState(max_retries=3, max_rotations=10)
        assert state.can_retry
        assert state.can_rotate
        assert state.normal_retries == 0
        assert state.rotation_retries == 0

    def test_exhaust_retries(self):
        state = RetryState(max_retries=2, max_rotations=10)
        state.use_retry()
        state.use_retry()
        assert not state.can_retry
        assert state.can_rotate  # independent

    def test_exhaust_rotations(self):
        state = RetryState(max_retries=3, max_rotations=2)
        state.use_rotation()
        state.use_rotation()
        assert not state.can_rotate
        assert state.can_retry  # independent

    def test_counters_independent(self):
        state = RetryState(max_retries=1, max_rotations=1)
        state.use_retry()
        assert not state.can_retry
        assert state.can_rotate
        state.use_rotation()
        assert not state.can_rotate
        assert not state.can_retry


# ---------------------------------------------------------------------------
# SyncSession retry loop
# ---------------------------------------------------------------------------


@patch("wafer._sync.time.sleep")
class TestSyncRetryLoop:
    def test_success_no_retry(self, mock_sleep):
        session, mock = make_sync_session([
            MockResponse(200, body="OK"),
        ])
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        assert mock.request_count == 1
        mock_sleep.assert_not_called()

    def test_403_403_200_rotation_success(self, mock_sleep):
        session, mock = make_sync_session([
            MockResponse(403, body="Denied"),
            MockResponse(403, body="Denied"),
            MockResponse(200, body="<html>Real content</html>"),
        ])
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        assert resp.text == "<html>Real content</html>"
        assert mock.request_count == 3

    def test_403_rotates_fingerprint(self, mock_sleep):
        session, mock = make_sync_session([
            MockResponse(403, body="Denied"),
            MockResponse(200, body="OK"),
        ])
        session.get("https://example.com")
        # Should have rotated and pinned after success
        assert session._fingerprint.pinned

    def test_403_pins_fingerprint_after_success(self, mock_sleep):
        session, mock = make_sync_session([
            MockResponse(403, body="Denied"),
            MockResponse(200, body="OK"),
        ])
        assert not session._fingerprint.pinned
        session.get("https://example.com")
        assert session._fingerprint.pinned

    def test_no_pin_without_rotation(self, mock_sleep):
        session, mock = make_sync_session([
            MockResponse(200, body="OK"),
        ])
        session.get("https://example.com")
        assert not session._fingerprint.pinned

    def test_429_with_retry_after(self, mock_sleep):
        session, mock = make_sync_session([
            MockResponse(
                429,
                headers={"Retry-After": "5"},
                body="Rate limited",
            ),
            MockResponse(200, body="OK"),
        ])
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        assert mock.request_count == 2
        # Should have waited 5 seconds
        mock_sleep.assert_any_call(5.0)

    def test_429_without_retry_after_uses_backoff(self, mock_sleep):
        session, mock = make_sync_session([
            MockResponse(429, body="Rate limited"),
            MockResponse(200, body="OK"),
        ])
        session.get("https://example.com")
        assert mock.request_count == 2
        # Should have called sleep with some backoff value
        assert mock_sleep.call_count >= 1

    def test_5xx_backoff_retry(self, mock_sleep):
        session, mock = make_sync_session([
            MockResponse(503, body="Unavailable"),
            MockResponse(503, body="Unavailable"),
            MockResponse(200, body="OK"),
        ])
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        assert mock.request_count == 3

    def test_5xx_exhausted_returns_response(self, mock_sleep):
        session, mock = make_sync_session(
            [
                MockResponse(503, body="Unavailable"),
                MockResponse(503, body="Unavailable"),
                MockResponse(503, body="Unavailable"),
                MockResponse(503, body="Still unavailable"),
            ],
            max_retries=3,
        )
        resp = session.get("https://example.com")
        # Returns the last 503 response when retries exhausted
        assert resp.status_code == 503

    def test_empty_200_retries(self, mock_sleep):
        session, mock = make_sync_session([
            MockResponse(200, body=""),
            MockResponse(200, body="   "),
            MockResponse(200, body="Real content"),
        ])
        resp = session.get("https://example.com")
        assert resp.text == "Real content"
        assert mock.request_count == 3

    def test_empty_200_exhausted_raises(self, mock_sleep):
        session, mock = make_sync_session(
            [
                MockResponse(200, body=""),
                MockResponse(200, body=""),
                MockResponse(200, body=""),
                MockResponse(200, body=""),
            ],
            max_retries=3,
        )
        with pytest.raises(EmptyResponse):
            session.get("https://example.com")

    def test_connection_error_retries(self, mock_sleep):
        session, mock = make_sync_session([
            ConnectionError("refused"),
            ConnectionError("refused"),
            MockResponse(200, body="OK"),
        ])
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        assert mock.request_count == 3

    def test_connection_error_exhausted_raises(self, mock_sleep):
        session, mock = make_sync_session(
            [
                ConnectionError("refused"),
                ConnectionError("refused"),
                ConnectionError("refused"),
                ConnectionError("refused"),
            ],
            max_retries=3,
        )
        with pytest.raises(ConnectionFailed):
            session.get("https://example.com")

    def test_challenge_detected_rotates(self, mock_sleep):
        session, mock = make_sync_session([
            MockResponse(
                403,
                headers={"cf-mitigated": "challenge"},
                body="<html>CF challenge</html>",
            ),
            MockResponse(200, body="OK"),
        ])
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        assert mock.request_count == 2

    def test_challenge_exhausted_raises(self, mock_sleep):
        session, mock = make_sync_session(
            [
                MockResponse(
                    403,
                    headers={"cf-mitigated": "challenge"},
                    body="CF challenge",
                ),
            ]
            * 15,
            max_rotations=3,
        )
        with pytest.raises(ChallengeDetected) as exc_info:
            session.get("https://example.com")
        assert exc_info.value.challenge_type == "cloudflare"

    def test_429_exhausted_raises(self, mock_sleep):
        session, mock = make_sync_session(
            [MockResponse(429, body="Rate limited")] * 15,
            max_rotations=3,
        )
        with pytest.raises(RateLimited):
            session.get("https://example.com")

    def test_separate_counters_5xx_then_403(self, mock_sleep):
        """5xx uses normal retries, 403 uses rotation retries — independent."""
        session, mock = make_sync_session(
            [
                # Use up normal retries
                MockResponse(503, body="Error"),
                MockResponse(503, body="Error"),
                MockResponse(503, body="Error"),
                # Now 403 — should still have rotation retries
                MockResponse(403, body="Denied"),
                MockResponse(200, body="OK"),
            ],
            max_retries=3,
            max_rotations=10,
        )
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        assert mock.request_count == 5

    def test_challenge_on_non_403_status(self, mock_sleep):
        """Challenge detected on non-403 status (e.g., 202 AWS WAF)."""
        session, mock = make_sync_session([
            MockResponse(
                202,
                headers={"x-amzn-waf-action": "challenge"},
                body="<script>gokuProps</script>",
            ),
            MockResponse(200, body="Real page"),
        ])
        resp = session.get("https://example.com")
        assert resp.status_code == 200

    def test_datadome_cookie_challenge(self, mock_sleep):
        session, mock = make_sync_session([
            MockResponse(
                403,
                headers={"Set-Cookie": "datadome=abc123; Path=/"},
                body="",
            ),
            MockResponse(200, body="OK"),
        ])
        resp = session.get("https://example.com")
        assert resp.status_code == 200

    def test_multi_set_cookie_challenge_detected(self, mock_sleep):
        """Challenge detected when WAF cookie is in second Set-Cookie header."""
        resp403 = MockResponse(403, body="")
        # Simulate two Set-Cookie headers: one benign, one datadome
        resp403.headers._raw[b"set-cookie"] = [
            b"session_id=abc; Path=/",
            b"datadome=xyz; Path=/",
        ]
        session, mock = make_sync_session([
            resp403,
            MockResponse(200, body="OK"),
        ])
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        assert mock.request_count == 2

    def test_post_uses_retry_loop(self, mock_sleep):
        session, mock = make_sync_session([
            MockResponse(503, body="Error"),
            MockResponse(200, body='{"ok": true}'),
        ])
        resp = session.post("https://example.com/api")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# AsyncSession retry loop (basic tests)
# ---------------------------------------------------------------------------


class TestAsyncRetryLoop:
    @pytest.mark.asyncio
    async def test_success_no_retry(self):
        session, mock = make_async_session([
            MockResponse(200, body="OK"),
        ])
        with patch("wafer._async.asyncio.sleep", return_value=None):
            resp = await session.get("https://example.com")
        assert resp.status_code == 200
        assert mock.request_count == 1

    @pytest.mark.asyncio
    async def test_403_rotation_success(self):
        session, mock = make_async_session([
            MockResponse(403, body="Denied"),
            MockResponse(200, body="OK"),
        ])
        with patch("wafer._async.asyncio.sleep", return_value=None):
            resp = await session.get("https://example.com")
        assert resp.status_code == 200
        assert mock.request_count == 2

    @pytest.mark.asyncio
    async def test_5xx_backoff(self):
        session, mock = make_async_session([
            MockResponse(500, body="Error"),
            MockResponse(200, body="OK"),
        ])
        with patch("wafer._async.asyncio.sleep", return_value=None):
            resp = await session.get("https://example.com")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_connection_error_retry(self):
        session, mock = make_async_session([
            ConnectionError("refused"),
            MockResponse(200, body="OK"),
        ])
        with patch("wafer._async.asyncio.sleep", return_value=None):
            resp = await session.get("https://example.com")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_empty_body_retry(self):
        session, mock = make_async_session([
            MockResponse(200, body=""),
            MockResponse(200, body="Content"),
        ])
        with patch("wafer._async.asyncio.sleep", return_value=None):
            resp = await session.get("https://example.com")
        assert resp.text == "Content"

    @pytest.mark.asyncio
    async def test_challenge_exhausted_raises(self):
        session, mock = make_async_session(
            [
                MockResponse(
                    403,
                    headers={"cf-mitigated": "challenge"},
                    body="CF",
                ),
            ]
            * 5,
            max_rotations=2,
        )
        with patch("wafer._async.asyncio.sleep", return_value=None):
            with pytest.raises(ChallengeDetected):
                await session.get("https://example.com")


# ---------------------------------------------------------------------------
# _decode_headers
# ---------------------------------------------------------------------------


class TestDecodeHeaders:
    def test_bytes_keys_and_values(self):
        from tests.conftest import MockHeaderMap
        from wafer._base import _decode_headers

        hmap = MockHeaderMap({"Content-Type": "text/html"})
        result = _decode_headers(hmap)
        assert result["content-type"] == "text/html"

    def test_lowercase_keys(self):
        from tests.conftest import MockHeaderMap
        from wafer._base import _decode_headers

        hmap = MockHeaderMap({"X-Custom-Header": "value"})
        result = _decode_headers(hmap)
        assert "x-custom-header" in result

    def test_empty_headers(self):
        from tests.conftest import MockHeaderMap
        from wafer._base import _decode_headers

        hmap = MockHeaderMap({})
        result = _decode_headers(hmap)
        assert result == {}

    def test_multi_value_set_cookie(self):
        """Multiple Set-Cookie values are joined with '; '."""
        from tests.conftest import MockHeaderMap
        from wafer._base import _decode_headers

        hmap = MockHeaderMap({})
        # Manually add multiple values for set-cookie
        hmap._raw[b"set-cookie"] = [
            b"datadome=abc; Path=/",
            b"_abck=xyz; Path=/",
        ]
        result = _decode_headers(hmap)
        assert "datadome" in result["set-cookie"]
        assert "_abck" in result["set-cookie"]

    def test_single_value_not_list_joined(self):
        from tests.conftest import MockHeaderMap
        from wafer._base import _decode_headers

        hmap = MockHeaderMap({"content-type": "text/html"})
        result = _decode_headers(hmap)
        # Single value should not have "; " separator
        assert result["content-type"] == "text/html"


# ---------------------------------------------------------------------------
# Redirect following tests
# ---------------------------------------------------------------------------


class TestResolveRedirectURL:
    """Unit tests for BaseSession._resolve_redirect_url."""

    def test_absolute_url(self):
        from wafer._base import BaseSession

        result = BaseSession._resolve_redirect_url(
            "https://example.com/page",
            "https://other.com/new",
        )
        assert result == "https://other.com/new"

    def test_protocol_relative_url(self):
        from wafer._base import BaseSession

        result = BaseSession._resolve_redirect_url(
            "https://www.indeed.com",
            "//ca.indeed.com?r=us",
        )
        assert result == "https://ca.indeed.com/?r=us"

    def test_relative_path(self):
        from wafer._base import BaseSession

        result = BaseSession._resolve_redirect_url(
            "https://example.com/old/page",
            "/new/page",
        )
        assert result == "https://example.com/new/page"

    def test_empty_path_gets_slash(self):
        from wafer._base import BaseSession

        result = BaseSession._resolve_redirect_url(
            "https://example.com/page",
            "https://other.com",
        )
        assert result == "https://other.com/"

    def test_preserves_query_string(self):
        from wafer._base import BaseSession

        result = BaseSession._resolve_redirect_url(
            "https://example.com",
            "/page?foo=bar&baz=1",
        )
        assert result == "https://example.com/page?foo=bar&baz=1"

    def test_protocol_relative_inherits_http(self):
        from wafer._base import BaseSession

        result = BaseSession._resolve_redirect_url(
            "http://example.com/page",
            "//other.com/path",
        )
        assert result == "http://other.com/path"


class TestRedirectFollowing:
    """Integration tests for 3xx redirect handling in the retry loop."""

    @patch("wafer._sync.time.sleep")
    def test_follows_301_redirect(self, mock_sleep):
        redirect_resp = MockResponse(
            301,
            {"location": "https://example.com/new"},
            "",
        )
        ok_resp = MockResponse(200, body="<html>Final</html>")
        session, mock = make_sync_session([redirect_resp, ok_resp])
        resp = session.get("https://example.com/old")
        assert resp.status_code == 200
        assert resp.text == "<html>Final</html>"
        assert mock.request_count == 2

    @patch("wafer._sync.time.sleep")
    def test_follows_302_redirect(self, mock_sleep):
        redirect_resp = MockResponse(
            302,
            {"location": "https://example.com/new"},
            "",
        )
        ok_resp = MockResponse(200, body="<html>Final</html>")
        session, mock = make_sync_session([redirect_resp, ok_resp])
        resp = session.get("https://example.com/old")
        assert resp.status_code == 200

    @patch("wafer._sync.time.sleep")
    def test_follows_multiple_redirects(self, mock_sleep):
        r1 = MockResponse(
            301, {"location": "https://a.com/step1"}, ""
        )
        r2 = MockResponse(
            302, {"location": "https://b.com/step2"}, ""
        )
        ok = MockResponse(200, body="<html>Done</html>")
        session, mock = make_sync_session([r1, r2, ok])
        resp = session.get("https://start.com/")
        assert resp.status_code == 200
        assert mock.request_count == 3

    @patch("wafer._sync.time.sleep")
    def test_too_many_redirects_raises(self, mock_sleep):
        redirects = [
            MockResponse(
                301,
                {"location": f"https://example.com/{i}"},
                "",
            )
            for i in range(5)
        ]
        session, _ = make_sync_session(
            redirects, max_redirects=3
        )
        with pytest.raises(TooManyRedirects) as exc_info:
            session.get("https://example.com/start")
        assert exc_info.value.max_redirects == 3

    @patch("wafer._sync.time.sleep")
    def test_follow_redirects_disabled(self, mock_sleep):
        redirect_resp = MockResponse(
            301,
            {"location": "https://example.com/new"},
            "",
        )
        session, _ = make_sync_session(
            [redirect_resp], follow_redirects=False
        )
        # With follow_redirects=False, 301 goes to challenge
        # detection, which returns it directly (no challenge markers)
        resp = session.get("https://example.com/old")
        assert resp.status_code == 301

    @patch("wafer._sync.time.sleep")
    def test_304_not_followed(self, mock_sleep):
        """304 Not Modified should NOT be treated as a redirect."""
        resp_304 = MockResponse(304, body="")
        session, _ = make_sync_session([resp_304])
        resp = session.get("https://example.com/cached")
        assert resp.status_code == 304


# ---------------------------------------------------------------------------
# WaferResponse field tests
# ---------------------------------------------------------------------------


@patch("wafer._sync.time.sleep")
class TestWaferResponseFields:
    def test_was_retried_true_after_retry(self, mock_sleep):
        """was_retried should be True when the response required retries."""
        session, mock = make_sync_session([
            MockResponse(500, body="Error"),
            MockResponse(200, body="OK"),
        ])
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        assert resp.was_retried is True

    def test_was_retried_false_on_first_success(self, mock_sleep):
        """was_retried should be False when first attempt succeeds."""
        session, mock = make_sync_session([
            MockResponse(200, body="OK"),
        ])
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        assert resp.was_retried is False

    def test_elapsed_positive(self, mock_sleep):
        """elapsed should be > 0 even in mocked tests."""
        session, _ = make_sync_session([
            MockResponse(200, body="OK"),
        ])
        resp = session.get("https://example.com")
        assert resp.elapsed > 0

    def test_url_tracks_redirects(self, mock_sleep):
        """url should reflect the final URL after redirects."""
        session, _ = make_sync_session([
            MockResponse(
                301,
                headers={"Location": "https://example.com/final"},
                body="",
            ),
            MockResponse(200, body="ok"),
        ])
        resp = session.get("https://example.com/start")
        assert resp.url == "https://example.com/final"

    def test_response_text_is_str(self, mock_sleep):
        """resp.text should be a str."""
        session, _ = make_sync_session([
            MockResponse(200, body="hello"),
        ])
        resp = session.get("https://example.com")
        assert resp.text == "hello"
        assert isinstance(resp.text, str)

    def test_response_headers_is_dict(self, mock_sleep):
        """resp.headers should be a dict."""
        session, _ = make_sync_session([
            MockResponse(
                200,
                headers={"X-Test": "value"},
                body="ok",
            ),
        ])
        resp = session.get("https://example.com")
        assert isinstance(resp.headers, dict)
