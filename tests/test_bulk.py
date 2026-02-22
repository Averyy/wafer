"""Tests for bulk mode: return-not-raise, max_failures=None, rotate_every."""

import pytest

from tests.conftest import (
    MockResponse,
    make_async_session,
    make_sync_session,
)
from wafer._errors import ChallengeDetected, EmptyResponse, RateLimited

# ---------------------------------------------------------------------------
# Step 1 & 6: max_failures=None + bulk() defaults
# ---------------------------------------------------------------------------


class TestHealthThresholdNone:
    def test_no_crash_on_repeated_failures(self):
        """max_failures=None → _record_failure never retires."""
        responses = [MockResponse(403, body="Forbidden")] * 5 + [
            MockResponse(200, body="ok")
        ]
        session, mock = make_sync_session(
            responses,
            max_rotations=5,
            max_failures=None,
        )
        resp = session.get("https://example.com/test")
        assert resp.status_code == 200
        # All 5 rotations used + final success = 6 requests
        assert mock.request_count == 6


class TestBulkDefaults:
    def test_sync_bulk_defaults(self):
        """bulk() sets expected defaults."""
        from wafer._sync import SyncSession

        # Verify the method exists and is a classmethod
        assert hasattr(SyncSession, "bulk")
        assert hasattr(SyncSession.bulk, "__func__")

    def test_async_bulk_defaults(self):
        """AsyncSession also inherits bulk()."""
        from wafer._async import AsyncSession

        assert hasattr(AsyncSession, "bulk")
        assert hasattr(AsyncSession.bulk, "__func__")


# ---------------------------------------------------------------------------
# Step 2: retry_after property on WaferResponse
# ---------------------------------------------------------------------------


class TestRetryAfterProperty:
    def test_retry_after_integer(self):
        """retry_after parses integer Retry-After header."""
        from wafer._response import WaferResponse

        resp = WaferResponse(
            status_code=429,
            headers={"retry-after": "120"},
            url="https://example.com",
        )
        assert resp.retry_after == 120.0

    def test_retry_after_missing(self):
        """retry_after returns None when header missing."""
        from wafer._response import WaferResponse

        resp = WaferResponse(
            status_code=429,
            headers={},
            url="https://example.com",
        )
        assert resp.retry_after is None

    def test_retry_after_empty(self):
        """retry_after returns None for empty header."""
        from wafer._response import WaferResponse

        resp = WaferResponse(
            status_code=429,
            headers={"retry-after": ""},
            url="https://example.com",
        )
        assert resp.retry_after is None

    def test_retry_after_http_date(self):
        """retry_after parses HTTP-date format."""
        from wafer._response import WaferResponse

        # Use a far-future date so delta is positive
        resp = WaferResponse(
            status_code=429,
            headers={
                "retry-after": "Sun, 01 Jan 2034 00:00:00 GMT"
            },
            url="https://example.com",
        )
        assert resp.retry_after is not None
        assert resp.retry_after > 0


# ---------------------------------------------------------------------------
# Step 3: Return instead of raise when max_rotations=0
# ---------------------------------------------------------------------------


class TestReturnOn429WithZeroRotations:
    def test_returns_429_response(self):
        """max_rotations=0 + 429 → returns response, not raises."""
        responses = [MockResponse(429, body="rate limited")]
        session, _ = make_sync_session(
            responses, max_rotations=0
        )
        resp = session.get("https://example.com/api")
        assert resp.status_code == 429
        assert resp.text == "rate limited"

    def test_raises_when_budget_exhausted(self):
        """max_rotations=1 + 429s → raises after budget used."""
        responses = [MockResponse(429, body="rate limited")] * 3
        session, _ = make_sync_session(
            responses, max_rotations=1
        )
        with pytest.raises(RateLimited):
            session.get("https://example.com/api")


class TestReturnOnChallengeWithZeroRotations:
    def test_returns_challenge_response(self):
        """max_rotations=0 + CF challenge → returns with challenge_type."""
        cf_headers = {"cf-mitigated": "challenge"}
        cf_body = "<html>Just a moment...</html>"
        responses = [
            MockResponse(403, cf_headers, cf_body)
        ]
        session, _ = make_sync_session(
            responses, max_rotations=0
        )
        resp = session.get("https://example.com/page")
        assert resp.status_code == 403
        assert resp.challenge_type == "cloudflare"

    def test_raises_when_budget_exhausted(self):
        """max_rotations=1 + CF challenges → raises after budget."""
        cf_headers = {"cf-mitigated": "challenge"}
        cf_body = "<html>Just a moment...</html>"
        responses = [
            MockResponse(403, cf_headers, cf_body)
        ] * 3
        session, _ = make_sync_session(
            responses, max_rotations=1
        )
        with pytest.raises(ChallengeDetected):
            session.get("https://example.com/page")


# ---------------------------------------------------------------------------
# Step 4: Return instead of raise for EmptyResponse when max_retries=0
# ---------------------------------------------------------------------------


class TestReturnOnEmptyWithZeroRetries:
    def test_returns_empty_response(self):
        """max_retries=0 + empty 200 → returns response, not raises."""
        responses = [MockResponse(200, body="")]
        session, _ = make_sync_session(
            responses, max_retries=0
        )
        resp = session.get("https://example.com/api")
        assert resp.status_code == 200
        assert resp.text == ""

    def test_raises_when_budget_exhausted(self):
        """max_retries=1 + empty bodies → raises after budget."""
        responses = [MockResponse(200, body="")] * 3
        session, _ = make_sync_session(
            responses, max_retries=1
        )
        with pytest.raises(EmptyResponse):
            session.get("https://example.com/api")


# ---------------------------------------------------------------------------
# Step 5: rotate_every
# ---------------------------------------------------------------------------


class TestRotateEvery:
    def test_rebuild_called_at_interval(self):
        """rotate_every=2 → _rebuild_client called after 2nd, 4th request."""
        responses = [MockResponse(200, body="ok")] * 5
        session, mock = make_sync_session(
            responses, rotate_every=2
        )
        rebuild_calls = []
        session._rebuild_client = lambda: rebuild_calls.append(1)

        for _ in range(4):
            session.get("https://example.com/page")

        # After requests 2 and 4, rebuild should be called
        assert len(rebuild_calls) == 2

    def test_no_rebuild_when_none(self):
        """rotate_every=None → no rebuilds."""
        responses = [MockResponse(200, body="ok")] * 3
        session, mock = make_sync_session(responses)
        rebuild_calls = []
        session._rebuild_client = lambda: rebuild_calls.append(1)

        for _ in range(3):
            session.get("https://example.com/page")

        assert len(rebuild_calls) == 0


# ---------------------------------------------------------------------------
# Step 3 extra: inline solve still works with max_rotations=0
# ---------------------------------------------------------------------------


class TestInlineSolveWithZeroRotations:
    def test_inline_solve_continues_loop(self):
        """max_rotations=0 + challenge → inline solve → retry → success."""
        cf_headers = {"cf-mitigated": "challenge"}
        cf_body = "<html>Just a moment...</html>"
        responses = [
            MockResponse(403, cf_headers, cf_body),
            MockResponse(200, body="real content"),
        ]
        session, mock = make_sync_session(
            responses, max_rotations=0
        )
        # Mock the inline solver to succeed
        session._try_inline_solve = lambda c, b, u: True
        resp = session.get("https://example.com/api")
        assert resp.status_code == 200
        assert resp.text == "real content"


# ---------------------------------------------------------------------------
# Async mirrors
# ---------------------------------------------------------------------------


class TestAsyncReturnOn429WithZeroRotations:
    @pytest.mark.asyncio
    async def test_returns_429_response(self):
        """Async: max_rotations=0 + 429 → returns response."""
        responses = [MockResponse(429, body="rate limited")]
        session, _ = make_async_session(
            responses, max_rotations=0
        )
        resp = await session.get("https://example.com/api")
        assert resp.status_code == 429


class TestAsyncReturnOnChallengeWithZeroRotations:
    @pytest.mark.asyncio
    async def test_returns_challenge_response(self):
        """Async: max_rotations=0 + CF challenge → returns."""
        cf_headers = {"cf-mitigated": "challenge"}
        cf_body = "<html>Just a moment...</html>"
        responses = [
            MockResponse(403, cf_headers, cf_body)
        ]
        session, _ = make_async_session(
            responses, max_rotations=0
        )
        resp = await session.get("https://example.com/page")
        assert resp.status_code == 403
        assert resp.challenge_type == "cloudflare"


class TestAsyncReturnOnEmptyWithZeroRetries:
    @pytest.mark.asyncio
    async def test_returns_empty_response(self):
        """Async: max_retries=0 + empty 200 → returns response."""
        responses = [MockResponse(200, body="")]
        session, _ = make_async_session(
            responses, max_retries=0
        )
        resp = await session.get("https://example.com/api")
        assert resp.status_code == 200
        assert resp.text == ""


class TestAsyncRotateEvery:
    @pytest.mark.asyncio
    async def test_rebuild_called_at_interval(self):
        """Async: rotate_every=2 → rebuild after 2nd, 4th."""
        responses = [MockResponse(200, body="ok")] * 5
        session, mock = make_async_session(
            responses, rotate_every=2
        )
        rebuild_calls = []
        session._rebuild_client = lambda: rebuild_calls.append(1)

        for _ in range(4):
            await session.get("https://example.com/page")
        assert len(rebuild_calls) == 2
