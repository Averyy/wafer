"""Tests for rate limiting and session health (increment 7)."""

import time
from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import (
    MockResponse,
    make_async_session,
    make_sync_session,
)
from wafer._errors import ChallengeDetected, RateLimited
from wafer._ratelimit import RateLimiter

# ---------------------------------------------------------------------------
# RateLimiter unit tests
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_first_request_no_delay(self):
        rl = RateLimiter(min_interval=1.0, jitter=0.0)
        delay = rl._delay_for("example.com")
        assert delay == 0.0

    def test_immediate_second_request_delays(self):
        rl = RateLimiter(min_interval=1.0, jitter=0.0)
        rl.record("example.com")
        delay = rl._delay_for("example.com")
        assert delay > 0.0
        assert delay <= 1.0

    def test_different_domains_independent(self):
        rl = RateLimiter(min_interval=1.0, jitter=0.0)
        rl.record("a.com")
        delay_b = rl._delay_for("b.com")
        assert delay_b == 0.0

    def test_jitter_adds_randomness(self):
        with patch("wafer._ratelimit.random.uniform", return_value=0.3):
            rl = RateLimiter(min_interval=1.0, jitter=0.5)
            rl.record("example.com")
            delay = rl._delay_for("example.com")
            # Should be approximately min_interval + jitter - elapsed
            # Since record just happened, elapsed ≈ 0, so delay ≈ 1.3
            assert delay > 1.0

    def test_after_interval_no_delay(self):
        rl = RateLimiter(min_interval=0.01, jitter=0.0)
        rl.record("example.com")
        time.sleep(0.02)
        delay = rl._delay_for("example.com")
        assert delay == 0.0

    @patch("wafer._ratelimit.time.sleep")
    def test_wait_sync_sleeps_when_needed(self, mock_sleep):
        rl = RateLimiter(min_interval=1.0, jitter=0.0)
        rl.record("example.com")
        delay = rl.wait_sync("example.com")
        assert delay > 0.0
        mock_sleep.assert_called_once()

    @patch("wafer._ratelimit.time.sleep")
    def test_wait_sync_no_sleep_first_request(self, mock_sleep):
        rl = RateLimiter(min_interval=1.0, jitter=0.0)
        delay = rl.wait_sync("example.com")
        assert delay == 0.0
        mock_sleep.assert_not_called()

    @pytest.mark.asyncio
    async def test_wait_async_no_delay_first_request(self):
        rl = RateLimiter(min_interval=1.0, jitter=0.0)
        with patch("asyncio.sleep", return_value=None):
            delay = await rl.wait_async("example.com")
        assert delay == 0.0

    @pytest.mark.asyncio
    async def test_wait_async_delays_when_needed(self):
        rl = RateLimiter(min_interval=1.0, jitter=0.0)
        rl.record("example.com")
        with patch("asyncio.sleep", return_value=None) as mock_sleep:
            delay = await rl.wait_async("example.com")
        assert delay > 0.0
        mock_sleep.assert_called_once()


# ---------------------------------------------------------------------------
# Session health: BaseSession._record_failure / _record_success
# ---------------------------------------------------------------------------


class TestSessionHealth:
    def test_record_failure_increments(self):
        from wafer._base import BaseSession

        session = BaseSession.__new__(BaseSession)
        session.max_failures = 3
        session._domain_failures = {}

        assert not session._record_failure("example.com")
        assert session._domain_failures["example.com"] == 1

    def test_record_failure_threshold_triggers(self):
        from wafer._base import BaseSession

        session = BaseSession.__new__(BaseSession)
        session.max_failures = 3
        session._domain_failures = {}

        session._record_failure("example.com")
        session._record_failure("example.com")
        result = session._record_failure("example.com")
        assert result is True

    def test_record_failure_per_domain(self):
        from wafer._base import BaseSession

        session = BaseSession.__new__(BaseSession)
        session.max_failures = 3
        session._domain_failures = {}

        session._record_failure("a.com")
        session._record_failure("a.com")
        session._record_failure("b.com")

        assert session._domain_failures["a.com"] == 2
        assert session._domain_failures["b.com"] == 1

    def test_record_success_resets_counter(self):
        from wafer._base import BaseSession

        session = BaseSession.__new__(BaseSession)
        session.max_failures = 3
        session._domain_failures = {}

        session._record_failure("example.com")
        session._record_failure("example.com")
        session._record_success("example.com")

        assert "example.com" not in session._domain_failures

    def test_record_success_noop_for_unknown_domain(self):
        from wafer._base import BaseSession

        session = BaseSession.__new__(BaseSession)
        session.max_failures = 3
        session._domain_failures = {}

        # Should not raise
        session._record_success("unknown.com")


# ---------------------------------------------------------------------------
# Session retirement in SyncSession
# ---------------------------------------------------------------------------


@patch("wafer._sync.time.sleep")
class TestSyncSessionRetirement:
    def test_403_retirement_after_threshold(self, mock_sleep):
        """3 consecutive 403s should trigger session retirement."""
        session, mock = make_sync_session(
            [
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(200, body="OK after retire"),
            ],
            max_failures=3,
        )
        retired = False

        def track_retire(domain):
            nonlocal retired
            retired = True
            # Reset fingerprint and clear failures like real retire
            session._fingerprint.reset()
            session._domain_failures.pop(domain, None)

        session._retire_session = track_retire
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        assert retired

    def test_success_resets_failure_counter(self, mock_sleep):
        """A successful response should clear the failure counter."""
        session, mock = make_sync_session(
            [
                MockResponse(403, body="Denied"),
                MockResponse(200, body="OK"),
            ],
            max_failures=3,
        )
        session.get("https://example.com")
        assert "example.com" not in session._domain_failures

    def test_429_also_tracks_failures(self, mock_sleep):
        """429 responses also count toward session health failures."""
        session, mock = make_sync_session(
            [
                MockResponse(429, body="Rate limited"),
                MockResponse(429, body="Rate limited"),
                MockResponse(429, body="Rate limited"),
                MockResponse(200, body="OK"),
            ],
            max_failures=3,
        )
        retired = False

        def track_retire(domain):
            nonlocal retired
            retired = True
            session._fingerprint.reset()
            session._domain_failures.pop(domain, None)

        session._retire_session = track_retire
        session.get("https://example.com")
        assert retired

    def test_mixed_domains_independent_health(self, mock_sleep):
        """Failures on one domain don't affect another's health."""

        session, mock = make_sync_session(
            [MockResponse(200, body="OK")],
            max_failures=3,
        )
        # Manually track failures for different domains
        session._record_failure("a.com")
        session._record_failure("a.com")
        # b.com should be unaffected
        assert session._domain_failures.get("b.com", 0) == 0
        assert session._domain_failures["a.com"] == 2

    def test_retirement_clears_cookie_cache(self, mock_sleep):
        """Session retirement should clear the disk cache for the domain."""
        mock_cache = MagicMock()
        session, mock = make_sync_session(
            [
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(200, body="OK"),
            ],
            max_failures=3,
            cookie_cache=mock_cache,
        )

        # Wire up real _retire_session (needs to use cookie_cache)
        def real_retire(domain):
            session._fingerprint.reset()
            if session._cookie_cache:
                session._cookie_cache.clear(domain)
            session._domain_failures.pop(domain, None)

        session._retire_session = real_retire
        session.get("https://example.com")
        mock_cache.clear.assert_called_with("example.com")

    def test_retirement_resets_fingerprint(self, mock_sleep):
        """Session retirement should reset the fingerprint (unpin + new profile)."""
        session, mock = make_sync_session(
            [
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(200, body="OK"),
            ],
            max_failures=3,
        )
        # Pin the fingerprint first
        session._fingerprint.pin()
        assert session._fingerprint.pinned

        was_reset = False

        def real_retire(domain):
            nonlocal was_reset
            session._fingerprint.reset()
            was_reset = True
            session._domain_failures.pop(domain, None)

        session._retire_session = real_retire
        session.get("https://example.com")
        # reset() was called during retirement
        assert was_reset
        # Failure counter cleared for the domain
        assert "example.com" not in session._domain_failures

    def test_below_threshold_no_retirement(self, mock_sleep):
        """Below threshold, no retirement should happen."""
        session, mock = make_sync_session(
            [
                MockResponse(403, body="Denied"),
                MockResponse(200, body="OK"),
            ],
            max_failures=3,
        )
        retired = False

        def track_retire(domain):
            nonlocal retired
            retired = True

        session._retire_session = track_retire
        session.get("https://example.com")
        assert not retired

    def test_no_retire_before_budget_exhaustion_challenge(self, mock_sleep):
        """Session should NOT be retired when rotation budget is exhausted.

        When max_rotations is hit on a real challenge, ChallengeDetected is
        raised. Retirement should not fire on the final iteration.
        """
        cf_resp = MockResponse(
            403,
            headers={"cf-mitigated": "challenge"},
            body="<html>CF challenge</html>",
        )
        session, mock = make_sync_session(
            [cf_resp] * 10,
            max_rotations=2,
            max_failures=5,  # high threshold so retirement doesn't
        )                        # interfere with the budget test
        retired = False

        def track_retire(domain):
            nonlocal retired
            retired = True

        session._retire_session = track_retire
        with pytest.raises(ChallengeDetected):
            session.get("https://example.com")
        # Budget exhausted before health threshold → no retirement
        assert not retired
        assert mock.request_count == 3  # 2 rotations + 1 final attempt

    def test_no_retire_before_budget_exhaustion_429(self, mock_sleep):
        """429 with exhausted budget should not retire session."""
        session, mock = make_sync_session(
            [MockResponse(429, body="Rate limited")] * 10,
            max_rotations=2,
            max_failures=5,  # high so retirement doesn't trigger
        )
        retired = False

        def track_retire(domain):
            nonlocal retired
            retired = True

        session._retire_session = track_retire
        with pytest.raises(RateLimited):
            session.get("https://example.com")
        # Session was never retired (budget exhausted before threshold)
        assert not retired


# ---------------------------------------------------------------------------
# Rate limiting integration in SyncSession
# ---------------------------------------------------------------------------


@patch("wafer._sync.time.sleep")
class TestSyncRateLimitIntegration:
    def test_rate_limiter_called_before_request(self, mock_sleep):
        rl = RateLimiter(min_interval=1.0, jitter=0.0)
        rl.wait_sync = MagicMock(return_value=0.0)
        rl.record = MagicMock()

        session, mock = make_sync_session(
            [MockResponse(200, body="OK")],
            rate_limiter=rl,
        )
        session.get("https://example.com")
        rl.wait_sync.assert_called_once_with("example.com")

    def test_rate_limiter_records_after_response(self, mock_sleep):
        rl = RateLimiter(min_interval=1.0, jitter=0.0)
        rl.wait_sync = MagicMock(return_value=0.0)
        rl.record = MagicMock()

        session, mock = make_sync_session(
            [MockResponse(200, body="OK")],
            rate_limiter=rl,
        )
        session.get("https://example.com")
        rl.record.assert_called_with("example.com")

    def test_no_rate_limiter_no_calls(self, mock_sleep):
        """When rate_limiter is None, no rate limiting happens."""
        session, mock = make_sync_session(
            [MockResponse(200, body="OK")],
            rate_limiter=None,
        )
        # Should not raise
        session.get("https://example.com")


# ---------------------------------------------------------------------------
# Async session health and rate limiting
# ---------------------------------------------------------------------------


class TestAsyncSessionRetirement:
    @pytest.mark.asyncio
    async def test_403_retirement_after_threshold(self):
        session, mock = make_async_session(
            [
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(200, body="OK"),
            ],
            max_failures=3,
        )
        retired = False

        async def track_retire(domain):
            nonlocal retired
            retired = True
            session._fingerprint.reset()
            session._domain_failures.pop(domain, None)

        session._retire_session = track_retire
        with patch("wafer._async.asyncio.sleep", return_value=None):
            resp = await session.get("https://example.com")
        assert resp.status_code == 200
        assert retired

    @pytest.mark.asyncio
    async def test_success_resets_failure_counter(self):
        session, mock = make_async_session(
            [
                MockResponse(403, body="Denied"),
                MockResponse(200, body="OK"),
            ],
            max_failures=3,
        )
        with patch("wafer._async.asyncio.sleep", return_value=None):
            await session.get("https://example.com")
        assert "example.com" not in session._domain_failures

    @pytest.mark.asyncio
    async def test_async_rate_limiter_called(self):
        rl = RateLimiter(min_interval=1.0, jitter=0.0)
        called = False

        async def mock_wait(domain):
            nonlocal called
            called = True
            return 0.0

        rl.wait_async = mock_wait
        rl.record = MagicMock()

        session, mock = make_async_session(
            [MockResponse(200, body="OK")],
            rate_limiter=rl,
        )
        with patch("wafer._async.asyncio.sleep", return_value=None):
            await session.get("https://example.com")
        assert called
