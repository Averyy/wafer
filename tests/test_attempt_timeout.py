"""Tests for attempt_timeout: per-attempt cap vs total timeout budget.

timeout= is the TOTAL budget for the whole retry loop (unchanged).
attempt_timeout= bounds each individual wreq attempt so a hanging
attempt can't eat the whole budget - retries/rotations still fire.
"""

import datetime
import time
from unittest.mock import AsyncMock, patch

import pytest
import wreq.exceptions

from tests.conftest import (
    MockResponse,
    make_async_session,
    make_sync_session,
)
from wafer._errors import WaferTimeout

URL = "https://example.com/page"


def ok():
    return MockResponse(200, {"content-type": "text/html"}, "<html>ok</html>")


def hang():
    """Simulated wreq-layer attempt timeout."""
    return wreq.exceptions.TimeoutError("simulated attempt timeout")


class BudgetEatingClient:
    """Mock client whose request sleeps for the full wreq timeout, then
    raises the wreq timeout error - a server that hangs forever."""

    def __init__(self):
        self.request_count = 0
        self.request_log = []

    def request(self, method, url, **kwargs):
        self.request_count += 1
        self.request_log.append((method, url, kwargs))
        wreq_timeout = kwargs.get("timeout")
        if wreq_timeout is not None:
            time.sleep(wreq_timeout.total_seconds())
        raise wreq.exceptions.TimeoutError("simulated hang")


class AsyncBudgetEatingClient(BudgetEatingClient):
    async def request(self, method, url, **kwargs):
        self.request_count += 1
        self.request_log.append((method, url, kwargs))
        wreq_timeout = kwargs.get("timeout")
        if wreq_timeout is not None:
            time.sleep(wreq_timeout.total_seconds())
        raise wreq.exceptions.TimeoutError("simulated hang")


def wreq_timeout_of(mock, attempt_index=0):
    return mock.request_log[attempt_index][2].get("timeout")


@patch("wafer._sync.time.sleep")
class TestSyncAttemptTimeout:
    def test_hanging_attempt_bounded_and_retry_fires(self, mock_sleep):
        """(a) attempt 1 times out at the wreq layer, attempt 2 succeeds."""
        session, mock = make_sync_session(
            [hang(), ok()], attempt_timeout=5,
        )
        resp = session.get(URL)
        assert resp.status_code == 200
        assert mock.request_count == 2
        assert resp.was_retried
        # Each attempt was bounded at the wreq layer by the attempt cap
        assert wreq_timeout_of(mock, 0) == datetime.timedelta(seconds=5)
        assert wreq_timeout_of(mock, 1) == datetime.timedelta(seconds=5)

    def test_attempt_timeouts_consume_retries_then_rotations(
        self, mock_sleep
    ):
        """Timeouts burn max_retries first, then rotation budget fires."""
        session, mock = make_sync_session(
            [hang(), hang(), ok()],
            attempt_timeout=5,
            max_retries=1,
            max_rotations=2,
        )
        resp = session.get(URL)
        assert resp.status_code == 200
        assert mock.request_count == 3
        assert resp.retries == 1
        assert resp.rotations == 1

    def test_exhaustion_raises_wafer_timeout(self, mock_sleep):
        """Retries + rotations exhausted by attempt timeouts -> WaferTimeout."""
        session, mock = make_sync_session(
            [hang()] * 10,
            attempt_timeout=5,
            max_retries=1,
            max_rotations=1,
        )
        with pytest.raises(WaferTimeout) as exc_info:
            session.get(URL)
        # initial + 1 retry + 1 rotation = 3 bounded attempts
        assert mock.request_count == 3
        # No total timeout= -> reported budget is the per-attempt cap
        assert exc_info.value.timeout_secs == 5

    def test_attempt_cap_applies_under_total_budget(self, mock_sleep):
        """(e) canonical combo: attempt cap < total -> attempt cap wins."""
        session, mock = make_sync_session([ok()], attempt_timeout=15)
        session.get(URL, timeout=60)
        assert wreq_timeout_of(mock).total_seconds() == pytest.approx(
            15.0, abs=0.1
        )

    def test_total_deadline_caps_attempt_timeout(self, mock_sleep):
        """(e) total budget smaller than attempt cap -> deadline wins."""
        session, mock = make_sync_session([ok()], attempt_timeout=15)
        session.get(URL, timeout=10)
        t = wreq_timeout_of(mock).total_seconds()
        assert t <= 10.0
        assert t == pytest.approx(10.0, abs=0.5)

    def test_total_deadline_aborts_loop_with_wafer_timeout(self, mock_sleep):
        """Both set: retries fire per attempt, total deadline ends the loop."""
        session, _ = make_sync_session([ok()])
        client = BudgetEatingClient()
        session._client = client
        with pytest.raises(WaferTimeout) as exc_info:
            session.get(URL, timeout=0.06, attempt_timeout=0.02)
        # The total budget is what's reported, and >1 attempt fired
        assert exc_info.value.timeout_secs == pytest.approx(0.06)
        assert client.request_count >= 2

    def test_per_request_override_beats_session_default(self, mock_sleep):
        """(c) per-request attempt_timeout= overrides the session value."""
        session, mock = make_sync_session([ok()], attempt_timeout=20)
        session.get(URL, attempt_timeout=5)
        assert wreq_timeout_of(mock) == datetime.timedelta(seconds=5)

    def test_timedelta_and_numeric_forms(self, mock_sleep):
        """(d) timedelta, int, and float are all accepted."""
        session, mock = make_sync_session([ok()])
        session.get(URL, attempt_timeout=datetime.timedelta(seconds=7))
        assert wreq_timeout_of(mock, 0) == datetime.timedelta(seconds=7)
        session.get(URL, attempt_timeout=7)
        assert wreq_timeout_of(mock, 1) == datetime.timedelta(seconds=7)
        session.get(URL, attempt_timeout=7.5)
        assert wreq_timeout_of(mock, 2) == datetime.timedelta(seconds=7.5)

    def test_no_attempt_timeout_no_wreq_timeout_kwarg(self, mock_sleep):
        """No timeout= and no attempt_timeout= -> wreq gets no timeout
        kwarg (client-level session timeout applies), as before."""
        session, mock = make_sync_session([ok()])
        session.get(URL)
        assert "timeout" not in mock.request_log[0][2]


@patch("wafer._sync.time.sleep")
class TestSyncAttemptTimeoutRecordsFailure:
    """FIX 5: an attempt-timeout rotation accrues failure strikes and
    eventually retires the session, like the 403/429 paths."""

    def test_attempt_timeout_records_failure_strike(self, mock_sleep):
        # No retries, plenty of rotations: every hang rotates, and each
        # rotation must register a failure strike on the domain.
        session, mock = make_sync_session(
            [hang(), ok()],
            attempt_timeout=5,
            max_retries=0,
            max_rotations=3,
            max_failures=None,  # never retire, just count strikes
        )
        resp = session.get(URL)
        assert resp.status_code == 200
        # One hang -> one rotation -> one recorded failure (cleared on the
        # subsequent success, so check it was recorded by spying).
        assert mock.request_count == 2

    def test_persistent_tarpit_retires_session(self, mock_sleep):
        # Every attempt hangs: strikes accrue until max_failures retires.
        session, mock = make_sync_session(
            [hang()] * 10,
            attempt_timeout=5,
            max_retries=0,
            max_rotations=5,
            max_failures=2,
        )
        retired = []
        orig = session._retire_session
        session._retire_session = lambda d: (retired.append(d), orig(d))[1]
        with pytest.raises(WaferTimeout):
            session.get(URL)
        # The tarpit accrued strikes and triggered retirement (was never
        # called before FIX 5).
        assert retired, "attempt-timeout tarpit should retire the session"

    def test_record_failure_called_on_timeout(self, mock_sleep):
        session, _ = make_sync_session(
            [hang(), ok()],
            attempt_timeout=5,
            max_retries=0,
            max_rotations=2,
            max_failures=None,
        )
        calls = []
        orig = session._record_failure
        session._record_failure = lambda d: (calls.append(d), orig(d))[1]
        session.get(URL)
        assert calls, "attempt-timeout rotation must call _record_failure"


class TestSyncTimeoutAlonePreserved:
    """(b) timeout= alone keeps today's semantics: the first attempt may
    consume the entire budget and no extra attempt fires."""

    def test_first_attempt_consumes_whole_budget_no_retry(self):
        session, _ = make_sync_session([ok()])
        client = BudgetEatingClient()
        session._client = client
        with pytest.raises(WaferTimeout) as exc_info:
            session.get(URL, timeout=0.05)
        assert client.request_count == 1  # no second attempt
        assert exc_info.value.timeout_secs == pytest.approx(0.05)
        # First attempt was given the whole budget, not a fraction
        t = client.request_log[0][2]["timeout"].total_seconds()
        assert t == pytest.approx(0.05, abs=0.02)


@patch("wafer._async.asyncio.sleep", new_callable=AsyncMock)
class TestAsyncAttemptTimeout:
    async def test_hanging_attempt_bounded_and_retry_fires(self, mock_sleep):
        session, mock = make_async_session(
            [hang(), ok()], attempt_timeout=5,
        )
        resp = await session.get(URL)
        assert resp.status_code == 200
        assert mock.request_count == 2
        assert wreq_timeout_of(mock, 0) == datetime.timedelta(seconds=5)

    async def test_attempt_timeouts_consume_retries_then_rotations(
        self, mock_sleep
    ):
        session, mock = make_async_session(
            [hang(), hang(), ok()],
            attempt_timeout=5,
            max_retries=1,
            max_rotations=2,
        )
        resp = await session.get(URL)
        assert resp.status_code == 200
        assert mock.request_count == 3
        assert resp.retries == 1
        assert resp.rotations == 1

    async def test_exhaustion_raises_wafer_timeout(self, mock_sleep):
        session, mock = make_async_session(
            [hang()] * 10,
            attempt_timeout=5,
            max_retries=1,
            max_rotations=1,
        )
        with pytest.raises(WaferTimeout) as exc_info:
            await session.get(URL)
        assert mock.request_count == 3
        assert exc_info.value.timeout_secs == 5

    async def test_attempt_cap_applies_under_total_budget(self, mock_sleep):
        session, mock = make_async_session([ok()], attempt_timeout=15)
        await session.get(URL, timeout=60)
        assert wreq_timeout_of(mock).total_seconds() == pytest.approx(
            15.0, abs=0.1
        )

    async def test_total_deadline_caps_attempt_timeout(self, mock_sleep):
        session, mock = make_async_session([ok()], attempt_timeout=15)
        await session.get(URL, timeout=10)
        t = wreq_timeout_of(mock).total_seconds()
        assert t <= 10.0
        assert t == pytest.approx(10.0, abs=0.5)

    async def test_per_request_override_beats_session_default(
        self, mock_sleep
    ):
        session, mock = make_async_session([ok()], attempt_timeout=20)
        await session.get(URL, attempt_timeout=5)
        assert wreq_timeout_of(mock) == datetime.timedelta(seconds=5)

    async def test_timedelta_and_numeric_forms(self, mock_sleep):
        session, mock = make_async_session([ok()])
        await session.get(URL, attempt_timeout=datetime.timedelta(seconds=7))
        assert wreq_timeout_of(mock, 0) == datetime.timedelta(seconds=7)
        await session.get(URL, attempt_timeout=7)
        assert wreq_timeout_of(mock, 1) == datetime.timedelta(seconds=7)


@patch("wafer._async.asyncio.sleep", new_callable=AsyncMock)
class TestAsyncAttemptTimeoutRecordsFailure:
    """FIX 5 async parity."""

    async def test_record_failure_called_on_timeout(self, mock_sleep):
        session, _ = make_async_session(
            [hang(), ok()],
            attempt_timeout=5,
            max_retries=0,
            max_rotations=2,
            max_failures=None,
        )
        calls = []
        orig = session._record_failure
        session._record_failure = lambda d: (calls.append(d), orig(d))[1]
        await session.get(URL)
        assert calls, "attempt-timeout rotation must call _record_failure"

    async def test_persistent_tarpit_retires_session(self, mock_sleep):
        session, _ = make_async_session(
            [hang()] * 10,
            attempt_timeout=5,
            max_retries=0,
            max_rotations=5,
            max_failures=2,
        )
        retired = []

        async def spy(d):
            retired.append(d)
            await orig(d)

        orig = session._retire_session
        session._retire_session = spy
        with pytest.raises(WaferTimeout):
            await session.get(URL)
        assert retired, "attempt-timeout tarpit should retire the session"


class TestAsyncTimeoutAlonePreserved:
    async def test_first_attempt_consumes_whole_budget_no_retry(self):
        session, _ = make_async_session([ok()])
        client = AsyncBudgetEatingClient()
        session._client = client
        with pytest.raises(WaferTimeout):
            await session.get(URL, timeout=0.05)
        assert client.request_count == 1


class TestConstructorNormalization:
    """Session-level attempt_timeout is normalized like timeout."""

    def test_numeric_normalized_to_timedelta(self):
        import wafer

        session = wafer.SyncSession(attempt_timeout=7)
        assert session.attempt_timeout == datetime.timedelta(seconds=7)

    def test_timedelta_kept(self):
        import wafer

        session = wafer.SyncSession(
            attempt_timeout=datetime.timedelta(seconds=8)
        )
        assert session.attempt_timeout == datetime.timedelta(seconds=8)

    def test_default_is_none(self):
        import wafer

        session = wafer.SyncSession()
        assert session.attempt_timeout is None

    async def test_async_session_numeric(self):
        import wafer

        session = wafer.AsyncSession(attempt_timeout=2.5)
        assert session.attempt_timeout == datetime.timedelta(seconds=2.5)
