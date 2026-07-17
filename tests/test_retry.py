"""Tests for retry logic, backoff, and separate counters."""

from unittest.mock import patch

import pytest
from wreq import Emulation

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
from wafer._fingerprint import emulation_family
from wafer._profiles import Profile
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

    def test_403_first_rotation_fresh_session(self, mock_sleep):
        session, mock = make_sync_session([
            MockResponse(403, body="Denied"),
            MockResponse(200, body="OK"),
        ])
        session.get("https://example.com")
        # New cross-family ladder, rung 1: fresh TLS session, SAME Chrome
        # fingerprint (a new family is not introduced until rotation 2).
        # (Old ladder behaved identically at rung 1.)
        assert session._safari_identity is None
        assert session._fingerprint is not None
        assert emulation_family(session._fingerprint.current) == "chrome"

    def test_403_second_rotation_firefox(self, mock_sleep):
        # New cross-family ladder, rung 2 = FIREFOX (was Safari in the old
        # Chrome->Safari ladder). Cross-family is the strong rotation axis:
        # WAF reputation pools key on browser family, so Chrome->Firefox is
        # real diversity, whereas the old Chrome-version bumps were not.
        session, mock = make_sync_session([
            MockResponse(403, body="Denied"),
            MockResponse(403, body="Denied"),
            MockResponse(200, body="OK"),
        ])
        session.get("https://example.com")
        assert session._safari_identity is None
        assert session._fingerprint is not None
        assert emulation_family(session._fingerprint.current) == "firefox"
        # Header envelope swapped to Firefox's (q=0.5, no sec-ch-ua) for
        # coherence with the Firefox TLS fingerprint.
        assert session.headers["Accept-Language"] == "en-US,en;q=0.5"

    def test_403_third_rotation_safari(self, mock_sleep):
        # Rung 3 of the new ladder is Safari (after Chrome -> Firefox).
        # max_failures=None so health-retirement doesn't short-circuit the
        # ladder (it would reset the identity before rung 3 is reached).
        session, mock = make_sync_session(
            [
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(200, body="OK"),
            ],
            max_failures=None,
        )
        session.get("https://example.com")
        assert session._safari_identity is not None
        assert session._fingerprint is None

    def test_403_fourth_rotation_edge(self, mock_sleep):
        # Rung 4 of the new ladder is Edge (Chrome->Firefox->Safari->Edge).
        session, mock = make_sync_session(
            [
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(200, body="OK"),
            ],
            max_failures=None,
        )
        session.get("https://example.com")
        assert session._safari_identity is None
        assert session._fingerprint is not None
        assert emulation_family(session._fingerprint.current) == "edge"

    def test_403_ladder_falls_back_to_chrome_versions(self, mock_sleep):
        # Beyond the family ladder, rotation cycles Chrome versions.
        session, mock = make_sync_session(
            [MockResponse(403, body="Denied")] * 5
            + [MockResponse(200, body="OK")],
            max_rotations=6,
            max_failures=None,
        )
        session.get("https://example.com")
        # rung 5 = Chrome (back from Edge to the Chrome family).
        assert session._safari_identity is None
        assert emulation_family(session._fingerprint.current) == "chrome"

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
        """Non-JS-only challenge (Akamai) rotates fingerprint."""
        session, mock = make_sync_session([
            MockResponse(
                403,
                headers={"Set-Cookie": "_abck=abc123; Path=/"},
                body="<html>akamai challenge</html>",
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

    def test_challenge_exhausted_exception_carries_response(
        self, mock_sleep
    ):
        """ChallengeDetected.response exposes the final challenge reply."""
        session, mock = make_sync_session(
            [
                MockResponse(
                    403,
                    headers={"cf-mitigated": "challenge"},
                    body="CF challenge body",
                ),
            ]
            * 15,
            max_rotations=3,
        )
        with pytest.raises(ChallengeDetected) as exc_info:
            session.get("https://example.com")
        r = exc_info.value.response
        assert r is not None
        assert r.status_code == 403
        assert r.text == "CF challenge body"
        assert r.challenge_type == "cloudflare"

    def test_429_exhausted_exception_carries_response(self, mock_sleep):
        """RateLimited.response exposes the final 429 reply."""
        session, mock = make_sync_session(
            [
                MockResponse(
                    429,
                    headers={"Retry-After": "7"},
                    body="Rate limited body",
                ),
            ]
            * 15,
            max_rotations=3,
        )
        with pytest.raises(RateLimited) as exc_info:
            session.get("https://example.com")
        r = exc_info.value.response
        assert r is not None
        assert r.status_code == 429
        assert r.text == "Rate limited body"
        assert r.headers.get("retry-after") == "7"

    def test_empty_200_exhausted_exception_carries_response(
        self, mock_sleep
    ):
        """EmptyResponse.response exposes the final empty 200 reply."""
        session, mock = make_sync_session(
            [MockResponse(200, headers={"X-Trace": "abc"}, body="")] * 5,
            max_retries=3,
        )
        with pytest.raises(EmptyResponse) as exc_info:
            session.get("https://example.com")
        r = exc_info.value.response
        assert r is not None
        assert r.status_code == 200
        assert r.text == ""
        assert r.headers.get("x-trace") == "abc"

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
        """Challenge detected on non-403 status (e.g., Shape 200)."""
        session, mock = make_sync_session([
            MockResponse(
                200,
                body="<html>istlWasHere</html>",
            ),
            MockResponse(200, body="<html>Real page content here</html>"),
        ])
        resp = session.get("https://example.com")
        assert resp.status_code == 200

    def test_datadome_cookie_challenge_js_only(self, mock_sleep):
        """DataDome is JS_ONLY: raises immediately without browser solver."""
        session, mock = make_sync_session([
            MockResponse(
                403,
                headers={"Set-Cookie": "datadome=abc123; Path=/"},
                body="",
            ),
            MockResponse(200, body="OK"),
        ])
        with pytest.raises(ChallengeDetected) as exc_info:
            session.get("https://example.com")
        assert exc_info.value.challenge_type == "datadome"
        assert mock.request_count == 1

    def test_multi_set_cookie_challenge_detected(self, mock_sleep):
        """Challenge detected when WAF cookie is in second Set-Cookie header."""
        resp403 = MockResponse(403, body="")
        # Simulate two Set-Cookie headers: one benign, one akamai
        resp403.headers._raw[b"set-cookie"] = [
            b"session_id=abc; Path=/",
            b"_abck=xyz; Path=/",
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

    def test_js_only_challenge_fast_fails_without_browser(
        self, mock_sleep
    ):
        """CF challenge + no browser solver → ChallengeDetected after 1 request."""
        session, mock = make_sync_session(
            [
                MockResponse(
                    403,
                    headers={"cf-mitigated": "challenge"},
                    body="CF challenge",
                ),
            ]
            * 10,
            max_rotations=10,
        )
        with pytest.raises(ChallengeDetected) as exc_info:
            session.get("https://example.com")
        assert exc_info.value.challenge_type == "cloudflare"
        assert mock.request_count == 1

    def test_non_js_challenge_still_rotates(self, mock_sleep):
        """Akamai challenge + no browser → still rotates (not in JS_ONLY)."""
        session, mock = make_sync_session(
            [
                MockResponse(
                    403,
                    headers={
                        "Set-Cookie": "_abck=abc123; Path=/",
                    },
                    body="",
                ),
                MockResponse(200, body="OK"),
            ],
            max_rotations=10,
        )
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        assert mock.request_count == 2


# ---------------------------------------------------------------------------
# fingerprint_pool rotation primitive
# ---------------------------------------------------------------------------


@patch("wafer._sync.time.sleep")
class TestFingerprintPool:
    """Opt-in pool replaces the default ladder as the rotation source."""

    POOL = [Emulation.Chrome149, Emulation.Firefox151, Emulation.Edge148]

    def test_pool_cycles_through_identities(self, mock_sleep):
        # Each rotation steps to the next pool member (not the family ladder).
        session, mock = make_sync_session(
            [
                MockResponse(403, body="Denied"),  # -> rotate to pool[1]
                MockResponse(403, body="Denied"),  # -> rotate to pool[2]
                MockResponse(200, body="OK"),
            ],
            fingerprint_pool=self.POOL,
            max_rotations=5,
            max_failures=None,
        )
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        # Landed on pool[2] = Edge148 after two rotations.
        assert emulation_family(session._fingerprint.current) == "edge"
        # Safari ladder rung is never used in pool mode.
        assert session._safari_identity is None

    def test_pool_swaps_header_envelope_per_family(self, mock_sleep):
        # Rotating to the Firefox pool member must swap to Firefox headers.
        session, mock = make_sync_session(
            [
                MockResponse(403, body="Denied"),  # -> pool[1] = Firefox151
                MockResponse(200, body="OK"),
            ],
            fingerprint_pool=self.POOL,
            max_rotations=5,
            max_failures=None,
        )
        session.get("https://example.com")
        assert emulation_family(session._fingerprint.current) == "firefox"
        assert session.headers["Accept-Language"] == "en-US,en;q=0.5"

    def test_pool_disables_retirement(self, mock_sleep):
        # With a pool, max_failures must NOT retire the session: rotation
        # presses on through every pool member instead of nuking state.
        session, mock = make_sync_session(
            [MockResponse(403, body="Denied")] * 4
            + [MockResponse(200, body="OK")],
            fingerprint_pool=self.POOL,
            max_rotations=6,
            max_failures=3,  # would retire WITHOUT a pool
        )
        resp = session.get("https://example.com")
        assert resp.status_code == 200
        # 4 failures recorded but no retirement fired.
        assert session._record_failure("never.example") is False

    def test_pool_per_identity_backoff_grows(self, mock_sleep):
        # A pool identity that fails twice rests longer the second time.
        session, _ = make_sync_session(
            [MockResponse(200, body="OK")],
            fingerprint_pool=self.POOL,
            max_failures=None,
        )
        # Walk a full cycle + revisit pool[0]: it accrues a strike, so its
        # _rotation_delay penalty climbs above the flat 1.0s.
        for r in range(1, len(self.POOL) + 1):
            session._advance_rotation(r)
        # Back on pool[0] (Chrome149) which now has 1 strike -> penalty 2.0.
        assert emulation_family(session._fingerprint.current) == "chrome"
        assert session._rotation_delay() == 2.0

    def test_429_pool_backoff_reflects_incoming_identity(self, mock_sleep):
        # FIX 4: on the 429 path the rotation delay must reflect the INCOMING
        # (about-to-be-tried) identity's strike count, not the outgoing
        # just-failed one. Pre-seed a strike on pool[1] (the incoming member);
        # after one 429 the sleep must be pool[1]'s penalty (2.0), proving the
        # identity advance happens BEFORE _rotation_delay() is computed.
        session, mock = make_sync_session(
            [
                MockResponse(429, body="Rate limited"),  # -> advance to pool[1]
                MockResponse(200, body="OK"),
            ],
            fingerprint_pool=self.POOL,
            max_rotations=5,
            max_failures=None,
        )
        # pool[1] = Firefox151 already has 1 strike -> incoming penalty 2.0.
        session._pool_strikes[repr(Emulation.Firefox151)] = 1
        session.get("https://example.com")
        # Landed on pool[1].
        assert emulation_family(session._fingerprint.current) == "firefox"
        # The 429 sleep used pool[1]'s (incoming) backoff, not pool[0]'s flat 1s.
        mock_sleep.assert_any_call(2.0)


# ---------------------------------------------------------------------------
# Profile sessions must NOT be dragged onto the cross-family ladder (FIX 1)
# ---------------------------------------------------------------------------


@patch("wafer._sync.time.sleep")
class TestProfileSessionRotation:
    """A profile= (Dart/Safari/Opera Mini) session keeps its own identity.

    The cross-family ladder is Emulation-only. Routing a Dart session through
    it would leave Dart TLS paired with Safari/Firefox headers (or re-roll an
    explicit Safari version) -- an incoherent fingerprint. _advance_rotation
    must be a no-op for these sessions (only the TLS session/cookies refresh).
    """

    def test_dart_session_not_corrupted_by_ladder(self, mock_sleep):
        session, mock = make_sync_session(
            [MockResponse(403, body="Denied")] * 4
            + [MockResponse(200, body="OK")],
            profile=Profile.DART,
            max_rotations=4,
            max_failures=None,
        )
        dart_headers = dict(session.headers)
        assert session._dart_identity is not None
        assert session._fingerprint is None

        resp = session.get("https://example.com")
        assert resp.status_code == 200
        # Identity unchanged across 4 rotations: still Dart, no Safari swap,
        # no Emulation FingerprintManager spun up, headers still Dart's.
        assert session._dart_identity is not None
        assert session._safari_identity is None
        assert session._fingerprint is None
        assert session.headers == dart_headers


@patch("wafer._sync.time.sleep")
class TestNonChromeStartLadderOrder:
    """A non-Chrome-START session keeps the cross-family ladder order (FIX 7).

    A session begun on Firefox must skip the Firefox rung (same family) and
    advance to the NEXT rung (Safari -> Edge), not drop straight into Chrome
    version cycling.
    """

    def test_firefox_start_reaches_safari_before_chrome(self, mock_sleep):
        from wafer._fingerprint import FingerprintManager

        session, _ = make_sync_session(
            [MockResponse(200, body="OK")],
            max_failures=None,
        )
        # Start the session on Firefox (as emulation=Emulation.Firefox149 would).
        session._fingerprint = FingerprintManager(Emulation.Firefox149)
        # rotation 1: fresh same-family session (no identity change).
        session._advance_rotation(1)
        assert emulation_family(session._fingerprint.current) == "firefox"
        # rotation 2 hits the Firefox rung == current family -> must skip to the
        # next rung (Safari), NOT fall into Chrome version cycling.
        session._advance_rotation(2)
        assert session._safari_identity is not None
        assert session._fingerprint is None
        # rotation 3 hits the already-tried Safari rung -> skips to Edge.
        session._advance_rotation(3)
        assert session._safari_identity is None
        assert emulation_family(session._fingerprint.current) == "edge"


@patch("wafer._sync.time.sleep")
class TestEmpty200RotationSignal:
    """An empty 200 from a 200-capable host triggers a rotation."""

    def test_empty_200_from_capable_host_rotates(self, mock_sleep):
        # First a real body (marks host 200-capable), then empty 200s that
        # exhaust normal retries, then a rotation recovers the real body.
        session, mock = make_sync_session(
            [
                MockResponse(200, body="real"),   # capability marker
                MockResponse(200, body=""),        # empty x (max_retries+1)
                MockResponse(200, body=""),
                MockResponse(200, body=""),
                MockResponse(200, body=""),
                MockResponse(200, body="recovered"),  # after rotation
            ],
            max_retries=3,
            max_rotations=2,
            max_failures=None,
        )
        session.get("https://example.com")  # arm capability
        resp = session.get("https://example.com")
        assert resp.text == "recovered"
        # The recovery used a rotation (a fresh identity), not just retries.
        assert resp.rotations >= 1

    def test_empty_200_first_request_not_rotated(self, mock_sleep):
        # A host that has NEVER served a body is not assumed hot: empty 200
        # exhausts retries and raises EmptyResponse without burning rotations.
        session, mock = make_sync_session(
            [MockResponse(200, body="")] * 6,
            max_retries=2,
            max_rotations=2,
            max_failures=None,
        )
        with pytest.raises(EmptyResponse):
            session.get("https://example.com")

    def test_empty_200_terminal_when_rotations_exhausted(self, mock_sleep):
        # Even for a 200-capable host, EmptyResponse is still the terminal
        # outcome once rotations are spent.
        session, mock = make_sync_session(
            [MockResponse(200, body="real")]
            + [MockResponse(200, body="")] * 20,
            max_retries=2,
            max_rotations=2,
            max_failures=None,
        )
        session.get("https://example.com")  # arm capability
        with pytest.raises(EmptyResponse):
            session.get("https://example.com")

    def test_max_retries_0_returns_empty_200_without_rotating(
        self, mock_sleep
    ):
        # FIX 2: max_retries=0 must RETURN the empty 200 (the documented
        # .bulk()/no-retry contract), NOT rotate -- even on a 200-capable host
        # that still has rotation budget. The empty-200 rotation branch used to
        # run before the max_retries==0 guard and would burn a rotation here.
        session, mock = make_sync_session(
            [
                MockResponse(200, body="real"),  # arm host as 200-capable
                MockResponse(200, body=""),       # empty -> must be RETURNED
                MockResponse(200, body="recovered"),  # never requested
            ],
            max_retries=0,
            max_rotations=2,
            max_failures=None,
        )
        session.get("https://example.com")  # arm capability (request 1)
        resp = session.get("https://example.com")  # request 2
        assert resp.status_code == 200
        assert resp.text == ""
        assert resp.rotations == 0
        # No rotation fired: only the 2 deliberate requests were made.
        assert mock.request_count == 2


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

    @pytest.mark.asyncio
    async def test_js_only_challenge_fast_fails_without_browser(self):
        """CF challenge + no browser solver → ChallengeDetected after 1 request."""
        session, mock = make_async_session(
            [
                MockResponse(
                    403,
                    headers={"cf-mitigated": "challenge"},
                    body="CF challenge",
                ),
            ]
            * 10,
            max_rotations=10,
        )
        with patch("wafer._async.asyncio.sleep", return_value=None):
            with pytest.raises(ChallengeDetected) as exc_info:
                await session.get("https://example.com")
        assert exc_info.value.challenge_type == "cloudflare"
        assert mock.request_count == 1

    @pytest.mark.asyncio
    async def test_non_js_challenge_still_rotates(self):
        """Akamai challenge + no browser → still rotates."""
        session, mock = make_async_session(
            [
                MockResponse(
                    403,
                    headers={
                        "Set-Cookie": "_abck=abc123; Path=/",
                    },
                    body="",
                ),
                MockResponse(200, body="OK"),
            ],
            max_rotations=10,
        )
        with patch("wafer._async.asyncio.sleep", return_value=None):
            resp = await session.get("https://example.com")
        assert resp.status_code == 200
        assert mock.request_count == 2

    @pytest.mark.asyncio
    async def test_history_records_redirect_chain(self):
        """Async mirror: resp.history lists each followed hop in order."""
        r1 = MockResponse(
            301, {"location": "https://a.com/step1"}, ""
        )
        r2 = MockResponse(
            302, {"location": "https://b.com/step2"}, ""
        )
        ok = MockResponse(200, body="Done")
        session, _ = make_async_session([r1, r2, ok])
        with patch("wafer._async.asyncio.sleep", return_value=None):
            resp = await session.get("https://start.com/")
        assert resp.history == [
            (301, "https://start.com/"),
            (302, "https://a.com/step1"),
        ]
        assert resp.url == "https://b.com/step2"

    @pytest.mark.asyncio
    async def test_history_empty_without_redirect(self):
        session, _ = make_async_session([MockResponse(200, body="ok")])
        with patch("wafer._async.asyncio.sleep", return_value=None):
            resp = await session.get("https://example.com")
        assert resp.history == []

    @pytest.mark.asyncio
    async def test_challenge_exhausted_exception_carries_response(self):
        """Async mirror: ChallengeDetected.response is the final reply."""
        session, mock = make_async_session(
            [
                MockResponse(
                    403,
                    headers={"cf-mitigated": "challenge"},
                    body="CF challenge body",
                ),
            ]
            * 5,
            max_rotations=2,
        )
        with patch("wafer._async.asyncio.sleep", return_value=None):
            with pytest.raises(ChallengeDetected) as exc_info:
                await session.get("https://example.com")
        r = exc_info.value.response
        assert r is not None
        assert r.status_code == 403
        assert r.text == "CF challenge body"
        assert r.challenge_type == "cloudflare"

    @pytest.mark.asyncio
    async def test_429_exhausted_exception_carries_response(self):
        """Async mirror: RateLimited.response is the final 429 reply."""
        session, mock = make_async_session(
            [MockResponse(429, body="Rate limited body")] * 15,
            max_rotations=3,
        )
        with patch("wafer._async.asyncio.sleep", return_value=None):
            with pytest.raises(RateLimited) as exc_info:
                await session.get("https://example.com")
        r = exc_info.value.response
        assert r is not None
        assert r.status_code == 429
        assert r.text == "Rate limited body"

    @pytest.mark.asyncio
    async def test_empty_200_exhausted_exception_carries_response(self):
        """Async mirror: EmptyResponse.response is the final empty reply."""
        session, mock = make_async_session(
            [MockResponse(200, body="")] * 5,
            max_retries=3,
        )
        with patch("wafer._async.asyncio.sleep", return_value=None):
            with pytest.raises(EmptyResponse) as exc_info:
                await session.get("https://example.com")
        r = exc_info.value.response
        assert r is not None
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_second_rotation_firefox(self):
        """Async mirror: rung 2 of the cross-family ladder is Firefox."""
        session, mock = make_async_session(
            [
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(200, body="OK"),
            ],
            max_failures=None,
        )
        with patch("wafer._async.asyncio.sleep", return_value=None):
            await session.get("https://example.com")
        assert session._safari_identity is None
        assert emulation_family(session._fingerprint.current) == "firefox"
        assert session.headers["Accept-Language"] == "en-US,en;q=0.5"

    @pytest.mark.asyncio
    async def test_fingerprint_pool_cycles(self):
        """Async mirror: a pool replaces the ladder as the rotation source."""
        session, mock = make_async_session(
            [
                MockResponse(403, body="Denied"),
                MockResponse(403, body="Denied"),
                MockResponse(200, body="OK"),
            ],
            fingerprint_pool=[
                Emulation.Chrome149,
                Emulation.Firefox151,
                Emulation.Edge148,
            ],
            max_rotations=5,
            max_failures=None,
        )
        with patch("wafer._async.asyncio.sleep", return_value=None):
            resp = await session.get("https://example.com")
        assert resp.status_code == 200
        assert emulation_family(session._fingerprint.current) == "edge"
        assert session._safari_identity is None

    @pytest.mark.asyncio
    async def test_empty_200_from_capable_host_rotates(self):
        """Async mirror: empty 200 from a 200-capable host rotates."""
        session, mock = make_async_session(
            [
                MockResponse(200, body="real"),
                MockResponse(200, body=""),
                MockResponse(200, body=""),
                MockResponse(200, body=""),
                MockResponse(200, body=""),
                MockResponse(200, body="recovered"),
            ],
            max_retries=3,
            max_rotations=2,
            max_failures=None,
        )
        with patch("wafer._async.asyncio.sleep", return_value=None):
            await session.get("https://example.com")
            resp = await session.get("https://example.com")
        assert resp.text == "recovered"
        assert resp.rotations >= 1

    @pytest.mark.asyncio
    async def test_max_retries_0_returns_empty_200_without_rotating(self):
        """Async mirror of FIX 2: max_retries=0 returns the empty 200."""
        session, mock = make_async_session(
            [
                MockResponse(200, body="real"),  # arm host as 200-capable
                MockResponse(200, body=""),       # empty -> must be RETURNED
                MockResponse(200, body="recovered"),  # never requested
            ],
            max_retries=0,
            max_rotations=2,
            max_failures=None,
        )
        with patch("wafer._async.asyncio.sleep", return_value=None):
            await session.get("https://example.com")  # arm capability
            resp = await session.get("https://example.com")
        assert resp.status_code == 200
        assert resp.text == ""
        assert resp.rotations == 0
        assert mock.request_count == 2


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

    @patch("wafer._sync.time.sleep")
    def test_history_records_redirect_chain(self, mock_sleep):
        """resp.history lists each followed hop in order (requests-style)."""
        r1 = MockResponse(
            301, {"location": "https://a.com/step1"}, ""
        )
        r2 = MockResponse(
            302, {"location": "https://b.com/step2"}, ""
        )
        ok = MockResponse(200, body="<html>Done</html>")
        session, _ = make_sync_session([r1, r2, ok])
        resp = session.get("https://start.com/")
        assert resp.history == [
            (301, "https://start.com/"),
            (302, "https://a.com/step1"),
        ]
        assert resp.history[0].status_code == 301
        assert resp.history[0].url == "https://start.com/"
        assert resp.url == "https://b.com/step2"

    @patch("wafer._sync.time.sleep")
    def test_history_empty_without_redirect(self, mock_sleep):
        session, _ = make_sync_session([MockResponse(200, body="ok")])
        resp = session.get("https://example.com")
        assert resp.history == []


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
