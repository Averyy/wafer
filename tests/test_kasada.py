"""Tests for Kasada CD generator, session cache, and retry integration."""

import hashlib
import json
from unittest.mock import patch

from tests.conftest import MockResponse, make_sync_session
from wafer._kasada import (
    _sessions,
    generate_cd,
    get_session,
    store_session,
)
from wafer.browser import SolveResult

# ---------------------------------------------------------------------------
# CD generator
# ---------------------------------------------------------------------------


class TestGenerateCD:
    def test_returns_valid_json_with_correct_fields(self):
        cd = generate_cd(1707644948142)
        data = json.loads(cd)
        assert "workTime" in data
        assert "id" in data
        assert "answers" in data
        assert "duration" in data
        assert "d" in data
        assert "st" in data
        assert "rst" in data

    def test_id_is_32_char_hex(self):
        cd = generate_cd(1707644948142)
        data = json.loads(cd)
        assert len(data["id"]) == 32
        int(data["id"], 16)  # should not raise

    def test_d_in_range(self):
        cd = generate_cd(1707644948142)
        data = json.loads(cd)
        assert 1400 <= data["d"] <= 2700

    def test_duration_is_float(self):
        cd = generate_cd(1707644948142)
        data = json.loads(cd)
        assert isinstance(data["duration"], float)

    def test_rst_equals_st_plus_d(self):
        cd = generate_cd(1707644948142)
        data = json.loads(cd)
        assert data["rst"] == data["st"] + data["d"]

    def test_answers_are_positive_ints(self):
        cd = generate_cd(1707644948142)
        data = json.loads(cd)
        assert len(data["answers"]) == 2
        for answer in data["answers"]:
            assert isinstance(answer, int)
            assert answer > 0

    def test_hash_chaining_satisfies_difficulty(self):
        """Verify the chained hash algorithm matches the spec."""
        st = 1707644948142
        difficulty = 10
        subchallenges = 2
        target = difficulty / subchallenges

        cd = generate_cd(st, difficulty=difficulty, subchallenges=subchallenges)
        data = json.loads(cd)

        # Replay the hash chain to verify answers
        challenge_id = data["id"]
        hash_val = hashlib.sha256(
            f"tp-v2-input, {st}, {challenge_id}".encode()
        ).hexdigest()

        for answer in data["answers"]:
            h = hashlib.sha256(
                f"{answer}, {hash_val}".encode()
            ).hexdigest()
            score = 0x10000000000000 / (int(h[:13], 16) + 1)
            assert score >= target
            hash_val = h  # chain

    def test_different_each_call(self):
        cd1 = generate_cd(1707644948142)
        cd2 = generate_cd(1707644948142)
        data1 = json.loads(cd1)
        data2 = json.loads(cd2)
        # Different challenge_id each time
        assert data1["id"] != data2["id"]

    def test_st_preserved(self):
        st = 1707644948142
        cd = generate_cd(st)
        data = json.loads(cd)
        assert data["st"] == st

    def test_custom_difficulty(self):
        cd = generate_cd(12345, difficulty=5, subchallenges=3)
        data = json.loads(cd)
        assert len(data["answers"]) == 3
        # d is the random offset, not the difficulty param
        assert 1400 <= data["d"] <= 2700


# ---------------------------------------------------------------------------
# Session cache
# ---------------------------------------------------------------------------


class TestSessionCache:
    def setup_method(self):
        _sessions.clear()

    def test_store_and_get_session(self):
        store_session(
            "example.com",
            "test-ct",
            12345,
            [{"name": "tkrm", "value": "x"}],
        )
        session = get_session("example.com")
        assert session is not None
        assert session.ct == "test-ct"
        assert session.st == 12345
        assert len(session.cookies) == 1

    def test_expired_session_returns_none(self):
        store_session("example.com", "ct", 123, [], ttl=-1)
        assert get_session("example.com") is None

    def test_different_domains_independent(self):
        store_session("a.com", "ct-a", 1, [])
        store_session("b.com", "ct-b", 2, [])
        assert get_session("a.com").ct == "ct-a"
        assert get_session("b.com").ct == "ct-b"

    def test_missing_domain_returns_none(self):
        assert get_session("nonexistent.com") is None

    def test_overwrite_session(self):
        store_session("example.com", "old-ct", 1, [])
        store_session("example.com", "new-ct", 2, [])
        session = get_session("example.com")
        assert session.ct == "new-ct"
        assert session.st == 2

    def test_expired_session_cleaned_up(self):
        store_session("example.com", "ct", 123, [], ttl=-1)
        get_session("example.com")
        assert "example.com" not in _sessions


# ---------------------------------------------------------------------------
# Browser solve → retry integration
# ---------------------------------------------------------------------------


class MockBrowserSolver:
    """Mock BrowserSolver that returns predefined results."""

    def __init__(self, result=None):
        self._result = result
        self.solve_calls = []

    def solve(self, url, challenge_type=None, timeout=None):
        self.solve_calls.append((url, challenge_type))
        return self._result

    def close(self):
        pass


class TestKasadaRetryIntegration:
    def setup_method(self):
        _sessions.clear()

    @patch("time.sleep")
    def test_kasada_browser_solve_then_retry(self, mock_sleep):
        """Full flow: 429 + kasada → browser solve → retry with cookies only.

        CT+CD headers are NOT injected because x-kpsdk-h HMAC is
        unavailable. Sending CT+CD without H causes server rejection.
        """
        mock_browser = MockBrowserSolver(
            result=SolveResult(
                cookies=[
                    {
                        "name": "tkrm_alpekz_s1.3",
                        "value": "abc",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": -1,
                    }
                ],
                user_agent="Chrome/145",
                extras={"ct": "test-ct-token", "st": 1707644948142},
            )
        )
        responses = [
            MockResponse(
                429,
                {"x-kpsdk-ct": "challenge"},
                "<html>kasada</html>",
            ),
            MockResponse(200, {}, "<html>success</html>"),
        ]
        session, mock_client = make_sync_session(
            responses,
            browser_solver=mock_browser,
            use_cookie_jar=True,
        )

        resp = session.request("GET", "https://example.com/page")
        assert resp.status_code == 200

        # Browser solver was called with kasada type
        assert len(mock_browser.solve_calls) == 1
        assert mock_browser.solve_calls[0] == (
            "https://example.com/page",
            "kasada",
        )

        # CT+CD NOT injected (no H HMAC available)
        retry_headers = mock_client.request_log[1][2]["headers"]
        assert "x-kpsdk-ct" not in retry_headers
        assert "x-kpsdk-cd" not in retry_headers

    @patch("time.sleep")
    def test_kasada_429_not_treated_as_rate_limit(self, mock_sleep):
        """Kasada 429 should route to challenge handler, not 429 handler."""
        mock_browser = MockBrowserSolver(
            result=SolveResult(
                cookies=[
                    {
                        "name": "tkrm",
                        "value": "x",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": -1,
                    }
                ],
                user_agent="Chrome/145",
                extras={"ct": "ct", "st": 12345},
            )
        )
        responses = [
            MockResponse(
                429,
                {"x-kpsdk-ct": "challenge"},
                "<html>kpsdk</html>",
            ),
            MockResponse(200, {}, "<html>ok</html>"),
        ]
        session, _ = make_sync_session(
            responses,
            max_rotations=0,
            browser_solver=mock_browser,
            use_cookie_jar=True,
        )

        # With max_rotations=0, a normal 429 would raise RateLimited.
        # But Kasada 429 goes through challenge handler → browser solve.
        resp = session.request("GET", "https://example.com/page")
        assert resp.status_code == 200
        assert len(mock_browser.solve_calls) == 1

    @patch("time.sleep")
    def test_kasada_body_ips_js_triggers_browser_solve(self, mock_sleep):
        """Kasada body with ips.js marker on 429 triggers browser solve."""
        mock_browser = MockBrowserSolver(
            result=SolveResult(
                cookies=[
                    {
                        "name": "tkrm",
                        "value": "x",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": -1,
                    }
                ],
                user_agent="Chrome/145",
                extras={"ct": "ct-val", "st": 99999},
            )
        )
        responses = [
            MockResponse(
                429, {}, '<script src="/ips.js"></script>'
            ),
            MockResponse(200, {}, "<html>ok</html>"),
        ]
        session, _ = make_sync_session(
            responses,
            browser_solver=mock_browser,
            use_cookie_jar=True,
        )

        resp = session.request("GET", "https://example.com/page")
        assert resp.status_code == 200
        assert mock_browser.solve_calls[0][1] == "kasada"

    @patch("time.sleep")
    def test_subsequent_requests_no_ct_cd_without_hmac(self, mock_sleep):
        """Cached session does NOT inject CT+CD (no H HMAC available)."""
        _sessions.clear()
        store_session("example.com", "cached-ct", 1707644948142, [])

        responses = [
            MockResponse(200, {}, "<html>ok</html>"),
        ]
        session, mock_client = make_sync_session(responses)

        resp = session.request("GET", "https://example.com/page")
        assert resp.status_code == 200

        # CT+CD NOT injected (would need x-kpsdk-h HMAC)
        req_headers = mock_client.request_log[0][2]["headers"]
        assert "x-kpsdk-ct" not in req_headers
        assert "x-kpsdk-cd" not in req_headers

    @patch("time.sleep")
    def test_no_kasada_headers_without_session(self, mock_sleep):
        """Without a cached Kasada session, no tokens are injected."""
        _sessions.clear()

        responses = [
            MockResponse(200, {}, "<html>ok</html>"),
        ]
        session, mock_client = make_sync_session(responses)

        session.request("GET", "https://example.com/page")

        req_headers = mock_client.request_log[0][2]["headers"]
        assert "x-kpsdk-ct" not in req_headers
        assert "x-kpsdk-cd" not in req_headers
