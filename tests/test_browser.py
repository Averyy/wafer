"""Tests for browser-based challenge solving and iframe interception."""

import math
import os
import shutil
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from tests.conftest import (
    MockResponse,
    make_async_session,
    make_sync_session,
)
from wafer._fingerprint import (
    chrome_version_from_ua,
    emulation_for_version,
)
from wafer.browser import (
    BrowserSolver,
    CapturedResponse,
    InterceptResult,
    SolveResult,
    format_cookie_str,
)
from wafer.browser._solver import (
    _angle_from_metadata,
    _parse_csv_rows,
    _parse_metadata,
)

# ---------------------------------------------------------------------------
# Local mock (browser-specific, not shared)
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


# ---------------------------------------------------------------------------
# SolveResult tests
# ---------------------------------------------------------------------------


class TestSolveResult:
    def test_creation(self):
        cookies = [{"name": "cf_clearance", "value": "abc123"}]
        result = SolveResult(cookies=cookies, user_agent="Chrome/145")
        assert result.cookies == cookies
        assert result.user_agent == "Chrome/145"

    def test_empty_cookies(self):
        result = SolveResult(cookies=[], user_agent="")
        assert result.cookies == []
        assert result.user_agent == ""


# ---------------------------------------------------------------------------
# format_cookie_str tests
# ---------------------------------------------------------------------------


class TestFormatCookieStr:
    def test_simple_cookie(self):
        cookie = {
            "name": "cf_clearance",
            "value": "abc123",
            "domain": ".example.com",
            "path": "/",
            "expires": -1,
            "secure": True,
            "httpOnly": True,
            "sameSite": "None",
        }
        result = format_cookie_str(cookie)
        assert result.startswith("cf_clearance=abc123")
        assert "Domain=.example.com" in result
        assert "Path=/" in result
        assert "Secure" in result
        assert "HttpOnly" in result
        # sameSite "None" should be included (needed for cross-site cookies)
        assert "SameSite=None" in result

    def test_session_cookie_no_expires(self):
        cookie = {
            "name": "sid",
            "value": "xyz",
            "domain": ".test.com",
            "path": "/",
            "expires": -1,
        }
        result = format_cookie_str(cookie)
        assert "Expires" not in result

    def test_cookie_with_expires(self):
        cookie = {
            "name": "token",
            "value": "val",
            "domain": ".test.com",
            "path": "/",
            "expires": 1800000000,
            "secure": False,
        }
        result = format_cookie_str(cookie)
        assert "Expires=" in result
        assert "Secure" not in result

    def test_same_site_lax(self):
        cookie = {
            "name": "pref",
            "value": "1",
            "domain": ".test.com",
            "path": "/",
            "expires": -1,
            "sameSite": "Lax",
        }
        result = format_cookie_str(cookie)
        assert "SameSite=Lax" in result

    def test_minimal_cookie(self):
        cookie = {"name": "a", "value": "b"}
        result = format_cookie_str(cookie)
        assert result == "a=b"


# ---------------------------------------------------------------------------
# chrome_version_from_ua tests
# ---------------------------------------------------------------------------


class TestChromeVersionFromUA:
    def test_standard_chrome_ua(self):
        ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/133.0.0.0 Safari/537.36"
        )
        assert chrome_version_from_ua(ua) == 133

    def test_chrome_145(self):
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/145.0.0.0 Safari/537.36"
        )
        assert chrome_version_from_ua(ua) == 145

    def test_firefox_ua(self):
        ua = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
        assert chrome_version_from_ua(ua) is None

    def test_safari_ua(self):
        ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.0 Safari/605.1.15"
        )
        assert chrome_version_from_ua(ua) is None

    def test_empty_string(self):
        assert chrome_version_from_ua("") is None


# ---------------------------------------------------------------------------
# emulation_for_version tests
# ---------------------------------------------------------------------------


class TestEmulationForVersion:
    def test_known_version_145(self):
        em = emulation_for_version(145)
        assert em is not None
        assert repr(em) == "Emulation.Chrome145"

    def test_known_version_100(self):
        em = emulation_for_version(100)
        assert em is not None
        assert repr(em) == "Emulation.Chrome100"

    def test_unknown_version(self):
        assert emulation_for_version(999) is None

    def test_version_0(self):
        assert emulation_for_version(0) is None


# ---------------------------------------------------------------------------
# BrowserSolver init / lifecycle tests
# ---------------------------------------------------------------------------


class TestBrowserSolverInit:
    def test_default_params(self):
        solver = BrowserSolver()
        assert solver._headless is False
        assert solver._idle_timeout == 300.0
        assert solver._solve_timeout == 30.0
        assert solver._browser is None
        assert solver._playwright is None

    def test_custom_params(self):
        solver = BrowserSolver(
            headless=True, idle_timeout=60, solve_timeout=15
        )
        assert solver._headless is True
        assert solver._idle_timeout == 60.0
        assert solver._solve_timeout == 15.0

    def test_context_manager(self):
        solver = BrowserSolver()
        with solver as s:
            assert s is solver

    def test_close_without_browser(self):
        solver = BrowserSolver()
        solver.close()  # Should not raise


# ---------------------------------------------------------------------------
# Sync retry loop integration with browser solving
# ---------------------------------------------------------------------------


class TestSyncBrowserSolveIntegration:
    @patch("time.sleep")
    def test_browser_solve_called_when_rotations_exhausted(
        self, mock_sleep
    ):
        """Browser solver should be tried when all rotations are used up."""
        # Cloudflare challenge response (always returns 403 + cf marker)
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        # After browser solve, return success
        ok_resp = MockResponse(200, body="<html>Real page</html>")

        browser_result = SolveResult(
            cookies=[
                {
                    "name": "cf_clearance",
                    "value": "solved",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "None",
                }
            ],
            user_agent=(
                "Mozilla/5.0 Chrome/145.0.0.0 Safari/537.36"
            ),
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        # 2 rotations allowed → 2 challenges → rotations exhausted
        # → browser solve → retry → success
        session, mock_client = make_sync_session(
            [cf_resp, cf_resp, cf_resp, ok_resp],
            max_rotations=2,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        resp = session.get("https://example.com/page")
        assert resp.status_code == 200
        assert len(mock_solver.solve_calls) == 1
        assert mock_solver.solve_calls[0] == (
            "https://example.com/page",
            "cloudflare",
        )

    @patch("time.sleep")
    def test_browser_solve_not_called_for_non_js_challenge_with_rotations(
        self, mock_sleep
    ):
        """Browser solver should not be called for non-JS challenges
        while rotations remain (rotation can help with these)."""
        # Akamai is NOT in JS_ONLY_CHALLENGES — rotation is tried first
        akamai_resp = MockResponse(
            403,
            {"set-cookie": "_abck=xyz; Path=/"},
            "<html>akam reference</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real page</html>")

        mock_solver = MockBrowserSolver(
            result=SolveResult(
                cookies=[{"name": "x", "value": "y"}],
                user_agent="Chrome/145",
            )
        )

        session, _ = make_sync_session(
            [akamai_resp, ok_resp],
            max_rotations=10,
            browser_solver=mock_solver,
        )

        resp = session.get("https://example.com/page")
        assert resp.status_code == 200
        assert len(mock_solver.solve_calls) == 0

    @patch("time.sleep")
    def test_browser_solve_not_called_when_no_solver(
        self, mock_sleep
    ):
        """Without browser_solver, challenge returns response
        (max_rotations=0 returns instead of raising)."""
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )

        session, _ = make_sync_session(
            [cf_resp],
            max_rotations=0,
            browser_solver=None,
        )

        resp = session.get("https://example.com/page")
        assert resp.status_code == 403
        assert resp.challenge_type == "cloudflare"

    @patch("time.sleep")
    def test_browser_solve_failure_returns_challenge(
        self, mock_sleep
    ):
        """If browser solve returns None with max_rotations=0,
        response is returned with challenge_type set."""
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )

        mock_solver = MockBrowserSolver(result=None)

        session, _ = make_sync_session(
            [cf_resp],
            max_rotations=0,
            browser_solver=mock_solver,
        )

        resp = session.get("https://example.com/page")
        assert resp.status_code == 403
        assert resp.challenge_type == "cloudflare"
        assert len(mock_solver.solve_calls) == 1

    @patch("time.sleep")
    def test_browser_solve_only_attempted_once(self, mock_sleep):
        """Browser solve should only be attempted once per request."""
        from wafer._errors import ChallengeDetected

        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )

        # Browser solve returns cookies but they don't help
        mock_solver = MockBrowserSolver(
            result=SolveResult(
                cookies=[
                    {
                        "name": "cf_clearance",
                        "value": "stale",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": -1,
                    }
                ],
                user_agent="Chrome/145",
            )
        )

        # max_rotations=1: first challenge uses rotation,
        # second challenge → browser solve → third challenge → give up
        session, _ = make_sync_session(
            [cf_resp, cf_resp, cf_resp],
            max_rotations=1,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        with pytest.raises(ChallengeDetected):
            session.get("https://example.com/page")
        # Browser solve attempted exactly once
        assert len(mock_solver.solve_calls) == 1

    @patch("time.sleep")
    def test_browser_solve_cookies_injected_into_jar(
        self, mock_sleep
    ):
        """Browser cookies should be added to the client's cookie jar."""
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real</html>")

        browser_result = SolveResult(
            cookies=[
                {
                    "name": "cf_clearance",
                    "value": "solved123",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                    "secure": True,
                    "httpOnly": True,
                },
                {
                    "name": "__cf_bm",
                    "value": "token456",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": 1800000000,
                },
            ],
            user_agent="Chrome/145.0.0.0",
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        session, mock_client = make_sync_session(
            [cf_resp, ok_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        resp = session.get("https://example.com/page")
        assert resp.status_code == 200

        # Verify cookies were added to jar
        jar = mock_client.cookie_jar
        assert len(jar.added) == 2
        assert any(
            "cf_clearance=solved123" in c[0] for c in jar.added
        )
        assert any(
            "__cf_bm=token456" in c[0] for c in jar.added
        )

    @patch("time.sleep")
    def test_browser_solve_fingerprint_matched(self, mock_sleep):
        """After browser solve, emulation should match browser's Chrome version."""
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real</html>")

        browser_result = SolveResult(
            cookies=[
                {
                    "name": "cf_clearance",
                    "value": "x",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 Chrome/133.0.0.0 Safari/537.36"
            ),
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        session, _ = make_sync_session(
            [cf_resp, ok_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        session.get("https://example.com/page")
        # Fingerprint should have been reset to Chrome133
        assert repr(session._fingerprint.current) == "Emulation.Chrome133"

    @patch("time.sleep")
    def test_browser_solve_with_cookie_cache(
        self, mock_sleep, tmp_path
    ):
        """Browser cookies should be persisted to disk cache."""
        from wafer._cookies import CookieCache

        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real</html>")

        browser_result = SolveResult(
            cookies=[
                {
                    "name": "cf_clearance",
                    "value": "disk_cached",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                    "secure": True,
                    "httpOnly": True,
                }
            ],
            user_agent="Chrome/145.0.0.0",
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        session, _ = make_sync_session(
            [cf_resp, ok_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )
        session._cookie_cache = CookieCache(str(tmp_path))

        session.get("https://example.com/page")

        # Verify cookies persisted to disk
        cached = session._cookie_cache.load("example.com")
        assert len(cached) >= 1
        assert any(
            c["name"] == "cf_clearance" for c in cached
        )

    @patch("time.sleep")
    def test_browser_solve_for_datadome(self, mock_sleep):
        """Browser solver should be called with 'datadome' challenge type."""
        dd_resp = MockResponse(
            403,
            {"set-cookie": "datadome=abc; Path=/"},
            "<html>datadome challenge</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real</html>")

        browser_result = SolveResult(
            cookies=[
                {
                    "name": "datadome",
                    "value": "solved",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Chrome/145",
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        session, _ = make_sync_session(
            [dd_resp, ok_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        resp = session.get("https://example.com/page")
        assert resp.status_code == 200
        assert mock_solver.solve_calls[0][1] == "datadome"


# ---------------------------------------------------------------------------
# Async retry loop integration with browser solving
# ---------------------------------------------------------------------------


class TestBrowserPassthrough:
    """Browser passthrough: WAF doesn't challenge browser, return content directly."""

    @patch("time.sleep")
    def test_passthrough_returns_wafer_response(self, mock_sleep):
        """When browser gets real content without solving, return it directly."""
        from wafer.browser._solver import CapturedResponse

        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )

        # Browser gets 200 with real content (no challenge solved)
        passthrough_body = b"<html><body>Real page content here</body></html>"
        browser_result = SolveResult(
            cookies=[
                {
                    "name": "session_id",
                    "value": "abc",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Chrome/145.0.0.0",
            response=CapturedResponse(
                url="https://example.com/page",
                status=200,
                headers={"content-type": "text/html"},
                body=passthrough_body,
            ),
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        session, mock_client = make_sync_session(
            [cf_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        resp = session.get("https://example.com/page")
        # Should return the browser's content directly
        assert resp.status_code == 200
        assert resp.content == passthrough_body
        assert resp.text == passthrough_body.decode()
        assert resp.headers["content-type"] == "text/html"
        # Only 1 TLS request (the initial 403), no retry
        assert mock_client.request_count == 1

    @patch("time.sleep")
    def test_passthrough_still_injects_cookies(self, mock_sleep):
        """Passthrough should still inject cookies for future TLS requests."""
        from wafer.browser._solver import CapturedResponse

        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )

        browser_result = SolveResult(
            cookies=[
                {
                    "name": "session_id",
                    "value": "injected_val",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Chrome/145.0.0.0",
            response=CapturedResponse(
                url="https://example.com/page",
                status=200,
                headers={},
                body=b"<html>Real content</html>",
            ),
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        session, mock_client = make_sync_session(
            [cf_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        session.get("https://example.com/page")
        # Cookies should still be injected into jar
        jar = mock_client.cookie_jar
        assert len(jar.added) >= 1
        assert any(
            "session_id=injected_val" in c[0] for c in jar.added
        )

    @patch("time.sleep")
    def test_passthrough_not_triggered_when_solved(self, mock_sleep):
        """Normal solve (response=None) should retry via TLS as before."""
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real</html>")

        browser_result = SolveResult(
            cookies=[
                {
                    "name": "cf_clearance",
                    "value": "solved",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Chrome/145.0.0.0",
            response=None,  # Normal solve, no passthrough
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        session, mock_client = make_sync_session(
            [cf_resp, ok_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        resp = session.get("https://example.com/page")
        assert resp.status_code == 200
        # 2 TLS requests: initial 403 + retry after solve
        assert mock_client.request_count == 2

    @patch("time.sleep")
    def test_passthrough_elapsed_set(self, mock_sleep):
        """Passthrough response should have elapsed time set."""
        from wafer.browser._solver import CapturedResponse

        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )

        browser_result = SolveResult(
            cookies=[
                {
                    "name": "x",
                    "value": "y",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Chrome/145",
            response=CapturedResponse(
                url="https://example.com/page",
                status=200,
                headers={},
                body=b"<html>Content</html>",
            ),
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        session, _ = make_sync_session(
            [cf_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        resp = session.get("https://example.com/page")
        assert resp.elapsed > 0


class TestAsyncBrowserSolveIntegration:
    @patch("asyncio.sleep")
    async def test_browser_solve_called_when_rotations_exhausted(
        self, mock_sleep
    ):
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real page</html>")

        browser_result = SolveResult(
            cookies=[
                {
                    "name": "cf_clearance",
                    "value": "solved",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Chrome/145.0.0.0",
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        session, _ = make_async_session(
            [cf_resp, cf_resp, cf_resp, ok_resp],
            max_rotations=2,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        resp = await session.get("https://example.com/page")
        assert resp.status_code == 200
        assert len(mock_solver.solve_calls) == 1

    @patch("asyncio.sleep")
    async def test_browser_solve_failure_returns_challenge(
        self, mock_sleep
    ):
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )

        mock_solver = MockBrowserSolver(result=None)

        session, _ = make_async_session(
            [cf_resp],
            max_rotations=0,
            browser_solver=mock_solver,
        )

        resp = await session.get("https://example.com/page")
        assert resp.status_code == 403
        assert resp.challenge_type == "cloudflare"
        assert len(mock_solver.solve_calls) == 1

    @patch("asyncio.sleep")
    async def test_browser_solve_cookies_injected(
        self, mock_sleep
    ):
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real</html>")

        browser_result = SolveResult(
            cookies=[
                {
                    "name": "cf_clearance",
                    "value": "async_solved",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Chrome/145",
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        session, mock_client = make_async_session(
            [cf_resp, ok_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        resp = await session.get("https://example.com/page")
        assert resp.status_code == 200
        assert len(mock_client.cookie_jar.added) >= 1


# ---------------------------------------------------------------------------
# InterceptResult / CapturedResponse dataclass tests
# ---------------------------------------------------------------------------


class TestInterceptResultDataclass:
    def test_creation(self):
        resp = CapturedResponse(
            url="https://www.marinetraffic.com/data",
            status=200,
            headers={"content-type": "application/json"},
            body=b'{"ships": []}',
        )
        result = InterceptResult(
            cookies=[{"name": "mt_id", "value": "abc"}],
            responses=[resp],
            user_agent="Chrome/145",
        )
        assert len(result.responses) == 1
        assert result.responses[0].url == "https://www.marinetraffic.com/data"
        assert result.responses[0].body == b'{"ships": []}'
        assert result.cookies[0]["name"] == "mt_id"
        assert result.user_agent == "Chrome/145"

    def test_empty_intercept(self):
        result = InterceptResult(
            cookies=[], responses=[], user_agent=""
        )
        assert result.cookies == []
        assert result.responses == []

    def test_captured_response_fields(self):
        resp = CapturedResponse(
            url="https://tiles.marinetraffic.com/tile.png",
            status=304,
            headers={"etag": '"abc"'},
            body=b"",
        )
        assert resp.status == 304
        assert resp.headers["etag"] == '"abc"'
        assert resp.body == b""


# ---------------------------------------------------------------------------
# Iframe intercept unit tests (mocked Playwright)
# ---------------------------------------------------------------------------


def _make_mock_pw_response(url, status=200, headers=None, body=b""):
    """Create a mock Playwright Response object."""
    resp = MagicMock()
    resp.url = url
    resp.status = status
    resp.headers = headers or {}
    resp.body.return_value = body
    return resp


class TestIframeIntercept:
    """Test intercept_iframe() with mocked Playwright internals."""

    def _make_solver_with_mock_browser(self):
        """Create a BrowserSolver with mocked browser/playwright."""
        solver = BrowserSolver()
        solver._browser = MagicMock()
        solver._browser.is_connected.return_value = True
        solver._playwright = MagicMock()
        solver._browser_ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 Chrome/145.0.0.0 Safari/537.36"
        )
        return solver

    def test_captures_target_domain_responses(self):
        solver = self._make_solver_with_mock_browser()

        # Mock context and page
        mock_context = MagicMock()
        mock_page = MagicMock()
        solver._browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page

        # Simulate responses via the on("response") handler
        response_handler = None

        def capture_on(event, handler):
            nonlocal response_handler
            if event == "response":
                response_handler = handler

        mock_page.on = capture_on

        # Mock cookies for target domain
        mock_context.cookies.return_value = [
            {
                "name": "mt_session",
                "value": "xyz",
                "domain": ".marinetraffic.com",
                "path": "/",
                "expires": -1,
            },
            {
                "name": "seaway_pref",
                "value": "en",
                "domain": ".seaway-greatlakes.com",
                "path": "/",
                "expires": -1,
            },
        ]

        # Override goto to trigger response handler
        def fake_goto(url, **kwargs):
            # Simulate iframe responses firing
            response_handler(
                _make_mock_pw_response(
                    "https://www.marinetraffic.com/getData/get_data_json_4",
                    200,
                    {"content-type": "application/json"},
                    b'{"type": 1}',
                )
            )
            response_handler(
                _make_mock_pw_response(
                    "https://seaway-greatlakes.com/assets/style.css",
                    200,
                    {},
                    b"body {}",
                )
            )
            response_handler(
                _make_mock_pw_response(
                    "https://tiles.marinetraffic.com/tile/z11/x285.png",
                    200,
                    {"content-type": "image/png"},
                    b"\x89PNG",
                )
            )

        mock_page.goto = fake_goto

        with patch("time.sleep"):
            result = solver.intercept_iframe(
                embedder_url="https://seaway-greatlakes.com/marine_traffic/en/marineTraffic_stCatherine.html",
                target_domain="marinetraffic.com",
                timeout=10.0,
            )

        assert result is not None
        # Should capture 2 marinetraffic responses, not the seaway one
        assert len(result.responses) == 2
        urls = [r.url for r in result.responses]
        assert "https://www.marinetraffic.com/getData/get_data_json_4" in urls
        assert "https://tiles.marinetraffic.com/tile/z11/x285.png" in urls
        # Should only include marinetraffic cookies
        assert len(result.cookies) == 1
        assert result.cookies[0]["name"] == "mt_session"
        assert result.user_agent == solver._browser_ua

    def test_no_matching_responses(self):
        solver = self._make_solver_with_mock_browser()

        mock_context = MagicMock()
        mock_page = MagicMock()
        solver._browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page

        def capture_on(event, handler):
            pass  # No responses fired

        mock_page.on = capture_on
        mock_context.cookies.return_value = []

        with patch("time.sleep"):
            result = solver.intercept_iframe(
                embedder_url="https://seaway-greatlakes.com/page",
                target_domain="marinetraffic.com",
            )

        assert result is not None
        assert result.responses == []
        assert result.cookies == []

    def test_response_body_failure_captured_as_empty(self):
        """If response.body() throws (e.g. redirect), body is empty bytes."""
        solver = self._make_solver_with_mock_browser()

        mock_context = MagicMock()
        mock_page = MagicMock()
        solver._browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page

        response_handler = None

        def capture_on(event, handler):
            nonlocal response_handler
            if event == "response":
                response_handler = handler

        mock_page.on = capture_on

        # Response whose body() throws
        bad_resp = MagicMock()
        bad_resp.url = "https://www.marinetraffic.com/redirect"
        bad_resp.status = 301
        bad_resp.headers = {"location": "/new-path"}
        bad_resp.body.side_effect = Exception("Response body unavailable")

        def fake_goto(url, **kwargs):
            response_handler(bad_resp)

        mock_page.goto = fake_goto
        mock_context.cookies.return_value = []

        with patch("time.sleep"):
            result = solver.intercept_iframe(
                embedder_url="https://seaway-greatlakes.com/page",
                target_domain="marinetraffic.com",
            )

        assert result is not None
        assert len(result.responses) == 1
        assert result.responses[0].body == b""
        assert result.responses[0].status == 301

    def test_subdomain_matching(self):
        """target_domain matches subdomains (www.X, tiles.X, etc.)."""
        solver = self._make_solver_with_mock_browser()

        mock_context = MagicMock()
        mock_page = MagicMock()
        solver._browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page

        response_handler = None

        def capture_on(event, handler):
            nonlocal response_handler
            if event == "response":
                response_handler = handler

        mock_page.on = capture_on

        def fake_goto(url, **kwargs):
            # Various subdomains
            response_handler(
                _make_mock_pw_response(
                    "https://marinetraffic.com/api",
                    200, {}, b"root",
                )
            )
            response_handler(
                _make_mock_pw_response(
                    "https://www.marinetraffic.com/page",
                    200, {}, b"www",
                )
            )
            response_handler(
                _make_mock_pw_response(
                    "https://tiles.marinetraffic.com/t1",
                    200, {}, b"tiles",
                )
            )
            response_handler(
                _make_mock_pw_response(
                    "https://notmarinetraffic.com/fake",
                    200, {}, b"fake",
                )
            )

        mock_page.goto = fake_goto
        mock_context.cookies.return_value = []

        with patch("time.sleep"):
            result = solver.intercept_iframe(
                embedder_url="https://embedder.example.com",
                target_domain="marinetraffic.com",
            )

        assert result is not None
        # Should match root domain + subdomains, NOT notmarinetraffic.com
        assert len(result.responses) == 3
        urls = {r.url for r in result.responses}
        assert "https://notmarinetraffic.com/fake" not in urls

    def test_browser_launch_failure_returns_none(self):
        solver = BrowserSolver()
        # No browser, ensure_browser will try to import patchright

        with patch(
            "wafer.browser._solver.BrowserSolver._ensure_browser",
            side_effect=Exception("No display"),
        ):
            result = solver.intercept_iframe(
                embedder_url="https://seaway-greatlakes.com/page",
                target_domain="marinetraffic.com",
            )

        assert result is None

    def test_navigation_error_still_captures(self):
        """Even if goto() raises, captured responses before the error
        are still returned."""
        solver = self._make_solver_with_mock_browser()

        mock_context = MagicMock()
        mock_page = MagicMock()
        solver._browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page

        response_handler = None

        def capture_on(event, handler):
            nonlocal response_handler
            if event == "response":
                response_handler = handler

        mock_page.on = capture_on

        def failing_goto(url, **kwargs):
            # Some responses arrive before timeout
            response_handler(
                _make_mock_pw_response(
                    "https://www.marinetraffic.com/partial",
                    200, {}, b"partial data",
                )
            )
            raise TimeoutError("Navigation timeout")

        mock_page.goto = failing_goto
        mock_context.cookies.return_value = []

        with patch("time.sleep"):
            result = solver.intercept_iframe(
                embedder_url="https://seaway-greatlakes.com/page",
                target_domain="marinetraffic.com",
            )

        assert result is not None
        assert len(result.responses) == 1
        assert result.responses[0].body == b"partial data"

    def test_context_closed_on_success(self):
        """Context is closed even after successful intercept."""
        solver = self._make_solver_with_mock_browser()

        mock_context = MagicMock()
        mock_page = MagicMock()
        solver._browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        mock_page.on = lambda *a: None
        mock_context.cookies.return_value = []

        with patch("time.sleep"):
            solver.intercept_iframe(
                embedder_url="https://seaway-greatlakes.com/page",
                target_domain="marinetraffic.com",
            )

        mock_context.close.assert_called_once()

    def test_context_closed_on_error(self):
        """Context is closed even if an exception occurs."""
        solver = self._make_solver_with_mock_browser()

        mock_context = MagicMock()
        solver._browser.new_context.return_value = mock_context
        mock_context.new_page.side_effect = RuntimeError("page crash")

        with patch("time.sleep"):
            result = solver.intercept_iframe(
                embedder_url="https://seaway-greatlakes.com/page",
                target_domain="marinetraffic.com",
            )

        assert result is None
        mock_context.close.assert_called_once()


# ---------------------------------------------------------------------------
# Module-level CSV / metadata helpers
# ---------------------------------------------------------------------------


class TestParseMetadata:
    def test_path_metadata(self):
        line = (
            "# type=paths viewport=1280x720"
            " start=45,68 end=640,396"
            " direction=to_center_from_ul"
        )
        meta = _parse_metadata(line)
        assert meta["type"] == "paths"
        assert meta["viewport"] == "1280x720"
        assert meta["start"] == "45,68"
        assert meta["end"] == "640,396"
        assert meta["direction"] == "to_center_from_ul"

    def test_hold_metadata(self):
        meta = _parse_metadata("# type=holds viewport=1280x720")
        assert meta["type"] == "holds"
        assert "start" not in meta

    def test_non_comment_returns_empty(self):
        assert _parse_metadata("t,dx,dy") == {}

    def test_empty_string(self):
        assert _parse_metadata("") == {}


class TestParseCsvRows:
    def test_idle_rows(self):
        text = (
            "# type=idles viewport=1280x720\n"
            "t,dx,dy\n"
            "0.000,0.0,0.0\n"
            "0.050,5.3,2.1\n"
            "0.100,-3.2,8.4\n"
        )
        rows = _parse_csv_rows(text, ("t", "dx", "dy"))
        assert len(rows) == 3
        assert rows[0] == {"t": 0.0, "dx": 0.0, "dy": 0.0}
        assert rows[1]["dx"] == pytest.approx(5.3)
        assert rows[2]["dy"] == pytest.approx(8.4)

    def test_path_rows(self):
        text = (
            "# type=paths viewport=1280x720"
            " start=50,50 end=640,400"
            " direction=to_center_from_ul\n"
            "t,rx,ry\n"
            "0.000,0.0000,0.0000\n"
            "0.500,0.5000,0.5000\n"
            "1.000,1.0000,1.0000\n"
        )
        rows = _parse_csv_rows(text, ("t", "rx", "ry"))
        assert len(rows) == 3
        assert rows[2]["rx"] == pytest.approx(1.0)

    def test_skips_comment_lines(self):
        text = "# comment\n# another\nt,dx,dy\n0.0,1.0,2.0\n"
        rows = _parse_csv_rows(text, ("t", "dx", "dy"))
        assert len(rows) == 1

    def test_empty_text(self):
        rows = _parse_csv_rows("# comment\nt,dx,dy\n", ("t", "dx", "dy"))
        assert rows == []


class TestAngleFromMetadata:
    def test_from_start_end_coords(self):
        meta = {"start": "50,50", "end": "640,400"}
        angle = _angle_from_metadata(meta)
        expected = math.atan2(350, 590)
        assert angle == pytest.approx(expected, abs=0.01)

    def test_fallback_to_direction_name(self):
        meta = {"direction": "to_center_from_ur"}
        angle = _angle_from_metadata(meta)
        assert angle == pytest.approx(2.55)

    def test_missing_both_returns_default(self):
        assert _angle_from_metadata({}) == pytest.approx(0.6)


# ---------------------------------------------------------------------------
# Recording loader
# ---------------------------------------------------------------------------

# Synthetic test recordings
_IDLE_CSV = (
    "# type=idles viewport=1280x720\n"
    "t,dx,dy\n"
    "0.000,0.0,0.0\n"
    "0.050,10.0,5.0\n"
    "0.100,20.0,10.0\n"
    "0.150,15.0,12.0\n"
)

_PATH_CSV_UL = (
    "# type=paths viewport=1280x720"
    " start=50,50 end=640,400"
    " direction=to_center_from_ul\n"
    "t,rx,ry\n"
    "0.000,0.0000,0.0000\n"
    "0.200,0.3000,0.2500\n"
    "0.400,0.6000,0.5500\n"
    "0.600,0.8500,0.8000\n"
    "0.800,1.0000,1.0000\n"
)

_PATH_CSV_BR = (
    "# type=paths viewport=1280x720"
    " start=1200,680 end=640,400"
    " direction=to_center_from_br\n"
    "t,rx,ry\n"
    "0.000,0.0000,0.0000\n"
    "0.300,0.4000,0.3500\n"
    "0.600,0.7500,0.7000\n"
    "0.900,1.0000,1.0000\n"
)

_HOLD_CSV = (
    "# type=holds viewport=1280x720\n"
    "t,dx,dy\n"
    "0.000,0.0,0.0\n"
    "0.100,0.3,-0.2\n"
    "0.200,-0.5,0.4\n"
    "5.000,0.1,-0.1\n"
    "10.000,-0.2,0.3\n"
    "11.000,0.1,0.0\n"
)

_DRAG_CSV = (
    "# type=drags viewport=1280x720 start=140,363 end=1178,360\n"
    "t,rx,ry\n"
    "0.000,0.0000,0.0000\n"
    "0.200,0.2500,0.0100\n"
    "0.400,0.5000,-0.0050\n"
    "0.600,0.7500,0.0030\n"
    "0.800,1.0000,0.0000\n"
)


def _setup_recordings_dir(tmp_path):
    """Write synthetic CSVs to a temp directory mimicking _recordings/."""
    for subdir, name, content in [
        ("idles", "idle_001.csv", _IDLE_CSV),
        ("paths", "to_center_from_ul_001.csv", _PATH_CSV_UL),
        ("paths", "to_center_from_br_001.csv", _PATH_CSV_BR),
        ("holds", "hold_001.csv", _HOLD_CSV),
        ("drags", "drag_001.csv", _DRAG_CSV),
    ]:
        d = tmp_path / subdir
        d.mkdir(exist_ok=True)
        (d / name).write_text(content)
    return tmp_path


class TestRecordingLoader:
    def test_loads_all_categories(self, tmp_path):
        rec_dir = _setup_recordings_dir(tmp_path)
        solver = BrowserSolver()
        with patch(
            "importlib.resources.files",
            return_value=MagicMock(
                __truediv__=lambda self, name: rec_dir
                if name == "_recordings"
                else self,
            ),
        ):
            # Directly set up the patched resource to return our dir
            pkg_mock = MagicMock()
            pkg_mock.__truediv__ = (
                lambda self, name: rec_dir
            )

            with patch(
                "wafer.browser._solver.importlib.resources.files",
                return_value=pkg_mock,
            ):
                result = solver._ensure_recordings()

        assert result is True
        assert len(solver._idle_recordings) == 1
        assert len(solver._path_recordings) == 2
        assert len(solver._hold_recordings) == 1
        assert len(solver._drag_recordings) == 1

    def test_returns_false_when_empty(self, tmp_path):
        # Empty dirs — no CSVs
        for sub in ("idles", "paths", "holds", "drags"):
            (tmp_path / sub).mkdir()

        solver = BrowserSolver()
        pkg_mock = MagicMock()
        pkg_mock.__truediv__ = lambda self, name: tmp_path

        with patch(
            "wafer.browser._solver.importlib.resources.files",
            return_value=pkg_mock,
        ):
            result = solver._ensure_recordings()

        assert result is False

    def test_cached_after_first_call(self, tmp_path):
        rec_dir = _setup_recordings_dir(tmp_path)
        solver = BrowserSolver()
        pkg_mock = MagicMock()
        pkg_mock.__truediv__ = lambda self, name: rec_dir

        with patch(
            "wafer.browser._solver.importlib.resources.files",
            return_value=pkg_mock,
        ):
            solver._ensure_recordings()

        # Second call should not re-read (no patch needed)
        result = solver._ensure_recordings()
        assert result is True

    def test_path_recordings_have_angle(self, tmp_path):
        rec_dir = _setup_recordings_dir(tmp_path)
        solver = BrowserSolver()
        pkg_mock = MagicMock()
        pkg_mock.__truediv__ = lambda self, name: rec_dir

        with patch(
            "wafer.browser._solver.importlib.resources.files",
            return_value=pkg_mock,
        ):
            solver._ensure_recordings()

        for rec in solver._path_recordings:
            assert "angle" in rec
            assert isinstance(rec["angle"], float)


# ---------------------------------------------------------------------------
# Path picker
# ---------------------------------------------------------------------------


class TestPathPicker:
    def _make_solver_with_paths(self):
        solver = BrowserSolver()
        solver._path_recordings = [
            {
                "rows": [{"t": 0, "rx": 0, "ry": 0}],
                "angle": math.atan2(350, 590),  # UL→center ~0.53
                "meta": {"direction": "to_center_from_ul"},
            },
            {
                "rows": [{"t": 0, "rx": 0, "ry": 0}],
                "angle": math.atan2(350, -560),  # UR→center ~2.58
                "meta": {"direction": "to_center_from_ur"},
            },
            {
                "rows": [{"t": 0, "rx": 0, "ry": 0}],
                "angle": math.atan2(-280, -560),  # BR→center ~-2.68
                "meta": {"direction": "to_center_from_br"},
            },
        ]
        return solver

    def test_picks_ul_for_upper_left_start(self):
        solver = self._make_solver_with_paths()
        rec = solver._pick_path(50, 50, 640, 400)
        # Should pick the UL→center recording (angle ~0.53)
        assert rec["rows"] == solver._path_recordings[0]["rows"]

    def test_picks_ur_for_upper_right_start(self):
        solver = self._make_solver_with_paths()
        rec = solver._pick_path(1200, 50, 640, 400)
        assert rec["rows"] == solver._path_recordings[1]["rows"]

    def test_picks_br_for_bottom_right_start(self):
        solver = self._make_solver_with_paths()
        rec = solver._pick_path(1200, 680, 640, 400)
        assert rec["rows"] == solver._path_recordings[2]["rows"]


# ---------------------------------------------------------------------------
# Coordinate denormalization
# ---------------------------------------------------------------------------


class TestCoordinateDenormalization:
    """Verify path rx/ry → pixel coordinate math."""

    def test_path_denormalization(self):
        start_x, start_y = 100.0, 100.0
        target_x, target_y = 600.0, 400.0
        dx = target_x - start_x  # 500
        dy = target_y - start_y  # 300

        row = {"rx": 0.5, "ry": 0.5}
        x = start_x + row["rx"] * dx
        y = start_y + row["ry"] * dy
        assert x == pytest.approx(350.0)
        assert y == pytest.approx(250.0)

    def test_path_endpoints(self):
        start_x, start_y = 50.0, 50.0
        target_x, target_y = 640.0, 400.0
        dx = target_x - start_x
        dy = target_y - start_y

        # rx=0, ry=0 → start
        assert start_x + 0.0 * dx == pytest.approx(start_x)
        assert start_y + 0.0 * dy == pytest.approx(start_y)

        # rx=1, ry=1 → target
        assert start_x + 1.0 * dx == pytest.approx(target_x)
        assert start_y + 1.0 * dy == pytest.approx(target_y)

    def test_overshoot(self):
        """rx/ry > 1.0 produces coordinates past the target (natural)."""
        start_x, start_y = 100.0, 100.0
        target_x, target_y = 600.0, 400.0
        dx = target_x - start_x
        dy = target_y - start_y

        row = {"rx": 1.05, "ry": 1.10}
        x = start_x + row["rx"] * dx
        y = start_y + row["ry"] * dy
        assert x > target_x
        assert y > target_y


# ---------------------------------------------------------------------------
# PX solver components (mocked Playwright)
# ---------------------------------------------------------------------------


class TestFindPxButton:
    def _make_px_frame(self, box):
        """Create a mock frame that looks like a PX captcha frame."""
        frame = MagicMock()
        frame.evaluate.return_value = "Human verification challenge"
        btn = MagicMock()
        frame.locator.return_value = btn
        btn.count.return_value = 1
        btn.first.bounding_box.return_value = box
        return frame

    def test_finds_button_in_px_frame(self):
        solver = BrowserSolver()
        page = MagicMock()

        box = {"x": 400, "y": 300, "width": 253, "height": 48}
        px_frame = self._make_px_frame(box)
        page.frames = [MagicMock(), px_frame]
        # Non-PX frame returns wrong title
        page.frames[0].evaluate.return_value = "Zillow"

        result = solver._find_px_button(page, timeout=0.1)
        assert result is not None
        x, y, frame = result
        # 20-80% of width: 400+50.6 to 400+202.4
        assert 450 < x < 603
        # 30-60% of height: 300+14.4 to 300+28.8
        assert 314 < y < 329
        # Should return the actual PX frame
        assert frame is px_frame

    def test_fallback_to_px_captcha_iframe(self):
        solver = BrowserSolver()
        page = MagicMock()

        # No PX frames
        page.frames = []
        # But #px-captcha iframe exists
        iframe_el = MagicMock()
        captcha_el = MagicMock()

        def locator_side_effect(selector):
            if selector == "#px-captcha iframe":
                return iframe_el
            if selector == "#px-captcha":
                return captcha_el
            return MagicMock(count=MagicMock(return_value=0))

        page.locator.side_effect = locator_side_effect
        iframe_el.count.return_value = 1
        iframe_el.first.bounding_box.return_value = {
            "x": 600, "y": 400, "width": 253, "height": 52,
        }

        result = solver._find_px_button(page, timeout=0.1)
        assert result is not None
        x, y, frame = result
        # Within iframe bounds
        assert 600 < x < 853
        assert 400 < y < 452
        # Fallback doesn't identify the frame
        assert frame is None

    def test_fallback_to_px_captcha_div(self):
        solver = BrowserSolver()
        page = MagicMock()

        # No PX frames, no iframe
        page.frames = []
        iframe_el = MagicMock()
        iframe_el.count.return_value = 0
        captcha_el = MagicMock()
        captcha_el.count.return_value = 1
        captcha_el.bounding_box.return_value = {
            "x": 400, "y": 300, "width": 530, "height": 100,
        }

        def locator_side_effect(selector):
            if selector == "#px-captcha iframe":
                return iframe_el
            if selector == "#px-captcha":
                return captcha_el
            return MagicMock(count=MagicMock(return_value=0))

        page.locator.side_effect = locator_side_effect

        result = solver._find_px_button(page, timeout=0.1)
        assert result is not None
        x, y, frame = result
        # 30-70% of 530 + 400 = 559 to 771
        assert 559 < x < 771
        # 15-40% of 100 + 300 = 315 to 340
        assert 315 < y < 340
        # Fallback doesn't identify the frame
        assert frame is None

    def test_returns_none_when_nothing_found(self):
        solver = BrowserSolver()
        page = MagicMock()
        page.frames = []
        page.locator.side_effect = Exception("no element")

        assert solver._find_px_button(page, timeout=0.1) is None


class TestWaitForPxSolve:
    @patch("time.sleep")
    @patch("time.monotonic")
    def test_success_captcha_gone(self, mock_mono, mock_sleep):
        from wafer.browser._perimeterx import wait_for_px_solve
        page = MagicMock()
        # First check: element exists. Second: gone.
        el = MagicMock()
        el.count.side_effect = [1, 0]
        page.locator.return_value = el
        page.frames = []
        mock_mono.side_effect = [0.0, 1.0, 2.0]

        assert wait_for_px_solve(page, timeout=20.0) is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_failure_try_again(self, mock_mono, mock_sleep):
        from wafer.browser._perimeterx import wait_for_px_solve
        page = MagicMock()
        el = MagicMock()
        el.count.return_value = 1
        page.locator.return_value = el
        # PX frame with "try again" text — must have visible button
        px_frame = MagicMock()
        px_frame.evaluate.side_effect = lambda js: (
            "Human verification challenge"
            if "document.title" in js
            else "Try Again"
        )
        btn_loc = MagicMock()
        btn_loc.count.return_value = 1
        btn_loc.first.bounding_box.return_value = {
            "x": 400, "y": 300, "width": 253, "height": 48,
        }
        px_frame.locator.return_value = btn_loc
        page.frames = [px_frame]
        mock_mono.side_effect = [0.0, 1.0]

        assert wait_for_px_solve(page, timeout=20.0) is False

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_navigation_exception_retries(
        self, mock_mono, mock_sleep
    ):
        from wafer.browser._perimeterx import wait_for_px_solve
        page = MagicMock()
        # First: navigation error on url. Second: element gone.
        page.url = PropertyMock(
            side_effect=[Exception("Navigation"), "https://ok"]
        )
        type(page).url = page.url
        el = MagicMock()
        el.count.return_value = 0
        page.locator.return_value = el
        page.frames = []
        mock_mono.side_effect = [0.0, 1.0, 2.0, 3.0]

        assert wait_for_px_solve(page, timeout=20.0) is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_timeout(self, mock_mono, mock_sleep):
        from wafer.browser._perimeterx import wait_for_px_solve
        page = MagicMock()
        el = MagicMock()
        el.count.return_value = 1
        page.locator.return_value = el
        page.frames = []
        # Time immediately past deadline
        mock_mono.side_effect = [0.0, 25.0]

        assert wait_for_px_solve(page, timeout=20.0) is False


class TestHasPxChallenge:
    def test_detects_px_captcha(self):
        from wafer.browser._perimeterx import has_px_challenge
        page = MagicMock()
        el = MagicMock()
        el.count.return_value = 1
        page.locator.return_value = el
        assert has_px_challenge(page) is True

    def test_no_challenge(self):
        from wafer.browser._perimeterx import has_px_challenge
        page = MagicMock()
        el = MagicMock()
        el.count.return_value = 0
        page.locator.return_value = el
        assert has_px_challenge(page) is False

    def test_exception_returns_false(self):
        from wafer.browser._perimeterx import has_px_challenge
        page = MagicMock()
        page.locator.side_effect = Exception("navigation")
        assert has_px_challenge(page) is False


class TestSolvePerimeterx:
    def _make_solver_with_recordings(self):
        solver = BrowserSolver()
        solver._idle_recordings = [
            {
                "rows": [
                    {"t": 0.0, "dx": 0.0, "dy": 0.0},
                    {"t": 0.05, "dx": 10.0, "dy": 5.0},
                ],
                "name": "test_idle.csv",
            }
        ]
        solver._path_recordings = [
            {
                "rows": [
                    {"t": 0.0, "rx": 0.0, "ry": 0.0},
                    {"t": 0.5, "rx": 1.0, "ry": 1.0},
                ],
                "angle": 0.57,
                "meta": {"direction": "to_center_from_ul"},
                "name": "test_path.csv",
            }
        ]
        solver._hold_recordings = [
            {
                "rows": [
                    {"t": 0.0, "dx": 0.0, "dy": 0.0},
                    {"t": 5.0, "dx": 0.3, "dy": -0.2},
                    {"t": 10.0, "dx": -0.1, "dy": 0.1},
                ],
                "name": "test_hold.csv",
            }
        ]
        solver._drag_recordings = []
        return solver

    @patch("time.sleep")
    def test_full_flow_success(self, mock_sleep):
        solver = self._make_solver_with_recordings()
        page = MagicMock()
        page.viewport_size = {"width": 1280, "height": 720}

        # Mock a PX captcha frame with role=button
        px_frame = MagicMock()
        px_frame.evaluate.side_effect = (
            lambda js: (
                "Human verification challenge"
                if "document.title" in js
                else 1.0  # progress bar always full
            )
        )
        btn_locator = MagicMock()
        btn_locator.count.return_value = 1
        btn_locator.first.bounding_box.return_value = {
            "x": 400, "y": 300, "width": 253, "height": 48,
        }
        px_frame.locator.return_value = btn_locator

        # Main frame (non-PX)
        main_frame = MagicMock()
        main_frame.evaluate.return_value = "Wayfair"
        page.frames = [main_frame, px_frame]

        # #px-captcha locator: present initially, gone after solve
        el = MagicMock()
        count_calls = [0]

        def count_side_effect():
            count_calls[0] += 1
            # First few calls: challenge present (detection + logging)
            # Later calls: challenge gone (solve detection)
            return 1 if count_calls[0] <= 4 else 0

        el.count.side_effect = count_side_effect
        el.bounding_box.return_value = {
            "x": 400, "y": 300, "width": 530, "height": 100,
        }
        page.locator.return_value = el
        page.on = MagicMock()
        page.remove_listener = MagicMock()

        mono_values = [
            float(i) * 0.1 for i in range(500)
        ]
        with patch("time.monotonic", side_effect=mono_values):
            result = solver._solve_perimeterx(page, 30000)

        assert result is True
        page.mouse.down.assert_called_once()
        page.mouse.up.assert_called_once()
        assert page.mouse.move.call_count > 0

    @patch("time.sleep")
    def test_skips_solve_when_no_challenge(self, mock_sleep):
        """No PX challenge on page → passive polling, no mouse."""
        solver = self._make_solver_with_recordings()
        page = MagicMock()
        # No #px-captcha element
        el = MagicMock()
        el.count.return_value = 0
        page.locator.return_value = el
        page.context.cookies.return_value = [
            {"name": "_px3", "value": "abc"}
        ]

        mono_values = [float(i) for i in range(50)]
        with patch("time.monotonic", side_effect=mono_values):
            result = solver._solve_perimeterx(page, 30000)

        assert result is True
        page.mouse.down.assert_not_called()

    @patch("time.sleep")
    def test_fallback_to_passive_when_no_recordings(
        self, mock_sleep
    ):
        solver = BrowserSolver()
        page = MagicMock()

        # Challenge present then gone (for passive polling)
        el = MagicMock()
        count_calls = [0]

        def count_side_effect():
            count_calls[0] += 1
            return 1 if count_calls[0] <= 1 else 0

        el.count.side_effect = count_side_effect
        page.locator.return_value = el
        page.context.cookies.return_value = [
            {"name": "_px3", "value": "abc"}
        ]

        pkg_mock = MagicMock()
        pkg_mock.__truediv__ = lambda self, name: MagicMock(
            iterdir=lambda: []
        )

        mono_values = [float(i) for i in range(50)]
        with patch(
            "wafer.browser._solver.importlib.resources.files",
            return_value=pkg_mock,
        ), patch("time.monotonic", side_effect=mono_values):
            result = solver._solve_perimeterx(page, 30000)

        assert result is True
        page.mouse.down.assert_not_called()

    @patch("time.sleep")
    def test_retries_on_failure(self, mock_sleep):
        solver = self._make_solver_with_recordings()
        page = MagicMock()
        page.viewport_size = {"width": 1280, "height": 720}

        # PX frame: "try again" on first solve check,
        # then element disappears on retry
        px_frame = MagicMock()
        innertext_calls = [0]

        def frame_eval(js):
            if "document.title" in js:
                return "Human verification challenge"
            if "innerText" in js:
                innertext_calls[0] += 1
                # First innerText check: "Try Again"
                if innertext_calls[0] <= 1:
                    return "Try Again"
                return "Press & Hold"
            return 1.0  # progress bar full

        px_frame.evaluate.side_effect = frame_eval
        btn_loc = MagicMock()
        btn_loc.count.return_value = 1
        btn_loc.first.bounding_box.return_value = {
            "x": 400, "y": 300, "width": 253, "height": 48,
        }
        px_frame.locator.return_value = btn_loc
        main_frame = MagicMock()
        main_frame.evaluate.return_value = "Page"
        page.frames = [main_frame, px_frame]

        el = MagicMock()
        count_calls = [0]

        def count_side_effect():
            count_calls[0] += 1
            # Present for detection + first attempt + retry,
            # gone after second attempt
            return 1 if count_calls[0] <= 15 else 0

        el.count.side_effect = count_side_effect
        el.bounding_box.return_value = {
            "x": 400, "y": 300, "width": 200, "height": 60,
        }
        page.locator.return_value = el
        page.on = MagicMock()
        page.remove_listener = MagicMock()

        mono_values = [float(i) * 0.1 for i in range(2000)]
        with patch("time.monotonic", side_effect=mono_values):
            result = solver._solve_perimeterx(page, 30000)

        assert result is True
        assert page.mouse.down.call_count >= 2


# ---------------------------------------------------------------------------
# F5 Shape solver
# ---------------------------------------------------------------------------


class TestWaitForShape:
    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_true_when_istlwashere_gone(
        self, mock_mono, mock_sleep
    ):
        from wafer.browser._shape import wait_for_shape
        page = MagicMock()
        solver = MagicMock()
        # First call: challenge present, second: gone
        page.content.side_effect = [
            "<html>istlWasHere challenge</html>",
            "<html>Real content</html>",
        ]
        mock_mono.side_effect = [0.0, 1.0, 3.0]

        assert wait_for_shape(solver, page, 10000) is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_false_on_timeout(self, mock_mono, mock_sleep):
        from wafer.browser._shape import wait_for_shape
        page = MagicMock()
        solver = MagicMock()
        page.content.return_value = "<html>istlWasHere still here</html>"
        mock_mono.side_effect = [0.0, 5.0, 15.0]

        assert wait_for_shape(solver, page, 10000) is False

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_case_insensitive(self, mock_mono, mock_sleep):
        from wafer.browser._shape import wait_for_shape
        page = MagicMock()
        solver = MagicMock()
        # Mixed case should still be detected
        page.content.side_effect = [
            "<html>IstlWasHere</html>",
            "<html>Normal page</html>",
        ]
        mock_mono.side_effect = [0.0, 1.0, 3.0]

        assert wait_for_shape(solver, page, 10000) is True


# ---------------------------------------------------------------------------
# DataDome solver
# ---------------------------------------------------------------------------


class TestWaitForDataDome:
    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_false_for_tbv_url(self, mock_mono, mock_sleep):
        from wafer.browser._datadome import wait_for_datadome
        page = MagicMock()
        page.url = "https://geo.captcha-delivery.com/captcha/?t=bv&dd=..."
        solver = MagicMock()

        assert wait_for_datadome(solver, page, 10000) is False

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_true_on_cookie_change(self, mock_mono, mock_sleep):
        from wafer.browser._datadome import wait_for_datadome
        page = MagicMock()
        page.url = "https://www.g2.com/"
        solver = MagicMock()

        # Initial cookies (before solve)
        initial_cookies = [
            {"name": "datadome", "value": "old_token"},
        ]
        # After solve, cookie value changes
        solved_cookies = [
            {"name": "datadome", "value": "new_token"},
        ]
        page.context.cookies.side_effect = [
            initial_cookies,  # _ensure initial value
            initial_cookies,  # first poll
            solved_cookies,   # second poll — solved!
        ]
        page.frames = []
        mock_mono.side_effect = [0.0, 0.5, 1.0, 1.5]

        assert wait_for_datadome(solver, page, 10000) is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_false_on_timeout(self, mock_mono, mock_sleep):
        from wafer.browser._datadome import wait_for_datadome
        page = MagicMock()
        page.url = "https://geo.captcha-delivery.com/captcha/?dd=..."
        solver = MagicMock()
        page.context.cookies.return_value = [
            {"name": "datadome", "value": "same_token"},
        ]
        page.frames = [MagicMock(url="https://geo.captcha-delivery.com/captcha")]
        mock_mono.side_effect = [0.0, 5.0, 15.0]

        assert wait_for_datadome(solver, page, 10000) is False

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_false_on_tbv_redirect_midsolve(
        self, mock_mono, mock_sleep
    ):
        from wafer.browser._datadome import wait_for_datadome
        page = MagicMock()
        solver = MagicMock()

        # URL changes to t=bv mid-solve
        url_values = [
            "https://geo.captcha-delivery.com/captcha/?dd=...",
            "https://geo.captcha-delivery.com/captcha/?dd=...",
            "https://geo.captcha-delivery.com/captcha/?t=bv&dd=...",
        ]
        type(page).url = PropertyMock(side_effect=url_values)
        page.context.cookies.return_value = [
            {"name": "datadome", "value": "same_token"},
        ]
        page.frames = []
        mock_mono.side_effect = [0.0, 0.5, 1.0]

        assert wait_for_datadome(solver, page, 10000) is False


# ---------------------------------------------------------------------------
# Imperva solver
# ---------------------------------------------------------------------------


class TestWaitForImperva:
    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_true_when_reese84_cookie(
        self, mock_mono, mock_sleep
    ):
        from wafer.browser._imperva import wait_for_imperva
        page = MagicMock()
        solver = MagicMock()
        # No cookie first, then reese84 appears
        page.context.cookies.side_effect = [
            [],
            [{"name": "reese84", "value": "abc123"}],
        ]
        mock_mono.side_effect = [0.0, 1.0, 3.0]

        assert wait_for_imperva(solver, page, 10000) is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_true_when_utmvc_cookie(
        self, mock_mono, mock_sleep
    ):
        from wafer.browser._imperva import wait_for_imperva
        page = MagicMock()
        solver = MagicMock()
        page.context.cookies.side_effect = [
            [],
            [{"name": "___utmvc", "value": "xyz789"}],
        ]
        mock_mono.side_effect = [0.0, 1.0, 3.0]

        assert wait_for_imperva(solver, page, 10000) is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_true_when_incap_ses_cookie(
        self, mock_mono, mock_sleep
    ):
        """Classic Incapsula: incap_ses_* cookie is solve signal."""
        from wafer.browser._imperva import wait_for_imperva
        page = MagicMock()
        solver = MagicMock()
        page.context.cookies.side_effect = [
            [],
            [
                {"name": "visid_incap_123", "value": "x"},
                {"name": "incap_ses_456_123", "value": "y"},
            ],
        ]
        mock_mono.side_effect = [0.0, 1.0, 3.0]

        assert wait_for_imperva(solver, page, 10000) is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_false_on_timeout(self, mock_mono, mock_sleep):
        from wafer.browser._imperva import wait_for_imperva
        page = MagicMock()
        solver = MagicMock()
        page.context.cookies.return_value = []
        mock_mono.side_effect = [0.0, 5.0, 15.0]

        assert wait_for_imperva(solver, page, 10000) is False


# ---------------------------------------------------------------------------
# Dispatch tests (solver routes to correct module)
# ---------------------------------------------------------------------------


class TestDispatchChallenge:
    def _make_solver_with_mock_browser(self):
        solver = BrowserSolver()
        solver._browser = MagicMock()
        solver._browser.is_connected.return_value = True
        solver._playwright = MagicMock()
        solver._browser_ua = "Chrome/145"
        return solver

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_dispatches_shape(self, mock_mono, mock_sleep):
        solver = self._make_solver_with_mock_browser()
        page = MagicMock()
        # istlWasHere gone immediately
        page.content.return_value = "<html>Normal</html>"
        mock_mono.side_effect = [
            float(i) * 0.1 for i in range(50)
        ]
        result = solver._dispatch_challenge(page, "shape", 10000)
        assert result is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_dispatches_imperva(self, mock_mono, mock_sleep):
        solver = self._make_solver_with_mock_browser()
        page = MagicMock()
        page.context.cookies.return_value = [
            {"name": "reese84", "value": "solved"}
        ]
        mock_mono.side_effect = [
            float(i) * 0.1 for i in range(50)
        ]
        result = solver._dispatch_challenge(page, "imperva", 10000)
        assert result is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_dispatches_datadome(self, mock_mono, mock_sleep):
        solver = self._make_solver_with_mock_browser()
        page = MagicMock()
        page.url = "https://geo.captcha-delivery.com/captcha/?dd=..."
        page.context.cookies.side_effect = [
            [{"name": "datadome", "value": "old"}],
            [{"name": "datadome", "value": "old"}],
            [{"name": "datadome", "value": "new"}],
        ]
        page.frames = []
        mock_mono.side_effect = [
            float(i) * 0.1 for i in range(50)
        ]
        result = solver._dispatch_challenge(page, "datadome", 10000)
        assert result is True


class TestScreenXYExtension:
    def test_extension_extracted(self):
        solver = BrowserSolver()
        ext_dir = solver._ensure_extension()

        assert ext_dir is not None
        assert os.path.isfile(
            os.path.join(ext_dir, "manifest.json")
        )
        assert os.path.isfile(
            os.path.join(ext_dir, "content.js")
        )

        # Cleanup
        shutil.rmtree(ext_dir)
        solver._extension_dir = None

    def test_extension_cached(self):
        solver = BrowserSolver()
        dir1 = solver._ensure_extension()
        dir2 = solver._ensure_extension()
        assert dir1 == dir2

        shutil.rmtree(dir1)
        solver._extension_dir = None

    def test_close_browser_cleans_up(self):
        solver = BrowserSolver()
        ext_dir = solver._ensure_extension()
        assert os.path.isdir(ext_dir)

        solver._close_browser()
        assert not os.path.isdir(ext_dir)
        assert solver._extension_dir is None


# ---------------------------------------------------------------------------
# Cloudflare early bail-out
# ---------------------------------------------------------------------------


class TestCloudflareEarlyBailout:
    @patch("time.sleep")
    @patch("time.monotonic")
    def test_no_iframe_bails_after_grace(self, mock_mono, mock_sleep):
        """No CF iframe after 3s grace period → returns False quickly."""
        from wafer.browser._cloudflare import wait_for_cloudflare

        page = MagicMock()
        solver = MagicMock()
        page.context.cookies.return_value = []
        page.frames = []  # No challenge iframe

        # t=0: start, grace_deadline=3.0
        # t=1: first poll (still in grace period)
        # t=4: past grace → bail out
        mock_mono.side_effect = [0.0, 0.0, 1.0, 4.0]

        result = wait_for_cloudflare(solver, page, 30000)
        assert result is False

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_iframe_present_continues_polling(
        self, mock_mono, mock_sleep
    ):
        """With CF iframe present, should keep polling for cf_clearance."""
        from wafer.browser._cloudflare import wait_for_cloudflare

        page = MagicMock()
        solver = MagicMock()
        # No cf_clearance, then it appears
        page.context.cookies.side_effect = [
            [],
            [{"name": "cf_clearance", "value": "solved"}],
        ]
        # CF iframe is present
        cf_frame = MagicMock()
        cf_frame.url = "https://challenges.cloudflare.com/turnstile/v0/..."
        page.frames = [cf_frame]
        mock_mono.side_effect = [0.0, 0.0, 1.0, 3.0]

        result = wait_for_cloudflare(solver, page, 30000)
        assert result is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_cf_clearance_before_grace_returns_true(
        self, mock_mono, mock_sleep
    ):
        """If cf_clearance appears early, returns True immediately."""
        from wafer.browser._cloudflare import wait_for_cloudflare

        page = MagicMock()
        solver = MagicMock()
        page.context.cookies.return_value = [
            {"name": "cf_clearance", "value": "fast"}
        ]
        page.frames = []
        mock_mono.side_effect = [0.0, 0.0, 0.5]

        result = wait_for_cloudflare(solver, page, 30000)
        assert result is True


# ---------------------------------------------------------------------------
# Async passthrough
# ---------------------------------------------------------------------------


class TestAsyncBrowserPassthrough:
    @patch("asyncio.sleep")
    async def test_passthrough_returns_wafer_response(
        self, mock_sleep
    ):
        """Async: browser passthrough returns WaferResponse directly."""
        from wafer.browser._solver import CapturedResponse

        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )

        passthrough_body = b"<html><body>Async real content</body></html>"
        browser_result = SolveResult(
            cookies=[
                {
                    "name": "sid",
                    "value": "abc",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Chrome/145.0.0.0",
            response=CapturedResponse(
                url="https://example.com/page",
                status=200,
                headers={"content-type": "text/html"},
                body=passthrough_body,
            ),
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        session, mock_client = make_async_session(
            [cf_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        resp = await session.get("https://example.com/page")
        assert resp.status_code == 200
        assert resp.content == passthrough_body
        assert mock_client.request_count == 1


# ---------------------------------------------------------------------------
# Browse recording loader
# ---------------------------------------------------------------------------

_BROWSE_CSV = (
    "# type=browses viewport=1280x720 sections=3 max_scroll=500\n"
    "t,dx,dy,scroll_y\n"
    "0.100,10.0,5.0,0\n"
    "0.200,20.0,10.0,0\n"
    "0.300,30.0,15.0,-100\n"
    "0.400,25.0,20.0,0\n"
    "0.500,15.0,25.0,-80\n"
)


class TestBrowseRecordingLoader:
    def test_loads_browse_csvs(self, tmp_path):
        """Browse recordings are parsed with correct fields."""
        rec_dir = _setup_recordings_dir(tmp_path)
        browse_dir = rec_dir / "browses"
        browse_dir.mkdir(exist_ok=True)
        (browse_dir / "browse_001.csv").write_text(_BROWSE_CSV)

        solver = BrowserSolver()
        pkg_mock = MagicMock()
        pkg_mock.__truediv__ = lambda self, name: rec_dir

        with patch(
            "wafer.browser._solver.importlib.resources.files",
            return_value=pkg_mock,
        ):
            solver._ensure_recordings()

        assert len(solver._browse_recordings) == 1
        rec = solver._browse_recordings[0]
        assert rec["max_scroll"] == 500
        assert rec["sections"] == 3
        assert rec["name"] == "browse_001.csv"
        assert len(rec["rows"]) == 5
        # Verify fields parsed
        row = rec["rows"][2]
        assert row["t"] == pytest.approx(0.3)
        assert row["dx"] == pytest.approx(30.0)
        assert row["scroll_y"] == pytest.approx(-100.0)

    def test_browses_optional_not_gating(self, tmp_path):
        """Missing browses dir does not prevent _ensure_recordings
        from returning True (browses are optional)."""
        rec_dir = _setup_recordings_dir(tmp_path)
        # No browses dir created

        solver = BrowserSolver()
        pkg_mock = MagicMock()
        pkg_mock.__truediv__ = lambda self, name: rec_dir

        with patch(
            "wafer.browser._solver.importlib.resources.files",
            return_value=pkg_mock,
        ):
            result = solver._ensure_recordings()

        # Should still return True (idles+paths+holds present)
        assert result is True
        assert solver._browse_recordings == []

    def test_browse_metadata_extraction(self, tmp_path):
        """Metadata fields max_scroll and sections are extracted."""
        rec_dir = _setup_recordings_dir(tmp_path)
        browse_dir = rec_dir / "browses"
        browse_dir.mkdir(exist_ok=True)

        csv_with_meta = (
            "# type=browses viewport=1280x720"
            " sections=17 max_scroll=1760\n"
            "t,dx,dy,scroll_y\n"
            "0.100,5.0,3.0,-50\n"
        )
        (browse_dir / "browse_big.csv").write_text(csv_with_meta)

        solver = BrowserSolver()
        pkg_mock = MagicMock()
        pkg_mock.__truediv__ = lambda self, name: rec_dir

        with patch(
            "wafer.browser._solver.importlib.resources.files",
            return_value=pkg_mock,
        ):
            solver._ensure_recordings()

        rec = solver._browse_recordings[0]
        assert rec["max_scroll"] == 1760
        assert rec["sections"] == 17


# ---------------------------------------------------------------------------
# Browse replay chunk
# ---------------------------------------------------------------------------


class TestReplayBrowseChunk:
    def _make_solver_with_browses(self):
        solver = BrowserSolver()
        solver._browse_recordings = [{
            "rows": [
                {"t": 0.0, "dx": 0.0, "dy": 0.0, "scroll_y": 0},
                {"t": 0.1, "dx": 10.0, "dy": 5.0, "scroll_y": 0},
                {"t": 0.2, "dx": 20.0, "dy": 10.0, "scroll_y": -100},
                {"t": 0.3, "dx": 30.0, "dy": 15.0, "scroll_y": 0},
            ],
            "max_scroll": 500,
            "sections": 2,
            "name": "test_browse.csv",
        }]
        return solver

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_dispatches_mouse_moves(self, mock_mono, mock_sleep):
        """Browse chunk dispatches mouse.move for each row."""
        solver = self._make_solver_with_browses()
        page = MagicMock()

        # Time progresses slowly so all rows fit within deadline
        mono_values = [0.0] + [0.01 * i for i in range(100)]
        mock_mono.side_effect = mono_values

        state = solver._start_browse(page, 400.0, 300.0)
        assert state is not None

        solver._replay_browse_chunk(page, state, 5.0)
        # Should have moved cursor for each row
        assert page.mouse.move.call_count >= 4

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_dispatches_scroll(self, mock_mono, mock_sleep):
        """Browse chunk dispatches mouse.wheel for non-zero scroll_y."""
        solver = self._make_solver_with_browses()
        page = MagicMock()

        mono_values = [0.0] + [0.01 * i for i in range(100)]
        mock_mono.side_effect = mono_values

        state = solver._start_browse(page, 400.0, 300.0)
        solver._replay_browse_chunk(page, state, 5.0)
        # Row index 2 has scroll_y=-100
        page.mouse.wheel.assert_called()

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_none_state_falls_back_to_sleep(
        self, mock_mono, mock_sleep
    ):
        """None state falls back to time.sleep(duration)."""
        solver = self._make_solver_with_browses()
        page = MagicMock()

        mock_mono.side_effect = [0.0, 2.0]
        solver._replay_browse_chunk(page, None, 2.0)
        mock_sleep.assert_any_call(2.0)
        page.mouse.move.assert_not_called()

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_exhausted_recording_falls_back_to_sleep(
        self, mock_mono, mock_sleep
    ):
        """Exhausted state falls back to time.sleep(duration)."""
        from wafer.browser._solver import _BrowseState

        solver = self._make_solver_with_browses()
        page = MagicMock()
        state = _BrowseState(
            rows=[], index=0, time_scale=1.0,
            origin_x=0, origin_y=0, scroll_scale=1.0,
            current_x=0, current_y=0,
        )

        mock_mono.side_effect = [0.0, 2.0]
        solver._replay_browse_chunk(page, state, 2.0)
        mock_sleep.assert_any_call(2.0)

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_state_index_advances(self, mock_mono, mock_sleep):
        """State index advances through rows during replay."""
        solver = self._make_solver_with_browses()
        page = MagicMock()

        mono_values = [0.0] + [0.01 * i for i in range(100)]
        mock_mono.side_effect = mono_values

        state = solver._start_browse(page, 100.0, 100.0)
        initial_index = state.index
        solver._replay_browse_chunk(page, state, 5.0)
        assert state.index > initial_index

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_current_xy_updated(self, mock_mono, mock_sleep):
        """State current_x/current_y are updated during replay."""
        solver = self._make_solver_with_browses()
        page = MagicMock()

        mono_values = [0.0] + [0.01 * i for i in range(100)]
        mock_mono.side_effect = mono_values

        state = solver._start_browse(page, 100.0, 200.0)
        solver._replay_browse_chunk(page, state, 5.0)
        # Last row dispatched: dx=30, dy=15
        assert state.current_x == pytest.approx(130.0)
        assert state.current_y == pytest.approx(215.0)
