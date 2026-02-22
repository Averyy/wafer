"""Tests for inline challenge solvers (ACW, Amazon, TMD)."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
from urllib.parse import urlparse

import pytest

from tests.conftest import (
    MockResponse,
    make_async_session,
    make_sync_session,
)
from wafer._solvers import (
    _is_amazon_domain,
    parse_amazon_captcha,
    solve_acw,
    tmd_homepage_url,
)

# ---------------------------------------------------------------------------
# ACW Solver
# ---------------------------------------------------------------------------


class TestSolveACW:
    def test_known_arg1_produces_expected_cookie(self):
        arg1 = "0123456789abcdef0123456789abcdef01234567"
        body = f"<html><script>var arg1='{arg1}'</script></html>"
        result = solve_acw(body)
        assert result == "d2c7186598ab1a508a4f6064e4fa746323ab17c6"

    def test_arg1_with_spaces_around_equals(self):
        arg1 = "aabbccddeeff00112233445566778899aabbccdd"
        body = (
            f"<html><script>var arg1 = '{arg1}'"
            f"</script></html>"
        )
        result = solve_acw(body)
        assert result is not None
        assert len(result) == 40

    def test_result_is_40_char_hex(self):
        arg1 = "aabbccddeeff00112233445566778899aabbccddee"
        body = f"<html><script>var arg1='{arg1}'</script></html>"
        result = solve_acw(body)
        assert result is not None
        assert len(result) == 40
        int(result, 16)  # must be valid hex

    def test_no_arg1_returns_none(self):
        body = "<html><script>acw_sc__v2 stuff</script></html>"
        assert solve_acw(body) is None

    def test_arg1_too_short_returns_none(self):
        body = "<html><script>var arg1='aabb'</script></html>"
        assert solve_acw(body) is None

    def test_arg1_non_hex_returns_none(self):
        body = "<html><script>var arg1='not_hex_at_all'</script></html>"
        assert solve_acw(body) is None

    def test_empty_body_returns_none(self):
        assert solve_acw("") is None

    def test_different_arg1_produces_different_result(self):
        arg1_a = "0123456789abcdef0123456789abcdef01234567"
        arg1_b = "fedcba9876543210fedcba9876543210fedcba98"
        result_a = solve_acw(f"<script>var arg1='{arg1_a}'</script>")
        result_b = solve_acw(f"<script>var arg1='{arg1_b}'</script>")
        assert result_a is not None
        assert result_b is not None
        assert result_a != result_b


# ---------------------------------------------------------------------------
# Amazon Captcha Parser
# ---------------------------------------------------------------------------


class TestParseAmazonCaptcha:
    def test_continue_shopping_link(self):
        html = """
        <html><body>
        <a href="https://www.amazon.com/ref=cs_503_link">Continue shopping</a>
        </body></html>
        """
        result = parse_amazon_captcha(html, "https://www.amazon.com/dp/B0D1XD1ZV3")
        assert result is not None
        assert result["method"] == "GET"
        assert result["url"] == "https://www.amazon.com/ref=cs_503_link"
        assert result["params"] == {}

    def test_continue_shopping_relative_link(self):
        html = """
        <html><body>
        <a href="/ref=cs_503">Continue Shopping</a>
        </body></html>
        """
        result = parse_amazon_captcha(html, "https://www.amazon.ca/dp/B0D1XD1ZV3")
        assert result is not None
        assert result["method"] == "GET"
        assert result["url"] == "https://www.amazon.ca/ref=cs_503"

    def test_form_with_hidden_fields(self):
        html = """
        <html><body>
        <form method="POST" action="https://www.amazon.com/errors/validateCaptcha">
            <input type="hidden" name="amzn" value="abc123">
            <input type="hidden" name="amzn-r" value="/dp/B0D1XD1ZV3">
            <input type="submit" value="Submit">
        </form>
        </body></html>
        """
        result = parse_amazon_captcha(html, "https://www.amazon.com/dp/B0D1XD1ZV3")
        assert result is not None
        assert result["method"] == "POST"
        assert result["url"] == "https://www.amazon.com/errors/validateCaptcha"
        assert result["params"]["amzn"] == "abc123"
        assert result["params"]["amzn-r"] == "/dp/B0D1XD1ZV3"

    def test_form_get_method(self):
        html = """
        <html><body>
        <form method="GET" action="https://www.amazon.de/ref=cs">
            <input type="hidden" name="token" value="xyz">
        </form>
        </body></html>
        """
        result = parse_amazon_captcha(html, "https://www.amazon.de/dp/B0D1XD1ZV3")
        assert result is not None
        assert result["method"] == "GET"
        assert result["params"]["token"] == "xyz"

    def test_form_default_method_is_get(self):
        html = """
        <html><body>
        <form action="https://www.amazon.com/ref=cs">
            <input type="hidden" name="k" value="v">
        </form>
        </body></html>
        """
        result = parse_amazon_captcha(html, "https://www.amazon.com/dp/B0D1XD1ZV3")
        assert result is not None
        assert result["method"] == "GET"

    def test_link_preferred_over_form(self):
        """Continue shopping link takes priority over form."""
        html = """
        <html><body>
        <a href="https://www.amazon.com/ref=cs">Continue shopping</a>
        <form action="https://www.amazon.com/errors/validate">
            <input type="hidden" name="k" value="v">
        </form>
        </body></html>
        """
        result = parse_amazon_captcha(html, "https://www.amazon.com/dp/B0D1XD1ZV3")
        assert result is not None
        assert result["method"] == "GET"
        assert "/ref=cs" in result["url"]

    def test_non_amazon_link_rejected(self):
        html = """
        <html><body>
        <a href="https://evil.com/steal">Continue shopping</a>
        </body></html>
        """
        result = parse_amazon_captcha(html, "https://www.amazon.com/dp/B0D1XD1ZV3")
        assert result is None

    def test_non_amazon_form_rejected(self):
        html = """
        <html><body>
        <form action="https://evil.com/steal">
            <input type="hidden" name="k" value="v">
        </form>
        </body></html>
        """
        result = parse_amazon_captcha(html, "https://www.amazon.com/dp/B0D1XD1ZV3")
        assert result is None

    def test_no_link_no_form_returns_none(self):
        html = "<html><body><p>Something went wrong</p></body></html>"
        result = parse_amazon_captcha(html, "https://www.amazon.com/dp/B0D1XD1ZV3")
        assert result is None

    def test_empty_body_returns_none(self):
        result = parse_amazon_captcha("", "https://www.amazon.com/dp/B0D1XD1ZV3")
        assert result is None

    def test_link_without_continue_shopping_ignored(self):
        html = """
        <html><body>
        <a href="https://www.amazon.com/help">Get help</a>
        </body></html>
        """
        result = parse_amazon_captcha(html, "https://www.amazon.com/dp/B0D1XD1ZV3")
        assert result is None


class TestIsAmazonDomain:
    def test_amazon_com(self):
        assert _is_amazon_domain("https://www.amazon.com/dp/B0D1XD1ZV3")

    def test_amazon_ca(self):
        assert _is_amazon_domain("https://www.amazon.ca/dp/B0D1XD1ZV3")

    def test_amazon_co_uk(self):
        assert _is_amazon_domain("https://www.amazon.co.uk/dp/B0D1XD1ZV3")

    def test_amazon_de(self):
        assert _is_amazon_domain("https://www.amazon.de/dp/B0D1XD1ZV3")

    def test_amzn_domain(self):
        assert _is_amazon_domain("https://amzn.com/ref=abc")

    def test_non_amazon_rejected(self):
        assert not _is_amazon_domain("https://evil.com/amazon")

    def test_amazon_substring_rejected(self):
        assert not _is_amazon_domain("https://notamazon.com/foo")

    def test_private_host_rejected(self):
        assert not _is_amazon_domain("http://localhost/amazon")

    def test_empty_url(self):
        assert not _is_amazon_domain("")


# ---------------------------------------------------------------------------
# TMD Homepage URL
# ---------------------------------------------------------------------------


class TestTMDHomepageUrl:
    def test_extracts_homepage(self):
        assert tmd_homepage_url(
            "https://example.com/some/deep/page?q=1"
        ) == "https://example.com/"

    def test_preserves_scheme(self):
        assert tmd_homepage_url(
            "http://example.com/page"
        ) == "http://example.com/"

    def test_preserves_port(self):
        assert tmd_homepage_url(
            "https://example.com:8443/page"
        ) == "https://example.com:8443/"


# ---------------------------------------------------------------------------
# Retry Loop Integration (Sync)
# ---------------------------------------------------------------------------

# ACW body for challenge response
_ACW_BODY = (
    "<html><script>"
    "var arg1='0123456789abcdef0123456789abcdef01234567'"
    "</script>acw_sc__v2</html>"
)

# Amazon captcha body
_AMAZON_BODY = """
<html><body>
<p>Sorry, we just need to make sure you're not a robot.</p>
<a href="https://www.amazon.com/ref=cs_503_link">Continue shopping</a>
<p>amazon.com</p>
</body></html>
"""

# TMD body
_TMD_BODY = (
    "<html><body>/_____tmd_____/punish redirect</body></html>"
)


class TestACWSolverIntegration:
    @patch("wafer._sync.time.sleep")
    def test_acw_solved_inline_then_success(self, mock_sleep):
        responses = [
            MockResponse(200, {}, _ACW_BODY),
            MockResponse(200, {}, "<html>real content</html>"),
        ]
        session, mock = make_sync_session(
            responses, use_cookie_jar=True,
        )
        resp = session.request("GET", "https://example.com/page")
        assert resp.text == "<html>real content</html>"
        assert mock.request_count == 2
        # ACW cookie added to jar
        assert len(mock.cookie_jar.added) == 1
        assert "acw_sc__v2=" in mock.cookie_jar.added[0][0]

    @patch("wafer._sync.time.sleep")
    def test_acw_bad_arg1_falls_through_to_rotation(self, mock_sleep):
        """If ACW arg1 regex doesn't match, fall through to rotation."""
        # Body has both markers so detect_challenge returns ACW,
        # but arg1 is not in var arg1='...' format so solver returns None
        bad_acw_body = (
            "<html>acw_sc__v2 arg1 present but malformed</html>"
        )
        responses = [
            MockResponse(200, {}, bad_acw_body),
            MockResponse(200, {}, "<html>real content</html>"),
        ]
        session, mock = make_sync_session(responses)
        resp = session.request("GET", "https://example.com/page")
        # Solver failed → rotation → second request succeeds
        assert resp.text == "<html>real content</html>"
        assert mock.request_count == 2


class TestInlineSolveBudget:
    """Inline solves should not consume rotation budget."""

    @patch("wafer._sync.time.sleep")
    def test_inline_solve_does_not_consume_rotation(self, mock_sleep):
        """ACW inline solve should leave rotation budget intact."""
        responses = [
            MockResponse(200, {}, _ACW_BODY),
            MockResponse(200, {}, "<html>real content</html>"),
        ]
        session, mock = make_sync_session(
            responses, use_cookie_jar=True, max_rotations=2,
        )
        resp = session.request("GET", "https://example.com/page")
        assert resp.text == "<html>real content</html>"
        # Only 2 requests: ACW challenge + success after inline solve
        assert mock.request_count == 2

    @patch("wafer._sync.time.sleep")
    def test_inline_solve_cap_falls_through_to_rotation(self, mock_sleep):
        """After 3 inline solves, fall through to fingerprint rotation."""
        responses = [
            # 3x ACW challenges that solver "solves" but server keeps
            # re-challenging (e.g. cookie immediately expires)
            MockResponse(200, {}, _ACW_BODY),
            MockResponse(200, {}, _ACW_BODY),
            MockResponse(200, {}, _ACW_BODY),
            # 4th ACW: inline cap (3) exhausted → falls through to
            # rotation path (challenge detected, rotation used)
            MockResponse(200, {}, _ACW_BODY),
            # After rotation, success
            MockResponse(200, {}, "<html>real content</html>"),
        ]
        session, mock = make_sync_session(
            responses, use_cookie_jar=True, max_rotations=10,
        )
        resp = session.request("GET", "https://example.com/page")
        assert resp.text == "<html>real content</html>"
        assert mock.request_count == 5

    @patch("wafer._sync.time.sleep")
    def test_inline_solve_cap_with_low_rotations(self, mock_sleep):
        """Inline solves preserve rotation budget for real rotations."""
        from wafer._errors import ChallengeDetected

        responses = [
            # 3x inline solves (don't consume rotation budget)
            MockResponse(200, {}, _ACW_BODY),
            MockResponse(200, {}, _ACW_BODY),
            MockResponse(200, {}, _ACW_BODY),
            # Inline cap hit → falls to rotation (uses 1 rotation)
            MockResponse(200, {}, _ACW_BODY),
            # Still ACW → uses 2nd rotation
            MockResponse(200, {}, _ACW_BODY),
        ] * 5  # plenty of responses
        session, mock = make_sync_session(
            responses, use_cookie_jar=True, max_rotations=2,
        )
        with pytest.raises(ChallengeDetected):
            session.request("GET", "https://example.com/page")
        # Should have used: 3 inline + 2 rotations + 1 final attempt
        # = 6 total requests before exhaustion
        assert mock.request_count == 6


class TestAmazonSolverIntegration:
    @patch("wafer._sync.time.sleep")
    def test_amazon_captcha_solved_inline(self, mock_sleep):
        responses = [
            # First response: Amazon captcha page
            MockResponse(200, {}, _AMAZON_BODY),
            # Second: solver follows "continue shopping" link
            MockResponse(200, {}, ""),
            # Third: retry of original URL succeeds
            MockResponse(200, {}, "<html>product page</html>"),
        ]
        session, mock = make_sync_session(
            responses, use_cookie_jar=True,
        )
        resp = session.request(
            "GET", "https://www.amazon.com/dp/B0D1XD1ZV3"
        )
        assert resp.text == "<html>product page</html>"
        assert mock.request_count == 3
        # Second request was the solver following the continue shopping link
        assert "ref=cs_503_link" in mock.request_log[1][1]

    @patch("wafer._sync.time.sleep")
    def test_amazon_non_amazon_domain_not_solved(self, mock_sleep):
        """Amazon captcha with non-Amazon URL should not be solved inline."""
        # Body looks like Amazon but URL is not Amazon
        non_amazon_body = """
        <html><body>
        <a href="https://evil.com/steal">Continue shopping</a>
        <p>amazon amzn</p>
        </body></html>
        """
        responses = [
            MockResponse(200, {}, non_amazon_body),
            MockResponse(200, {}, "<html>real content</html>"),
        ]
        session, mock = make_sync_session(responses)
        # This body triggers Amazon detection (has "continue shopping" +
        # amazon markers + small body), but the link points to evil.com
        # so parse_amazon_captcha returns None. Since detect_challenge
        # returned AMAZON, solver fails, falls through to rotation.
        # After rotation, next request succeeds.
        resp = session.request(
            "GET", "https://www.amazon.com/dp/B0D1XD1ZV3"
        )
        assert resp.text == "<html>real content</html>"


class TestTMDSolverIntegration:
    @patch("wafer._sync.time.sleep")
    def test_tmd_session_warming(self, mock_sleep):
        responses = [
            # First: TMD challenge page
            MockResponse(200, {}, _TMD_BODY),
            # Second: solver fetches homepage (sets cookies)
            MockResponse(
                200,
                {"set-cookie": "session=abc123; Path=/"},
                "<html>homepage</html>",
            ),
            # Third: retry of original URL succeeds
            MockResponse(200, {}, "<html>real content</html>"),
        ]
        session, mock = make_sync_session(
            responses, use_cookie_jar=True,
        )
        resp = session.request(
            "GET", "https://example.com/deep/page"
        )
        assert resp.text == "<html>real content</html>"
        assert mock.request_count == 3
        # Second request was the homepage fetch
        assert mock.request_log[1][1] == "https://example.com/"


class TestACWSolverIntegrationAsync:
    @pytest.mark.asyncio
    @patch("wafer._async.asyncio.sleep")
    async def test_acw_solved_inline_then_success(self, mock_sleep):
        responses = [
            MockResponse(200, {}, _ACW_BODY),
            MockResponse(200, {}, "<html>real content</html>"),
        ]
        session, mock = make_async_session(
            responses, use_cookie_jar=True,
        )
        resp = await session.request("GET", "https://example.com/page")
        body = resp.text
        assert body == "<html>real content</html>"
        assert mock.request_count == 2
        assert len(mock.cookie_jar.added) == 1
        assert "acw_sc__v2=" in mock.cookie_jar.added[0][0]


class TestTMDSolverIntegrationAsync:
    @pytest.mark.asyncio
    @patch("wafer._async.asyncio.sleep")
    async def test_tmd_session_warming(self, mock_sleep):
        responses = [
            MockResponse(200, {}, _TMD_BODY),
            MockResponse(
                200,
                {"set-cookie": "session=abc123; Path=/"},
                "<html>homepage</html>",
            ),
            MockResponse(200, {}, "<html>real content</html>"),
        ]
        session, mock = make_async_session(
            responses, use_cookie_jar=True,
        )
        resp = await session.request(
            "GET", "https://example.com/deep/page"
        )
        body = resp.text
        assert body == "<html>real content</html>"
        assert mock.request_count == 3
        assert mock.request_log[1][1] == "https://example.com/"


# ---------------------------------------------------------------------------
# End-to-end tests with real HTTP servers (no mocks)
# ---------------------------------------------------------------------------
def _start_server(handler_class):
    """Start an HTTP server on a random port, return (server, port)."""
    server = HTTPServer(("127.0.0.1", 0), handler_class)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port


class _ACWHandler(BaseHTTPRequestHandler):
    """Serve ACW challenge if no acw_sc__v2 cookie, else real content."""

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        if "acw_sc__v2=" in cookie:
            self._respond(200, "<html>Real ACW content</html>")
        else:
            body = (
                "<html><script>"
                "var arg1='0123456789abcdef"
                "0123456789abcdef01234567';"
                "</script>acw_sc__v2</html>"
            )
            self._respond(200, body)

    def _respond(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


class _AmazonHandler(BaseHTTPRequestHandler):
    """Serve captcha on first hit, then real content after solve."""

    _served_captcha = False

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/ref=cs_503_link":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header(
                "Set-Cookie", "session-id=abc; Path=/"
            )
            self.end_headers()
            self.wfile.write(b"ok")
        elif not _AmazonHandler._served_captcha:
            _AmazonHandler._served_captcha = True
            body = (
                '<html><body>'
                '<a href="/ref=cs_503_link">'
                'Continue shopping</a>'
                '<p>amazon.com</p>'
                '</body></html>'
            )
            self._respond(200, body)
        else:
            self._respond(
                200, "<html>Real Amazon product</html>"
            )

    def _respond(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


class _TMDHandler(BaseHTTPRequestHandler):
    """Serve TMD challenge unless session cookie is present."""

    def do_GET(self):
        path = urlparse(self.path).path
        cookie = self.headers.get("Cookie", "")
        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header(
                "Set-Cookie", "tmd_sess=yes; Path=/"
            )
            self.end_headers()
            self.wfile.write(b"<html>homepage</html>")
        elif "tmd_sess=" in cookie:
            self._respond(200, "<html>Real TMD content</html>")
        else:
            body = (
                "<html>/_____tmd_____/punish redirect"
                "</html>"
            )
            self._respond(200, body)

    def _respond(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


class TestACWE2E:
    def test_acw_solver_real_http(self):
        """ACW solver against a real HTTP server (no mocks)."""
        from wafer._sync import SyncSession

        server, port = _start_server(_ACWHandler)
        try:
            session = SyncSession(
                max_rotations=5, cache_dir=None
            )
            url = f"http://127.0.0.1:{port}/page"
            resp = session.request("GET", url)
            assert resp.status_code == 200
            assert "Real ACW content" in resp.text
        finally:
            server.shutdown()


class TestAmazonE2E:
    def test_amazon_solver_real_http(self):
        """Amazon captcha solver against a real HTTP server."""
        from wafer._sync import SyncSession

        _AmazonHandler._served_captcha = False
        server, port = _start_server(_AmazonHandler)
        try:
            with patch(
                "wafer._solvers._is_amazon_domain",
                return_value=True,
            ):
                session = SyncSession(
                    max_rotations=5, cache_dir=None
                )
                url = f"http://127.0.0.1:{port}/dp/B0D1XD1ZV3"
                resp = session.request("GET", url)
                assert resp.status_code == 200
                assert "Real Amazon product" in resp.text
        finally:
            server.shutdown()


class TestTMDE2E:
    def test_tmd_solver_real_http(self):
        """TMD session warming against a real HTTP server."""
        from wafer._sync import SyncSession

        server, port = _start_server(_TMDHandler)
        try:
            session = SyncSession(
                max_rotations=5, cache_dir=None
            )
            url = f"http://127.0.0.1:{port}/products/widget"
            resp = session.request("GET", url)
            assert resp.status_code == 200
            assert "Real TMD content" in resp.text
        finally:
            server.shutdown()
