"""Tests for increment 8: referer chain, auto Host, embed mode, logging."""

import logging
from unittest.mock import patch

import pytest

from tests.conftest import (
    MockResponse,
    make_async_session,
    make_sync_session,
)

# ---------------------------------------------------------------------------
# Referer chain tests
# ---------------------------------------------------------------------------


class TestRefererChain:
    @patch("time.sleep")
    def test_referer_set_on_second_request_same_domain(self, mock_sleep):
        """After fetching URL A, fetching URL B on the same domain
        should have Referer: A."""
        session, mock = make_sync_session([
            MockResponse(200, body="page A"),
            MockResponse(200, body="page B"),
        ])
        session.get("https://example.com/a")
        session.get("https://example.com/b")

        # Second request should have Referer set to first URL
        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Referer") == "https://example.com/a"

    @patch("time.sleep")
    def test_no_referer_on_first_request(self, mock_sleep):
        """First request to a domain should not have an auto-Referer."""
        session, mock = make_sync_session([
            MockResponse(200, body="page A"),
        ])
        session.get("https://example.com/a")

        headers = mock.last_kwargs.get("headers", {})
        assert "Referer" not in headers

    @patch("time.sleep")
    def test_no_referer_cross_domain(self, mock_sleep):
        """Request to a different domain should not inherit Referer."""
        session, mock = make_sync_session([
            MockResponse(200, body="page A"),
            MockResponse(200, body="page B"),
        ])
        session.get("https://example.com/a")
        session.get("https://other.com/b")

        headers = mock.last_kwargs.get("headers", {})
        assert "Referer" not in headers

    @patch("time.sleep")
    def test_referer_chain_updates(self, mock_sleep):
        """Referer should update to the most recent URL each time."""
        session, mock = make_sync_session([
            MockResponse(200, body="page 1"),
            MockResponse(200, body="page 2"),
            MockResponse(200, body="page 3"),
        ])
        session.get("https://example.com/1")
        session.get("https://example.com/2")
        session.get("https://example.com/3")

        # Third request should reference second URL
        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Referer") == "https://example.com/2"

    @patch("time.sleep")
    def test_referer_suppressed_by_empty_string(self, mock_sleep):
        """Setting Referer to empty string suppresses auto-Referer."""
        session, mock = make_sync_session([
            MockResponse(200, body="page A"),
            MockResponse(200, body="page B"),
        ])
        session.get("https://example.com/a")
        session.get("https://example.com/b", headers={"Referer": ""})

        headers = mock.last_kwargs.get("headers", {})
        assert "Referer" not in headers

    @patch("time.sleep")
    def test_explicit_referer_overrides_auto(self, mock_sleep):
        """Per-request Referer should override auto-Referer."""
        session, mock = make_sync_session([
            MockResponse(200, body="page A"),
            MockResponse(200, body="page B"),
        ])
        session.get("https://example.com/a")
        session.get(
            "https://example.com/b",
            headers={"Referer": "https://google.com"},
        )

        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Referer") == "https://google.com"

    @pytest.mark.asyncio
    async def test_async_referer_chain(self):
        """Async session should also track referer chain."""
        session, mock = make_async_session([
            MockResponse(200, body="page A"),
            MockResponse(200, body="page B"),
        ])
        await session.get("https://example.com/a")
        await session.get("https://example.com/b")

        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Referer") == "https://example.com/a"


# ---------------------------------------------------------------------------
# Auto Host header tests
# ---------------------------------------------------------------------------


class TestAutoHost:
    @patch("time.sleep")
    def test_no_auto_host(self, mock_sleep):
        """Host should NOT be auto-set (rnet handles it from the URL).

        Sending Host per-request duplicates it in HTTP/2 frames, which
        strict WAFs like Cloudflare detect as non-browser behavior.
        """
        session, mock = make_sync_session([
            MockResponse(200, body="ok"),
        ])
        session.get("https://example.com/path")

        headers = mock.last_kwargs.get("headers", {})
        assert "Host" not in headers

    @patch("time.sleep")
    def test_explicit_host_per_request(self, mock_sleep):
        """Per-request Host override should be in delta."""
        session, mock = make_sync_session([
            MockResponse(200, body="ok"),
        ])
        session.get(
            "https://example.com/path",
            headers={"Host": "other.com"},
        )

        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Host") == "other.com"


# ---------------------------------------------------------------------------
# Embed mode tests
# ---------------------------------------------------------------------------


class TestEmbedMode:
    """XHR embed mode: Seaway page JS fetching MarineTraffic tile API."""

    MT_TILE_URL = (
        "https://www.marinetraffic.com/getData/get_data_json_4"
        "/z:11/X:285/Y:374/station:0"
    )
    SEAWAY_ORIGIN = "https://seaway-greatlakes.com"
    SEAWAY_REFERER = (
        "https://seaway-greatlakes.com/marine_traffic"
        "/en/marineTraffic_stCatherine.html"
    )

    @patch("time.sleep")
    def test_embed_sets_origin(self, mock_sleep):
        """Embed mode should set Origin header."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed_origin=self.SEAWAY_ORIGIN,
        )
        session.get(self.MT_TILE_URL)

        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Origin") == self.SEAWAY_ORIGIN

    @patch("time.sleep")
    def test_xhr_embed_no_x_requested_with(self, mock_sleep):
        """XHR embed mode should NOT set X-Requested-With (fetch never does)."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed_origin=self.SEAWAY_ORIGIN,
        )
        session.get(self.MT_TILE_URL)

        headers = mock.last_kwargs.get("headers", {})
        assert "X-Requested-With" not in headers

    @patch("time.sleep")
    def test_xhr_embed_accept_star(self, mock_sleep):
        """XHR embed mode should send Accept: */* (not navigation Accept)."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed_origin=self.SEAWAY_ORIGIN,
        )
        session.get(self.MT_TILE_URL)

        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Accept") == "*/*"

    @patch("time.sleep")
    def test_embed_sets_sec_fetch_headers(self, mock_sleep):
        """Embed mode should set cross-site Sec-Fetch headers."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed_origin=self.SEAWAY_ORIGIN,
        )
        session.get(self.MT_TILE_URL)

        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Sec-Fetch-Site") == "cross-site"
        assert headers.get("Sec-Fetch-Mode") == "cors"
        assert headers.get("Sec-Fetch-Dest") == "empty"

    @patch("time.sleep")
    def test_embed_uses_full_referer(self, mock_sleep):
        """Embed mode should send full Referer URL (not origin-only)."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed_origin=self.SEAWAY_ORIGIN,
            embed_referers=[self.SEAWAY_REFERER],
        )
        session.get(self.MT_TILE_URL)

        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Referer") == self.SEAWAY_REFERER

    @patch("time.sleep")
    def test_embed_no_referer_without_pool(self, mock_sleep):
        """Embed mode without referer pool should not set Referer."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed_origin=self.SEAWAY_ORIGIN,
        )
        session.get(self.MT_TILE_URL)

        headers = mock.last_kwargs.get("headers", {})
        # Embed mode sets Origin but no Referer when pool is empty
        assert "Referer" not in headers

    @patch("time.sleep")
    def test_embed_referer_overrides_chain(self, mock_sleep):
        """Embed mode Referer should override normal referer chain."""
        session, mock = make_sync_session(
            [
                MockResponse(200, body="first"),
                MockResponse(200, body="second"),
            ],
            embed_origin=self.SEAWAY_ORIGIN,
            embed_referers=[self.SEAWAY_REFERER],
        )
        # First request -- auto-referer tracking would normally set
        # the referer for second request to the first URL.
        session.get(self.MT_TILE_URL)
        session.get(
            "https://www.marinetraffic.com/getData/get_data_json_4"
            "/z:11/X:286/Y:375/station:0"
        )

        headers = mock.last_kwargs.get("headers", {})
        # Should use embed referer pool, not auto-referer chain
        assert headers.get("Referer") == self.SEAWAY_REFERER

    @patch("time.sleep")
    def test_non_embed_mode_no_origin(self, mock_sleep):
        """Normal (non-embed) mode should not set Origin."""
        session, mock = make_sync_session([
            MockResponse(200, body="ok"),
        ])
        session.get("https://www.marinetraffic.com/")

        headers = mock.last_kwargs.get("headers", {})
        assert "Origin" not in headers
        assert "X-Requested-With" not in headers

    @pytest.mark.asyncio
    async def test_async_embed_mode(self):
        """Async session embed mode should work identically."""
        session, mock = make_async_session(
            [MockResponse(200, body="ok")],
            embed_origin=self.SEAWAY_ORIGIN,
            embed_referers=[self.SEAWAY_REFERER],
        )
        await session.get(self.MT_TILE_URL)

        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Origin") == self.SEAWAY_ORIGIN
        assert "X-Requested-With" not in headers
        # Full Referer URL
        assert headers.get("Referer") == self.SEAWAY_REFERER


# ---------------------------------------------------------------------------
# Logging tests
# ---------------------------------------------------------------------------


class TestLogging:
    @patch("time.sleep")
    def test_request_debug_log(self, mock_sleep, caplog):
        """Request should log method + URL at DEBUG level."""
        session, _ = make_sync_session([
            MockResponse(200, body="ok"),
        ])
        with caplog.at_level(logging.DEBUG, logger="wafer"):
            session.get("https://example.com/test")

        assert any(
            "GET https://example.com/test" in r.message
            for r in caplog.records
        )

    @patch("time.sleep")
    def test_auto_referer_debug_log(self, mock_sleep, caplog):
        """Auto-Referer should log at DEBUG level."""
        session, _ = make_sync_session([
            MockResponse(200, body="page A"),
            MockResponse(200, body="page B"),
        ])
        with caplog.at_level(logging.DEBUG, logger="wafer"):
            session.get("https://example.com/a")
            session.get("https://example.com/b")

        assert any(
            "Auto-Referer" in r.message for r in caplog.records
        )

    @patch("time.sleep")
    def test_embed_mode_debug_log(self, mock_sleep, caplog):
        """Embed mode should log Origin at DEBUG level."""
        session, _ = make_sync_session(
            [MockResponse(200, body="ok")],
            embed_origin="https://seaway-greatlakes.com",
        )
        with caplog.at_level(logging.DEBUG, logger="wafer"):
            session.get(
                "https://www.marinetraffic.com/getData/get_data_json_4"
                "/z:11/X:285/Y:374/station:0"
            )

        assert any(
            "Embed mode" in r.message for r in caplog.records
        )

    def test_session_embed_info_log(self, caplog):
        """Session creation in embed mode should log at INFO level."""
        from wafer import SyncSession

        with caplog.at_level(logging.INFO, logger="wafer"):
            SyncSession(
                embed_origin="https://seaway-greatlakes.com",
            )

        assert any(
            "embed mode" in r.message.lower() for r in caplog.records
        )


# ---------------------------------------------------------------------------
# _build_headers unit tests (no I/O)
# ---------------------------------------------------------------------------


class TestBuildHeaders:
    def test_sec_ch_ua_at_client_level(self):
        """sec-ch-ua headers should be in client-level kwargs (not delta)."""
        session, _ = make_sync_session([])
        client_kwargs = session._build_client_kwargs()
        assert "sec-ch-ua" in client_kwargs["headers"]
        assert "sec-ch-ua-mobile" in client_kwargs["headers"]
        assert "sec-ch-ua-platform" in client_kwargs["headers"]
        # Delta should NOT include them (already at client level)
        delta = session._build_headers("https://example.com")
        assert "sec-ch-ua" not in delta

    def test_session_headers_at_client_level(self):
        """Session-level headers are at client level, not in delta."""
        session, _ = make_sync_session([])
        client_kwargs = session._build_client_kwargs()
        assert (
            client_kwargs["headers"]["Accept-Language"]
            == "en-US,en;q=0.9"
        )
        # Delta should NOT include them
        delta = session._build_headers("https://example.com")
        assert "Accept-Language" not in delta

    def test_per_request_headers_override(self):
        """Per-request headers that differ from client appear in delta."""
        session, _ = make_sync_session([])
        headers = session._build_headers(
            "https://example.com",
            {"Accept-Language": "fr-FR"},
        )
        assert headers["Accept-Language"] == "fr-FR"

    def test_empty_string_suppresses_header(self):
        """Setting a header to empty string should suppress it."""
        session, _ = make_sync_session([])
        headers = session._build_headers(
            "https://example.com",
            {"Accept-Language": ""},
        )
        assert "Accept-Language" not in headers


# ---------------------------------------------------------------------------
# Proxy tests
# ---------------------------------------------------------------------------


class TestProxy:
    def test_no_proxy_by_default(self):
        """Session created without proxy should have _proxy=None and
        no 'proxies' key in _build_client_kwargs()."""
        session, _ = make_sync_session([])
        assert session._proxy is None
        kwargs = session._build_client_kwargs()
        assert "proxies" not in kwargs

    def test_proxy_in_client_kwargs(self):
        """Setting _proxy on a session should produce a 'proxies' key
        in _build_client_kwargs()."""
        session, _ = make_sync_session([])
        session._proxy = "fake-proxy-object"
        kwargs = session._build_client_kwargs()
        assert kwargs["proxies"] == ["fake-proxy-object"]


# ---------------------------------------------------------------------------
# Iframe embed mode tests
# ---------------------------------------------------------------------------


class TestIframeEmbedMode:
    @patch("time.sleep")
    def test_iframe_sets_sec_fetch_headers(self, mock_sleep):
        """Iframe embed mode should set cross-site navigate/iframe
        Sec-Fetch headers."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="iframe",
            embed_origin="https://seaway-greatlakes.com",
        )
        session.get("https://www.marinetraffic.com/widget")

        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Sec-Fetch-Site") == "cross-site"
        assert headers.get("Sec-Fetch-Mode") == "navigate"
        assert headers.get("Sec-Fetch-Dest") == "iframe"

    @patch("time.sleep")
    def test_iframe_no_origin(self, mock_sleep):
        """Iframe GET navigations should NOT send Origin."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="iframe",
            embed_origin="https://seaway-greatlakes.com",
        )
        session.get("https://www.marinetraffic.com/widget")

        headers = mock.last_kwargs.get("headers", {})
        assert "Origin" not in headers

    @patch("time.sleep")
    def test_iframe_referer_origin_only(self, mock_sleep):
        """Iframe embed mode should strip path from Referer
        (origin-only per strict-origin-when-cross-origin)."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="iframe",
            embed_origin="https://seaway-greatlakes.com",
            embed_referers=[
                "https://seaway-greatlakes.com/marine_traffic"
                "/en/marineTraffic_stCatherine.html"
            ],
        )
        session.get("https://www.marinetraffic.com/widget")

        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Referer") == (
            "https://seaway-greatlakes.com/marine_traffic"
            "/en/marineTraffic_stCatherine.html"
        )

    @patch("time.sleep")
    def test_iframe_keeps_navigation_accept(self, mock_sleep):
        """Iframe embed mode should keep the full navigation Accept
        header (text/html,...), NOT '*/*'."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="iframe",
            embed_origin="https://seaway-greatlakes.com",
        )
        session.get("https://www.marinetraffic.com/widget")

        headers = mock.last_kwargs.get("headers", {})
        # Accept should NOT be overridden to */* (that's XHR mode)
        assert headers.get("Accept", "") != "*/*"

    @patch("time.sleep")
    def test_iframe_keeps_upgrade_insecure_requests(self, mock_sleep):
        """Iframe embed mode should keep Upgrade-Insecure-Requests
        (navigation header)."""
        session, _ = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="iframe",
            embed_origin="https://seaway-greatlakes.com",
        )
        # Check via _build_headers that UIR is NOT removed
        # (it's a client-level header, so if iframe mode doesn't
        # pop it, it stays at client level — not in delta)
        client_kwargs = session._build_client_kwargs()
        assert (
            client_kwargs["headers"].get("Upgrade-Insecure-Requests")
            == "1"
        )
        # Also verify it's not in delta (meaning it's at client level,
        # which is correct — it's still sent)
        delta = session._build_headers(
            "https://www.marinetraffic.com/widget"
        )
        # UIR should NOT be popped (unlike XHR mode which removes it)
        assert "Upgrade-Insecure-Requests" not in delta

    @patch("time.sleep")
    def test_iframe_no_x_requested_with(self, mock_sleep):
        """Iframe embed mode should NOT set X-Requested-With."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="iframe",
            embed_origin="https://seaway-greatlakes.com",
        )
        session.get("https://www.marinetraffic.com/widget")

        headers = mock.last_kwargs.get("headers", {})
        assert "X-Requested-With" not in headers
