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
        """Host should NOT be auto-set (wreq handles it from the URL).

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

        # Accept is set at client level (not per-request) to avoid
        # HTTP/2 header duplication.
        assert session._client_headers.get("Accept") == "*/*"

    @patch("time.sleep")
    def test_jquery_xhr_sends_x_requested_with(self, mock_sleep):
        """embed='xhr-jquery' should send X-Requested-With: XMLHttpRequest."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="xhr-jquery",
            embed_origin=self.SEAWAY_ORIGIN,
        )
        session.get(self.MT_TILE_URL)

        # X-Requested-With is set at client level (avoids H2 duplication).
        assert (
            session._client_headers.get("X-Requested-With")
            == "XMLHttpRequest"
        )

    @patch("time.sleep")
    def test_jquery_xhr_sends_jquery_accept(self, mock_sleep):
        """embed='xhr-jquery' should send the jQuery $.ajax Accept."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="xhr-jquery",
            embed_origin=self.SEAWAY_ORIGIN,
        )
        session.get(self.MT_TILE_URL)

        assert session._client_headers.get("Accept") == (
            "application/json, text/javascript, */*; q=0.01"
        )

    @patch("time.sleep")
    def test_jquery_xhr_keeps_xhr_sec_fetch_and_origin(self, mock_sleep):
        """jQuery XHR keeps the same CORS Sec-Fetch-* / Origin as plain xhr."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="xhr-jquery",
            embed_origin=self.SEAWAY_ORIGIN,
        )
        session.get(self.MT_TILE_URL)

        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Origin") == self.SEAWAY_ORIGIN
        assert headers.get("Sec-Fetch-Site") == "cross-site"
        assert headers.get("Sec-Fetch-Mode") == "cors"
        assert headers.get("Sec-Fetch-Dest") == "empty"
        # No navigation-only headers in jQuery XHR mode.
        assert "Cache-Control" not in session._client_headers
        assert "Upgrade-Insecure-Requests" not in session._client_headers

    @patch("time.sleep")
    def test_plain_xhr_has_no_jquery_headers(self, mock_sleep):
        """Plain embed='xhr' must NOT send X-Requested-With or jQuery Accept."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="xhr",
            embed_origin=self.SEAWAY_ORIGIN,
        )
        session.get(self.MT_TILE_URL)

        assert "X-Requested-With" not in session._client_headers
        assert session._client_headers.get("Accept") == "*/*"

    @patch("time.sleep")
    def test_iframe_embed_has_no_jquery_headers(self, mock_sleep):
        """Iframe embed mode is unchanged: no X-Requested-With, nav Accept."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="iframe",
            embed_origin=self.SEAWAY_ORIGIN,
        )
        session.get(self.MT_TILE_URL)

        assert "X-Requested-With" not in session._client_headers
        # Iframe is a navigation: keeps the navigation Accept (not */* or
        # the jQuery Accept).
        assert "application/json, text/javascript" not in (
            session._client_headers.get("Accept", "")
        )

    @pytest.mark.asyncio
    async def test_async_jquery_xhr(self):
        """Async jQuery XHR embed should set the same headers as sync."""
        session, mock = make_async_session(
            [MockResponse(200, body="ok")],
            embed="xhr-jquery",
            embed_origin=self.SEAWAY_ORIGIN,
        )
        await session.get(self.MT_TILE_URL)

        assert (
            session._client_headers.get("X-Requested-With")
            == "XMLHttpRequest"
        )
        assert session._client_headers.get("Accept") == (
            "application/json, text/javascript, */*; q=0.01"
        )

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
    def test_request_debug_log_redacts_path_and_query(self, mock_sleep, caplog):
        """Request diagnostics expose method/host but never signed URL data."""
        session, _ = make_sync_session([
            MockResponse(200, body="ok"),
        ])
        with caplog.at_level(logging.DEBUG, logger="wafer"):
            session.get("https://user:pass@example.com/secret?sign=token")

        assert any(
            "GET host=example.com" in r.message
            for r in caplog.records
        )
        assert "secret" not in caplog.text
        assert "sign=token" not in caplog.text
        assert "user:pass" not in caplog.text

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

    @pytest.mark.parametrize(
        "sent,canonical",
        [
            ("accept", "Accept"),
            ("ACCEPT", "Accept"),
            ("accept-language", "Accept-Language"),
            ("ACCEPT-LANGUAGE", "Accept-Language"),
        ],
    )
    def test_differently_cased_override_does_not_duplicate_on_the_wire(
        self, sent, canonical
    ):
        """HTTP header names are case-insensitive; wreq's are not.

        A per-request ``accept`` beside the client-level ``Accept`` puts two
        Accept fields in the HTTP/2 frame, which strict WAFs read as
        non-browser. The delta must carry the client's spelling so wreq
        overrides the existing field instead of adding a second one.
        """
        session, _ = make_sync_session([])
        client_headers = session._client_headers
        assert canonical in client_headers

        delta = session._build_headers(
            "https://example.com", {sent: "application/json"}
        )

        assert delta[canonical] == "application/json"
        # Exactly one spelling of the header, and it is the client's.
        matches = [k for k in delta if k.lower() == canonical.lower()]
        assert matches == [canonical]

    def test_differently_cased_suppression_still_works(self):
        """Empty-string suppression must survive the case folding."""
        session, _ = make_sync_session([])
        assert "Accept-Language" not in session._build_headers(
            "https://example.com", {"accept-language": ""}
        )

    def test_unknown_header_keeps_caller_casing(self):
        """Only headers that exist at client level get re-spelled."""
        session, _ = make_sync_session([])
        delta = session._build_headers("https://example.com", {"X-Custom": "1"})
        assert delta["X-Custom"] == "1"


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
    def test_iframe_post_sends_origin(self, mock_sleep):
        """Iframe POST navigations should send Origin (Fetch spec)."""
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="iframe",
            embed_origin="https://seaway-greatlakes.com",
        )
        session.post("https://www.marinetraffic.com/submit")

        headers = mock.last_kwargs.get("headers", {})
        assert headers.get("Origin") == "https://seaway-greatlakes.com"

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


# ---------------------------------------------------------------------------
# Embed mode owns its full header set (wreq's navigation headers are off)
# ---------------------------------------------------------------------------


class TestEmbedOwnedHeaders:
    """In embed mode wafer turns off wreq's per-profile header set, which is a
    top-level navigation (it carries Upgrade-Insecure-Requests and, since wreq
    0.12.2, Sec-Fetch-User), and supplies every header plus the captured
    browser order itself."""

    @staticmethod
    def _session(embed, **kwargs):
        from wafer import SyncSession

        return SyncSession(
            embed=embed, embed_origin="https://widget-host.example", **kwargs
        )

    @pytest.mark.parametrize(
        "embed,expected", [(None, True), ("xhr", False), ("iframe", False)]
    )
    def test_wreq_header_set_off_only_in_embed(self, monkeypatch, embed, expected):
        import wafer._base as base

        seen = []
        real = base.wreq_emulation

        def recording(profile, *, default_headers=True):
            seen.append(default_headers)
            return real(profile, default_headers=default_headers)

        monkeypatch.setattr(base, "wreq_emulation", recording)
        from wafer import SyncSession

        if embed is None:
            SyncSession()._build_client_kwargs()
        else:
            self._session(embed)._build_client_kwargs()
        assert seen and seen[-1] is expected

    def test_navigation_keeps_wreq_default_headers(self):
        from wreq import Emulation

        from wafer import SyncSession

        kwargs = SyncSession()._build_client_kwargs()
        assert isinstance(kwargs["emulation"], Emulation)
        assert "orig_headers" not in kwargs

    @pytest.mark.parametrize("embed", ["xhr", "xhr-jquery"])
    def test_xhr_sends_no_navigation_headers(self, embed):
        kwargs = self._session(embed)._build_client_kwargs()
        names = {k.lower() for k in kwargs["headers"]}
        assert "upgrade-insecure-requests" not in names
        assert "cache-control" not in names
        assert "sec-fetch-user" not in names
        assert kwargs["headers"]["Priority"] == "u=1, i"

    def test_xhr_supplies_what_wreq_used_to(self):
        from wafer import SyncSession
        from wafer._base import DEFAULT_EMULATION
        from wafer._fingerprint import emulation_user_agent

        headers = self._session("xhr")._build_client_kwargs()["headers"]
        assert headers["User-Agent"] == emulation_user_agent(DEFAULT_EMULATION)
        assert headers["Accept"] == "*/*"
        assert headers["Accept-Encoding"] == "gzip, deflate, br, zstd"
        # A session whose headers= left out Accept-Encoding still sends one.
        bare = SyncSession(
            headers={"Accept-Language": "fr-FR"},
            embed="xhr",
            embed_origin="https://widget-host.example",
        )
        filled = bare._build_client_kwargs()["headers"]
        assert filled["Accept-Encoding"] == "gzip, deflate, br, zstd"
        assert filled["Accept-Language"] == "fr-FR"

    def test_chrome_fetch_order(self):
        order = self._session("xhr")._build_client_kwargs()["orig_headers"]
        # Google Chrome 153 fetch(), captured 2026-09-24.
        assert order[:8] == [
            "Content-Length", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua",
            "Content-Type", "sec-ch-ua-mobile", "Accept", "Origin",
        ]
        assert order[-3:] == ["Accept-Language", "Cookie", "Priority"]

    def test_chrome_jquery_order_puts_x_requested_with_second(self):
        order = self._session("xhr-jquery")._build_client_kwargs()["orig_headers"]
        assert order[1:3] == ["sec-ch-ua-platform", "X-Requested-With"]

    def test_iframe_is_an_unactivated_frame_load(self):
        kwargs = self._session("iframe")._build_client_kwargs()
        names = {k.lower() for k in kwargs["headers"]}
        assert kwargs["headers"]["Upgrade-Insecure-Requests"] == "1"
        assert kwargs["headers"]["Priority"] == "u=0, i"
        assert "sec-fetch-user" not in names
        assert "Sec-Fetch-Storage-Access" in kwargs["orig_headers"]

    def test_iframe_storage_access_only_cross_site(self):
        session = self._session("iframe")
        cross = session._build_headers("https://other-site.example/w")
        same = session._build_headers("https://www.widget-host.example/w")
        assert cross["Sec-Fetch-Storage-Access"] == "active"
        assert "Sec-Fetch-Storage-Access" not in same

    def test_firefox_rung_uses_firefox_shape(self):
        from wreq import Emulation

        xhr = self._session("xhr", emulation=Emulation.Firefox151)
        kwargs = xhr._build_client_kwargs()
        assert kwargs["headers"]["TE"] == "trailers"
        assert kwargs["headers"]["Priority"] == "u=4"
        assert "Firefox/151.0" in kwargs["headers"]["User-Agent"]
        assert kwargs["orig_headers"][0] == "User-Agent"
        assert kwargs["orig_headers"][-1] == "te"
        # Firefox sends no Priority header on an XMLHttpRequest.
        jq = self._session("xhr-jquery", emulation=Emulation.Firefox151)
        assert "Priority" not in jq._build_client_kwargs()["headers"]
        frame = self._session("iframe", emulation=Emulation.Firefox151)
        cross = frame._build_headers("https://other-site.example/w")
        assert cross["Sec-Fetch-Storage-Access"] == "none"

    def test_session_headers_win(self):
        session = self._session(
            "xhr", headers={"User-Agent": "custom-ua", "Priority": "u=3"}
        )
        headers = session._build_client_kwargs()["headers"]
        assert headers["User-Agent"] == "custom-ua"
        assert headers["Priority"] == "u=3"

    @pytest.mark.parametrize("embed", [None, "xhr"])
    def test_empty_session_header_never_reaches_wreq(self, embed):
        # wreq would send "" as an empty header; a session "" means "leave it
        # off", and it still suppresses the auto-Referer.
        from wafer import SyncSession
        from wafer._base import DEFAULT_HEADERS

        headers = dict(DEFAULT_HEADERS, **{"Cache-Control": "", "Referer": ""})
        session = (
            self._session(embed, headers=headers)
            if embed
            else SyncSession(headers=headers)
        )
        sent = session._build_client_kwargs()["headers"]
        assert "Cache-Control" not in sent
        assert "Referer" not in sent
        session._record_url("https://example.com/a")
        assert "Referer" not in session._build_headers("https://example.com/b")

    def test_safari_profile_keeps_its_own_headers(self):
        from wafer import Profile

        kwargs = self._session("xhr", profile=Profile.SAFARI)._build_client_kwargs()
        assert "emulation" not in kwargs
        assert "orig_headers" not in kwargs

    def test_suspended_embed_restores_navigation_headers(self):
        session = self._session("xhr")
        with session._embed_suspended():
            assert "orig_headers" not in session._build_client_kwargs()
        assert "orig_headers" in session._build_client_kwargs()
