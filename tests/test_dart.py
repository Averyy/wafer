"""Tests for Dart profile and identity."""

import pytest
from wreq.tls import TlsOptions

from wafer._dart import _DART_VERSION, DartIdentity
from wafer._profiles import Profile


class TestProfile:
    def test_dart_value(self):
        assert Profile.DART.value == "dart"

    def test_dart_name(self):
        assert Profile.DART.name == "DART"

    def test_import_from_wafer(self):
        from wafer import Profile

        assert Profile.DART.value == "dart"


class TestDartIdentity:
    def test_user_agent_format(self):
        identity = DartIdentity()
        assert identity.user_agent == f"Dart/{_DART_VERSION} (dart:io)"

    def test_user_agent_stable(self):
        """User-Agent is fixed per session (no randomization)."""
        identity = DartIdentity()
        assert identity.user_agent == identity.user_agent

    def test_client_headers_keys(self):
        identity = DartIdentity()
        h = identity.client_headers()
        assert set(h.keys()) == {"User-Agent", "Accept-Encoding"}

    def test_client_headers_user_agent(self):
        identity = DartIdentity()
        h = identity.client_headers()
        assert h["User-Agent"] == f"Dart/{_DART_VERSION} (dart:io)"

    def test_client_headers_accept_encoding(self):
        identity = DartIdentity()
        h = identity.client_headers()
        assert h["Accept-Encoding"] == "gzip"

    def test_tls_options_returns_tls_options(self):
        identity = DartIdentity()
        opts = identity.tls_options()
        assert isinstance(opts, TlsOptions)


class TestDartSession:
    """Test Dart profile integration with BaseSession."""

    def test_no_fingerprint_manager(self):
        """Dart sessions should not have a FingerprintManager."""
        from tests.conftest import make_sync_session

        session, _ = make_sync_session([], profile=Profile.DART)
        assert session._profile is Profile.DART
        assert session._fingerprint is None

    def test_challenge_detection_skipped(self):
        """Dart sessions should skip challenge detection."""
        from tests.conftest import MockResponse, make_sync_session

        # Cloudflare challenge page
        cf_body = (
            '<html><head><title>Just a moment...</title></head>'
            '<body>Checking your browser</body></html>'
        )
        resp = MockResponse(
            403,
            {"content-type": "text/html"},
            cf_body,
        )
        session, _ = make_sync_session(
            [resp],
            profile=Profile.DART,
            max_rotations=0,
        )
        result = session.get("https://example.com")
        # Should return the 403 response, not raise ChallengeDetected
        assert result.status_code == 403

    def test_build_headers_returns_only_extra(self):
        """Dart _build_headers returns only per-request overrides."""
        from tests.conftest import make_sync_session

        session, _ = make_sync_session([], profile=Profile.DART)
        # No extra headers
        delta = session._build_headers("https://example.com")
        assert delta == {}

        # With extra headers
        delta = session._build_headers(
            "https://example.com",
            extra={"X-User-Agent": "android(...);bmw;6.3.1;na"},
        )
        assert delta == {"X-User-Agent": "android(...);bmw;6.3.1;na"}

    def test_tried_safari_true_for_dart(self):
        """Dart sessions must have _tried_safari=True to block rotation."""
        from tests.conftest import make_sync_session

        session, _ = make_sync_session([], profile=Profile.DART)
        assert session._tried_safari is True

    def test_429_does_not_mutate_identity(self):
        """A 429 response must not switch Dart to Safari or Chrome."""
        from tests.conftest import MockResponse, make_sync_session

        ok_resp = MockResponse(200, {"content-type": "text/html"}, "ok")
        rate_resp = MockResponse(429, {"retry-after": "0"})
        session, _ = make_sync_session(
            [rate_resp, ok_resp],
            profile=Profile.DART,
            max_rotations=2,
        )
        result = session.get("https://example.com")
        # Should eventually succeed after retry
        assert result.status_code == 200
        # Identity must remain Dart throughout
        assert session._dart_identity is not None
        assert session._safari_identity is None
        assert session._fingerprint is None

    def test_chrome_headers_not_captured(self):
        """Dart sessions must not store headers in _chrome_headers."""
        from tests.conftest import make_sync_session

        session, _ = make_sync_session([], profile=Profile.DART)
        assert session._chrome_headers is None

    def test_embed_mode_rejected(self):
        """Embed mode should raise ValueError with Dart profile."""
        from wafer._base import BaseSession

        with pytest.raises(ValueError, match="Embed mode"):
            BaseSession(profile=Profile.DART, embed_origin="https://x.com")
