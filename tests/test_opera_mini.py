"""Tests for Opera Mini profile and identity generation."""

import re

from wafer._opera_mini import (
    _LOCALES,
    _OM_VERSIONS,
    _SERVER_VERSIONS,
    OperaMiniIdentity,
    _stock_chrome_ua,
)
from wafer._profiles import Profile


class TestProfile:
    def test_opera_mini_value(self):
        assert Profile.OPERA_MINI.value == "opera_mini"

    def test_profile_is_enum(self):
        assert Profile.OPERA_MINI.name == "OPERA_MINI"


class TestOmVersionPool:
    def test_all_versions_match_format(self):
        """All versions follow the X.{0,1}.2254 format."""
        for v in _OM_VERSIONS:
            parts = v.split(".")
            assert len(parts) == 3, f"Bad format: {v}"
            assert int(parts[0]) >= 83, f"Major too low: {v}"
            assert parts[1] in ("0", "1"), f"Bad minor: {v}"
            assert parts[2] == "2254", f"Bad product line: {v}"

    def test_has_enough_versions(self):
        assert len(_OM_VERSIONS) >= 15

    def test_has_both_minor_variants(self):
        """Pool includes both .0 and .1 minor versions."""
        minors = {v.split(".")[1] for v in _OM_VERSIONS}
        assert "0" in minors
        assert "1" in minors


class TestServerVersionPool:
    def test_all_server_versions_match_format(self):
        for v in _SERVER_VERSIONS:
            parts = v.split(".")
            assert len(parts) == 2, f"Bad format: {v}"
            assert parts[0] == "191", f"Bad prefix: {v}"
            assert int(parts[1]) >= 300, f"Build too low: {v}"

    def test_has_enough_versions(self):
        assert len(_SERVER_VERSIONS) >= 5


class TestStockChromeUa:
    def test_contains_chrome(self):
        ua = _stock_chrome_ua("SM-A515F", 13, 3)
        assert "Chrome/" in ua

    def test_contains_model(self):
        ua = _stock_chrome_ua("SM-A515F", 13, 3)
        assert "SM-A515F" in ua

    def test_contains_android_version(self):
        ua = _stock_chrome_ua("SM-A515F", 13, 3)
        assert "Android 13" in ua

    def test_valid_ua_format(self):
        ua = _stock_chrome_ua("Nokia C22", 13, 7)
        assert ua.startswith("Mozilla/5.0")
        assert "AppleWebKit/537.36" in ua
        assert "Mobile Safari/537.36" in ua

    def test_lag_produces_older_chrome(self):
        """More lag months produce older Chrome version."""
        ua_3mo = _stock_chrome_ua("SM-A515F", 13, 3)
        ua_12mo = _stock_chrome_ua("SM-A515F", 13, 12)
        chrome_re = re.compile(r"Chrome/(\d+)")
        ver_3 = int(chrome_re.search(ua_3mo).group(1))
        ver_12 = int(chrome_re.search(ua_12mo).group(1))
        assert ver_3 > ver_12


class TestOperaMiniIdentity:
    def test_user_agent_contains_opera_mini(self):
        identity = OperaMiniIdentity()
        assert "Opera Mini" in identity.user_agent

    def test_user_agent_contains_presto(self):
        identity = OperaMiniIdentity()
        assert "Presto/" in identity.user_agent

    def test_user_agent_format(self):
        identity = OperaMiniIdentity()
        assert identity.user_agent.startswith("Opera/9.80")
        assert "Version/12.16" in identity.user_agent

    def test_headers_returns_dict(self):
        identity = OperaMiniIdentity()
        h = identity.headers()
        assert isinstance(h, dict)

    def test_headers_has_all_required_keys(self):
        identity = OperaMiniIdentity()
        h = identity.headers()
        required_keys = [
            "User-Agent",
            "Accept",
            "Accept-Language",
            "Accept-Encoding",
            "Connection",
            "X-OperaMini-Features",
            "X-OperaMini-Phone",
            "X-OperaMini-Phone-UA",
            "Device-Stock-UA",
        ]
        for key in required_keys:
            assert key in h, f"Missing required header: {key}"

    def test_headers_user_agent_is_opera_mini(self):
        identity = OperaMiniIdentity()
        h = identity.headers()
        assert "Opera Mini" in h["User-Agent"]
        assert "Presto/" in h["User-Agent"]

    def test_headers_stock_ua_matches(self):
        identity = OperaMiniIdentity()
        h = identity.headers()
        assert h["X-OperaMini-Phone-UA"] == identity.stock_ua
        assert h["Device-Stock-UA"] == identity.stock_ua

    def test_identity_binding_stable_except_server_ver(self):
        """Device, features, phone headers are stable across calls."""
        identity = OperaMiniIdentity()
        h1 = identity.headers()
        h2 = identity.headers()
        # These are bound per-session and must not change
        assert h1["X-OperaMini-Phone"] == h2["X-OperaMini-Phone"]
        assert h1["X-OperaMini-Features"] == h2["X-OperaMini-Features"]
        assert h1["Device-Stock-UA"] == h2["Device-Stock-UA"]
        assert h1["Accept-Encoding"] == h2["Accept-Encoding"]
        assert h1["Connection"] == h2["Connection"]

    def test_accept_encoding_opera_mini_style(self):
        """Accept-Encoding matches Opera Mini's proxy format."""
        identity = OperaMiniIdentity()
        h = identity.headers()
        assert "deflate" in h["Accept-Encoding"]
        assert "x-gzip" in h["Accept-Encoding"]

    def test_connection_keep_alive(self):
        identity = OperaMiniIdentity()
        h = identity.headers()
        assert h["Connection"] == "Keep-Alive"

    def test_features_is_valid(self):
        """Features header contains known capability strings."""
        identity = OperaMiniIdentity()
        h = identity.headers()
        features = h["X-OperaMini-Features"]
        assert "advanced" in features
        assert "secure" in features
        assert "touch" in features

    def test_different_identities_may_differ(self):
        """Two independent identities are unlikely to be identical."""
        identities = [OperaMiniIdentity() for _ in range(20)]
        phones = {i.phone_header for i in identities}
        assert len(phones) > 1

    def test_user_agent_has_real_server_version(self):
        """Server version in UA must be from real observed values."""
        identity = OperaMiniIdentity()
        ua = identity.user_agent
        match = re.search(r"Opera Mini/[\d.]+/(\d+\.\d+)", ua)
        assert match, f"No server version in UA: {ua}"
        assert match.group(1) in _SERVER_VERSIONS

    def test_server_version_varies_across_calls(self):
        """Server version should vary across many calls."""
        identity = OperaMiniIdentity()
        server_versions = set()
        for _ in range(200):
            ua = identity.user_agent
            match = re.search(r"Opera Mini/[\d.]+/(\d+\.\d+)", ua)
            server_versions.add(match.group(1))
        # With 10 server versions (weighted), 200 calls should hit at least 3
        assert len(server_versions) >= 3

    def test_locale_in_ua(self):
        """UA contains a locale code (not always 'en')."""
        identity = OperaMiniIdentity()
        ua = identity.user_agent
        match = re.search(r"; U; ([a-z]+)\)", ua)
        assert match, f"No locale in UA: {ua}"
        assert match.group(1) in _LOCALES

    def test_accept_language_matches_locale(self):
        """Accept-Language should reflect the locale in the UA."""
        identity = OperaMiniIdentity()
        h = identity.headers()
        locale = identity._locale
        if locale == "en":
            assert h["Accept-Language"].startswith("en-US")
        else:
            assert h["Accept-Language"].startswith(locale)

    def test_ua_full_format_regex(self):
        """UA matches the documented Opera Mini format."""
        identity = OperaMiniIdentity()
        ua = identity.user_agent
        pattern = (
            r"Opera/9\.80 \(Android( \d+)?; Opera Mini/"
            r"\d+\.[01]\.2254/\d+\.\d+; U; [a-z]+\) "
            r"Presto/2\.12\.423 Version/12\.16"
        )
        assert re.match(pattern, ua), f"UA doesn't match format: {ua}"

    def test_om_version_from_confirmed_pool(self):
        """Client version must come from the confirmed version pool."""
        identity = OperaMiniIdentity()
        assert identity.om_version in _OM_VERSIONS

    def test_locale_diversity(self):
        """Multiple identities should produce diverse locales."""
        locales = set()
        for _ in range(100):
            identity = OperaMiniIdentity()
            locales.add(identity._locale)
        assert len(locales) >= 3


class TestApplyParams:
    """Test BaseSession._apply_params (params= kwarg support)."""

    def test_adds_params_to_url(self):
        from wafer._base import BaseSession
        result = BaseSession._apply_params(
            "https://example.com/search", {"q": "test", "page": "1"}
        )
        assert "?" in result
        assert "q=test" in result
        assert "page=1" in result

    def test_appends_to_existing_query(self):
        from wafer._base import BaseSession
        result = BaseSession._apply_params(
            "https://example.com/search?hl=en", {"q": "test"}
        )
        assert "&q=test" in result
        assert result.startswith("https://example.com/search?hl=en&")

    def test_none_params_returns_url_unchanged(self):
        from wafer._base import BaseSession
        url = "https://example.com/search"
        assert BaseSession._apply_params(url, None) == url

    def test_empty_params_returns_url_unchanged(self):
        from wafer._base import BaseSession
        url = "https://example.com/search"
        assert BaseSession._apply_params(url, {}) == url

    def test_special_characters_encoded(self):
        from wafer._base import BaseSession
        result = BaseSession._apply_params(
            "https://example.com/search", {"q": "hello world"}
        )
        assert "q=hello+world" in result


class TestProfileImport:
    def test_import_from_wafer(self):
        """Profile is importable from the top-level wafer package."""
        from wafer import Profile
        assert Profile.OPERA_MINI.value == "opera_mini"
