"""Tests for fingerprint management and sec-ch-ua generation."""

import os

import pytest
from wreq import Emulation

from wafer._fingerprint import (
    _CHROME_BUILDS,
    _EDGE_BUILDS,
    CHROME_PROFILES,
    FingerprintManager,
    build_fingerprint_envelope,
    chrome_version,
    emulation_family,
    emulation_is_mobile,
    emulation_major_version,
    emulation_user_agent,
    family_headers,
    full_version,
    generate_sec_ch_ua,
    sec_ch_ua,
)


class TestSecChUaGeneration:
    """Verify sec-ch-ua output matches real Chrome for known versions.

    Expected values computed from the Chromium source algorithm and
    validated against observed Chrome headers in the wild.
    """

    def test_chrome_131(self):
        result = generate_sec_ch_ua(131)
        assert result == (
            '"Google Chrome";v="131", '
            '"Chromium";v="131", '
            '"Not_A Brand";v="24"'
        )

    def test_chrome_134(self):
        result = generate_sec_ch_ua(134)
        assert result == (
            '"Chromium";v="134", '
            '"Not:A-Brand";v="24", '
            '"Google Chrome";v="134"'
        )

    def test_chrome_138(self):
        result = generate_sec_ch_ua(138)
        assert result == (
            '"Not)A;Brand";v="8", '
            '"Chromium";v="138", '
            '"Google Chrome";v="138"'
        )

    def test_chrome_145(self):
        result = generate_sec_ch_ua(145)
        assert result == (
            '"Not:A-Brand";v="99", '
            '"Google Chrome";v="145", '
            '"Chromium";v="145"'
        )

    def test_chrome_130(self):
        result = generate_sec_ch_ua(130)
        assert result == (
            '"Chromium";v="130", '
            '"Google Chrome";v="130", '
            '"Not?A_Brand";v="99"'
        )

    def test_chrome_143(self):
        result = generate_sec_ch_ua(143)
        assert result == (
            '"Google Chrome";v="143", '
            '"Chromium";v="143", '
            '"Not A(Brand";v="24"'
        )

    def test_grease_chars_cycle_every_11(self):
        """Chrome versions 11 apart should produce the same GREASE chars."""
        v100 = generate_sec_ch_ua(100)
        v111 = generate_sec_ch_ua(111)
        # Extract GREASE brand from each -- both should have same
        # char pattern since 100 % 11 == 111 % 11 == 1
        assert "Not(A:Brand" in v100
        assert "Not(A:Brand" in v111

    def test_full_cycle_repeats_at_66(self):
        """The sec-ch-ua pattern repeats every lcm(11, 3, 6) = 66 versions."""
        assert generate_sec_ch_ua(100) == generate_sec_ch_ua(166).replace(
            "166", "100"
        )


class TestChromeVersion:
    def test_known_profile(self):
        assert chrome_version(Emulation.Chrome145) == 145

    def test_oldest_profile(self):
        assert chrome_version(Emulation.Chrome100) == 100

    def test_non_chrome_returns_none(self):
        assert chrome_version(Emulation.Firefox133) is None


class TestChromeProfiles:
    def test_profiles_discovered(self):
        assert len(CHROME_PROFILES) == 41

    def test_newest_first(self):
        versions = [v for v, _ in CHROME_PROFILES]
        assert versions[0] == 149
        assert versions == sorted(versions, reverse=True)


class TestFingerprintManager:
    def test_defaults_to_newest_chrome(self):
        fm = FingerprintManager()
        assert fm.current == Emulation.Chrome149

    def test_custom_initial(self):
        fm = FingerprintManager(initial=Emulation.Chrome130)
        assert fm.current == Emulation.Chrome130

    def test_rotation_changes_profile(self):
        fm = FingerprintManager(initial=Emulation.Chrome149)
        original = fm.current
        fm.rotate()
        assert fm.current != original

    def test_rotation_cycles_through_profiles(self):
        fm = FingerprintManager(initial=Emulation.Chrome149)
        seen = {repr(fm.current)}
        for _ in range(40):  # 41 total profiles - 1 initial
            fm.rotate()
            seen.add(repr(fm.current))
        # Should have visited all 41 Chrome profiles
        assert len(seen) == 41

    def test_pinning_prevents_rotation(self):
        fm = FingerprintManager(initial=Emulation.Chrome149)
        fm.pin()
        assert fm.pinned
        fm.rotate()
        assert fm.current == Emulation.Chrome149

    def test_pin_is_idempotent(self):
        fm = FingerprintManager()
        fm.pin()
        fm.pin()
        assert fm.pinned

    def test_reset_clears_pin(self):
        fm = FingerprintManager(initial=Emulation.Chrome130)
        fm.pin()
        fm.reset()
        assert not fm.pinned
        assert fm.current == Emulation.Chrome149  # resets to newest

    def test_reset_with_custom_emulation(self):
        fm = FingerprintManager()
        fm.reset(emulation=Emulation.Chrome130)
        assert fm.current == Emulation.Chrome130
        assert not fm.pinned

    def test_sec_ch_ua_headers_for_chrome(self):
        fm = FingerprintManager(initial=Emulation.Chrome149)
        headers = fm.sec_ch_ua_headers()
        assert "sec-ch-ua" in headers
        assert "sec-ch-ua-mobile" in headers
        assert "sec-ch-ua-platform" in headers
        assert '"149"' in headers["sec-ch-ua"]
        assert headers["sec-ch-ua-mobile"] == "?0"

    def test_sec_ch_ua_updates_after_rotation(self):
        fm = FingerprintManager(initial=Emulation.Chrome149)
        headers_before = fm.sec_ch_ua_headers()
        fm.rotate()
        headers_after = fm.sec_ch_ua_headers()
        # sec-ch-ua should change because the Chrome version changed
        assert headers_before["sec-ch-ua"] != headers_after["sec-ch-ua"]


class TestSessionFingerprint:
    def test_session_has_fingerprint_manager(self):
        from wafer import SyncSession

        s = SyncSession()
        assert hasattr(s, "_fingerprint")
        assert s.emulation == Emulation.Chrome149

    @pytest.mark.live
    @pytest.mark.skipif(
        os.environ.get("WAFER_LIVE") != "1",
        reason="live network test; set WAFER_LIVE=1 to run",
    )
    def test_session_sends_sec_ch_ua(self):
        from wafer import SyncSession

        s = SyncSession()
        resp = s.get("https://httpbin.org/headers")
        data = resp.json()
        headers = data["headers"]
        assert "Sec-Ch-Ua" in headers
        assert '"149"' in headers["Sec-Ch-Ua"]

    def test_session_rebuild_changes_emulation(self):
        from wafer import SyncSession

        s = SyncSession()
        assert s.emulation == Emulation.Chrome149
        s._fingerprint.rotate()
        s._rebuild_client()
        assert s.emulation != Emulation.Chrome149

    def test_auto_sec_ch_ua_overrides_user_header(self):
        """Auto-generated sec-ch-ua must override user-provided headers.

        Mismatched sec-ch-ua vs TLS fingerprint is a detection signal,
        so the auto-generated value (matching the Emulation profile) wins.
        The override happens at client construction time (in
        _build_client_kwargs), so _build_headers returns an empty delta
        for sec-ch-ua (it's already correct at client level).
        """
        from wafer import SyncSession

        s = SyncSession(headers={"sec-ch-ua": "custom-bad-value"})
        # Client-level headers should have the correct sec-ch-ua
        client_kwargs = s._build_client_kwargs()
        assert client_kwargs["headers"]["sec-ch-ua"] != "custom-bad-value"
        assert '"149"' in client_kwargs["headers"]["sec-ch-ua"]
        # Per-request delta should NOT include sec-ch-ua (already correct)
        built = s._build_headers("https://example.com")
        assert "sec-ch-ua" not in built


class TestEmulationFamily:
    """Family classification across Chrome/Edge/Firefox/Opera/Safari."""

    def test_chrome_family(self):
        assert emulation_family(Emulation.Chrome147) == "chrome"

    def test_edge_family(self):
        assert emulation_family(Emulation.Edge147) == "edge"

    def test_firefox_family(self):
        assert emulation_family(Emulation.Firefox149) == "firefox"

    def test_opera_family(self):
        assert emulation_family(Emulation.Opera130) == "opera"

    def test_safari_family(self):
        assert emulation_family(Emulation.Safari26) == "safari"

    def test_major_version_chrome(self):
        assert emulation_major_version(Emulation.Chrome147) == 147

    def test_major_version_firefox(self):
        assert emulation_major_version(Emulation.Firefox149) == 149

    def test_major_version_edge(self):
        assert emulation_major_version(Emulation.Edge147) == 147

    def test_firefox_android_variant(self):
        # Variant profile (digits not immediately after "Firefox") must
        # classify into the firefox base family, not fall back to Chrome.
        assert emulation_family(Emulation.FirefoxAndroid135) == "firefox"
        assert emulation_major_version(Emulation.FirefoxAndroid135) == 135

    def test_firefox_private_variant(self):
        assert emulation_family(Emulation.FirefoxPrivate136) == "firefox"
        assert emulation_major_version(Emulation.FirefoxPrivate136) == 136

    def test_safari_ios_variant(self):
        # SafariIos26_2 -> safari v26 (digits after "Ios", not "Safari").
        assert emulation_family(Emulation.SafariIos26_2) == "safari"
        assert emulation_major_version(Emulation.SafariIos26_2) == 26

    def test_safari_ipad_variants(self):
        # Both casings wreq uses: "IPad" and "Ipad".
        assert emulation_family(Emulation.SafariIPad18) == "safari"
        assert emulation_family(Emulation.SafariIpad26_2) == "safari"

    def test_okhttp_classifies_as_none(self):
        # OkHttp is not a browser family and sends no client hints.
        assert emulation_family(Emulation.OkHttp5) is None

    def test_all_profiles_classify_sensibly(self):
        # Every wreq Emulation profile must classify into the family its
        # repr name starts with (or None for OkHttp / random). A variant
        # like FirefoxAndroid135 must NOT silently fall back to Chrome.
        prefixes = {
            "Chrome": "chrome",
            "Edge": "edge",
            "Firefox": "firefox",
            "Opera": "opera",
            "Safari": "safari",
        }
        for name in dir(Emulation):
            if name.startswith("_") or name == "random":
                continue
            em = getattr(Emulation, name)
            fam = emulation_family(em)
            expected = None
            for prefix, family in prefixes.items():
                if name.startswith(prefix):
                    expected = family
                    break
            assert fam == expected, (
                f"{name!r} classified as {fam!r}, expected {expected!r}"
            )


class TestPublicSecChUa:
    """The public sec_ch_ua wrapper, used by external tooling."""

    def test_default_brand_is_chrome(self):
        # Public wrapper matches the internal generator for Chrome.
        assert sec_ch_ua(147) == generate_sec_ch_ua(147)

    def test_edge_brand_token(self):
        result = sec_ch_ua(147, brand="Microsoft Edge")
        assert '"Microsoft Edge";v="147"' in result
        assert '"Chromium";v="147"' in result
        assert "Google Chrome" not in result

    def test_edge_brand_matches_internal(self):
        assert sec_ch_ua(147, brand="Microsoft Edge") == generate_sec_ch_ua(
            147, brand="Microsoft Edge"
        )


class TestFamilyHeaders:
    """Per-family navigation header envelope."""

    def test_firefox_no_sec_ch_ua_and_short_accept(self):
        env = family_headers("firefox")
        # Firefox 132+ navigation Accept (MDN-authoritative, wire-verified).
        assert env["Accept"] == (
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )
        # Firefox uses q=0.5 in Accept-Language (not Chrome's q=0.9).
        assert env["Accept-Language"] == "en-US,en;q=0.5"
        # No sec-ch-ua keys in the Firefox envelope.
        assert not any(k.lower().startswith("sec-ch-ua") for k in env)
        # No Chrome-only signed-exchange token.
        assert "application/signed-exchange" not in env["Accept"]

    def test_edge_uses_chrome_accept(self):
        # Edge is Chromium: same navigation Accept as Chrome.
        assert family_headers("edge")["Accept"] == family_headers(
            "chrome"
        )["Accept"]

    def test_safari_short_accept_no_zstd_no_nav_headers(self):
        # wreq's Safari Emulation profiles (desktop + mobile iOS/iPad) get
        # the short WebKit Accept, q=0.9 Accept-Language, no zstd, and no
        # navigation-only headers. Wire-verified 2026-06-12.
        env = family_headers("safari")
        assert env["Accept"] == (
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )
        assert env["Accept-Language"] == "en-US,en;q=0.9"
        assert env["Accept-Encoding"] == "gzip, deflate, br"  # no zstd
        assert "Cache-Control" not in env
        assert "Upgrade-Insecure-Requests" not in env
        assert not any(k.lower().startswith("sec-ch-ua") for k in env)
        # No Chromium-only signed-exchange / image-format tokens.
        assert "application/signed-exchange" not in env["Accept"]
        assert "image/avif" not in env["Accept"]

    def test_unknown_family_returns_none(self):
        # Opera has its own wreq-native hints; None has no envelope.
        assert family_headers("opera") is None
        assert family_headers(None) is None


class TestEmulationUserAgent:
    """UA reconstruction mirrors what wreq sends per family."""

    def test_chrome_ua(self):
        ua = emulation_user_agent(Emulation.Chrome147)
        assert "Chrome/147.0.0.0" in ua
        assert "Edg/" not in ua

    def test_edge_ua_has_edg_token(self):
        ua = emulation_user_agent(Emulation.Edge147)
        assert "Chrome/147.0.0.0" in ua
        assert "Edg/147" in ua

    def test_firefox_ua(self):
        ua = emulation_user_agent(Emulation.Firefox149)
        assert "Firefox/149.0" in ua
        assert "rv:149.0" in ua
        assert "Gecko/20100101" in ua

    def test_safari_not_reconstructed(self):
        # Safari uses its own identity module, not this path.
        assert emulation_user_agent(Emulation.Safari26) is None


class TestFingerprintManagerFamilies:
    """sec_ch_ua_headers() is family-aware."""

    def test_edge_sends_microsoft_edge_brand(self):
        fm = FingerprintManager(initial=Emulation.Edge147)
        headers = fm.sec_ch_ua_headers()
        assert '"Microsoft Edge";v="147"' in headers["sec-ch-ua"]
        assert "sec-ch-ua-full-version-list" in headers
        assert "Microsoft Edge" in headers["sec-ch-ua-full-version-list"]

    def test_firefox_sends_no_client_hints(self):
        fm = FingerprintManager(initial=Emulation.Firefox149)
        assert fm.sec_ch_ua_headers() == {}

    def test_opera_sends_no_client_hints(self):
        # Opera hints are injected accurately by wreq's own Emulation;
        # wafer must NOT emit its own (wrong) Opera-GREASE hints, which
        # would clobber wreq's correct ones. Wire-verified 2026-06-12.
        fm = FingerprintManager(initial=Emulation.Opera130)
        assert fm.sec_ch_ua_headers() == {}

    def test_chrome_unchanged(self):
        fm = FingerprintManager(initial=Emulation.Chrome147)
        headers = fm.sec_ch_ua_headers()
        assert '"Google Chrome";v="147"' in headers["sec-ch-ua"]

    def test_edge_brand_carries_edge_build_not_chrome(self):
        # The "Microsoft Edge" brand must carry Edge's OWN build number,
        # NOT Chrome's. Edge147 = 147.0.3912.51, Chrome147 = 147.0.7727.24.
        fm = FingerprintManager(initial=Emulation.Edge147)
        h = fm.sec_ch_ua_headers()
        edge_build, edge_patch = _EDGE_BUILDS[147]
        chrome_build, _ = _CHROME_BUILDS[147]
        edge_full = f"147.0.{edge_build}.{edge_patch}"
        # sec-ch-ua-full-version is the Edge brand build.
        assert h["sec-ch-ua-full-version"] == f'"{edge_full}"'
        assert edge_build != chrome_build  # genuinely different series
        fvl = h["sec-ch-ua-full-version-list"]
        # Microsoft Edge brand -> Edge build; Chromium brand -> Chrome build.
        assert f'"Microsoft Edge";v="{edge_full}"' in fvl
        assert f'"Chromium";v="{full_version(147)}"' in fvl
        # Chrome's build must NOT appear on the Microsoft Edge brand.
        assert f'"Microsoft Edge";v="{full_version(147)}"' not in fvl


class TestFingerprintEnvelope:
    """build_fingerprint_envelope() and session.fingerprint_envelope()."""

    def test_chrome_envelope_coherent(self):
        env = build_fingerprint_envelope(
            Emulation.Chrome147, "ua-string"
        )
        assert env["family"] == "chrome"
        assert env["emulation"] == "Profile.Chrome147"
        assert env["user_agent"] == "ua-string"
        assert '"Google Chrome";v="147"' in env["sec_ch_ua"]
        assert env["sec_ch_ua_mobile"] == "?0"
        assert env["user_agent_data"]["mobile"] is False
        assert any(
            b["brand"] == "Google Chrome"
            for b in env["user_agent_data"]["brands"]
        )

    def test_edge_envelope_brand(self):
        env = build_fingerprint_envelope(Emulation.Edge147)
        assert env["family"] == "edge"
        assert '"Microsoft Edge";v="147"' in env["sec_ch_ua"]
        assert any(
            b["brand"] == "Microsoft Edge"
            for b in env["user_agent_data"]["brands"]
        )

    def test_edge_envelope_full_version_list_uses_edge_build(self):
        env = build_fingerprint_envelope(Emulation.Edge147)
        edge_build, edge_patch = _EDGE_BUILDS[147]
        edge_full = f"147.0.{edge_build}.{edge_patch}"
        fvl = env["full_version_list"]
        assert f'"Microsoft Edge";v="{edge_full}"' in fvl
        assert f'"Chromium";v="{full_version(147)}"' in fvl
        # navigator.userAgentData.fullVersionList carries the Edge build too.
        ms = [
            b for b in env["user_agent_data"]["fullVersionList"]
            if b["brand"] == "Microsoft Edge"
        ]
        assert ms and ms[0]["version"] == edge_full

    def test_edge_envelope_ua_carries_real_edge_build(self):
        # The reconstructed Edge UA's Edg/ token uses the real Edge build
        # (wire-verified: wreq emits Edg/147.0.3912.51), not the reduced
        # MAJOR.0.0.0, so it matches the wire and the full-version-list.
        ua = emulation_user_agent(Emulation.Edge147)
        edge_build, edge_patch = _EDGE_BUILDS[147]
        assert f"Edg/147.0.{edge_build}.{edge_patch}" in ua
        assert "Edg/147.0.0.0" not in ua

    def test_opera_envelope_no_client_hints_but_family_opera(self):
        env = build_fingerprint_envelope(Emulation.Opera130)
        assert env["family"] == "opera"
        assert env["sec_ch_ua"] is None
        assert env["full_version_list"] is None
        assert env["user_agent_data"] is None

    def test_firefox_envelope_no_client_hints(self):
        env = build_fingerprint_envelope(Emulation.Firefox149)
        assert env["family"] == "firefox"
        assert env["sec_ch_ua"] is None
        assert env["sec_ch_ua_mobile"] is None
        assert env["sec_ch_ua_platform"] is None
        assert env["full_version_list"] is None
        assert env["platform_version"] is None
        assert env["user_agent_data"] is None

    def test_session_envelope_chrome(self):
        from wafer import SyncSession

        s = SyncSession()
        env = s.fingerprint_envelope()
        assert env["family"] == "chrome"
        assert env["emulation"] == "Profile.Chrome149"
        assert "Chrome/149.0.0.0" in env["user_agent"]
        assert '"149"' in env["sec_ch_ua"]

    def test_session_envelope_firefox(self):
        from wafer import SyncSession

        s = SyncSession(emulation=Emulation.Firefox149)
        env = s.fingerprint_envelope()
        assert env["family"] == "firefox"
        assert env["sec_ch_ua"] is None
        assert "Firefox/149.0" in env["user_agent"]

    def test_session_envelope_edge(self):
        from wafer import SyncSession

        s = SyncSession(emulation=Emulation.Edge147)
        env = s.fingerprint_envelope()
        assert env["family"] == "edge"
        assert '"Microsoft Edge";v="147"' in env["sec_ch_ua"]
        assert "Edg/147" in env["user_agent"]

    def test_session_envelope_uses_user_supplied_ua(self):
        from wafer import SyncSession

        s = SyncSession(headers={"User-Agent": "my-custom-ua"})
        env = s.fingerprint_envelope()
        assert env["user_agent"] == "my-custom-ua"

    def test_public_envelope_exported(self):
        import wafer

        assert wafer.build_fingerprint_envelope is build_fingerprint_envelope
        assert callable(wafer.sec_ch_ua)
        assert callable(wafer.full_version)
        assert callable(wafer.emulation_family)


class TestSessionFamilyHeaders:
    """Session-level per-family header envelope wiring."""

    def test_firefox_session_no_sec_ch_ua(self):
        from wafer import SyncSession

        s = SyncSession(emulation=Emulation.Firefox149)
        headers = s._build_client_kwargs()["headers"]
        assert not any(
            k.lower().startswith("sec-ch-ua") for k in headers
        )
        assert headers["Accept"] == (
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )
        assert headers["Accept-Language"] == "en-US,en;q=0.5"

    def test_edge_session_microsoft_edge_brand(self):
        from wafer import SyncSession

        s = SyncSession(emulation=Emulation.Edge147)
        headers = s._build_client_kwargs()["headers"]
        assert '"Microsoft Edge";v="147"' in headers["sec-ch-ua"]
        # Edge is Chromium, shares Chrome's navigation Accept.
        assert "application/signed-exchange" in headers["Accept"]

    def test_user_headers_override_family_envelope(self):
        from wafer import SyncSession

        # Explicit headers= replaces the family envelope entirely.
        s = SyncSession(
            emulation=Emulation.Firefox149,
            headers={"Accept": "custom/accept"},
        )
        assert s.headers["Accept"] == "custom/accept"

    def test_firefox_session_chrome_headers_are_real_chrome(self):
        # _chrome_headers (restored on a rotation that switches back to a
        # Chrome fingerprint) must be the REAL Chrome navigation envelope,
        # NOT the Firefox envelope the session started with. Otherwise a
        # rotated Chrome TLS fingerprint would send Firefox's Accept /
        # "...;q=0.5" Accept-Language - incoherent.
        from wafer import SyncSession
        from wafer._base import DEFAULT_HEADERS

        s = SyncSession(emulation=Emulation.Firefox149)
        # Session headers are the Firefox envelope...
        assert s.headers["Accept-Language"] == "en-US,en;q=0.5"
        # ...but the Chrome-restore headers are the real Chrome envelope.
        assert s._chrome_headers == DEFAULT_HEADERS
        assert s._chrome_headers is not DEFAULT_HEADERS  # a copy

    def test_edge_session_chrome_headers_are_real_chrome(self):
        from wafer import SyncSession
        from wafer._base import DEFAULT_HEADERS

        s = SyncSession(emulation=Emulation.Edge147)
        assert s._chrome_headers == DEFAULT_HEADERS

    def test_user_headers_preserved_as_chrome_headers(self):
        # When the user passes explicit headers=, the documented full-replace
        # contract wins: those headers are what get restored on rotation too.
        from wafer import SyncSession

        custom = {"Accept": "custom/accept", "X-Mine": "1"}
        s = SyncSession(emulation=Emulation.Firefox149, headers=dict(custom))
        assert s._chrome_headers == custom

    def test_switch_to_chrome_uses_real_chrome_headers(self):
        # End-to-end: a Firefox session that rotates to Chrome must end up
        # with the real Chrome navigation headers, not the Firefox envelope.
        from wafer import SyncSession
        from wafer._base import DEFAULT_HEADERS

        s = SyncSession(emulation=Emulation.Firefox149)
        s._switch_to_chrome()
        assert s.headers == DEFAULT_HEADERS
        assert s.headers["Accept-Language"] == "en-US,en;q=0.9"


class TestMobileProfiles:
    """S5: wreq mobile Emulation profiles (iOS/iPad Safari, Android Firefox)."""

    def test_no_mobile_chromium_profile_in_wreq(self):
        # wreq exposes NO mobile Chromium profile, so wafer never invents one
        # or emits sec-ch-ua-mobile: ?1. If wreq ever adds a "ChromeAndroid"
        # member this guard fails -- wire a mobile CH envelope at that point.
        import re

        chromium_mobile = [
            n
            for n in dir(Emulation)
            if "Chrome" in n
            and re.search(r"Android|Mobile|Ios", n, re.I)
        ]
        assert chromium_mobile == []

    def test_safari_ios_is_mobile(self):
        assert emulation_is_mobile(Emulation.SafariIos26_2) is True

    def test_safari_ipad_is_mobile(self):
        assert emulation_is_mobile(Emulation.SafariIPad26) is True
        assert emulation_is_mobile(Emulation.SafariIpad26_2) is True

    def test_firefox_android_is_mobile(self):
        assert emulation_is_mobile(Emulation.FirefoxAndroid135) is True

    def test_desktop_profiles_not_mobile(self):
        assert emulation_is_mobile(Emulation.Chrome147) is False
        assert emulation_is_mobile(Emulation.Firefox149) is False
        assert emulation_is_mobile(Emulation.Edge147) is False
        assert emulation_is_mobile(Emulation.Safari26_2) is False

    def test_mobile_safari_envelope_no_client_hints(self):
        # Mobile Safari: is_mobile True, no sec-ch-ua (Safari sends none,
        # mobile or not), and no mobile Chromium hint.
        env = build_fingerprint_envelope(Emulation.SafariIos26_2, "ios-ua")
        assert env["is_mobile"] is True
        assert env["family"] == "safari"
        assert env["sec_ch_ua"] is None
        assert env["sec_ch_ua_mobile"] is None
        assert env["user_agent_data"] is None

    def test_mobile_firefox_envelope(self):
        env = build_fingerprint_envelope(
            Emulation.FirefoxAndroid135, "android-ua"
        )
        assert env["is_mobile"] is True
        assert env["family"] == "firefox"
        assert env["sec_ch_ua"] is None

    def test_desktop_envelope_is_mobile_false(self):
        env = build_fingerprint_envelope(Emulation.Chrome147, "ua")
        assert env["is_mobile"] is False
        # Chrome still sends its client hints with mobile: ?0.
        assert env["sec_ch_ua_mobile"] == "?0"

    def test_mobile_safari_session_coherent_envelope(self):
        # A SafariIos session serves the Safari header envelope (short Accept,
        # no zstd, no sec-ch-ua), NOT Chrome's DEFAULT_HEADERS, over the
        # mobile Safari TLS shape. The wrong (Chrome) Accept was the bug.
        from wafer import SyncSession

        s = SyncSession(emulation=Emulation.SafariIos26_2)
        headers = s._build_client_kwargs()["headers"]
        assert headers["Accept"] == (
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )
        assert headers["Accept-Encoding"] == "gzip, deflate, br"  # no zstd
        assert "Cache-Control" not in headers
        assert "Upgrade-Insecure-Requests" not in headers
        assert not any(k.lower().startswith("sec-ch-ua") for k in headers)
        # image/avif is the Chrome tell -- it must NOT leak onto Safari.
        assert "image/avif" not in headers["Accept"]
        env = s.fingerprint_envelope()
        assert env["is_mobile"] is True
        assert env["family"] == "safari"

    def test_mobile_profile_exported(self):
        import wafer

        assert wafer.emulation_is_mobile is emulation_is_mobile


class TestIdentityProfileEnvelopeFamily:
    """fingerprint_envelope() family for non-Emulation identity profiles."""

    def test_dart_envelope_family(self):
        from wafer import Profile, SyncSession

        env = SyncSession(profile=Profile.DART).fingerprint_envelope()
        assert env["family"] == "dart"
        assert env["emulation"] == "dart"
        assert env["sec_ch_ua"] is None

    def test_opera_mini_envelope_family(self):
        from wafer import Profile, SyncSession

        env = SyncSession(profile=Profile.OPERA_MINI).fingerprint_envelope()
        assert env["family"] == "opera_mini"
        assert env["emulation"] == "opera_mini"

    def test_safari_envelope_family(self):
        from wafer import Profile, SyncSession

        env = SyncSession(profile=Profile.SAFARI).fingerprint_envelope()
        assert env["family"] == "safari"


class TestResponseEmulationStamp:
    """resp.emulation reports the serving identity."""

    def test_chrome_response_stamped(self):
        from wafer import SyncSession

        s = SyncSession()
        resp = s._make_response(
            status_code=200,
            headers={},
            url="https://example.com",
            start_time=0.0,
            was_retried=False,
        )
        assert resp.emulation == "Profile.Chrome149"

    def test_firefox_response_stamped(self):
        from wafer import SyncSession

        s = SyncSession(emulation=Emulation.Firefox149)
        resp = s._make_response(
            status_code=200,
            headers={},
            url="https://example.com",
            start_time=0.0,
            was_retried=False,
        )
        assert resp.emulation == "Profile.Firefox149"

    def test_serving_emulation_repr_safari(self):
        from wafer import Profile, SyncSession

        s = SyncSession(profile=Profile.SAFARI)
        assert s._serving_emulation_repr() == "safari"

    def test_serving_emulation_repr_after_safari_rung(self):
        """Default Chrome session rotated onto the ladder's Safari rung
        (_profile is None) still stamps "safari", not None."""
        from wafer import SyncSession

        s = SyncSession()
        s._switch_to_safari()
        assert s._serving_emulation_repr() == "safari"
        env = s.fingerprint_envelope()
        assert env["family"] == "safari"
        assert env["emulation"] == "safari"
