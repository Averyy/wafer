"""Tests for fingerprint management and sec-ch-ua generation."""

from rnet import Emulation

from wafer._fingerprint import (
    CHROME_PROFILES,
    FingerprintManager,
    chrome_version,
    generate_sec_ch_ua,
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
        assert len(CHROME_PROFILES) == 37

    def test_newest_first(self):
        versions = [v for v, _ in CHROME_PROFILES]
        assert versions[0] == 145
        assert versions == sorted(versions, reverse=True)


class TestFingerprintManager:
    def test_defaults_to_newest_chrome(self):
        fm = FingerprintManager()
        assert fm.current == Emulation.Chrome145

    def test_custom_initial(self):
        fm = FingerprintManager(initial=Emulation.Chrome130)
        assert fm.current == Emulation.Chrome130

    def test_rotation_changes_profile(self):
        fm = FingerprintManager(initial=Emulation.Chrome145)
        original = fm.current
        fm.rotate()
        assert fm.current != original

    def test_rotation_cycles_through_profiles(self):
        fm = FingerprintManager(initial=Emulation.Chrome145)
        seen = {repr(fm.current)}
        for _ in range(36):  # 37 total profiles - 1 initial
            fm.rotate()
            seen.add(repr(fm.current))
        # Should have visited all 37 Chrome profiles
        assert len(seen) == 37

    def test_pinning_prevents_rotation(self):
        fm = FingerprintManager(initial=Emulation.Chrome145)
        fm.pin()
        assert fm.pinned
        fm.rotate()
        assert fm.current == Emulation.Chrome145

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
        assert fm.current == Emulation.Chrome145  # resets to newest

    def test_reset_with_custom_emulation(self):
        fm = FingerprintManager()
        fm.reset(emulation=Emulation.Chrome130)
        assert fm.current == Emulation.Chrome130
        assert not fm.pinned

    def test_sec_ch_ua_headers_for_chrome(self):
        fm = FingerprintManager(initial=Emulation.Chrome145)
        headers = fm.sec_ch_ua_headers()
        assert "sec-ch-ua" in headers
        assert "sec-ch-ua-mobile" in headers
        assert "sec-ch-ua-platform" in headers
        assert '"145"' in headers["sec-ch-ua"]
        assert headers["sec-ch-ua-mobile"] == "?0"

    def test_sec_ch_ua_updates_after_rotation(self):
        fm = FingerprintManager(initial=Emulation.Chrome145)
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
        assert s.emulation == Emulation.Chrome145

    def test_session_sends_sec_ch_ua(self):
        from wafer import SyncSession

        s = SyncSession()
        resp = s.get("https://httpbin.org/headers")
        data = resp.json()
        headers = data["headers"]
        assert "Sec-Ch-Ua" in headers
        assert '"145"' in headers["Sec-Ch-Ua"]

    def test_session_rebuild_changes_emulation(self):
        from wafer import SyncSession

        s = SyncSession()
        assert s.emulation == Emulation.Chrome145
        s._fingerprint.rotate()
        s._rebuild_client()
        assert s.emulation != Emulation.Chrome145

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
        assert '"145"' in client_kwargs["headers"]["sec-ch-ua"]
        # Per-request delta should NOT include sec-ch-ua (already correct)
        built = s._build_headers("https://example.com")
        assert "sec-ch-ua" not in built
