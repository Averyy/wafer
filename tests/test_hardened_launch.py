"""Tests for the exported hardened Chromium launch configuration.

These settings were previously inline in ``_ensure_browser`` and untested. They
are now shared with callers that drive their own Playwright, so a regression
here degrades those callers silently: a site that answers a flagged browser
differently gets recorded as a fact about the site.
"""

from unittest.mock import MagicMock, patch

import pytest

from wafer.browser import (
    BrowserSolver,
    HardenedLaunch,
    hardened_launch_config,
    scrub_headless_ua,
)
from wafer.browser._solver import _HEADLESS_FIX_SCRIPT, _SCREENXY_FIX_SCRIPT

_WEBRTC_ARG = "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"


class TestHeadlessMode:
    def test_uses_new_headless_and_strips_the_old_flag(self):
        config = hardened_launch_config(headless=True, platform="darwin")
        # Old --headless clamps performance.now to 100us, which a timing loop
        # detects. Both halves matter: adding the new flag is useless while
        # Patchright's default old flag survives.
        assert "--headless=new" in config.args
        assert "--headless" in config.ignore_default_args
        assert "--headless" not in config.args

    def test_headed_never_asks_for_headless(self):
        config = hardened_launch_config(headless=False, platform="darwin")
        assert not any(a.startswith("--headless") for a in config.args)
        assert "--headless" not in config.ignore_default_args

    def test_macos_headless_forces_ten_bit_color(self):
        config = hardened_launch_config(headless=True, platform="darwin")
        assert "--force-color-profile=scrgb-linear" in config.args

    def test_non_macos_headless_omits_the_macos_color_profile(self):
        config = hardened_launch_config(headless=True, platform="linux")
        assert "--force-color-profile=scrgb-linear" not in config.args

    def test_linux_headed_starts_maximized(self):
        config = hardened_launch_config(headless=False, platform="linux")
        assert "--start-maximized" in config.args

    def test_linux_headless_does_not_start_maximized(self):
        config = hardened_launch_config(headless=True, platform="linux")
        assert "--start-maximized" not in config.args


class TestAutomationSignals:
    def test_enable_automation_stripped_in_both_modes(self):
        # The single strongest signal: it removes chrome.runtime and sets
        # internal automation state.
        for headless in (True, False):
            config = hardened_launch_config(headless=headless, platform="darwin")
            assert "--enable-automation" in config.ignore_default_args

    def test_playwright_srgb_override_stripped_in_both_modes(self):
        for headless in (True, False):
            config = hardened_launch_config(headless=headless, platform="darwin")
            assert "--force-color-profile=srgb" in config.ignore_default_args

    def test_webdriver_blink_feature_disabled_in_both_modes(self):
        for headless in (True, False):
            config = hardened_launch_config(headless=headless, platform="darwin")
            assert "--disable-blink-features=AutomationControlled" in config.args


class TestGpuBackend:
    def test_macos_selects_metal(self):
        config = hardened_launch_config(headless=True, platform="darwin")
        assert "--use-angle=metal" in config.args

    def test_linux_pins_mesa_opengl(self):
        # Automatic ANGLE selection can resolve to gl=none under Xvfb, which
        # removes WebGL entirely.
        config = hardened_launch_config(headless=True, platform="linux")
        assert "--use-angle=gl" in config.args
        assert "--ignore-gpu-blocklist" in config.args

    def test_gpu_forced_on_every_platform(self):
        for platform in ("darwin", "linux", "win32"):
            config = hardened_launch_config(headless=True, platform=platform)
            assert "--enable-gpu" in config.args
            assert "--use-gl=angle" in config.args


class TestProxyUdpContainment:
    def test_proxied_disables_page_controlled_udp(self):
        config = hardened_launch_config(headless=True, proxied=True, platform="darwin")
        assert "--disable-quic" in config.args
        assert _WEBRTC_ARG in config.args

    def test_direct_launch_fingerprint_stays_unchanged(self):
        # Omitted for direct browsers on purpose: the switches are a fingerprint
        # difference, and there is no proxy for UDP to leak around.
        config = hardened_launch_config(headless=True, proxied=False, platform="darwin")
        assert "--disable-quic" not in config.args
        assert _WEBRTC_ARG not in config.args

    def test_proxied_is_the_only_difference(self):
        direct = hardened_launch_config(headless=True, proxied=False, platform="darwin")
        proxied = hardened_launch_config(headless=True, proxied=True, platform="darwin")
        assert set(proxied.args) - set(direct.args) == {"--disable-quic", _WEBRTC_ARG}
        assert direct.ignore_default_args == proxied.ignore_default_args


class TestInitScripts:
    def test_headless_ships_the_geometry_patch(self):
        config = hardened_launch_config(headless=True, platform="darwin")
        assert _HEADLESS_FIX_SCRIPT in config.init_scripts

    def test_headed_ships_no_scripts(self):
        config = hardened_launch_config(headless=False, platform="darwin")
        assert config.init_scripts == ()

    def test_screenxy_patch_is_never_shipped(self):
        # It is only correct on a Chrome whose event descriptors are already
        # wrong, which wafer establishes with a real-input probe at solve time.
        # Shipping it in a static config double-counts the window offset.
        for headless in (True, False):
            for platform in ("darwin", "linux"):
                config = hardened_launch_config(headless=headless, platform=platform)
                assert _SCREENXY_FIX_SCRIPT not in config.init_scripts


class TestScrubHeadlessUa:
    def test_replaces_the_headless_token(self):
        raw = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) HeadlessChrome/147.0.7727.15 Safari/537.36"
        )
        scrubbed = scrub_headless_ua(raw)
        assert "Headless" not in scrubbed
        assert "Chrome/147.0.7727.15" in scrubbed

    def test_leaves_a_headed_ua_untouched(self):
        raw = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
        )
        assert scrub_headless_ua(raw) == raw

    def test_preserves_the_real_version(self):
        # Composing a UA instead of scrubbing the launched browser's own value
        # is how version skew gets introduced.
        assert "150.0.7871.125" in scrub_headless_ua("HeadlessChrome/150.0.7871.125")

    def test_empty_input_is_returned_unchanged(self):
        assert scrub_headless_ua("") == ""


class TestImmutability:
    def test_config_is_frozen_and_hashable(self):
        config = hardened_launch_config(headless=True, platform="darwin")
        assert isinstance(config, HardenedLaunch)
        # Tuples, so a caller cannot mutate the shared configuration in place.
        assert isinstance(config.args, tuple)
        assert isinstance(config.ignore_default_args, tuple)
        assert isinstance(config.init_scripts, tuple)
        hash(config)

    def test_repeated_calls_agree(self):
        first = hardened_launch_config(headless=True, platform="darwin")
        second = hardened_launch_config(headless=True, platform="darwin")
        assert first == second


class TestSolverUsesTheSharedConfig:
    """The solver must launch with exactly what the exported function returns.

    Without this, the extraction can drift back apart and callers would harden
    against a configuration wafer itself no longer uses.
    """

    def _launch_kwargs(self, *, headless):
        solver = BrowserSolver(headless=headless)
        browser = MagicMock()
        browser.version = "149.0.7827.201"
        # The headless path probes the launched browser for its real UA.
        browser.new_page.return_value.evaluate.return_value = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) HeadlessChrome/149.0.7827.201 Safari/537.36"
        )
        playwright = MagicMock()
        playwright.chromium.launch.return_value = browser
        try:
            with (
                patch("patchright.sync_api.sync_playwright") as sync_playwright,
                patch.object(solver, "_ensure_browser_installed"),
                patch.object(
                    solver, "_expected_browser_version", return_value="149.0.7827.201"
                ),
                patch.object(solver, "_browser_executable", return_value="/bin/chrome"),
            ):
                sync_playwright.return_value.start.return_value = playwright
                solver._ensure_browser()
            return playwright.chromium.launch.call_args.kwargs
        finally:
            solver.close()

    def test_missing_user_agent_fails_loudly(self):
        # A headless browser whose UA cannot be read would otherwise leave
        # _browser_ua unset, _create_context would skip the override, and every
        # request would carry "HeadlessChrome". Louder is safer than silent.
        solver = BrowserSolver(headless=True)
        browser = MagicMock()
        browser.version = "149.0.7827.201"
        browser.new_page.return_value.evaluate.return_value = None
        playwright = MagicMock()
        playwright.chromium.launch.return_value = browser
        try:
            with (
                patch("patchright.sync_api.sync_playwright") as sync_playwright,
                patch.object(solver, "_ensure_browser_installed"),
                patch.object(
                    solver, "_expected_browser_version", return_value="149.0.7827.201"
                ),
                patch.object(solver, "_browser_executable", return_value="/bin/chrome"),
            ):
                sync_playwright.return_value.start.return_value = playwright
                with pytest.raises(RuntimeError, match="did not report a user agent"):
                    solver._ensure_browser()
        finally:
            solver.close()

    def test_headed_launch_matches_exported_config(self):
        kwargs = self._launch_kwargs(headless=False)
        expected = hardened_launch_config(headless=False)
        assert list(kwargs["args"]) == list(expected.args)
        assert list(kwargs["ignore_default_args"]) == list(expected.ignore_default_args)

    def test_headless_launch_matches_exported_config(self):
        kwargs = self._launch_kwargs(headless=True)
        expected = hardened_launch_config(headless=True)
        assert list(kwargs["args"]) == list(expected.args)
        assert list(kwargs["ignore_default_args"]) == list(expected.ignore_default_args)
