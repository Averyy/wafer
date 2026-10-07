"""Tests for the exported hardened Chromium launch configuration.

These settings were previously inline in ``_ensure_browser`` and untested. They
are now shared with callers that drive their own Playwright, so a regression
here degrades those callers silently: a site that answers a flagged browser
differently gets recorded as a fact about the site.
"""

import json
import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from wafer.browser import (
    BrowserSolver,
    HardenedLaunch,
    hardened_driver_env,
    hardened_launch_config,
    scrub_headless_ua,
)
from wafer.browser._solver import (
    _DRIVER_PRELOAD,
    _HEADLESS_FIX_SCRIPT,
    _OFFLINE_ARGS,
    _SCREENXY_FIX_SCRIPT,
)

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

    @pytest.mark.parametrize("headless", [True, False])
    @pytest.mark.parametrize("platform", ["darwin", "linux", "win32"])
    def test_updater_scheduler_disabled_everywhere(self, platform, headless):
        # Chrome's 19s updater wake held Playwright's stdio pipes open and made
        # every later close take 17-26s (Chromium issue 481087595).
        config = hardened_launch_config(headless=headless, platform=platform)
        assert "--disable-updater-scheduler" in config.args


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


class TestHeadlessUserAgentSwitch:
    """Chrome builds "HeadlessChrome" into its default UA from --headless.

    That default reaches every target no CDP session overrides before it runs:
    a service worker's script fetch and navigator.userAgent, and all of a
    shared worker. Only the command line reaches those.
    """

    def test_headless_puts_the_scrubbed_ua_on_the_command_line(self):
        raw = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) HeadlessChrome/154.0.0.0 Safari/537.36"
        )
        config = hardened_launch_config(
            headless=True, platform="darwin", user_agent=raw
        )
        assert f"--user-agent={raw.replace('HeadlessChrome', 'Chrome')}" in config.args
        assert not any("HeadlessChrome" in a for a in config.args)

    def test_headed_never_overrides_the_ua(self):
        # Headed Chrome's own UA is right, and a command-line UA makes Chrome
        # send only low-entropy client hints by default.
        config = hardened_launch_config(
            headless=False, platform="darwin", user_agent="Mozilla/5.0 Chrome/154"
        )
        assert not any(a.startswith("--user-agent") for a in config.args)

    def test_no_ua_means_no_switch(self):
        config = hardened_launch_config(headless=True, platform="darwin")
        assert not any(a.startswith("--user-agent") for a in config.args)

    def test_the_ua_is_the_only_difference(self):
        plain = hardened_launch_config(headless=True, platform="darwin")
        with_ua = hardened_launch_config(
            headless=True, platform="darwin", user_agent="Mozilla/5.0 Chrome/154"
        )
        assert set(with_ua.args) - set(plain.args) == {
            "--user-agent=Mozilla/5.0 Chrome/154"
        }
        assert plain.init_scripts == with_ua.init_scripts


class TestDeviceScaleFactor:
    def test_macos_headless_forces_retina(self):
        # Playwright's device_scale_factor reaches only the top frame: without
        # this a cross-site iframe reports devicePixelRatio 1 under a top
        # document reporting 2, measured on Chrome 154.
        config = hardened_launch_config(headless=True, platform="darwin")
        assert "--force-device-scale-factor=2" in config.args

    def test_headed_keeps_the_display_ratio(self):
        config = hardened_launch_config(headless=False, platform="darwin")
        assert not any(a.startswith("--force-device-scale-factor") for a in config.args)

    def test_other_platforms_keep_the_default_ratio(self):
        for platform in ("linux", "win32"):
            config = hardened_launch_config(headless=True, platform=platform)
            assert not any(
                a.startswith("--force-device-scale-factor") for a in config.args
            )


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


_RAW_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) HeadlessChrome/149.0.0.0 Safari/537.36"
)
_SCRUBBED_UA = _RAW_UA.replace("HeadlessChrome", "Chrome")


def _browser_reporting(ua):
    browser = MagicMock()
    browser.version = "149.0.7827.201"
    browser.new_page.return_value.evaluate.return_value = ua
    return browser


class TestSolverUsesTheSharedConfig:
    """The solver must launch with exactly what the exported function returns.

    Without this, the extraction can drift back apart and callers would harden
    against a configuration wafer itself no longer uses.
    """

    def _launch(self, *, headless, browsers, known_ua=None):
        solver = BrowserSolver(headless=headless)
        solver._browser_ua = known_ua
        playwright = MagicMock()
        playwright.chromium.launch.side_effect = browsers
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
        return solver, playwright.chromium.launch.call_args_list

    def test_missing_user_agent_fails_loudly(self):
        # A headless browser whose UA cannot be read leaves nothing to put on
        # the command line, and every target would carry "HeadlessChrome".
        solver = BrowserSolver(headless=True)
        playwright = MagicMock()
        playwright.chromium.launch.return_value = _browser_reporting(None)
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
        solver, launches = self._launch(
            headless=False, browsers=[_browser_reporting(_SCRUBBED_UA)]
        )
        try:
            expected = hardened_launch_config(headless=False)
            assert len(launches) == 1
            kwargs = launches[0].kwargs
            assert list(kwargs["args"]) == list(expected.args)
            assert list(kwargs["ignore_default_args"]) == list(
                expected.ignore_default_args
            )
        finally:
            solver.close()

    def test_headless_reads_the_ua_then_relaunches_with_it(self):
        # Chrome builds "HeadlessChrome" into its own default UA, which service
        # and shared workers read before any CDP session can change it. Only
        # the command line reaches them, so the solver reads the real UA from
        # a first launch and relaunches with it scrubbed.
        first = _browser_reporting(_RAW_UA)
        final = _browser_reporting(_SCRUBBED_UA)
        solver, launches = self._launch(headless=True, browsers=[first, final])
        try:
            assert len(launches) == 2
            # The first launch only reads the UA, so it gets no network: its
            # background traffic would otherwise carry HeadlessChrome.
            # Both launches open the solver's one window size.
            viewport = solver._solver_viewport()
            assert list(launches[0].kwargs["args"]) == list(
                hardened_launch_config(headless=True, viewport=viewport).args
            ) + _OFFLINE_ARGS
            expected = hardened_launch_config(
                headless=True, user_agent=_SCRUBBED_UA, viewport=viewport
            )
            assert list(launches[1].kwargs["args"]) == list(expected.args)
            assert list(launches[1].kwargs["ignore_default_args"]) == list(
                expected.ignore_default_args
            )
            first.close.assert_called_once()
            assert solver._browser_ua == _SCRUBBED_UA
        finally:
            solver.close()

    def test_only_the_working_launch_uses_the_proxy(self):
        first = _browser_reporting(_RAW_UA)
        final = _browser_reporting(_SCRUBBED_UA)
        solver = BrowserSolver(headless=True, proxy="http://127.0.0.1:8080")
        playwright = MagicMock()
        playwright.chromium.launch.side_effect = [first, final]
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
            probe, working = playwright.chromium.launch.call_args_list
            assert "proxy" not in probe.kwargs
            assert "--proxy-server=http://127.0.0.1:9" in probe.kwargs["args"]
            assert working.kwargs["proxy"]["server"].endswith("127.0.0.1:8080")
            assert not any(a in working.kwargs["args"] for a in _OFFLINE_ARGS)
        finally:
            solver.close()

    def test_idle_relaunch_reuses_the_known_ua(self):
        final = _browser_reporting(_SCRUBBED_UA)
        solver, launches = self._launch(
            headless=True, browsers=[final], known_ua=_SCRUBBED_UA
        )
        try:
            assert len(launches) == 1
            assert f"--user-agent={_SCRUBBED_UA}" in launches[0].kwargs["args"]
        finally:
            solver.close()

    def test_relaunch_that_still_says_headless_fails_loudly(self):
        # The switch not taking would leave every target the page session
        # cannot reach announcing HeadlessChrome. Louder is safer than silent.
        solver = BrowserSolver(headless=True)
        playwright = MagicMock()
        playwright.chromium.launch.side_effect = [
            _browser_reporting(_RAW_UA),
            _browser_reporting(_RAW_UA),
        ]
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
                with pytest.raises(RuntimeError, match="HeadlessChrome"):
                    solver._ensure_browser()
        finally:
            solver.close()

    def test_headless_pages_harden_workers_on_the_solver_browser(self):
        # Service and shared workers are hardened from page setup, through the
        # browser the solver launched.
        solver = BrowserSolver(headless=True)
        solver._browser = MagicMock()
        solver._browser_ua = _SCRUBBED_UA
        solver._browser_version = "149.0.7827.201"
        page = MagicMock()
        page._wafer_headless_patched = False
        page.viewport_size = {"width": 1440, "height": 900}
        try:
            solver._setup_headless_patches(page)
            solver._browser.new_browser_cdp_session.assert_called_once()
            # The page's own session plus the service-worker holder.
            assert page.context.new_cdp_session.call_count == 2
        finally:
            solver._browser = None
            solver.close()

    def test_headed_launch_opens_no_browser_session(self):
        # Headed Chrome's own identity is already right everywhere.
        browser = _browser_reporting(_SCRUBBED_UA)
        solver, _ = self._launch(headless=False, browsers=[browser])
        try:
            browser.new_browser_cdp_session.assert_not_called()
        finally:
            solver.close()

    @pytest.mark.parametrize("headless", [True, False])
    def test_contexts_carry_no_user_agent(self, headless):
        # Playwright attaches its own metadata to a context-level UA, and
        # cross-site iframes then report architecture x86 and platformVersion
        # 10.15.7 whatever the host.
        solver = BrowserSolver(headless=headless)
        solver._browser = MagicMock()
        solver._browser_ua = _SCRUBBED_UA
        try:
            solver._create_context()
            assert "user_agent" not in solver._browser.new_context.call_args.kwargs
        finally:
            solver._browser = None
            solver.close()

    def test_the_probe_browser_disconnecting_late_leaves_the_solver_ready(self):
        first = _browser_reporting(_RAW_UA)
        final = _browser_reporting(_SCRUBBED_UA)
        solver, _ = self._launch(headless=True, browsers=[first, final])
        try:
            assert solver._runtime_ready.is_set()
            handler = next(
                c.args[1]
                for c in first.on.call_args_list
                if c.args[0] == "disconnected"
            )
            handler()
            assert solver._runtime_ready.is_set()
            current = next(
                c.args[1]
                for c in final.on.call_args_list
                if c.args[0] == "disconnected"
            )
            current()
            assert not solver._runtime_ready.is_set()
        finally:
            solver.close()

    def test_a_failed_post_launch_check_closes_the_browser(self):
        # Left open, the next call would find it connected and skip the
        # UA verification and shared-worker hardening for good.
        final = _browser_reporting(_SCRUBBED_UA)
        final.new_page.return_value.evaluate.side_effect = RuntimeError("crashed")
        solver = BrowserSolver(headless=True)
        solver._browser_ua = _SCRUBBED_UA
        playwright = MagicMock()
        playwright.chromium.launch.side_effect = [final]
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
                with pytest.raises(RuntimeError, match="crashed"):
                    solver._ensure_browser()
            assert solver._browser is None
            final.close.assert_called()
        finally:
            solver.close()

    def test_the_driver_starts_with_the_shared_worker_preload(self):
        # Started without it, Playwright resumes every new shared worker
        # ahead of wafer's override (15-17 of 100 wrong for a blob: worker).
        seen = []
        solver = BrowserSolver(headless=False)
        playwright = MagicMock()
        playwright.chromium.launch.side_effect = [_browser_reporting(_SCRUBBED_UA)]

        def start():
            seen.append(os.environ.get("NODE_OPTIONS", ""))
            return playwright

        try:
            with (
                patch("patchright.sync_api.sync_playwright") as sync_playwright,
                patch.object(solver, "_ensure_browser_installed"),
                patch.object(
                    solver, "_expected_browser_version", return_value="149.0.7827.201"
                ),
                patch.object(solver, "_browser_executable", return_value="/bin/chrome"),
            ):
                sync_playwright.return_value.start.side_effect = start
                solver._ensure_browser()
        finally:
            solver.close()
        assert len(seen) == 1 and _DRIVER_PRELOAD in seen[0]


class TestHardenedDriverEnv:
    """The driver preload that leaves shared workers to wafer."""

    def test_sets_node_options_for_the_block_only(self, monkeypatch):
        monkeypatch.delenv("NODE_OPTIONS", raising=False)
        with hardened_driver_env():
            assert os.environ["NODE_OPTIONS"] == f'--require "{_DRIVER_PRELOAD}"'
        assert "NODE_OPTIONS" not in os.environ

    def test_keeps_the_callers_node_options(self, monkeypatch):
        monkeypatch.setenv("NODE_OPTIONS", "--max-old-space-size=4096")
        with hardened_driver_env():
            assert os.environ["NODE_OPTIONS"] == (
                f'--max-old-space-size=4096 --require "{_DRIVER_PRELOAD}"'
            )
        assert os.environ["NODE_OPTIONS"] == "--max-old-space-size=4096"

    def test_restored_when_the_start_fails(self, monkeypatch):
        monkeypatch.delenv("NODE_OPTIONS", raising=False)
        with pytest.raises(RuntimeError), hardened_driver_env():
            raise RuntimeError("driver failed")
        assert "NODE_OPTIONS" not in os.environ

    def test_the_preload_is_shipped_in_the_package(self):
        assert os.path.isfile(_DRIVER_PRELOAD)

    def test_names_the_override_file_for_the_block_only(self, monkeypatch):
        from wafer.browser._solver import _ua_params_file

        monkeypatch.delenv("WAFER_UA_PARAMS", raising=False)
        with hardened_driver_env():
            assert os.environ["WAFER_UA_PARAMS"] == _ua_params_file()
        assert "WAFER_UA_PARAMS" not in os.environ

    def test_published_overrides_are_keyed_by_browser_user_agent(self, monkeypatch):
        from wafer.browser import _solver

        monkeypatch.setattr(_solver, "_UA_TABLE", {})
        params = {"userAgent": "UA", "userAgentMetadata": {"architecture": "arm"}}
        _solver._publish_ua_override("BROWSER-UA", params)
        _solver._publish_ua_override(None, params)
        _solver._publish_ua_override("OTHER", None)
        with open(_solver._ua_params_file()) as handle:
            assert json.load(handle) == {"BROWSER-UA": params}
        assert oct(os.stat(_solver._ua_params_file()).st_mode & 0o777) == "0o600"

    def test_the_installed_driver_is_patched(self):
        # Runs the driver's own node and its real crConnection.js, so a
        # Patchright upgrade that moves or renames what the preload patches
        # fails here instead of silently restoring the race.
        pytest.importorskip("patchright")
        from patchright._impl._driver import compute_driver_executable

        node, cli = compute_driver_executable()
        connection = os.path.join(
            os.path.dirname(cli), "lib", "server", "chromium", "crConnection.js"
        )
        if not (os.path.isfile(node) and os.path.isfile(connection)):
            pytest.skip("Patchright driver files not found")
        script = (
            "const {CRConnection} = require(%s);"
            "const sent = [];"
            "const c = Object.create(CRConnection.prototype);"
            "c._lastId = 0; c._protocolLogger = () => {};"
            "c._transport = {send: m => sent.push(m)};"
            "c._rawSend('', 'Target.setAutoAttach',"
            " {autoAttach: true, waitForDebuggerOnStart: true, flatten: true});"
            "c._rawSend('S1', 'Target.setAutoAttach',"
            " {autoAttach: true, waitForDebuggerOnStart: true, flatten: true});"
            "process.stdout.write(JSON.stringify(sent));"
        ) % json.dumps(connection)
        result = subprocess.run(
            [node, "--require", _DRIVER_PRELOAD, "-e", script],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        root, page = json.loads(result.stdout)
        assert root["params"]["filter"] == [
            {"type": "shared_worker", "exclude": True},
            {"type": "browser", "exclude": True},
            {"type": "tab", "exclude": True},
            {},
        ]
        assert root["params"]["waitForDebuggerOnStart"] is True
        # Page sessions keep Playwright's own auto-attach untouched.
        assert "filter" not in page["params"]

    def test_the_installed_driver_gives_new_pages_wafers_override(self, tmp_path):
        # A popup's first document ran with empty high-entropy hints: the
        # driver resumes it before wafer can reach it. Its page session now
        # gets wafer's published override right before that resume.
        pytest.importorskip("patchright")
        from patchright._impl._driver import compute_driver_executable

        node, cli = compute_driver_executable()
        connection = os.path.join(
            os.path.dirname(cli), "lib", "server", "chromium", "crConnection.js"
        )
        if not (os.path.isfile(node) and os.path.isfile(connection)):
            pytest.skip("Patchright driver files not found")
        override = {"userAgent": "UA", "userAgentMetadata": {"architecture": "arm"}}
        table = tmp_path / "ua.json"
        table.write_text(json.dumps({"BROWSER-UA": override}))
        script = (
            "const {CRSession} = require(%s);"
            "const sent = [];"
            "const conn = {_lastId: 0, _closed: false, _sessions: new Map(),"
            " _rawSend(sid, method, params) { sent.push([sid, method, params]);"
            " return ++this._lastId; }};"
            "function session(id) { const s = Object.create(CRSession.prototype);"
            " s._connection = conn; s._sessionId = id; s._callbacks = new Map();"
            " s._crashed = false; s._closed = false; return s; }"
            "const root = session('');"
            "const version = root.send('Browser.getVersion');"
            "root._onMessage({id: 1, result: {userAgent: 'BROWSER-UA'}});"
            "version.then(async () => {"
            " const page = session('P');"
            " page.send('Page.enable'); page.send('Runtime.runIfWaitingForDebugger');"
            " const own = session('C');"
            " own.send('Page.enable');"
            " own.send('Emulation.setUserAgentOverride', {userAgent: 'CTX'});"
            " own.send('Runtime.runIfWaitingForDebugger');"
            " const worker = session('W');"
            " worker.send('Runtime.runIfWaitingForDebugger');"
            " process.stdout.write(JSON.stringify(sent));"
            "});"
        ) % json.dumps(connection)
        env = dict(os.environ, WAFER_UA_PARAMS=str(table))
        result = subprocess.run(
            [node, "--require", _DRIVER_PRELOAD, "-e", script],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        by_session = {}
        for sid, method, params in json.loads(result.stdout):
            by_session.setdefault(sid, []).append((method, params))
        assert by_session["P"] == [
            ("Page.enable", None),
            ("Emulation.setUserAgentOverride", override),
            ("Runtime.runIfWaitingForDebugger", None),
        ]
        # A context's own user agent, and a worker, are left as they were.
        assert [m for m, _ in by_session["C"]] == [
            "Page.enable",
            "Emulation.setUserAgentOverride",
            "Runtime.runIfWaitingForDebugger",
        ]
        assert by_session["C"][1][1] == {"userAgent": "CTX"}
        assert by_session["W"] == [("Runtime.runIfWaitingForDebugger", None)]


class TestRealDisplay:
    """Headless macOS describes the Mac's real display to Chrome natively."""

    def test_parses_appkit_screen_geometry(self):
        from wafer.browser._solver import _MacScreen, _parse_mac_screen

        # This Mac: 1710x1107 points, a 34pt menu bar, a 55pt Dock below.
        output = "[1710, 1107, 0, 55, 1710, 1018, 2, true]"
        assert _parse_mac_screen(output) == _MacScreen(
            1710, 1107, 34, 55, 0, 0, 2, 30
        )

    def test_a_dock_on_the_side_and_an_srgb_display(self):
        from wafer.browser._solver import _parse_mac_screen

        screen = _parse_mac_screen("[1440, 900, 64, 0, 1376, 875, 1, false]")
        assert (screen.left, screen.right, screen.top, screen.bottom) == (64, 0, 25, 0)
        assert screen.color_depth == 24 and screen.scale == 1

    def test_garbage_is_rejected(self):
        from wafer.browser._solver import _parse_mac_screen

        assert _parse_mac_screen("") is None
        assert _parse_mac_screen("[0, 0, 0, 0, 0, 0, 2, true]") is None
        assert _parse_mac_screen("[1440, 900, 0, 0, 1500, 900, 2, true]") is None

    def test_screen_info_is_in_device_pixels(self):
        from wafer.browser._solver import _MacScreen, _screen_info_switch

        switch = _screen_info_switch(_MacScreen(1710, 1107, 34, 55, 0, 0, 2, 30))
        assert switch == (
            "--screen-info={0,0 3420x2214 colorDepth=30 workAreaTop=68 "
            "workAreaBottom=110 workAreaLeft=0 workAreaRight=0}"
        )

    def test_default_window_is_the_largest_that_fits(self):
        from wafer.browser._solver import (
            _default_viewport,
            _fitting_viewports,
            _MacScreen,
        )

        screen = _MacScreen(1710, 1107, 34, 55, 0, 0, 2, 30)
        fitting = _fitting_viewports(screen)
        assert (1920, 1080) not in fitting
        assert all(h + 87 <= 1018 and w <= 1710 for w, h in fitting)
        assert _default_viewport(screen) == (1536, 864)

    def test_launch_flags_on_a_mac(self, monkeypatch):
        from wafer.browser import _solver
        from wafer.browser._solver import _MacScreen

        monkeypatch.setattr(_solver.sys, "platform", "darwin")
        monkeypatch.setattr(
            _solver, "_host_screen", lambda: _MacScreen(1710, 1107, 34, 55, 0, 0, 2, 30)
        )
        args = hardened_launch_config(headless=True, viewport=(1440, 900)).args
        assert "--force-device-scale-factor=2" in args
        assert "--window-size=1440,987" in args
        screen_info = "--screen-info={0,0 3420x2214 colorDepth=30"
        assert any(a.startswith(screen_info) for a in args)

    def test_headed_and_other_platforms_get_none_of_it(self):
        for config in (
            hardened_launch_config(headless=False, platform="darwin"),
            hardened_launch_config(headless=True, platform="linux"),
        ):
            assert not any(
                a.startswith(("--screen-info", "--window-size")) for a in config.args
            )

    def test_an_unreadable_display_falls_back(self, monkeypatch):
        from wafer.browser import _solver

        monkeypatch.setattr(_solver, "_HOST_SCREEN", [])
        def fail(*args, **kwargs):
            raise OSError("no osascript")

        monkeypatch.setattr(_solver.subprocess, "run", fail)
        assert _solver._host_screen() == _solver._DEFAULT_MAC_SCREEN

    def test_headless_mac_contexts_use_the_native_window(self, monkeypatch):
        from wafer.browser import _solver

        monkeypatch.setattr(_solver.sys, "platform", "darwin")
        solver = BrowserSolver(headless=True)
        solver._browser = MagicMock()
        try:
            solver._create_context()
            kwargs = solver._browser.new_context.call_args.kwargs
            assert kwargs == {"no_viewport": True}
        finally:
            solver._browser = None
            solver.close()

    def test_one_window_size_per_solver(self, monkeypatch):
        from wafer.browser import _solver
        from wafer.browser._solver import _MacScreen

        monkeypatch.setattr(_solver.sys, "platform", "darwin")
        monkeypatch.setattr(
            _solver, "_host_screen", lambda: _MacScreen(1710, 1107, 34, 55, 0, 0, 2, 30)
        )
        solver = BrowserSolver(headless=True)
        try:
            first = solver._solver_viewport()
            assert all(solver._solver_viewport() == first for _ in range(10))
            assert first in _solver._fitting_viewports(_solver._host_screen())
        finally:
            solver.close()
