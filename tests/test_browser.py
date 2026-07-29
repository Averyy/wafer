"""Tests for browser-based challenge solving and iframe interception."""

import asyncio
import hashlib
import json
import logging
import math
import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, MagicMock, PropertyMock, call, patch

import pytest
from wreq import Emulation

from tests.conftest import (
    MockResponse,
    make_async_session,
    make_sync_session,
)
from wafer._base import BaseSession
from wafer._challenge import ChallengeType
from wafer._errors import (
    ChallengeDetected,
    ConnectionFailed,
    ResponseTooLarge,
    WaferTimeout,
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
    preflight_recaptcha_models,
    preload_recaptcha_models,
)
from wafer.browser._solver import (
    _angle_from_metadata,
    _parse_csv_rows,
    _parse_metadata,
    _playwright_proxy,
)

# ---------------------------------------------------------------------------
# Local mock (browser-specific, not shared)
# ---------------------------------------------------------------------------


class MockBrowserSolver:
    """Mock BrowserSolver that returns predefined results."""

    def __init__(self, result=None, *, results=None):
        if results is not None and result is not None:
            raise ValueError("provide result or results, not both")
        self._result = result
        self._results = list(results) if results is not None else None
        self.solve_calls = []
        # Full per-call kwargs (url, challenge_type, embedder, replay) so
        # tests can assert solve_origin / embedder threading.
        self.solve_kwargs = []

    def solve(
        self,
        url,
        challenge_type=None,
        timeout=None,
        embedder=None,
        replay=None,
        max_size=None,
    ):
        self.solve_calls.append((url, challenge_type))
        self.solve_kwargs.append(
            {
                "url": url,
                "challenge_type": challenge_type,
                "timeout": timeout,
                "embedder": embedder,
                "replay": replay,
                "max_size": max_size,
            }
        )
        if self._results is not None:
            if not self._results:
                raise AssertionError("browser solver called more times than expected")
            return self._results.pop(0)
        return self._result

    async def asolve(self, *args, **kwargs):
        return self.solve(*args, **kwargs)

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

    def test_host_only_cookie_omits_domain_attribute(self):
        result = format_cookie_str(
            {
                "name": "sid",
                "value": "host",
                "domain": "api.example.com",
                "path": "/",
            }
        )

        assert result == "sid=host; Path=/"


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
        assert repr(em) == "Profile.Chrome145"

    def test_known_version_100(self):
        em = emulation_for_version(100)
        assert em is not None
        assert repr(em) == "Profile.Chrome100"

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
        assert solver._executable_path is None
        assert solver.runtime_ready is False

    def test_custom_params(self):
        solver = BrowserSolver(headless=True, idle_timeout=60, solve_timeout=15)
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

    def test_preflight_captures_headed_identity_and_close_clears_it(self):
        solver = BrowserSolver()
        browser = MagicMock()
        browser.is_connected.return_value = True
        context = MagicMock()
        page = MagicMock()
        user_agent = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "Chrome/150.0.0.0 Safari/537.36"
        )
        browser.new_context.return_value = context
        context.new_page.return_value = page
        page.evaluate.return_value = user_agent
        solver._browser = browser
        solver._browser_version = "150.0.7871.125"
        solver._needs_screenxy_patch = False
        try:
            solver._preflight_on_worker()
            assert solver.browser_identity == (user_agent, "150.0.7871.125")
            assert solver.runtime_ready is True
            context.close.assert_called_once()

            solver._close_browser()
            assert solver.browser_identity is None
            assert solver.runtime_ready is False
        finally:
            solver.close()

    @pytest.mark.parametrize(
        ("observed", "needs_patch"),
        [
            (
                {
                    "clientX": 100,
                    "clientY": 100,
                    "screenX": 110,
                    "screenY": 214,
                    "windowX": 10,
                    "windowY": 27,
                    "chromeY": 87,
                },
                False,
            ),
            (
                {
                    "clientX": 100,
                    "clientY": 100,
                    "screenX": 100,
                    "screenY": 100,
                    "windowX": 10,
                    "windowY": 27,
                    "chromeY": 87,
                },
                True,
            ),
        ],
    )
    def test_screenxy_probe_uses_real_input_result(self, observed, needs_patch):
        solver = BrowserSolver()
        context = MagicMock()
        page = MagicMock()
        context.new_page.return_value = page
        page.evaluate.side_effect = [None, observed]
        try:
            with patch.object(solver, "_create_context", return_value=context):
                solver._probe_screenxy_patch()
            page.mouse.click.assert_called_once_with(100, 100)
            assert "<script" not in page.set_content.call_args.args[0]
            assert "addEventListener" in page.evaluate.call_args_list[0].args[0]
            assert solver._needs_screenxy_patch is needs_patch
            context.close.assert_called_once()
        finally:
            solver.close()

    def test_inconclusive_screenxy_probe_does_not_disable_the_solver(self, caplog):
        """An unexplained geometry must not be fatal.

        These are the real values from headless Chrome 150 on macOS: the event
        screenY carries an offset that window.screenY/outerHeight do not
        account for, matching neither the broken nor the native shape. Raising
        here took down preflight and every solve. The coordinates are still
        offset from the client origin, so the correct fallback is to leave
        them alone -- the compatibility script is a toString-visible override
        that only a positive probe may authorize.
        """
        observed = {
            "clientX": 100,
            "clientY": 100,
            "screenX": 122,
            "screenY": 209,
            "windowX": 22,
            "windowY": 22,
            "chromeY": 0,
        }
        solver = BrowserSolver()
        context = MagicMock()
        page = MagicMock()
        context.new_page.return_value = page
        page.evaluate.side_effect = [None, observed]
        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                caplog.at_level(logging.WARNING, logger="wafer"),
            ):
                solver._probe_screenxy_patch()
            assert solver._needs_screenxy_patch is False
            assert "inconclusive" in caplog.text
            context.close.assert_called_once()
        finally:
            solver.close()

    @pytest.mark.parametrize("needs_patch", [False, True])
    def test_screenxy_init_script_is_only_injected_for_proven_bug(self, needs_patch):
        solver = BrowserSolver()
        solver._needs_screenxy_patch = needs_patch
        solver._browser_ua = "Mozilla/5.0 Chrome/149.0.0.0 Safari/537.36"
        solver._browser_version = "149.0.7827.155"
        page = MagicMock()
        page._wafer_headless_patched = False
        cdp = MagicMock()
        page.context.new_cdp_session.return_value = cdp
        try:
            solver._setup_headless_patches(page)
            methods = [call.args[0] for call in cdp.send.call_args_list]
            assert ("Page.addScriptToEvaluateOnNewDocument" in methods) is needs_patch
        finally:
            solver.close()

    def test_cross_origin_screenxy_patch_is_a_noop_when_native_is_correct(self):
        frame = MagicMock()
        from wafer.browser._solver import patch_frame_screenxy

        patch_frame_screenxy(frame, needs_patch=False)
        frame.evaluate.assert_not_called()

    def test_browser_identity_snapshot_pins_while_solver_lock_is_held(self):
        solver = BrowserSolver()
        solver._browser_ua = "Mozilla/5.0 Chrome/150.0.0.0 Safari/537.36"
        solver._browser_version = "150.0.7871.125"
        solver._publish_browser_identity()
        locked = threading.Event()
        release = threading.Event()

        def hold_solver_lock():
            with solver._lock:
                locked.set()
                release.wait(timeout=2)

        holder = threading.Thread(target=hold_solver_lock)
        holder.start()
        assert locked.wait(timeout=1)
        try:
            start = time.monotonic()
            session = BaseSession(browser_solver=solver)
            assert time.monotonic() - start < 0.2
            assert session._fingerprint.pinned is True
            assert solver.browser_identity == (
                "Mozilla/5.0 Chrome/150.0.0.0 Safari/537.36",
                "150.0.7871.125",
            )
        finally:
            release.set()
            holder.join(timeout=1)
            solver.close()

    def test_idle_relaunch_preserves_published_transport_identity(self):
        solver = BrowserSolver(idle_timeout=1)
        old_browser = MagicMock()
        old_browser.version = "149.0.7827.201"
        old_browser.is_connected.return_value = True
        solver._browser = old_browser
        solver._browser_ua = "Mozilla/5.0 Chrome/149.0.0.0 Safari/537.36"
        solver._browser_version = "149.0.7827.201"
        solver._publish_browser_identity()
        solver._last_used = time.monotonic() - 2
        new_browser = MagicMock()
        new_browser.version = "149.0.7827.201"
        playwright = MagicMock()
        playwright.chromium.launch.return_value = new_browser

        with (
            patch("patchright.sync_api.sync_playwright") as sync_playwright,
            patch.object(solver, "_ensure_browser_installed"),
        ):
            sync_playwright.return_value.start.return_value = playwright
            solver._ensure_browser()

        assert solver.browser_identity == (
            "Mozilla/5.0 Chrome/149.0.0.0 Safari/537.36",
            "149.0.7827.201",
        )
        old_browser.close.assert_called_once()
        solver.close()

    def test_preflight_identity_pins_default_transport_before_first_request(self):
        user_agent = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "Chrome/150.0.0.0 Safari/537.36"
        )
        solver = SimpleNamespace(
            browser_identity=(user_agent, "150.0.7871.125"),
            proxy_server=None,
        )
        session = BaseSession(browser_solver=solver)

        assert repr(session.emulation) == "Profile.Chrome149"
        assert session._fingerprint.pinned is True
        assert session._client_headers["User-Agent"] == user_agent
        assert '"150"' in session._client_headers["sec-ch-ua"]
        assert (
            "150.0.7871.125" in session._client_headers["sec-ch-ua-full-version-list"]
        )

    def test_preflight_identity_rejects_mismatched_explicit_user_agent(self):
        user_agent = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "Chrome/150.0.0.0 Safari/537.36"
        )
        solver = SimpleNamespace(
            browser_identity=(user_agent, "150.0.7871.125"),
            proxy_server=None,
        )
        aligned = BaseSession(emulation=Emulation.Chrome145, browser_solver=solver)
        matching = BaseSession(
            headers={"User-Agent": user_agent}, browser_solver=solver
        )
        with pytest.raises(ValueError, match="exactly match"):
            BaseSession(
                headers={"User-Agent": "Caller-owned UA"},
                browser_solver=solver,
            )

        # Browser identity wins over an emulation choice just as it does after
        # a successful solve; otherwise the first challenge request is skewed.
        assert aligned._fingerprint.pinned is True
        assert aligned._fingerprint.ua_override == user_agent
        assert matching._fingerprint.pinned is True
        with pytest.raises(ValueError, match="per-request User-Agent"):
            matching._build_headers("https://example.com/", {"User-Agent": "different"})

    def test_authenticated_proxy_uses_playwright_credentials(self):
        proxy = "http://user:p%40ss@proxy.example:8080"
        solver = BrowserSolver(proxy=proxy)
        try:
            assert solver.proxy_matches("http://user:p%40ss@PROXY.EXAMPLE:8080/")
            assert _playwright_proxy(proxy) == {
                "server": "http://proxy.example:8080",
                "username": "user",
                "password": "p@ss",
            }
        finally:
            solver.close()

    def test_session_proxy_is_applied_to_browser_solver(self):
        solver = BrowserSolver()
        try:
            BaseSession(
                proxy="http://proxy.example:8080",
                browser_solver=solver,
            )
            assert solver.proxy_matches("http://proxy.example:8080")
        finally:
            solver.close()

    def test_session_rejects_browser_with_different_egress(self):
        solver = BrowserSolver(proxy="http://one.example:8080")
        try:
            with pytest.raises(ValueError, match="same proxy"):
                BaseSession(
                    proxy="http://two.example:8080",
                    browser_solver=solver,
                )
            with pytest.raises(ValueError, match="session does not"):
                BaseSession(browser_solver=solver)
        finally:
            solver.close()

    def test_session_proxy_rejects_unverifiable_custom_solver(self):
        with pytest.raises(ValueError, match="cannot bypass"):
            BaseSession(
                proxy="http://proxy.example:8080",
                browser_solver=MockBrowserSolver(),
            )

    @pytest.mark.parametrize(
        ("proxy", "expected_proxy", "expects_udp_guards"),
        [
            (None, None, False),
            (
                "http://user:p%40ss@proxy.example:8080",
                {
                    "server": "http://proxy.example:8080",
                    "username": "user",
                    "password": "p@ss",
                },
                True,
            ),
        ],
    )
    def test_launch_proxy_shape_and_udp_guards(
        self,
        proxy,
        expected_proxy,
        expects_udp_guards,
    ):
        solver = BrowserSolver(proxy=proxy)
        playwright = MagicMock()
        browser = MagicMock()
        browser.version = "149.0.7827.201"
        playwright.chromium.launch.return_value = browser
        driver = MagicMock()
        driver.start.return_value = playwright

        try:
            with (
                patch.object(solver, "_ensure_browser_installed"),
                patch(
                    "patchright.sync_api.sync_playwright",
                    return_value=driver,
                ),
            ):
                solver._ensure_browser()
            kwargs = playwright.chromium.launch.call_args.kwargs
            assert kwargs.get("proxy") == expected_proxy
            assert ("--disable-quic" in kwargs["args"]) is expects_udp_guards
            assert (
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
                in kwargs["args"]
            ) is expects_udp_guards
            assert solver.runtime_ready is True
            event_name, disconnected = browser.on.call_args.args
            assert event_name == "disconnected"
            disconnected(browser)
            assert solver.runtime_ready is False
        finally:
            solver._close_browser()
            solver.close()

    def test_linux_launch_selects_mesa_angle_backend(self):
        solver = BrowserSolver(executable_path="/opt/google/chrome/chrome")
        playwright = MagicMock()
        browser = MagicMock()
        browser.version = "149.0.7827.201"
        playwright.chromium.launch.return_value = browser
        driver = MagicMock()
        driver.start.return_value = playwright

        try:
            with (
                patch.object(solver, "_ensure_browser_installed"),
                patch(
                    "patchright.sync_api.sync_playwright",
                    return_value=driver,
                ),
                patch("wafer.browser._solver.sys.platform", "linux"),
            ):
                solver._ensure_browser()
            args = playwright.chromium.launch.call_args.kwargs["args"]
            assert "--enable-gpu" in args
            assert "--use-gl=angle" in args
            assert "--use-angle=gl" in args
            assert "--ignore-gpu-blocklist" in args
            assert "--use-angle=metal" not in args
        finally:
            solver._close_browser()
            solver.close()

    def test_launch_adopts_skewed_browser_version_as_identity(self, caplog):
        """A launched Chrome that differs from DEFAULT_EMULATION must be
        adopted, not rejected.

        Chrome auto-updates and wreq's newest Emulation lags it, so refusing
        to run would strand every solver behind a routine Chrome release.
        Agreement is achieved by pinning wafer's hints onto the browser (see
        FingerprintManager.pin_to_browser), so the launched version must be
        recorded and published as the identity.
        """
        solver = BrowserSolver()
        playwright = MagicMock()
        browser = MagicMock()
        browser.version = "150.0.7871.182"
        playwright.chromium.launch.return_value = browser
        driver = MagicMock()
        driver.start.return_value = playwright

        try:
            with (
                patch.object(solver, "_ensure_browser_installed"),
                patch.object(solver, "_probe_screenxy_patch"),
                patch(
                    "patchright.sync_api.sync_playwright",
                    return_value=driver,
                ),
                caplog.at_level(logging.WARNING, logger="wafer"),
            ):
                solver._ensure_browser()
            assert solver._browser is browser
            assert solver._browser_version == "150.0.7871.182"
            assert "150.0.7871.182" in caplog.text
        finally:
            solver._browser = None
            solver.close()

    def test_browser_install_lock_respects_deadline(self):
        solver = BrowserSolver()
        was_installed = BrowserSolver._browser_installed.copy()
        BrowserSolver._browser_installed.clear()
        BrowserSolver._browser_install_lock.acquire()
        try:
            with pytest.raises(TimeoutError, match="install check"):
                solver._ensure_browser_installed(time.monotonic() + 0.01)
        finally:
            BrowserSolver._browser_install_lock.release()
            BrowserSolver._browser_installed = was_installed
            solver.close()

    def test_browser_check_accepts_exact_emulation_chrome(self, monkeypatch):
        solver = BrowserSolver()
        was_installed = BrowserSolver._browser_installed.copy()
        BrowserSolver._browser_installed.clear()
        try:
            monkeypatch.setattr(
                "wafer.browser._solver._system_chrome_executable",
                lambda: "/opt/google/chrome/chrome",
            )
            monkeypatch.setattr(
                "wafer.browser._solver._browser_executable_version",
                lambda _path, _timeout: "149.0.7827.201",
            )
            solver._ensure_browser_installed()
            assert BrowserSolver._browser_installed
        finally:
            BrowserSolver._browser_installed = was_installed
            solver.close()

    @pytest.mark.parametrize(
        "installed",
        [
            "150.0.7871.182",  # newer major: the routine Chrome auto-update
            "149.0.7827.155",  # same major, different patch
            "147.0.7727.24",  # older major
        ],
    )
    def test_browser_check_accepts_version_skew_with_warning(
        self, monkeypatch, caplog, installed
    ):
        """Version skew must not be fatal.

        An equality gate here made every challenge-solving path dead the week
        Chrome shipped an update, because DEFAULT_EMULATION tracks wreq's
        newest Emulation rather than the installed browser. The skew is
        resolved by pinning wafer's UA/client hints onto the browser, so this
        check only has to surface it.
        """
        solver = BrowserSolver(executable_path="/opt/chrome/chrome")
        was_installed = BrowserSolver._browser_installed.copy()
        BrowserSolver._browser_installed.clear()
        try:
            monkeypatch.setattr(
                "wafer.browser._solver._browser_executable_version",
                lambda _path, _timeout: installed,
            )
            with caplog.at_level(logging.WARNING, logger="wafer"):
                solver._ensure_browser_installed()
            assert BrowserSolver._browser_installed
            assert installed in caplog.text
        finally:
            BrowserSolver._browser_installed = was_installed
            solver.close()

    def test_browser_check_still_rejects_unusable_executable(self, monkeypatch):
        """Relaxing the version match must not relax binary validation."""
        solver = BrowserSolver(executable_path="/opt/chrome/chrome")
        was_installed = BrowserSolver._browser_installed.copy()
        BrowserSolver._browser_installed.clear()

        def _boom(_path, _timeout):
            raise RuntimeError("Browser executable did not report a Chrome version")

        try:
            monkeypatch.setattr(
                "wafer.browser._solver._browser_executable_version", _boom
            )
            with pytest.raises(RuntimeError, match="did not report a Chrome version"):
                solver._ensure_browser_installed()
        finally:
            BrowserSolver._browser_installed = was_installed
            solver.close()

    def test_browser_check_fails_fast_without_actual_chrome(self, monkeypatch):
        solver = BrowserSolver()
        was_installed = BrowserSolver._browser_installed.copy()
        BrowserSolver._browser_installed.clear()
        try:
            monkeypatch.setattr(
                "wafer.browser._solver._system_chrome_executable", lambda: None
            )
            with pytest.raises(RuntimeError, match="No executable branded"):
                solver._ensure_browser_installed()
        finally:
            BrowserSolver._browser_installed = was_installed
            solver.close()

    def test_chrome_lookup_accepts_windows_per_user_install(self, monkeypatch):
        from wafer.browser._solver import _system_chrome_executable

        per_user = os.path.join(
            r"C:\Users\agent\AppData\Local",
            "Google",
            "Chrome",
            "Application",
            "chrome.exe",
        )
        monkeypatch.setattr("wafer.browser._solver.sys.platform", "win32")
        monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\agent\AppData\Local")
        monkeypatch.setattr(
            "wafer.browser._solver.os.access",
            lambda path, _mode: path == per_user,
        )

        assert _system_chrome_executable() == per_user


# ---------------------------------------------------------------------------
# Sync retry loop integration with browser solving
# ---------------------------------------------------------------------------


class TestSyncBrowserSolveIntegration:
    @patch("time.sleep")
    def test_tmd_browser_shell_is_replayed_through_transport(self, mock_sleep):
        punish = MockResponse(
            200,
            {"content-type": "text/html"},
            '<meta content="0;url=/_____tmd_____/punish?x=1">',
        )
        authoritative = MockResponse(
            200,
            {"content-type": "text/html"},
            "<html>authoritative SSR offer data</html>",
        )
        solver = MockBrowserSolver(
            SolveResult(
                cookies=[
                    {
                        "name": "x5sec",
                        "value": "solved",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": time.time() + 3600,
                    }
                ],
                user_agent="Chrome/145.0.0.0",
                response=CapturedResponse(
                    url="https://www.example.com/search",
                    status=200,
                    headers={"content-type": "text/html"},
                    body=b"<html>incomplete CSR shell</html>",
                ),
            )
        )
        session, client = make_sync_session(
            [punish, punish, authoritative],
            max_rotations=0,
            browser_solver=solver,
            use_cookie_jar=True,
        )

        response = session.get("https://www.example.com/search")

        assert response.text == "<html>authoritative SSR offer data</html>"
        assert client.request_count == 3
        assert solver.solve_calls == [("https://www.example.com/search", "tmd")]

    def test_browser_prime_imports_state_without_http_challenge(self):
        mock_solver = MockBrowserSolver(
            result=SolveResult(
                cookies=[
                    {
                        "name": "_m_h5_tk",
                        "value": "token_123",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": time.time() + 3600,
                    }
                ],
                user_agent="Chrome/145.0.0.0",
            )
        )
        session, _ = make_sync_session(
            [MockResponse(200)],
            browser_solver=mock_solver,
            use_cookie_jar=True,
            max_response_size=4321,
        )

        assert session.browser_prime("https://www.example.com/", timeout=5)
        assert session.get_cookie("_m_h5_tk", "https://www.example.com/") == "token_123"
        assert mock_solver.solve_calls == [("https://www.example.com/", "generic_js")]
        assert mock_solver.solve_kwargs[0]["max_size"] == 4321

    def test_configured_size_cap_preserves_legacy_custom_solver_protocol(self):
        calls = []

        class LegacySolver:
            def solve(
                self,
                url,
                challenge_type=None,
                timeout=None,
                embedder=None,
                replay=None,
            ):
                calls.append((url, challenge_type, timeout, embedder, replay))
                return SolveResult(
                    cookies=[
                        {
                            "name": "clearance",
                            "value": "valid",
                            "domain": ".example.com",
                            "path": "/",
                            "expires": time.time() + 3600,
                        }
                    ],
                    user_agent="Chrome/145.0.0.0",
                )

            def close(self):
                pass

        session, _ = make_sync_session(
            [MockResponse(200)],
            browser_solver=LegacySolver(),
            use_cookie_jar=True,
            max_response_size=4321,
        )

        assert session.browser_prime("https://www.example.com/", timeout=5)
        assert len(calls) == 1

    def test_browser_prime_without_solver_is_false(self):
        session, _ = make_sync_session([MockResponse(200)], browser_solver=None)

        assert not session.browser_prime("https://www.example.com/")

    def test_browser_solve_challenge_targets_issued_url_not_solve_origin(self):
        mock_solver = MockBrowserSolver(
            result=SolveResult(
                cookies=[
                    {
                        "name": "x5sec",
                        "value": "solved",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": time.time() + 3600,
                    }
                ],
                user_agent="Chrome/145.0.0.0",
            )
        )
        session, _ = make_sync_session(
            [MockResponse(200)],
            browser_solver=mock_solver,
            solve_origin="https://www.example.com/",
            use_cookie_jar=True,
        )
        issued = "https://www.example.com/_____tmd_____/punish?x5secdata=x"

        assert session.browser_solve_challenge(issued, "tmd", timeout=5)
        assert mock_solver.solve_calls == [(issued, "tmd")]
        assert mock_solver.solve_kwargs[0]["embedder"] is None

    def test_browser_solve_challenge_rejects_unknown_type(self):
        session, _ = make_sync_session(
            [MockResponse(200)], browser_solver=MockBrowserSolver()
        )

        assert not session.browser_solve_challenge(
            "https://www.example.com/", "not-a-challenge"
        )

    def test_browser_prime_rejects_third_party_only_cookies(self):
        mock_solver = MockBrowserSolver(
            result=SolveResult(
                cookies=[
                    {
                        "name": "tracker",
                        "value": "not-target-state",
                        "domain": ".third-party.test",
                        "path": "/",
                        "expires": time.time() + 3600,
                    }
                ],
                user_agent="Chrome/145.0.0.0",
            )
        )
        session, client = make_sync_session(
            [MockResponse(200)],
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        assert not session.browser_prime("https://www.example.com/")
        assert client.cookie_jar.added == []
        assert session._fingerprint.pinned is False

    def test_browser_prime_rejects_cookie_less_passthrough(self):
        mock_solver = MockBrowserSolver(
            result=SolveResult(
                cookies=[],
                user_agent="Chrome/145.0.0.0",
                response=CapturedResponse(
                    url="https://www.example.com/",
                    status=200,
                    headers={"content-type": "text/html"},
                    body=b"<html>content only</html>",
                ),
            )
        )
        session, _ = make_sync_session([MockResponse(200)], browser_solver=mock_solver)

        assert not session.browser_prime("https://www.example.com/")

    def test_browser_prime_survives_cookie_cache_write_failure(self):
        mock_solver = MockBrowserSolver(
            result=SolveResult(
                cookies=[
                    {
                        "name": "_m_h5_tk",
                        "value": "token_123",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": time.time() + 3600,
                    }
                ],
                user_agent="Chrome/145.0.0.0",
            )
        )
        cache = MagicMock()
        cache.save.side_effect = OSError("disk flush failed")
        session, _ = make_sync_session(
            [MockResponse(200)],
            browser_solver=mock_solver,
            use_cookie_jar=True,
            cookie_cache=cache,
        )

        assert session.browser_prime("https://www.example.com/")
        assert session.get_cookie("_m_h5_tk", "https://www.example.com/") == "token_123"

    @patch("time.sleep")
    def test_tmd_warm_must_clear_challenge_before_browser(self, mock_sleep):
        punish = MockResponse(
            200,
            {"content-type": "text/html"},
            '<meta content="0;url=/_____tmd_____/punish?x=1">',
        )
        mock_solver = MockBrowserSolver(result=None)
        session, client = make_sync_session(
            [punish, punish],
            max_rotations=0,
            browser_solver=mock_solver,
        )

        response = session.get("https://acs.example.com/api", timeout=180)

        assert response.challenge_type == "tmd"
        assert client.request_count == 2
        assert (
            mock_solver.solve_calls
            == [
                ("https://acs.example.com/api", "tmd"),
            ]
            * 3
        )

    @patch("time.sleep")
    def test_tmd_browser_retry_uses_fresh_solve_and_second_result(self, mock_sleep):
        punish = MockResponse(
            200,
            {"content-type": "text/html"},
            '<meta content="0;url=/_____tmd_____/punish?x=1">',
        )
        authoritative = MockResponse(200, body='{"ok":true}')
        solved = SolveResult(
            cookies=[
                {
                    "name": "x5sec",
                    "value": "second-context",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": time.time() + 3600,
                }
            ],
            user_agent="Chrome/145.0.0.0",
        )
        mock_solver = MockBrowserSolver(results=[None, solved])
        session, client = make_sync_session(
            [punish, punish, authoritative],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        response = session.get("https://acs.example.com/api", timeout=180)

        assert response.status_code == 200
        assert response.challenge_type is None
        assert client.request_count == 3
        assert (
            mock_solver.solve_calls
            == [
                ("https://acs.example.com/api", "tmd"),
            ]
            * 2
        )
        assert all(
            0 < call_kwargs["timeout"] <= 180
            for call_kwargs in mock_solver.solve_kwargs
        )

    @patch("time.sleep")
    def test_tmd_cleared_homepage_retries_without_browser(self, mock_sleep):
        punish = MockResponse(
            200,
            {"content-type": "text/html"},
            '<meta content="0;url=/_____tmd_____/punish?x=1">',
        )
        clear_homepage = MockResponse(
            200,
            {"content-type": "text/html"},
            "<html>Storefront</html>",
        )
        ok = MockResponse(200, body='{"ok":true}')
        mock_solver = MockBrowserSolver(result=None)
        session, client = make_sync_session(
            [punish, clear_homepage, ok],
            max_rotations=0,
            browser_solver=mock_solver,
        )

        response = session.get("https://acs.example.com/api")

        assert response.status_code == 200
        assert response.challenge_type is None
        assert client.request_count == 3
        assert mock_solver.solve_calls == []

    @patch("time.sleep")
    def test_tmd_warms_and_replays_only_once_before_browser(self, mock_sleep):
        punish = MockResponse(
            200,
            {"content-type": "text/html"},
            '<meta content="0;url=/_____tmd_____/punish?x=1">',
        )
        clear_homepage = MockResponse(
            200,
            {"content-type": "text/html"},
            "<html>Storefront</html>",
        )
        authoritative = MockResponse(200, body='{"ok":true}')
        solver = MockBrowserSolver(
            SolveResult(
                cookies=[
                    {
                        "name": "x5sec",
                        "value": "solved",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": time.time() + 3600,
                    }
                ],
                user_agent="Chrome/145.0.0.0",
            )
        )
        session, client = make_sync_session(
            [punish, clear_homepage, punish, authoritative],
            max_rotations=0,
            browser_solver=solver,
            use_cookie_jar=True,
        )

        response = session.get("https://acs.example.com/api")

        assert response.status_code == 200
        assert client.request_count == 4
        assert sum(url.endswith("/") for _, url, _ in client.request_log) == 1
        assert solver.solve_calls == [("https://acs.example.com/api", "tmd")]

    @patch("time.sleep")
    def test_browser_solve_called_when_rotations_exhausted(self, mock_sleep):
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
            user_agent=("Mozilla/5.0 Chrome/145.0.0.0 Safari/537.36"),
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
    def test_browser_solve_not_called_when_no_solver(self, mock_sleep):
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
    def test_browser_solve_failure_returns_challenge(self, mock_sleep):
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
    def test_browser_solve_cookies_injected_into_jar(self, mock_sleep):
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
        assert any("cf_clearance=solved123" in c[0] for c in jar.added)
        assert any("__cf_bm=token456" in c[0] for c in jar.added)

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
        assert repr(session._fingerprint.current) == "Profile.Chrome133"

    @patch("time.sleep")
    def test_browser_solve_version_skew_pins_newest(self, mock_sleep):
        """Regression: a browser NEWER than any wreq Emulation (Patchright
        Chromium ahead of wreq) must still pin + override the UA/hints, not
        silently no-op. This is the miata.net "clearance doesn't stick" bug."""
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real</html>")

        ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/150.0.0.0 Safari/537.36"
        )
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
            user_agent=ua,
            browser_version="150.0.7871.125",
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        session, _ = make_sync_session(
            [cf_resp, ok_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        session.get("https://example.com/page")
        # TLS pins the newest available wreq profile (no Chrome150 in wreq)...
        assert repr(session._fingerprint.current) == "Profile.Chrome149"
        assert session._fingerprint.pinned is True
        # ...but the wire identity follows the real browser (Chrome150).
        assert session._fingerprint.ua_override == ua
        env = session.fingerprint_envelope()
        assert env["user_agent"] == ua
        assert '"150"' in env["sec_ch_ua"]
        assert "150.0.7871.125" in env["full_version_list"]

    @patch("time.sleep")
    def test_imperva_solve_leaves_fingerprint_unpinned(self, mock_sleep):
        """Imperva's earned token rides an unpinned wreq/native path, so an
        Imperva browser solve must NOT pin/override the fingerprint (the pin
        block is deliberately skipped for Imperva)."""
        from wafer._challenge import ChallengeType

        browser_result = SolveResult(
            cookies=[
                {
                    "name": "reese84",
                    "value": "tok",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Mozilla/5.0 Chrome/150.0.0.0 Safari/537.36",
            browser_version="150.0.7871.125",
        )
        mock_solver = MockBrowserSolver(result=browser_result)
        session, _ = make_sync_session(
            [MockResponse(200, body="ok")],
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        session._try_browser_solve(
            ChallengeType.IMPERVA,
            "https://api2.example.com/listing",
            embedder="https://www.example.com/",
            replay={"method": "GET", "body": None, "content_type": None},
        )
        # Imperva must leave the fingerprint untouched: no pin, no UA override.
        assert session._fingerprint.pinned is False
        assert session._fingerprint.ua_override is None

    @patch("time.sleep")
    def test_browser_solve_full_version_from_ua_fallback(self, mock_sleep):
        """When SolveResult.browser_version is None, the full build is extracted
        from the UA (chrome_full_version_from_ua) so the hints still carry it."""
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real</html>")

        ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/150.0.7871.125 Safari/537.36"
        )
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
            user_agent=ua,
            browser_version=None,  # force the UA-extraction fallback
        )
        mock_solver = MockBrowserSolver(result=browser_result)
        session, _ = make_sync_session(
            [cf_resp, ok_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        session.get("https://example.com/page")
        env = session.fingerprint_envelope()
        assert "150.0.7871.125" in env["full_version_list"]

    @patch("time.sleep")
    def test_browser_solve_with_cookie_cache(self, mock_sleep, tmp_path):
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
                    "expires": time.time() + 1800,  # 30min TTL
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
        assert any(c["name"] == "cf_clearance" for c in cached)

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
        assert any("session_id=injected_val" in c[0] for c in jar.added)

    @patch("time.sleep")
    def test_challenge_absent_passthrough_preserves_client_identity_and_jar(
        self,
        mock_sleep,
    ):
        """Challenge-absent CF passthrough must not rebuild or pin."""
        from wafer.browser._solver import CapturedResponse

        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        browser_result = SolveResult(
            cookies=[
                {
                    "name": "browser_cookie",
                    "value": "merged",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Chrome/150.0.0.0",
            response=CapturedResponse(
                url="https://example.com/page",
                status=200,
                headers={"content-type": "text/html"},
                body=b"<html>Real content</html>",
            ),
            challenge_absent=True,
        )
        session, client = make_sync_session(
            [cf_resp],
            max_rotations=0,
            browser_solver=MockBrowserSolver(result=browser_result),
            use_cookie_jar=True,
        )
        client.cookie_jar.add(
            "auth=keep; Domain=.example.com; Path=/; Secure",
            "https://example.com/",
        )
        session._rebuild_client = MagicMock()

        response = session.get("https://example.com/page")

        assert response.status_code == 200
        session._rebuild_client.assert_not_called()
        assert session._fingerprint.pinned is False
        assert client.cookie_jar.get("auth", response.url).value == "keep"
        assert (
            client.cookie_jar.get("browser_cookie", response.url).value
            == "merged"
        )

    @patch("time.sleep")
    def test_passthrough_text_uses_declared_charset(self, mock_sleep):
        from wafer.browser._solver import CapturedResponse

        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        browser_result = SolveResult(
            cookies=[],
            user_agent="Chrome/150.0.0.0",
            response=CapturedResponse(
                url="https://example.com/page",
                status=200,
                headers={"content-type": "text/html; charset=iso-8859-1"},
                body=b"<html><body>caf\xe9</body></html>",
            ),
            challenge_absent=True,
        )
        session, _ = make_sync_session(
            [cf_resp],
            max_rotations=0,
            browser_solver=MockBrowserSolver(result=browser_result),
        )

        response = session.get("https://example.com/page")

        assert "café" in response.text

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

    @patch("time.sleep")
    def test_passthrough_preserves_individual_set_cookie(self, mock_sleep):
        """FIX 4: a passthrough response with several Set-Cookie headers
        exposes them individually (not collapsed into the flat dict)."""
        from wafer.browser._solver import CapturedResponse

        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        multi = [
            "cf_clearance=tok; Path=/; Secure; HttpOnly",
            "__cf_bm=bm; Path=/; Secure",
        ]
        browser_result = SolveResult(
            cookies=[
                {
                    "name": "cf_clearance",
                    "value": "tok",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Chrome/145.0.0.0",
            response=CapturedResponse(
                url="https://example.com/page",
                status=200,
                # Flat dict collapses to one "; "-joined value...
                headers={"set-cookie": "; ".join(multi)},
                body=b"<html>Real content</html>",
                set_cookie=multi,  # ...but the individual values are kept.
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
        # Individual Set-Cookie values survive the passthrough.
        assert resp.get_all("set-cookie") == multi
        assert resp.cookies.get("cf_clearance") == "tok"
        assert resp.cookies.get("__cf_bm") == "bm"

    @patch("time.sleep")
    def test_passthrough_over_cap_raises(self, mock_sleep):
        """FIX 1: the browser passthrough body is bounded by max_response_size."""
        from wafer import ResponseTooLarge
        from wafer.browser._solver import CapturedResponse

        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        browser_result = SolveResult(
            cookies=[],
            user_agent="Chrome/145.0.0.0",
            response=CapturedResponse(
                url="https://example.com/page",
                status=200,
                headers={"content-type": "text/html"},
                body=b"z" * 5000,
            ),
        )
        mock_solver = MockBrowserSolver(result=browser_result)
        session, _ = make_sync_session(
            [cf_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
            max_response_size=500,
        )
        with pytest.raises(ResponseTooLarge) as ei:
            session.get("https://example.com/page")
        assert ei.value.limit == 500


class TestSolveOrigin:
    """E8: session-level solve_origin threads to BrowserSolver.solve()."""

    def _solved_result(self):
        return SolveResult(
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
            user_agent="Mozilla/5.0 Chrome/145.0.0.0 Safari/537.36",
        )

    @patch("time.sleep")
    def test_solve_origin_passed_as_embedder(self, mock_sleep):
        """solve_origin becomes the solver's navigation target (embedder),
        while the API url stays the request url for cookie scoping."""
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real page</html>")
        mock_solver = MockBrowserSolver(result=self._solved_result())

        # JSON API url; the WAF token is mintable on the origin page.
        api_url = "https://api.example.com/v1/data"
        origin = "https://www.example.com/"
        session, mock_client = make_sync_session(
            [cf_resp, ok_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            solve_origin=origin,
            use_cookie_jar=True,
        )

        resp = session.get(api_url)
        assert resp.status_code == 200
        # The solver was navigated to solve_origin, not the JSON API url.
        assert mock_solver.solve_kwargs[0]["embedder"] == origin
        # The request url is still the API url (cookie scoping uses it).
        assert mock_solver.solve_kwargs[0]["url"] == api_url

    @patch("time.sleep")
    def test_no_solve_origin_navigates_request_url(self, mock_sleep):
        """Without solve_origin, a non-Imperva challenge has embedder=None
        (the solver navigates the request url itself)."""
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real page</html>")
        mock_solver = MockBrowserSolver(result=self._solved_result())

        session, mock_client = make_sync_session(
            [cf_resp, ok_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        session.get("https://example.com/page")
        assert mock_solver.solve_kwargs[0]["embedder"] is None
        assert mock_solver.solve_kwargs[0]["url"] == ("https://example.com/page")

    @patch("time.sleep")
    def test_solve_origin_overrides_imperva_embedder(self, mock_sleep):
        """For Imperva, an explicit solve_origin overrides the auto-derived
        embedder heuristic (the caller knows the real origin)."""
        from wafer._challenge import ChallengeType

        mock_solver = MockBrowserSolver(result=self._solved_result())
        session, _ = make_sync_session(
            [MockResponse(200, body="ok")],
            browser_solver=mock_solver,
            solve_origin="https://chosen-origin.example/",
        )
        # Drive _try_browser_solve directly with an Imperva-derived embedder.
        session._try_browser_solve(
            ChallengeType.IMPERVA,
            "https://api2.example.com/listing",
            embedder="https://www.example.com/",  # heuristic embedder
            replay={"method": "GET", "body": None, "content_type": None},
        )
        # solve_origin wins over the heuristic embedder.
        assert mock_solver.solve_kwargs[0]["embedder"] == (
            "https://chosen-origin.example/"
        )

    @pytest.mark.asyncio
    async def test_async_solve_origin_passed_as_embedder(self):
        """Async parity: solve_origin threads through to the solver."""
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real page</html>")
        mock_solver = MockBrowserSolver(result=self._solved_result())

        origin = "https://www.example.com/"
        session, _ = make_async_session(
            [cf_resp, ok_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            solve_origin=origin,
            use_cookie_jar=True,
        )
        with patch("asyncio.sleep"):
            resp = await session.get("https://api.example.com/v1/data")
        assert resp.status_code == 200
        assert mock_solver.solve_kwargs[0]["embedder"] == origin


class TestAsyncBrowserSolveIntegration:
    @patch("asyncio.sleep")
    async def test_tmd_browser_shell_is_replayed_through_transport(self, mock_sleep):
        punish = MockResponse(
            200,
            {"content-type": "text/html"},
            '<meta content="0;url=/_____tmd_____/punish?x=1">',
        )
        authoritative = MockResponse(
            200,
            {"content-type": "text/html"},
            "<html>authoritative SSR offer data</html>",
        )
        solver = MockBrowserSolver(
            SolveResult(
                cookies=[
                    {
                        "name": "x5sec",
                        "value": "solved",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": time.time() + 3600,
                    }
                ],
                user_agent="Chrome/145.0.0.0",
                response=CapturedResponse(
                    url="https://www.example.com/search",
                    status=200,
                    headers={"content-type": "text/html"},
                    body=b"<html>incomplete CSR shell</html>",
                ),
            )
        )
        session, client = make_async_session(
            [punish, punish, authoritative],
            max_rotations=0,
            browser_solver=solver,
            use_cookie_jar=True,
        )

        response = await session.get("https://www.example.com/search")

        assert response.text == "<html>authoritative SSR offer data</html>"
        assert client.request_count == 3
        assert solver.solve_calls == [("https://www.example.com/search", "tmd")]

    async def test_browser_prime_imports_state_without_http_challenge(self):
        mock_solver = MockBrowserSolver(
            result=SolveResult(
                cookies=[
                    {
                        "name": "_m_h5_tk",
                        "value": "token_123",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": time.time() + 3600,
                    }
                ],
                user_agent="Chrome/145.0.0.0",
            )
        )
        session, _ = make_async_session(
            [MockResponse(200)],
            browser_solver=mock_solver,
            use_cookie_jar=True,
            max_response_size=4321,
        )

        assert await session.browser_prime("https://www.example.com/", timeout=5)
        assert session.get_cookie("_m_h5_tk", "https://www.example.com/") == "token_123"
        assert mock_solver.solve_calls == [("https://www.example.com/", "generic_js")]
        assert mock_solver.solve_kwargs[0]["max_size"] == 4321

    async def test_configured_size_cap_preserves_legacy_custom_solver_protocol(
        self,
    ):
        calls = []

        class LegacyAsyncSolver:
            async def asolve(
                self,
                url,
                challenge_type=None,
                timeout=None,
                embedder=None,
                replay=None,
            ):
                calls.append((url, challenge_type, timeout, embedder, replay))
                return SolveResult(
                    cookies=[
                        {
                            "name": "clearance",
                            "value": "valid",
                            "domain": ".example.com",
                            "path": "/",
                            "expires": time.time() + 3600,
                        }
                    ],
                    user_agent="Chrome/145.0.0.0",
                )

            def solve(self, *args, **kwargs):
                raise AssertionError("sync solve should not be called")

            def close(self):
                pass

        session, _ = make_async_session(
            [MockResponse(200)],
            browser_solver=LegacyAsyncSolver(),
            use_cookie_jar=True,
            max_response_size=4321,
        )

        assert await session.browser_prime(
            "https://www.example.com/",
            timeout=5,
        )
        assert len(calls) == 1

    async def test_browser_prime_without_solver_is_false(self):
        session, _ = make_async_session([MockResponse(200)], browser_solver=None)

        assert not await session.browser_prime("https://www.example.com/")

    async def test_browser_solve_challenge_targets_issued_url_not_solve_origin(
        self,
    ):
        mock_solver = MockBrowserSolver(
            result=SolveResult(
                cookies=[
                    {
                        "name": "x5sec",
                        "value": "solved",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": time.time() + 3600,
                    }
                ],
                user_agent="Chrome/145.0.0.0",
            )
        )
        session, _ = make_async_session(
            [MockResponse(200)],
            browser_solver=mock_solver,
            solve_origin="https://www.example.com/",
            use_cookie_jar=True,
        )
        issued = "https://www.example.com/_____tmd_____/punish?x5secdata=x"

        assert await session.browser_solve_challenge(issued, "tmd", timeout=5)
        assert mock_solver.solve_calls == [(issued, "tmd")]
        assert mock_solver.solve_kwargs[0]["embedder"] is None

    async def test_browser_solve_challenge_rejects_unknown_type(self):
        session, _ = make_async_session(
            [MockResponse(200)], browser_solver=MockBrowserSolver()
        )

        assert not await session.browser_solve_challenge(
            "https://www.example.com/", "not-a-challenge"
        )

    async def test_browser_prime_rejects_third_party_only_cookies(self):
        mock_solver = MockBrowserSolver(
            result=SolveResult(
                cookies=[
                    {
                        "name": "tracker",
                        "value": "not-target-state",
                        "domain": ".third-party.test",
                        "path": "/",
                        "expires": time.time() + 3600,
                    }
                ],
                user_agent="Chrome/145.0.0.0",
            )
        )
        session, client = make_async_session(
            [MockResponse(200)],
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        assert not await session.browser_prime("https://www.example.com/")
        assert client.cookie_jar.added == []
        assert session._fingerprint.pinned is False

    async def test_browser_prime_rejects_cookie_less_passthrough(self):
        mock_solver = MockBrowserSolver(
            result=SolveResult(
                cookies=[],
                user_agent="Chrome/145.0.0.0",
                response=CapturedResponse(
                    url="https://www.example.com/",
                    status=200,
                    headers={"content-type": "text/html"},
                    body=b"<html>content only</html>",
                ),
            )
        )
        session, _ = make_async_session([MockResponse(200)], browser_solver=mock_solver)

        assert not await session.browser_prime("https://www.example.com/")

    async def test_browser_prime_survives_cookie_cache_write_failure(self):
        mock_solver = MockBrowserSolver(
            result=SolveResult(
                cookies=[
                    {
                        "name": "_m_h5_tk",
                        "value": "token_123",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": time.time() + 3600,
                    }
                ],
                user_agent="Chrome/145.0.0.0",
            )
        )
        cache = MagicMock()
        cache.save.side_effect = OSError("disk flush failed")
        session, _ = make_async_session(
            [MockResponse(200)],
            browser_solver=mock_solver,
            use_cookie_jar=True,
            cookie_cache=cache,
        )

        assert await session.browser_prime("https://www.example.com/")
        assert session.get_cookie("_m_h5_tk", "https://www.example.com/") == "token_123"

    @patch("asyncio.sleep")
    async def test_tmd_warm_must_clear_challenge_before_browser(self, mock_sleep):
        punish = MockResponse(
            200,
            {"content-type": "text/html"},
            '<meta content="0;url=/_____tmd_____/punish?x=1">',
        )
        mock_solver = MockBrowserSolver(result=None)
        session, client = make_async_session(
            [punish, punish],
            max_rotations=0,
            browser_solver=mock_solver,
        )

        response = await session.get(
            "https://acs.example.com/api",
            timeout=180,
        )

        assert response.challenge_type == "tmd"
        assert client.request_count == 2
        assert (
            mock_solver.solve_calls
            == [
                ("https://acs.example.com/api", "tmd"),
            ]
            * 3
        )

    @patch("asyncio.sleep")
    async def test_tmd_browser_retry_uses_fresh_solve_and_second_result(
        self, mock_sleep
    ):
        punish = MockResponse(
            200,
            {"content-type": "text/html"},
            '<meta content="0;url=/_____tmd_____/punish?x=1">',
        )
        authoritative = MockResponse(200, body='{"ok":true}')
        solved = SolveResult(
            cookies=[
                {
                    "name": "x5sec",
                    "value": "second-context",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": time.time() + 3600,
                }
            ],
            user_agent="Chrome/145.0.0.0",
        )
        mock_solver = MockBrowserSolver(results=[None, solved])
        session, client = make_async_session(
            [punish, punish, authoritative],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        response = await session.get(
            "https://acs.example.com/api",
            timeout=180,
        )

        assert response.status_code == 200
        assert response.challenge_type is None
        assert client.request_count == 3
        assert (
            mock_solver.solve_calls
            == [
                ("https://acs.example.com/api", "tmd"),
            ]
            * 2
        )
        assert all(
            0 < call_kwargs["timeout"] <= 180
            for call_kwargs in mock_solver.solve_kwargs
        )

    @patch("asyncio.sleep")
    async def test_tmd_cleared_homepage_retries_without_browser(self, mock_sleep):
        punish = MockResponse(
            200,
            {"content-type": "text/html"},
            '<meta content="0;url=/_____tmd_____/punish?x=1">',
        )
        clear_homepage = MockResponse(
            200,
            {"content-type": "text/html"},
            "<html>Storefront</html>",
        )
        ok = MockResponse(200, body='{"ok":true}')
        mock_solver = MockBrowserSolver(result=None)
        session, client = make_async_session(
            [punish, clear_homepage, ok],
            max_rotations=0,
            browser_solver=mock_solver,
        )

        response = await session.get("https://acs.example.com/api")

        assert response.status_code == 200
        assert response.challenge_type is None
        assert client.request_count == 3
        assert mock_solver.solve_calls == []

    @patch("asyncio.sleep")
    async def test_tmd_warms_and_replays_only_once_before_browser(self, mock_sleep):
        punish = MockResponse(
            200,
            {"content-type": "text/html"},
            '<meta content="0;url=/_____tmd_____/punish?x=1">',
        )
        clear_homepage = MockResponse(
            200,
            {"content-type": "text/html"},
            "<html>Storefront</html>",
        )
        authoritative = MockResponse(200, body='{"ok":true}')
        solver = MockBrowserSolver(
            SolveResult(
                cookies=[
                    {
                        "name": "x5sec",
                        "value": "solved",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": time.time() + 3600,
                    }
                ],
                user_agent="Chrome/145.0.0.0",
            )
        )
        session, client = make_async_session(
            [punish, clear_homepage, punish, authoritative],
            max_rotations=0,
            browser_solver=solver,
            use_cookie_jar=True,
        )

        response = await session.get("https://acs.example.com/api")

        assert response.status_code == 200
        assert client.request_count == 4
        assert sum(url.endswith("/") for _, url, _ in client.request_log) == 1
        assert solver.solve_calls == [("https://acs.example.com/api", "tmd")]

    @patch("asyncio.sleep")
    async def test_browser_solve_called_when_rotations_exhausted(self, mock_sleep):
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
    async def test_browser_solve_failure_returns_challenge(self, mock_sleep):
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
    async def test_browser_solve_cookies_injected(self, mock_sleep):
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

    @patch("asyncio.sleep")
    async def test_browser_solve_version_skew_pins_newest(self, mock_sleep):
        """Async parity for the version-skew pin fix (browser newer than any
        wreq Emulation still pins newest + overrides UA/hints)."""
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real</html>")

        ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/150.0.0.0 Safari/537.36"
        )
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
            user_agent=ua,
            browser_version="150.0.7871.125",
        )
        mock_solver = MockBrowserSolver(result=browser_result)

        session, _ = make_async_session(
            [cf_resp, ok_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        await session.get("https://example.com/page")
        assert repr(session._fingerprint.current) == "Profile.Chrome149"
        assert session._fingerprint.pinned is True
        assert session._fingerprint.ua_override == ua
        env = session.fingerprint_envelope()
        assert '"150"' in env["sec_ch_ua"]
        assert "150.0.7871.125" in env["full_version_list"]

    @patch("asyncio.sleep")
    async def test_imperva_solve_leaves_fingerprint_unpinned(self, mock_sleep):
        """Async parity for the Imperva pin-skip (the guard is duplicated in
        _async.py, so it needs its own test)."""
        from wafer._challenge import ChallengeType

        browser_result = SolveResult(
            cookies=[
                {
                    "name": "reese84",
                    "value": "tok",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Mozilla/5.0 Chrome/150.0.0.0 Safari/537.36",
            browser_version="150.0.7871.125",
        )
        mock_solver = MockBrowserSolver(result=browser_result)
        session, _ = make_async_session(
            [MockResponse(200, body="ok")],
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        await session._try_browser_solve(
            ChallengeType.IMPERVA,
            "https://api2.example.com/listing",
            embedder="https://www.example.com/",
            replay={"method": "GET", "body": None, "content_type": None},
        )
        assert session._fingerprint.pinned is False
        assert session._fingerprint.ua_override is None

    @patch("asyncio.sleep")
    async def test_browser_solve_full_version_from_ua_fallback(self, mock_sleep):
        """When SolveResult.browser_version is None, the full build is extracted
        from the UA (chrome_full_version_from_ua) so the hints still carry it."""
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        ok_resp = MockResponse(200, body="<html>Real</html>")

        ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/150.0.7871.125 Safari/537.36"
        )
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
            user_agent=ua,
            browser_version=None,  # force the UA-extraction fallback
        )
        mock_solver = MockBrowserSolver(result=browser_result)
        session, _ = make_async_session(
            [cf_resp, ok_resp],
            max_rotations=0,
            browser_solver=mock_solver,
            use_cookie_jar=True,
        )

        await session.get("https://example.com/page")
        env = session.fingerprint_envelope()
        assert "150.0.7871.125" in env["full_version_list"]


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
        result = InterceptResult(cookies=[], responses=[], user_agent="")
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
        solver._needs_screenxy_patch = False
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
                    200,
                    {},
                    b"root",
                )
            )
            response_handler(
                _make_mock_pw_response(
                    "https://www.marinetraffic.com/page",
                    200,
                    {},
                    b"www",
                )
            )
            response_handler(
                _make_mock_pw_response(
                    "https://tiles.marinetraffic.com/t1",
                    200,
                    {},
                    b"tiles",
                )
            )
            response_handler(
                _make_mock_pw_response(
                    "https://notmarinetraffic.com/fake",
                    200,
                    {},
                    b"fake",
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
                    200,
                    {},
                    b"partial data",
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
                __truediv__=lambda self, name: (
                    rec_dir if name == "_recordings" else self
                ),
            ),
        ):
            # Directly set up the patched resource to return our dir
            pkg_mock = MagicMock()
            pkg_mock.__truediv__ = lambda self, name: rec_dir

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


class TestReplayDrag:
    def test_approach_joins_first_hover_sample_without_handle_teleport(self):
        solver = BrowserSolver()
        solver._drag_recordings = [
            {
                "name": "hover-offset.csv",
                "meta": {
                    "start": "100,100",
                    "end": "200,100",
                    "mousedown_t": "0.1",
                },
                "rows": [
                    {"t": 0.0, "rx": 0.2, "ry": -0.1},
                    {"t": 0.1, "rx": 0.0, "ry": 0.0},
                    {"t": 0.2, "rx": 1.0, "ry": 0.0},
                ],
            }
        ]
        page = MagicMock()

        with (
            patch.object(solver, "_replay_path", return_value=True) as path,
            patch("wafer.browser._solver.time.sleep"),
        ):
            assert solver._replay_drag(
                page,
                100,
                100,
                200,
                100,
                approach_from=(400, 300),
            )

        path.assert_called_once_with(
            page,
            400,
            300,
            120,
            90,
            deadline=None,
        )
        # The approach already ended at the first sample; replay must not
        # insert the old instantaneous jump to the mousedown coordinate.
        assert page.mouse.method_calls[0] == call.move(100, 100)
        assert page.mouse.method_calls[1] == call.down()
        solver.close()

    def test_mousedown_occurs_after_recorded_coordinate_and_delay(self):
        solver = BrowserSolver()
        solver._drag_recordings = [
            {
                "name": "press-order.csv",
                "meta": {
                    "start": "100,100",
                    "end": "200,100",
                    "mousedown_t": "0.2",
                },
                "rows": [
                    {"t": 0.0, "rx": 0.2, "ry": 0.1},
                    {"t": 0.2, "rx": 0.0, "ry": 0.0},
                    {"t": 0.3, "rx": 1.0, "ry": 0.0},
                ],
            }
        ]
        page = MagicMock()

        with patch("wafer.browser._solver.time.sleep") as sleep:
            assert solver._replay_drag(page, 100, 100, 200, 100)

        assert page.mouse.method_calls[:3] == [
            call.move(120, 110),
            call.move(100, 100),
            call.down(),
        ]
        assert sleep.called
        solver.close()

    def test_excluded_slider_recording_is_not_reused(self):
        solver = BrowserSolver()
        solver._drag_recordings = [
            {
                "name": "used.csv",
                "meta": {"start": "0,0", "end": "100,0", "mousedown_t": "0"},
                "rows": [{"t": 0.0, "rx": 1.0, "ry": 0.0}],
            },
            {
                "name": "unused.csv",
                "meta": {"start": "0,0", "end": "100,0", "mousedown_t": "0"},
                "rows": [{"t": 0.0, "rx": 1.0, "ry": 0.0}],
            },
        ]

        assert solver._replay_drag(
            MagicMock(),
            0,
            0,
            100,
            0,
            exclude_recordings={"used.csv"},
        )

        assert solver._last_drag_recording_name == "unused.csv"
        solver.close()

    def test_slider_can_use_full_bounded_recording_pool(self, monkeypatch):
        solver = BrowserSolver()
        solver._drag_recordings = [
            {
                "name": f"trace-{index}.csv",
                "meta": {"start": "0,0", "end": "100,0", "mousedown_t": "0"},
                "rows": [{"t": 0.0, "rx": 1.0, "ry": 0.0}],
            }
            for index in range(5)
        ]
        monkeypatch.setattr(
            "wafer.browser._solver.random.choice", lambda values: values[-1]
        )

        assert solver._replay_drag(MagicMock(), 0, 0, 100, 0, recording_pool_size=5)

        assert solver._last_drag_recording_name == "trace-4.csv"
        solver.close()

    def test_baxia_trace_logs_selected_recording_and_timing(self, caplog):
        caplog.set_level(logging.INFO, logger="wafer")
        solver = BrowserSolver()
        solver._drag_recordings = [
            {
                "name": "slide-human-01.csv",
                "meta": {"start": "0,0", "end": "100,0", "mousedown_t": "0"},
                "rows": [{"t": 0.0, "rx": 1.0, "ry": 0.0}],
            }
        ]
        page = MagicMock()

        assert solver._replay_drag(page, 10, 20, 110, 20, telemetry_label="Baxia")

        assert "Baxia drag trace: recording=slide-human-01.csv" in caplog.text
        assert "time_scale=" in caplog.text
        solver.close()

    def test_pressed_pointer_is_clamped_to_slider_endpoint(self):
        solver = BrowserSolver()
        solver._drag_recordings = [
            {
                "name": "overshooting-slide.csv",
                "meta": {"start": "100,100", "end": "200,100", "mousedown_t": "0.1"},
                "rows": [
                    {"t": 0.0, "rx": -0.1, "ry": 0.0},
                    {"t": 0.1, "rx": 0.0, "ry": 0.0},
                    {"t": 0.2, "rx": 1.1, "ry": 0.0},
                ],
            }
        ]
        page = MagicMock()

        assert solver._replay_drag(page, 100, 100, 200, 100)

        moves = [call.args for call in page.mouse.move.call_args_list]
        # Pre-click hover retains natural overshoot to the left.
        assert (90.0, 100.0) in moves
        # Once held, the physical slider cannot be released beyond its track.
        assert moves[-1] == (200, 100.0)
        page.mouse.down.assert_called_once()
        page.mouse.up.assert_called_once()
        solver.close()


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
            "x": 600,
            "y": 400,
            "width": 253,
            "height": 52,
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
            "x": 400,
            "y": 300,
            "width": 530,
            "height": 100,
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
            "Human verification challenge" if "document.title" in js else "Try Again"
        )
        btn_loc = MagicMock()
        btn_loc.count.return_value = 1
        btn_loc.first.bounding_box.return_value = {
            "x": 400,
            "y": 300,
            "width": 253,
            "height": 48,
        }
        px_frame.locator.return_value = btn_loc
        page.frames = [px_frame]
        mock_mono.side_effect = [0.0, 1.0]

        assert wait_for_px_solve(page, timeout=20.0) is False

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_navigation_exception_retries(self, mock_mono, mock_sleep):
        from wafer.browser._perimeterx import wait_for_px_solve

        page = MagicMock()
        # First: navigation error on url. Second: element gone.
        page.url = PropertyMock(side_effect=[Exception("Navigation"), "https://ok"])
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


class TestBaxiaViewport:
    def test_main_frame_is_not_screenxy_double_patched(self):
        from wafer.browser._drag import solve_baxia

        solver = MagicMock()
        solver._slide_recordings = [object()]
        page = MagicMock()

        with (
            patch(
                "wafer.browser._drag._find_baxia_frame",
                return_value=page,
            ),
            patch(
                "wafer.browser._drag._attempt_baxia_drag",
                return_value=True,
            ),
            patch(
                "wafer.browser._solver.patch_frame_screenxy",
            ) as screenxy_patch,
        ):
            assert solve_baxia(solver, page, 1000)

        screenxy_patch.assert_not_called()

    @pytest.mark.parametrize("needs_patch", [False, True])
    def test_child_frame_screenxy_patch_uses_immutable_probe_result(self, needs_patch):
        from wafer.browser._drag import solve_baxia

        solver = MagicMock()
        solver._slide_recordings = [object()]
        solver._needs_screenxy_patch = needs_patch
        page = MagicMock()
        frame = MagicMock()

        with (
            patch(
                "wafer.browser._drag._find_baxia_frame",
                return_value=frame,
            ),
            patch(
                "wafer.browser._drag._attempt_baxia_drag",
                return_value=True,
            ),
            patch(
                "wafer.browser._solver.patch_frame_screenxy",
            ) as screenxy_patch,
        ):
            assert solve_baxia(solver, page, 1000)

        screenxy_patch.assert_called_once_with(
            frame,
            needs_patch=needs_patch,
            timeout_ms=ANY,
        )

    def test_fresh_context_excludes_recent_rejected_drag_recording(self):
        from wafer.browser._drag import _attempt_baxia_drag

        solver = MagicMock()
        solver._start_browse.return_value = object()
        solver._drag_recordings = []
        solver._slide_recordings = []
        solver._baxia_recent_drag_recordings = []
        selected = iter(("slide-a.csv", "slide-b.csv"))
        exclusions = []

        def replay_drag(*args, **kwargs):
            exclusions.append(set(kwargs["exclude_recordings"]))
            solver._last_drag_recording_name = next(selected)
            return False

        solver._replay_drag.side_effect = replay_drag
        page = MagicMock()
        page.viewport_size = {"width": 1280, "height": 720}
        page.url = "https://acs.example.com/_____tmd_____/punish"
        geometry = (
            {"x": 100, "y": 200, "width": 42, "height": 30},
            258,
        )

        with (
            patch(
                "wafer.browser._drag._wait_for_baxia_geometry",
                return_value=(page, geometry),
            ),
            patch(
                "wafer.browser._drag._baxia_browser_environment",
                return_value=None,
            ),
            patch("wafer.browser._drag._log_baxia_diagnostic"),
            patch(
                "wafer.browser._drag._install_baxia_event_contract",
                return_value=False,
            ),
        ):
            for _ in range(2):
                assert (
                    _attempt_baxia_drag(
                        solver,
                        page,
                        page,
                        max_attempts=1,
                        issued_url=page.url,
                    )
                    is False
                )

        assert exclusions == [set(), {"slide-a.csv"}]
        assert solver._baxia_recent_drag_recordings == [
            "slide-a.csv",
            "slide-b.csv",
        ]

    @pytest.mark.parametrize(
        "redirected_url",
        [
            "https://www.alibaba.com/error",
            "https://www.alibaba.com/login",
            "https://www.alibaba.com/captcha/verify",
            "https://www.alibaba.com/other",
            "https://evil.example/finished",
        ],
    )
    def test_navigation_is_not_success_without_expected_callback(self, redirected_url):
        from wafer.browser._drag import _page_left_punish

        page = MagicMock()
        page.url = redirected_url
        issued = "https://acs.alibaba.com/_____tmd_____/punish?x5secdata=issued"

        assert _page_left_punish(page, issued) is False

    def test_only_exact_allowlisted_issued_callback_is_success(self):
        from wafer.browser._drag import _page_left_punish

        callback = "https://www.alibaba.com/trade/search?SearchText=wireless%20earbuds"
        issued = (
            "https://acs.alibaba.com/_____tmd_____/punish?"
            "x5secdata=issued&url=https%3A%2F%2Fwww.alibaba.com%2Ftrade%2F"
            "search%3FSearchText%3Dwireless%2520earbuds"
        )
        page = MagicMock()
        page.url = callback

        assert _page_left_punish(page, issued) is True
        page.url = callback + "&page=2"
        assert _page_left_punish(page, issued) is False

    def test_exact_application_target_requires_cleared_challenge(self):
        from wafer.browser._drag import _page_left_punish

        issued = (
            "https://www.aliexpress.com/w/wholesale-cable.html?"
            "SearchText=usb%20c&g=y#results"
        )
        page = MagicMock()
        page.url = (
            "https://www.aliexpress.com/w/wholesale-cable.html?"
            "SearchText=usb%20c&g=y#updated"
        )

        assert _page_left_punish(page, issued) is False
        assert (
            _page_left_punish(
                page,
                issued,
                challenge_gone=True,
            )
            is True
        )

    @pytest.mark.parametrize(
        "current_url",
        [
            "https://www.aliexpress.com/w/wholesale-cable.html?SearchText=other",
            "https://www.aliexpress.com/w/wholesale-cable.html?SearchText=usb%20c&g=n",
            "https://www.aliexpress.com/w/wholesale-other.html?SearchText=usb%20c&g=y",
            "https://login.aliexpress.com/w/wholesale-cable.html?SearchText=usb%20c&g=y",
            "https://aliexpress.com.evil.example/w/wholesale-cable.html?SearchText=usb%20c&g=y",
        ],
    )
    def test_application_target_rejects_any_route_or_origin_mutation(
        self,
        current_url,
    ):
        from wafer.browser._drag import _page_left_punish

        issued = (
            "https://www.aliexpress.com/w/wholesale-cable.html?SearchText=usb%20c&g=y"
        )
        page = MagicMock()
        page.url = current_url

        assert (
            _page_left_punish(
                page,
                issued,
                challenge_gone=True,
            )
            is False
        )

    @pytest.mark.parametrize(
        "issued",
        [
            "https://acs.aliexpress.com/not-punishment",
            "https://www.aliexpress.com/login",
            "https://www.aliexpress.com/error",
            "https://www.aliexpress.com/captcha/verify",
        ],
    )
    def test_application_target_rejects_infrastructure_and_failure_urls(
        self,
        issued,
    ):
        from wafer.browser._drag import _page_left_punish

        page = MagicMock()
        page.url = issued

        assert (
            _page_left_punish(
                page,
                issued,
                challenge_gone=True,
            )
            is False
        )

    def test_application_target_requires_baxia_handle_to_disappear(self):
        from wafer.browser._drag import _page_reached_baxia_target

        issued = "https://www.aliexpress.com/w/wholesale-cable.html"
        page = MagicMock()
        page.url = issued

        with patch(
            "wafer.browser._drag._find_baxia_frame",
            return_value=page,
        ):
            assert _page_reached_baxia_target(page, issued, None) is False
        with patch(
            "wafer.browser._drag._find_baxia_frame",
            return_value=None,
        ):
            assert _page_reached_baxia_target(page, issued, None) is True

    @pytest.mark.parametrize("leading_slash", ["/", "//"])
    def test_mtop_prefixed_issued_callback_is_success(self, leading_slash):
        from wafer.browser._drag import _page_left_punish

        callback = "https://www.aliexpress.com/item/1005001234567890.html"
        issued = (
            "https://acs.aliexpress.com"
            f"{leading_slash}h5/mtop.aliexpress.pdp.pc.query/1.0/"
            "_____tmd_____/punish?x5secdata=issued&"
            "url=https%3A%2F%2Fwww.aliexpress.com%2Fitem%2F"
            "1005001234567890.html"
        )
        page = MagicMock()
        page.url = callback

        assert _page_left_punish(page, issued) is True

    def test_issued_callback_rejects_cousin_domain_and_failure_paths(self):
        from wafer.browser._drag import _expected_baxia_callback

        cousin = (
            "https://acs.alibaba.com/_____tmd_____/punish?"
            "url=https%3A%2F%2Falibaba.com.evil.example%2Fproduct"
        )
        failure = (
            "https://acs.alibaba.com/_____tmd_____/punish?"
            "url=https%3A%2F%2Fwww.alibaba.com%2Ferror"
        )

        assert _expected_baxia_callback(cousin) is None
        assert _expected_baxia_callback(failure) is None

    @pytest.mark.parametrize(
        "issued",
        [
            (
                "http://acs.alibaba.com/_____tmd_____/punish?"
                "url=https%3A%2F%2Fwww.alibaba.com%2Fproduct"
            ),
            (
                "https://acs.alibaba.com/not-a-punish-page?"
                "url=https%3A%2F%2Fwww.alibaba.com%2Fproduct"
            ),
            (
                "https://acs.alibaba.com/_____tmd_____/punish?"
                "url=https%3A%2F%2Fwww.alibaba.com%3A444%2Fproduct"
            ),
        ],
    )
    def test_issued_callback_requires_strict_transport_and_path(self, issued):
        from wafer.browser._drag import _expected_baxia_callback

        assert _expected_baxia_callback(issued) is None

    def test_clearance_snapshot_is_target_scoped_and_value_sensitive(self):
        from wafer.browser._drag import _baxia_clearance_signatures

        page = MagicMock()
        page.context.cookies.return_value = [
            {
                "name": "x5sec",
                "value": "valid",
                "domain": ".alibaba.com",
                "path": "/",
                "expires": -1,
            },
            {
                "name": "x5sec",
                "value": "wrong-domain",
                "domain": ".evil.example",
                "path": "/",
                "expires": -1,
            },
            {
                "name": "x5sec",
                "value": "wrong-path",
                "domain": ".alibaba.com",
                "path": "/private",
                "expires": -1,
            },
            {
                "name": "analytics",
                "value": "not-clearance",
                "domain": ".alibaba.com",
                "path": "/",
                "expires": -1,
            },
            {
                "name": "x5sec",
                "value": "",
                "domain": ".alibaba.com",
                "path": "/",
                "expires": -1,
            },
        ]

        assert _baxia_clearance_signatures(
            page,
            "https://acs.alibaba.com/_____tmd_____/punish",
        ) == {("alibaba.com", "/", "valid")}

    def test_event_contract_is_off_by_default_and_explicitly_cleaned(self, monkeypatch):
        from wafer.browser._drag import (
            _clear_baxia_event_contract,
            _install_baxia_event_contract,
        )

        frame = MagicMock()
        frame.evaluate.return_value = True
        monkeypatch.delenv("WAFER_BAXIA_DIAGNOSTICS", raising=False)
        assert _install_baxia_event_contract(frame) is False
        frame.evaluate.assert_not_called()

        monkeypatch.setenv("WAFER_BAXIA_DIAGNOSTICS", "1")
        assert _install_baxia_event_contract(frame) is True
        install_script = frame.evaluate.call_args.args[0]
        assert "requestAnimationFrame" in install_script
        monkeypatch.delenv("WAFER_BAXIA_DIAGNOSTICS")
        _clear_baxia_event_contract(frame)
        clear_script = frame.evaluate.call_args.args[0]
        assert "cancelAnimationFrame" in clear_script
        assert "removeEventListener" in clear_script
        assert "delete window.__waferBaxiaEventContract" in clear_script

    def test_structural_diagnostic_is_opt_in_and_strips_raw_dom_values(
        self, monkeypatch
    ):
        from wafer.browser._drag import _baxia_structural_diagnostic

        frame = MagicMock()
        monkeypatch.delenv("WAFER_BAXIA_DIAGNOSTICS", raising=False)
        assert _baxia_structural_diagnostic(frame) is None
        frame.evaluate.assert_not_called()

        monkeypatch.setenv("WAFER_BAXIA_DIAGNOSTICS", "1")
        frame.evaluate.return_value = {
            "elementCount": 120,
            "shadowRootCount": 1,
            "iframeCount": 0,
            "canvasCount": 2,
            "svgCount": 3,
            "pageText": "secret challenge payload",
            "candidates": [
                {
                    "tag": "vendor-secret-element",
                    "idHash": "1234abcd",
                    "classHash": "deadbeef",
                    "classCount": 2,
                    "rawId": "session-secret",
                    "exact": {
                        "handle": True,
                        "fill": False,
                        "track": False,
                    },
                    "sliderRole": False,
                    "pointerHandler": True,
                    "visible": True,
                    "box": {
                        "x": 100,
                        "y": 200,
                        "width": 42,
                        "height": 30,
                    },
                }
            ],
        }

        result = _baxia_structural_diagnostic(frame)

        assert result == {
            "elementCount": 120,
            "shadowRootCount": 1,
            "iframeCount": 0,
            "canvasCount": 2,
            "svgCount": 3,
            "scripts": [],
            "candidates": [
                {
                    "tag": "other",
                    "idHash": "1234abcd",
                    "classHash": "deadbeef",
                    "classCount": 2,
                    "exact": {
                        "handle": True,
                        "fill": False,
                        "track": False,
                    },
                    "sliderRole": False,
                    "pointerHandler": True,
                    "visible": True,
                    "box": {
                        "x": 100,
                        "y": 200,
                        "width": 42,
                        "height": 30,
                    },
                }
            ],
        }
        assert "secret" not in repr(result)

    def test_diagnostic_screenshot_requires_absolute_explicit_directory(
        self, monkeypatch, tmp_path
    ):
        from wafer.browser._drag import (
            _capture_baxia_diagnostic_screenshot,
        )

        page = MagicMock()
        monkeypatch.setenv("WAFER_BAXIA_DIAGNOSTICS", "1")
        monkeypatch.delenv("WAFER_BAXIA_DIAGNOSTIC_DIR", raising=False)
        assert not _capture_baxia_diagnostic_screenshot(page, attempt=1, stage="before")
        page.screenshot.assert_not_called()

        monkeypatch.setenv("WAFER_BAXIA_DIAGNOSTIC_DIR", "relative")
        assert not _capture_baxia_diagnostic_screenshot(page, attempt=1, stage="before")
        page.screenshot.assert_not_called()

        diagnostic_dir = tmp_path / "baxia"
        monkeypatch.setenv(
            "WAFER_BAXIA_DIAGNOSTIC_DIR",
            str(diagnostic_dir),
        )

        def write_screenshot(**kwargs):
            Path(kwargs["path"]).write_bytes(b"diagnostic")

        page.screenshot.side_effect = write_screenshot
        assert _capture_baxia_diagnostic_screenshot(page, attempt=2, stage="rejected")
        [screenshot] = diagnostic_dir.iterdir()
        assert screenshot.name.endswith("-2-rejected.png")
        assert screenshot.stat().st_mode & 0o777 == 0o600
        assert page.screenshot.call_args.kwargs["full_page"] is False
        assert page.screenshot.call_args.kwargs["animations"] == "disabled"

    def test_baxia_browser_environment_is_geometry_only(self):
        from wafer.browser._drag import _baxia_browser_environment

        page = MagicMock()
        page.evaluate.return_value = {
            "screenX": 10,
            "screenY": 20,
            "outerWidth": 1000,
            "outerHeight": 800,
            "innerWidth": 990,
            "innerHeight": 700,
            "availWidth": 1920,
            "availHeight": 1080,
            "dpr": 1,
            "page_text": "must never be logged",
        }

        assert _baxia_browser_environment(page) == {
            "screenX": 10.0,
            "screenY": 20.0,
            "outerWidth": 1000.0,
            "outerHeight": 800.0,
            "innerWidth": 990.0,
            "innerHeight": 700.0,
            "availWidth": 1920.0,
            "availHeight": 1080.0,
            "dpr": 1.0,
        }
        assert "document" not in page.evaluate.call_args.args[0]

    def test_baxia_frame_lookup_without_deadline_has_bounded_wait(self):
        from wafer.browser._drag import _find_baxia_frame

        page = MagicMock()
        page.wait_for_selector.side_effect = TimeoutError
        frame = MagicMock()
        frame.url = "https://acs.example.com/_____tmd_____/punish"
        frame.wait_for_selector.side_effect = TimeoutError
        page.main_frame = MagicMock()
        page.frames = [page.main_frame, frame]

        assert _find_baxia_frame(page) is None
        frame.wait_for_load_state.assert_not_called()
        assert page.wait_for_selector.call_args.kwargs["timeout"] == 250
        assert frame.wait_for_selector.call_args.kwargs["timeout"] == 100

    def test_baxia_rejection_diagnostic_contains_no_page_content(self):
        from wafer.browser._drag import _baxia_rejection_diagnostic

        frame = MagicMock()
        frame.evaluate.return_value = {
            "handle": True,
            "handleLeft": 258,
            "fillWidth": 258,
            "trackWidth": 300,
            "explicitError": True,
            "unexpected_page_text": "session=secret",
        }

        assert _baxia_rejection_diagnostic(frame) == {
            "handle": True,
            "handleLeft": 258,
            "fillWidth": 258,
            "trackWidth": 300,
            "explicitError": True,
            "errorCategory": None,
            "errorCode": None,
        }

    def test_baxia_rejection_preserves_only_bounded_sdk_error_code(self):
        from wafer.browser._drag import _check_baxia_result

        frame = MagicMock()
        frame.evaluate.return_value = {
            "state": "rejected",
            "category": "sdk_error_code",
            "code": "NC_1001",
            "page_text": "never retain this challenge content",
        }
        rejection = {}

        assert (
            _check_baxia_result(frame, saw_movement=True, rejection=rejection) is False
        )
        assert rejection == {
            "category": "sdk_error_code",
            "code": "NC_1001",
        }

    def test_baxia_rejection_discards_unbounded_sdk_error_code(self):
        from wafer.browser._drag import _check_baxia_result

        frame = MagicMock()
        frame.evaluate.return_value = {
            "state": "rejected",
            "category": "sdk_error_code",
            "code": "not safe because it contains whitespace",
        }
        rejection = {}

        assert (
            _check_baxia_result(frame, saw_movement=True, rejection=rejection) is False
        )
        assert rejection == {"category": "sdk_error_code", "code": None}

    def test_live_chrome150_rejection_fixture_replays_fail_closed(self):
        from wafer.browser._drag import (
            _check_baxia_result,
            _get_baxia_geometry,
        )

        fixture_path = (
            Path(__file__).parent
            / "fixtures"
            / "baxia_alibaba_chrome150_rejection.json"
        )
        fixture = json.loads(fixture_path.read_text())
        frame = MagicMock()
        frame.evaluate.return_value = {
            "handle": fixture["before"]["handle"],
            "trackWidth": fixture["before"]["trackWidth"],
        }

        assert _get_baxia_geometry(frame) == (
            fixture["before"]["handle"],
            fixture["event_contract"]["maxHandleLeft"],
        )

        frame.evaluate.return_value = fixture["rejection"]
        rejection = {}
        assert (
            _check_baxia_result(
                frame,
                saw_movement=True,
                rejection=rejection,
            )
            is False
        )
        assert rejection == {
            "category": "sdk_error_code",
            "code": "gddtf",
        }
        assert fixture["event_contract"]["pointerDown"]["trusted"] is True
        assert fixture["event_contract"]["pointerUp"]["trusted"] is True
        assert fixture["event_contract"]["counts"] == {
            "pointerdown": 1,
            "pointermove": 260,
            "pointerup": 1,
            "mousedown": 1,
            "mousemove": 260,
            "mouseup": 1,
        }
        assert fixture["transport"]["newClearance"] is False

    def test_baxia_geometry_rejects_collapsed_reload_shell(self):
        from wafer.browser._drag import _get_baxia_geometry

        frame = MagicMock()
        frame.evaluate.return_value = {
            "handle": {"x": 0, "y": 0, "width": 0, "height": 0},
            "trackWidth": 0,
        }

        assert _get_baxia_geometry(frame) is None

    def test_baxia_geometry_accepts_laid_out_widget(self):
        from wafer.browser._drag import _get_baxia_geometry

        frame = MagicMock()
        frame.evaluate.return_value = {
            "handle": {"x": 123, "y": 456, "width": 42, "height": 40},
            "trackWidth": 300,
        }

        assert _get_baxia_geometry(frame) == (
            {"x": 123, "y": 456, "width": 42, "height": 40},
            258,
        )

    def test_live_baxia_geometry_uses_protocol_bounded_locator_evaluate(
        self,
    ):
        from wafer.browser._drag import _get_baxia_geometry

        frame = MagicMock()
        locator = frame.locator.return_value
        locator.evaluate.return_value = {
            "handle": {"x": 123, "y": 456, "width": 42, "height": 40},
            "trackWidth": 300,
        }

        assert _get_baxia_geometry(
            frame,
            deadline=time.monotonic() + 2,
        ) == (
            {"x": 123, "y": 456, "width": 42, "height": 40},
            258,
        )
        frame.evaluate.assert_not_called()
        frame.locator.assert_called_once_with("html")
        timeout = locator.evaluate.call_args.kwargs["timeout"]
        assert 0 < timeout <= 1_000

    @patch("time.sleep")
    @patch("wafer.browser._drag._check_baxia_result", return_value=True)
    @patch(
        "wafer.browser._drag._get_baxia_geometry",
        return_value=(
            {"x": 100, "y": 200, "width": 42, "height": 30},
            258,
        ),
    )
    def test_native_window_context_measures_none_viewport(
        self,
        mock_geometry,
        mock_result,
        mock_sleep,
    ):
        from wafer.browser._drag import _attempt_baxia_drag

        solver = MagicMock()
        solver._start_browse.return_value = object()
        solver._drag_recordings = []
        solver._slide_recordings = []
        page = MagicMock()
        page.viewport_size = None
        page.url = "https://acs.alibaba.com/_____tmd_____/punish"
        page.evaluate.return_value = {"width": 1440, "height": 900}
        page.context.cookies.side_effect = [
            [],
            [
                {
                    "name": "x5sec",
                    "value": "new-clearance",
                    "domain": ".alibaba.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
        ]

        assert (
            _attempt_baxia_drag(
                solver,
                page,
                page,
                max_attempts=1,
                issued_url=page.url,
            )
            is True
        )
        page.evaluate.assert_any_call(
            "() => ({width: window.innerWidth, height: window.innerHeight})"
        )
        browse_args = solver._start_browse.call_args.args
        assert browse_args[0] is page
        assert 0 < browse_args[1] < 1440
        assert 0 < browse_args[2] < 900
        solver._replay_drag.assert_called_once()

    @patch("time.sleep")
    @patch("wafer.browser._drag._check_baxia_result", return_value=True)
    @patch(
        "wafer.browser._drag._get_baxia_geometry",
        return_value=(
            {"x": 100, "y": 200, "width": 42, "height": 30},
            258,
        ),
    )
    def test_widget_success_is_intermediate_without_sync_cookie_poll(
        self,
        mock_geometry,
        mock_result,
        mock_sleep,
    ):
        from wafer.browser._drag import _attempt_baxia_drag

        solver = MagicMock()
        solver._start_browse.return_value = object()
        solver._replay_path.return_value = True
        solver._replay_drag.return_value = True
        solver._drag_recordings = []
        solver._slide_recordings = []
        page = MagicMock()
        page.viewport_size = {"width": 1280, "height": 720}
        page.url = "https://acs.alibaba.com/_____tmd_____/punish"
        page.context.cookies.return_value = []

        assert (
            _attempt_baxia_drag(
                solver,
                page,
                page,
                max_attempts=1,
                issued_url=page.url,
            )
            is True
        )
        page.context.cookies.assert_not_called()

    def test_fill_width_alone_is_never_authoritative_success(self):
        from wafer.browser._drag import _check_baxia_result

        frame = MagicMock()
        frame.evaluate.return_value = None

        assert _check_baxia_result(frame, saw_movement=True) is None
        script = frame.evaluate.call_args.args[0]
        assert "trackW * 0.85" not in script
        assert "dataset.solved" in script
        assert "includes('success')" in script
        assert "return sawMovement ? false : null" not in script
        assert "return {state: 'pending'};" in script

    def test_disappearing_widget_is_pending_not_a_rejection(self):
        from wafer.browser._drag import _check_baxia_result

        frame = MagicMock()
        frame.evaluate.return_value = None

        assert _check_baxia_result(frame, saw_movement=True) is None
        script = frame.evaluate.call_args.args[0]
        missing_handle = script.split("if (!handle)", 1)[1].split("}", 1)[0]
        assert "return {state: 'pending'" in missing_handle
        assert "state: 'rejected'" not in missing_handle

    def test_explicit_vendor_error_remains_a_rejection(self):
        from wafer.browser._drag import _check_baxia_result

        frame = MagicMock()
        frame.evaluate.return_value = False

        assert _check_baxia_result(frame, saw_movement=True) is False
        script = frame.evaluate.call_args.args[0]
        assert "something's wrong" in script
        assert "please refresh and try again" in script
        assert "state: 'rejected'" in script
        assert r"\\berror\\s*:\\s*" in script
        assert "\x08" not in script

    @patch(
        "wafer.browser._drag._get_baxia_geometry",
        return_value=(
            {"x": 100, "y": 200, "width": 42, "height": 30},
            258,
        ),
    )
    @patch("wafer.browser._drag._baxia_has_movement", return_value=True)
    @patch("wafer.browser._drag._check_baxia_result", return_value=None)
    def test_attempt_never_exceeds_absolute_deadline(
        self,
        mock_result,
        mock_movement,
        mock_geometry,
    ):
        from wafer.browser._drag import _attempt_baxia_drag

        clock = [0.0]

        def monotonic():
            return clock[0]

        def sleep(duration):
            clock[0] += duration

        solver = MagicMock()
        solver._start_browse.return_value = object()
        solver._replay_path.return_value = True
        solver._replay_drag.return_value = True
        solver._drag_recordings = []
        solver._slide_recordings = []
        page = MagicMock()
        page.viewport_size = {"width": 1280, "height": 720}
        page.url = "https://example.com/_____tmd_____/punish"

        with (
            patch("wafer.browser._drag.time.monotonic", side_effect=monotonic),
            patch("wafer.browser._drag.time.sleep", side_effect=sleep),
        ):
            assert (
                _attempt_baxia_drag(
                    solver,
                    page,
                    page,
                    deadline=1.0,
                    issued_url=page.url,
                )
                is False
            )

        assert clock[0] <= 1.0

    @pytest.mark.parametrize(
        ("issued_url", "refresh_method"),
        [
            (
                "https://acs.aliexpress.com/_____tmd_____/punish",
                "reload",
            ),
            (
                "https://www.aliexpress.com/w/wholesale-cable.html",
                "goto",
            ),
        ],
    )
    def test_rejected_destroyed_widget_refreshes_and_retries(
        self,
        issued_url,
        refresh_method,
    ):
        from wafer.browser._drag import _attempt_baxia_drag

        solver = MagicMock()
        solver._start_browse.return_value = object()
        solver._replay_path.return_value = True
        solver._replay_drag.return_value = True
        solver._drag_recordings = []
        solver._slide_recordings = []
        page = MagicMock()
        page.viewport_size = {"width": 1280, "height": 720}
        page.url = "https://example.com/_____tmd_____/punish"

        with (
            patch(
                "wafer.browser._drag._get_baxia_geometry",
                return_value=(
                    {"x": 100, "y": 200, "width": 42, "height": 30},
                    258,
                ),
            ),
            patch(
                "wafer.browser._drag._baxia_has_movement",
                return_value=True,
            ),
            patch(
                "wafer.browser._drag._check_baxia_result",
                side_effect=[False, True],
            ),
            patch(
                "wafer.browser._drag._find_baxia_frame",
                side_effect=[None, None, None, None, page, page],
            ),
            patch(
                "wafer.browser._drag._sleep_with_deadline",
                return_value=True,
            ),
            patch(
                "wafer.browser._drag._page_left_punish",
                return_value=False,
            ),
            patch(
                "wafer.browser._drag._baxia_clearance_signatures",
                side_effect=[
                    set(),
                    set(),
                    set(),
                    {("alibaba.com", "/", "new-clearance")},
                ],
            ),
            patch(
                "wafer.browser._solver.patch_frame_screenxy",
            ),
        ):
            assert (
                _attempt_baxia_drag(
                    solver,
                    page,
                    page,
                    issued_url=issued_url,
                )
                is True
            )

        expected_kwargs = {
            "wait_until": "commit",
            "timeout": 5_000,
        }
        if refresh_method == "reload":
            page.reload.assert_called_once_with(**expected_kwargs)
            page.goto.assert_not_called()
        else:
            page.goto.assert_called_once_with(
                issued_url,
                **expected_kwargs,
            )
            page.reload.assert_not_called()
        assert solver._replay_drag.call_count == 2


class TestBrowserSolverThreadOwnership:
    def test_timed_out_worker_clears_readiness_then_next_solve_recovers(
        self,
    ):
        solver = BrowserSolver()
        browser = MagicMock()
        browser.is_connected.return_value = True
        solver._browser = browser
        solver._runtime_ready.set()
        released = threading.Event()
        driver = MagicMock()
        driver.returncode = None
        driver.terminate.side_effect = released.set
        transport = SimpleNamespace(_proc=driver)
        connection = SimpleNamespace(_transport=transport)
        solver._playwright = SimpleNamespace(
            _impl_obj=SimpleNamespace(_connection=connection)
        )
        recovered = object()
        calls = 0

        def operation(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                assert released.wait(timeout=5)
                time.sleep(0.1)
                return object()
            return recovered

        with patch.object(
            solver,
            "_solve_on_worker",
            side_effect=operation,
        ):
            assert (
                solver.solve(
                    "https://www.alibaba.com/",
                    timeout=0.02,
                )
                is None
            )
            assert solver.runtime_ready is False
            assert (
                solver.solve(
                    "https://www.alibaba.com/",
                    timeout=1,
                )
                is recovered
            )

        assert calls == 2
        driver.terminate.assert_called_once_with()
        assert solver.runtime_ready is True
        assert solver.close(timeout=1) is True

    def test_timed_out_intercept_recovers_the_serial_worker(self):
        """A stalled intercept must release the worker like a stalled solve.

        cancel() cannot stop an already-running task, so without recovery the
        single worker stays occupied and every later solve blocks forever.
        """
        solver = BrowserSolver()
        browser = MagicMock()
        browser.is_connected.return_value = True
        solver._browser = browser
        solver._runtime_ready.set()
        released = threading.Event()
        driver = MagicMock()
        driver.returncode = None
        driver.terminate.side_effect = released.set
        solver._playwright = SimpleNamespace(
            _impl_obj=SimpleNamespace(
                _connection=SimpleNamespace(
                    _transport=SimpleNamespace(_proc=driver)
                )
            )
        )
        recovered = object()
        calls = 0

        def operation(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                assert released.wait(timeout=5)
                time.sleep(0.1)
                return object()
            return recovered

        with patch.object(
            solver,
            "_intercept_iframe_on_worker",
            side_effect=operation,
        ):
            assert (
                solver.intercept_iframe(
                    "https://www.example.com/",
                    "example.com",
                    timeout=0.02,
                )
                is None
            )
            assert solver.runtime_ready is False
            assert (
                solver.intercept_iframe(
                    "https://www.example.com/",
                    "example.com",
                    timeout=1,
                )
                is recovered
            )

        assert calls == 2
        driver.terminate.assert_called_once_with()
        assert solver.runtime_ready is True
        assert solver.close(timeout=1) is True

    def test_close_timeout_does_not_wait_for_busy_browser_worker(self):
        solver = BrowserSolver()
        entered = threading.Event()
        release = threading.Event()

        def busy_worker():
            entered.set()
            release.wait(timeout=2)

        solver._executor.submit(busy_worker)
        assert entered.wait(timeout=1)

        started = time.monotonic()
        assert solver.close(timeout=0.01) is False
        elapsed = time.monotonic() - started
        assert solver.close(timeout=0.01) is False
        release.set()

        assert elapsed < 0.5
        assert solver.close(timeout=1) is True

    def test_timed_out_close_does_not_hold_interpreter_shutdown(self):
        """A stuck browser callback must not be joined again by CPython exit."""

        script = textwrap.dedent("""
            import threading
            from wafer.browser import BrowserSolver

            solver = BrowserSolver()
            entered = threading.Event()
            solver._executor.submit(lambda: (entered.set(), threading.Event().wait(30)))
            assert entered.wait(1)
            assert solver.close(timeout=0.01) is False
        """)
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=Path(__file__).parents[1],
            capture_output=True,
            text=True,
            # A real executor-shutdown regression blocks for the callback's
            # full 30 seconds. Allow ordinary process-start scheduling under
            # a loaded full-suite runner without weakening that distinction.
            timeout=2.0,
            check=False,
        )

        assert completed.returncode == 0, completed.stderr

    def test_close_rejects_negative_timeout(self):
        solver = BrowserSolver()
        try:
            with pytest.raises(ValueError, match="non-negative"):
                solver.close(timeout=-0.1)
        finally:
            solver.close()

    def test_gc_finalizer_cannot_submit_or_lock_executor(self):
        # ThreadPoolExecutor.submit takes a process-global non-reentrant lock.
        # Calling it from __del__ can self-deadlock if GC runs re-entrantly
        # while another submit already owns that lock. Cleanup is therefore an
        # explicit ownership operation; BrowserSolver must have no finalizer.
        assert "__del__" not in BrowserSolver.__dict__

    @pytest.mark.asyncio
    async def test_preflight_sync_async_solve_and_close_share_one_worker(self):
        from concurrent.futures import ThreadPoolExecutor

        solver = BrowserSolver()
        solver._needs_screenxy_patch = False
        thread_ids = []

        def record(value=None):
            thread_ids.append(threading.get_ident())
            return value

        with (
            patch.object(solver, "_ensure_browser", side_effect=record),
            patch.object(
                solver,
                "_solve_on_worker",
                side_effect=lambda *_args, **_kwargs: record("solved"),
            ),
            patch.object(
                solver,
                "_close_browser",
                side_effect=lambda: record(None),
            ),
        ):
            solver.preflight()
            with ThreadPoolExecutor(max_workers=2) as callers:
                futures = [
                    callers.submit(
                        solver.solve,
                        f"https://example.com/{index}",
                    )
                    for index in range(2)
                ]
                assert [future.result() for future in futures] == [
                    "solved",
                    "solved",
                ]
            assert await solver.asolve("https://example.com/async") == "solved"
            solver.close()

        assert len(thread_ids) == 5
        assert len(set(thread_ids)) == 1

    def test_sync_solve_timeout_includes_worker_queue_wait(self):
        solver = BrowserSolver()
        blocker_started = threading.Event()
        release_blocker = threading.Event()

        def block_worker():
            blocker_started.set()
            release_blocker.wait(timeout=1)

        blocker = solver._submit_on_worker(block_worker)
        assert blocker_started.wait(timeout=1)
        with patch.object(
            solver,
            "_ensure_browser",
            side_effect=AssertionError("expired solve must not launch"),
        ) as ensure:
            started = time.monotonic()
            result = solver.solve("https://example.com/", timeout=0.05)
            elapsed = time.monotonic() - started
            assert result is None
            assert elapsed < 0.2
            release_blocker.set()
            blocker.result(timeout=1)
            solver._submit_on_worker(lambda: None).result(timeout=1)
            ensure.assert_not_called()
        solver.close()

    @pytest.mark.asyncio
    async def test_async_solve_timeout_includes_worker_queue_wait(self):
        solver = BrowserSolver()
        blocker_started = threading.Event()
        release_blocker = threading.Event()

        def block_worker():
            blocker_started.set()
            release_blocker.wait(timeout=1)

        blocker = solver._submit_on_worker(block_worker)
        assert blocker_started.wait(timeout=1)
        started = time.monotonic()
        result = await solver.asolve("https://example.com/", timeout=0.05)
        elapsed = time.monotonic() - started
        assert result is None
        assert elapsed < 0.2
        release_blocker.set()
        blocker.result(timeout=1)
        solver.close()

    @pytest.mark.asyncio
    async def test_async_caller_cancellation_reports_running_worker(self, caplog):
        solver = BrowserSolver()
        started = threading.Event()
        release = threading.Event()

        def slow_solve(*_args, **_kwargs):
            started.set()
            release.wait(timeout=1)
            return None

        caplog.set_level(logging.WARNING, logger="wafer")
        try:
            with patch.object(solver, "_solve_on_worker", side_effect=slow_solve):
                task = asyncio.create_task(
                    solver.asolve(
                        "https://example.com/",
                        "tmd",
                        timeout=1,
                    )
                )
                assert await asyncio.to_thread(started.wait, 1)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert "challenge_type=tmd worker_continues=True" in caplog.text
                release.set()
                drain = solver._submit_on_worker(lambda: None)
                await asyncio.to_thread(drain.result, 1)
        finally:
            release.set()
            solver.close()

    def test_iframe_timeout_includes_worker_queue_wait(self):
        solver = BrowserSolver()
        blocker_started = threading.Event()
        release_blocker = threading.Event()

        def block_worker():
            blocker_started.set()
            release_blocker.wait(timeout=1)

        blocker = solver._submit_on_worker(block_worker)
        assert blocker_started.wait(timeout=1)
        started = time.monotonic()
        result = solver.intercept_iframe(
            "https://example.com/",
            "example.com",
            timeout=0.05,
        )
        elapsed = time.monotonic() - started
        assert result is None
        assert elapsed < 0.2
        release_blocker.set()
        blocker.result(timeout=1)
        solver._submit_on_worker(lambda: None).result(timeout=1)
        solver.close()

    def test_close_clears_worker_identity_and_rejects_future_work(self):
        solver = BrowserSolver()
        solver._run_on_worker(lambda: None)
        assert solver._worker_ident is not None

        solver.close()

        assert solver._worker_ident is None
        with pytest.raises(RuntimeError, match="closed"):
            solver.solve("https://example.com/")

    def test_generic_settle_respects_timeout(self):
        solver = BrowserSolver()
        page = MagicMock()
        started = time.monotonic()
        try:
            assert solver._wait_for_generic(page, 20) is False
        finally:
            solver.close()
        assert time.monotonic() - started < 0.2

    def test_navigation_cannot_consume_the_whole_solve_budget(self):
        """A stalled interstitial must leave time for the solver.

        page.goto() used to get the entire remaining deadline, so a WAF page
        that never fires domcontentloaded burned the whole budget in
        navigation and the solver never ran -- seen live as a 295s DataDome
        "solve" that logged nothing at all.
        """
        import time as _time

        from wafer.browser._solver import _MAX_NAVIGATION_MS, _navigation_budget_ms

        now = _time.monotonic()
        # Long budgets are capped outright...
        assert _navigation_budget_ms(now + 300) == _MAX_NAVIGATION_MS
        # ...and short ones still leave half for solving.
        assert _navigation_budget_ms(now + 30) <= 15_000
        assert _navigation_budget_ms(now + 10) <= 5_000
        # Never zero or negative: goto() rejects a non-positive timeout.
        assert _navigation_budget_ms(now - 5) >= 1

    def test_generic_wait_survives_a_page_that_never_goes_idle(self):
        """Persistent traffic must not fail an otherwise-fine solve.

        Analytics beacons, websockets and long-polls mean "networkidle" may
        never fire. When that wait was given the whole budget it consumed
        everything, the JS settle was skipped, and the solve reported failure
        on a page that had already cleared.
        """
        solver = BrowserSolver()
        page = MagicMock()
        idle_waits = []

        def never_idle(state, timeout=None):
            idle_waits.append((state, timeout))
            raise TimeoutError("networkidle never fired")

        page.wait_for_load_state.side_effect = never_idle
        try:
            assert solver._wait_for_generic(page, 5000) is True
        finally:
            solver.close()

        # The idle wait is capped at half the budget rather than given all of
        # it, and its failure no longer aborts the solve.
        assert idle_waits and idle_waits[0][1] <= 2500


class TestBrowserNavigationSizeLimit:
    @staticmethod
    def _guard(limit=100, main_frame_id=None):
        page = MagicMock()
        cdp = MagicMock()
        page.context.new_cdp_session.return_value = cdp
        if main_frame_id is not None:
            cdp.send.side_effect = lambda method: (
                {"frameTree": {"frame": {"id": main_frame_id}}}
                if method == "Page.getFrameTree"
                else None
            )
        handlers = {}
        cdp.on.side_effect = lambda event, handler: handlers.__setitem__(event, handler)
        state = BrowserSolver._install_navigation_size_limit(page, limit)
        return cdp, handlers, state

    def test_declared_oversize_document_stops_before_body(self):
        cdp, handlers, state = self._guard(100)
        handlers["Network.requestWillBeSent"]({"type": "Document", "requestId": "main"})
        handlers["Network.responseReceived"](
            {
                "requestId": "main",
                "response": {"headers": {"Content-Length": "101"}},
            }
        )

        assert state["exceeded"] is True
        cdp.send.assert_any_call("Page.stopLoading")

    def test_streamed_decoded_bytes_stop_at_limit(self):
        cdp, handlers, state = self._guard(100)
        handlers["Network.requestWillBeSent"]({"type": "Document", "requestId": "main"})
        handlers["Network.dataReceived"](
            {
                "requestId": "main",
                "dataLength": 60,
                "encodedDataLength": 20,
            }
        )
        handlers["Network.dataReceived"](
            {
                "requestId": "main",
                "dataLength": 41,
                "encodedDataLength": 20,
            }
        )

        assert state["exceeded"] is True
        assert (
            sum(call.args == ("Page.stopLoading",) for call in cdp.send.call_args_list)
            == 1
        )

    def test_subresources_do_not_consume_document_budget(self):
        cdp, handlers, state = self._guard(100)
        handlers["Network.requestWillBeSent"]({"type": "Image", "requestId": "asset"})
        handlers["Network.dataReceived"](
            {
                "requestId": "asset",
                "dataLength": 10_000,
                "encodedDataLength": 10_000,
            }
        )

        assert state["exceeded"] is False
        assert not any(
            call.args == ("Page.stopLoading",) for call in cdp.send.call_args_list
        )

    def test_uncapped_navigation_installs_no_hidden_limit(self):
        page = MagicMock()

        state = BrowserSolver._install_navigation_size_limit(page, None)

        assert state["exceeded"] is False
        page.context.new_cdp_session.assert_not_called()

    def test_uncapped_page_content_skips_length_probe(self):
        page = MagicMock()
        page.content.return_value = "<html>" + ("x" * 11_000_000) + "</html>"

        html = BrowserSolver._bounded_page_content(page, None)

        assert len(html) > 10 * 1024 * 1024
        page.evaluate.assert_not_called()

    def test_iframe_document_does_not_consume_main_document_budget(self):
        cdp, handlers, state = self._guard(100)
        handlers["Network.requestWillBeSent"]({"type": "Document", "requestId": "main"})
        handlers["Network.requestWillBeSent"](
            {"type": "Document", "requestId": "iframe"}
        )
        handlers["Network.dataReceived"](
            {
                "requestId": "iframe",
                "dataLength": 10_000,
                "encodedDataLength": 10_000,
            }
        )

        assert state["exceeded"] is False
        assert state["documents"] == {"main"}
        assert not any(
            call.args == ("Page.stopLoading",) for call in cdp.send.call_args_list
        )

    def test_main_frame_identity_wins_when_iframe_document_arrives_first(self):
        cdp, handlers, state = self._guard(100, main_frame_id="top")
        handlers["Network.requestWillBeSent"](
            {
                "type": "Document",
                "requestId": "iframe",
                "frameId": "child",
            }
        )
        handlers["Network.dataReceived"](
            {
                "requestId": "iframe",
                "dataLength": 10_000,
                "encodedDataLength": 10_000,
            }
        )
        handlers["Network.requestWillBeSent"](
            {
                "type": "Document",
                "requestId": "main",
                "frameId": "top",
            }
        )

        assert state["documents"] == {"main"}
        assert state["exceeded"] is False
        assert not any(
            call.args == ("Page.stopLoading",) for call in cdp.send.call_args_list
        )

    def test_unresolved_frame_tree_does_not_guess_identified_iframe(self):
        page = MagicMock()
        cdp = MagicMock()
        page.context.new_cdp_session.return_value = cdp

        def send(method):
            if method == "Page.getFrameTree":
                raise RuntimeError("unsupported")
            return None

        cdp.send.side_effect = send
        handlers = {}
        cdp.on.side_effect = lambda event, handler: handlers.__setitem__(event, handler)
        state = BrowserSolver._install_navigation_size_limit(page, 100)

        handlers["Network.requestWillBeSent"](
            {
                "type": "Document",
                "requestId": "iframe",
                "frameId": "unknown-child",
            }
        )
        handlers["Network.dataReceived"](
            {
                "requestId": "iframe",
                "dataLength": 10_000,
                "encodedDataLength": 10_000,
            }
        )

        assert state["documents"] == set()
        assert state["exceeded"] is False

    def test_main_frame_auto_reload_gets_its_own_transfer_budget(self):
        cdp, handlers, state = self._guard(100, main_frame_id="top")
        handlers["Network.requestWillBeSent"](
            {
                "type": "Document",
                "requestId": "challenge",
                "frameId": "top",
            }
        )
        handlers["Network.dataReceived"](
            {
                "requestId": "challenge",
                "dataLength": 50,
                "encodedDataLength": 50,
            }
        )
        handlers["Network.requestWillBeSent"](
            {
                "type": "Document",
                "requestId": "final",
                "frameId": "top",
            }
        )
        handlers["Network.dataReceived"](
            {
                "requestId": "final",
                "dataLength": 101,
                "encodedDataLength": 80,
            }
        )

        assert state["documents"] == {"challenge", "final"}
        assert state["exceeded"] is True
        cdp.send.assert_any_call("Page.stopLoading")

    def test_decoded_and_encoded_totals_are_not_cross_summed(self):
        _cdp, handlers, state = self._guard(150)
        handlers["Network.requestWillBeSent"]({"type": "Document", "requestId": "main"})
        handlers["Network.dataReceived"](
            {
                "requestId": "main",
                "dataLength": 100,
                "encodedDataLength": 1,
            }
        )
        handlers["Network.dataReceived"](
            {
                "requestId": "main",
                "dataLength": 1,
                "encodedDataLength": 100,
            }
        )

        assert state["sizes"]["main"] == {
            "decoded": 101,
            "encoded": 101,
        }
        assert state["exceeded"] is False


class TestBrowserSolverFailClosed:
    def test_clearance_poll_never_sleeps_negative_at_deadline(self):
        from wafer.browser._solver import _sleep_before_deadline

        with (
            patch(
                "wafer.browser._solver.time.monotonic",
                return_value=10.000001,
            ),
            patch("wafer.browser._solver.time.sleep") as sleep,
        ):
            assert not _sleep_before_deadline(10.0, 0.2)

        sleep.assert_not_called()

    @staticmethod
    def _pending_tmd_solver(clearance):
        solver = BrowserSolver(solve_timeout=1)
        solver._browser = MagicMock()
        solver._browser.is_connected.return_value = True
        solver._browser_ua = "Chrome/149"
        solver._needs_screenxy_patch = False

        context = MagicMock()
        page = MagicMock()
        context.new_page.return_value = page
        context.cookies.side_effect = [[], [clearance]]
        return solver, context

    def test_pending_widget_accepts_new_target_clearance_sync(
        self,
        monkeypatch,
        caplog,
    ):
        issued = (
            "https://acs.aliexpress.com/h5/"
            "mtop.aliexpress.pdp.pc.query/1.0/_____tmd_____/punish?"
            "action=captcharecaptcha&x5secdata=issued-token&"
            "url=https%3A%2F%2Fwww.aliexpress.com%2Fitem%2F1.html"
        )
        clearance = {
            "name": "x5sec",
            "value": "browser-minted",
            "domain": ".aliexpress.com",
            "path": "/h5/",
            "expires": time.time() + 60,
        }
        solver, context = self._pending_tmd_solver(clearance)
        monkeypatch.setenv("WAFER_TMD_DIAGNOSTICS", "1")

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=False,
                ),
                caplog.at_level(logging.INFO, logger="wafer"),
            ):
                result = solver.solve(issued, "tmd", timeout=1)
        finally:
            solver.close()

        assert result is not None
        assert result.cookies == [clearance]
        assert "widget_solved=False x5sec_target_new_or_changed=True" in caplog.text

    async def test_pending_widget_accepts_new_target_clearance_async(self):
        issued = (
            "https://acs.aliexpress.com/h5/"
            "mtop.aliexpress.pdp.pc.query/1.0/_____tmd_____/punish?"
            "action=captcharecaptcha&x5secdata=issued-token&"
            "url=https%3A%2F%2Fwww.aliexpress.com%2Fitem%2F1.html"
        )
        clearance = {
            "name": "x5sec",
            "value": "browser-minted",
            "domain": ".aliexpress.com",
            "path": "/h5/",
            "expires": time.time() + 60,
        }
        solver, context = self._pending_tmd_solver(clearance)

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=False,
                ),
            ):
                result = await solver.asolve(issued, "tmd", timeout=1)
        finally:
            solver.close()

        assert result is not None
        assert result.cookies == [clearance]

    @pytest.mark.parametrize("widget_solved", [False, True])
    @pytest.mark.parametrize(
        ("domain", "path"),
        [
            (".example.com", "/h5/"),
            (".aliexpress.com", "/wrong/"),
        ],
    )
    def test_tmd_wrong_scope_never_passes(
        self,
        widget_solved,
        domain,
        path,
        monkeypatch,
        caplog,
    ):
        issued = (
            "https://acs.aliexpress.com/h5/"
            "mtop.aliexpress.pdp.pc.query/1.0/_____tmd_____/punish?"
            "action=captcharecaptcha&x5secdata=issued-token&"
            "url=https%3A%2F%2Fwww.aliexpress.com%2Fitem%2F1.html"
        )
        wrong_scope = {
            "name": "x5sec",
            "value": "browser-minted",
            "domain": domain,
            "path": path,
            "expires": time.time() + 60,
        }
        solver = BrowserSolver(solve_timeout=0.01)
        solver._browser = MagicMock()
        solver._browser.is_connected.return_value = True
        solver._browser_ua = "Chrome/149"
        solver._needs_screenxy_patch = False
        context = MagicMock()
        context.new_page.return_value = MagicMock()
        cookie_reads = iter([[], [wrong_scope]])

        def cookies():
            return next(cookie_reads, [wrong_scope])

        context.cookies.side_effect = cookies
        monkeypatch.setenv("WAFER_TMD_DIAGNOSTICS", "1")

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=widget_solved,
                ),
                caplog.at_level(logging.INFO, logger="wafer"),
            ):
                result = solver._solve_on_worker(issued, "tmd", timeout=0.01)
        finally:
            solver.close()

        assert result is None
        assert (
            f"widget_solved={widget_solved} "
            "x5sec_target_new_or_changed=False"
        ) in caplog.text

    def test_tmd_unchanged_target_clearance_never_passes_even_when_widget_solved(
        self,
    ):
        issued = (
            "https://acs.aliexpress.com/h5/"
            "mtop.aliexpress.pdp.pc.query/1.0/_____tmd_____/punish?"
            "action=captcharecaptcha&x5secdata=issued-token&"
            "url=https%3A%2F%2Fwww.aliexpress.com%2Fitem%2F1.html"
        )
        unchanged = {
            "name": "x5sec",
            "value": "preexisting",
            "domain": ".aliexpress.com",
            "path": "/h5/",
            "expires": time.time() + 60,
        }
        solver = BrowserSolver(solve_timeout=0.01)
        solver._browser = MagicMock()
        solver._browser.is_connected.return_value = True
        solver._browser_ua = "Chrome/149"
        solver._needs_screenxy_patch = False
        context = MagicMock()
        context.new_page.return_value = MagicMock()
        context.cookies.return_value = [unchanged]

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=True,
                ),
            ):
                result = solver._solve_on_worker(issued, "tmd", timeout=0.01)
        finally:
            solver.close()

        assert result is None

    def test_tmd_baseline_precedes_navigation_time_clearance(self):
        solver = BrowserSolver(solve_timeout=1)
        solver._browser = MagicMock()
        solver._browser.is_connected.return_value = True
        solver._browser_ua = "Chrome/149"
        solver._needs_screenxy_patch = False

        issued = (
            "https://acs.alibaba.com/_____tmd_____/punish?"
            "x5secdata=issued&url=https%3A%2F%2Fwww.alibaba.com%2F"
            "trade%2Fsearch%3FSearchText%3Dswitch"
        )
        clearance = {
            "name": "x5sec",
            "value": "navigation-minted",
            "domain": ".alibaba.com",
            "path": "/trade/",
            "expires": time.time() + 60,
        }
        events = []
        context = MagicMock()
        page = MagicMock()
        context.new_page.return_value = page

        def cookies():
            events.append("cookies")
            return [clearance] if "goto" in events else []

        def goto(*_args, **_kwargs):
            events.append("goto")

        context.cookies.side_effect = cookies
        page.goto.side_effect = goto

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=True,
                ),
            ):
                result = solver._solve_on_worker(
                    issued,
                    "tmd",
                    timeout=1,
                )
        finally:
            solver.close()

        assert result is not None
        assert result.cookies == [clearance]
        assert events[:2] == ["cookies", "goto"]

    def test_real_prefixed_aliexpress_url_passes_outer_clearance_gate(self):
        solver = BrowserSolver(solve_timeout=1)
        solver._browser = MagicMock()
        solver._browser.is_connected.return_value = True
        solver._browser_ua = "Chrome/149"
        solver._needs_screenxy_patch = False

        issued = (
            "https://acs.aliexpress.com:443//h5/"
            "mtop.aliexpress.pdp.pc.query/1.0/_____tmd_____/punish?"
            "x5secdata=issued-token&x5step=2&"
            "url=https%3A%2F%2Fwww.aliexpress.com%2Fitem%2F"
            "1005001234567890.html"
        )
        clearance = {
            "name": "x5sec",
            "value": "browser-minted",
            "domain": ".aliexpress.com",
            "path": "/h5/",
            "expires": time.time() + 60,
        }
        context = MagicMock()
        page = MagicMock()
        context.new_page.return_value = page
        context.cookies.side_effect = [[], [clearance]]

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=True,
                ),
            ):
                result = solver._solve_on_worker(issued, "tmd", timeout=1)
        finally:
            solver.close()

        assert result is not None
        assert result.cookies == [clearance]

    def test_unresolved_large_tmd_page_with_cookies_is_not_passthrough(self):
        solver = BrowserSolver(solve_timeout=1)
        solver._browser = MagicMock()
        solver._browser.is_connected.return_value = True
        solver._browser_ua = "Chrome/145"

        context = MagicMock()
        page = MagicMock()
        page.url = "https://acs.aliexpress.com/_____tmd_____/punish"
        page.content.return_value = (
            "<html><body>blocked baxia " + ("x" * 5000) + "</body></html>"
        )
        context.new_page.return_value = page
        context.cookies.return_value = [
            {
                "name": "incidental",
                "value": "not-proof",
                "domain": ".aliexpress.com",
            }
        ]

        with (
            patch.object(solver, "_create_context", return_value=context),
            patch.object(solver, "_setup_headless_patches"),
            patch.object(
                solver,
                "_dispatch_challenge",
                return_value=False,
            ),
        ):
            result = solver._solve_on_worker(
                "https://acs.aliexpress.com/_____tmd_____/punish",
                "tmd",
                timeout=1,
            )
        solver.close()

        assert result is None
        page.content.assert_not_called()

    @staticmethod
    def _cloudflare_navigation(
        *,
        body=None,
        status=200,
        response_url="https://apollomapping.com/",
        page_url="https://apollomapping.com/",
        content_type="text/html; charset=utf-8",
        cookies=None,
    ):
        if body is None:
            body = (
                b"<html><head><title>Apollo Mapping | The Image Hunters</title>"
                b"</head><body>"
                + b"real application content " * 100
                + b"</body></html>"
            )
        solver = BrowserSolver(solve_timeout=1)
        solver._browser = MagicMock()
        solver._browser.is_connected.return_value = True
        solver._browser_ua = "Chrome/149"
        solver._needs_screenxy_patch = False

        response = MagicMock()
        response.status = status
        response.url = response_url
        response.all_headers.return_value = {
            "content-type": content_type,
            "cache-control": "public, max-age=0",
        }
        response.headers_array.return_value = [
            {
                "name": "set-cookie",
                "value": "apollo_session=ready; Path=/; Secure",
            }
        ]
        response.body.return_value = body

        context = MagicMock()
        page = MagicMock()
        page.url = page_url
        page.goto.return_value = response
        context.new_page.return_value = page
        context.cookies.return_value = cookies or []
        return solver, context, page, response

    def test_cloudflare_absent_returns_validated_main_document(self):
        solver, context, page, response = self._cloudflare_navigation()
        response.all_headers.return_value.update(
            {
                "content-encoding": "br",
                "content-length": "123",
                "transfer-encoding": "chunked",
            }
        )

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=None,
                ),
            ):
                result = solver._solve_on_worker(
                    "https://apollomapping.com/",
                    "cloudflare",
                    timeout=1,
                )
        finally:
            solver.close()

        assert result is not None
        assert result.cookies == []
        assert result.response is not None
        assert result.response.status == 200
        assert result.response.url == "https://apollomapping.com/"
        assert result.response.body == response.body.return_value
        assert result.response.headers["cache-control"] == "public, max-age=0"
        assert "content-encoding" not in result.response.headers
        assert "content-length" not in result.response.headers
        assert "transfer-encoding" not in result.response.headers
        assert result.response.set_cookie == [
            "apollo_session=ready; Path=/; Secure"
        ]
        assert result.challenge_absent is True
        page.content.assert_not_called()

    @pytest.mark.parametrize(
        ("response_url", "page_url"),
        [
            (
                "https://apollomapping.com/?utm_source=test",
                "https://apollomapping.com/",
            ),
            (
                "https://apollomapping.com/?source=one",
                "https://apollomapping.com/?source=two#section",
            ),
        ],
    )
    def test_cloudflare_absent_allows_history_query_cleanup(
        self,
        response_url,
        page_url,
    ):
        solver, context, _page, _response = self._cloudflare_navigation(
            response_url=response_url,
            page_url=page_url,
        )

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=None,
                ),
            ):
                result = solver._solve_on_worker(
                    response_url,
                    "cloudflare",
                    timeout=1,
                )
        finally:
            solver.close()

        assert result is not None
        assert result.response is not None

    def test_cloudflare_absent_rejects_history_path_navigation(self):
        solver, context, _page, response = self._cloudflare_navigation(
            response_url="https://apollomapping.com/",
            page_url="https://apollomapping.com/other-document",
        )

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=None,
                ),
            ):
                result = solver._solve_on_worker(
                    "https://apollomapping.com/",
                    "cloudflare",
                    timeout=1,
                )
        finally:
            solver.close()

        assert result is None
        response.body.assert_not_called()

    def test_cloudflare_absent_rejects_server_redirect_passthrough(self):
        solver, context, _page, response = self._cloudflare_navigation(
            response_url="https://www.apollomapping.com/",
            page_url="https://www.apollomapping.com/",
        )

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=None,
                ),
            ):
                result = solver._solve_on_worker(
                    "https://apollomapping.com/",
                    "cloudflare",
                    timeout=1,
                )
        finally:
            solver.close()

        assert result is None
        response.body.assert_not_called()

    def test_cloudflare_absent_accepts_small_valid_html(self):
        body = b"<html><title>Ready</title><body>ok</body></html>"
        solver, context, _page, _response = self._cloudflare_navigation(
            body=body
        )

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=None,
                ),
            ):
                result = solver._solve_on_worker(
                    "https://apollomapping.com/",
                    "cloudflare",
                    timeout=1,
                )
        finally:
            solver.close()

        assert result is not None
        assert result.response is not None
        assert result.response.body == body

    def test_cloudflare_observed_but_unresolved_is_never_passthrough(self):
        solver, context, _page, response = self._cloudflare_navigation()

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=False,
                ),
            ):
                result = solver._solve_on_worker(
                    "https://apollomapping.com/",
                    "cloudflare",
                    timeout=1,
                )
        finally:
            solver.close()

        assert result is None
        response.body.assert_not_called()

    @pytest.mark.parametrize(
        "body",
        [
            b"<html><title>Just a moment...</title>"
            + b"<script src='/cdn-cgi/challenge-platform/x'></script>"
            + b"x" * 2000,
            b"<html><title>Access denied</title>" + b"x" * 2000,
        ],
    )
    def test_cloudflare_absent_rejects_challenge_and_block_documents(
        self,
        body,
    ):
        solver, context, _page, _response = self._cloudflare_navigation(
            body=body
        )

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=None,
                ),
            ):
                result = solver._solve_on_worker(
                    "https://apollomapping.com/",
                    "cloudflare",
                    timeout=1,
                )
        finally:
            solver.close()

        assert result is None

    @pytest.mark.parametrize(
        "marker",
        [
            "checking your browser",
            "attention required",
            "enable javascript and cookies",
            "unusual traffic",
            "request blocked",
            "access denied",
        ],
    )
    def test_cloudflare_generic_block_copy_is_not_shared_with_other_wafs(
        self,
        marker,
    ):
        from wafer.browser._solver import (
            _is_cloudflare_absent_challenge_html,
            _is_passthrough_challenge_html,
        )

        legitimate = (
            "<html><script>window.translations = "
            f'{{"permission_error": "{marker}"}}'
            "</script><body>Real application</body></html>"
        )

        assert not _is_passthrough_challenge_html(legitimate)
        assert _is_cloudflare_absent_challenge_html(legitimate)

    def test_cloudflare_absent_does_not_substitute_get_for_post(self):
        solver, context, _page, response = self._cloudflare_navigation()

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=None,
                ),
            ):
                result = solver._solve_on_worker(
                    "https://apollomapping.com/api",
                    "cloudflare",
                    timeout=1,
                    replay={
                        "method": "POST",
                        "body": "{}",
                        "content_type": "application/json",
                    },
                )
        finally:
            solver.close()

        assert result is None
        response.body.assert_not_called()

    def test_cloudflare_absent_rejects_cross_site_final_document(self):
        solver, context, _page, response = self._cloudflare_navigation(
            response_url="https://example.net/landing",
            page_url="https://example.net/landing",
        )

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(
                    solver,
                    "_dispatch_challenge",
                    return_value=None,
                ),
            ):
                result = solver._solve_on_worker(
                    "https://apollomapping.com/",
                    "cloudflare",
                    timeout=1,
                )
        finally:
            solver.close()

        assert result is None
        response.body.assert_not_called()

    def test_reddit_browser_dispatch_refuses_json_navigation(self):
        solver = BrowserSolver(solve_timeout=1)
        solver._browser = MagicMock()
        solver._browser.is_connected.return_value = True
        solver._browser_ua = "Chrome/149"
        solver._needs_screenxy_patch = False

        context = MagicMock()
        page = MagicMock()
        context.new_page.return_value = page
        context.cookies.return_value = [
            {
                "name": "csv",
                "value": "incidental",
                "domain": ".reddit.com",
                "path": "/",
            }
        ]

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
            ):
                result = solver._solve_on_worker(
                    "https://www.reddit.com/r/Python/hot.json",
                    "reddit",
                    timeout=1,
                )
        finally:
            solver.close()

        assert result is None
        page.wait_for_load_state.assert_not_called()
        page.content.assert_not_called()
        page.reload.assert_not_called()

    def test_reddit_browser_dispatch_accepts_scoped_cookie_evidence(self):
        solver = BrowserSolver(solve_timeout=1)
        page = MagicMock()
        page.url = "https://www.reddit.com/"
        page.context.cookies.return_value = [
            {"name": "loid", "domain": ".reddit.com"},
            {"name": "token_v2", "domain": ".reddit.com"},
        ]

        try:
            assert solver._dispatch_challenge(page, "reddit", 1000)
        finally:
            solver.close()

        page.context.cookies.assert_called_once_with(
            "https://www.reddit.com/"
        )
        page.reload.assert_not_called()

    @pytest.mark.parametrize(
        "url",
        [
            "https://www.reddit.com/?rdt=logged-out",
            "https://www.reddit.com/#verification",
            "https://www.reddit.com/?rdt=logged-out#verification",
        ],
    )
    def test_reddit_browser_dispatch_allows_root_query_and_fragment(
        self,
        url,
    ):
        solver = BrowserSolver(solve_timeout=1)
        page = MagicMock()
        page.url = url
        page.context.cookies.return_value = [
            {"name": "loid", "domain": ".reddit.com"},
            {"name": "csv", "domain": ".reddit.com"},
        ]

        try:
            assert solver._dispatch_challenge(page, "reddit", 1000)
        finally:
            solver.close()

    def test_reddit_browser_solve_navigates_fixed_root_not_json(self):
        solver = BrowserSolver(solve_timeout=1)
        solver._browser = MagicMock()
        solver._browser.is_connected.return_value = True
        solver._browser_ua = "Chrome/149"
        solver._needs_screenxy_patch = False

        cookies = [
            {
                "name": "loid",
                "value": "anonymous",
                "domain": ".reddit.com",
                "path": "/",
            },
            {
                "name": "token_v2",
                "value": "token",
                "domain": ".reddit.com",
                "path": "/",
            },
        ]
        context = MagicMock()
        page = MagicMock()
        page.url = "https://www.reddit.com/"
        page.context = context
        context.new_page.return_value = page
        context.cookies.return_value = cookies
        json_url = "https://www.reddit.com/r/Python/hot.json"

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
            ):
                result = solver._solve_on_worker(
                    json_url,
                    "reddit",
                    timeout=1,
                    embedder="https://www.reddit.com/",
                )
        finally:
            solver.close()

        assert result is not None
        assert result.cookies == cookies
        assert page.goto.call_args.args[0] == "https://www.reddit.com/"
        assert page.goto.call_args.args[0] != json_url

    def test_reddit_browser_dispatch_reloads_root_once_for_cookie_evidence(
        self,
    ):
        solver = BrowserSolver(solve_timeout=1)
        page = MagicMock()
        page.url = "https://www.reddit.com/"
        partial = [{"name": "csv", "domain": ".reddit.com"}]
        solved = [
            {"name": "loid", "domain": ".reddit.com"},
            {"name": "csv", "domain": ".reddit.com"},
        ]
        page.context.cookies.side_effect = [partial, partial, solved]

        try:
            assert solver._dispatch_challenge(page, "reddit", 1000)
        finally:
            solver.close()

        page.reload.assert_called_once()
        assert page.reload.call_args.kwargs["wait_until"] == "domcontentloaded"

    def test_reddit_browser_dispatch_rejects_partial_cookies_after_reload(
        self,
    ):
        solver = BrowserSolver(solve_timeout=1)
        page = MagicMock()
        page.url = "https://www.reddit.com/"
        page.context.cookies.return_value = [
            {"name": "csv", "domain": ".reddit.com"},
            {"name": "edgebucket", "domain": ".reddit.com"},
        ]

        try:
            assert not solver._dispatch_challenge(page, "reddit", 1000)
        finally:
            solver.close()

        page.reload.assert_called_once()

    @pytest.mark.parametrize(
        "marker",
        [
            "You've been blocked by network security.",
            "<title>Reddit - Please wait for verification</title>",
        ],
    )
    def test_reddit_marker_outside_prefix_is_never_passthrough(self, marker):
        from wafer.browser._solver import _is_passthrough_challenge_html

        html = "<html><body>" + ("x" * 20_000) + marker + "</body></html>"

        assert _is_passthrough_challenge_html(html)


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
        px_frame.evaluate.side_effect = lambda js: (
            "Human verification challenge"
            if "document.title" in js
            else 1.0  # progress bar always full
        )
        btn_locator = MagicMock()
        btn_locator.count.return_value = 1
        btn_locator.first.bounding_box.return_value = {
            "x": 400,
            "y": 300,
            "width": 253,
            "height": 48,
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
            "x": 400,
            "y": 300,
            "width": 530,
            "height": 100,
        }
        page.locator.return_value = el
        page.on = MagicMock()
        page.remove_listener = MagicMock()

        mono_values = [float(i) * 0.1 for i in range(500)]
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
        page.context.cookies.return_value = [{"name": "_px3", "value": "abc"}]

        mono_values = [float(i) for i in range(50)]
        with patch("time.monotonic", side_effect=mono_values):
            result = solver._solve_perimeterx(page, 30000)

        assert result is True
        page.mouse.down.assert_not_called()

    @patch("time.sleep")
    def test_fallback_to_passive_when_no_recordings(self, mock_sleep):
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
        page.context.cookies.return_value = [{"name": "_px3", "value": "abc"}]

        pkg_mock = MagicMock()
        pkg_mock.__truediv__ = lambda self, name: MagicMock(iterdir=lambda: [])

        mono_values = [float(i) for i in range(50)]
        with (
            patch(
                "wafer.browser._solver.importlib.resources.files",
                return_value=pkg_mock,
            ),
            patch("time.monotonic", side_effect=mono_values),
        ):
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
            "x": 400,
            "y": 300,
            "width": 253,
            "height": 48,
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
            "x": 400,
            "y": 300,
            "width": 200,
            "height": 60,
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
    def test_returns_true_when_istlwashere_gone(self, mock_mono, mock_sleep):
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
            solved_cookies,  # second poll — solved!
        ]
        page.frames = []
        # deadline(0.0) + grace(0.5) + while(1.0) + grace_check(1.5)
        # + while(2.0) — second iteration finds solved cookie
        # + redirect_deadline(2.5) + redirect_while(3.0) — no DD frame,
        #   returns True
        mock_mono.side_effect = [
            0.0,
            0.5,
            1.0,
            1.5,
            2.0,
            2.5,
            3.0,
        ]

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
    def test_returns_false_on_tbv_redirect_midsolve(self, mock_mono, mock_sleep):
        from wafer.browser._datadome import wait_for_datadome

        page = MagicMock()
        solver = MagicMock()

        # URL changes to t=bv mid-solve
        # Read order: initial check, loop1 check, loop2 check (t=bv)
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
        # deadline(0.0) + grace(0.5) + while1(1.0) + grace1(1.5)
        # + while2(2.0) → loop2 url reads t=bv → returns False
        mock_mono.side_effect = [0.0, 0.5, 1.0, 1.5, 2.0]

        assert wait_for_datadome(solver, page, 10000) is False


# ---------------------------------------------------------------------------
# Imperva solver
# ---------------------------------------------------------------------------


class TestWaitForImperva:
    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_true_when_reese84_cookie_appears(self, mock_mono, mock_sleep):
        from wafer.browser._imperva import wait_for_imperva

        page = MagicMock()
        solver = MagicMock()
        # Initial snapshot: no cookies. Then reese84 appears.
        page.context.cookies.side_effect = [
            [],  # initial snapshot
            [],  # first poll
            [{"name": "reese84", "value": "abc123"}],  # second poll
        ]
        mock_mono.side_effect = [0.0, 1.0, 2.0, 3.0]

        assert wait_for_imperva(solver, page, 10000) is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_true_when_reese84_value_changes(self, mock_mono, mock_sleep):
        """reese84 set by challenge response, then updated by JS."""
        from wafer.browser._imperva import wait_for_imperva

        page = MagicMock()
        solver = MagicMock()
        page.context.cookies.side_effect = [
            [{"name": "reese84", "value": "server-set"}],  # initial
            [{"name": "reese84", "value": "server-set"}],  # unchanged
            [{"name": "reese84", "value": "js-updated"}],  # changed
        ]
        mock_mono.side_effect = [0.0, 1.0, 2.0, 3.0]

        assert wait_for_imperva(solver, page, 10000) is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_no_false_positive_on_preexisting_cookie(self, mock_mono, mock_sleep):
        """reese84 present from challenge response must not trigger
        immediate success - value must change."""
        from wafer.browser._imperva import wait_for_imperva

        page = MagicMock()
        solver = MagicMock()
        page.context.cookies.side_effect = [
            [{"name": "reese84", "value": "stale"}],  # initial
            [{"name": "reese84", "value": "stale"}],  # still same
            [{"name": "reese84", "value": "stale"}],  # still same
        ]
        mock_mono.side_effect = [0.0, 1.0, 5.0, 15.0]

        assert wait_for_imperva(solver, page, 10000) is False

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_true_when_utmvc_cookie(self, mock_mono, mock_sleep):
        from wafer.browser._imperva import wait_for_imperva

        page = MagicMock()
        solver = MagicMock()
        # Initial snapshot: no cookies. Then ___utmvc appears.
        page.context.cookies.side_effect = [
            [],  # initial snapshot
            [],  # first poll
            [{"name": "___utmvc", "value": "xyz789"}],  # appears
        ]
        mock_mono.side_effect = [0.0, 1.0, 2.0, 3.0]

        assert wait_for_imperva(solver, page, 10000) is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_true_when_incap_ses_cookie(self, mock_mono, mock_sleep):
        """Classic Incapsula: incap_ses_* cookie is solve signal."""
        from wafer.browser._imperva import wait_for_imperva

        page = MagicMock()
        solver = MagicMock()
        # Initial snapshot: no cookies. Then incap_ses appears.
        page.context.cookies.side_effect = [
            [],  # initial snapshot
            [],  # first poll
            [
                {"name": "visid_incap_123", "value": "x"},
                {"name": "incap_ses_456_123", "value": "y"},
            ],
        ]
        mock_mono.side_effect = [0.0, 1.0, 2.0, 3.0]

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


class TestSolveImpervaEmbedder:
    """Error 15 fix: solve on the origin page, not the API host directly."""

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_navigates_embedder_and_succeeds_on_reese84(self, mock_mono, mock_sleep):
        from wafer.browser._imperva import solve_imperva_embedder

        page = MagicMock()
        solver = MagicMock()
        # Cookie absent, then reese84 appears on the embedder page.
        page.context.cookies.side_effect = [
            [],
            [{"name": "reese84", "value": "earned"}],
        ]
        mock_mono.side_effect = [0.0, 0.1, 0.2, 0.3, 0.4]

        assert (
            solve_imperva_embedder(solver, page, "https://www.realtor.ca/", 10000)
            is True
        )
        # Navigated the embedder origin, not the API URL.
        assert page.goto.call_args[0][0] == "https://www.realtor.ca/"

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_succeeds_on_incap_ses(self, mock_mono, mock_sleep):
        from wafer.browser._imperva import solve_imperva_embedder

        page = MagicMock()
        solver = MagicMock()
        page.context.cookies.side_effect = [
            [],
            [{"name": "incap_ses_1226_999", "value": "y"}],
        ]
        mock_mono.side_effect = [0.0, 0.1, 0.2, 0.3, 0.4]

        assert (
            solve_imperva_embedder(solver, page, "https://www.realtor.ca/", 10000)
            is True
        )

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_succeeds_on_legacy_utmvc(self, mock_mono, mock_sleep):
        # Legacy Incapsula sets ___utmvc, not reese84 - the poll must accept it
        # (else it times out and the XHR passthrough never runs).
        from wafer.browser._imperva import solve_imperva_embedder

        page = MagicMock()
        solver = MagicMock()
        page.context.cookies.side_effect = [
            [],
            [{"name": "___utmvc", "value": "z"}],
        ]
        mock_mono.side_effect = [0.0, 0.1, 0.2, 0.3, 0.4]

        assert (
            solve_imperva_embedder(solver, page, "https://legacy.example.com/", 10000)
            is True
        )

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_returns_false_on_timeout(self, mock_mono, mock_sleep):
        from wafer.browser._imperva import solve_imperva_embedder

        page = MagicMock()
        solver = MagicMock()
        page.context.cookies.return_value = []
        mock_mono.side_effect = [0.0, 0.1, 5.0, 15.0]

        assert (
            solve_imperva_embedder(solver, page, "https://www.realtor.ca/", 10000)
            is False
        )

    @patch("time.monotonic")
    def test_returns_false_when_navigation_fails(self, mock_mono):
        from wafer.browser._imperva import solve_imperva_embedder

        page = MagicMock()
        solver = MagicMock()
        page.goto.side_effect = RuntimeError("nav blew up")
        mock_mono.side_effect = [0.0, 0.1]

        assert (
            solve_imperva_embedder(solver, page, "https://www.realtor.ca/", 10000)
            is False
        )


class TestImpervaXhrReplay:
    """Same-site XHR replay from the embedder page (passthrough source)."""

    def test_returns_result_dict(self):
        from wafer.browser._imperva import imperva_xhr_replay

        page = MagicMock()
        page.evaluate.return_value = {
            "status": 200,
            "body": '{"ok":1}',
            "content_type": "application/json",
        }
        res = imperva_xhr_replay(
            page,
            "https://api2.realtor.ca/x",
            {
                "method": "POST",
                "body": "a=1",
                "content_type": "application/x-www-form-urlencoded",
            },
            10000,
        )
        assert res["status"] == 200 and res["body"] == '{"ok":1}'
        # The page received the replay descriptor (method/body/content-type).
        arg = page.evaluate.call_args[0][1]
        assert arg["method"] == "POST"
        assert arg["body"] == "a=1"
        assert arg["content_type"] == "application/x-www-form-urlencoded"
        assert arg["max_size"] is None

    def test_oversize_stream_raises_typed_error(self):
        from wafer._errors import ResponseTooLarge
        from wafer.browser._imperva import imperva_xhr_replay

        page = MagicMock()
        page.evaluate.return_value = {
            "status": -2,
            "body": "",
            "content_type": "application/json",
            "too_large": True,
            "size": 101,
        }

        with pytest.raises(ResponseTooLarge) as raised:
            imperva_xhr_replay(
                page,
                "https://api2.realtor.ca/x",
                {"method": "GET"},
                10000,
                max_size=100,
            )

        assert raised.value.size == 101
        assert raised.value.limit == 100
        assert page.evaluate.call_args[0][1]["max_size"] == 100

    def test_reencoded_text_expansion_is_checked_in_python(self):
        from wafer._errors import ResponseTooLarge

        solver = BrowserSolver(solve_timeout=1)
        solver._browser = MagicMock()
        solver._browser.is_connected.return_value = True
        solver._browser_ua = "Chrome/145"
        solver._needs_screenxy_patch = False
        context = MagicMock()
        page = MagicMock()
        context.new_page.return_value = page
        context.cookies.return_value = [
            {
                "name": "reese84",
                "value": "solved",
                "domain": ".realtor.ca",
            }
        ]

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch(
                    "wafer.browser._imperva.solve_imperva_embedder",
                    return_value=True,
                ),
                patch(
                    "wafer.browser._imperva.imperva_xhr_replay",
                    return_value={
                        "status": 200,
                        "body": "\ufffd",
                        "content_type": "application/json",
                    },
                ),
                pytest.raises(ResponseTooLarge) as raised,
            ):
                solver._solve_on_worker(
                    "https://api2.realtor.ca/x",
                    "imperva",
                    timeout=1,
                    embedder="https://www.realtor.ca/",
                    replay={"method": "GET"},
                    max_size=2,
                )
        finally:
            solver.close()

        assert raised.value.size == 3
        assert raised.value.limit == 2

    def test_none_on_evaluate_error(self):
        from wafer.browser._imperva import imperva_xhr_replay

        page = MagicMock()
        page.evaluate.side_effect = RuntimeError("evaluate failed")
        assert (
            imperva_xhr_replay(
                page, "https://api2.realtor.ca/x", {"method": "GET"}, 10000
            )
            is None
        )

    def test_none_on_negative_status(self):
        from wafer.browser._imperva import imperva_xhr_replay

        page = MagicMock()
        page.evaluate.return_value = {
            "status": -1,
            "body": "AbortError",
            "content_type": "",
        }
        assert (
            imperva_xhr_replay(
                page, "https://api2.realtor.ca/x", {"method": "GET"}, 10000
            )
            is None
        )

    def test_method_defaults_to_get(self):
        from wafer.browser._imperva import imperva_xhr_replay

        page = MagicMock()
        page.evaluate.return_value = {
            "status": 200,
            "body": "{}",
            "content_type": "application/json",
        }
        imperva_xhr_replay(page, "https://api2.realtor.ca/x", {}, 10000)
        assert page.evaluate.call_args[0][1]["method"] == "GET"


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
        mock_mono.side_effect = [float(i) * 0.1 for i in range(50)]
        result = solver._dispatch_challenge(page, "shape", 10000)
        assert result is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_dispatches_imperva(self, mock_mono, mock_sleep):
        solver = self._make_solver_with_mock_browser()
        page = MagicMock()
        # Initial snapshot has server-set value, then JS updates it
        page.context.cookies.side_effect = [
            [{"name": "reese84", "value": "server"}],  # initial
            [{"name": "reese84", "value": "solved"}],  # changed
        ]
        mock_mono.side_effect = [float(i) * 0.1 for i in range(50)]
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
        mock_mono.side_effect = [float(i) * 0.1 for i in range(50)]
        result = solver._dispatch_challenge(page, "datadome", 10000)
        assert result is True

    @patch("wafer.browser._drag.solve_baxia")
    def test_tmd_baxia_receives_immutable_issued_url(self, mock_baxia):
        solver = self._make_solver_with_mock_browser()
        page = MagicMock()
        page.url = "https://acs.aliexpress.com/_____tmd_____/punish?iframe=1"
        issued_url = (
            "https://acs.aliexpress.com/_____tmd_____/punish?"
            "x5secdata=issued&url=https%3A%2F%2Fwww.aliexpress.com%2F"
        )
        mock_baxia.return_value = True

        assert solver._dispatch_challenge(page, "tmd", 10_000, challenge_url=issued_url)
        mock_baxia.assert_called_once_with(
            solver, page, 10_000, challenge_url=issued_url
        )

    @patch("wafer.browser._drag.solve_baxia")
    @patch("wafer.browser._recaptcha.wait_for_recaptcha", return_value=True)
    def test_tmd_recaptcha_url_uses_recaptcha_before_baxia(
        self, mock_recaptcha, mock_baxia
    ):
        solver = self._make_solver_with_mock_browser()
        page = MagicMock()
        page.url = (
            "https://acs.aliexpress.com/_____tmd_____/punish?action=captcharecaptcha"
        )

        assert solver._dispatch_challenge(page, "tmd", 10_000)
        mock_recaptcha.assert_called_once_with(
            solver,
            page,
            10_000,
            protocol_completion_is_intermediate=True,
        )
        mock_baxia.assert_not_called()

    @patch("wafer.browser._drag.solve_baxia")
    @patch("wafer.browser._recaptcha.wait_for_recaptcha", return_value=True)
    def test_application_challenge_url_defers_to_navigated_page_url(
        self, mock_recaptcha, mock_baxia
    ):
        """The normal flow passes the APPLICATION url to solve(), not an
        issued punishment url. It can never carry ``action``, so it must not
        be trusted as the classifier -- doing so sent every normal-flow
        reCAPTCHA punishment to the slider solver, which waits for a widget
        that never exists."""
        solver = self._make_solver_with_mock_browser()
        page = MagicMock()
        page.url = (
            "https://acs.aliexpress.com/_____tmd_____/punish?action=captcharecaptcha"
        )

        assert solver._dispatch_challenge(
            page,
            "tmd",
            10_000,
            challenge_url="https://www.aliexpress.com/w/wholesale-widget.html",
        )
        mock_recaptcha.assert_called_once_with(
            solver,
            page,
            10_000,
            protocol_completion_is_intermediate=True,
        )
        mock_baxia.assert_not_called()

    @patch("wafer.browser._drag.solve_baxia", return_value=True)
    @patch("wafer.browser._recaptcha.wait_for_recaptcha")
    def test_application_challenge_url_still_reaches_slider(
        self, mock_recaptcha, mock_baxia
    ):
        """The same deferral must not misroute an ordinary Baxia slider: the
        navigated punishment url carries no reCAPTCHA action."""
        solver = self._make_solver_with_mock_browser()
        page = MagicMock()
        page.url = "https://acs.aliexpress.com/_____tmd_____/punish?x5secdata=abc"
        app_url = "https://www.aliexpress.com/w/wholesale-widget.html"

        assert solver._dispatch_challenge(page, "tmd", 10_000, challenge_url=app_url)
        mock_baxia.assert_called_once_with(
            solver, page, 10_000, challenge_url=app_url
        )
        mock_recaptcha.assert_not_called()

    @patch("wafer.browser._recaptcha.wait_for_recaptcha", return_value=True)
    def test_generic_recaptcha_cannot_use_tmd_protocol_handoff(
        self,
        mock_recaptcha,
    ):
        solver = self._make_solver_with_mock_browser()
        page = MagicMock()

        assert solver._dispatch_challenge(page, "recaptcha", 10_000)
        mock_recaptcha.assert_called_once_with(solver, page, 10_000)

    @patch("wafer.browser._drag.solve_baxia")
    @patch("wafer.browser._recaptcha.wait_for_recaptcha", return_value=False)
    def test_tmd_recaptcha_failure_does_not_fall_back_to_baxia(
        self, mock_recaptcha, mock_baxia
    ):
        solver = self._make_solver_with_mock_browser()
        page = MagicMock()
        page.url = (
            "https://acs.aliexpress.com/_____tmd_____/punish?action=captcharecaptcha"
        )

        assert not solver._dispatch_challenge(page, "tmd", 10_000)
        mock_recaptcha.assert_called_once_with(
            solver,
            page,
            10_000,
            protocol_completion_is_intermediate=True,
        )
        mock_baxia.assert_not_called()

    @pytest.mark.parametrize(
        "query",
        [
            "action=captcharecaptcha&action=",
            "action=&action=captcharecaptcha",
        ],
    )
    @patch("wafer.browser._drag.solve_baxia", return_value=True)
    @patch("wafer.browser._recaptcha.wait_for_recaptcha", return_value=True)
    def test_tmd_duplicate_blank_action_keeps_budget_and_dispatch_aligned(
        self,
        mock_recaptcha,
        mock_baxia,
        query,
    ):
        from wafer._base import _tmd_browser_attempt_count

        solver = self._make_solver_with_mock_browser()
        page = MagicMock()
        issued_url = (
            "https://acs.aliexpress.com/_____tmd_____/punish?" + query
        )
        page.url = issued_url

        assert _tmd_browser_attempt_count(180.0, issued_url) == 3
        assert solver._dispatch_challenge(
            page,
            "tmd",
            10_000,
            challenge_url=issued_url,
        )
        mock_baxia.assert_called_once_with(
            solver,
            page,
            10_000,
            challenge_url=issued_url,
        )
        mock_recaptcha.assert_not_called()

    @pytest.mark.parametrize(
        "body,expect_recaptcha,label",
        [
            (
                '{"url":"//acs.aliexpress.com/_____tmd_____/punish'
                '?action=captcharecaptcha&x5secdata=abc"}',
                True,
                "MTop answers with the action already on the URL",
            ),
            (
                '&quot;//acs.aliexpress.com/_____tmd_____/punish'
                '?action=captcharecaptcha&amp;x5secdata=z&quot;',
                True,
                "HTML-escaped MTop payload",
            ),
            (
                '{"url":"//acs.aliexpress.com/_____tmd_____/punish?x5secdata=abc"}',
                False,
                "MTop slider punishment",
            ),
            (
                '<html><meta content="0;url=/_____tmd_____/punish?x=1"></html>',
                False,
                "page redirect carries no action yet",
            ),
            ("<html>ordinary page</html>", False, "not a punishment at all"),
        ],
    )
    def test_tmd_budget_is_classified_from_the_response_body(
        self, body, expect_recaptcha, label
    ):
        """The attempt budget must come from the issued punishment URL.

        Passing the *application* URL here could never carry an ``action``, so
        a reCAPTCHA punishment was always given the disposable-slider budget:
        three short throwaway contexts instead of the single long one its
        image rounds need. MTop puts the issued URL in the response body, so
        classify from there and keep the slider default when it is absent.
        """
        from wafer._base import (
            _tmd_browser_attempt_count,
            _tmd_punish_url_from_body,
        )

        app_url = "https://acs.aliexpress.com/h5/mtop.relation.x/1.0/"
        issued = _tmd_punish_url_from_body(body, app_url)
        attempts = _tmd_browser_attempt_count(180.0, issued or app_url)

        if expect_recaptcha:
            # One long single-use context, not three throwaway ones.
            assert attempts == 1, label
        else:
            assert attempts == 3, label

    @patch("wafer.browser._drag.solve_baxia")
    @patch("wafer.browser._recaptcha.wait_for_recaptcha", return_value=True)
    def test_tmd_uses_issued_url_when_navigation_changes_page_url(
        self, mock_recaptcha, mock_baxia
    ):
        solver = self._make_solver_with_mock_browser()
        page = MagicMock()
        # The actual TMD top page redirects/nests to this wrapper URL, which
        # intentionally lacks the MTop-issued action parameter.
        page.url = "https://acs.aliexpress.com/_____tmd_____/punish?iframe=1"
        issued_url = (
            "https://acs.aliexpress.com/_____tmd_____/punish?"
            "action=captcharecaptcha&x5secdata=issued"
        )

        assert solver._dispatch_challenge(page, "tmd", 10_000, challenge_url=issued_url)
        mock_recaptcha.assert_called_once_with(
            solver,
            page,
            10_000,
            protocol_completion_is_intermediate=True,
        )
        mock_baxia.assert_not_called()


class TestRecaptchaFrameRouting:
    def test_widget_binding_uses_instance_not_shared_sitekey_or_owner(self):
        from wafer.browser._recaptcha import _bind_widget, _find_bframe

        owner = MagicMock()
        first_anchor = MagicMock()
        first_anchor.url = "https://www.google.com/recaptcha/api2/anchor?k=same"
        first_anchor.name = "a-first"
        first_anchor.parent_frame = owner
        first_grid = MagicMock()
        first_grid.url = "https://www.google.com/recaptcha/api2/bframe?k=same"
        first_grid.name = "c-first"
        first_grid.parent_frame = owner
        second_grid = MagicMock()
        second_grid.url = "https://www.google.com/recaptcha/api2/bframe?k=same"
        second_grid.name = "c-second"
        second_grid.parent_frame = owner
        page = MagicMock()
        page.frames = [first_anchor, second_grid, first_grid]

        widget = _bind_widget(first_anchor)

        assert widget is not None
        assert _find_bframe(page, widget) is first_grid

    def test_widget_token_scope_does_not_accept_sibling_widget_token(self):
        from wafer.browser._recaptcha import _bind_widget, _check_token, _token_values

        owner = MagicMock()
        anchor = MagicMock()
        anchor.url = "https://www.google.com/recaptcha/api2/anchor?k=same"
        anchor.name = "a-first"
        anchor.parent_frame = owner
        anchor.locator.return_value.get_attribute.return_value = "true"
        widget = _bind_widget(anchor)
        owner.evaluate.side_effect = [["first-old"], ["first-old"], ["first-new"]]
        page = MagicMock()
        page.frames = []

        baseline = _token_values(page, widget)

        # A sibling's newly populated textarea is never queried: only the
        # exact a-first/c-first owner subtree can satisfy this challenge.
        assert not _check_token(page, baseline, widget)
        assert _check_token(page, baseline, widget)
        assert all(
            call.args[1] == ["a-first", "c-first"]
            for call in owner.evaluate.call_args_list
        )

    def test_sibling_body_token_cannot_complete_an_unchecked_anchor(self):
        from wafer.browser._recaptcha import _bind_widget, _check_token

        owner = MagicMock()
        anchor = MagicMock()
        anchor.url = "https://www.google.com/recaptcha/api2/anchor?k=same"
        anchor.name = "a-first"
        anchor.parent_frame = owner
        # Simulate a body-level LCA whose broad textarea query sees the
        # sibling response, while the widget actually clicked is unchecked.
        owner.evaluate.return_value = ["sibling-new-token"]
        anchor.locator.return_value.get_attribute.return_value = "false"
        widget = _bind_widget(anchor)

        assert not _check_token(MagicMock(), {"first-old-token"}, widget)
        owner.evaluate.assert_not_called()

    def test_token_check_requires_a_value_newer_than_widget_baseline(self):
        from wafer.browser._recaptcha import _check_token, _token_values

        page = MagicMock()
        page.frames = []
        page.eval_on_selector.side_effect = [
            "ambient-token",
            "ambient-token",
            "new-token",
        ]

        baseline = _token_values(page)

        assert not _check_token(page, baseline)
        assert _check_token(page, baseline)

    def test_token_observation_retains_counts_not_values(self):
        from wafer.browser._recaptcha import _token_observation

        page = MagicMock()
        widget = {
            "anchor": MagicMock(),
            "owner": MagicMock(),
            "anchor_name": "a-exact",
            "bframe_name": "c-exact",
            "instance": "exact",
        }
        widget["anchor"].locator.return_value.get_attribute.return_value = "false"
        widget["owner"].evaluate.return_value = [
            "old-secret",
            "new-secret",
        ]

        observation = _token_observation(
            page,
            {"old-secret"},
            widget,
        )

        assert observation == {
            "anchor_checked": False,
            "scoped_value_count": 2,
            "new_value_count": 1,
        }
        assert "secret" not in repr(observation)

    def test_payload_intercept_keeps_checkbox_grid_when_replacements_arrive(self):
        from wafer.browser import _recaptcha_grid as grid

        page = MagicMock()
        state = grid._setup_payload_intercept(page)
        listener = page.on.call_args.args[1]
        first = MagicMock()
        first.url = "https://www.google.com/recaptcha/api2/payload?p=first"
        first.body.return_value = b"checkbox-grid"
        replacement = MagicMock()
        replacement.url = "https://www.google.com/recaptcha/api2/payload?p=next"
        replacement.body.return_value = b"replacement-grid"

        listener(first)
        listener(replacement)

        assert state["payload"] == b"checkbox-grid"

    def test_payload_intercept_records_userverify_status_without_url(self):
        from wafer.browser import _recaptcha_grid as grid

        page = MagicMock()
        state = grid._setup_payload_intercept(page)
        listener = page.on.call_args.args[1]
        response = MagicMock()
        response.url = "https://www.google.com/recaptcha/enterprise/userverify"
        response.status = 200
        response.body.return_value = (
            b")]}'\n[\"uvresp\",\"secret-response-token\",1,120]"
        )

        listener(response)

        assert state["verify_statuses"] == [200]
        assert state["verify_summaries"] == [
            {
                "classification": "protocol_solved",
                "token_present": True,
                "success_flag": True,
                "error_present": False,
                "continuation_present": False,
            }
        ]
        assert "secret-response-token" not in repr(state)

    @pytest.mark.parametrize(
        "url",
        [
            "http://www.google.com/recaptcha/api2/userverify",
            "https://www.google.com/recaptcha/api2/userverify-extra",
            "https://www.google.com/not/recaptcha/api2/userverify",
            "https://google.evil.test/recaptcha/api2/userverify",
        ],
    )
    def test_payload_intercept_ignores_nonexact_userverify_routes(self, url):
        from wafer.browser import _recaptcha_grid as grid

        page = MagicMock()
        state = grid._setup_payload_intercept(page)
        listener = page.on.call_args.args[1]
        response = MagicMock()
        response.url = url

        listener(response)

        assert state["verify_statuses"] == []
        assert state["verify_summaries"] == []
        response.body.assert_not_called()

    @pytest.mark.parametrize(
        ("payload", "classification"),
        [
            (
                b")]}'\n[\"uvresp\",\"sensitive-value\",1,120]",
                "protocol_solved",
            ),
            (b'["uvresp","sensitive-value",0,120,"bad"]', "error"),
            (b'["uvresp","",0,120,null,null,null,["next"]]', "continued"),
            (
                b'["uvresp","sensitive-value",1,120,null,null,null,[]]',
                "continued",
            ),
            (
                b'["uvresp","sensitive-value",1,120,null,null,null,{}]',
                "continued",
            ),
            (b'["uvresp","",0,120]', "unknown"),
            (b'["other","sensitive-value",1,120]', "unknown_schema"),
            (b"not-json", "invalid_json"),
            (b"", "empty"),
        ],
    )
    def test_userverify_summary_is_token_free(self, payload, classification):
        from wafer.browser import _recaptcha_grid as grid

        summary = grid._safe_userverify_summary(payload)

        assert summary["classification"] == classification
        assert "sensitive-value" not in repr(summary)

    def test_userverify_summary_rejects_oversize_and_non_bytes(self):
        from wafer.browser import _recaptcha_grid as grid

        assert grid._safe_userverify_summary(
            b"x" * (grid._MAX_USERVERIFY_BYTES + 1)
        ) == {"classification": "oversize"}
        assert grid._safe_userverify_summary("not bytes") == {
            "classification": "unreadable"
        }

    def test_grid_diagnostics_hash_signed_payload_url(self):
        from wafer.browser import _recaptcha_grid as grid

        marker = (
            "https://www.google.com/recaptcha/enterprise/payload?"
            "p=signed-secret&k=site-key",
            "Select all images with bicycles",
            "Verify",
        )

        safe = grid._safe_grid_state_marker(marker)

        assert safe == {
            "image_src_sha256": hashlib.sha256(marker[0].encode()).hexdigest(),
            "prompt": marker[1],
            "button": marker[2],
        }
        assert "signed-secret" not in repr(safe)
        assert grid._safe_grid_state_marker(None) is None

    def test_opt_in_challenge_snapshot_is_private_and_bounded(self, tmp_path):
        from wafer.browser import _recaptcha_grid as grid

        bframe = MagicMock()
        challenge = bframe.locator.return_value
        challenge.screenshot.return_value = b"diagnostic-png"

        with patch.object(grid, "_COLLECT_DET_DIR", str(tmp_path)):
            filename = grid._collect_challenge_snapshot(
                bframe,
                time.monotonic() + 5,
            )

        output = tmp_path / filename
        assert output.read_bytes() == b"diagnostic-png"
        assert output.stat().st_mode & 0o777 == 0o600
        challenge.screenshot.assert_called_once_with(
            type="png",
            timeout=pytest.approx(3000, abs=10),
        )

    def test_challenge_snapshot_is_disabled_by_default(self):
        from wafer.browser import _recaptcha_grid as grid

        bframe = MagicMock()
        with patch.object(grid, "_COLLECT_DET_DIR", None):
            assert (
                grid._collect_challenge_snapshot(
                    bframe,
                    time.monotonic() + 5,
                )
                is None
            )
        bframe.locator.assert_not_called()

    @pytest.mark.parametrize(
        ("before", "after"),
        [
            (
                {
                    "selected": False,
                    "base_visible": True,
                    "dom_signature": "static",
                    "image_signature": "base",
                    "visible_image_count": 1,
                    "replacement_src": "",
                },
                {
                    "selected": True,
                    "base_visible": True,
                    "dom_signature": "static",
                    "image_signature": "base",
                    "visible_image_count": 1,
                    "replacement_src": "",
                },
            ),
            (
                {
                    "selected": False,
                    "base_visible": False,
                    "dom_signature": "replacement",
                    "image_signature": "replacement-old",
                    "visible_image_count": 1,
                    "replacement_src": "old",
                },
                {
                    "selected": False,
                    "base_visible": False,
                    "dom_signature": "replacement",
                    "image_signature": "replacement-new",
                    "visible_image_count": 1,
                    "replacement_src": "new",
                },
            ),
            (
                {
                    "selected": False,
                    "base_visible": True,
                    "dom_signature": "base",
                    "image_signature": "base",
                    "visible_image_count": 1,
                    "replacement_src": "",
                },
                {
                    "selected": False,
                    "base_visible": False,
                    "dom_signature": "base",
                    "image_signature": "base",
                    "visible_image_count": 1,
                    "replacement_src": "",
                },
            ),
            (
                {
                    "selected": False,
                    "base_visible": False,
                    "dom_signature": "visible",
                    "image_signature": "visible-image",
                    "visible_image_count": 1,
                    "replacement_src": "",
                },
                {
                    "selected": False,
                    "base_visible": False,
                    "dom_signature": "visible",
                    "image_signature": "blank-transition",
                    "visible_image_count": 0,
                    "replacement_src": "",
                },
            ),
            (
                {
                    "selected": False,
                    "base_visible": True,
                    "dom_signature": "post-hover-markup",
                    "image_signature": "same-image",
                    "visible_image_count": 1,
                    "replacement_src": "",
                },
                {
                    "selected": False,
                    "base_visible": True,
                    "dom_signature": "post-click-transition-markup",
                    "image_signature": "same-image",
                    "visible_image_count": 1,
                    "replacement_src": "",
                },
            ),
        ],
    )
    def test_tile_click_requires_exact_cell_dom_acknowledgment(
        self,
        before,
        after,
    ):
        from wafer.browser import _recaptcha_grid as grid

        solver = MagicMock(_grid_recordings=None, _path_recordings=None)
        page = MagicMock()
        bframe = MagicMock()
        tile = bframe.locator.return_value
        tile.bounding_box.return_value = {
            "x": 100,
            "y": 200,
            "width": 90,
            "height": 90,
        }
        tile.evaluate.side_effect = [before, before, after]

        with patch.object(grid, "_sleep_with_deadline", return_value=True):
            _x, _y, acknowledged = grid._click_tile(
                solver,
                page,
                bframe,
                4,
                3,
                10.0,
                20.0,
                deadline=time.monotonic() + 5,
            )

        assert acknowledged is True
        page.mouse.click.assert_called_once()

    def test_tile_ack_baseline_is_sampled_after_hover_before_click(self):
        from wafer.browser import _recaptcha_grid as grid

        events = []
        solver = MagicMock(_grid_recordings=None, _path_recordings=None)
        page = MagicMock()
        page.mouse.move.side_effect = lambda *_args: events.append("hover")
        page.mouse.click.side_effect = lambda *_args: events.append("click")
        bframe = MagicMock()
        tile = bframe.locator.return_value
        tile.bounding_box.return_value = {
            "x": 100,
            "y": 200,
            "width": 90,
            "height": 90,
        }
        states = iter(
            [
                {
                    "selected": False,
                    "base_visible": True,
                    "dom_signature": "post-hover",
                    "image_signature": "post-hover",
                    "visible_image_count": 1,
                    "replacement_src": "",
                },
                {
                    "selected": False,
                    "base_visible": True,
                    "dom_signature": "post-hover",
                    "image_signature": "post-hover",
                    "visible_image_count": 1,
                    "replacement_src": "",
                },
                {
                    "selected": True,
                    "base_visible": True,
                    "dom_signature": "post-click",
                    "image_signature": "post-click",
                    "visible_image_count": 1,
                    "replacement_src": "",
                },
            ]
        )

        def evaluate(*_args, **_kwargs):
            events.append("evaluate")
            return next(states)

        tile.evaluate.side_effect = evaluate
        with patch.object(grid, "_sleep_with_deadline", return_value=True):
            _x, _y, acknowledged = grid._click_tile(
                solver,
                page,
                bframe,
                4,
                3,
                10.0,
                20.0,
                deadline=time.monotonic() + 5,
            )

        assert acknowledged is True
        assert events == [
            "hover",
            "evaluate",
            "evaluate",
            "click",
            "evaluate",
        ]

    def test_tile_click_refuses_unsettled_post_hover_dom(self):
        from wafer.browser import _recaptcha_grid as grid

        solver = MagicMock(_grid_recordings=None, _path_recordings=None)
        page = MagicMock()
        bframe = MagicMock()
        tile = bframe.locator.return_value
        tile.bounding_box.return_value = {
            "x": 100,
            "y": 200,
            "width": 90,
            "height": 90,
        }
        common = {
            "selected": False,
            "base_visible": True,
            "image_signature": "same",
            "visible_image_count": 1,
            "replacement_src": "",
        }
        tile.evaluate.side_effect = [
            {**common, "dom_signature": "hover-frame-1"},
            {**common, "dom_signature": "hover-frame-2"},
        ]

        with patch.object(grid, "_sleep_with_deadline", return_value=True):
            _x, _y, acknowledged = grid._click_tile(
                solver,
                page,
                bframe,
                4,
                3,
                10.0,
                20.0,
                deadline=time.monotonic() + 5,
            )

        assert acknowledged is False
        page.mouse.click.assert_not_called()

    def test_tile_click_refuses_css_animation_that_settles_hidden(self):
        from wafer.browser import _recaptcha_grid as grid

        clock = [100.0]
        solver = MagicMock(_grid_recordings=None, _path_recordings=None)
        page = MagicMock()
        bframe = MagicMock()
        tile = bframe.locator.return_value
        tile.bounding_box.return_value = {
            "x": 100,
            "y": 200,
            "width": 90,
            "height": 90,
        }
        visible = {
            "selected": False,
            "base_visible": True,
            "dom_signature": "unchanged",
            "image_signature": "opacity=1",
            "visible_image_count": 1,
            "replacement_src": "",
        }
        hidden = {
            **visible,
            "base_visible": False,
            "image_signature": "opacity=0",
            "visible_image_count": 0,
        }
        tile.evaluate.side_effect = [visible, *([hidden] * 20)]

        def advance(_deadline, _duration):
            clock[0] += 0.12
            return True

        with (
            patch.object(grid.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(grid, "_sleep_with_deadline", side_effect=advance),
        ):
            _x, _y, acknowledged = grid._click_tile(
                solver,
                page,
                bframe,
                4,
                3,
                10.0,
                20.0,
                deadline=105.0,
            )

        assert acknowledged is False
        page.mouse.click.assert_not_called()

    def test_tile_click_deadline_break_cannot_reuse_unstable_sample(self):
        from wafer.browser import _recaptcha_grid as grid

        solver = MagicMock(_grid_recordings=None, _path_recordings=None)
        page = MagicMock()
        bframe = MagicMock()
        tile = bframe.locator.return_value
        tile.bounding_box.return_value = {
            "x": 100,
            "y": 200,
            "width": 90,
            "height": 90,
        }
        visible = {
            "selected": False,
            "base_visible": True,
            "dom_signature": "same-dom",
            "image_signature": "opacity=1",
            "visible_image_count": 1,
            "replacement_src": "",
        }
        hidden = {
            **visible,
            "base_visible": False,
            "image_signature": "opacity=0",
            "visible_image_count": 0,
        }
        tile.evaluate.side_effect = [visible, hidden]

        with patch.object(
            grid,
            "_sleep_with_deadline",
            side_effect=[True, True, False],
        ):
            _x, _y, acknowledged = grid._click_tile(
                solver,
                page,
                bframe,
                4,
                3,
                10.0,
                20.0,
                deadline=time.monotonic() + 5,
            )

        assert acknowledged is False
        page.mouse.click.assert_not_called()

    def test_grid_must_be_fully_visible_and_stable_before_verify(self):
        from wafer.browser import _recaptcha_grid as grid

        stable = [
            {"visible_image_count": 1, "dom_signature": f"cell-{cell}"}
            for cell in range(9)
        ]
        with (
            patch.object(
                grid,
                "_grid_dom_states",
                side_effect=[stable, stable],
            ),
            patch.object(grid, "_sleep_with_deadline", return_value=True),
        ):
            assert grid._wait_for_grid_stable(
                MagicMock(),
                3,
                time.monotonic() + 5,
            )

    def test_hidden_grid_never_becomes_verify_ready_at_deadline(self):
        from wafer.browser import _recaptcha_grid as grid

        clock = [100.0]
        hidden = [
            {"visible_image_count": int(cell != 4), "dom_signature": f"cell-{cell}"}
            for cell in range(9)
        ]

        def advance(_deadline, _duration):
            clock[0] += 0.25
            return True

        with (
            patch.object(grid.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(grid, "_grid_dom_states", return_value=hidden),
            patch.object(grid, "_sleep_with_deadline", side_effect=advance),
        ):
            assert not grid._wait_for_grid_stable(
                MagicMock(),
                3,
                105.0,
            )

    def test_unacknowledged_tile_click_fails_closed_with_snapshot(self):
        from wafer.browser import _recaptcha_grid as grid

        clock = [100.0]
        solver = MagicMock(_grid_recordings=None, _path_recordings=None)
        page = MagicMock()
        bframe = MagicMock()
        tile = bframe.locator.return_value
        tile.bounding_box.return_value = {
            "x": 100,
            "y": 200,
            "width": 90,
            "height": 90,
        }
        before = {
            "selected": False,
            "base_visible": True,
            "dom_signature": "unchanged-markup",
            "image_signature": "post-hover",
            "visible_image_count": 1,
            "replacement_src": "",
        }
        after = {
            **before,
            # Signature-only CSS/animation drift is not click authority.
            "image_signature": "hover-animation-only",
        }
        tile.evaluate.side_effect = [before, before, *([after] * 50)]

        def advance(_deadline, _duration):
            clock[0] += 0.11
            return True

        with (
            patch.object(grid.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(grid, "_sleep_with_deadline", side_effect=advance),
            patch.object(
                grid,
                "_collect_challenge_snapshot",
                return_value="snapshot.png",
            ) as snapshot,
            patch.object(grid, "_collect_det_grid") as collect,
        ):
            _x, _y, acknowledged = grid._click_tile(
                solver,
                page,
                bframe,
                4,
                3,
                10.0,
                20.0,
                deadline=105.0,
            )

        assert acknowledged is False
        page.mouse.click.assert_called_once()
        snapshot.assert_called_once_with(bframe, 105.0)
        collect.assert_called_once_with(
            "",
            "3x3",
            "unacknowledged_click",
            extra={
                "cell": 4,
                "phase": "initial",
                "snapshot": "snapshot.png",
                "before": {
                    "selected": False,
                    "base_visible": True,
                    "visible_image_count": 1,
                    "replacement_present": False,
                    "dom_signature_sha256": hashlib.sha256(
                        b"unchanged-markup"
                    ).hexdigest(),
                    "image_signature_sha256": hashlib.sha256(
                        b"post-hover"
                    ).hexdigest(),
                },
                "after": {
                    "selected": False,
                    "base_visible": True,
                    "visible_image_count": 1,
                    "replacement_present": False,
                    "dom_signature_sha256": hashlib.sha256(
                        b"unchanged-markup"
                    ).hexdigest(),
                    "image_signature_sha256": hashlib.sha256(
                        b"hover-animation-only"
                    ).hexdigest(),
                },
            },
        )


class TestTmdClearanceEvidence:
    @pytest.mark.parametrize(
        "application_url",
        [
            ("https://www.alibaba.com/trade/search?SearchText=waterproof%20switch"),
            (
                "https://acs.aliexpress.com/h5/"
                "mtop.aliexpress.pdp.pc.query/1.0/?jsv=2.7.2"
            ),
        ],
    )
    def test_application_url_is_the_exact_retry_target(self, application_url):
        from wafer.browser._solver import _tmd_retry_target

        assert _tmd_retry_target(application_url) == application_url

    def test_alibaba_uses_strict_issued_callback_as_retry_target(self):
        from wafer.browser._solver import _tmd_retry_target

        callback = "https://www.alibaba.com/trade/search?SearchText=waterproof%20switch"
        issued = (
            "https://acs.alibaba.com/_____tmd_____/punish?"
            "x5secdata=issued&url=https%3A%2F%2Fwww.alibaba.com%2F"
            "trade%2Fsearch%3FSearchText%3Dwaterproof%2520switch"
        )

        assert _tmd_retry_target(issued) == callback

    def test_aliexpress_uses_only_native_mtop_retry_target(self):
        from wafer.browser._solver import (
            _TMD_MTOP_RETRY_URL,
            _tmd_retry_target,
        )

        issued = (
            "https://acs.aliexpress.com/_____tmd_____/punish?"
            "x5secdata=issued&url=https%3A%2F%2Fwww.aliexpress.com%2F"
            "item%2F1005001234567890.html"
        )

        assert _tmd_retry_target(issued) == _TMD_MTOP_RETRY_URL
        assert "www.aliexpress.com/item/" not in _tmd_retry_target(issued)

    @pytest.mark.parametrize("leading_slash", ["/", "//"])
    def test_aliexpress_accepts_real_mtop_prefixed_punishment_path(self, leading_slash):
        from wafer.browser._solver import (
            _TMD_MTOP_RETRY_URL,
            _tmd_retry_target,
        )

        issued = (
            "https://acs.aliexpress.com:443"
            f"{leading_slash}h5/mtop.aliexpress.pdp.pc.query/1.0/"
            "_____tmd_____/punish?x5secdata=issued&"
            "url=https%3A%2F%2Fwww.aliexpress.com%2Fitem%2F"
            "1005001234567890.html"
        )

        assert _tmd_retry_target(issued) == _TMD_MTOP_RETRY_URL

    @pytest.mark.parametrize(
        "issued",
        [
            "https://acs.alibaba.com/_____tmd_____/punish?x5secdata=issued",
            (
                "https://acs.alibaba.com/_____tmd_____/punish?"
                "url=https%3A%2F%2Falibaba.com.evil.test%2Fproduct"
            ),
            (
                "https://acs.alibaba.com/_____tmd_____/punish?"
                "url=https%3A%2F%2Fwww.aliexpress.com%2Fitem%2F1.html"
            ),
            (
                "https://acs.aliexpress.com/_____tmd_____/punish?"
                "url=https%3A%2F%2Fwww.alibaba.com%2Ftrade%2Fsearch"
            ),
            (
                "http://acs.alibaba.com/_____tmd_____/punish?"
                "url=https%3A%2F%2Fwww.alibaba.com%2Ftrade%2Fsearch"
            ),
            (
                "https://user@acs.alibaba.com/_____tmd_____/punish?"
                "url=https%3A%2F%2Fwww.alibaba.com%2Ftrade%2Fsearch"
            ),
            (
                "https://acs.alibaba.com:444/_____tmd_____/punish?"
                "url=https%3A%2F%2Fwww.alibaba.com%2Ftrade%2Fsearch"
            ),
            (
                "https://acs.alibaba.com/not-punish?"
                "url=https%3A%2F%2Fwww.alibaba.com%2Ftrade%2Fsearch"
            ),
            (
                "https://acs.aliexpress.com/arbitrary/prefix/"
                "_____tmd_____/punish?"
                "url=https%3A%2F%2Fwww.aliexpress.com%2Fitem%2F1.html"
            ),
            (
                "https://acs.aliexpress.com/h5/mtop.alibaba.product/1.0/"
                "_____tmd_____/punish?"
                "url=https%3A%2F%2Fwww.aliexpress.com%2Fitem%2F1.html"
            ),
            (
                "https://acs.aliexpress.com/h5/mtop.aliexpress.product/latest/"
                "_____tmd_____/punish?"
                "url=https%3A%2F%2Fwww.aliexpress.com%2Fitem%2F1.html"
            ),
        ],
    )
    def test_retry_target_rejects_missing_unsafe_or_cross_family_callback(self, issued):
        from wafer.browser._solver import _tmd_retry_target

        assert _tmd_retry_target(issued) is None

    def test_alibaba_and_aliexpress_clearance_never_cross_hosts(self):
        from wafer.browser._solver import _tmd_x5sec_signatures

        alibaba_target = "https://www.alibaba.com/trade/search?SearchText=switch"
        aliexpress_target = (
            "https://acs.aliexpress.com/h5/mtop.aliexpress.pdp.pc.query/1.0/"
        )
        cookies = [
            {
                "name": "x5sec",
                "value": "alibaba",
                "domain": ".alibaba.com",
                "path": "/trade/",
            },
            {
                "name": "x5sec",
                "value": "aliexpress",
                "domain": ".aliexpress.com",
                "path": "/h5/",
            },
        ]

        assert _tmd_x5sec_signatures(cookies, alibaba_target) == {
            ("alibaba.com", "/trade/", "alibaba")
        }
        assert _tmd_x5sec_signatures(cookies, aliexpress_target) == {
            ("aliexpress.com", "/h5/", "aliexpress")
        }

    def test_requires_new_or_changed_target_scoped_x5sec(self):
        from wafer.browser._solver import _tmd_x5sec_signatures

        prior = [
            {
                "name": "x5sec",
                "value": "old",
                "domain": ".aliexpress.com",
                "path": "/h5/",
            }
        ]
        unchanged = [dict(prior[0])]
        minted = [dict(prior[0], value="new")]

        assert not (_tmd_x5sec_signatures(unchanged) - _tmd_x5sec_signatures(prior))
        assert _tmd_x5sec_signatures(minted) - _tmd_x5sec_signatures(prior)

    @pytest.mark.parametrize("value", ["", None, 123])
    def test_empty_or_non_string_x5sec_is_not_clearance(self, value):
        from wafer.browser._solver import (
            _has_tmd_x5sec_clearance,
            _tmd_x5sec_signatures,
        )

        cookies = [
            {
                "name": "x5sec",
                "value": value,
                "domain": ".aliexpress.com",
                "path": "/h5/",
                "expires": time.time() + 60,
            }
        ]

        assert not _has_tmd_x5sec_clearance(cookies)
        assert not _tmd_x5sec_signatures(cookies)

    def test_x5sec_scope_uses_exact_mtop_retry_cookie_rules(self):
        from wafer.browser._solver import _has_tmd_x5sec_clearance

        assert _has_tmd_x5sec_clearance(
            [
                {
                    "name": "x5sec",
                    "value": "new",
                    "domain": ".aliexpress.com",
                    "path": "/h5/",
                    "expires": time.time() + 60,
                }
            ]
        )
        assert not _has_tmd_x5sec_clearance(
            [
                {
                    "name": "x5sec",
                    "value": "new",
                    "domain": ".aliexpress.com",
                    "path": "/h5x",
                    "expires": time.time() + 60,
                }
            ]
        )
        assert not _has_tmd_x5sec_clearance(
            [
                {
                    "name": "x5sec",
                    "value": "new",
                    "domain": ".aliexpress.com",
                    "path": "/h5/",
                    "expires": time.time() - 1,
                }
            ]
        )

    @pytest.mark.parametrize(
        ("domain", "expected"),
        [
            (".aliexpress.com", True),
            (".acs.aliexpress.com", True),
            ("acs.aliexpress.com", True),
            ("aliexpress.com", False),
            ("www.aliexpress.com", False),
        ],
    )
    def test_x5sec_scope_preserves_host_only_cookie_semantics(self, domain, expected):
        from wafer.browser._solver import _has_tmd_x5sec_clearance

        cookies = [
            {
                "name": "x5sec",
                "value": "new",
                "domain": domain,
                "path": "/h5/",
                "expires": time.time() + 60,
            }
        ]

        assert _has_tmd_x5sec_clearance(cookies) is expected

    def test_token_check_finds_token_in_tmd_wrapper_frame(self):
        from wafer.browser._recaptcha import _check_token

        page = MagicMock()
        top = MagicMock()
        wrapper = MagicMock()
        page.eval_on_selector.return_value = ""
        top.eval_on_selector.side_effect = RuntimeError("no textarea")
        wrapper.eval_on_selector.return_value = "enterprise-token"
        page.frames = [top, wrapper]

        assert _check_token(page)
        wrapper.eval_on_selector.assert_called_once_with(
            'textarea[name^="g-recaptcha-response"]', "el => el.value"
        )

    @patch("wafer.browser._recaptcha_grid._setup_payload_intercept")
    def test_releases_payload_listener_when_early_browser_setup_fails(self, mock_setup):
        from wafer.browser._recaptcha import wait_for_recaptcha

        cleanup = MagicMock()
        mock_setup.return_value = {"cleanup": cleanup}
        solver = MagicMock()
        solver._start_browse.side_effect = RuntimeError("browser unavailable")

        assert not wait_for_recaptcha(solver, MagicMock(), 1_000)
        cleanup.assert_called_once_with()

    def test_visible_bframe_enters_image_grid_solver(self):
        from wafer.browser._recaptcha import wait_for_recaptcha

        cleanup = MagicMock()
        anchor = MagicMock()
        anchor.url = "https://www.google.com/recaptcha/api2/anchor?k=x"
        anchor.name = "a-widget-1"
        anchor.eval_on_selector.return_value = ""
        bframe = MagicMock()
        bframe.url = "https://www.google.com/recaptcha/api2/bframe?k=x"
        bframe.name = "c-widget-1"
        bframe.eval_on_selector.return_value = ""
        bframe.locator.return_value.is_visible.return_value = True
        page = MagicMock()
        anchor.parent_frame = page
        bframe.parent_frame = page
        page.evaluate.return_value = []
        page.frames = [anchor, bframe]
        page.eval_on_selector.return_value = ""
        solver = MagicMock()
        with (
            patch(
                "wafer.browser._recaptcha_grid._setup_payload_intercept",
                return_value={"cleanup": cleanup, "payload": b"grid"},
            ),
            patch(
                "wafer.browser._recaptcha._click_element",
                return_value=True,
            ),
            patch(
                "wafer.browser._recaptcha_grid.solve_image_grid",
                return_value=True,
            ) as solve_grid,
            patch("wafer.browser._solver.patch_frame_screenxy"),
        ):
            assert wait_for_recaptcha(solver, page, 10_000)

        bframe.locator.assert_called_with(".rc-imageselect-challenge")
        solve_grid.assert_called_once()
        cleanup.assert_called_once_with()

    @pytest.mark.parametrize(
        ("url", "kind"),
        [
            ("https://www.google.com/recaptcha/api2/anchor?k=x", "api2/anchor"),
            (
                "https://www.recaptcha.net/recaptcha/enterprise/anchor?k=x",
                "enterprise/anchor",
            ),
            (
                "https://www.google.com/recaptcha/enterprise/bframe?k=x",
                "enterprise/bframe",
            ),
        ],
    )
    def test_accepts_google_and_recaptcha_net_api_variants(self, url, kind):
        from wafer.browser._recaptcha import _is_recaptcha_frame

        assert _is_recaptcha_frame(url, kind)

    def test_rejects_non_recaptcha_frame(self):
        from wafer.browser._recaptcha import _is_recaptcha_frame

        assert not _is_recaptcha_frame(
            "https://acs.aliexpress.com/_____tmd_____/punish", "api2/anchor"
        )

    @pytest.mark.parametrize(
        "url",
        [
            "https://evilgoogle.com/recaptcha/api2/anchor?k=x",
            "https://google.com.evil.example/recaptcha/api2/anchor?k=x",
            "https://www.google.com/recaptcha/api2/anchor-evil?k=x",
            "https://www.google.com/not-recaptcha/api2/anchor?k=x",
        ],
    )
    def test_rejects_lookalike_or_nonexact_frame_urls(self, url):
        from wafer.browser._recaptcha import _is_recaptcha_frame

        assert not _is_recaptcha_frame(url, "api2/anchor")

    @patch("wafer.browser._recaptcha.time.sleep")
    def test_checkbox_click_uses_remaining_deadline(self, mock_sleep):
        from wafer.browser._recaptcha import _click_element

        solver = MagicMock()
        page = MagicMock()
        frame = MagicMock()
        frame.locator.return_value.bounding_box.return_value = {
            "x": 1,
            "y": 2,
            "width": 10,
            "height": 10,
        }
        state = MagicMock(current_x=1, current_y=2)
        deadline = time.monotonic() + 0.05

        assert _click_element(
            solver, page, state, frame, ".recaptcha-checkbox-border", deadline
        )
        assert solver._replay_path.call_args.kwargs["deadline"] == deadline
        timeout = frame.locator.return_value.bounding_box.call_args.kwargs["timeout"]
        assert 1 <= timeout <= 50

    @patch("wafer.browser._recaptcha.time.sleep")
    def test_checkbox_click_stops_when_path_replay_exhausts_deadline(self, mock_sleep):
        from wafer.browser._recaptcha import _click_element

        solver = MagicMock()
        solver._replay_path.return_value = False
        page = MagicMock()
        frame = MagicMock()
        frame.locator.return_value.bounding_box.return_value = {
            "x": 1,
            "y": 2,
            "width": 10,
            "height": 10,
        }

        assert not _click_element(
            solver,
            page,
            MagicMock(current_x=1, current_y=2),
            frame,
            ".recaptcha-checkbox-border",
            time.monotonic() + 1,
        )
        page.mouse.click.assert_not_called()


class TestRecaptchaGridDeadline:
    def test_protocol_intermediate_wakes_observer_without_sleep(self):
        from wafer.browser import _recaptcha_grid as grid

        ready = MagicMock(return_value=True)
        with (
            patch(
                "wafer.browser._recaptcha._check_token",
                return_value=False,
            ),
            patch.object(grid, "_sleep_with_deadline") as sleep,
        ):
            outcome = grid._wait_for_post_verify_outcome(
                MagicMock(),
                MagicMock(),
                time.monotonic() + 10,
                None,
                protocol_intermediate_ready=ready,
            )

        assert outcome == "protocol_intermediate"
        ready.assert_called_once_with()
        sleep.assert_not_called()

    def test_verify_does_not_click_until_button_is_actionable(self):
        from wafer.browser import _recaptcha_grid as grid

        solver = MagicMock()
        solver._grid_recordings = []
        solver._path_recordings = []
        page = MagicMock()
        bframe = MagicMock()
        button = MagicMock()
        bframe.locator.return_value = button
        button.is_visible.return_value = True
        button.is_enabled.return_value = True
        button.get_attribute.side_effect = lambda name, **_kwargs: (
            "disabled" if name == "disabled" else None
        )

        with patch.object(grid, "_sleep_with_deadline", return_value=False):
            result = grid._click_verify(
                solver,
                page,
                bframe,
                10.0,
                20.0,
                deadline=time.monotonic() + 1,
            )

        assert result == (10.0, 20.0, False)
        page.mouse.click.assert_not_called()

    def test_verify_rechecks_fallback_after_mouse_path(self):
        from wafer.browser import _recaptcha_grid as grid

        solver = MagicMock()
        solver._grid_recordings = []
        solver._path_recordings = []
        page = MagicMock()
        bframe = MagicMock()
        button = MagicMock()
        bframe.locator.return_value = button
        button.is_visible.return_value = True
        button.is_enabled.return_value = True
        button.get_attribute.side_effect = lambda name, **_kwargs: (
            "verify-button" if name == "class" else None
        )
        button.bounding_box.return_value = {
            "x": 100,
            "y": 200,
            "width": 80,
            "height": 40,
        }

        with patch.object(grid, "_sleep_with_deadline", return_value=True):
            result = grid._click_verify(
                solver,
                page,
                bframe,
                10.0,
                20.0,
                deadline=time.monotonic() + 1,
                preclick_guard=lambda: False,
            )

        assert result == (10.0, 20.0, False)
        page.mouse.move.assert_called_once()
        page.mouse.click.assert_not_called()

    def test_classifier_uses_training_normalization_and_chw_batch(self):
        """Production inference must match the exported classifier contract."""
        import numpy as np
        from PIL import Image

        from wafer.browser import _recaptcha_grid as grid

        class RecordingSession:
            def __init__(self):
                self.feed = None

            def get_inputs(self):
                return [SimpleNamespace(name="input")]

            def run(self, _outputs, feeds):
                self.feed = feeds["input"]
                return [np.arange(14, dtype=np.float32)[None, :]]

        tile = Image.new("RGB", (2, 2))
        tile.putdata(
            [
                (128, 64, 32),
                (32, 128, 64),
                (64, 32, 128),
                (255, 0, 96),
            ]
        )
        session = RecordingSession()
        probabilities = grid._classify_tiles_batch(
            session,
            [tile],
            size=3,
        )

        assert session.feed.shape == (1, 3, 3, 3)
        expected_pixels = np.asarray(
            tile.resize((3, 3), Image.Resampling.BILINEAR),
            dtype=np.float32,
        )
        expected = (
            expected_pixels / 255.0
            - np.asarray([0.485, 0.456, 0.406], dtype=np.float32)
        ) / np.asarray([0.229, 0.224, 0.225], dtype=np.float32)
        np.testing.assert_allclose(
            session.feed[0],
            expected.transpose(2, 0, 1),
            rtol=1e-6,
        )
        nearest = np.asarray(
            tile.resize((3, 3), Image.Resampling.NEAREST), dtype=np.float32
        )
        assert not np.array_equal(expected_pixels, nearest)
        assert probabilities.shape == (1, 14)
        assert probabilities.argmax(axis=1).tolist() == [13]
        np.testing.assert_allclose(probabilities.sum(axis=1), [1.0])

    def test_post_verify_detects_a_delayed_token_without_touching_audio(
        self,
    ):
        """Verify observation must not switch a live image challenge to audio."""
        from wafer.browser import _recaptcha_grid as grid

        page = MagicMock()
        bframe = MagicMock()
        bframe.locator.return_value.first.is_visible.return_value = False
        previous_marker = ("old-payload", "Select all buses", "VERIFY")

        with (
            patch(
                "wafer.browser._recaptcha._check_token",
                side_effect=[False, False, True],
            ),
            patch.object(grid, "_grid_state_marker", return_value=previous_marker),
            patch.object(grid, "_sleep_with_deadline", return_value=True),
        ):
            outcome = grid._wait_for_post_verify_outcome(
                page,
                bframe,
                time.monotonic() + 1,
                previous_marker,
            )

        assert outcome == "solved"
        assert all(
            call.args[0] != "#recaptcha-audio-button"
            for call in bframe.locator.call_args_list
        )

    def test_post_verify_continues_when_a_new_grid_arrives(self):
        from wafer.browser import _recaptcha_grid as grid

        page = MagicMock()
        bframe = MagicMock()
        bframe.locator.return_value.first.is_visible.return_value = False
        previous_marker = ("old-payload", "Select all buses", "VERIFY")

        with (
            patch("wafer.browser._recaptcha._check_token", return_value=False),
            patch.object(
                grid,
                "_grid_state_marker",
                return_value=("new-payload", "Select all buses", "VERIFY"),
            ),
        ):
            outcome = grid._wait_for_post_verify_outcome(
                page,
                bframe,
                time.monotonic() + 1,
                previous_marker,
            )

        assert outcome == "changed"

    def test_post_verify_pending_is_not_mislabeled_as_incorrect(self):
        from wafer.browser import _recaptcha_grid as grid

        page = MagicMock()
        bframe = MagicMock()
        bframe.locator.return_value.first.is_visible.return_value = False
        previous_marker = ("same-payload", "Select all crosswalks", "VERIFY")

        with (
            patch("wafer.browser._recaptcha._check_token", return_value=False),
            patch.object(grid, "_grid_state_marker", return_value=previous_marker),
            patch.object(grid, "_sleep_with_deadline", return_value=False),
        ):
            outcome = grid._wait_for_post_verify_outcome(
                page,
                bframe,
                time.monotonic() + 1,
                previous_marker,
            )

        assert outcome == "pending"

    @pytest.mark.parametrize(
        (
            "protocol_intermediate",
            "verify_status",
            "classification",
            "expected_observations",
        ),
        [
            (False, 200, "protocol_solved", 2),
            (True, 200, "protocol_solved", 1),
            (True, 500, "protocol_solved", 2),
            (True, 200, "unreadable", 2),
            (True, 200, None, 2),
            (1, 200, "protocol_solved", 2),
        ],
    )
    def test_protocol_completion_only_short_circuits_for_outer_gate(
        self,
        protocol_intermediate,
        verify_status,
        classification,
        expected_observations,
    ):
        import io

        import numpy as np
        from PIL import Image

        from wafer.browser import _recaptcha_grid as grid

        image = Image.new("RGB", (12, 12))
        raw = io.BytesIO()
        image.save(raw, "PNG")
        response = MagicMock(status=200)
        response.body.return_value = raw.getvalue()
        page = MagicMock()
        page.request.get.return_value = response
        bframe = MagicMock()
        bframe.locator.return_value.first.get_attribute.return_value = (
            "https://www.google.com/recaptcha/api2/payload"
        )
        solver = MagicMock()
        solver._ensure_recordings.return_value = True
        probabilities = np.zeros((9, 14), dtype=np.float32)
        probabilities[:, 3] = 1.0
        diagnostics = {
            "verify_statuses": [],
            "verify_summaries": [],
        }

        def submit(*_args, **_kwargs):
            diagnostics["verify_statuses"].append(verify_status)
            if classification is not None:
                diagnostics["verify_summaries"].append(
                    {
                        "classification": classification,
                        "token_present": True,
                        "success_flag": True,
                        "error_present": False,
                        "continuation_present": False,
                    }
                )
            return 10.0, 20.0, True

        with (
            patch.object(
                grid,
                "_ensure_models_before",
                return_value=(MagicMock(), None),
            ),
            patch.object(
                grid,
                "_detect_grid_type",
                return_value=("static_3x3", "cars"),
            ),
            patch.object(grid, "_split_grid", return_value=[image] * 9),
            patch.object(
                grid,
                "_classify_tiles_batch",
                return_value=probabilities,
            ),
            patch.object(grid, "_select_tiles", return_value=[0]),
            patch.object(
                grid,
                "_click_tile",
                return_value=(10.0, 20.0, True),
            ),
            patch.object(grid, "_click_verify", side_effect=submit),
            patch.object(
                grid,
                "_wait_for_post_verify_outcome",
                side_effect=["pending", "solved"],
            ) as observe,
            patch.object(
                grid,
                "_grid_state_marker",
                return_value=("payload", "cars", "VERIFY"),
            ),
            patch.object(grid, "_wait_for_grid_stable", return_value=True),
            patch.object(grid, "_sleep_with_deadline", return_value=True),
            patch.object(grid, "_collect_tiles"),
            patch.object(grid, "_collect_det_grid"),
        ):
            solved = grid.solve_image_grid(
                solver,
                page,
                bframe,
                MagicMock(current_x=10.0, current_y=20.0),
                time.monotonic() + 60,
                diagnostics=diagnostics,
                max_attempts=1,
                protocol_completion_is_intermediate=protocol_intermediate,
            )

        assert solved is True
        assert observe.call_count == expected_observations
        first_ready = observe.call_args_list[0].kwargs[
            "protocol_intermediate_ready"
        ]
        if protocol_intermediate is True:
            assert callable(first_ready)
            assert first_ready() is (
                verify_status == 200 and classification == "protocol_solved"
            )
        else:
            assert first_ready is None
        if expected_observations == 2:
            assert observe.call_args_list[1].kwargs["maximum"] == 30.0

    def test_dynamic_grid_without_stable_base_selection_never_claims_complete(self):
        from wafer.browser import _recaptcha_grid as grid

        with (
            patch.object(grid, "_sleep_with_deadline", return_value=False),
            patch.object(
                grid,
                "_dynamic_base_selection_complete",
                return_value=False,
            ),
        ):
            _x, _y, complete = grid._handle_dynamic_replacements(
                MagicMock(),
                MagicMock(),
                MagicMock(),
                [1],
                0,
                MagicMock(),
                3,
                10.0,
                20.0,
                time.monotonic() + 1,
            )

        assert not complete

    def test_dynamic_grid_accepts_exact_stable_base_selection(self):
        from wafer.browser import _recaptcha_grid as grid

        bframe = MagicMock()
        bframe.evaluate.return_value = [None] * 9
        trace = []
        with (
            patch.object(grid, "_sleep_with_deadline", return_value=True),
            patch.object(
                grid,
                "_dynamic_base_selection_complete",
                return_value=True,
            ),
        ):
            _x, _y, complete = grid._handle_dynamic_replacements(
                MagicMock(),
                MagicMock(),
                bframe,
                [4, 8],
                13,
                MagicMock(),
                3,
                10.0,
                20.0,
                time.monotonic() + 0.05,
                trace=trace,
            )

        assert complete
        assert trace == [
            {
                "round": 1,
                "pending": [4, 8],
                "outcome": "stable_base_selection",
                "snapshot": None,
            }
        ]

    def test_dynamic_fallback_mutation_before_verify_never_submits(self):
        import io

        import numpy as np
        from PIL import Image

        from wafer.browser import _recaptcha_grid as grid

        image = Image.new("RGB", (12, 12))
        raw = io.BytesIO()
        image.save(raw, "PNG")
        response = MagicMock(status=200)
        response.body.return_value = raw.getvalue()
        page = MagicMock()
        page.request.get.return_value = response
        bframe = MagicMock()
        bframe.locator.return_value.first.get_attribute.return_value = (
            "https://www.google.com/recaptcha/api2/payload"
        )
        solver = MagicMock()
        solver._ensure_recordings.return_value = True
        probabilities = np.zeros((9, 14), dtype=np.float32)
        probabilities[:, 3] = 1.0

        def complete_dynamic(*args, **kwargs):
            kwargs["trace"].append(
                {
                    "round": 1,
                    "pending": [0],
                    "outcome": "stable_base_selection",
                    "snapshot": None,
                }
            )
            return 10.0, 20.0, True

        with (
            patch.object(
                grid,
                "_ensure_models_before",
                return_value=(MagicMock(), None),
            ),
            patch.object(
                grid,
                "_detect_grid_type",
                return_value=("dynamic_3x3", "cars"),
            ),
            patch.object(grid, "_split_grid", return_value=[image] * 9),
            patch.object(
                grid,
                "_classify_tiles_batch",
                return_value=probabilities,
            ),
            patch.object(grid, "_select_tiles", return_value=[0]),
            patch.object(
                grid,
                "_click_tile",
                return_value=(10.0, 20.0, True),
            ),
            patch.object(
                grid,
                "_handle_dynamic_replacements",
                side_effect=complete_dynamic,
            ),
            patch.object(grid, "_wait_for_grid_stable", return_value=True),
            patch.object(
                grid,
                "_dynamic_base_selection_state",
                return_value=None,
            ),
            patch.object(grid, "_click_verify") as verify,
            patch.object(grid, "_sleep_with_deadline", return_value=True),
            patch.object(grid, "_collect_tiles"),
            patch.object(grid, "_collect_det_grid"),
        ):
            solved = grid.solve_image_grid(
                solver,
                page,
                bframe,
                MagicMock(current_x=10.0, current_y=20.0),
                time.monotonic() + 60,
                max_attempts=1,
            )

        assert solved is False
        verify.assert_not_called()

    def test_dynamic_base_selection_requires_full_stable_interval(self):
        from wafer.browser import _recaptcha_grid as grid

        def state(cell):
            return {
                "selected": cell in {4, 8},
                "base_visible": True,
                "dom_signature": f"cell-{cell}",
                "visible_image_count": 1,
                "image_signature": f"image-{cell}",
                "replacement_src": "",
            }

        states = [state(cell) for cell in range(9)]
        clock = [10.0]

        def advance(_deadline, duration):
            clock[0] += duration
            return True

        with (
            patch.object(grid.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(
                grid,
                "_atomic_dynamic_base_snapshot",
                return_value={
                    "keyword": "traffic lights",
                    "states": states,
                },
            ),
            patch.object(grid, "_sleep_with_deadline", side_effect=advance),
        ):
            assert grid._dynamic_base_selection_complete(
                MagicMock(),
                3,
                {4, 8},
                "traffic lights",
                20.0,
            )
        assert clock[0] - 10.0 >= 1.5

    def test_dynamic_base_selection_rejects_late_replacement(self):
        from wafer.browser import _recaptcha_grid as grid

        clock = [10.0]

        def states_now(*_args):
            return {
                "keyword": "traffic lights",
                "states": [
                    {
                        "selected": cell in {4, 8},
                        "base_visible": True,
                        "dom_signature": f"cell-{cell}",
                        "visible_image_count": 1,
                        "image_signature": f"image-{cell}",
                        "replacement_src": (
                            "https://example.test/replacement"
                            if cell == 4 and clock[0] >= 11.4
                            else ""
                        ),
                    }
                    for cell in range(9)
                ],
            }

        def advance(_deadline, duration):
            clock[0] += duration
            return True

        with (
            patch.object(grid.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(
                grid,
                "_atomic_dynamic_base_snapshot",
                side_effect=states_now,
            ),
            patch.object(grid, "_sleep_with_deadline", side_effect=advance),
        ):
            assert not grid._dynamic_base_selection_complete(
                MagicMock(),
                3,
                {4, 8},
                "traffic lights",
                20.0,
            )

    def test_dynamic_base_selection_rejects_prompt_change(self):
        from wafer.browser import _recaptcha_grid as grid

        states = [
            {
                "selected": cell in {4, 8},
                "base_visible": True,
                "dom_signature": f"cell-{cell}",
                "visible_image_count": 1,
                "image_signature": f"image-{cell}",
                "replacement_src": "",
            }
            for cell in range(9)
        ]
        clock = [10.0]

        def snapshot_now(*_args):
            return {
                "keyword": (
                    "traffic lights" if clock[0] < 11.0 else "motorcycles"
                ),
                "states": states,
            }

        def advance(_deadline, duration):
            clock[0] += duration
            return True

        with (
            patch.object(grid.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(
                grid,
                "_atomic_dynamic_base_snapshot",
                side_effect=snapshot_now,
            ),
            patch.object(grid, "_sleep_with_deadline", side_effect=advance),
        ):
            assert not grid._dynamic_base_selection_complete(
                MagicMock(),
                3,
                {4, 8},
                "traffic lights",
                20.0,
            )

    def test_dynamic_base_selection_rejects_insufficient_remaining_time(self):
        from wafer.browser import _recaptcha_grid as grid

        with (
            patch.object(grid.time, "monotonic", return_value=10.0),
            patch.object(grid, "_atomic_dynamic_base_snapshot") as states,
        ):
            assert not grid._dynamic_base_selection_complete(
                MagicMock(),
                3,
                {4, 8},
                "traffic lights",
                11.99,
            )
        states.assert_not_called()

    def test_dynamic_fallback_summary_retains_no_dom_or_image_identity(self):
        from wafer.browser import _recaptcha_grid as grid

        states = [
            {
                "selected": cell == 0,
                "base_visible": True,
                "dom_signature": "secret-dom-markup",
                "visible_image_count": 1,
                "image_signature": "https://google.test/payload?signed=secret",
                "replacement_src": (
                    "https://google.test/replacement?signed=secret"
                    if cell == 0
                    else ""
                ),
            }
            for cell in range(9)
        ]
        with patch.object(
            grid,
            "_atomic_dynamic_base_snapshot",
            return_value={"keyword": "traffic lights", "states": states},
        ):
            summary = grid._safe_dynamic_base_summary(
                MagicMock(),
                3,
                {0},
                "traffic lights",
                time.monotonic() + 1,
            )

        assert summary == {
            "readable": True,
            "keyword_match": True,
            "cell_count": 9,
            "selected_cells": [0],
            "expected_cells": [0],
            "base_visible_count": 9,
            "replacement_count": 1,
            "all_cells_visible": True,
        }
        assert "secret" not in repr(summary)

    @pytest.mark.parametrize(
        "mutation",
        [
            lambda states: states[4].update(selected=False),
            lambda states: states[2].update(selected=True),
            lambda states: states[4].update(base_visible=False),
            lambda states: states[4].update(replacement_src="https://example.test"),
            lambda states: states[4].update(visible_image_count=0),
        ],
    )
    def test_dynamic_base_selection_rejects_ambiguous_state(self, mutation):
        from wafer.browser import _recaptcha_grid as grid

        states = [
            {
                "selected": cell in {4, 8},
                "base_visible": True,
                "dom_signature": f"cell-{cell}",
                "visible_image_count": 1,
                "image_signature": f"image-{cell}",
                "replacement_src": "",
            }
            for cell in range(9)
        ]
        mutation(states)
        with (
            patch.object(
                grid,
                "_atomic_dynamic_base_snapshot",
                return_value={
                    "keyword": "traffic lights",
                    "states": states,
                },
            ),
            patch.object(grid, "_sleep_with_deadline", return_value=False),
        ):
            assert not grid._dynamic_base_selection_complete(
                MagicMock(),
                3,
                {4, 8},
                "traffic lights",
                time.monotonic() + 3,
            )

    def test_dynamic_all_nontarget_replacements_complete_before_verify(self):
        import io

        import numpy as np
        from PIL import Image

        from wafer.browser import _recaptcha_grid as grid

        image = Image.new("RGB", (12, 12))
        raw = io.BytesIO()
        image.save(raw, "PNG")
        response = MagicMock(status=200)
        response.body.return_value = raw.getvalue()
        page = MagicMock()
        page.request.get.return_value = response
        bframe = MagicMock()
        bframe.evaluate.return_value = ["https://www.google.com/recaptcha/api2/payload"]
        probabilities = np.zeros((1, 14), dtype=np.float32)
        probabilities[0, 1] = 1.0
        trace = []

        with (
            patch.object(grid, "_sleep_with_deadline", return_value=True),
            patch.object(grid, "_classify_tiles_batch", return_value=probabilities),
        ):
            _x, _y, complete = grid._handle_dynamic_replacements(
                MagicMock(),
                page,
                bframe,
                [0],
                0,
                MagicMock(),
                3,
                10.0,
                20.0,
                time.monotonic() + 1,
                trace=trace,
            )

        assert complete
        assert trace == [
            {
                "round": 1,
                "pending": [0],
                "observed_cells": [0],
                "classifications": [
                    {
                        "cell": 0,
                        "target_score": 0.0,
                        "argmax": 1,
                        "selected": False,
                    }
                ],
                "clicks": [],
            }
        ]

    def test_dynamic_failed_replacement_click_is_not_silently_complete(self):
        import io

        import numpy as np
        from PIL import Image

        from wafer.browser import _recaptcha_grid as grid

        image = Image.new("RGB", (12, 12))
        raw = io.BytesIO()
        image.save(raw, "PNG")
        response = MagicMock(status=200)
        response.body.return_value = raw.getvalue()
        page = MagicMock()
        page.request.get.return_value = response
        bframe = MagicMock()
        bframe.evaluate.return_value = ["https://www.google.com/recaptcha/api2/payload"]
        probabilities = np.zeros((1, 14), dtype=np.float32)
        probabilities[0, 0] = 1.0

        with (
            patch.object(grid, "_sleep_with_deadline", return_value=True),
            patch.object(grid, "_classify_tiles_batch", return_value=probabilities),
            patch.object(grid, "_click_tile", return_value=(10.0, 20.0, False)),
        ):
            _x, _y, complete = grid._handle_dynamic_replacements(
                MagicMock(),
                page,
                bframe,
                [0],
                0,
                MagicMock(),
                3,
                10.0,
                20.0,
                time.monotonic() + 1,
            )

        assert not complete

    def test_models_are_warmed_before_they_are_published(self, monkeypatch):
        from wafer.browser import _recaptcha_grid as grid

        classifier = MagicMock()
        classifier.get_inputs.return_value = [SimpleNamespace(name="input")]
        detector = MagicMock()
        detector.get_inputs.return_value = []
        session_options = MagicMock()
        ort = SimpleNamespace(
            SessionOptions=MagicMock(return_value=session_options),
            InferenceSession=MagicMock(side_effect=[classifier, detector]),
        )
        hub = SimpleNamespace(hf_hub_download=MagicMock(side_effect=["cls", "det"]))
        monkeypatch.setattr(grid, "_cls_session", None)
        monkeypatch.setattr(grid, "_det_session", None)
        monkeypatch.setattr(grid, "_models_unavailable", False)
        monkeypatch.setattr(grid, "_validate_model_asset", lambda path, *_: path)
        monkeypatch.setitem(sys.modules, "onnxruntime", ort)
        monkeypatch.setitem(sys.modules, "huggingface_hub", hub)

        cls, det = grid._ensure_models()

        assert cls is classifier
        assert det is detector
        classifier.run.assert_called_once()
        detector.run.assert_called_once()
        assert grid._cls_session is classifier
        assert grid._det_session is detector

    def test_failed_warmup_is_not_published(self, monkeypatch):
        from wafer.browser import _recaptcha_grid as grid

        classifier = MagicMock()
        classifier.get_inputs.return_value = [SimpleNamespace(name="input")]
        detector = MagicMock()
        detector.run.side_effect = RuntimeError("invalid model contract")
        ort = SimpleNamespace(
            SessionOptions=MagicMock(),
            InferenceSession=MagicMock(side_effect=[classifier, detector]),
        )
        hub = SimpleNamespace(hf_hub_download=MagicMock(side_effect=["cls", "det"]))
        monkeypatch.setattr(grid, "_cls_session", None)
        monkeypatch.setattr(grid, "_det_session", None)
        monkeypatch.setattr(grid, "_models_unavailable", False)
        monkeypatch.setattr(grid, "_validate_model_asset", lambda path, *_: path)
        monkeypatch.setitem(sys.modules, "onnxruntime", ort)
        monkeypatch.setitem(sys.modules, "huggingface_hub", hub)

        cls, det = grid._ensure_models()

        assert cls is classifier
        assert det is None
        assert grid._cls_session is classifier
        assert grid._det_session is None

    @pytest.mark.parametrize(
        ("helper_name", "args"),
        [
            ("_click_tile", (0, 3, 10.0, 20.0)),
            ("_click_verify", (10.0, 20.0)),
            ("_click_reload", (10.0, 20.0)),
        ],
    )
    def test_deadline_exhausted_path_never_clicks(self, helper_name, args):
        from wafer.browser import _recaptcha_grid as grid

        solver = MagicMock()
        solver._grid_recordings = [{"rows": []}]
        solver._path_recordings = [{"rows": []}]
        solver._replay_path.return_value = False
        page = MagicMock()
        bframe = MagicMock()
        bframe.locator.return_value.bounding_box.return_value = {
            "x": 1,
            "y": 2,
            "width": 10,
            "height": 10,
        }
        helper = getattr(grid, helper_name)

        result = helper(
            solver,
            page,
            bframe,
            *args,
            deadline=time.monotonic() + 1,
        )

        assert result == (*args[-2:], False)
        page.mouse.click.assert_not_called()

    def test_cold_model_load_does_not_block_past_deadline(self, monkeypatch):
        from wafer.browser import _recaptcha_grid as grid

        release = threading.Event()
        monkeypatch.setattr(grid, "_cls_session", None)
        monkeypatch.setattr(grid, "_det_session", None)
        monkeypatch.setattr(grid, "_models_unavailable", False)
        monkeypatch.setattr(grid, "_model_load_started", False)
        monkeypatch.setattr(grid, "_model_load_done", threading.Event())
        monkeypatch.setattr(grid, "_model_start_lock", threading.Lock())
        monkeypatch.setattr(
            grid,
            "_ensure_models",
            lambda: release.wait(timeout=1),
        )

        started = time.monotonic()
        try:
            assert grid._ensure_models_before(started + 0.02) == (None, None)
            assert time.monotonic() - started < 0.2
        finally:
            release.set()
            assert grid._model_load_done.wait(timeout=1)

    def test_partial_model_load_retries_only_missing_model(self, monkeypatch):
        from wafer.browser import _recaptcha_grid as grid

        classifier = object()
        detector = object()
        monkeypatch.setattr(grid, "_cls_session", classifier)
        monkeypatch.setattr(grid, "_det_session", None)
        monkeypatch.setattr(grid, "_models_unavailable", False)
        monkeypatch.setattr(grid, "_model_load_started", True)
        completed = threading.Event()
        completed.set()
        monkeypatch.setattr(grid, "_model_load_done", completed)
        monkeypatch.setattr(grid, "_model_start_lock", threading.Lock())

        def finish_missing_model():
            grid._det_session = detector
            return classifier, detector

        monkeypatch.setattr(grid, "_ensure_models", finish_missing_model)

        assert grid._ensure_models_before(time.monotonic() + 1) == (
            classifier,
            detector,
        )

    def test_public_preload_requires_both_models(self):
        with patch(
            "wafer.browser._recaptcha_grid._ensure_models_before",
            return_value=(object(), None),
        ):
            assert not preload_recaptcha_models(timeout=0.1)
        with patch(
            "wafer.browser._recaptcha_grid._ensure_models_before",
            return_value=(object(), object()),
        ):
            assert preload_recaptcha_models(timeout=0.1)

    def test_preflight_raises_unless_both_models_are_ready(self):
        with patch(
            "wafer.browser._recaptcha_grid.preload_recaptcha_models",
            return_value=False,
        ):
            with pytest.raises(RuntimeError, match="not both ready"):
                preflight_recaptcha_models(timeout=0.1)
        with patch(
            "wafer.browser._recaptcha_grid.preload_recaptcha_models",
            return_value=True,
        ):
            assert preflight_recaptcha_models(timeout=0.1) is None

    @pytest.mark.parametrize("timeout", [-1, True, "1"])
    def test_public_preload_rejects_invalid_timeout(self, timeout):
        with pytest.raises(ValueError, match="non-negative"):
            preload_recaptcha_models(timeout=timeout)

    def test_model_asset_validation_rejects_size_and_digest_mismatch(self, tmp_path):
        from wafer.browser._recaptcha_grid import _validate_model_asset

        model = tmp_path / "model.onnx"
        model.write_bytes(b"pinned model bytes")
        digest = hashlib.sha256(model.read_bytes()).hexdigest()

        assert _validate_model_asset(model, model.stat().st_size, digest) == str(model)
        assert _validate_model_asset(model, model.stat().st_size + 1, digest) is None
        assert _validate_model_asset(model, model.stat().st_size, "0" * 64) is None


class TestScreenXYFixScript:
    def test_screenxy_fix_script_exists(self):
        """The screenXY fix script constant is defined and non-empty."""
        from wafer.browser._solver import _SCREENXY_FIX_SCRIPT

        assert _SCREENXY_FIX_SCRIPT
        assert "screenX" in _SCREENXY_FIX_SCRIPT
        assert "screenY" in _SCREENXY_FIX_SCRIPT
        assert "MouseEvent" in _SCREENXY_FIX_SCRIPT


# ---------------------------------------------------------------------------
# Cloudflare early bail-out
# ---------------------------------------------------------------------------


class TestCloudflareEarlyBailout:
    @patch("time.sleep")
    @patch("time.monotonic")
    def test_no_iframe_bails_after_grace(self, mock_mono, mock_sleep):
        """No CF iframe after 3s grace period → reports challenge absence."""
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
        assert result is None

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_iframe_present_continues_polling(self, mock_mono, mock_sleep):
        """With CF iframe present, should keep polling for cf_clearance."""
        from wafer.browser._cloudflare import wait_for_cloudflare

        page = MagicMock()
        solver = MagicMock()
        # No cf_clearance, then it appears
        page.context.cookies.side_effect = [
            [],
            [{"name": "cf_clearance", "value": "solved"}],
        ]
        # CF iframe is present with checkbox
        cf_frame = MagicMock()
        cf_frame.url = "https://challenges.cloudflare.com/turnstile/v0/..."
        page.frames = [cf_frame]
        # monotonic calls: deadline, grace_deadline,
        # loop check, click throttle check, click timestamp,
        # loop check (2nd iteration)
        mock_mono.side_effect = [0.0, 0.0, 1.0, 1.0, 1.0, 2.0]

        result = wait_for_cloudflare(solver, page, 30000)
        assert result is True

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_cf_clearance_before_grace_returns_true(self, mock_mono, mock_sleep):
        """If cf_clearance appears early, returns True immediately."""
        from wafer.browser._cloudflare import wait_for_cloudflare

        page = MagicMock()
        solver = MagicMock()
        page.context.cookies.return_value = [{"name": "cf_clearance", "value": "fast"}]
        page.frames = []
        mock_mono.side_effect = [0.0, 0.0, 0.5]

        result = wait_for_cloudflare(solver, page, 30000)
        assert result is True


# ---------------------------------------------------------------------------
# Async passthrough
# ---------------------------------------------------------------------------


class TestAsyncBrowserPassthrough:
    @patch("asyncio.sleep")
    async def test_passthrough_returns_wafer_response(self, mock_sleep):
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

    @patch("asyncio.sleep")
    async def test_challenge_absent_passthrough_preserves_session_and_charset(
        self,
        mock_sleep,
    ):
        from wafer.browser._solver import CapturedResponse

        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        browser_result = SolveResult(
            cookies=[
                {
                    "name": "browser_cookie",
                    "value": "merged",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": -1,
                }
            ],
            user_agent="Chrome/150.0.0.0",
            response=CapturedResponse(
                url="https://example.com/page",
                status=200,
                headers={"content-type": "text/html; charset=iso-8859-1"},
                body=b"<html><body>caf\xe9</body></html>",
            ),
            challenge_absent=True,
        )
        session, client = make_async_session(
            [cf_resp],
            max_rotations=0,
            browser_solver=MockBrowserSolver(result=browser_result),
            use_cookie_jar=True,
        )
        client.cookie_jar.add(
            "auth=keep; Domain=.example.com; Path=/; Secure",
            "https://example.com/",
        )
        session._rebuild_client = MagicMock()

        response = await session.get("https://example.com/page")

        session._rebuild_client.assert_not_called()
        assert session._fingerprint.pinned is False
        assert client.cookie_jar.get("auth", response.url).value == "keep"
        assert (
            client.cookie_jar.get("browser_cookie", response.url).value
            == "merged"
        )
        assert "café" in response.text


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
        solver._browse_recordings = [
            {
                "rows": [
                    {"t": 0.0, "dx": 0.0, "dy": 0.0, "scroll_y": 0},
                    {"t": 0.1, "dx": 10.0, "dy": 5.0, "scroll_y": 0},
                    {"t": 0.2, "dx": 20.0, "dy": 10.0, "scroll_y": -100},
                    {"t": 0.3, "dx": 30.0, "dy": 15.0, "scroll_y": 0},
                ],
                "max_scroll": 500,
                "sections": 2,
                "name": "test_browse.csv",
            }
        ]
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
    def test_none_state_falls_back_to_sleep(self, mock_mono, mock_sleep):
        """None state falls back to time.sleep(duration)."""
        solver = self._make_solver_with_browses()
        page = MagicMock()

        mock_mono.side_effect = [0.0, 2.0]
        solver._replay_browse_chunk(page, None, 2.0)
        mock_sleep.assert_any_call(2.0)
        page.mouse.move.assert_not_called()

    @patch("time.sleep")
    @patch("time.monotonic")
    def test_exhausted_recording_falls_back_to_sleep(self, mock_mono, mock_sleep):
        """Exhausted state falls back to time.sleep(duration)."""
        from wafer.browser._solver import _BrowseState

        solver = self._make_solver_with_browses()
        page = MagicMock()
        state = _BrowseState(
            rows=[],
            index=0,
            time_scale=1.0,
            origin_x=0,
            origin_y=0,
            scroll_scale=1.0,
            current_x=0,
            current_y=0,
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


# ---------------------------------------------------------------------------
# Browser-solve timeout bounding
#
# Regression: a caller must not hang past its request timeout while a
# challenge is being browser-solved, and a shared solver's lock must not
# block one caller while another solve is in flight. (Wellfound TODO.)
# ---------------------------------------------------------------------------


class _RecordingSolver:
    """Solver stub that records the timeout passed to solve() and fails."""

    def __init__(self):
        self.timeouts = []

    def solve(self, url, challenge_type=None, timeout=None, embedder=None, replay=None):
        self.timeouts.append(timeout)
        return None  # "fails" → caller reports the challenge

    def close(self):
        pass


class _BudgetConsumingSolver:
    """Advance a fake monotonic clock by every granted solve timeout."""

    def __init__(self, clock):
        self.clock = clock
        self.timeouts = []

    def solve(
        self,
        url,
        challenge_type=None,
        timeout=None,
        embedder=None,
        replay=None,
    ):
        assert timeout is not None
        self.timeouts.append(timeout)
        self.clock[0] += timeout
        return None

    async def asolve(self, *args, **kwargs):
        return self.solve(*args, **kwargs)

    def close(self):
        pass


class TestBrowserSolveTimeout:
    def test_sync_tmd_contexts_receive_fair_deadline_slices(self):
        clock = [100.0]
        solver = _BudgetConsumingSolver(clock)
        session, _ = make_sync_session(
            [MockResponse(200)],
            browser_solver=solver,
        )

        with patch("wafer._sync.time.monotonic", side_effect=lambda: clock[0]):
            result = session._try_browser_solve(
                ChallengeType.TMD,
                "https://acs.example.com/api",
                deadline=280.0,
            )

        assert result is False
        assert solver.timeouts == pytest.approx([165 / 3] * 3)
        assert clock[0] == pytest.approx(265.0)

    @pytest.mark.asyncio
    async def test_async_tmd_contexts_receive_fair_deadline_slices(self):
        clock = [100.0]
        solver = _BudgetConsumingSolver(clock)
        session, _ = make_async_session(
            [MockResponse(200)],
            browser_solver=solver,
        )

        with patch("wafer._async.time.monotonic", side_effect=lambda: clock[0]):
            result = await session._try_browser_solve(
                ChallengeType.TMD,
                "https://acs.example.com/api",
                deadline=280.0,
            )

        assert result is False
        assert solver.timeouts == pytest.approx([165 / 3] * 3)
        assert clock[0] == pytest.approx(265.0)

    def test_sync_tmd_recaptcha_retains_one_long_single_use_context(self):
        clock = [100.0]
        solver = _BudgetConsumingSolver(clock)
        session, _ = make_sync_session(
            [MockResponse(200)],
            browser_solver=solver,
        )
        issued = (
            "https://acs.aliexpress.com/_____tmd_____/punish?"
            "action=captcharecaptcha&x5secdata=issued"
        )

        with patch("wafer._sync.time.monotonic", side_effect=lambda: clock[0]):
            result = session._try_browser_solve(
                ChallengeType.TMD,
                issued,
                deadline=280.0,
            )

        assert result is False
        assert solver.timeouts == pytest.approx([165.0])
        assert clock[0] == pytest.approx(265.0)

    @pytest.mark.asyncio
    async def test_async_tmd_recaptcha_retains_one_long_single_use_context(
        self,
    ):
        clock = [100.0]
        solver = _BudgetConsumingSolver(clock)
        session, _ = make_async_session(
            [MockResponse(200)],
            browser_solver=solver,
        )
        issued = (
            "https://acs.aliexpress.com/_____tmd_____/punish?"
            "action=captcharecaptcha&x5secdata=issued"
        )

        with patch("wafer._async.time.monotonic", side_effect=lambda: clock[0]):
            result = await session._try_browser_solve(
                ChallengeType.TMD,
                issued,
                deadline=280.0,
            )

        assert result is False
        assert solver.timeouts == pytest.approx([165.0])
        assert clock[0] == pytest.approx(265.0)

    def test_short_tmd_budget_uses_one_viable_context(self):
        clock = [100.0]
        solver = _BudgetConsumingSolver(clock)
        session, _ = make_sync_session(
            [MockResponse(200)],
            browser_solver=solver,
        )

        with patch("wafer._sync.time.monotonic", side_effect=lambda: clock[0]):
            result = session._try_browser_solve(
                ChallengeType.TMD,
                "https://acs.example.com/api",
                deadline=130.0,
            )

        assert result is False
        assert solver.timeouts == pytest.approx([22.5])
        assert clock[0] == pytest.approx(122.5)

    @patch("time.sleep")
    def test_solve_timeout_clamped_to_request_deadline_sync(self, mock_sleep):
        """A per-request timeout clamps the browser solve to the remaining
        budget, so a slow solve can't block the caller past their timeout."""
        solver = _RecordingSolver()
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        session, _ = make_sync_session(
            [cf_resp], max_rotations=0, browser_solver=solver
        )
        resp = session.get("https://example.com/page", timeout=5)
        assert resp.challenge_type == "cloudflare"
        assert len(solver.timeouts) == 1
        # Finite budget within the 5s request timeout — NOT None, which
        # would let the solver run its full 30s default.
        assert solver.timeouts[0] is not None
        assert 0 < solver.timeouts[0] <= 5

    @patch("time.sleep")
    def test_solve_bounded_by_session_timeout_sync(self, mock_sleep):
        """The session timeout is a total deadline, so a browser solve with
        no per-request timeout is bounded by the remaining session budget
        (~30s) rather than running unbounded on the solver's own default."""
        solver = _RecordingSolver()
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        session, _ = make_sync_session(
            [cf_resp], max_rotations=0, browser_solver=solver
        )
        session.get("https://example.com/page")
        # Ten percent remains for cookie injection + the HTTP retry.
        assert solver.timeouts[0] == pytest.approx(27.0, abs=1.0)

    @pytest.mark.asyncio
    async def test_solve_timeout_clamped_to_request_deadline_async(self):
        """Async path clamps the browser solve to the request deadline."""
        solver = _RecordingSolver()
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        session, _ = make_async_session(
            [cf_resp], max_rotations=0, browser_solver=solver
        )
        resp = await session.get("https://example.com/page", timeout=5)
        assert resp.challenge_type == "cloudflare"
        assert len(solver.timeouts) == 1
        assert solver.timeouts[0] is not None
        assert 0 < solver.timeouts[0] <= 5

    @pytest.mark.asyncio
    async def test_sixty_second_deadline_reserves_replay_budget(self):
        """A near-deadline solve must not race the caller's own timeout."""

        solver = _RecordingSolver()
        cf_resp = MockResponse(
            403,
            {"cf-mitigated": "challenge"},
            "<html>Just a moment...</html>",
        )
        session, _ = make_async_session(
            [cf_resp], max_rotations=0, browser_solver=solver
        )

        resp = await session.get("https://example.com/page", timeout=60)

        assert resp.challenge_type == "cloudflare"
        assert len(solver.timeouts) == 1
        assert solver.timeouts[0] == pytest.approx(55.0, abs=0.5)

    def test_solve_skips_when_lock_busy(self):
        """solve() must not block past its timeout waiting for the shared
        solver lock. A concurrent solve (modeled by holding the lock on a
        separate thread) must not stall this caller past its budget — so
        concurrent or repeated solves can't block a caller past its
        request timeout.

        The lock is held on a *separate* thread and solve() runs on its
        own thread joined with a timeout, so a regression to an unbounded
        acquire fails this test cleanly (thread still alive) instead of
        deadlocking the whole suite (the non-reentrant lock would block a
        same-thread re-acquire forever, and there is no pytest-timeout)."""
        import threading

        solver = BrowserSolver()
        held = threading.Event()
        release = threading.Event()

        def _holder():
            solver._lock.acquire()
            held.set()
            release.wait(10)
            solver._lock.release()

        holder = threading.Thread(target=_holder, daemon=True)
        holder.start()
        assert held.wait(2), "holder thread failed to take the lock"

        result = {}

        def _run():
            result["value"] = solver.solve(
                "https://example.com/", "cloudflare", timeout=0.3
            )

        worker = threading.Thread(target=_run, daemon=True)
        t0 = time.monotonic()
        worker.start()
        worker.join(timeout=5)
        elapsed = time.monotonic() - t0

        release.set()
        holder.join(timeout=2)
        solver.close()

        assert not worker.is_alive(), (
            "solve() hung on a busy lock (regression: unbounded acquire)"
        )
        assert result["value"] is None
        assert elapsed < 3.0  # bounded by ~0.3s, not the 30s default

    def test_render_skips_when_lock_busy(self):
        """render() owes callers the same bound as solve().

        A shared solver serializes browser work, so a render must not stall
        past its budget waiting on someone else's solve. Same structure as
        the solve test: the lock is held on a separate thread and the render
        runs on its own joined thread, so an unbounded acquire fails the
        assertion instead of deadlocking the suite.
        """
        import threading

        solver = BrowserSolver()
        held = threading.Event()
        release = threading.Event()

        def _holder():
            solver._lock.acquire()
            held.set()
            release.wait(10)
            solver._lock.release()

        holder = threading.Thread(target=_holder, daemon=True)
        holder.start()
        assert held.wait(2), "holder thread failed to take the lock"

        result = {}

        def _run():
            result["value"] = solver.render("https://example.com/", timeout=0.3)

        worker = threading.Thread(target=_run, daemon=True)
        t0 = time.monotonic()
        worker.start()
        worker.join(timeout=5)
        elapsed = time.monotonic() - t0

        release.set()
        holder.join(timeout=2)
        solver.close()

        assert not worker.is_alive(), (
            "render() hung on a busy lock (regression: unbounded acquire)"
        )
        assert result["value"] is None
        assert elapsed < 3.0

    def test_render_timeout_is_bounded_by_the_request_budget(self):
        """A per-request timeout= must cap the render, not just the solve."""
        solver = BrowserSolver(solve_timeout=300)
        recorded = []

        def _slow_render(url, timeout=None, max_size=None):
            recorded.append(timeout)
            return None

        solver.render = _slow_render
        session, _ = make_sync_session([MockResponse(200)], browser_solver=solver)
        with pytest.raises(ConnectionFailed):
            session.render("https://example.com/", timeout=12)
        solver.close()

        # The solver's own 300s default must not win over the caller's budget.
        assert recorded and recorded[0] is not None
        assert recorded[0] <= 12


class TestRecaptchaModelWaitBudget:
    """A cold model load must not consume the whole challenge deadline."""

    def _cold(self, monkeypatch):
        import threading

        import wafer.browser._recaptcha_grid as grid

        monkeypatch.setattr(grid, "_model_load_done", threading.Event())
        monkeypatch.setattr(grid, "_model_load_started", True)
        monkeypatch.setattr(grid, "_models_unavailable", False)
        monkeypatch.setattr(grid, "_cls_session", None)
        monkeypatch.setattr(grid, "_det_session", None)
        return grid

    # Budgets stay under 2x the reserve so the wait is the proportional
    # half-budget branch and the test costs ~1s instead of ~15s.
    @pytest.mark.parametrize("budget", [2.0, 4.0])
    def test_cold_load_leaves_budget_to_use_the_models(self, monkeypatch, budget):
        """Returning models with the deadline already spent is useless.

        Detection, classification and clicking all still have to happen, so
        the wait holds back a slice. The loader is a daemon thread that keeps
        running regardless, so bailing early still warms the next challenge.
        """
        grid = self._cold(monkeypatch)
        started = time.monotonic()
        result = grid._ensure_models_before(started + budget)
        waited = time.monotonic() - started

        assert result == (None, None)
        # Some budget survived for the solve itself...
        assert waited < budget
        # ...and it is the documented reserve, not an arbitrary early exit.
        expected_reserve = min(grid._MODEL_WAIT_SOLVE_RESERVE, budget * 0.5)
        assert waited == pytest.approx(budget - expected_reserve, abs=0.75)

    def test_already_loaded_models_do_not_wait_at_all(self, monkeypatch):
        """The reserve must not slow down the warm path."""
        import wafer.browser._recaptcha_grid as grid

        monkeypatch.setattr(grid, "_cls_session", object())
        monkeypatch.setattr(grid, "_det_session", object())
        monkeypatch.setattr(grid, "_models_unavailable", False)

        started = time.monotonic()
        cls, det = grid._ensure_models_before(started + 60)
        assert cls is not None and det is not None
        assert time.monotonic() - started < 0.5


class TestHeadlessPatchVerification:
    """A silently-inert fingerprint patch must not fail a solve unexplained."""

    def _page(self, outer, inner, depth):
        page = MagicMock()
        page.evaluate.return_value = [outer, inner, depth]
        del page._wafer_patch_checked
        return page

    def test_warns_when_headless_patches_did_not_apply(self, caplog):
        solver = BrowserSolver(headless=True)
        try:
            page = self._page(1366, 1366, 24)
            with caplog.at_level(logging.WARNING, logger="wafer"):
                solver._verify_headless_patches(page)
            assert "did not apply" in caplog.text
            assert "headless=False" in caplog.text
        finally:
            solver.close(timeout=5)

    def test_silent_when_patches_took_effect(self, caplog):
        solver = BrowserSolver(headless=True)
        try:
            page = self._page(1368, 1366, 30)
            with caplog.at_level(logging.WARNING, logger="wafer"):
                solver._verify_headless_patches(page)
            assert "did not apply" not in caplog.text
        finally:
            solver.close(timeout=5)

    def test_headed_is_never_warned_about(self, caplog):
        """Headed Chrome is natively correct; the patches are not needed."""
        solver = BrowserSolver(headless=False)
        try:
            page = self._page(1366, 1366, 24)
            with caplog.at_level(logging.WARNING, logger="wafer"):
                solver._verify_headless_patches(page)
            assert caplog.text == "" or "did not apply" not in caplog.text
            page.evaluate.assert_not_called()
        finally:
            solver.close(timeout=5)

    def test_check_runs_once_per_page(self, caplog):
        solver = BrowserSolver(headless=True)
        try:
            page = self._page(1366, 1366, 24)
            with caplog.at_level(logging.WARNING, logger="wafer"):
                solver._verify_headless_patches(page)
                solver._verify_headless_patches(page)
            assert caplog.text.count("did not apply") == 1
        finally:
            solver.close(timeout=5)


class TestInitScriptFallback:
    """CDP init scripts register and then never run under Patchright.

    _setup_headless_patches registers via Page.addScriptToEvaluateOnNewDocument,
    which returns an identifier and silently never executes, leaving every
    fingerprint patch inert. Frame.evaluate does work, so the same scripts are
    re-applied on navigation.
    """

    def test_scripts_are_reapplied_on_main_frame_navigation(self):
        solver = BrowserSolver(headless=True)
        try:
            page = MagicMock()
            main = MagicMock()
            page.main_frame = main
            handlers = {}
            page.on.side_effect = lambda ev, fn: handlers.__setitem__(ev, fn)

            solver._install_init_script_fallback(page, ["SCRIPT_A", "SCRIPT_B"])
            handlers["framenavigated"](main)

            assert [c.args[0] for c in main.evaluate.call_args_list] == [
                "SCRIPT_A",
                "SCRIPT_B",
            ]
        finally:
            solver.close(timeout=5)

    def test_subframes_are_left_alone(self):
        """Only the main frame; OOPIFs have their own patch path."""
        solver = BrowserSolver(headless=True)
        try:
            page = MagicMock()
            page.main_frame = MagicMock()
            other = MagicMock()
            handlers = {}
            page.on.side_effect = lambda ev, fn: handlers.__setitem__(ev, fn)

            solver._install_init_script_fallback(page, ["SCRIPT"])
            handlers["framenavigated"](other)

            other.evaluate.assert_not_called()
        finally:
            solver.close(timeout=5)

    def test_no_listener_registered_when_there_is_nothing_to_apply(self):
        solver = BrowserSolver(headless=True)
        try:
            page = MagicMock()
            solver._install_init_script_fallback(page, [])
            page.on.assert_not_called()
        finally:
            solver.close(timeout=5)

    def test_a_failing_script_does_not_stop_the_rest(self):
        solver = BrowserSolver(headless=True)
        try:
            page = MagicMock()
            main = MagicMock()
            page.main_frame = main
            main.evaluate.side_effect = [RuntimeError("boom"), None]
            handlers = {}
            page.on.side_effect = lambda ev, fn: handlers.__setitem__(ev, fn)

            solver._install_init_script_fallback(page, ["A", "B"])
            handlers["framenavigated"](main)  # must not raise

            # B still applied despite A raising: they patch unrelated surfaces.
            assert [c.args[0] for c in main.evaluate.call_args_list] == ["A", "B"]
        finally:
            solver.close(timeout=5)


# ---------------------------------------------------------------------------
# Rendered fetch
# ---------------------------------------------------------------------------


_RENDERED_HTML = (
    "<html><head><title>App</title></head><body>"
    "<nav>Home</nav><main>" + ("Content the client wrote. " * 60) + "</main>"
    "</body></html>"
)


class _RenderingSolver:
    """Solver stub that records render calls and returns a captured DOM."""

    def __init__(
        self, result=None, *, html=_RENDERED_HTML, cookies=None, status=200
    ):
        self.render_calls = []
        self._result = (
            result
            if result is not None
            else SolveResult(
                cookies=cookies if cookies is not None else [],
                user_agent="Chrome/150.0.0.0",
                response=CapturedResponse(
                    url="https://example.com/",
                    status=status,
                    headers={"content-type": "text/html; charset=utf-8"},
                    body=html.encode("utf-8"),
                ),
                browser_version="150.0.7871.187",
                challenge_absent=True,
            )
        )

    def render(self, url, timeout=None, max_size=None):
        self.render_calls.append(
            {"url": url, "timeout": timeout, "max_size": max_size}
        )
        return self._result

    async def arender(self, url, timeout=None, max_size=None):
        return self.render(url, timeout=timeout, max_size=max_size)

    def solve(self, *args, **kwargs):
        raise AssertionError("render must not go through solve()")

    def close(self):
        pass


class TestSessionRender:
    def test_returns_the_rendered_document(self):
        solver = _RenderingSolver()
        session, mock = make_sync_session(
            [MockResponse(200, body="unused")],
            browser_solver=solver,
        )
        resp = session.render("https://example.com/", timeout=30)
        assert resp.status_code == 200
        assert "Content the client wrote." in resp.text
        assert resp.needs_render is False
        # No transport request: a render replaces the fetch, not follows it.
        assert mock.request_count == 0
        assert solver.render_calls[0]["url"] == "https://example.com/"

    def test_shell_response_points_at_render(self):
        """The hint and the remedy line up."""
        shell = MockResponse(
            200,
            headers={"content-type": "text/html"},
            body='<html><body><div id="root"></div><script src="/a.js">'
            "</script></body></html>",
        )
        solver = _RenderingSolver()
        session, _ = make_sync_session([shell], browser_solver=solver)
        first = session.get("https://example.com/")
        assert first.needs_render is True
        rendered = session.render("https://example.com/")
        assert rendered.needs_render is False

    def test_max_response_size_is_passed_through(self):
        solver = _RenderingSolver()
        session, _ = make_sync_session(
            [MockResponse(200)],
            browser_solver=solver,
            max_response_size=4321,
        )
        session.render("https://example.com/")
        assert solver.render_calls[0]["max_size"] == 4321

    def test_per_call_max_response_size_overrides_session(self):
        solver = _RenderingSolver()
        session, _ = make_sync_session(
            [MockResponse(200)],
            browser_solver=solver,
            max_response_size=4321,
        )
        session.render("https://example.com/", max_response_size=100_000)
        assert solver.render_calls[0]["max_size"] == 100_000

    def test_cookies_set_during_render_reach_the_jar(self):
        solver = _RenderingSolver(
            cookies=[
                {
                    "name": "session",
                    "value": "abc",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": time.time() + 3600,
                }
            ]
        )
        session, _ = make_sync_session(
            [MockResponse(200)],
            browser_solver=solver,
            use_cookie_jar=True,
        )
        session.render("https://example.com/")
        assert any(
            "session=abc" in raw
            for raw, _ in session._client.cookie_jar.added
        )

    def test_challenge_page_raises_instead_of_passing_as_content(self):
        solver = _RenderingSolver(
            html="<html><body><script>window._cf_chl_opt={};</script>"
            "</body></html>",
            status=403,
        )
        session, _ = make_sync_session([MockResponse(200)], browser_solver=solver)
        with pytest.raises(ChallengeDetected) as excinfo:
            session.render("https://example.com/")
        assert excinfo.value.challenge_type == "cloudflare"

    def test_no_document_raises_connection_failed(self):
        class _EmptySolver(_RenderingSolver):
            def render(self, url, timeout=None, max_size=None):
                self.render_calls.append({"url": url})
                return None

        session, _ = make_sync_session(
            [MockResponse(200)],
            browser_solver=_EmptySolver(),
        )
        with pytest.raises(ConnectionFailed):
            session.render("https://example.com/")

    def test_zero_timeout_raises_before_launching_a_browser(self):
        solver = _RenderingSolver()
        session, _ = make_sync_session([MockResponse(200)], browser_solver=solver)
        with pytest.raises(WaferTimeout):
            session.render("https://example.com/", timeout=0)
        assert solver.render_calls == []

    def test_supplied_solver_is_not_taken_over(self):
        """A shared solver keeps its lifecycle with the caller."""
        solver = _RenderingSolver()
        session, _ = make_sync_session([MockResponse(200)], browser_solver=solver)
        session.render("https://example.com/")
        assert session._owns_solver is False


class TestAsyncSessionRender:
    @pytest.mark.asyncio
    async def test_returns_the_rendered_document(self):
        solver = _RenderingSolver()
        session, mock = make_async_session(
            [MockResponse(200, body="unused")],
            browser_solver=solver,
        )
        resp = await session.render("https://example.com/", timeout=30)
        assert resp.status_code == 200
        assert "Content the client wrote." in resp.text
        assert mock.request_count == 0

    @pytest.mark.asyncio
    async def test_prefers_the_async_render_entry_point(self):
        class _SyncOnlyIsAnError(_RenderingSolver):
            def render(self, url, timeout=None, max_size=None):
                raise AssertionError("sync render should not be called")

            async def arender(self, url, timeout=None, max_size=None):
                self.render_calls.append({"url": url, "max_size": max_size})
                return self._result

        solver = _SyncOnlyIsAnError()
        session, _ = make_async_session(
            [MockResponse(200)],
            browser_solver=solver,
        )
        resp = await session.render("https://example.com/")
        assert resp.status_code == 200
        assert solver.render_calls[0]["url"] == "https://example.com/"

    @pytest.mark.asyncio
    async def test_challenge_page_raises(self):
        solver = _RenderingSolver(
            html="<html><body><script>window._cf_chl_opt={};</script>"
            "</body></html>",
            status=403,
        )
        session, _ = make_async_session([MockResponse(200)], browser_solver=solver)
        with pytest.raises(ChallengeDetected):
            await session.render("https://example.com/")


class TestRenderedHeaders:
    def test_forces_utf8_html_content_type(self):
        """The DOM is re-serialized, so the original charset no longer holds."""
        from wafer.browser._solver import _rendered_headers

        response = SimpleNamespace(
            all_headers=lambda: {
                "Content-Type": "text/html; charset=iso-8859-1",
                "Content-Length": "1234",
                "X-Frame-Options": "SAMEORIGIN",
            },
            headers_array=lambda: [],
        )
        headers, set_cookie = _rendered_headers(response)
        assert headers["content-type"] == "text/html; charset=utf-8"
        assert "content-length" not in headers
        assert headers["x-frame-options"] == "SAMEORIGIN"
        assert set_cookie == []

    def test_no_navigation_response_still_yields_html_headers(self):
        from wafer.browser._solver import _rendered_headers

        headers, set_cookie = _rendered_headers(None)
        assert headers == {"content-type": "text/html; charset=utf-8"}
        assert set_cookie == []


class TestRenderOnWorker:
    """The render path itself, driven with a faked Playwright page."""

    @staticmethod
    def _setup(
        *,
        dom="<html><body>" + "rendered content " * 50 + "</body></html>",
        nav_status=200,
        url="https://spa.example.com/",
        page_url=None,
        extra_responses=(),
        cookies=None,
        content_type="text/html",
        raw_body=b"",
        body_error=False,
    ):
        """Build a solver whose page replays `extra_responses` during goto()."""
        solver = BrowserSolver(solve_timeout=5)
        solver._browser = MagicMock()
        solver._browser.is_connected.return_value = True
        solver._browser_ua = "Chrome/150"
        solver._needs_screenxy_patch = False

        navigation = _fake_document_response(
            url, nav_status, content_type=content_type, raw_body=raw_body
        )
        if body_error:
            navigation.body.side_effect = RuntimeError("body not retained")
        context = MagicMock()
        page = MagicMock()
        page.url = page_url or url
        page.main_frame = _MAIN_FRAME
        page.content.return_value = dom
        # Steady DOM length: the stability poll settles after its sample count
        # and the size check sees a real number rather than a mock.
        page.evaluate.return_value = len(dom)
        context.new_page.return_value = page
        context.cookies.return_value = list(cookies or [])

        handlers = {}
        page.on.side_effect = lambda event, fn: handlers.__setitem__(event, fn)

        def _goto(*_args, **_kwargs):
            handler = handlers.get("response")
            if handler is not None:
                handler(navigation)
                for response in extra_responses:
                    handler(response)
            return navigation

        page.goto.side_effect = _goto
        return solver, context, page

    @staticmethod
    def _run(solver, context, **kwargs):
        with (
            patch.object(solver, "_create_context", return_value=context),
            patch.object(solver, "_setup_headless_patches"),
            patch.object(solver, "_verify_headless_patches"),
            patch("wafer.browser._solver._RENDER_POLL_INTERVAL", 0.0),
        ):
            try:
                return solver._render_on_worker("https://spa.example.com/", **kwargs)
            finally:
                solver.close()

    def test_returns_the_serialized_dom(self):
        solver, context, page = self._setup(cookies=[{"name": "a", "value": "b"}])
        result = self._run(solver, context, timeout=5)
        assert result is not None
        assert b"rendered content" in result.response.body
        assert result.response.status == 200
        assert result.response.headers["content-type"] == "text/html; charset=utf-8"
        assert result.cookies == [{"name": "a", "value": "b"}]
        # A render earns no clearance, so the session must not pin or rebuild.
        assert result.challenge_absent is True

    def test_client_side_redirect_reports_the_final_document(self):
        """Status and body must describe the same document."""
        destination = _fake_document_response(
            "https://spa.example.com/login", 404
        )
        solver, context, page = self._setup(
            nav_status=200,
            extra_responses=[destination],
            page_url="https://spa.example.com/login",
        )
        result = self._run(solver, context, timeout=5)
        assert result.response.status == 404
        assert result.response.url == "https://spa.example.com/login"

    def test_subresources_do_not_become_the_document(self):
        script = _fake_document_response(
            "https://cdn.example.com/app.js", 500, resource_type="script"
        )
        solver, context, page = self._setup(extra_responses=[script])
        result = self._run(solver, context, timeout=5)
        assert result.response.status == 200

    def test_iframe_documents_do_not_become_the_document(self):
        frame = _fake_document_response(
            "https://ads.example.com/frame", 503, main_frame=False
        )
        solver, context, page = self._setup(extra_responses=[frame])
        result = self._run(solver, context, timeout=5)
        assert result.response.status == 200

    def test_route_change_without_a_document_keeps_the_navigation_status(self):
        """history.pushState issues no document response."""
        solver, context, page = self._setup(
            page_url="https://spa.example.com/careers",
        )
        result = self._run(solver, context, timeout=5)
        assert result.response.status == 200
        assert result.response.url == "https://spa.example.com/careers"

    def test_empty_document_is_not_returned_as_content(self):
        solver, context, page = self._setup(dom="")
        assert self._run(solver, context, timeout=5) is None

    def test_oversize_dom_raises_rather_than_looking_empty(self):
        """A DOM that hydrates past the cap is an error, not a failed render."""
        solver, context, page = self._setup()
        with pytest.raises(ResponseTooLarge) as excinfo:
            self._run(solver, context, timeout=5, max_size=64)
        assert excinfo.value.limit == 64

    def test_no_budget_returns_none_without_touching_the_browser(self):
        solver, context, page = self._setup()
        assert self._run(solver, context, timeout=0) is None
        context.new_page.assert_not_called()

    def test_challenge_is_solved_in_place_and_the_page_recaptured(self):
        """A protected page must not come back as its interstitial."""
        interstitial = (
            "<html><body><script>window._cf_chl_opt={};</script>"
            "Just a moment...</body></html>"
        )
        real = "<html><body>" + "real page content " * 50 + "</body></html>"
        solver, context, page = self._setup(dom=interstitial)
        page.content.side_effect = [interstitial, real, real, real]
        with patch.object(
            solver, "_dispatch_challenge", return_value=True
        ) as dispatch:
            result = self._run(solver, context, timeout=30)
        assert dispatch.call_count == 1
        assert dispatch.call_args[0][1] == "cloudflare"
        assert b"real page content" in result.response.body

    def test_solving_in_place_earns_an_identity_to_pin(self):
        """Clearance is bound to the solving browser; the session must pin."""
        interstitial = (
            "<html><body><script>window._cf_chl_opt={};</script>"
            "Just a moment...</body></html>"
        )
        real = "<html><body>" + "real page content " * 50 + "</body></html>"
        solver, context, page = self._setup(dom=interstitial)
        page.content.side_effect = [interstitial, real, real, real]
        with patch.object(solver, "_dispatch_challenge", return_value=True):
            result = self._run(solver, context, timeout=30)
        assert result.challenge_absent is False

    def test_plain_render_claims_no_identity(self):
        """No challenge means no clearance, so the session must not pin."""
        solver, context, page = self._setup()
        result = self._run(solver, context, timeout=30)
        assert result.challenge_absent is True

    def test_unsolved_challenge_is_returned_for_the_caller_to_classify(self):
        interstitial = (
            "<html><body><script>window._cf_chl_opt={};</script>"
            "Just a moment...</body></html>"
        )
        solver, context, page = self._setup(dom=interstitial)
        with patch.object(solver, "_dispatch_challenge", return_value=False):
            result = self._run(solver, context, timeout=30)
        assert b"_cf_chl_opt" in result.response.body

    def test_ordinary_page_never_reaches_the_challenge_dispatcher(self):
        solver, context, page = self._setup()
        with patch.object(solver, "_dispatch_challenge") as dispatch:
            result = self._run(solver, context, timeout=30)
        dispatch.assert_not_called()
        assert b"rendered content" in result.response.body

    def test_unclassifiable_interstitial_is_not_dispatched(self):
        """Structurally challenge-shaped but no known WAF: nothing to run."""
        body = "<html><body>just a moment</body></html>"
        solver, context, page = self._setup(dom=body)
        with patch.object(solver, "_dispatch_challenge") as dispatch:
            self._run(solver, context, timeout=30)
        dispatch.assert_not_called()

    def test_json_is_returned_as_bytes_not_as_chromes_viewer(self):
        """Chrome wraps JSON in a viewer document; the caller wants the JSON."""
        payload = b'{"jobs": [{"title": "FPGA Engineer"}]}'
        solver, context, page = self._setup(
            dom="<html><body><pre>{&quot;jobs&quot;: []}</pre></body></html>",
            content_type="application/json; charset=utf-8",
            raw_body=payload,
        )
        result = self._run(solver, context, timeout=5)
        assert result.response.body == payload
        assert result.response.headers["content-type"] == (
            "application/json; charset=utf-8"
        )

    def test_non_html_over_the_cap_still_raises(self):
        solver, context, page = self._setup(
            content_type="application/json",
            raw_body=b"x" * 4096,
        )
        with pytest.raises(ResponseTooLarge):
            self._run(solver, context, timeout=5, max_size=100)

    def test_xhtml_is_serialized_like_html(self):
        solver, context, page = self._setup(
            content_type="application/xhtml+xml",
            raw_body=b"<html/>",
        )
        result = self._run(solver, context, timeout=5)
        assert b"rendered content" in result.response.body
        assert result.response.headers["content-type"] == "text/html; charset=utf-8"

    def test_unreadable_non_html_body_falls_back_to_the_dom(self):
        """Chrome not retaining the bytes must not lose the render entirely."""
        solver, context, page = self._setup(
            content_type="application/json",
            raw_body=b'{"a": 1}',
            body_error=True,
        )
        result = self._run(solver, context, timeout=5)
        assert b"rendered content" in result.response.body
        assert result.response.headers["content-type"] == "text/html; charset=utf-8"

    def test_invalid_url_is_refused(self):
        solver = BrowserSolver(solve_timeout=5)
        try:
            assert solver._render_on_worker("file:///etc/passwd") is None
            assert solver._render_on_worker("javascript:alert(1)") is None
        finally:
            solver.close()


_MAIN_FRAME = object()


def _fake_document_response(
    url,
    status,
    *,
    resource_type="document",
    main_frame=True,
    content_type="text/html",
    raw_body=b"",
):
    """A Playwright-shaped response for the render listener to classify."""
    request = SimpleNamespace(
        resource_type=resource_type,
        frame=_MAIN_FRAME if main_frame else object(),
    )
    response = MagicMock()
    response.status = status
    response.url = url
    response.request = request
    response.all_headers.return_value = {"content-type": content_type}
    response.headers_array.return_value = []
    response.body.return_value = raw_body
    return response
