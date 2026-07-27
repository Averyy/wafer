"""BrowserSolver proxy and navigation-boundary tests."""

from unittest.mock import MagicMock, patch

import pytest

from wafer._base import BaseSession
from wafer.browser._solver import BrowserSolver, _valid_browser_url


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/",
        "http://example.com:8080/path?q=1",
        "https://[2606:4700:4700::1111]/",
    ],
)
def test_valid_browser_url_accepts_http_urls(url):
    assert _valid_browser_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "file:///etc/passwd",
        "chrome://settings/",
        "data:text/html,secret",
        "https://user:password@example.com/",
        "https://example.com:0/",
        "https://example.com/\ninternal",
        "https:///missing-host",
    ],
)
def test_valid_browser_url_rejects_non_network_or_ambiguous_urls(url):
    assert not _valid_browser_url(url)


def test_constructor_rejects_invalid_proxy_url():
    with pytest.raises(ValueError):
        BrowserSolver(proxy="file:///tmp/proxy")
    with pytest.raises(ValueError):
        BrowserSolver(proxy="socks5://127.0.0.1")
    with pytest.raises(ValueError):
        BrowserSolver(egress_guard_proxy="socks5://proxy.example:1080")
    with pytest.raises(ValueError):
        BrowserSolver(
            proxy="http://proxy.example:8080",
            egress_guard_proxy="socks5://127.0.0.1:1080",
        )


def test_configure_proxy_only_before_browser_launch():
    solver = BrowserSolver()
    solver.configure_proxy("socks5://127.0.0.1:32123")
    assert solver.proxy_server == "socks5://127.0.0.1:32123"
    solver._browser = MagicMock()
    with pytest.raises(RuntimeError):
        solver.configure_proxy("socks5://127.0.0.1:32124")
    solver._browser = None
    solver.close()


def test_configure_browser_only_egress_guard_before_launch():
    solver = BrowserSolver()
    solver.configure_egress_guard("socks5://127.0.0.1:32123")
    assert solver.egress_guard_proxy == "socks5://127.0.0.1:32123"
    assert solver.proxy_server is None
    with pytest.raises(RuntimeError):
        solver.configure_proxy("http://proxy.example:8080")
    solver.close()


def test_chromium_launch_receives_proxy_and_udp_bypass_guards():
    solver = BrowserSolver(
        headless=False,
        egress_guard_proxy="socks5://127.0.0.1:32123",
    )
    browser = MagicMock()
    browser.version = "149.0.7827.201"
    playwright = MagicMock()
    playwright.chromium.launch.return_value = browser
    starter = MagicMock()
    starter.start.return_value = playwright

    with (
        patch.object(solver, "_ensure_browser_installed"),
        patch("patchright.sync_api.sync_playwright", return_value=starter),
    ):
        solver._ensure_browser()

    kwargs = playwright.chromium.launch.call_args.kwargs
    assert kwargs["proxy"] == {
        "server": "socks5://127.0.0.1:32123",
    }
    assert "--disable-quic" in kwargs["args"]
    assert (
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
        in kwargs["args"]
    )
    solver.close()


def test_browser_only_guard_does_not_require_native_session_proxy():
    solver = BrowserSolver(
        egress_guard_proxy="socks5://127.0.0.1:32123",
    )
    try:
        session = BaseSession(browser_solver=solver)
        assert session._proxy_url is None
        assert solver.proxy_server is None
        assert solver.egress_guard_proxy == "socks5://127.0.0.1:32123"
    finally:
        solver.close()


def test_invalid_solve_target_is_rejected_before_browser_launch():
    solver = BrowserSolver()
    with patch.object(solver, "_ensure_browser") as ensure:
        assert solver._solve_on_worker("file:///etc/passwd") is None
    ensure.assert_not_called()
    solver.close()


def test_invalid_embedder_is_rejected_before_browser_launch():
    solver = BrowserSolver()
    with patch.object(solver, "_ensure_browser") as ensure:
        assert (
            solver._solve_on_worker(
                "https://example.com/",
                embedder="file:///etc/passwd",
            )
            is None
        )
    ensure.assert_not_called()
    solver.close()


def test_invalid_iframe_target_is_rejected_before_browser_launch():
    solver = BrowserSolver()
    with patch.object(solver, "_ensure_browser") as ensure:
        assert (
            solver._intercept_iframe_on_worker(
                "file:///etc/passwd",
                "example.com",
            )
            is None
        )
    ensure.assert_not_called()
    solver.close()
