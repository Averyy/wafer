"""Solver sleeps must keep a hardened sync page's events flowing.

The page's iframes and workers are attached paused and released only by CDP
events this thread processes, which sync Playwright delivers only inside a
Playwright call. A plain time.sleep held a new iframe paused for the rest of
the sleep (1.7s of 2s, measured on Chrome 154).
"""

from unittest.mock import MagicMock, patch

from wafer.browser import _pump


def _open_page():
    page = MagicMock()
    page.is_closed.return_value = False
    return page


def test_without_a_page_it_is_time_sleep():
    with patch("time.sleep") as sleep:
        _pump.idle(0.25)
    sleep.assert_called_once_with(0.25)


def test_a_bound_page_waits_through_playwright():
    page = _open_page()
    _pump.bind_page(page)
    with patch("time.sleep") as sleep:
        _pump.idle(0.25)
    page.wait_for_timeout.assert_called_once_with(250.0)
    sleep.assert_not_called()


def test_a_closed_page_falls_back_to_time_sleep():
    page = MagicMock()
    page.is_closed.return_value = True
    _pump.bind_page(page)
    with patch("time.sleep") as sleep:
        _pump.idle(0.25)
    page.wait_for_timeout.assert_not_called()
    sleep.assert_called_once_with(0.25)


def test_a_page_closing_mid_wait_sleeps_out_the_remainder():
    page = _open_page()
    page.wait_for_timeout.side_effect = RuntimeError("Target closed")
    _pump.bind_page(page)
    with patch("time.sleep") as sleep:
        _pump.idle(0.25)
    (remaining,), _ = sleep.call_args
    assert 0 < remaining <= 0.25


def test_negative_durations_never_reach_playwright_negative():
    page = _open_page()
    _pump.bind_page(page)
    _pump.idle(-1)
    page.wait_for_timeout.assert_called_once_with(0.0)


def test_binding_is_per_thread():
    import threading

    _pump.bind_page(_open_page())
    seen = []
    thread = threading.Thread(
        target=lambda: seen.append(getattr(_pump._local, "page", None))
    )
    thread.start()
    thread.join()
    assert seen == [None]


def test_unbind():
    _pump.bind_page(_open_page())
    _pump.unbind_page()
    with patch("time.sleep") as sleep:
        _pump.idle(0.1)
    sleep.assert_called_once_with(0.1)
