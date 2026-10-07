"""Sleeps that keep a hardened sync Playwright page's events flowing.

The per-page hardening attaches every iframe and worker a page starts paused,
and only this thread can release it: sync Playwright delivers the CDP events
that do so only while the thread is inside a Playwright call. A plain
``time.sleep`` therefore held a dynamically created iframe paused for the rest
of the sleep (1.7s of a 2s sleep, measured on Chrome 154), and an iframe whose
first script runs that late is itself a tell. Solver code sleeps through
:func:`idle`, which waits on the page instead while one is bound.
"""

import threading
import time

_local = threading.local()


def bind_page(page) -> None:
    """Deliver *page*'s events during this thread's :func:`idle` calls."""
    _local.page = page


def unbind_page() -> None:
    _local.page = None


def idle(seconds: float) -> None:
    """Sleep *seconds*, delivering Playwright events meanwhile when bound.

    Falls back to ``time.sleep(seconds)`` when no open page is bound to this
    thread, and sleeps out the remainder if the page closes mid-wait.
    """
    page = getattr(_local, "page", None)
    if page is not None:
        start = time.monotonic()
        try:
            if page.is_closed() is False:
                page.wait_for_timeout(max(0.0, seconds) * 1000)
                return
        except Exception:
            remaining = seconds - (time.monotonic() - start)
            if remaining > 0:
                time.sleep(remaining)
            return
    time.sleep(seconds)
