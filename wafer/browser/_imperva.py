"""Imperva / Incapsula challenge solver."""

import logging
import random
import time

logger = logging.getLogger("wafer")

# Cookie names that signal a solved Imperva challenge.
# Modern: reese84 (advanced bot detection JS)
# Legacy: ___utmvc (older Incapsula)
# Classic: incap_ses_* (session cookie set after JS challenge)
_SOLVE_COOKIES = ("reese84", "___utmvc")
_CLASSIC_PREFIX = "incap_ses_"


def _snapshot_cookies(cookies):
    """Capture current values of solve-signal cookies."""
    snap = {}
    for c in cookies:
        if c["name"] in _SOLVE_COOKIES or c["name"].startswith(_CLASSIC_PREFIX):
            snap[c["name"]] = c["value"]
    return snap


def wait_for_imperva(solver, page, timeout_ms: int) -> bool:
    """Wait for Imperva challenge to resolve.

    Polls for solve-signal cookies:
    - ``reese84`` — modern Imperva advanced bot JS
    - ``___utmvc`` — legacy Incapsula
    - ``incap_ses_*`` — classic Incapsula session (set after JS runs)

    Imperva may set ``reese84`` via Set-Cookie on the challenge
    response itself (before JS runs), so we track value *changes*
    rather than mere presence to avoid false-positive success.
    """
    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    deadline = time.monotonic() + timeout_ms / 1000

    # Capture initial cookie values (may already be set by the
    # challenge page's Set-Cookie header before JS executes)
    initial = _snapshot_cookies(page.context.cookies())

    while time.monotonic() < deadline:
        cookies = page.context.cookies()
        current = _snapshot_cookies(cookies)

        for name, value in current.items():
            if name not in initial:
                # New cookie appeared (wasn't in initial response)
                solver._replay_browse_chunk(page, state, 1)
                return True
            if value != initial[name]:
                # Existing cookie changed value (JS updated it)
                solver._replay_browse_chunk(page, state, 1)
                return True

        solver._replay_browse_chunk(page, state, 2)

    return False
