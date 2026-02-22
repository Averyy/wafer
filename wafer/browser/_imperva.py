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


def wait_for_imperva(solver, page, timeout_ms: int) -> bool:
    """Wait for Imperva challenge to resolve.

    Polls for solve-signal cookies:
    - ``reese84`` — modern Imperva advanced bot JS
    - ``___utmvc`` — legacy Incapsula
    - ``incap_ses_*`` — classic Incapsula session (set after JS runs)

    The ``_Incapsula_Resource`` script stays in the DOM even after
    solving (used for monitoring), so we don't check for its removal.
    The session cookie is the definitive signal.
    """
    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    deadline = time.monotonic() + timeout_ms / 1000

    while time.monotonic() < deadline:
        cookies = page.context.cookies()

        # Modern/legacy solve cookies
        if any(c["name"] in _SOLVE_COOKIES for c in cookies):
            solver._replay_browse_chunk(page, state, 1)
            return True

        # Classic Incapsula: incap_ses_* set after JS challenge
        if any(c["name"].startswith(_CLASSIC_PREFIX) for c in cookies):
            solver._replay_browse_chunk(page, state, 1)
            return True

        solver._replay_browse_chunk(page, state, 2)

    return False
