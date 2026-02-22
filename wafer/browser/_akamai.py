"""Akamai challenge solver."""

import logging
import random
import time

logger = logging.getLogger("wafer")


def wait_for_akamai(solver, page, timeout_ms: int) -> bool:
    """Wait for Akamai _abck cookie to be set/updated."""
    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    deadline = time.monotonic() + timeout_ms / 1000
    initial_abck = None

    for cookie in page.context.cookies():
        if cookie["name"] == "_abck":
            initial_abck = cookie["value"]
            break

    while time.monotonic() < deadline:
        cookies = page.context.cookies()
        for cookie in cookies:
            if cookie["name"] == "_abck":
                if cookie["value"] != initial_abck:
                    solver._replay_browse_chunk(page, state, 1)
                    return True
        solver._replay_browse_chunk(page, state, 0.5)

    return False
