"""AWS WAF challenge solver."""

import logging
import random
import time

logger = logging.getLogger("wafer")


def wait_for_awswaf(solver, page, timeout_ms: int) -> bool:
    """Wait for AWS WAF JS challenge to auto-solve.

    The challenge executes AwsWafIntegration.getToken(), sets an
    aws-waf-token cookie, and reloads the page automatically.
    """
    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    deadline = time.monotonic() + timeout_ms / 1000

    while time.monotonic() < deadline:
        cookies = page.context.cookies()
        if any(c["name"] == "aws-waf-token" for c in cookies):
            solver._replay_browse_chunk(page, state, 0.5)
            return True
        solver._replay_browse_chunk(page, state, 0.5)

    return False
