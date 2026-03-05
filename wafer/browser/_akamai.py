"""Akamai challenge solver."""

import logging
import random
import time

logger = logging.getLogger("wafer")


def wait_for_akamai(solver, page, timeout_ms: int) -> bool:
    """Wait for Akamai _abck cookie to be set/updated.

    Also detects behavioral challenge pages (sec-if-cpt) that
    auto-resolve after the browser executes the challenge JS.
    When the challenge resolves, the page navigates to real
    content - detected by the page growing beyond the stub size.
    """
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

    # Check if this is a behavioral challenge page (small JS stub)
    try:
        initial_html = page.content()
    except Exception:
        initial_html = ""
    is_behavioral = (
        len(initial_html) < 10_000
        and ("sec-if-cpt" in initial_html or "behavioral-content" in initial_html)
    )

    while time.monotonic() < deadline:
        cookies = page.context.cookies()
        for cookie in cookies:
            if cookie["name"] == "_abck":
                if cookie["value"] != initial_abck:
                    solver._replay_browse_chunk(page, state, 1)
                    return True

        # Behavioral challenge: check if the page navigated to
        # real content (challenge JS auto-resolved and redirected)
        if is_behavioral:
            try:
                html = page.content()
            except Exception:
                html = ""
            if len(html) > 10_000 and "sec-if-cpt" not in html[:5000]:
                logger.info("Akamai behavioral challenge auto-resolved")
                return True

        solver._replay_browse_chunk(page, state, 0.5)

    return False
