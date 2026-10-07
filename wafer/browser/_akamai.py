"""Akamai challenge solver."""

import json
import logging
import random
import time

logger = logging.getLogger("wafer")

# The statuses Akamai serves its challenge documents under.
_CHALLENGE_STATUSES = (403, 429)
_STUB_SIZE = 10_000
_DOCUMENT_HEAD = (
    "JSON.stringify([document.documentElement.outerHTML.length,"
    " document.documentElement.outerHTML.slice(0, 10000)])"
)


def _document_head(page) -> tuple[int, str]:
    """The current document's length and its first 10,000 characters.

    Read without a user gesture (``_quiet_read``): ``page.content()`` marked
    the page user-activated on every poll.
    """
    from wafer.browser._solver import _quiet_read

    try:
        length, head = json.loads(_quiet_read(page, _DOCUMENT_HEAD))
        return int(length), str(head)
    except Exception:
        return 0, ""


def _challenge_then_document(documents) -> bool:
    """A challenge document was served, and the page has since landed on a 2xx.

    *documents* is the solve's list of main-frame ``(url, status)`` as they
    arrived. chewy.com's behavioral page (429) reloads and redirects to a 200
    page before the handler first looks, so the stub is gone by then
    (2026-10-06); its document history still shows the challenge.
    """
    statuses = [status for _, status, *_ in list(documents or ())]
    for index, status in enumerate(statuses):
        if status in _CHALLENGE_STATUSES:
            return index < len(statuses) - 1 and 200 <= statuses[-1] < 300
    return False


def wait_for_akamai(solver, page, timeout_ms: int, documents=None) -> bool:
    """Wait for Akamai _abck cookie to be set/updated.

    Also detects behavioral challenge pages (sec-if-cpt) that
    auto-resolve after the browser executes the challenge JS.
    When the challenge resolves, the page navigates to real
    content - detected by the page growing beyond the stub size.
    That applies when the first look found the stub, or when *documents*
    (main-frame ``(url, status)`` of this solve) shows a challenge document
    followed by a 2xx one. Without either, the page is not taken for
    cleared on its size alone: a protected page loads Akamai's sensor and
    real content before ``_abck`` is valid.
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
    initial_length, initial_head = _document_head(page)
    is_behavioral = initial_length < _STUB_SIZE and (
        "sec-if-cpt" in initial_head or "behavioral-content" in initial_head
    )

    while time.monotonic() < deadline:
        cookies = page.context.cookies()
        for cookie in cookies:
            if cookie["name"] == "_abck":
                if cookie["value"] != initial_abck:
                    # For behavioral challenges the sensor always updates
                    # _abck, even when the server rejects the fingerprint.
                    # Require the page to navigate to real content too.
                    if not is_behavioral:
                        solver._replay_browse_chunk(page, state, 1)
                        return True
                break

        if is_behavioral or _challenge_then_document(documents):
            length, head = _document_head(page)
            if length > _STUB_SIZE and "sec-if-cpt" not in head[:5000]:
                logger.info("Akamai behavioral challenge auto-resolved")
                return True

        solver._replay_browse_chunk(page, state, 0.5)

    return False
