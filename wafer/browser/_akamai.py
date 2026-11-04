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
        logger.debug("Akamai document read failed", exc_info=True)
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


_BEHAVIORAL_GRACE = 15.0

# A refusal document: a small 403/429 that is not the behavioral stub. Akamai
# answers a cold navigation it distrusts with one (an "Error Page" loading its
# script at ``/<random path>?v=<uuid>``), and once that script has posted, the
# same navigation goes through: stock Chrome for Testing on Linux was refused
# by www.ebay.ca, and after 8s and one reload landed on eBay's splash
# challenge and then the results page (2026-11-03). Nothing else moves it, so
# polling it ran the whole solve budget (142s on homedepot.com). The
# navigation is retried once, after the script's POST or _DENY_SENSOR_WAIT,
# and a refusal that survives the retry for _DENY_RETRY_GRACE is final. A
# second retry was refused again, so there is only one.
_DENY_SENSOR_WAIT = 8.0
_DENY_RETRY_GRACE = 15.0


def _latest_status(documents) -> int | None:
    entries = list(documents or ())
    return entries[-1][1] if entries else None


def _is_real_content(length: int, head: str) -> bool:
    """A document past Akamai's stub that is not itself a challenge page."""
    from wafer._challenge import is_ebay_splash_challenge

    return (
        length > _STUB_SIZE
        and "sec-if-cpt" not in head[:5000]
        and not is_ebay_splash_challenge(head)
    )


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

    # When _abck changes on a behavioral page, the sensor ran but the
    # server may have rejected the fingerprint. Give the page a grace
    # window to navigate; if it doesn't, bail early instead of burning
    # the full timeout.
    behavioral_deadline = None

    # A refusal document (see _DENY_SENSOR_WAIT).
    refused = (
        not is_behavioral
        and _latest_status(documents) in _CHALLENGE_STATUSES
        and initial_length < _STUB_SIZE
    )
    refused_at = time.monotonic()
    retried_at: float | None = None
    script_posted: dict = {}
    if refused:

        def _on_post(response) -> None:
            try:
                if response.request.method == "POST":
                    script_posted.setdefault("at", time.monotonic())
            except Exception:
                return

        page.on("response", _on_post)

    while time.monotonic() < deadline:
        if behavioral_deadline and time.monotonic() >= behavioral_deadline:
            logger.info(
                "Akamai behavioral: sensor ran but page did not "
                "navigate within %.0fs, giving up", _BEHAVIORAL_GRACE,
            )
            return False

        status = _latest_status(documents)
        if refused and status in _CHALLENGE_STATUSES:
            # Still on a refusal: an _abck change here is the script's own
            # bookkeeping, not clearance.
            now = time.monotonic()
            if retried_at is None:
                posted = script_posted.get("at")
                if (
                    posted is not None and now - posted >= 1.0
                ) or now - refused_at >= _DENY_SENSOR_WAIT:
                    logger.info(
                        "Akamai refused the navigation (HTTP %s); retrying it "
                        "after its script ran",
                        status,
                    )
                    retried_at = now
                    try:
                        page.reload(
                            wait_until="domcontentloaded",
                            timeout=max(1, int((deadline - now) * 1000)),
                        )
                    except Exception as exc:
                        logger.debug(
                            "Akamai retry navigation error (%s)",
                            type(exc).__name__,
                        )
                    continue
            elif now - retried_at >= _DENY_RETRY_GRACE:
                logger.info(
                    "Akamai refused the retried navigation too (HTTP %s); "
                    "giving up",
                    status,
                )
                return False
            solver._replay_browse_chunk(page, state, 0.5)
            continue

        cookies = page.context.cookies()
        for cookie in cookies:
            if cookie["name"] == "_abck":
                if cookie["value"] != initial_abck:
                    if not is_behavioral and not refused:
                        solver._replay_browse_chunk(page, state, 1)
                        return True
                    if is_behavioral and behavioral_deadline is None:
                        behavioral_deadline = min(
                            deadline,
                            time.monotonic() + _BEHAVIORAL_GRACE,
                        )
                break

        if is_behavioral or refused or _challenge_then_document(documents):
            length, head = _document_head(page)
            if _is_real_content(length, head):
                logger.info(
                    "Akamai %s challenge auto-resolved",
                    "refusal" if refused else "behavioral",
                )
                return True

        solver._replay_browse_chunk(page, state, 0.5)

    return False
