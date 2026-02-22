"""Kasada challenge solver — browser CT/ST extraction.

Kasada's challenge flow:
1. Page loads → Kasada JS runs fingerprinting
2. JS POSTs to ips.js, p.js, or /tl endpoint
3. Response contains x-kpsdk-ct (fingerprint token) and optionally
   x-kpsdk-st (server timestamp) in headers
4. We intercept ANY response with x-kpsdk-ct to extract the token

The CT token is reusable (~30 min). Per-request proof-of-work (CD)
is generated in pure Python by wafer._kasada.generate_cd().

IMPORTANT: The response listener must be attached BEFORE page.goto()
because the token response can fire during initial page load. Use
setup_kasada_listener() before navigation, then wait_for_kasada()
after navigation to collect the result.
"""

import logging
import random
import time

logger = logging.getLogger("wafer")


def setup_kasada_listener(page) -> dict:
    """Attach /tl response listener to a page BEFORE navigation.

    Returns a shared dict that will be populated with {"ct", "st"}
    when the /tl response is intercepted. Pass this dict to
    wait_for_kasada() after navigation completes.
    """
    captured: dict = {}

    def on_response(response):
        try:
            # Stop watching once we have both CT and ST
            if captured.get("ct") and captured.get("st"):
                return
            headers = response.headers
            ct = headers.get("x-kpsdk-ct", "")
            if not ct:
                return
            st_str = headers.get("x-kpsdk-st", "")
            st = int(st_str) if st_str else 0
            # First response with CT: capture it
            if "ct" not in captured:
                captured["ct"] = ct
                logger.debug(
                    "Kasada CT intercepted on %s: ct=%s...",
                    response.url[:80], ct[:20],
                )
            # Update ST if we get a better one (non-zero)
            if st and not captured.get("st"):
                captured["st"] = st
                logger.debug("Kasada ST intercepted: %d", st)
        except Exception:
            logger.debug("Kasada listener error", exc_info=True)

    page.on("response", on_response)
    # Stash for cleanup
    page._kasada_listener = on_response
    page._kasada_captured = captured
    return captured


def wait_for_kasada(solver, page, timeout_ms: int) -> bool:
    """Wait for Kasada /tl response and extract CT/ST tokens.

    If setup_kasada_listener() was called before navigation, uses
    the pre-attached listener. Otherwise attaches one now (may miss
    early /tl responses).

    Sets ``page._kasada_result`` to ``{"ct": str, "st": int}`` on
    success.

    Returns True if tokens were captured, False on timeout.
    """
    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    deadline = time.monotonic() + timeout_ms / 1000

    # Use pre-attached listener if available, otherwise set up now
    captured = getattr(page, "_kasada_captured", None)
    if captured is None:
        captured = setup_kasada_listener(page)

    # After CT is captured, wait for:
    # 1. ST to also arrive (may come on a later /tl response)
    # 2. Kasada JS to finish setting session cookies (~10s)
    # Returning too early results in missing cookies.
    min_settle = 10  # seconds after CT capture

    try:
        ct_time: float | None = None
        while time.monotonic() < deadline:
            if captured.get("ct") and ct_time is None:
                ct_time = time.monotonic()
            if ct_time and time.monotonic() - ct_time >= min_settle:
                page._kasada_result = captured
                return True
            solver._replay_browse_chunk(page, state, 1)
    finally:
        listener = getattr(page, "_kasada_listener", None)
        if listener:
            try:
                page.remove_listener("response", listener)
            except Exception:
                pass

    # Post-timeout: only return success if CT was captured AND settle
    # time completed. Incomplete settle means cookies may be missing.
    if captured.get("ct") and ct_time and time.monotonic() - ct_time >= min_settle:
        page._kasada_result = captured
        return True

    if captured.get("ct"):
        logger.warning(
            "Kasada CT captured but settle time incomplete "
            "(%.1fs of %ds), cookies may be missing",
            time.monotonic() - ct_time if ct_time else 0,
            min_settle,
        )

    return False
