"""DataDome challenge solver."""

import logging
import random
import time

logger = logging.getLogger("wafer")


def wait_for_datadome(solver, page, timeout_ms: int) -> bool:
    """Wait for DataDome challenge to resolve.

    Polls for the ``datadome`` cookie value to change (new token after
    solve) and for the captcha-delivery iframe to be removed.

    Returns False immediately if the page URL contains ``t=bv`` — this
    indicates a "blocked visitor" verdict that cannot be solved.
    """
    # t=bv = blocked visitor, unsolvable
    try:
        if "t=bv" in page.url:
            logger.warning("DataDome t=bv (blocked visitor), skipping")
            return False
    except Exception:
        pass

    state = solver._start_browse(
        page,
        random.uniform(400, 800),
        random.uniform(200, 400),
    )
    deadline = time.monotonic() + timeout_ms / 1000

    # Capture initial datadome cookie value (if any) to detect change
    initial_dd = None
    for c in page.context.cookies():
        if c["name"] == "datadome":
            initial_dd = c["value"]
            break

    while time.monotonic() < deadline:
        # Check for t=bv redirect mid-solve
        try:
            if "t=bv" in page.url:
                logger.warning(
                    "DataDome redirected to t=bv, solve failed"
                )
                return False
        except Exception:
            pass

        cookies = page.context.cookies()
        for c in cookies:
            if c["name"] == "datadome" and c["value"] != initial_dd:
                # Cookie value changed — challenge solved
                solver._replay_browse_chunk(page, state, 0.5)
                return True

        # Check if captcha-delivery iframe is gone (secondary signal)
        try:
            has_captcha_frame = any(
                "captcha-delivery" in f.url for f in page.frames
            )
            if not has_captcha_frame and initial_dd is not None:
                # Iframe removed — re-check cookie value changed
                cookies = page.context.cookies()
                for c in cookies:
                    if (
                        c["name"] == "datadome"
                        and c["value"] != initial_dd
                    ):
                        solver._replay_browse_chunk(
                            page, state, 0.5
                        )
                        return True
        except Exception:
            pass

        solver._replay_browse_chunk(page, state, 0.5)

    return False
