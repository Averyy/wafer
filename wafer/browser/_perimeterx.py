"""PerimeterX press-and-hold challenge solver.

All PX-specific logic lives here.  Functions receive a *solver*
reference (``BrowserSolver``) for access to mouse-replay methods
and recordings.
"""

import logging
import random
import time

logger = logging.getLogger("wafer")

# JS to check progress bar fill percentage inside the PX frame.
# Finds the absolute-positioned, z-index:-1 div inside
# role="button" (the progress bar) and returns its width
# as a fraction of its parent's width (0.0 to 1.0).
# NOTE: Must use ``(function(){...})()`` IIFE — Playwright
# auto-wraps bare ``() =>`` / ``function`` strings as callables.
_PROGRESS_JS = """(function() {
    var btn = document.querySelector('[role="button"]');
    if (!btn) return -1;
    var divs = btn.querySelectorAll('div');
    for (var i = 0; i < divs.length; i++) {
        var cs = getComputedStyle(divs[i]);
        if (cs.position === 'absolute'
            && cs.zIndex === '-1'
            && cs.height !== '0px') {
            var pw = divs[i].parentElement
                .getBoundingClientRect().width;
            var ew = divs[i].getBoundingClientRect().width;
            return pw > 0 ? ew / pw : 0;
        }
    }
    return -1;
})()"""


def has_px_challenge(page) -> bool:
    """Check if the page currently shows a PX challenge."""
    try:
        el = page.locator("#px-captcha")
        return el.count() > 0
    except Exception:
        return False


def find_px_frame(page):
    """Find the real (visible) PX captcha frame.

    PX creates multiple decoy frames with the same title and
    ``role="button"`` elements but invisible (0x0) dimensions.
    We must check that the button is actually visible.
    """
    for frame in page.frames:
        try:
            title = frame.evaluate("document.title")
            if "human verification" not in title.lower():
                continue
            btn = frame.locator('[role="button"]')
            if btn.count() == 0:
                continue
            box = btn.first.bounding_box(timeout=500)
            if (
                box
                and box["width"] > 10
                and box["height"] > 10
            ):
                return frame
        except Exception:
            pass
    return None


def find_px_button(
    page, timeout: float = 30.0
) -> tuple[float, float, object] | None:
    """Locate the PX press-and-hold button center.

    Scans all frames for the actual button element
    (``role="button"`` or visible iframe inside ``#px-captcha``).
    Polls until found or timeout, solving both timing and
    targeting: we don't proceed until the button is rendered,
    and we click its exact center.

    Returns ``(x, y, frame)`` where *frame* is the Playwright
    frame containing the visible button (needed for progress
    bar monitoring).  Fallback strategies return ``None`` for
    the frame when the real PX frame can't be identified.
    """
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        # Strategy 1: Find role="button" in PX captcha
        # frames (identified by title="Human verification
        # challenge" — unique to PX, won't match page buttons)
        for frame in page.frames:
            try:
                title = frame.evaluate("document.title")
            except Exception:
                continue
            if "human verification" not in title.lower():
                continue
            try:
                btn = frame.locator('[role="button"]')
                if btn.count() > 0:
                    box = btn.first.bounding_box(timeout=500)
                    if (
                        box
                        and box["width"] > 10
                        and box["height"] > 10
                    ):
                        # Click within 20-80% of width,
                        # 30-60% of height (not dead center)
                        rx = random.uniform(0.2, 0.8)
                        ry = random.uniform(0.3, 0.6)
                        x = box["x"] + box["width"] * rx
                        y = box["y"] + box["height"] * ry
                        logger.info(
                            "Found button in PX frame "
                            "(title=%r): box=%s "
                            "click=(%.0f,%.0f) "
                            "at %.0f%%,%.0f%%",
                            title,
                            box,
                            x,
                            y,
                            rx * 100,
                            ry * 100,
                        )
                        return (x, y, frame)
            except Exception:
                pass

        # Strategy 2: Find visible iframe inside #px-captcha
        try:
            iframe_el = page.locator("#px-captcha iframe")
            if iframe_el.count() > 0:
                box = iframe_el.first.bounding_box(
                    timeout=500
                )
                if (
                    box
                    and box["width"] > 10
                    and box["height"] > 10
                ):
                    rx = random.uniform(0.2, 0.8)
                    ry = random.uniform(0.3, 0.6)
                    x = box["x"] + box["width"] * rx
                    y = box["y"] + box["height"] * ry
                    logger.info(
                        "Found button via #px-captcha "
                        "iframe: box=%s "
                        "click=(%.0f,%.0f)",
                        box,
                        x,
                        y,
                    )
                    return (x, y, None)
        except Exception:
            pass

        time.sleep(0.5)

    # Final fallback: #px-captcha div (upper portion
    # where the iframe button sits, not dead center)
    try:
        el = page.locator("#px-captcha")
        if el.count() > 0:
            box = el.bounding_box()
            if box and box["width"] > 10 and box["height"] > 10:
                rx = random.uniform(0.3, 0.7)
                # Button iframe is top-aligned in the div,
                # so click upper 40% not center
                ry = random.uniform(0.15, 0.40)
                x = box["x"] + box["width"] * rx
                y = box["y"] + box["height"] * ry
                logger.warning(
                    "Using #px-captcha fallback: "
                    "box=%s click=(%.0f,%.0f)",
                    box,
                    x,
                    y,
                )
                return (x, y, None)
    except Exception:
        pass

    return None


def replay_hold(
    solver, page, x: float, y: float, px_frame=None
) -> None:
    """Hold at ``(x, y)`` with jitter, release when bar fills.

    Watches the progress bar in the PX iframe. Releases
    300-600ms after the bar reaches 100% (human reaction time).
    Falls back to max hold if progress can't be read.

    PX fakes fast bar fills as a honeypot to catch bots.
    Real fills take 6-10s.  Never release before ``min_hold``.

    Args:
        solver: BrowserSolver instance (for hold recordings).
        px_frame: The Playwright frame containing the visible
            PX button.  Must be the same frame found by
            ``find_px_button`` to avoid decoy frames.
    """
    rec = random.choice(solver._hold_recordings)
    recording = rec["rows"]
    time_scale = random.uniform(0.90, 1.10)
    max_hold = 20.0  # safety ceiling
    # PX fakes fast bar fills as a honeypot to catch bots.
    # Real fills take 6-10s.  Never release before this floor.
    min_hold = 5.0

    if px_frame:
        logger.debug("Watching progress bar in PX frame")
    else:
        logger.debug(
            "No PX frame provided, using max hold fallback"
        )

    logger.info(
        "Hold: %s (%d jitter points) at (%.0f, %.0f)",
        rec["name"],
        len(recording),
        x,
        y,
    )

    page.mouse.move(x, y)
    logger.debug("mouse.down() at (%.0f, %.0f)", x, y)
    page.mouse.down()

    hold_start = time.monotonic()
    jitter_idx = 0
    last_check = 0.0
    check_interval = 0.3  # check progress every 300ms
    bar_filled = False

    while True:
        elapsed = time.monotonic() - hold_start
        if elapsed > max_hold:
            logger.warning("Max hold reached (%.0fs)", elapsed)
            break

        # Apply jitter from recording
        while jitter_idx < len(recording):
            row = recording[jitter_idx]
            target_t = row["t"] * time_scale
            if target_t > elapsed:
                break  # not time for this point yet
            page.mouse.move(
                x + row["dx"], y + row["dy"]
            )
            jitter_idx += 1

        # Check progress bar periodically
        if (
            px_frame
            and elapsed - last_check >= check_interval
        ):
            last_check = elapsed
            try:
                pct = px_frame.evaluate(_PROGRESS_JS)
                if isinstance(pct, (int, float)):
                    logger.debug(
                        "Progress: %.1f%% (%.1fs)",
                        pct * 100,
                        elapsed,
                    )
                    if pct >= 0.99 and elapsed >= min_hold:
                        bar_filled = True
                        break
                    if pct >= 0.99 and elapsed < min_hold:
                        logger.debug(
                            "Bar full but too early "
                            "(%.1fs < %.0fs min) — "
                            "honeypot, keep holding",
                            elapsed,
                            min_hold,
                        )
            except Exception as exc:
                logger.debug(
                    "Progress check error: %s", exc
                )

        # Small sleep to avoid busy-waiting
        time.sleep(0.05)

    # Human reaction delay before release
    release_delay = random.uniform(0.3, 0.6)
    time.sleep(release_delay)

    total = time.monotonic() - hold_start
    logger.debug(
        "mouse.up() after %.1fs (+%.2fs release)%s",
        total - release_delay,
        release_delay,
        " [bar full]" if bar_filled else " [timeout]",
    )
    page.mouse.up()


def wait_for_px_solve(page, timeout: float = 20.0) -> bool:
    """Detect whether PX challenge was solved after hold."""
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        # Check for navigation (redirect = solve)
        try:
            _ = page.url
        except Exception:
            # Navigation in progress — good sign
            time.sleep(1)
            continue

        # Check #px-captcha element specifically (not string
        # search — CSS class names contain "px-captcha" too)
        try:
            el = page.locator("#px-captcha")
            if el.count() == 0:
                logger.info("PX solve: #px-captcha removed")
                return True
        except Exception:
            # Page navigating
            time.sleep(1)
            continue

        # Check for "try again" / error inside the PX frame
        px_frame = find_px_frame(page)
        if px_frame:
            try:
                text = px_frame.evaluate(
                    "document.body.innerText"
                )
                if "try again" in text.lower():
                    logger.info("PX solve: try again detected")
                    return False
            except Exception:
                pass

        time.sleep(0.5)

    return False


def poll_perimeterx_cookies(page, timeout_ms: int) -> bool:
    """Passive PX polling — wait for cookies without interaction.

    Kept as fallback when recordings are unavailable.
    """
    deadline = time.monotonic() + timeout_ms / 1000

    while time.monotonic() < deadline:
        cookies = page.context.cookies()
        cookie_names = {c["name"] for c in cookies}
        if "_pxhd" in cookie_names or "_px3" in cookie_names:
            try:
                # Use element query, not string search — CSS class
                # names like "px-captcha-container" cause false matches
                # in page.content() (ref-perimeterx.md bug #7).
                el = page.locator("#px-captcha")
                if el.count() == 0:
                    time.sleep(0.5)
                    return True
            except Exception:
                pass
        time.sleep(0.5)

    return False


def solve_perimeterx(solver, page, timeout_ms: int) -> bool:
    """Solve PX press-and-hold using recorded human input.

    Two-phase approach:
    1. Detect challenge via DOM (poll for ``#px-captcha``).
    2. Wait for iframe to appear, find the button.
    3. Perform the click-and-hold with progress monitoring.
    """
    # --- Phase 1: Detect challenge via DOM ---
    challenge_found = False
    for i in range(20):  # up to ~10 seconds
        if has_px_challenge(page):
            challenge_found = True
            logger.info(
                "PX challenge detected in DOM after "
                "%.1fs (%d frames)",
                i * 0.5,
                len(page.frames),
            )
            break
        time.sleep(0.5)

    if not challenge_found:
        logger.debug(
            "No PX challenge detected after 10s, "
            "using passive polling"
        )
        return poll_perimeterx_cookies(page, timeout_ms)

    if not solver._ensure_recordings():
        logger.info(
            "PX challenge detected but no recordings "
            "available, falling back to passive polling"
        )
        return poll_perimeterx_cookies(page, timeout_ms)

    for attempt in range(3):
        # --- Phase 2: Wait for iframe content to load ---
        # Step A: Wait for an iframe to appear inside
        # #px-captcha (PX injects it after a delay)
        try:
            page.wait_for_function(
                "document.querySelector("
                "'#px-captcha iframe') !== null",
                timeout=30000,
            )
            logger.info("Iframe appeared in #px-captcha")
        except Exception:
            logger.warning(
                "No iframe in #px-captcha after 30s"
            )

        # Step B: Brief settle for iframe content — don't
        # wait for full networkidle (30s+ on PX sites with
        # persistent connections).  find_px_button already
        # polls until the button is rendered and visible.
        time.sleep(random.uniform(0.5, 1.0))

        # Locate the button via DOM (polls up to 30s)
        result = find_px_button(page)
        if not result:
            logger.warning("Could not locate PX button")
            return False

        target_x, target_y, btn_frame = result
        viewport = page.viewport_size or {
            "width": 1920,
            "height": 1080,
        }

        # Log button position + bounding box details
        try:
            el = page.locator("#px-captcha")
            box = el.bounding_box()
            logger.info(
                "Attempt %d: button at (%.0f, %.0f), "
                "box=%s, viewport=%dx%d, frames=%d",
                attempt + 1,
                target_x,
                target_y,
                box,
                viewport["width"],
                viewport["height"],
                len(page.frames),
            )
        except Exception:
            logger.info(
                "Attempt %d: button at (%.0f, %.0f)",
                attempt + 1,
                target_x,
                target_y,
            )

        # Pre-interaction idle
        idle_origin_x = random.uniform(
            viewport["width"] * 0.3,
            viewport["width"] * 0.7,
        )
        idle_origin_y = random.uniform(
            viewport["height"] * 0.2,
            viewport["height"] * 0.5,
        )
        start_x, start_y = solver._replay_idle(
            page, idle_origin_x, idle_origin_y
        )

        # Path to button
        solver._replay_path(
            page, start_x, start_y, target_x, target_y
        )

        # Brief hover pause (human reads button text)
        hover_pause = random.uniform(0.3, 0.8)
        logger.debug("Hovering for %.2fs", hover_pause)
        time.sleep(hover_pause)

        # Hold (pass the real frame for progress monitoring)
        replay_hold(
            solver, page, target_x, target_y,
            px_frame=btn_frame,
        )

        # Check result
        logger.info("Hold complete, checking result...")
        if wait_for_px_solve(page, timeout=20.0):
            return True

        logger.info(
            "PX attempt %d failed, retrying",
            attempt + 1,
        )
        time.sleep(random.uniform(1.0, 2.0))

        # Challenge may have disappeared (redirect = success)
        if not has_px_challenge(page):
            return True

    return False
