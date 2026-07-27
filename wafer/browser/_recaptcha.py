"""reCAPTCHA v2 checkbox + image grid solver."""

import logging
import random
import re
import time
from urllib.parse import urlsplit

logger = logging.getLogger("wafer")


def _is_recaptcha_frame(url: str, kind: str) -> bool:
    """Match Google and recaptcha.net API v2/enterprise iframe URLs."""

    if not isinstance(url, str) or not isinstance(kind, str):
        return False
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").rstrip(".").lower()
    if not (
        host == "google.com"
        or host.endswith(".google.com")
        or host == "recaptcha.net"
        or host.endswith(".recaptcha.net")
    ):
        return False
    expected_path = f"/recaptcha/{kind}"
    return parsed.path in {expected_path, f"{expected_path}/"}


def _widget_frame_name(frame, prefix: str) -> str | None:
    """Return a reCAPTCHA's concrete iframe instance name.

    Google names the sibling anchor/challenge frames ``a-<instance>`` and
    ``c-<instance>``.  The public site key is deliberately not used here: a
    page may host several widgets with that same key.
    """

    try:
        name = frame.name
    except Exception:
        return None
    if not isinstance(name, str):
        return None
    match = re.fullmatch(rf"{re.escape(prefix)}-(.+)", name)
    return match.group(1) if match else None


def _frame_parent(frame):
    """Get a Playwright frame's immediate owner without trusting a fallback."""

    try:
        return frame.parent_frame
    except Exception:
        return None


def _bind_widget(anchor):
    """Bind all later observations to the wrapper containing this anchor.

    A page can host more than one reCAPTCHA widget.  The generic response
    textarea is not enough to identify the widget that was clicked, so retain
    both its anchor's public URL identity and its immediate owning frame.
    """

    instance = _widget_frame_name(anchor, "a")
    owner = _frame_parent(anchor)
    if instance is None or owner is None:
        return None
    return {
        "instance": instance,
        "anchor_name": f"a-{instance}",
        "bframe_name": f"c-{instance}",
        "anchor": anchor,
        "owner": owner,
    }


def _find_bframe(page, widget=None):
    """Find the reCAPTCHA bframe, optionally bound to a clicked widget."""
    # Check the page explicitly as well as every frame.  Playwright normally
    # includes the main frame in ``page.frames``, but keeping the page first
    # makes this correct for wrappers and test doubles that expose only child
    # frames there.
    for frame in (page, *page.frames):
        if not (_is_recaptcha_frame(frame.url, "api2/bframe") or _is_recaptcha_frame(
            frame.url, "enterprise/bframe"
        )):
            continue
        if widget is not None and (
            _frame_parent(frame) is not widget["owner"]
            or _widget_frame_name(frame, "c") != widget["instance"]
        ):
            continue
        return frame
    return None


def _token_values(page, widget=None) -> set[str]:
    """Return populated reCAPTCHA response values from accessible frames.

    Alibaba's TMD page renders the Enterprise widget inside a same-origin
    wrapper iframe, so the textarea is not necessarily in the top document.
    Cross-origin Google frames may reject evaluation; those failures are
    expected and do not prevent checking the remaining frames.
    """

    selector = 'textarea[name^="g-recaptcha-response"]'
    values: set[str] = set()
    # A bound widget intentionally gets exactly one owner frame.  Searching
    # all frames lets another widget's token prove the wrong challenge.
    if widget is not None:
        # The response field belongs to the least common owner of the exact
        # ``a-*`` and ``c-*`` iframe elements.  A page-wide first textarea
        # would let a sibling widget's freshly minted token satisfy ours.
        try:
            scoped = widget["owner"].evaluate(
                """([anchorName, challengeName]) => {
                    const byName = name => document.querySelector(
                        `iframe[name="${CSS.escape(name)}"], ` +
                        `iframe#${CSS.escape(name)}`
                    );
                    const anchor = byName(anchorName);
                    const challenge = byName(challengeName);
                    if (!anchor || !challenge) return [];
                    const ancestors = new Set();
                    for (let node = anchor; node; node = node.parentElement) {
                        ancestors.add(node);
                    }
                    let root = challenge;
                    while (root && !ancestors.has(root)) root = root.parentElement;
                    if (!root) return [];
                    return Array.from(root.querySelectorAll(
                        'textarea[name^="g-recaptcha-response"]'
                    ), el => el.value).filter(Boolean);
                }""",
                [widget["anchor_name"], widget["bframe_name"]],
            )
            if isinstance(scoped, list):
                return {value for value in scoped if isinstance(value, str) and value}
        except Exception:
            pass
        return values

    frames = (page, *page.frames)
    for frame in frames:
        try:
            value = frame.eval_on_selector(selector, "el => el.value")
            if isinstance(value, str) and value:
                values.add(value)
        except Exception:
            continue
    return values


def _check_token(page, baseline: set[str] | None = None, widget=None) -> bool:
    """Accept only a token minted after this challenge began.

    TMD wrappers can retain a response textarea from another widget.  A
    non-empty value alone is therefore not proof that the checkbox/grid just
    interacted with completed.  When a baseline is supplied, require a new
    response value rather than accepting that ambient state.
    """

    if widget is not None:
        # The clicked checkbox is the only per-widget completion signal that
        # is available across Google's cross-origin frames.  In particular,
        # challenge iframes can be appended directly under ``body``; their
        # DOM LCA would otherwise include a sibling widget's response field.
        try:
            checked = widget["anchor"].locator(
                "#recaptcha-anchor"
            ).get_attribute("aria-checked")
        except Exception:
            return False
        if checked != "true":
            return False

    values = _token_values(page, widget)
    if baseline is not None:
        values.difference_update(baseline)
    if values:
        logger.info("reCAPTCHA diagnostic: new response token observed")
        return True
    return False


def _token_observation(
    page,
    baseline: set[str] | None = None,
    widget=None,
) -> dict[str, object]:
    """Return secret-free diagnostics for bound token propagation."""

    checked = None
    if widget is not None:
        try:
            checked = (
                widget["anchor"]
                .locator("#recaptcha-anchor")
                .get_attribute("aria-checked")
                == "true"
            )
        except Exception:
            checked = None
    values = _token_values(page, widget)
    new_values = values - baseline if baseline is not None else values
    return {
        "anchor_checked": checked,
        "scoped_value_count": min(len(values), 32),
        "new_value_count": min(len(new_values), 32),
    }


def _remaining_seconds(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _remaining_timeout_ms(deadline: float, maximum_ms: int) -> int | None:
    """Return a Playwright timeout clamped to the operation deadline."""

    remaining = _remaining_seconds(deadline)
    if remaining <= 0:
        return None
    return max(1, min(maximum_ms, int(remaining * 1000)))


def _click_element(solver, page, state, frame, selector, deadline: float):
    """Click an element using mouse path replay or direct click."""
    timeout = _remaining_timeout_ms(deadline, 3000)
    if timeout is None:
        return False
    try:
        box = frame.locator(selector).bounding_box(timeout=timeout)
    except Exception:
        return False

    if not box:
        return False

    target_x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
    target_y = box["y"] + box["height"] * random.uniform(0.3, 0.7)

    try:
        replayed = solver._replay_path(
            page,
            state.current_x if state else random.uniform(300, 600),
            state.current_y if state else random.uniform(200, 400),
            target_x,
            target_y,
            deadline=deadline,
        )
        if not replayed:
            return False
    except Exception:
        if _remaining_seconds(deadline) <= 0:
            return False
        page.mouse.move(target_x, target_y)

    pause = min(random.uniform(0.08, 0.22), _remaining_seconds(deadline))
    if pause <= 0:
        return False
    time.sleep(pause)
    if _remaining_seconds(deadline) <= 0:
        return False
    page.mouse.click(target_x, target_y)
    return True


def wait_for_recaptcha(
    solver,
    page,
    timeout_ms: int,
    *,
    protocol_completion_is_intermediate: bool = False,
) -> bool:
    """Wait for reCAPTCHA v2 checkbox challenge to resolve.

    Clicks the checkbox in the google.com/recaptcha iframe and polls
    for the g-recaptcha-response token.  If Google escalates to an
    image challenge, solves it via the image grid solver (ONNX).

    Early bail-out: if no recaptcha iframe appears within 5 seconds,
    returns False (browser likely passed through without challenge).
    """
    if timeout_ms <= 0:
        return False
    deadline = time.monotonic() + timeout_ms / 1000
    token_baseline = None
    widget = None

    # Set up payload intercept BEFORE checkbox click - the payload
    # response fires during challenge load and we need the image for
    # the grid solver.
    from wafer.browser._recaptcha_grid import _setup_payload_intercept

    payload_state = _setup_payload_intercept(page)

    def _cleanup_listener():
        try:
            payload_state["cleanup"]()
        except Exception:
            pass

    try:
        logger.info(
            "reCAPTCHA diagnostic: phase=wait-anchor remaining_ms=%d",
            int(_remaining_seconds(deadline) * 1000),
        )
        state = solver._start_browse(
            page,
            random.uniform(400, 800),
            random.uniform(200, 400),
        )
        # Natural "reading the page" before interacting with CAPTCHA.
        initial_browse = min(
            random.uniform(1.5, 3.0), _remaining_seconds(deadline)
        )
        if initial_browse <= 0:
            return False
        solver._replay_browse_chunk(page, state, initial_browse)
        grace_deadline = min(deadline, time.monotonic() + 5.0)
        iframe_seen = False
        checkbox_clicked = False

        # Phase 1: Click checkbox and wait for auto-pass or bframe escalation.
        while time.monotonic() < deadline:
            if widget is not None and _check_token(
                page, token_baseline, widget
            ):
                logger.info("reCAPTCHA solved, token obtained")
                return True

            # Find and click the checkbox iframe
            if not checkbox_clicked:
                try:
                    for frame in page.frames:
                        is_anchor = _is_recaptcha_frame(
                            frame.url, "api2/anchor"
                        ) or _is_recaptcha_frame(
                            frame.url, "enterprise/anchor"
                        )
                        if is_anchor:
                            candidate = _bind_widget(frame)
                            if candidate is None:
                                # Without a concrete owner and matching
                                # identity, a token from a sibling widget
                                # could be mistaken for this one.
                                continue
                            widget = candidate
                            token_baseline = _token_values(page, widget)
                            iframe_seen = True
                            logger.info(
                                "reCAPTCHA diagnostic: phase=anchor-found "
                                "remaining_ms=%d",
                                int(_remaining_seconds(deadline) * 1000),
                            )
                            from wafer.browser._solver import (
                                patch_frame_screenxy,
                            )

                            patch_frame_screenxy(
                                frame,
                                needs_patch=bool(
                                    getattr(solver, "_needs_screenxy_patch", False)
                                ),
                            )
                            if _click_element(
                                solver,
                                page,
                                state,
                                frame,
                                ".recaptcha-checkbox-border",
                                deadline,
                            ):
                                checkbox_clicked = True
                                logger.info(
                                    "reCAPTCHA diagnostic: phase=checkbox-clicked "
                                    "remaining_ms=%d",
                                    int(_remaining_seconds(deadline) * 1000),
                                )
                            break
                except Exception:
                    pass
            else:
                # Only check for bframe AFTER checkbox click - reCAPTCHA
                # pre-loads the bframe iframe, so its URL exists before
                # the user interacts.  Detect escalation by checking if
                # the challenge content is visible inside the bframe.
                bframe = _find_bframe(page, widget)
                if bframe:
                    try:
                        timeout = _remaining_timeout_ms(deadline, 300)
                        if timeout is None:
                            return False
                        visible = bframe.locator(
                            ".rc-imageselect-challenge"
                        ).is_visible(timeout=timeout)
                        if visible:
                            logger.info(
                                "reCAPTCHA diagnostic: phase=grid-visible "
                                "remaining_ms=%d",
                                int(_remaining_seconds(deadline) * 1000),
                            )
                            break
                    except Exception:
                        pass

            if not iframe_seen and time.monotonic() > grace_deadline:
                logger.info(
                    "No reCAPTCHA iframe after 5s, "
                    "browser likely passed through"
                )
                return False

            browse_seconds = min(1.0, _remaining_seconds(deadline))
            if browse_seconds <= 0:
                break
            solver._replay_browse_chunk(page, state, browse_seconds)
        else:
            # Timed out without bframe or token
            return False

        # Grab bframe reference for image grid phase
        bframe = _find_bframe(page, widget)
        if not bframe:
            return False

        from wafer.browser._solver import patch_frame_screenxy

        patch_frame_screenxy(
            bframe,
            needs_patch=bool(getattr(solver, "_needs_screenxy_patch", False)),
        )

        # Phase 2: Solve image grid challenge.
        logger.info("reCAPTCHA escalated to image challenge")

        # Wait for bframe DOM to load (URL appears before content)
        try:
            timeout = _remaining_timeout_ms(deadline, 5000)
            if timeout is None:
                return False
            bframe.wait_for_load_state("domcontentloaded", timeout=timeout)
        except Exception:
            pass

        if time.monotonic() < deadline:
            from wafer.browser._recaptcha_grid import solve_image_grid

            return bool(
                solve_image_grid(
                    solver,
                    page,
                    bframe,
                    state,
                    deadline,
                    payload=payload_state.get("payload"),
                    diagnostics=payload_state,
                    token_baseline=token_baseline,
                    token_widget=widget,
                    protocol_completion_is_intermediate=(
                        protocol_completion_is_intermediate
                    ),
                )
            )
        return False
    except Exception:
        logger.debug("reCAPTCHA interaction failed", exc_info=True)
        return False
    finally:
        _cleanup_listener()
