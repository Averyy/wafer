"""reCAPTCHA grid round handling: carousel transitions, grid type, verdicts.

Every case here comes from a live AliExpress MTop reCAPTCHA solve
(2026-10-08) whose log showed the solver losing a round or the whole solve.
"""

import io
import logging
import time
from unittest.mock import MagicMock, patch

import numpy as np
import pytest
from PIL import Image

from wafer.browser import _recaptcha_grid as grid


def _png() -> bytes:
    raw = io.BytesIO()
    Image.new("RGB", (12, 12)).save(raw, "PNG")
    return raw.getvalue()


# ---------------------------------------------------------------------------
# Round identity
# ---------------------------------------------------------------------------


class TestNewRound:
    def test_button_relabel_is_not_a_new_round(self):
        # Live: 45 ms after a 4x4 "Next", the button read "Skip" while the
        # old image was still on screen and the carousel had not moved.
        before = ("payload-a", "Select all squares with bicycles", "Next")
        after = ("payload-a", "Select all squares with bicycles", "Skip")

        assert grid._new_round(before, after) is False

    @pytest.mark.parametrize(
        "after",
        [
            ("payload-b", "Select all squares with bicycles", "Next"),
            ("payload-a", "Select all images with buses", "Next"),
        ],
        ids=["new-image", "new-prompt"],
    )
    def test_new_image_or_prompt_is_a_new_round(self, after):
        before = ("payload-a", "Select all squares with bicycles", "Next")

        assert grid._new_round(before, after) is True

    @pytest.mark.parametrize("pair", [(None, ("a", "b", "c")), (("a", "b", "c"), None)])
    def test_unreadable_marker_is_not_a_new_round(self, pair):
        assert grid._new_round(*pair) is False

    def test_post_verify_keeps_waiting_through_a_button_relabel(self):
        bframe = MagicMock()
        bframe.locator.return_value.first.is_visible.return_value = False
        before = ("payload-a", "Select all squares with bicycles", "Next")

        with (
            patch("wafer.browser._recaptcha._check_token", return_value=False),
            patch.object(
                grid,
                "_grid_state_marker",
                return_value=("payload-a", before[1], "Skip"),
            ),
            patch.object(grid, "_sleep_with_deadline", return_value=False),
        ):
            outcome = grid._wait_for_post_verify_outcome(
                MagicMock(), bframe, time.monotonic() + 1, before
            )

        assert outcome == "pending"

    def test_post_verify_ignores_an_error_that_was_already_showing(self):
        bframe = MagicMock()
        bframe.locator.return_value.first.is_visible.return_value = True
        marker = ("payload-a", "Select all images with cars", "Verify")

        with (
            patch("wafer.browser._recaptcha._check_token", return_value=False),
            patch.object(grid, "_grid_state_marker", return_value=marker),
            patch.object(grid, "_sleep_with_deadline", return_value=False),
        ):
            stale = grid._wait_for_post_verify_outcome(
                MagicMock(),
                bframe,
                time.monotonic() + 1,
                marker,
                ignore_outcomes=frozenset({"more", "incorrect"}),
            )
            fresh = grid._wait_for_post_verify_outcome(
                MagicMock(), bframe, time.monotonic() + 1, marker
            )

        assert stale == "pending"
        assert fresh == "more"

    def test_stale_error_that_clears_and_returns_is_this_rounds_verdict(self):
        bframe = MagicMock()
        shows = iter([True, False, False, False, True, False])
        bframe.locator.return_value.first.is_visible.side_effect = (
            lambda **_k: next(shows)
        )
        marker = ("payload-a", "Select all images with cars", "Verify")

        with (
            patch("wafer.browser._recaptcha._check_token", return_value=False),
            patch.object(grid, "_grid_state_marker", return_value=marker),
            patch.object(grid, "_sleep_with_deadline", return_value=True),
        ):
            outcome = grid._wait_for_post_verify_outcome(
                MagicMock(),
                bframe,
                time.monotonic() + 5,
                marker,
                ignore_outcomes=frozenset({"more"}),
            )

        assert outcome == "more"

    def test_visible_error_outcomes_reads_both_messages(self):
        bframe = MagicMock()
        more, incorrect = (selector for selector, _ in grid._ERROR_OUTCOME_SELECTORS)
        visible = {more: False, incorrect: True}
        bframe.locator.side_effect = lambda selector: MagicMock(
            first=MagicMock(
                is_visible=MagicMock(return_value=visible[selector])
            )
        )

        assert grid._visible_error_outcomes(
            bframe, time.monotonic() + 1
        ) == frozenset({"incorrect"})


# ---------------------------------------------------------------------------
# Grid type
# ---------------------------------------------------------------------------


CAROUSEL = [
    {"size": 4, "moving": True, "image": True},
    {"size": 4, "moving": True, "image": True},
]
ONE_MOVING = [{"size": 4, "moving": True, "image": True}]
SETTLED_44 = [{"size": 4, "moving": False, "image": True}]
SETTLED_33 = [{"size": 3, "moving": False, "image": True}]


class TestGridType:
    def test_waits_for_the_carousel_to_settle(self):
        # Live: mid-carousel the bframe held a "leaving-left" and an
        # "offscreen-right" table-44; the old strict locator raised and the
        # round was read as dynamic_3x3, then reloaded away.
        bframe = MagicMock()
        bframe.evaluate.side_effect = [CAROUSEL, ONE_MOVING, SETTLED_44]

        with patch.object(grid, "_sleep_with_deadline", return_value=True):
            size = grid._settled_grid_size(bframe, time.monotonic() + 10)

        assert size == 4
        assert bframe.evaluate.call_count == 3

    def test_grid_that_never_settles_is_not_guessed(self):
        bframe = MagicMock()
        bframe.evaluate.return_value = CAROUSEL

        with patch.object(grid, "_sleep_with_deadline", side_effect=[True, False]):
            assert grid._settled_grid_size(bframe, time.monotonic() + 10) is None

    @pytest.mark.parametrize(
        "layout",
        [
            [{"size": 3, "moving": False, "image": False}],
            [{"size": 5, "moving": False, "image": True}],
            "not-a-list",
        ],
        ids=["image-missing", "unknown-size", "garbage"],
    )
    def test_incomplete_layout_is_not_settled(self, layout):
        bframe = MagicMock()
        bframe.evaluate.return_value = layout

        with patch.object(grid, "_sleep_with_deadline", return_value=False):
            assert grid._settled_grid_size(bframe, time.monotonic() + 10) is None

    @pytest.mark.parametrize(
        ("layout", "followup", "expected"),
        [
            (SETTLED_44, None, "4x4"),
            (SETTLED_33, True, "dynamic_3x3"),
            (SETTLED_33, False, "static_3x3"),
        ],
    )
    def test_detects_type_from_the_settled_table_and_prompt(
        self, layout, followup, expected
    ):
        bframe = MagicMock()
        bframe.locator.return_value.text_content.return_value = "cars"
        bframe.evaluate.side_effect = [layout, followup]

        grid_type, keyword = grid._detect_grid_type(bframe, time.monotonic() + 10)

        assert (grid_type, keyword) == (expected, "cars")

    def test_unsettled_grid_reports_not_ready(self):
        bframe = MagicMock()
        bframe.locator.return_value.text_content.return_value = "bicycles"

        with patch.object(grid, "_settled_grid_size", return_value=None):
            assert grid._detect_grid_type(bframe, time.monotonic() + 10) == (
                None,
                None,
            )

    @pytest.mark.parametrize(
        ("detected", "reasons", "clicked", "expected"),
        [
            # A dynamic "cars" grid read as static: every click faded a tile.
            ("static_3x3", ["dom_mutation"] * 4, 4, "dynamic_3x3"),
            # A static "traffic lights" grid read as dynamic.
            ("dynamic_3x3", ["selected", "selected"], 2, "static_3x3"),
            ("static_3x3", ["selected", "dom_mutation"], 2, "dynamic_3x3"),
            # Without a reason for every click the DOM guess stands.
            ("static_3x3", ["dom_mutation"], 2, "static_3x3"),
            ("dynamic_3x3", [], 0, "dynamic_3x3"),
            ("4x4", ["dom_mutation"], 1, "4x4"),
        ],
    )
    def test_observed_type_follows_tile_behaviour(
        self, detected, reasons, clicked, expected
    ):
        assert grid._observed_grid_type(detected, reasons, clicked) == expected


# ---------------------------------------------------------------------------
# Tile selection floor
# ---------------------------------------------------------------------------


class TestTileFloor:
    def test_floor_is_data_backed(self):
        assert grid._MIN_TILE_CONFIDENCE == pytest.approx(0.70)

    def test_mid_confidence_argmax_pick_is_skipped(self):
        probs = np.zeros((9, 14), dtype=np.float32)
        probs[:, 9] = 1.0
        for cell, score in ((0, 0.998), (1, 0.955), (2, 0.70), (3, 0.680)):
            probs[cell, :] = (1.0 - score) / 13
            probs[cell, 3] = score

        assert sorted(grid._select_tiles(probs, 3)) == [0, 1, 2]

    def test_target_that_is_not_the_top_class_is_skipped(self):
        probs = np.zeros((9, 14), dtype=np.float32)
        probs[:, 9] = 1.0
        probs[4, 3] = 0.45
        probs[4, 5] = 0.55

        assert grid._select_tiles(probs, 3) is None


# ---------------------------------------------------------------------------
# Payload intercept
# ---------------------------------------------------------------------------


class TestVerifyRequestCounting:
    def test_counts_userverify_requests_when_sent(self):
        page = MagicMock()
        state = grid._setup_payload_intercept(page)
        listeners = {c.args[0]: c.args[1] for c in page.on.call_args_list}

        for url in (
            "https://www.google.com/recaptcha/enterprise/userverify?k=x",
            "https://www.google.com/recaptcha/enterprise/reload?k=x",
            "https://google.evil.test/recaptcha/api2/userverify",
        ):
            listeners["request"](MagicMock(url=url))

        assert state["verify_requests"] == 1
        state["cleanup"]()
        assert {c.args[0] for c in page.remove_listener.call_args_list} == {
            "request",
            "response",
        }

    @pytest.mark.parametrize(
        ("diagnostics", "requests_before", "expected"),
        [
            ({"verify_statuses": [200], "verify_requests": 1}, 1, True),
            ({"verify_statuses": [], "verify_requests": 1}, 0, True),
            ({"verify_statuses": [], "verify_requests": 0}, 0, False),
            ({"verify_statuses": []}, None, False),
            (None, None, False),
        ],
        ids=["answered", "in-flight", "never-sent", "uncounted", "no-diagnostics"],
    )
    def test_verify_reached_google(self, diagnostics, requests_before, expected):
        assert (
            grid._verify_reached_google(diagnostics, 0, requests_before) is expected
        )


# ---------------------------------------------------------------------------
# solve_image_grid round handling
# ---------------------------------------------------------------------------


def _run_grid(
    *,
    detected="static_3x3",
    ack_reasons=("selected",),
    outcomes=("solved",),
    submit_reaches_google=True,
    max_attempts=1,
    new_round_after_verdict=False,
    click_dispatches=True,
    markers=None,
    base_selection=None,
    stale_errors=frozenset(),
):
    """Run solve_image_grid over one mocked grid; return the patched calls."""

    response = MagicMock(status=200)
    response.body.return_value = _png()
    page = MagicMock()
    page.request.get.return_value = response
    bframe = MagicMock()
    bframe.locator.return_value.first.get_attribute.return_value = (
        "https://www.google.com/recaptcha/api2/payload"
    )
    solver = MagicMock()
    solver._ensure_recordings.return_value = True
    probabilities = np.zeros((9, 14), dtype=np.float32)
    probabilities[:, 3] = 1.0
    diagnostics = {"verify_requests": 0, "verify_statuses": [], "verify_summaries": []}
    reasons = list(ack_reasons)

    def click_tile(*_args, ack_reasons=None, **_kwargs):
        if not click_dispatches:
            return 10.0, 20.0, False
        if ack_reasons is not None and reasons:
            ack_reasons.append(reasons.pop(0))
        return 10.0, 20.0, True

    def submit(*_args, **_kwargs):
        if submit_reaches_google:
            diagnostics["verify_requests"] += 1
            diagnostics["verify_statuses"].append(200)
            diagnostics["verify_summaries"].append({"classification": "continued"})
        return 10.0, 20.0, True

    with (
        patch.object(grid, "_ensure_models_before", return_value=(MagicMock(), None)),
        patch.object(
            grid, "_detect_grid_type", return_value=(detected, "cars")
        ) as detect,
        patch.object(grid, "_split_grid", return_value=[Image.new("RGB", (4, 4))] * 9),
        patch.object(grid, "_classify_tiles_batch", return_value=probabilities),
        patch.object(grid, "_select_tiles", return_value=[0]),
        patch.object(grid, "_click_tile", side_effect=click_tile),
        patch.object(
            grid,
            "_handle_dynamic_replacements",
            return_value=(10.0, 20.0, True),
        ) as dynamic,
        patch.object(grid, "_click_verify", side_effect=submit) as verify,
        patch.object(
            grid, "_wait_for_post_verify_outcome", side_effect=list(outcomes)
        ) as observe,
        patch.object(
            grid, "_click_reload", return_value=(10.0, 20.0, True)
        ) as reload,
        patch.object(
            grid,
            "_grid_state_marker",
            side_effect=markers
            or (lambda *_a, **_k: ("payload", "cars", "Verify")),
        ),
        patch.object(
            grid, "_wait_for_new_round", return_value=new_round_after_verdict
        ),
        patch.object(grid, "_visible_error_outcomes", return_value=stale_errors),
        patch.object(
            grid, "_dynamic_base_selection_state", return_value=base_selection
        ),
        patch.object(grid, "_wait_for_grid_stable", return_value=True),
        patch.object(grid, "_sleep_with_deadline", return_value=True),
        patch.object(grid, "_collect_tiles"),
        patch.object(grid, "_collect_det_grid"),
    ):
        solved = grid.solve_image_grid(
            solver,
            page,
            bframe,
            MagicMock(current_x=10.0, current_y=20.0),
            time.monotonic() + 60,
            diagnostics=diagnostics,
            max_attempts=max_attempts,
            protocol_completion_is_intermediate=True,
        )
    return {
        "solved": solved,
        "detect": detect,
        "dynamic": dynamic,
        "verify": verify,
        "observe": observe,
        "reload": reload,
    }


class TestGridRounds:
    def test_static_guess_with_replaced_tiles_watches_replacements(self):
        # Live: a dynamic "cars" grid read as static had Verify pressed while
        # its tiles were still being replaced; no answer went out.
        run = _run_grid(detected="static_3x3", ack_reasons=("dom_mutation",))

        run["dynamic"].assert_called_once()
        assert run["solved"] is True

    def test_dynamic_guess_with_selected_tiles_skips_the_replacement_wait(self):
        run = _run_grid(
            detected="dynamic_3x3",
            ack_reasons=("selected",),
            base_selection=[{"selected": True}],
        )

        run["dynamic"].assert_not_called()
        run["verify"].assert_called_once()
        assert run["solved"] is True

    def test_selected_ack_on_a_grid_that_then_swaps_stays_dynamic(self):
        # A dynamic tile that showed the selected class before fading must
        # not be submitted mid-swap: without a stable selected base grid the
        # DOM guess stands.
        run = _run_grid(
            detected="dynamic_3x3",
            ack_reasons=("selected",),
            base_selection=None,
        )

        run["dynamic"].assert_called_once()

    def test_incorrect_with_a_new_grid_continues_without_reload(self):
        # Live: Google answered a wrong submission with a new grid under
        # "Please try again"; reloading on top of it threw that grid away.
        run = _run_grid(
            outcomes=("incorrect", "solved"),
            max_attempts=2,
            new_round_after_verdict=True,
        )

        run["reload"].assert_not_called()
        assert run["detect"].call_count == 2
        assert run["solved"] is True

    def test_incorrect_without_a_new_grid_reloads(self):
        run = _run_grid(outcomes=("incorrect",), new_round_after_verdict=False)

        run["reload"].assert_called_once()
        assert run["solved"] is False

    def test_verify_that_sent_nothing_reloads_instead_of_ending_the_solve(self):
        # Live: this state ended a 150 s solve at 89 s.
        run = _run_grid(
            outcomes=("pending", "solved"),
            submit_reaches_google=False,
            max_attempts=2,
        )

        run["reload"].assert_called_once()
        assert run["observe"].call_count == 2
        assert all(
            c.kwargs.get("maximum", 10.0) == 10.0
            for c in run["observe"].call_args_list
        )
        assert run["solved"] is True

    def test_verify_that_sent_nothing_but_left_a_new_round_continues(self):
        markers = iter(
            [
                ("payload-a", "cars", "Verify"),
                ("payload-b", "buses", "Skip"),
            ]
        )
        run = _run_grid(
            outcomes=("pending", "solved"),
            submit_reaches_google=False,
            max_attempts=2,
            markers=lambda *_a, **_k: next(markers, ("payload-b", "buses", "Skip")),
        )

        run["reload"].assert_not_called()
        assert run["detect"].call_count == 2
        assert run["solved"] is True

    def test_answer_in_flight_is_watched_not_reloaded(self):
        run = _run_grid(outcomes=("pending", "pending"), submit_reaches_google=True)

        run["reload"].assert_not_called()
        assert run["observe"].call_args_list[1].kwargs["maximum"] == 30.0
        assert run["solved"] is False

    def test_stale_errors_reach_both_observation_windows(self):
        run = _run_grid(
            outcomes=("pending", "solved"),
            stale_errors=frozenset({"incorrect"}),
        )

        assert [
            c.kwargs["ignore_outcomes"] for c in run["observe"].call_args_list
        ] == [frozenset({"incorrect"})] * 2
        assert run["solved"] is True

    def test_error_that_never_cleared_after_an_answer_reloads(self):
        run = _run_grid(
            outcomes=("pending", "pending"),
            stale_errors=frozenset({"more"}),
        )

        run["reload"].assert_called_once()

    def test_lost_tile_click_reloads_without_verify(self):
        run = _run_grid(click_dispatches=False, outcomes=())

        run["verify"].assert_not_called()
        run["reload"].assert_called_once()
        assert run["solved"] is False


# ---------------------------------------------------------------------------
# wait_for_recaptcha
# ---------------------------------------------------------------------------


class _Clock:
    def __init__(self, step: float = 0.25):
        self.now = 1000.0
        self.step = step

    def __call__(self) -> float:
        self.now += self.step
        return self.now


@pytest.mark.parametrize(
    ("tmd", "minimum", "maximum"),
    [(False, 5.0, 12.0), (True, 20.0, 30.0)],
    ids=["generic", "tmd"],
)
def test_anchor_grace_is_longer_under_tmd(tmd, minimum, maximum):
    from wafer.browser import _recaptcha as recaptcha

    clock = _Clock()
    page = MagicMock()
    page.frames = []
    solver = MagicMock()
    with (
        patch.object(recaptcha.time, "monotonic", side_effect=clock),
        patch(
            "wafer.browser._recaptcha_grid._setup_payload_intercept",
            return_value={"cleanup": MagicMock()},
        ),
    ):
        started = clock.now
        result = recaptcha.wait_for_recaptcha(
            solver,
            page,
            150_000,
            protocol_completion_is_intermediate=tmd,
        )

    assert result is False
    assert minimum < clock.now - started < maximum


def test_unexpected_failure_is_logged_at_warning(caplog):
    from wafer.browser._recaptcha import wait_for_recaptcha

    solver = MagicMock()
    solver._start_browse.side_effect = RuntimeError("browser gone")
    with (
        patch(
            "wafer.browser._recaptcha_grid._setup_payload_intercept",
            return_value={"cleanup": MagicMock()},
        ),
        caplog.at_level(logging.INFO, logger="wafer"),
    ):
        assert wait_for_recaptcha(solver, MagicMock(), 1_000) is False

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("RuntimeError" in r.getMessage() for r in warnings)
