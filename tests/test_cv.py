"""Tests for CV notch detection against GeeTest test image pairs."""

from pathlib import Path

import pytest

from wafer.browser._cv import find_notch

IMAGES = Path(__file__).parent / "mocks" / "geetest" / "images"
PAIRS = [(1, "bg_001.png", "piece_001.png"),
         (2, "bg_002.png", "piece_002.png"),
         (3, "bg_003.png", "piece_003.png"),
         (4, "bg_004.png", "piece_004.png"),
         (5, "bg_005.png", "piece_005.png")]

BG_WIDTH = 300


@pytest.mark.parametrize("pair_id,bg_name,piece_name", PAIRS)
class TestFindNotch:
    def test_confidence_above_threshold(self, pair_id, bg_name, piece_name):
        """Confidence must exceed the retry threshold (0.4)."""
        bg = (IMAGES / bg_name).read_bytes()
        piece = (IMAGES / piece_name).read_bytes()
        _, confidence = find_notch(bg, piece)
        assert confidence > 0.4, (
            f"Pair {pair_id}: confidence {confidence:.3f} below 0.4"
        )

    def test_x_offset_in_right_portion(self, pair_id, bg_name, piece_name):
        """Notch should be in the right ~70% of the background (x > 60)."""
        bg = (IMAGES / bg_name).read_bytes()
        piece = (IMAGES / piece_name).read_bytes()
        x_offset, _ = find_notch(bg, piece)
        assert 60 < x_offset < BG_WIDTH, (
            f"Pair {pair_id}: x_offset {x_offset} outside expected range"
        )

    def test_returns_int_offset_and_float_confidence(
        self, pair_id, bg_name, piece_name
    ):
        """Return types must be (int, float)."""
        bg = (IMAGES / bg_name).read_bytes()
        piece = (IMAGES / piece_name).read_bytes()
        x_offset, confidence = find_notch(bg, piece)
        assert isinstance(x_offset, int)
        assert isinstance(confidence, float)


class TestMismatchedPair:
    def test_wrong_piece_lower_confidence(self):
        """Mismatched piece should have lower confidence than correct pair."""
        bg = (IMAGES / "bg_001.png").read_bytes()
        correct_piece = (IMAGES / "piece_001.png").read_bytes()
        wrong_piece = (IMAGES / "piece_003.png").read_bytes()
        _, correct_conf = find_notch(bg, correct_piece)
        _, wrong_conf = find_notch(bg, wrong_piece)
        assert correct_conf > wrong_conf, (
            f"Correct pair ({correct_conf:.3f}) should beat "
            f"mismatched pair ({wrong_conf:.3f})"
        )
