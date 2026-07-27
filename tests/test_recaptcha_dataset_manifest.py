import json
from pathlib import Path

import pytest
from PIL import Image, ImageDraw

from training.recaptcha.dataset_manifest import (
    LABEL_CONFLICT_RESOLUTIONS,
    _deduplicate,
    build_manifest,
    write_manifest,
)


def _tile(path, color):
    path.parent.mkdir(parents=True, exist_ok=True)
    image = Image.new("RGB", (100, 100), color)
    ImageDraw.Draw(image).rectangle((0, 0, color[1], 99), fill=(0, 0, 0))
    image.save(path)


def _dataset(root, *, start=0, pattern_offset=0):
    for offset, label in enumerate(("Car", "Crosswalk")):
        _tile(
            root / label / f"{label}-one.jpg",
            (start + offset, 20 + pattern_offset, 30),
        )
        _tile(
            root / label / f"{label}-two.jpg",
            (start + offset, 40 + pattern_offset, 50),
        )


def test_manifest_is_deterministic_stratified_and_has_no_split_leakage(tmp_path):
    data = tmp_path / "data"
    _dataset(data)

    first = build_manifest([data], validation_fraction=0.5, seed=7)
    second = build_manifest([data], validation_fraction=0.5, seed=7)

    assert first["manifest_sha256"] == second["manifest_sha256"]
    assert {item["label"] for item in first["splits"]["train"]} == {
        "Car",
        "Crosswalk",
    }
    assert {item["label"] for item in first["splits"]["validation"]} == {
        "Car",
        "Crosswalk",
    }
    train = {item["pixel_sha256"] for item in first["splits"]["train"]}
    validation = {item["pixel_sha256"] for item in first["splits"]["validation"]}
    assert not train & validation
    train_dhashes = {item["dhash"] for item in first["splits"]["train"]}
    validation_dhashes = {
        item["dhash"] for item in first["splits"]["validation"]
    }
    assert not train_dhashes & validation_dhashes
    train_origins = {item["origin_key"] for item in first["splits"]["train"]}
    validation_origins = {
        item["origin_key"] for item in first["splits"]["validation"]
    }
    assert not train_origins & validation_origins


def test_roboflow_derivative_origin_group_cannot_cross_split(tmp_path):
    data = tmp_path / "data"
    _tile(data / "Car" / "Car (2545).png", (1, 20, 30))
    _tile(data / "Car" / "Car-2545-_png.rf.abcdef.jpg", (2, 80, 30))
    _tile(data / "Car" / "Car-999.png", (3, 40, 30))
    _tile(data / "Crosswalk" / "Cross-1.png", (4, 30, 30))
    _tile(data / "Crosswalk" / "Cross-2.png", (5, 70, 30))

    manifest = build_manifest([data], validation_fraction=0.5, seed=7)

    pair = {
        "Car (2545).png",
        "Car-2545-_png.rf.abcdef.jpg",
    }
    train_names = {Path(item["path"]).name for item in manifest["splits"]["train"]}
    validation_names = {
        Path(item["path"]).name for item in manifest["splits"]["validation"]
    }
    assert pair <= train_names or pair <= validation_names


def test_cross_label_dhash_and_origin_groups_cannot_cross_split(tmp_path):
    data = tmp_path / "data"
    _tile(data / "Car" / "scene-1.png", (1, 20, 30))
    _tile(data / "Car" / "car-2.png", (2, 40, 30))
    _tile(data / "Crosswalk" / "scene-1.png", (3, 80, 30))
    _tile(data / "Crosswalk" / "cross-2.png", (4, 60, 30))

    manifest = build_manifest([data], validation_fraction=0.5, seed=7)

    train = manifest["splits"]["train"]
    validation = manifest["splits"]["validation"]
    assert not {item["dhash"] for item in train} & {
        item["dhash"] for item in validation
    }
    assert not {item["origin_key"] for item in train} & {
        item["origin_key"] for item in validation
    }


@pytest.mark.parametrize(
    ("heldout_name", "heldout_color", "match"),
    [
        ("different-name.png", (1, 20, 90), "dhash"),
        ("Crosswalk-one.jpg", (99, 90, 90), "origin_key"),
    ],
)
def test_manifest_rejects_heldout_perceptual_or_origin_overlap(
    tmp_path, heldout_name, heldout_color, match
):
    data = tmp_path / "data"
    heldout = tmp_path / "heldout"
    _dataset(data)
    target = heldout / "Crosswalk" / heldout_name
    if match == "dhash":
        with Image.open(data / "Crosswalk" / "Crosswalk-one.jpg") as source:
            image = source.convert("RGB")
        image.putpixel((99, 99), (255, 0, 0))
        target.parent.mkdir(parents=True, exist_ok=True)
        image.save(target)
    else:
        _tile(target, heldout_color)

    with pytest.raises(ValueError, match=match):
        build_manifest([data], [heldout], validation_fraction=0.5)


def test_manifest_excludes_duplicate_extra_source_with_provenance(tmp_path):
    base = tmp_path / "base"
    extra = tmp_path / "extra"
    _dataset(base)
    _dataset(extra)

    manifest = build_manifest([base, extra], validation_fraction=0.5)

    assert len(manifest["splits"]["train"]) == 2
    assert len(manifest["splits"]["validation"]) == 2
    assert len(manifest["excluded_duplicates"]) == 4
    assert {item["reason"] for item in manifest["excluded_duplicates"]} == {
        "pixel_sha256"
    }


def test_manifest_explicitly_excludes_extra_collection_only_class(tmp_path):
    base = tmp_path / "base"
    extra = tmp_path / "extra"
    _dataset(base)
    _dataset(extra, start=80)
    _tile(extra / "Boat" / "boat.jpg", (20, 80, 120))

    manifest = build_manifest([base, extra], validation_fraction=0.5)

    assert manifest["classes"] == ["Car", "Crosswalk"]
    assert manifest["excluded_unsupported_classes"] == [
        {
            "label": "Boat",
            "reason": "unsupported_class",
            "source": str(extra.resolve()),
        }
    ]


def test_reviewed_conflict_keeps_only_explicit_manual_resolution(monkeypatch):
    pixel_digest = "a" * 64
    first = {
        "path": "/base/car.jpg",
        "label": "Car",
        "pixel_sha256": pixel_digest,
        "raw_sha256": "1" * 64,
        "dhash": "1" * 16,
    }
    reviewed = {
        "path": "/manual/crosswalk.jpg",
        "label": "Crosswalk",
        "pixel_sha256": pixel_digest,
        "raw_sha256": "2" * 64,
        "dhash": "1" * 16,
    }
    monkeypatch.setitem(LABEL_CONFLICT_RESOLUTIONS, pixel_digest, "Crosswalk")

    selected, excluded = _deduplicate([first, reviewed])

    assert selected == [reviewed]
    assert excluded[0]["path"] == first["path"]
    assert excluded[0]["reason"] == "superseded_conflicting_label"
    assert excluded[0]["resolved_label"] == "Crosswalk"


def test_manifest_rejects_heldout_overlap_and_writes_reviewable_json(tmp_path):
    data = tmp_path / "data"
    heldout = tmp_path / "heldout"
    _dataset(data)
    _dataset(heldout)

    with pytest.raises(ValueError, match="Held-out images overlap"):
        build_manifest([data], [heldout], validation_fraction=0.5)

    heldout = tmp_path / "different-heldout"
    _tile(heldout / "Car" / "fresh-car.jpg", (80, 70, 30))
    _tile(heldout / "Crosswalk" / "fresh-crosswalk.jpg", (81, 60, 50))
    manifest = build_manifest([data], [heldout], validation_fraction=0.5)
    output = tmp_path / "manifest.json"
    write_manifest(manifest, output)
    saved = json.loads(output.read_text())
    assert saved["manifest_sha256"] == manifest["manifest_sha256"]
    assert len(saved["splits"]["heldout"]) == 2
