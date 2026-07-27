"""Deterministic, leakage-safe manifests for reCAPTCHA classifier training.

The datasets in this project are class-directory trees, not torchvision's
``train/``/``val/`` layout.  This module creates one explicit split manifest
from those trees so train/validation/held-out membership is reviewable and
reproducible without moving or deleting source data.
"""

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from PIL import Image

try:
    from .durable_io import atomic_write_json
except ImportError:
    from durable_io import atomic_write_json

IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".webp"}
NORMALIZED_SIZE = (100, 100)

# These exact conflicts were independently visual-reviewed against both source
# trees. The inherited classic label is ``Car`` in every case; its manually
# reviewed counterpart is the visually correct target. Keep this finite,
# hash-pinned exception list explicit instead of silently preferring a source.
LABEL_CONFLICT_RESOLUTIONS = {
    "c46f8e3666200bb34949e7fae688a602432ff9e21c1394e31941657355b10b09": "Crosswalk",
    "b11e1895a5562b14a4762bd930e6a5c1f16c43ba15d9e95683f1ca4403b5403a": "Crosswalk",
    "1e77ce2739907ffc7b6fdf6c971b1af39f31400b454c953801b705ed43fe2aab": "Crosswalk",
    "c5428da8ecbacae988c90f3391830c067807dafe4f73aa595de8b6b7c38cdb10": "Motorcycle",
    "1fad7d771f9f9a478032815b9ac7415a1a282be70a6ca4ca0fe2319b0c6adfda": "Stair",
    "717ae967c7f425e269ca48163665f70ddbbe3beb32414bae393856ae1038309b": "Tractor",
    "a89d5dc2134183e1c104c043e664cdc2098fbf811a9f129f3a05d00744420813": "Traffic Light",
    "c58c969154e016568078164ae24056d6aaa5bd6dbde077a60b20aa7f4b012464": "Traffic Light",
}
_CONFLICT_REVIEW_EVIDENCE = "independent visual review of both exact source copies"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _image_digests(path: Path) -> tuple[str, str, str]:
    """Return raw-byte, normalized-pixel, and exact perceptual digests."""

    raw_digest = _sha256_bytes(path.read_bytes())
    try:
        with Image.open(path) as image:
            normalized = image.convert("RGB").resize(NORMALIZED_SIZE)
            pixel_digest = _sha256_bytes(normalized.tobytes())
            gray = normalized.convert("L").resize((9, 8))
            pixels = list(gray.get_flattened_data())
    except Exception as exc:
        raise ValueError(f"Unreadable training image: {path}") from exc
    bits = 0
    for row in range(8):
        for col in range(8):
            bits = (bits << 1) | (pixels[row * 9 + col] < pixels[row * 9 + col + 1])
    return raw_digest, pixel_digest, f"{bits:016x}"


def _canonical_origin(path: Path) -> str:
    """Normalize known original/Roboflow derivative filename relationships."""

    stem = path.stem.lower()
    stem = re.sub(r"\.rf\.[^.]+$", "", stem)
    stem = re.sub(r"\((\d+)\)", r"-\1", stem)
    stem = re.sub(r"[-_]+(?:jpg|jpeg|png)$", "", stem)
    stem = re.sub(r"[^a-z0-9]+", "-", stem).strip("-")
    return stem


def _records_from_roots(
    roots: Iterable[Path],
    role: str,
    allowed_labels: set[str] | None = None,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    records: list[dict[str, str]] = []
    excluded_classes: list[dict[str, str]] = []
    for source_index, root in enumerate(roots):
        root = root.resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"{role} dataset does not exist: {root}")
        classes = sorted(path.name for path in root.iterdir() if path.is_dir())
        if not classes:
            raise ValueError(f"{role} dataset has no class directories: {root}")
        for label in classes:
            if allowed_labels is not None and label not in allowed_labels:
                excluded_classes.append(
                    {
                        "source": str(root),
                        "label": label,
                        "reason": "unsupported_class",
                    }
                )
                continue
            for path in sorted((root / label).iterdir()):
                if not path.is_file() or path.suffix.lower() not in IMAGE_SUFFIXES:
                    continue
                raw_digest, pixel_digest, perceptual_digest = _image_digests(path)
                records.append(
                    {
                        "path": str(path.resolve()),
                        "label": label,
                        "source": str(root),
                        "source_index": str(source_index),
                        "raw_sha256": raw_digest,
                        "pixel_sha256": pixel_digest,
                        "dhash": perceptual_digest,
                        "origin_key": _canonical_origin(path),
                    }
                )
    return records, excluded_classes


def _deduplicate(
    records: list[dict[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Keep one exact-pixel sample and report excluded duplicate provenance.

    dHash is retained in the manifest for audit/optional review, but is not a
    deletion criterion: visually simple, legitimately distinct tiles can
    share a perceptual hash and must never be silently discarded.
    """

    selected: list[dict[str, str]] = []
    excluded: list[dict[str, str]] = []
    by_pixel: dict[str, dict[str, str]] = {}
    for record in records:
        duplicate = by_pixel.get(record["pixel_sha256"])
        if duplicate is None:
            by_pixel[record["pixel_sha256"]] = record
            selected.append(record)
            continue
        if duplicate["label"] != record["label"]:
            resolution = LABEL_CONFLICT_RESOLUTIONS.get(record["pixel_sha256"])
            if resolution in {duplicate["label"], record["label"]}:
                chosen, superseded = (
                    (duplicate, record)
                    if duplicate["label"] == resolution
                    else (record, duplicate)
                )
                if chosen is record:
                    selected.remove(duplicate)
                    selected.append(record)
                    by_pixel[record["pixel_sha256"]] = record
                excluded.append(
                    {
                        "path": superseded["path"],
                        "label": superseded["label"],
                        "duplicate_of": chosen["path"],
                        "reason": "superseded_conflicting_label",
                        "resolved_label": resolution,
                        "reviewer_evidence": _CONFLICT_REVIEW_EVIDENCE,
                    }
                )
                continue
            raise ValueError(
                "Conflicting labels for duplicate reCAPTCHA tiles: "
                f"{duplicate['path']} and {record['path']}"
            )
        excluded.append(
            {
                "path": record["path"],
                "label": record["label"],
                "duplicate_of": duplicate["path"],
                "reason": "pixel_sha256",
            }
        )
    return selected, excluded


def _split_key(record: dict[str, str], seed: int) -> str:
    value = f"{seed}:{record['label']}:{record['pixel_sha256']}:{record['raw_sha256']}"
    return _sha256_bytes(value.encode())


def build_manifest(
    data_roots: Iterable[Path],
    heldout_roots: Iterable[Path] = (),
    *,
    validation_fraction: float = 0.1,
    seed: int = 20260726,
) -> dict:
    """Build deterministic train/validation/held-out records with no overlap."""

    if not 0 < validation_fraction < 1:
        raise ValueError("validation_fraction must be between zero and one")
    data_roots = tuple(Path(root) for root in data_roots)
    heldout_roots = tuple(Path(root) for root in heldout_roots)
    if not data_roots:
        raise ValueError("At least one training dataset is required")
    primary_root = data_roots[0].resolve()
    if not primary_root.is_dir():
        raise FileNotFoundError(f"training dataset does not exist: {primary_root}")
    training_labels = sorted(
        path.name for path in primary_root.iterdir() if path.is_dir()
    )
    if not training_labels:
        raise ValueError(f"training dataset has no class directories: {primary_root}")
    source_records, excluded_classes = _records_from_roots(
        data_roots, "training", set(training_labels)
    )
    data_records, duplicate_records = _deduplicate(source_records)
    if heldout_roots:
        heldout_source_records, heldout_unsupported = _records_from_roots(
            heldout_roots, "held-out", set(training_labels)
        )
        if heldout_unsupported:
            raise ValueError("Held-out dataset contains unsupported classes")
        heldout_records, heldout_duplicates = _deduplicate(heldout_source_records)
    else:
        heldout_records, heldout_duplicates = [], []
    training_hashes = {record["pixel_sha256"] for record in data_records}
    heldout_hashes = {record["pixel_sha256"] for record in heldout_records}
    overlap = training_hashes & heldout_hashes
    if overlap:
        raise ValueError("Held-out images overlap training images")
    observed_training_labels = sorted({record["label"] for record in data_records})
    heldout_labels = sorted({record["label"] for record in heldout_records})
    if observed_training_labels != training_labels:
        raise ValueError("Training dataset is missing samples for a canonical class")
    if heldout_records and not set(heldout_labels).issubset(training_labels):
        raise ValueError("Held-out dataset contains unknown classes")

    totals = {
        label: sum(record["label"] == label for record in data_records)
        for label in training_labels
    }
    targets = {
        label: min(max(1, round(total * validation_fraction)), total - 1)
        for label, total in totals.items()
    }
    parents = list(range(len(data_records)))

    def find(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left, right):
        left, right = find(left), find(right)
        if left != right:
            parents[right] = left

    seen_dhash: dict[str, int] = {}
    seen_origin: dict[str, int] = {}
    for index, sample in enumerate(data_records):
        # dHash/origin are conservative leakage edges across the entire corpus,
        # including collisions between labels. They group samples; they never
        # remove samples or infer a label.
        for seen, key in (
            (seen_dhash, sample["dhash"]),
            (seen_origin, sample["origin_key"]),
        ):
            previous = seen.get(key)
            if previous is None:
                seen[key] = index
            else:
                union(index, previous)
    groups: dict[int, list[dict[str, str]]] = defaultdict(list)
    for index, sample in enumerate(data_records):
        groups[find(index)].append(sample)
    ordered_groups = sorted(
        groups.values(),
        key=lambda group: min(_split_key(sample, seed) for sample in group),
    )
    validation: list[dict[str, str]] = []
    validation_counts = {label: 0 for label in training_labels}
    for group in ordered_groups:
        group_counts = {
            label: sum(sample["label"] == label for sample in group)
            for label in training_labels
        }
        candidate = {
            label: validation_counts[label] + group_counts[label]
            for label in training_labels
        }
        if any(candidate[label] >= totals[label] for label in training_labels):
            continue
        current_error = sum(
            abs(validation_counts[label] - targets[label]) for label in training_labels
        )
        candidate_error = sum(
            abs(candidate[label] - targets[label]) for label in training_labels
        )
        if candidate_error < current_error:
            validation.extend(group)
            validation_counts = candidate
    validation_paths = {sample["path"] for sample in validation}
    train = [
        sample for sample in data_records if sample["path"] not in validation_paths
    ]
    if not train or not validation:
        raise ValueError("Split requires non-empty train and validation sets")
    for label in training_labels:
        if not any(record["label"] == label for record in train):
            raise ValueError(f"Train split is missing class: {label}")
        if not any(record["label"] == label for record in validation):
            raise ValueError(f"Validation split is missing class: {label}")

    def overlap(left, right, field):
        return {record[field] for record in left} & {record[field] for record in right}

    for field in ("pixel_sha256", "dhash", "origin_key"):
        if overlap(train, validation, field):
            raise ValueError(f"Train/validation {field} overlap")
        if overlap(train + validation, heldout_records, field):
            raise ValueError(f"Held-out {field} overlap with train/validation")

    manifest = {
        "schema_version": 1,
        "seed": seed,
        "validation_fraction": validation_fraction,
        "classes": training_labels,
        "splits": {
            "train": sorted(train, key=lambda item: item["path"]),
            "validation": sorted(validation, key=lambda item: item["path"]),
            "heldout": sorted(heldout_records, key=lambda item: item["path"]),
        },
        "excluded_duplicates": sorted(
            duplicate_records + heldout_duplicates,
            key=lambda item: item["path"],
        ),
        "excluded_unsupported_classes": sorted(
            excluded_classes, key=lambda item: (item["source"], item["label"])
        ),
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["manifest_sha256"] = _sha256_bytes(canonical)
    return manifest


def write_manifest(manifest: dict, path: Path) -> None:
    """Durably write a reviewed manifest with stable formatting."""

    atomic_write_json(path, manifest)
