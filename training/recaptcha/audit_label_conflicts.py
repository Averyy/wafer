"""Produce an evidence manifest for conflicting exact duplicate labels."""

import argparse
import json
import os
from pathlib import Path

import numpy as np
import onnxruntime as ort
from dataset_manifest import _records_from_roots
from PIL import Image
from predict_cls import CLS_NAMES, MEAN, STD


def _predict(model, path: str) -> list[dict[str, float | str]]:
    with Image.open(path) as image:
        array = np.asarray(
            image.convert("RGB").resize((224, 224), Image.Resampling.BILINEAR),
            dtype=np.float32,
        ) / 255.0
    input_tensor = ((array - MEAN) / STD).transpose(2, 0, 1)[None]
    input_name = model.get_inputs()[0].name
    logits = model.run(None, {input_name: input_tensor})[0][0]
    probabilities = np.exp(logits - logits.max())
    probabilities /= probabilities.sum()
    return [
        {"label": CLS_NAMES[index], "score": round(float(probabilities[index]), 6)}
        for index in np.argsort(probabilities)[::-1][:3]
    ]


def _provenance(record: dict[str, str]) -> dict[str, str | int]:
    stat = os.stat(record["path"])
    return {
        "path": record["path"],
        "source": record["source"],
        "label": record["label"],
        "raw_sha256": record["raw_sha256"],
        "pixel_sha256": record["pixel_sha256"],
        "dhash": record["dhash"],
        "mtime_ns": stat.st_mtime_ns,
        "size_bytes": stat.st_size,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--extra", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    base, _ = _records_from_roots([args.base], "base")
    extra, _ = _records_from_roots([args.extra], "extra")
    by_pixel = {record["pixel_sha256"]: record for record in base}
    conflicts = [
        (by_pixel[record["pixel_sha256"]], record)
        for record in extra
        if record["pixel_sha256"] in by_pixel
        and by_pixel[record["pixel_sha256"]]["label"] != record["label"]
    ]
    model = ort.InferenceSession(str(args.model), providers=["CPUExecutionProvider"])
    evidence = []
    for base_record, extra_record in conflicts:
        evidence.append(
            {
                "base": _provenance(base_record),
                "extra": _provenance(extra_record),
                "model_top3": _predict(model, base_record["path"]),
                "resolution": None,
            }
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {len(evidence)} conflicting-label records to {args.output}")


if __name__ == "__main__":
    main()
