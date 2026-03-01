"""Batch-predict CLS tiles using the wafer ONNX model.

Reads collected_cls/metadata.jsonl, runs inference on tiles missing predictions,
and rewrites metadata.jsonl with predicted_class, confidence, and top3.

Usage:
    uv run python training/recaptcha/predict_cls.py [--collected PATH]
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path

import numpy as np
from PIL import Image

_SCRIPT_DIR = Path(__file__).resolve().parent
_DEFAULT_COLLECTED = _SCRIPT_DIR / "collected_cls"

CLS_NAMES = [
    "Bicycle", "Bridge", "Bus", "Car", "Chimney", "Crosswalk",
    "Hydrant", "Motorcycle", "Mountain", "Other", "Palm",
    "Stair", "Tractor", "Traffic Light",
]

IMG_SIZE = 224
MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32)
STD = np.array([0.229, 0.224, 0.225], dtype=np.float32)
BATCH_SIZE = 64


def _load_model():
    import onnxruntime as ort
    from huggingface_hub import hf_hub_download

    path = hf_hub_download("Averyyyyyy/wafer-models", "wafer_cls_s.onnx")
    sess = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
    input_name = sess.get_inputs()[0].name
    return sess, input_name


def _preprocess(img: Image.Image) -> np.ndarray:
    img = img.convert("RGB").resize((IMG_SIZE, IMG_SIZE), Image.BILINEAR)
    arr = np.array(img, dtype=np.float32) / 255.0
    arr = (arr - MEAN) / STD
    return arr.transpose(2, 0, 1)  # HWC -> CHW


def _softmax(logits: np.ndarray) -> np.ndarray:
    e = np.exp(logits - logits.max(axis=1, keepdims=True))
    return e / e.sum(axis=1, keepdims=True)


def main():
    parser = argparse.ArgumentParser(description="Batch predict CLS tiles")
    parser.add_argument("--collected", default=str(_DEFAULT_COLLECTED))
    args = parser.parse_args()

    collected = Path(args.collected)
    meta_path = collected / "metadata.jsonl"
    if not meta_path.is_file():
        print(f"No metadata.jsonl in {collected}")
        sys.exit(1)

    # Load all entries
    entries = []
    with open(meta_path) as f:
        for line in f:
            entries.append(json.loads(line))

    # Find entries needing prediction
    need_pred = []
    for i, entry in enumerate(entries):
        if entry.get("predicted_class"):
            continue
        img_path = collected / entry["file"]
        if not img_path.is_file():
            continue
        need_pred.append((i, img_path))

    if not need_pred:
        print("All tiles already have predictions.")
        return

    print(f"Loading model...")
    sess, input_name = _load_model()

    print(f"Running inference on {len(need_pred)} tiles (batch={BATCH_SIZE})...")
    processed = 0

    for batch_start in range(0, len(need_pred), BATCH_SIZE):
        batch = need_pred[batch_start:batch_start + BATCH_SIZE]
        images = []
        valid = []

        for idx, img_path in batch:
            try:
                img = Image.open(img_path)
                images.append(_preprocess(img))
                valid.append(idx)
            except Exception as e:
                print(f"  Skip {img_path.name}: {e}")

        if not images:
            continue

        blob = np.stack(images, axis=0).astype(np.float32)
        logits = sess.run(None, {input_name: blob})[0]
        probs = _softmax(logits)

        for j, idx in enumerate(valid):
            p = probs[j]
            top3_idx = p.argsort()[::-1][:3]
            top3 = [(CLS_NAMES[k], round(float(p[k]), 4)) for k in top3_idx]
            pred_idx = int(top3_idx[0])

            entries[idx]["predicted_class"] = CLS_NAMES[pred_idx]
            entries[idx]["predicted_index"] = pred_idx
            entries[idx]["confidence"] = top3[0][1]
            entries[idx]["top3"] = top3

        processed += len(valid)
        if processed % 500 == 0 or batch_start + BATCH_SIZE >= len(need_pred):
            print(f"  {processed}/{len(need_pred)} done")

    # Atomic rewrite
    tmp = tempfile.NamedTemporaryFile(
        mode="w", dir=collected, suffix=".jsonl", delete=False,
    )
    try:
        for entry in entries:
            tmp.write(json.dumps(entry) + "\n")
        tmp.close()
        Path(tmp.name).replace(meta_path)
    except Exception:
        Path(tmp.name).unlink(missing_ok=True)
        raise

    print(f"Done. Updated {processed} entries in metadata.jsonl")


if __name__ == "__main__":
    main()
