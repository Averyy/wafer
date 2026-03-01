"""Offline dedup for collected reCAPTCHA CLS tiles.

Commands:
    build-index  Build dedup index from existing dataset (pixel hashes + dHash).
    dedup        Remove tiles from datasets/wafer_cls/ that match existing dataset.

Usage:
    python dedup.py build-index [--dataset PATH]
    python dedup.py dedup [--wafer-cls PATH] [--index PATH]
"""

import argparse
import hashlib
import pickle
import sys
from pathlib import Path

# Default paths
_SCRIPT_DIR = Path(__file__).resolve().parent
_DEFAULT_DATASET = _SCRIPT_DIR / "datasets" / "wafer_cls_classic"
_DEFAULT_WAFER_CLS = _SCRIPT_DIR / "datasets" / "wafer_cls"
_DEFAULT_INDEX = _SCRIPT_DIR / "dedup_index.pkl"

# Canonical size for pixel-level comparison
_NORM_SIZE = (100, 100)


def _pixhash(img) -> str:
    """SHA256 of normalized pixel data. Catches identical images regardless
    of file format, JPEG quality, or resolution."""
    norm = img.convert("RGB").resize(_NORM_SIZE, 1)
    return hashlib.sha256(norm.tobytes()).hexdigest()


def _dhash(img, hash_size: int = 8) -> int:
    """64-bit perceptual difference hash for near-duplicate detection."""
    small = img.convert("L").resize((hash_size + 1, hash_size), 1)
    pixels = list(small.getdata())
    w = hash_size + 1
    bits = 0
    for row in range(hash_size):
        for col in range(hash_size):
            bits = (bits << 1) | (pixels[row * w + col] < pixels[row * w + col + 1])
    return bits


def _hamming(a: int, b: int) -> int:
    """Count differing bits between two integers."""
    return bin(a ^ b).count("1")


def cmd_build_index(args: argparse.Namespace) -> None:
    from PIL import Image

    dataset = Path(args.dataset)
    if not dataset.is_dir():
        print(f"Dataset not found: {dataset}")
        sys.exit(1)

    pixel_hashes: set[str] = set()
    dhashes: list[int] = []
    count = 0
    for cls_dir in sorted(dataset.iterdir()):
        if not cls_dir.is_dir():
            continue
        for img_path in sorted(cls_dir.iterdir()):
            if img_path.suffix.lower() not in (".jpg", ".jpeg", ".png"):
                continue
            try:
                img = Image.open(img_path)
                pixel_hashes.add(_pixhash(img))
                dhashes.append(_dhash(img))
                count += 1
                if count % 1000 == 0:
                    print(f"  Indexed {count} images...")
            except Exception as e:
                print(f"  Skip {img_path}: {e}")

    out = Path(args.index)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "wb") as f:
        pickle.dump(
            {"pixel_hashes": pixel_hashes, "dhashes": dhashes}, f,
        )
    unique = len(pixel_hashes)
    print(f"Built index: {count} images ({unique} unique) -> {out}")


def cmd_dedup(args: argparse.Namespace) -> None:
    wafer_cls = Path(args.wafer_cls)
    index_path = Path(args.index)

    if not wafer_cls.is_dir():
        print(f"wafer_cls dir not found: {wafer_cls}")
        sys.exit(1)
    if not index_path.is_file():
        print(f"Index not found: {index_path}")
        print("Run `python dedup.py build-index` first.")
        sys.exit(1)

    from PIL import Image

    with open(index_path, "rb") as f:
        index = pickle.load(f)

    pixel_hashes: set[str] = index["pixel_hashes"]
    dhashes: list[int] = index["dhashes"]
    dhash_set = set(dhashes)
    threshold = args.threshold
    exact_removed = 0
    near_removed = 0
    checked = 0

    for cls_dir in sorted(wafer_cls.iterdir()):
        if not cls_dir.is_dir():
            continue
        for img_path in sorted(cls_dir.iterdir()):
            if img_path.suffix.lower() not in (".jpg", ".jpeg", ".png"):
                continue
            checked += 1
            try:
                img = Image.open(img_path)

                # Tier 1: exact pixel match (fast, reliable)
                ph = _pixhash(img)
                if ph in pixel_hashes:
                    print(f"  Exact dup: {img_path.parent.name}/{img_path.name}")
                    img_path.unlink()
                    exact_removed += 1
                    continue

                # Tier 2: perceptual near-match via dHash
                dh = _dhash(img)
                name = f"{img_path.parent.name}/{img_path.name}"
                if dh in dhash_set:
                    print(f"  Near dup (exact dHash): {name}")
                    img_path.unlink()
                    near_removed += 1
                    continue
                for eh in dhashes:
                    d = _hamming(dh, eh)
                    if d <= threshold:
                        print(f"  Near dup (d={d}): {name}")
                        img_path.unlink()
                        near_removed += 1
                        break
            except Exception:
                pass

    total = exact_removed + near_removed
    print(
        f"Checked {checked}, removed {total} "
        f"({exact_removed} exact, {near_removed} near, "
        f"threshold={threshold})",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="reCAPTCHA CLS tile dedup")
    sub = parser.add_subparsers(dest="command")

    p_idx = sub.add_parser(
        "build-index", help="Build dedup index from dataset",
    )
    p_idx.add_argument("--dataset", default=str(_DEFAULT_DATASET))
    p_idx.add_argument("--index", default=str(_DEFAULT_INDEX))

    p_dup = sub.add_parser("dedup", help="Remove duplicates from wafer_cls tiles")
    p_dup.add_argument("--wafer-cls", default=str(_DEFAULT_WAFER_CLS))
    p_dup.add_argument("--index", default=str(_DEFAULT_INDEX))
    p_dup.add_argument("--threshold", type=int, default=4, help="Max hamming distance")

    args = parser.parse_args()
    if args.command == "build-index":
        cmd_build_index(args)
    elif args.command == "dedup":
        cmd_dedup(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
