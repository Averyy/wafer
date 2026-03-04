"""Manual dedup for collected_cls tiles.

Finds duplicates within collected_cls (intra-set) and against
the classic dataset directory (cross-set).

Uses multiple hash types to find candidates, then verifies with pixel
comparison to eliminate false positives. This catches dupes that single-hash
exact matching misses (different JPEG quality, off-by-1px crops).

Approach:
  1. Compute dHash (64-bit + 256-bit) and pHash (64-bit DCT-based) per image
  2. Cast a wide net: any pair within hamming threshold on ANY hash is a candidate
  3. Verify each candidate with mean absolute pixel difference (MAD)
  4. MAD < 20 on normalized 100x100 = confirmed duplicate

Dry run by default. Use --delete to actually remove duplicates.

Usage:
    .venv/bin/python manual_dedup.py
    .venv/bin/python manual_dedup.py --mad-threshold 15
    .venv/bin/python manual_dedup.py --gallery
    .venv/bin/python manual_dedup.py --delete
"""

import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
from PIL import Image
from scipy.fftpack import dct  # type: ignore[import-not-found]

_SCRIPT_DIR = Path(__file__).resolve().parent
_COLLECTED_CLS = _SCRIPT_DIR / "collected_cls"
_NORM_SIZE = (100, 100)

_POPCOUNT_LUT = np.array([bin(i).count("1") for i in range(256)], dtype=np.uint8)


# ---------------------------------------------------------------------------
# Hash functions
# ---------------------------------------------------------------------------

def _pixhash(img: Image.Image) -> str:
    """SHA256 of normalized pixel data - exact match only."""
    norm = img.convert("RGB").resize(_NORM_SIZE, 1)
    return hashlib.sha256(norm.tobytes()).hexdigest()


def _dhash(img: Image.Image, hash_size: int = 8) -> int:
    """Difference hash - captures horizontal gradient structure."""
    small = img.convert("L").resize((hash_size + 1, hash_size), 1)
    pixels = list(small.getdata())
    w = hash_size + 1
    bits = 0
    for row in range(hash_size):
        for col in range(hash_size):
            bits = (bits << 1) | (pixels[row * w + col] < pixels[row * w + col + 1])
    return bits


def _phash(img: Image.Image, hash_size: int = 8, highfreq_factor: int = 4) -> int:
    """Perceptual hash - DCT-based, more robust to JPEG and crops than dHash."""
    img_size = hash_size * highfreq_factor  # 32x32 default
    small = img.convert("L").resize((img_size, img_size), 1)
    pixels = np.array(small, dtype=np.float64)
    dct_result = dct(dct(pixels, axis=0), axis=1)
    dct_low = dct_result[:hash_size, :hash_size]
    med = np.median(dct_low)
    bits = 0
    for val in dct_low.flatten():
        bits = (bits << 1) | (val > med)
    return bits


def _to_pixels(img: Image.Image) -> np.ndarray:
    """Normalized 100x100 RGB pixel array for MAD comparison."""
    return np.array(img.convert("RGB").resize(_NORM_SIZE, 1), dtype=np.float32)


def _mad(a: np.ndarray, b: np.ndarray) -> float:
    """Mean absolute pixel difference."""
    return float(np.abs(a - b).mean())


# ---------------------------------------------------------------------------
# Vectorized hamming
# ---------------------------------------------------------------------------

def _hamming_batch_64(hashes: np.ndarray, query: int) -> np.ndarray:
    xored = np.bitwise_xor(hashes, np.uint64(query))
    byte_view = xored.view(np.uint8).reshape(-1, 8)
    return _POPCOUNT_LUT[byte_view].sum(axis=1)


def _dhash_256_to_bytes(h: int) -> np.ndarray:
    return np.frombuffer(h.to_bytes(32, "big"), dtype=np.uint8)


def _hamming_batch_256(hashes_bytes: np.ndarray, query_bytes: np.ndarray) -> np.ndarray:
    xored = np.bitwise_xor(hashes_bytes, query_bytes)
    return _POPCOUNT_LUT[xored].sum(axis=1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Multi-hash dedup for collected_cls")
    parser.add_argument(
        "--dh64-threshold", type=int, default=12,
        help="Hamming threshold for 64-bit dHash candidates (default: 12)",
    )
    parser.add_argument(
        "--dh256-threshold", type=int, default=30,
        help="Hamming threshold for 256-bit dHash candidates (default: 30)",
    )
    parser.add_argument(
        "--ph64-threshold", type=int, default=12,
        help="Hamming threshold for 64-bit pHash candidates (default: 12)",
    )
    parser.add_argument(
        "--mad-threshold", type=float, default=20.0,
        help="Max mean absolute pixel diff to confirm as duplicate (default: 20.0)",
    )
    parser.add_argument(
        "--gallery", action="store_true",
        help="Save side-by-side gallery of confirmed dupes to /tmp/dedup_gallery.png",
    )
    parser.add_argument(
        "--delete", action="store_true",
        help="Delete confirmed duplicates (keeps earlier file)",
    )
    args = parser.parse_args()

    # ---------------------------------------------------------------
    # Hash all collected tiles
    # ---------------------------------------------------------------
    files = sorted(_COLLECTED_CLS.glob("*.jpg"))
    total_files = len(files)
    print(f"Hashing {total_files} collected tiles (dHash64 + dHash256 + pHash64)...")

    fnames: list[str] = []
    pixels_cache: list[np.ndarray] = []
    dh64_list: list[int] = []
    dh256_list: list[int] = []
    ph64_list: list[int] = []

    t0 = time.monotonic()
    for i, p in enumerate(files):
        try:
            img = Image.open(p)
            fnames.append(p.name)
            pixels_cache.append(_to_pixels(img))
            dh64_list.append(_dhash(img, hash_size=8))
            dh256_list.append(_dhash(img, hash_size=16))
            ph64_list.append(_phash(img, hash_size=8))
        except Exception as e:
            print(f"  Skip {p.name}: {e}")
            continue
        if (i + 1) % 5000 == 0:
            print(f"  {i + 1}/{total_files} ({time.monotonic() - t0:.1f}s)")

    n = len(fnames)
    elapsed = time.monotonic() - t0
    print(f"  Done: {n} tiles hashed in {elapsed:.1f}s ({n / elapsed:.0f}/s)\n")

    dh64_arr = np.array(dh64_list, dtype=np.uint64)
    ph64_arr = np.array(ph64_list, dtype=np.uint64)
    dh256_bytes = np.array([_dhash_256_to_bytes(h) for h in dh256_list], dtype=np.uint8)

    # ---------------------------------------------------------------
    # Find intra-set candidates via any hash, verify with pixels
    # ---------------------------------------------------------------
    print("Scanning for intra-set duplicates...")
    print(f"  Hash thresholds: dHash64<={args.dh64_threshold}, "
          f"dHash256<={args.dh256_threshold}, pHash64<={args.ph64_threshold}")
    print(f"  Pixel verification: MAD < {args.mad_threshold}\n")

    confirmed: list[tuple[str, str, float, str]] = []  # (file_a, file_b, mad, method)
    candidates_total = 0
    already_duped: set[int] = set()  # indices already flagged

    t0 = time.monotonic()
    for i in range(1, n):
        if i in already_duped:
            continue

        best_match_idx = -1
        best_mad = 999.0
        best_method = ""

        # Collect candidate indices from all three hash types
        candidate_indices: set[int] = set()

        # dHash64
        dists = _hamming_batch_64(dh64_arr[:i], dh64_list[i])
        for idx in np.where(dists <= args.dh64_threshold)[0]:
            if int(idx) not in already_duped:
                candidate_indices.add(int(idx))

        # pHash64
        dists = _hamming_batch_64(ph64_arr[:i], ph64_list[i])
        for idx in np.where(dists <= args.ph64_threshold)[0]:
            if int(idx) not in already_duped:
                candidate_indices.add(int(idx))

        # dHash256
        dists = _hamming_batch_256(dh256_bytes[:i], dh256_bytes[i])
        for idx in np.where(dists <= args.dh256_threshold)[0]:
            if int(idx) not in already_duped:
                candidate_indices.add(int(idx))

        candidates_total += len(candidate_indices)

        # Verify each candidate with pixel MAD
        for idx in candidate_indices:
            m = _mad(pixels_cache[i], pixels_cache[idx])
            if m < best_mad:
                best_mad = m
                best_match_idx = idx
                # Figure out which hash(es) flagged it
                d_dh64 = bin(dh64_list[i] ^ dh64_list[idx]).count("1")
                d_ph64 = bin(ph64_list[i] ^ ph64_list[idx]).count("1")
                methods = []
                if d_dh64 <= args.dh64_threshold:
                    methods.append(f"dH64={d_dh64}")
                if d_ph64 <= args.ph64_threshold:
                    methods.append(f"pH64={d_ph64}")
                best_method = "+".join(methods) if methods else "dH256"

        if best_match_idx >= 0 and best_mad < args.mad_threshold:
            confirmed.append((fnames[i], fnames[best_match_idx], best_mad, best_method))
            already_duped.add(i)

        if (i + 1) % 2000 == 0:
            elapsed = time.monotonic() - t0
            print(f"  {i + 1}/{n} ({elapsed:.1f}s) - "
                  f"{len(confirmed)} confirmed, {candidates_total} candidates checked")

    elapsed = time.monotonic() - t0
    print(f"  Done in {elapsed:.1f}s\n")

    # ---------------------------------------------------------------
    # Cross-set: compare collected_cls against classic dataset
    # ---------------------------------------------------------------
    _CLASSIC_DIR = _SCRIPT_DIR / "datasets" / "wafer_cls_classic"
    # (collected_file, classic_file, mad)
    cross_confirmed: list[tuple[str, str, float]] = []

    if _CLASSIC_DIR.is_dir():
        print("Scanning for cross-set duplicates (collected vs classic)...")
        classic_files = [
            p for p in _CLASSIC_DIR.rglob("*")
            if p.suffix.lower() in (".jpg", ".jpeg", ".png")
        ]
        print(f"  Hashing {len(classic_files)} classic tiles...")

        cls_dh64: list[int] = []
        cls_ph64: list[int] = []
        cls_pixels: list[np.ndarray] = []
        cls_names: list[str] = []

        t0 = time.monotonic()
        for i, p in enumerate(classic_files):
            try:
                img = Image.open(p)
                cls_dh64.append(_dhash(img, hash_size=8))
                cls_ph64.append(_phash(img, hash_size=8))
                cls_pixels.append(_to_pixels(img))
                cls_names.append(str(p.relative_to(_CLASSIC_DIR)))
            except Exception:
                continue
            if (i + 1) % 10000 == 0:
                el = time.monotonic() - t0
                print(f"    {i+1}/{len(classic_files)} ({el:.1f}s)")

        nc = len(cls_names)
        print(f"  Done: {nc} classic tiles in {time.monotonic() - t0:.1f}s")

        if nc > 0:
            cls_dh64_arr = np.array(cls_dh64, dtype=np.uint64)
            cls_ph64_arr = np.array(cls_ph64, dtype=np.uint64)

            t0 = time.monotonic()
            for i in range(n):
                if i in already_duped:
                    continue

                # Check dHash64 + pHash64 against classic
                dh_dists = _hamming_batch_64(cls_dh64_arr, dh64_list[i])
                ph_dists = _hamming_batch_64(cls_ph64_arr, ph64_list[i])
                candidates = np.where(
                    (dh_dists <= args.dh64_threshold)
                    & (ph_dists <= args.ph64_threshold)
                )[0]

                for idx in candidates:
                    m = _mad(pixels_cache[i], cls_pixels[idx])
                    if m < args.mad_threshold:
                        cross_confirmed.append((fnames[i], cls_names[idx], m))
                        already_duped.add(i)
                        break

                if (i + 1) % 5000 == 0:
                    print(f"    {i + 1}/{n} ({time.monotonic() - t0:.1f}s) - "
                          f"{len(cross_confirmed)} cross-set dupes")

            print(f"  Cross-set dupes: {len(cross_confirmed)}\n")
    else:
        print(f"Classic not found at {_CLASSIC_DIR}, skipping.\n")

    total_dupes = len(confirmed) + len(cross_confirmed)

    # ---------------------------------------------------------------
    # Results
    # ---------------------------------------------------------------
    print(f"{'='*70}")
    print("RESULTS")
    print(f"{'='*70}")
    print(f"  Total tiles:           {n}")
    print(f"  Candidates checked:    {candidates_total}")
    print(f"  Intra-set duplicates:  {len(confirmed)}")
    print(f"  Cross-set duplicates:  {len(cross_confirmed)}")
    print(f"  Total duplicates:      {total_dupes}")
    print(f"  MAD threshold:         {args.mad_threshold}")
    print()

    # Distribution by MAD
    if confirmed:
        mads = [c[2] for c in confirmed]
        print("  MAD distribution of confirmed dupes:")
        for lo, hi in [(0, 5), (5, 10), (10, 15), (15, 20)]:
            count = sum(1 for m in mads if lo <= m < hi)
            print(f"    MAD {lo:>2}-{hi:<2}: {count:>5}")
        print()

        # Distribution by detection method
        from collections import Counter
        method_counts = Counter()
        for _, _, _, method in confirmed:
            for m in method.split("+"):
                key = m.split("=")[0]
                method_counts[key] += 1
        print("  Detection method contribution:")
        for method, count in method_counts.most_common():
            print(f"    {method}: {count}")
        print()

        # Which dupes are ONLY caught by pHash (not dHash)?
        phash_only = [
            c for c in confirmed
            if "dH64" not in c[3] and "dH256" not in c[3]
        ]
        print(f"  Caught ONLY by pHash (not dHash): {len(phash_only)}")

        # Which dupes are ONLY caught by dHash256 (not dHash64 or pHash)?
        dh256_only = [c for c in confirmed if c[3] == "dH256"]
        print(f"  Caught ONLY by dHash256:          {len(dh256_only)}")
        print()

    # Print all confirmed dupes
    print(f"{'='*70}")
    print("ALL CONFIRMED DUPLICATES (intra-set)")
    print(f"{'='*70}")
    for fa, fb, mad_val, method in sorted(confirmed, key=lambda x: x[2]):
        print(f"  MAD={mad_val:>5.1f}  [{method:<20}]  {fa}  ~  {fb}")

    if cross_confirmed:
        print(f"\n{'='*70}")
        print("CROSS-SET DUPLICATES (collected vs classic)")
        print(f"{'='*70}")
        for fa, fb, mad_val in sorted(cross_confirmed, key=lambda x: x[2]):
            print(f"  MAD={mad_val:>5.1f}  {fa}  ~  classic:{fb}")

    # ---------------------------------------------------------------
    # Gallery
    # ---------------------------------------------------------------
    if args.gallery and confirmed:
        print(f"\nBuilding gallery of {len(confirmed)} confirmed dupes...")
        tile_size = 120
        gap = 6
        cols_per_row = 4  # 4 pairs per row
        pair_w = tile_size * 2 + gap
        pairs_per_row = cols_per_row
        num_rows = (len(confirmed) + pairs_per_row - 1) // pairs_per_row
        canvas_w = pairs_per_row * (pair_w + gap * 2) + gap
        canvas_h = num_rows * (tile_size + 20 + gap) + gap

        canvas = Image.new("RGB", (canvas_w, canvas_h), (255, 255, 255))
        from PIL import ImageDraw
        draw = ImageDraw.Draw(canvas)

        sorted_dupes = sorted(confirmed, key=lambda x: x[2])
        for idx, (fa, fb, mad_val, method) in enumerate(sorted_dupes):
            row = idx // pairs_per_row
            col = idx % pairs_per_row
            x = gap + col * (pair_w + gap * 2)
            y = gap + row * (tile_size + 20 + gap)

            sz = (tile_size, tile_size)
            a = Image.open(_COLLECTED_CLS / fa).convert("RGB").resize(sz, 1)
            b = Image.open(_COLLECTED_CLS / fb).convert("RGB").resize(sz, 1)
            canvas.paste(a, (x, y))
            canvas.paste(b, (x + tile_size + gap, y))
            draw.text((x, y + tile_size + 2), f"MAD={mad_val:.1f}", fill=(0, 0, 0))

        out = Path("/tmp/dedup_gallery.png")
        canvas.save(out)
        print(f"  Saved to {out}")

    # ---------------------------------------------------------------
    # Delete
    # ---------------------------------------------------------------
    if args.delete and total_dupes > 0:
        # Collect all files to delete from collected_cls (never classic)
        # Intra-set: delete the later file (file_a), keep the earlier (file_b)
        to_delete: set[str] = {fa for fa, fb, _, _ in confirmed}
        # Cross-set: delete the collected file (it's a dupe of classic)
        to_delete |= {fa for fa, fb, _ in cross_confirmed}

        print(f"\nDeleting {len(to_delete)} duplicate files from {_COLLECTED_CLS}...")
        deleted = 0
        for fname in to_delete:
            p = _COLLECTED_CLS / fname
            if p.is_file():
                p.unlink()
                deleted += 1
        print(f"  Deleted {deleted} files.")

        # Clean metadata.jsonl
        meta = _COLLECTED_CLS / "metadata.jsonl"
        if meta.is_file():
            lines = meta.read_text().splitlines()
            kept = []
            removed = 0
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("file") in to_delete:
                        removed += 1
                        continue
                except Exception:
                    pass
                kept.append(line)
            meta.write_text("\n".join(kept) + "\n" if kept else "")
            print(f"  Removed {removed} entries from metadata.jsonl.")
    elif args.delete:
        print("\nNo duplicates to delete.")


if __name__ == "__main__":
    main()
