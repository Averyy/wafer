"""Collect reCAPTCHA grid images from the Google demo page.

Runs browser workers that grab both 3x3 and 4x4 grids.
No model inference, no solving - just image + keyword collection.

3x3 grids are split into 9 individual 100x100 tiles on save
(ready for CLS annotation in Mousse). 4x4 grids are saved as
full images for DET annotation.

Headless by default, but Google may throttle headless after repeated
hits from the same IP (empty challenge frames). Use --headful if
headless stops getting challenges.

Usage:
    uv run python training/recaptcha/collect.py
    uv run python training/recaptcha/collect.py --workers 3
    uv run python training/recaptcha/collect.py --workers 3 --headful
"""

import argparse
import io
import json
import logging
import os
import random
import signal
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
from scipy.fftpack import dct  # type: ignore[import-not-found]

# Set collection env vars before importing wafer modules
os.environ.setdefault("WAFER_COLLECT_DET", "training/recaptcha/collected_det")
os.environ.setdefault("WAFER_COLLECT_CLS", "training/recaptcha/collected_cls")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(threadName)s]: %(message)s",
)
logger = logging.getLogger("collect")

DEMO_URL = "https://www.google.com/recaptcha/api2/demo"
PAGE_LOAD_TIMEOUT_MS = 15000
PAUSE_MIN = 0.5
PAUSE_MAX = 1.5
BACKOFF_SCHEDULE = [43200, 57600]  # 12h, 16h
MAX_AUTOPASSES = 1
MAX_GRIDS_PER_SESSION = 8  # reload within a session, then fresh browser
MAX_PAYLOAD_BYTES = 5 * 1024 * 1024

_RECAPTCHA_DOMAINS = frozenset({"google.com", "gstatic.com", "recaptcha.net"})

# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_stats = {
    "rounds": 0,
    "auto_pass": 0,
    "grids_3x3": 0,
    "grids_4x4": 0,
    "images_saved": 0,
    "tiles_saved": 0,
    "dupes_skipped": 0,
    "errors": 0,
}
_start_time = 0.0
_shutdown = threading.Event()


def _inc(**kw):
    with _lock:
        for k, v in kw.items():
            _stats[k] = _stats.get(k, 0) + v


def _print_stats():
    with _lock:
        s = dict(_stats)
    elapsed = time.monotonic() - _start_time
    mins = elapsed / 60
    total = s["images_saved"] + s["tiles_saved"]
    rate = total / mins if mins > 0 else 0
    logger.info(
        "rounds=%d | 3x3=%d(%d tiles) 4x4=%d | "
        "dupes=%d | auto=%d errors=%d | %.1f saved/min (%.0fs)",
        s["rounds"], s["grids_3x3"], s["tiles_saved"], s["grids_4x4"],
        s["dupes_skipped"],
        s["auto_pass"], s["errors"],
        rate, elapsed,
    )


# ---------------------------------------------------------------------------
# Dedup - dual hash (dHash + pHash) with pixel MAD verification
# ---------------------------------------------------------------------------

_DH_THRESHOLD = 12    # hamming distance for dHash64 candidates
_PH_THRESHOLD = 12    # hamming distance for pHash64 candidates
_MAD_THRESHOLD = 20.0  # max mean absolute pixel diff to confirm dupe
_NORM_SIZE = (100, 100)
_POPCOUNT_LUT = np.array(
    [bin(i).count("1") for i in range(256)], dtype=np.uint8,
)


def _dhash(img, hash_size: int = 8) -> int:
    small = img.convert("L").resize((hash_size + 1, hash_size), 1)
    get = getattr(small, "get_flattened_data", small.getdata)
    pixels = list(get())
    w = hash_size + 1
    bits = 0
    for row in range(hash_size):
        for col in range(hash_size):
            bits = (bits << 1) | int(
                pixels[row * w + col] < pixels[row * w + col + 1]
            )
    return bits


def _phash(img, hash_size: int = 8, highfreq_factor: int = 4) -> int:
    img_size = hash_size * highfreq_factor
    small = img.convert("L").resize((img_size, img_size), 1)
    pixels = np.array(small, dtype=np.float64)
    dct_result = dct(dct(pixels, axis=0), axis=1)
    dct_low = dct_result[:hash_size, :hash_size]
    med = np.median(dct_low)
    bits = 0
    for val in dct_low.flatten():
        bits = (bits << 1) | int(val > med)
    return bits


def _to_pixels(img) -> np.ndarray:
    return np.array(
        img.convert("RGB").resize(_NORM_SIZE, 1), dtype=np.float32,
    )


def _hamming_batch(hashes: np.ndarray, query: int, count: int):
    xored = np.bitwise_xor(hashes[:count], np.uint64(query))
    return _POPCOUNT_LUT[xored.view(np.uint8).reshape(-1, 8)].sum(
        axis=1,
    )


class DedupIndex:
    """Per-type dedup index with dual-hash + pixel MAD verification."""

    def __init__(self, name: str):
        self.name = name
        self._cap = 100_000
        self._dh = np.zeros(self._cap, dtype=np.uint64)
        self._ph = np.zeros(self._cap, dtype=np.uint64)
        self._paths: list[str] = []
        self._size = 0
        self._exact: set[int] = set()
        self._loaded = threading.Event()
        self._lock = threading.Lock()

    def _grow(self):
        new_cap = self._cap * 2
        new_dh = np.zeros(new_cap, dtype=np.uint64)
        new_ph = np.zeros(new_cap, dtype=np.uint64)
        new_dh[: self._cap] = self._dh
        new_ph[: self._cap] = self._ph
        self._dh = new_dh
        self._ph = new_ph
        self._cap = new_cap

    def add(self, dh: int, ph: int, path: str):
        if self._size >= self._cap:
            self._grow()
        self._dh[self._size] = np.uint64(dh)
        self._ph[self._size] = np.uint64(ph)
        self._paths.append(path)
        self._exact.add(dh)
        self._size += 1

    def _load_collected(self, collect_dir: str):
        """Load previously collected images from metadata.jsonl."""
        from PIL import Image
        meta = Path(collect_dir) / "metadata.jsonl"
        if not meta.is_file():
            return
        count = 0
        try:
            with open(meta) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    fname = entry.get("file")
                    dh = entry.get("dhash")
                    if dh is None or not fname:
                        continue
                    img_path = Path(collect_dir) / fname
                    if not img_path.is_file():
                        self._exact.add(dh)
                        continue
                    try:
                        img = Image.open(img_path)
                        ph = _phash(img)
                        self.add(dh, ph, str(img_path))
                        count += 1
                    except Exception:
                        self._exact.add(dh)
        except Exception:
            pass
        if count:
            logger.info(
                "[%s] Loaded %d from %s", self.name, count,
                collect_dir,
            )

    def _load_dataset(self, ds_dir: Path):
        """Load a dataset directory into the index."""
        from PIL import Image
        if not ds_dir.is_dir():
            return
        count = 0
        name = ds_dir.name
        for img_path in ds_dir.rglob("*"):
            if img_path.suffix.lower() not in (".jpg", ".jpeg", ".png"):
                continue
            try:
                img = Image.open(img_path)
                dh = _dhash(img)
                ph = _phash(img)
                self.add(dh, ph, str(img_path))
                count += 1
                if count % 10000 == 0:
                    logger.info(
                        "[%s] Indexed %d from %s...",
                        self.name, count, name,
                    )
            except Exception:
                pass
        if count:
            logger.info(
                "[%s] Loaded %d from %s", self.name, count, name,
            )

    def is_dupe(self, img) -> tuple[bool, int, int]:
        """Check if img is a duplicate. Returns (is_dupe, dHash, pHash).

        Tier 1: Exact dHash match (O(1) set lookup).
        Tier 2: Both dHash64 AND pHash64 within hamming threshold,
                confirmed by mean absolute pixel difference < 20.

        Does NOT modify the index - caller must call add() on non-dupes.
        """
        self._ensure_loaded()
        norm = img.convert("RGB").resize(_NORM_SIZE, 1)
        dh = _dhash(norm)
        ph = _phash(norm)

        # Tier 1: exact dHash
        with self._lock:
            if dh in self._exact:
                return True, dh, ph

        # Tier 2: find candidate indices under lock, do I/O outside
        candidate_paths: list[str] = []
        with self._lock:
            if self._size > 0:
                dh_d = _hamming_batch(self._dh, dh, self._size)
                ph_d = _hamming_batch(self._ph, ph, self._size)
                idxs = np.where(
                    (dh_d <= _DH_THRESHOLD)
                    & (ph_d <= _PH_THRESHOLD)
                )[0]
                candidate_paths = [self._paths[i] for i in idxs]

        if candidate_paths:
            from PIL import Image as _Img
            pix = _to_pixels(norm)
            for cpath in candidate_paths:
                try:
                    cpix = _to_pixels(_Img.open(cpath))
                    mad = float(np.abs(pix - cpix).mean())
                    if mad < _MAD_THRESHOLD:
                        return True, dh, ph
                except Exception:
                    continue

        # Optimistically reserve this hash so concurrent threads skip it.
        # Caller must call add() after saving, or remove from _exact on failure.
        with self._lock:
            self._exact.add(dh)

        return False, dh, ph

    def _ensure_loaded(self):
        raise NotImplementedError


class _ClsDedup(DedupIndex):
    """CLS: collected_cls + datasets/wafer_cls + datasets/wafer_cls_classic."""

    def _ensure_loaded(self):
        if self._loaded.is_set():
            return
        with self._lock:
            if self._loaded.is_set():
                return

            d = os.environ.get("WAFER_COLLECT_CLS", "")
            if d:
                self._load_collected(d)
                ds = Path(d).parent / "datasets"
                self._load_dataset(ds / "wafer_cls_classic")
                self._load_dataset(ds / "wafer_cls")

            logger.info(
                "[cls] Dedup index: %d full, %d exact",
                self._size, len(self._exact),
            )
            self._loaded.set()


class _DetDedup(DedupIndex):
    """DET: collected_det + datasets/wafer_det."""

    def _ensure_loaded(self):
        if self._loaded.is_set():
            return
        with self._lock:
            if self._loaded.is_set():
                return

            d = os.environ.get("WAFER_COLLECT_DET", "")
            if d:
                self._load_collected(d)
                ds = Path(d).parent / "datasets"
                self._load_dataset(ds / "wafer_det")

            logger.info(
                "[det] Dedup index: %d full, %d exact",
                self._size, len(self._exact),
            )
            self._loaded.set()


_cls_dedup = _ClsDedup("cls")
_det_dedup = _DetDedup("det")


# ---------------------------------------------------------------------------
# Save helpers
# ---------------------------------------------------------------------------

def _save_det(keyword: str, grid_type: str, image_bytes: bytes):
    """Save a 4x4 grid image to collected_det/."""
    d = os.environ.get("WAFER_COLLECT_DET")
    if not d:
        return False
    try:
        from PIL import Image

        img = Image.open(io.BytesIO(image_bytes))

        dupe, dh, ph = _det_dedup.is_dupe(img)
        if dupe:
            _inc(dupes_skipped=1)
            return False

        out = Path(d)
        out.mkdir(parents=True, exist_ok=True)
        fname = f"{uuid.uuid4()}.jpg"
        fpath = out / fname
        fpath.write_bytes(image_bytes)

        entry = {
            "file": fname,
            "keyword": keyword,
            "grid_type": grid_type,
            "outcome": "collected",
            "dhash": dh,
            "phash": ph,
        }
        meta = Path(d) / "metadata.jsonl"
        with _det_dedup._lock:
            with open(meta, "a") as f:
                f.write(json.dumps(entry) + "\n")
            _det_dedup.add(dh, ph, str(fpath))
        _inc(images_saved=1)
        return True
    except Exception as e:
        logger.debug("Save DET failed: %s", e)
        return False


def _save_cls(keyword: str, grid_type: str, image_bytes: bytes):
    """Split a 3x3 grid into 9 tiles and save each to collected_cls/."""
    d = os.environ.get("WAFER_COLLECT_CLS")
    if not d:
        return 0
    try:
        from PIL import Image

        img = Image.open(io.BytesIO(image_bytes))
        w, h = img.size
        tw, th = w // 3, h // 3

        out_dir = Path(d)
        out_dir.mkdir(parents=True, exist_ok=True)
        meta = Path(d) / "metadata.jsonl"
        saved = 0

        for idx in range(9):
            col, row = idx % 3, idx // 3
            tile = img.crop((
                col * tw, row * th,
                (col + 1) * tw, (row + 1) * th,
            ))
            tile_100 = tile.convert("RGB").resize((100, 100), 1)

            dupe, dh, ph = _cls_dedup.is_dupe(tile_100)
            if dupe:
                _inc(dupes_skipped=1)
                continue

            fname = f"{uuid.uuid4()}.jpg"
            fpath = out_dir / fname
            tile_100.save(fpath, "JPEG", quality=100)

            entry = {
                "file": fname,
                "keyword": keyword,
                "grid_type": grid_type,
                "outcome": "collected",
                "cell_index": idx,
                "dhash": dh,
                "phash": ph,
            }
            with _cls_dedup._lock:
                with open(meta, "a") as f:
                    f.write(json.dumps(entry) + "\n")
                _cls_dedup.add(dh, ph, str(fpath))
            saved += 1

        _inc(tiles_saved=saved)
        return saved
    except Exception as e:
        logger.debug("Save CLS failed: %s", e)
        return 0


# ---------------------------------------------------------------------------
# Browser helpers
# ---------------------------------------------------------------------------

def _is_recaptcha_url(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False
    parts = host.rsplit(".", 2)
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    return domain in _RECAPTCHA_DOMAINS


def _detect_grid(bframe):
    """Detect grid type and keyword. Returns (grid_type, keyword) or (None, None)."""
    try:
        keyword = bframe.locator(
            ".rc-imageselect-desc-wrapper strong"
        ).text_content(timeout=3000)
    except Exception:
        keyword = None
    if not keyword:
        return None, None

    keyword = keyword.strip().lower()

    try:
        if bframe.locator("table.rc-imageselect-table-44").is_visible(timeout=500):
            return "4x4", keyword
    except Exception:
        pass

    try:
        if bframe.locator(".rc-imageselect-desc-no-canonical").is_visible(timeout=500):
            return "dynamic_3x3", keyword
    except Exception:
        pass

    return "static_3x3", keyword


def _get_grid_image(page, bframe, grid_type: str) -> bytes | None:
    """Download the grid payload image."""
    tile_class = "rc-image-tile-44" if grid_type == "4x4" else "rc-image-tile-33"
    try:
        img_src = bframe.locator(
            f"img.{tile_class}"
        ).first.get_attribute("src", timeout=3000)
        if not img_src:
            return None
        if not (_is_recaptcha_url(img_src) or img_src.startswith("data:")):
            return None
        resp = page.request.get(img_src)
        if resp.status == 200:
            body = resp.body()
            if body and len(body) <= MAX_PAYLOAD_BYTES:
                return body
    except Exception:
        pass
    return None


def _click_reload(page, bframe):
    """Click reload button to get the next grid. Simple click, no mouse replay."""
    try:
        btn = bframe.locator("#recaptcha-reload-button")
        btn.click(timeout=3000)
        time.sleep(random.uniform(1.5, 2.5))
    except Exception:
        pass


def _find_bframe(page):
    """Find the reCAPTCHA challenge iframe."""
    for frame in page.frames:
        if "api2/bframe" in frame.url or "enterprise/bframe" in frame.url:
            return frame
    return None


def _check_autopass(page) -> bool:
    """Check if reCAPTCHA auto-passed (token present, no challenge)."""
    try:
        token = page.evaluate(
            "document.getElementById('g-recaptcha-response')?.value || ''"
        )
        return bool(token)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def _worker(wid: int, headless: bool):
    from patchright.sync_api import sync_playwright

    pw = sync_playwright().start()
    consecutive_fails = 0

    try:
        while not _shutdown.is_set():
            _inc(rounds=1)
            browser = pw.chromium.launch(
                headless=headless,
                args=["--disable-blink-features=AutomationControlled"],
            )
            try:
                collected = _run_session(browser, wid)
                if collected > 0:
                    consecutive_fails = 0
                else:
                    consecutive_fails += 1
            except _AutoPassError:
                consecutive_fails += 1
            except Exception as e:
                logger.error("W%d: %s", wid, e)
                _inc(errors=1)
                consecutive_fails += 1
            finally:
                try:
                    browser.close()
                except Exception:
                    pass

            _print_stats()

            if consecutive_fails >= MAX_AUTOPASSES:
                idx = min(
                    consecutive_fails - MAX_AUTOPASSES,
                    len(BACKOFF_SCHEDULE) - 1,
                )
                backoff = BACKOFF_SCHEDULE[idx]
                logger.warning(
                    "W%d: %d consecutive fails, backing off %ds (%dh)",
                    wid, consecutive_fails, backoff, backoff // 3600,
                )
                _shutdown.wait(backoff)
            else:
                _shutdown.wait(random.uniform(PAUSE_MIN, PAUSE_MAX))
    finally:
        try:
            pw.stop()
        except Exception:
            pass


class _AutoPassError(Exception):
    pass


def _run_session(browser, wid: int) -> int:
    """One browser session. Returns number of grids collected."""
    grids_collected = 0
    ctx = browser.new_context()
    page = ctx.new_page()

    try:
        page.goto(DEMO_URL, timeout=PAGE_LOAD_TIMEOUT_MS)
    except Exception as e:
        logger.warning("W%d: page load failed: %s", wid, e)
        return 0

    # Click checkbox
    time.sleep(random.uniform(0.8, 1.5))
    try:
        frame = page.frame_locator('iframe[title="reCAPTCHA"]')
        frame.locator(".recaptcha-checkbox-border").click()
    except Exception as e:
        logger.warning("W%d: checkbox click failed: %s", wid, e)
        return 0

    time.sleep(random.uniform(2.0, 3.5))

    if _check_autopass(page):
        logger.info("W%d: auto-passed", wid)
        _inc(auto_pass=1)
        raise _AutoPassError()

    bframe = _find_bframe(page)
    if not bframe:
        logger.info("W%d: no bframe found", wid)
        return 0

    try:
        bframe.wait_for_load_state("domcontentloaded", timeout=5000)
    except Exception:
        pass

    # Wait for the challenge image to appear
    try:
        bframe.locator(".rc-imageselect-desc-wrapper strong").wait_for(
            timeout=5000,
        )
    except Exception:
        pass

    # Collect grids by clicking reload to cycle through challenges
    for i in range(MAX_GRIDS_PER_SESSION):
        if _shutdown.is_set():
            break

        grid_type, keyword = _detect_grid(bframe)
        if not grid_type or not keyword:
            time.sleep(1.5)
            grid_type, keyword = _detect_grid(bframe)
            if not grid_type:
                logger.info("W%d: grid %d - could not detect grid", wid, i)
                break

        image_bytes = _get_grid_image(page, bframe, grid_type)
        if not image_bytes:
            logger.info("W%d: grid %d - no image", wid, i)
            _click_reload(page, bframe)
            continue

        if grid_type == "4x4":
            _inc(grids_4x4=1)
            saved = _save_det(keyword, grid_type, image_bytes)
            status = "saved" if saved else "dupe"
            logger.info(
                "W%d: grid %d - %s %s %r",
                wid, i, grid_type, status, keyword,
            )
            if saved:
                grids_collected += 1
        else:
            _inc(grids_3x3=1)
            tiles = _save_cls(keyword, grid_type, image_bytes)
            logger.info(
                "W%d: grid %d - %s %d tiles %r",
                wid, i, grid_type, tiles, keyword,
            )
            if tiles > 0:
                grids_collected += 1
        _click_reload(page, bframe)

    return grids_collected


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _start_time

    parser = argparse.ArgumentParser(description="Collect reCAPTCHA grid images")
    parser.add_argument(
        "--workers", type=int, default=1, help="Number of browser workers",
    )
    parser.add_argument("--headful", action="store_true", help="Run browsers visibly")
    args = parser.parse_args()

    headless = not args.headful
    num_workers = args.workers

    _start_time = time.monotonic()

    def _sig(sig, frame):
        logger.info("Shutting down...")
        _shutdown.set()

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    # Pre-load dedup indexes
    _cls_dedup._ensure_loaded()
    _det_dedup._ensure_loaded()

    logger.info(
        "Starting %d %s worker(s) against %s",
        num_workers,
        "headless" if headless else "headful",
        DEMO_URL,
    )

    threads = []
    for i in range(num_workers):
        t = threading.Thread(
            target=_worker, args=(i, headless), name=f"W{i}", daemon=True,
        )
        t.start()
        threads.append(t)
        if i < num_workers - 1:
            time.sleep(random.uniform(2.0, 4.0))

    try:
        while not _shutdown.is_set():
            _shutdown.wait(1.0)
    except KeyboardInterrupt:
        _shutdown.set()

    logger.info("Waiting for workers...")
    for t in threads:
        t.join(timeout=15)

    _print_stats()


if __name__ == "__main__":
    main()
