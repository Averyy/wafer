"""reCAPTCHA v2 image grid solver (classification + D-FINE detection).

Uses two ONNX models hosted on HuggingFace (Averyyyyyy/wafer-models):
- Classification (wafer_cls_{s,x}.onnx): 14-class tile classifier for 3x3 grids
- Detection (wafer_det_{s,x}.onnx): D-FINE COCO detector for 4x4 grids

Models are lazy-loaded on first encounter via huggingface_hub.
If unavailable, returns False and the escalation chain continues.
"""

import io
import json
import logging
import os
import random
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("wafer")

# ---------------------------------------------------------------------------
# Grid collection for training data (DET grids - full images with outcomes)
# ---------------------------------------------------------------------------

_COLLECT_DET_DIR: str | None = os.environ.get("WAFER_COLLECT_DET") or None

# ---------------------------------------------------------------------------
# Tile collection for training data (CLS grids only)
# ---------------------------------------------------------------------------

# 16 class names - indices 0-13 match current CLS model output,
# indices 14-15 are collection-only until the model is retrained.
_CLS_NAMES = [
    "Bicycle", "Bridge", "Bus", "Car", "Chimney", "Crosswalk",
    "Hydrant", "Motorcycle", "Mountain", "Other", "Palm",
    "Stair", "Tractor", "Traffic Light", "Boat", "Parking Meter",
]

_COLLECT_CLS_DIR: str | None = os.environ.get("WAFER_COLLECT_CLS") or None

_seen_hashes: set[int] = set()
_seen_hashes_loaded = False
_seen_hashes_lock = threading.Lock()  # guards one-time hash loading (I/O)
_collect_lock = threading.Lock()  # guards metadata writes and hash set updates


def _dhash(img, hash_size: int = 8) -> int:
    """64-bit perceptual difference hash for dedup."""
    small = img.convert("L").resize((hash_size + 1, hash_size), 1)  # LANCZOS=1
    pixels = list(small.getdata())
    w = hash_size + 1
    bits = 0
    for row in range(hash_size):
        for col in range(hash_size):
            bits = (bits << 1) | (pixels[row * w + col] < pixels[row * w + col + 1])
    return bits


def _collect_tiles(
    image_bytes: bytes,
    probs,  # numpy (9, 14)
    target_class: int | None,
    keyword: str,
    grid_type: str,
    cells: list[int] | None,
):
    """Split a 3x3 grid into tiles and save each with metadata."""
    if not _COLLECT_CLS_DIR:
        return
    try:
        from PIL import Image

        img = Image.open(io.BytesIO(image_bytes))
        w, h = img.size
        tw, th = w // 3, h // 3

        for idx in range(9):
            tile = img.crop((
                (idx % 3) * tw, (idx // 3) * th,
                (idx % 3 + 1) * tw, (idx // 3 + 1) * th,
            ))
            _collect_single_tile(
                tile, probs[idx] if probs is not None else None,
                target_class,
                cells is not None and idx in cells,
                keyword,
                source_grid=grid_type,
            )
    except Exception:
        pass  # Never break the solver


def _collect_single_tile(
    tile_img,
    probs,  # numpy (14,) or None
    target_class: int | None,
    is_match: bool,
    keyword: str,
    source_grid: str = "dynamic_3x3",
):
    """Save a single tile with metadata.

    Used for both grid splits and dynamic replacements.
    """
    if not _COLLECT_CLS_DIR:
        return
    try:
        import hashlib

        import numpy as np

        # Normalize to 100x100 RGB first - used for both saving and hashing
        tile_100 = tile_img.convert("RGB").resize((100, 100), 1)

        # Cross-session dedup via dHash
        h = _dhash(tile_100)
        _load_seen_hashes()
        with _collect_lock:
            if h in _seen_hashes:
                return
            _seen_hashes.add(h)

        # Pixel-level hash for reliable dedup against training data
        pixhash = hashlib.sha256(tile_100.tobytes()).hexdigest()

        # Classify tile for metadata (prediction stored, not used for folder)
        if probs is not None:
            argmax = int(np.argmax(probs))
            confidence = float(probs[argmax])
            top3_idx = np.argsort(probs)[::-1][:3]
            top3 = [(int(i), float(probs[i])) for i in top3_idx]
            predicted_class = _CLS_NAMES[argmax]
        else:
            argmax = -1
            confidence = 0.0
            top3 = []
            predicted_class = None

        out_dir = Path(_COLLECT_CLS_DIR)
        out_dir.mkdir(parents=True, exist_ok=True)

        filename = f"{uuid.uuid4()}.jpg"
        tile_100.save(out_dir / filename, "JPEG", quality=90)

        entry = {
            "file": filename,
            "predicted_class": predicted_class,
            "predicted_index": argmax,
            "confidence": round(confidence, 4),
            "top3": [[_CLS_NAMES[i], round(s, 4)] for i, s in top3],
            "keyword": keyword,
            "target_class": target_class,
            "is_selected": bool(is_match),
            "source_grid": source_grid,
            "dhash": h,
            "pixhash": pixhash,
        }

        meta_path = Path(_COLLECT_CLS_DIR) / "metadata.jsonl"
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        with _collect_lock:
            with open(meta_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # Never break the solver


def _load_seen_hashes() -> None:
    """Seed _seen_hashes from existing metadata.jsonl (once per process).

    Uses its own lock so the file I/O doesn't block _collect_lock.
    """
    global _seen_hashes_loaded  # noqa: PLW0603
    if _seen_hashes_loaded:
        return
    with _seen_hashes_lock:
        if _seen_hashes_loaded:
            return
        _seen_hashes_loaded = True
        for dir_path in (_COLLECT_DET_DIR, _COLLECT_CLS_DIR):
            if not dir_path:
                continue
            meta = Path(dir_path) / "metadata.jsonl"
            if not meta.is_file():
                continue
            try:
                with open(meta) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        entry = json.loads(line)
                        h = entry.get("dhash")
                        if h is not None:
                            _seen_hashes.add(h)
            except Exception:
                pass


def _collect_det_grid(
    keyword: str,
    grid_type: str,
    outcome: str,
    image_bytes: bytes | None = None,
    extra: dict | None = None,
):
    """Save a full grid image with metadata for DET review.

    Logs both successes and failures to a single collection directory.
    """
    if not _COLLECT_DET_DIR:
        return
    try:
        out_dir = Path(_COLLECT_DET_DIR)
        out_dir.mkdir(parents=True, exist_ok=True)

        img_name = None
        h = None
        if image_bytes:
            from PIL import Image

            img = Image.open(io.BytesIO(image_bytes))
            h = _dhash(img)
            _load_seen_hashes()
            with _collect_lock:
                if h in _seen_hashes:
                    return
                _seen_hashes.add(h)
            img_name = f"{uuid.uuid4()}.jpg"
            (out_dir / img_name).write_bytes(image_bytes)

        entry = {
            "file": img_name,
            "keyword": keyword,
            "grid_type": grid_type,
            "outcome": outcome,
        }
        if extra:
            entry.update(extra)
        if h is not None:
            entry["dhash"] = h

        meta_path = Path(_COLLECT_DET_DIR) / "metadata.jsonl"
        with _collect_lock:
            with open(meta_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # Never break the solver


# ---------------------------------------------------------------------------
# ONNX model loading (lazy, thread-safe)
# ---------------------------------------------------------------------------

_cls_session = None
_det_session = None
_models_unavailable = False
_model_lock = threading.Lock()
_inference_lock = threading.Lock()
_warmup_done = threading.Event()


_HF_REPO = "Averyyyyyy/wafer-models"


def _ensure_models():
    """Download + load ONNX models from HuggingFace. Thread-safe, lazy.

    Returns (cls_session, det_session). Either may be None if unavailable.
    Detection and classification are independent - one can work without the other.
    """
    global _cls_session, _det_session, _models_unavailable

    if _models_unavailable:
        return _cls_session, _det_session
    if _cls_session is not None or _det_session is not None:
        return _cls_session, _det_session

    with _model_lock:
        if _models_unavailable:
            return _cls_session, _det_session
        if _cls_session is not None or _det_session is not None:
            return _cls_session, _det_session

        try:
            import onnxruntime as ort
        except ImportError:
            logger.debug("onnxruntime not installed, image grid solver unavailable")
            _models_unavailable = True
            return None, None

        try:
            from huggingface_hub import hf_hub_download
        except ImportError:
            logger.debug("huggingface_hub not installed, image grid solver unavailable")
            _models_unavailable = True
            return None, None

        opts = ort.SessionOptions()
        opts.inter_op_num_threads = 1
        opts.intra_op_num_threads = 2

        # cls: only download "s" - "x" exists on HF as backup but is 40%
        # larger with <1% accuracy gain (92.1% vs 92.5%).
        cls = None
        try:
            p = hf_hub_download(_HF_REPO, "wafer_cls_s.onnx")
            cls = ort.InferenceSession(
                p, opts, providers=["CPUExecutionProvider"]
            )
        except Exception:
            pass

        # det: only download "s" - "x" exists on HF as backup (248 MB vs 42 MB)
        # but hasn't been benchmarked against reCAPTCHA grids.
        det = None
        try:
            p = hf_hub_download(_HF_REPO, "wafer_det_s.onnx")
            det = ort.InferenceSession(
                p, opts, providers=["CPUExecutionProvider"]
            )
        except Exception:
            pass

        if cls is None and det is None:
            logger.debug("Could not download any ONNX models from %s", _HF_REPO)
            _models_unavailable = True
            return None, None

        _cls_session = cls
        _det_session = det
        _models_unavailable = True  # Don't retry on next call

        # Background warmup
        def _warmup():
            import numpy as np
            try:
                if _cls_session is not None:
                    _cls_session.run(
                        None,
                        {_cls_session.get_inputs()[0].name: np.zeros(
                            (1, 3, 224, 224), dtype=np.float32
                        )},
                    )
                if _det_session is not None:
                    _det_session.run(
                        None,
                        {
                            "images": np.zeros(
                                (1, 3, 640, 640), dtype=np.float32
                            ),
                            "orig_target_sizes": np.array(
                                [[640, 640]], dtype=np.int64
                            ),
                        },
                    )
            except Exception:
                pass
            _warmup_done.set()

        threading.Thread(target=_warmup, daemon=True).start()
        loaded = []
        if cls:
            loaded.append("cls")
        if det:
            loaded.append("det")
        logger.info("ONNX models loaded: %s", " + ".join(loaded))
        return _cls_session, _det_session


# ---------------------------------------------------------------------------
# Keyword -> class index mapping (9 languages, 16 classes)
# ---------------------------------------------------------------------------

# fmt: off
KEYWORD_TO_CLASS: dict[str, int] = {
    # English
    "bicycles": 0, "a bicycle": 0,
    "bridges": 1, "a bridge": 1,
    "buses": 2, "a bus": 2, "school buses": 2, "a school bus": 2,
    "cars": 3, "taxis": 3, "a taxi": 3, "a car": 3,
    "chimneys": 4, "a chimney": 4,
    "crosswalks": 5, "a crosswalk": 5,
    "fire hydrants": 6, "a fire hydrant": 6,
    "motorcycles": 7, "a motorcycle": 7,
    "mountains": 8, "mountains or hills": 8,
    "palm trees": 10,
    "stairs": 11, "a staircase": 11,
    "tractors": 12, "a tractor": 12,
    "traffic lights": 13, "a traffic light": 13,
    # "boats" (14) and "parking meters" (15) are collection-only — the CLS
    # model has 14 outputs (0-13).  They live in EXTRA_COCO for detection.
    # Spanish (shared words with PT: bicicletas, hidrantes,
    # motocicletas, semáforos - only listed once)
    "bicicletas": 0, "una bicicleta": 0,
    "puentes": 1, "un puente": 1,
    "autobuses": 2, "un autobús": 2,
    "coches": 3, "un coche": 3, "un taxi": 3,
    "chimeneas": 4, "una chimenea": 4,
    "pasos de peatones": 5, "un paso de peatones": 5,
    "hidrantes": 6, "un hidrante": 6,
    "bocas de incendio": 6,
    "motocicletas": 7, "una motocicleta": 7,
    "montañas": 8, "montañas o colinas": 8,
    "palmeras": 10,
    "escaleras": 11, "una escalera": 11,
    "tractores": 12, "un tractor": 12,
    "semáforos": 13, "un semáforo": 13,
    # French
    "vélos": 0, "un vélo": 0,
    "ponts": 1, "un pont": 1,
    "bus": 2, "un bus": 2,
    "voitures": 3, "une voiture": 3,
    "cheminées": 4, "une cheminée": 4,
    "passages piétons": 5, "un passage piéton": 5,
    "bouches d\u2019incendie": 6,
    "une bouche d\u2019incendie": 6,
    "motos": 7, "une moto": 7,
    "montagnes": 8, "montagnes ou collines": 8,
    "palmiers": 10,
    "escaliers": 11, "un escalier": 11,
    "tracteurs": 12, "un tracteur": 12,
    "feux de signalisation": 13,
    "un feu de signalisation": 13,
    # German
    "fahrräder": 0, "ein fahrrad": 0,
    "brücken": 1, "eine brücke": 1,
    "busse": 2, "einen bus": 2,
    "autos": 3, "ein auto": 3,
    "schornsteine": 4, "einen schornstein": 4,
    "zebrastreifen": 5, "einen zebrastreifen": 5,
    "hydranten": 6, "einen hydranten": 6,
    "motorräder": 7, "ein motorrad": 7,
    "berge": 8, "berge oder hügel": 8,
    "palmen": 10,
    "treppen": 11, "eine treppe": 11,
    "traktoren": 12, "einen traktor": 12,
    "ampeln": 13, "eine ampel": 13,
    # Italian
    "biciclette": 0, "una bicicletta": 0,
    "ponti": 1, "un ponte": 1,
    "autobus": 2, "un autobus": 2,
    "automobili": 3, "un\u2019automobile": 3,
    "macchine": 3,
    "camini": 4, "un camino": 4,
    "strisce pedonali": 5, "una striscia pedonale": 5,
    "idranti": 6, "un idrante": 6,
    "motociclette": 7, "una motocicletta": 7,
    "montagne": 8, "montagne o colline": 8,
    "palme": 10,
    "scale": 11, "una scala": 11,
    "trattori": 12, "un trattore": 12,
    "semafori": 13, "un semaforo": 13,
    # Portuguese (shared keys already in Spanish section)
    "uma bicicleta": 0,
    "pontes": 1, "uma ponte": 1,
    "ônibus": 2, "um ônibus": 2,
    "carros": 3, "um carro": 3,
    "chaminés": 4, "uma chaminé": 4,
    "faixas de pedestres": 5,
    "uma faixa de pedestres": 5,
    "um hidrante": 6,
    "uma motocicleta": 7,
    "montanhas": 8, "montanhas ou colinas": 8,
    "palmeiras": 10,
    "escadas": 11, "uma escada": 11,
    "tratores": 12, "um trator": 12,
    "um semáforo": 13,
    # Dutch
    "fietsen": 0, "een fiets": 0,
    "bruggen": 1, "een brug": 1,
    "bussen": 2, "een bus": 2,
    "auto\u2019s": 3, "een auto": 3,
    "schoorstenen": 4, "een schoorsteen": 4,
    "zebrapaden": 5, "een zebrapad": 5,
    "brandkranen": 6, "een brandkraan": 6,
    "motoren": 7, "een motor": 7,
    "bergen": 8, "bergen of heuvels": 8,
    "palmbomen": 10,
    "trappen": 11, "een trap": 11,
    "tractoren": 12, "een tractor": 12,
    "verkeerslichten": 13, "een verkeerslicht": 13,
    # Russian
    "велосипеды": 0,
    "велосипед": 0,
    "мосты": 1, "мост": 1,
    "автобусы": 2, "автобус": 2,
    "автомобили": 3,
    "автомобиль": 3,
    "такси": 3,
    "дымовые трубы": 4,
    "дымовую трубу": 4,
    "пешеходные переходы": 5,
    "пешеходный переход": 5,
    "пожарные гидранты": 6,
    "пожарный гидрант": 6,
    "мотоциклы": 7, "мотоцикл": 7,
    "горы": 8,
    "горы или холмы": 8,
    "пальмы": 10,
    "лестницы": 11, "лестницу": 11,
    "тракторы": 12, "трактор": 12,
    "светофоры": 13, "светофор": 13,
    # Chinese (Simplified)
    "自行车": 0,
    "桥梁": 1, "桥": 1,
    "公共汽车": 2, "巴士": 2,
    "汽车": 3, "车": 3, "出租车": 3,
    "烟囱": 4,
    "人行横道": 5,
    "消防栓": 6,
    "摩托车": 7,
    "山": 8, "山或丘陵": 8, "山脉": 8,
    "棕榈树": 10,
    "楼梯": 11, "台阶": 11,
    "拖拉机": 12,
    "红绿灯": 13, "交通灯": 13,
}
# fmt: on

# Extra COCO keywords for 4x4 grids - looked up by raw keyword string
# before falling back to CLASS_TO_COCO index lookup.
EXTRA_COCO: dict[str, int] = {
    "boats": 8, "a boat": 8,
    "parking meters": 12, "a parking meter": 12,
}

# Classifier class index → COCO80 class mapping for 4x4 grid detection.
CLASS_TO_COCO: dict[int, int] = {
    0: 1,   # bicycle
    2: 5,   # bus
    3: 2,   # car
    6: 10,  # fire hydrant
    7: 3,   # motorcycle
    13: 9,  # traffic light
    14: 8,  # boat
    15: 12,  # parking meter
}


# ---------------------------------------------------------------------------
# Inference functions
# ---------------------------------------------------------------------------

def _split_grid(image_bytes: bytes, grid_size: int = 3):
    """Split combined grid image into individual tile PIL Images."""
    from PIL import Image

    img = Image.open(io.BytesIO(image_bytes))
    w, h = img.size
    tw, th = w // grid_size, h // grid_size
    tiles = []
    for row in range(grid_size):
        for col in range(grid_size):
            tiles.append(
                img.crop((col * tw, row * th, (col + 1) * tw, (row + 1) * th))
            )
    return tiles


def _classify_tiles_batch(session, tile_images, size: int = 224):
    """Batch classify tiles. Returns (N, 14) probabilities."""
    import numpy as np

    blobs = []
    for img in tile_images:
        arr = np.array(
            img.convert("RGB").resize((size, size)),
            dtype=np.float32,
        )
        blobs.append(arr / 255.0)
    batch = np.stack(blobs).transpose(0, 3, 1, 2)  # (N, 3, H, W)

    with _inference_lock:
        logits = session.run(
            None, {session.get_inputs()[0].name: batch}
        )[0]  # (N, 14)

    # Softmax per row
    e = np.exp(logits - logits.max(axis=1, keepdims=True))
    return e / e.sum(axis=1, keepdims=True)


def _detect_in_grid(
    session, full_image, target_coco_class: int,
    grid_cols: int = 4, conf_thresh: float = 0.25, size: int = 640,
    min_cell_coverage: float = 0.15,
):
    """Run COCO detection on full 4x4 image, return occupied cell indices (0-based).

    min_cell_coverage: minimum fraction of a cell's area that must be covered
    by a detection box for that cell to be selected. Prevents marking cells
    where a box barely clips the corner. 0.15 = 15% of the cell area.
    """
    import numpy as np

    orig_w, orig_h = full_image.size

    # Letterbox to 640x640
    scale = min(size / orig_w, size / orig_h)
    new_w, new_h = int(orig_w * scale), int(orig_h * scale)
    pad_w, pad_h = (size - new_w) // 2, (size - new_h) // 2

    from PIL import Image

    img = full_image.convert("RGB").resize((new_w, new_h))
    padded = Image.new("RGB", (size, size), (114, 114, 114))
    padded.paste(img, (pad_w, pad_h))
    blob = (
        np.array(padded, dtype=np.float32) / 255.0
    ).transpose(2, 0, 1)[np.newaxis, ...]  # (1, 3, 640, 640)

    # D-FINE: 2 inputs (images + orig_target_sizes), 3 outputs (labels, boxes, scores)
    with _inference_lock:
        labels, boxes_raw, scores = session.run(
            None,
            {
                "images": blob,
                "orig_target_sizes": np.array([[size, size]], dtype=np.int64),
            },
        )
    labels = labels[0]      # (300,)
    boxes_raw = boxes_raw[0]  # (300, 4) - x1,y1,x2,y2 in input-size coords
    scores = scores[0]      # (300,)

    mask = (labels.astype(int) == target_coco_class) & (scores > conf_thresh)
    boxes = boxes_raw[mask]
    if len(boxes) == 0:
        return []

    # Rescale from letterbox to original coords
    boxes[:, [0, 2]] = (boxes[:, [0, 2]] - pad_w) / scale
    boxes[:, [1, 3]] = (boxes[:, [1, 3]] - pad_h) / scale
    boxes = np.clip(boxes, 0, [orig_w, orig_h, orig_w, orig_h])

    # Map boxes to grid cells, requiring minimum coverage of each cell
    cell_w, cell_h = orig_w / grid_cols, orig_h / grid_cols
    cell_area = cell_w * cell_h
    # Track max coverage per cell across all detection boxes
    coverage = {}
    for bx1, by1, bx2, by2 in boxes:
        for r in range(
            max(0, int(by1 // cell_h)),
            min(grid_cols, int(by2 // cell_h) + 1),
        ):
            for c in range(
                max(0, int(bx1 // cell_w)),
                min(grid_cols, int(bx2 // cell_w) + 1),
            ):
                # Intersection of box with this cell
                cx1, cy1 = c * cell_w, r * cell_h
                cx2, cy2 = cx1 + cell_w, cy1 + cell_h
                ix1 = max(bx1, cx1)
                iy1 = max(by1, cy1)
                ix2 = min(bx2, cx2)
                iy2 = min(by2, cy2)
                inter = max(0, ix2 - ix1) * max(0, iy2 - iy1)
                frac = inter / cell_area
                idx = r * grid_cols + c
                coverage[idx] = max(coverage.get(idx, 0), frac)
    cells = [idx for idx, frac in coverage.items() if frac >= min_cell_coverage]
    return sorted(cells)


# Tile selection thresholds (tuned for nano model's probability distribution -
# nano spreads softmax across 14 classes, so absolute values are low)
_MIN_TILE_CONFIDENCE = 0.10   # tile must exceed this to be selected


def _select_tiles(
    probs, target_class: int | None,
    min_confidence: float = _MIN_TILE_CONFIDENCE,
):
    """Given (N, 14) probs, return 0-based list of tiles to click.

    Selects tiles where the target class is the argmax (highest predicted
    class). The nano model reliably puts the correct class as argmax even
    though absolute probabilities are low (~0.15-0.20). Tiles where a
    different class is argmax are almost never correct.

    If more than 5 tiles match (likely false positives from the nano model),
    keeps only the top 5 by score to avoid over-selection.
    """
    if target_class is None:
        return None

    n = probs.shape[0]
    argmaxes = probs.argmax(axis=1)

    # Select tiles where target class is the top prediction
    candidates = [
        (i, float(probs[i, target_class]))
        for i in range(n)
        if argmaxes[i] == target_class
        and probs[i, target_class] >= min_confidence
    ]

    if not candidates:
        return None

    # Sort by score descending - if too many matched, keep top 5
    candidates.sort(key=lambda x: x[1], reverse=True)
    if len(candidates) > 5:
        candidates = candidates[:5]

    return [i for i, _ in candidates]


# ---------------------------------------------------------------------------
# Payload intercept
# ---------------------------------------------------------------------------

_MAX_PAYLOAD_BYTES = 5 * 1024 * 1024  # 5 MB size cap for images

_RECAPTCHA_DOMAINS = frozenset({
    "google.com", "gstatic.com", "recaptcha.net",
})


def _is_recaptcha_url(url: str) -> bool:
    """Check if URL belongs to a known reCAPTCHA domain."""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False
    parts = host.rsplit(".", 2)
    # Match "google.com" and "*.google.com" etc.
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    return domain in _RECAPTCHA_DOMAINS


def _setup_payload_intercept(page):
    """Set up response listener to capture reCAPTCHA payload images.

    Must be called BEFORE checkbox click (payload fires during challenge load).
    Returns a dict with "payload" key (populated on capture) and "cleanup"
    callable to remove the listener when done.
    """
    captured = {"payload": None, "cleanup": lambda: None}

    def _on_response(response):
        url = response.url
        if _is_recaptcha_url(url) and (
            "/recaptcha/api2/payload" in url
            or "/recaptcha/enterprise/payload" in url
        ):
            try:
                body = response.body()
                if len(body) <= _MAX_PAYLOAD_BYTES:
                    captured["payload"] = body
            except Exception:
                pass

    page.on("response", _on_response)
    captured["cleanup"] = lambda: page.remove_listener("response", _on_response)
    return captured


# ---------------------------------------------------------------------------
# Tile clicking
# ---------------------------------------------------------------------------

def _click_tile(solver, page, bframe, cell, grid_size, cur_x, cur_y):
    """Click a grid tile using mouse path replay.

    Args:
        cell: 0-based cell index (row-major).
        grid_size: 3 or 4.
        cur_x, cur_y: Current mouse position.

    Returns (target_x, target_y) of the clicked tile center.
    """
    # Tile selector is 1-indexed in the DOM
    selector = f"td.rc-imageselect-tile:nth-child({(cell % grid_size) + 1})"
    row_idx = cell // grid_size
    # Rows are in separate <tr> elements
    row_selector = (
        f"table.rc-imageselect-table-33 tr:nth-child({row_idx + 1})"
        if grid_size == 3
        else f"table.rc-imageselect-table-44 tr:nth-child({row_idx + 1})"
    )
    full_selector = f"{row_selector} {selector}"

    try:
        box = bframe.locator(full_selector).bounding_box(timeout=3000)
    except Exception:
        return cur_x, cur_y

    if not box:
        return cur_x, cur_y

    target_x = box["x"] + box["width"] * random.uniform(0.25, 0.75)
    target_y = box["y"] + box["height"] * random.uniform(0.25, 0.75)

    # Use grid recordings if available, fall back to regular paths
    pool = solver._grid_recordings or solver._path_recordings or None
    try:
        if pool:
            solver._replay_path(
                page, cur_x, cur_y, target_x, target_y, pool=pool,
            )
        else:
            page.mouse.move(target_x, target_y)
    except Exception:
        page.mouse.move(target_x, target_y)

    time.sleep(random.uniform(0.05, 0.15))
    page.mouse.click(target_x, target_y)
    return target_x, target_y


def _click_verify(solver, page, bframe, cur_x, cur_y):
    """Click the verify button."""
    try:
        box = bframe.locator("#recaptcha-verify-button").bounding_box(timeout=3000)
    except Exception:
        return cur_x, cur_y
    if not box:
        return cur_x, cur_y

    target_x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
    target_y = box["y"] + box["height"] * random.uniform(0.3, 0.7)

    pool = solver._grid_recordings or solver._path_recordings or None
    try:
        if pool:
            solver._replay_path(
                page, cur_x, cur_y, target_x, target_y, pool=pool,
            )
        else:
            page.mouse.move(target_x, target_y)
    except Exception:
        page.mouse.move(target_x, target_y)

    time.sleep(random.uniform(0.08, 0.22))
    page.mouse.click(target_x, target_y)
    return target_x, target_y


def _click_reload(solver, page, bframe, cur_x, cur_y):
    """Click the reload button to get a new challenge."""
    try:
        box = bframe.locator("#recaptcha-reload-button").bounding_box(timeout=3000)
    except Exception:
        return cur_x, cur_y
    if not box:
        return cur_x, cur_y

    target_x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
    target_y = box["y"] + box["height"] * random.uniform(0.3, 0.7)

    pool = solver._path_recordings or None
    try:
        if pool:
            solver._replay_path(
                page, cur_x, cur_y, target_x, target_y, pool=pool,
            )
        else:
            page.mouse.move(target_x, target_y)
    except Exception:
        page.mouse.move(target_x, target_y)

    time.sleep(random.uniform(0.08, 0.22))
    page.mouse.click(target_x, target_y)
    time.sleep(random.uniform(1.5, 2.5))
    return target_x, target_y


# ---------------------------------------------------------------------------
# Dynamic replacement handler (3x3 grids where tiles refresh after clicking)
# ---------------------------------------------------------------------------

def _handle_dynamic_replacements(
    solver, page, bframe, clicked_cells, target_class,
    cls_session, grid_size, cur_x, cur_y, deadline,
    keyword: str = "",
):
    """Poll for replacement tiles and re-classify them.

    After clicking correct tiles in a dynamic 3x3 grid, reCAPTCHA replaces
    them with new images. The original tile (img.rc-image-tile-33) is removed
    and a new individual tile (img.rc-image-tile-11) appears in its place.
    We detect these replacements, download and classify the new tiles,
    and click any new matches.
    """
    from PIL import Image

    pending = set(clicked_cells)
    max_rounds = 3
    seen_urls: set[str] = set()  # Track URLs we've already classified

    logger.info(
        "Dynamic replacement: watching cells %s",
        sorted(pending),
    )

    for round_num in range(max_rounds):
        if time.monotonic() > deadline:
            break
        if not pending:
            break

        # Wait for NEW replacement tiles (rc-image-tile-11) to appear.
        # After clicking a tile-33, it gets removed and a tile-11 appears.
        # After clicking a tile-11, it gets replaced with a new tile-11.
        new_tiles: dict[int, str] = {}
        wait_deadline = time.monotonic() + 5.0
        while time.monotonic() < wait_deadline:
            time.sleep(0.4)
            try:
                cell_info = bframe.evaluate(
                    """() => {
                        const tds = document.querySelectorAll(
                            'td.rc-imageselect-tile'
                        );
                        return Array.from(tds, td => {
                            const img11 = td.querySelector(
                                'img.rc-image-tile-11'
                            );
                            return img11 ? img11.src : null;
                        });
                    }"""
                )
            except Exception:
                break

            # Check which pending cells have new tile-11 URLs
            for c in pending:
                if c < len(cell_info) and cell_info[c]:
                    url = cell_info[c]
                    if url not in seen_urls:
                        new_tiles[c] = url

            if len(new_tiles) >= len(pending):
                break

        if not new_tiles:
            logger.info(
                "Dynamic round %d: no new tiles for cells %s, done",
                round_num + 1, sorted(pending),
            )
            break

        logger.info(
            "Dynamic round %d: %d new tiles, classifying",
            round_num + 1, len(new_tiles),
        )

        # Mark these URLs as seen
        seen_urls.update(new_tiles.values())

        # Download and classify replacement tiles
        new_matches = []
        for cell, tile_url in new_tiles.items():
            try:
                if not _is_recaptcha_url(tile_url):
                    continue
                resp = page.request.get(tile_url)
                if resp.status != 200:
                    continue
                body = resp.body()
                if not body or len(body) > _MAX_PAYLOAD_BYTES:
                    continue
                tile_img = Image.open(io.BytesIO(body))
                probs = _classify_tiles_batch(cls_session, [tile_img])
                is_target = (
                    probs.argmax(axis=1)[0] == target_class
                    and probs[0, target_class] >= _MIN_TILE_CONFIDENCE
                )
                logger.info(
                    "Replacement cell %d: score=%.3f argmax=%d %s",
                    cell, probs[0, target_class],
                    probs.argmax(axis=1)[0],
                    "MATCH" if is_target else "skip",
                )
                # Collect replacement tile for training
                _collect_single_tile(
                    tile_img, probs[0], target_class,
                    is_target, keyword, source_grid="dynamic_3x3",
                )
                if is_target:
                    new_matches.append(cell)
            except Exception:
                continue

        pending = set()
        if not new_matches:
            logger.info("Dynamic round %d: no matches", round_num + 1)
            break

        logger.info(
            "Dynamic round %d: clicking %s",
            round_num + 1, new_matches,
        )

        random.shuffle(new_matches)
        for cell in new_matches:
            time.sleep(random.uniform(0.2, 0.5))
            cur_x, cur_y = _click_tile(
                solver, page, bframe, cell, grid_size, cur_x, cur_y,
            )
            pending.add(cell)

    return cur_x, cur_y


# ---------------------------------------------------------------------------
# Grid type detection
# ---------------------------------------------------------------------------

def _detect_grid_type(bframe):
    """Detect grid type from DOM structure.

    Uses the actual table class (rc-imageselect-table-33 vs table-44)
    and tile count to determine grid type, avoiding locale-dependent
    text matching.

    Returns ("static_3x3" | "dynamic_3x3" | "4x4", keyword_text).
    """
    # Extract target keyword from <strong> element
    try:
        keyword = bframe.locator(
            ".rc-imageselect-desc-wrapper strong"
        ).text_content(timeout=3000)
    except Exception:
        keyword = None

    if not keyword:
        return None, None

    # Detect 4x4 by table class (rc-imageselect-table-44)
    try:
        is_4x4 = bframe.locator(
            "table.rc-imageselect-table-44"
        ).is_visible(timeout=500)
        if is_4x4:
            return "4x4", keyword
    except Exception:
        pass

    # 3x3 grid - detect dynamic vs static by checking if the
    # desc uses the "no" class (rc-imageselect-desc-no-canonical)
    # which indicates "select all matching images" (dynamic replacement)
    try:
        is_dynamic = bframe.locator(
            ".rc-imageselect-desc-no-canonical"
        ).is_visible(timeout=500)
        if is_dynamic:
            return "dynamic_3x3", keyword
    except Exception:
        pass

    return "static_3x3", keyword


# ---------------------------------------------------------------------------
# Main solve loop
# ---------------------------------------------------------------------------

def solve_image_grid(
    solver, page, bframe, state, deadline,
    payload: bytes | None = None,
    max_attempts: int = 12,
) -> bool:
    """Solve reCAPTCHA image grid challenge.

    Returns True if a token was obtained, False otherwise.

    Args:
        solver: BrowserSolver instance (for mouse replay).
        page: Playwright page.
        bframe: reCAPTCHA bframe (challenge iframe).
        state: _BrowseState for current mouse position tracking.
        deadline: time.monotonic() deadline for the entire solve.
        payload: Pre-intercepted payload image bytes (from checkbox phase).
        max_attempts: Maximum number of solve attempts (default 12).
    """
    cls_session, det_session = _ensure_models()
    if cls_session is None and det_session is None:
        logger.debug("No ONNX models available, skipping image grid solver")
        return False

    # Wait for warmup if still running (respect solve deadline)
    remaining = max(0, deadline - time.monotonic())
    _warmup_done.wait(timeout=min(10, remaining))

    # Ensure recordings are loaded (for mouse replay)
    solver._ensure_recordings()

    cur_x = state.current_x if state else random.uniform(400, 700)
    cur_y = state.current_y if state else random.uniform(300, 500)
    for attempt in range(max_attempts):
        if time.monotonic() > deadline:
            logger.debug("Image grid solver deadline exceeded")
            break

        # Detect grid type and target
        grid_type, keyword = _detect_grid_type(bframe)
        if not grid_type or not keyword:
            if attempt < 3:
                # Challenge may still be loading
                logger.debug(
                    "Grid type not ready (attempt %d), waiting...",
                    attempt,
                )
                time.sleep(1.5)
                continue
            logger.debug("Could not detect grid type or keyword")
            break

        keyword_lower = keyword.lower().strip()
        target_class = KEYWORD_TO_CLASS.get(keyword_lower)

        # Check extra COCO keywords for 4x4 grids
        coco_direct = EXTRA_COCO.get(keyword_lower)

        if target_class is None and coco_direct is None:
            logger.warning(
                "Unknown reCAPTCHA keyword: %r — collecting image for review",
                keyword_lower,
            )
            # Still fetch the image before reloading so we can annotate it
            try:
                tile_class = (
                    "rc-image-tile-44" if grid_type == "4x4"
                    else "rc-image-tile-33"
                )
                img_src = bframe.locator(
                    f"img.{tile_class}"
                ).first.get_attribute("src", timeout=3000)
                if img_src and (
                    _is_recaptcha_url(img_src)
                    or img_src.startswith("data:")
                ):
                    resp = page.request.get(img_src)
                    if resp.status == 200:
                        body = resp.body()
                        if body and len(body) <= _MAX_PAYLOAD_BYTES:
                            _collect_det_grid(
                                keyword_lower, grid_type, "unknown_keyword",
                                body,
                            )
            except Exception:
                _collect_det_grid(keyword_lower, grid_type, "unknown_keyword")
            cur_x, cur_y = _click_reload(
                solver, page, bframe, cur_x, cur_y,
            )
            continue

        logger.info(
            "reCAPTCHA image grid attempt %d: %s, keyword=%r, class=%s",
            attempt + 1, grid_type, keyword_lower,
            target_class if target_class is not None else f"coco:{coco_direct}",
        )

        # Get payload image - try intercepted payload first (attempt 1)
        from PIL import Image

        image_bytes = None
        if payload is not None and attempt == 0:
            image_bytes = payload
            payload = None  # Only use intercepted payload once

        if not image_bytes:
            # Tiles are CSS-cropped from a single payload image.
            # Both 3x3 (rc-image-tile-33) and 4x4 (rc-image-tile-44)
            # share the same src URL across all tiles.
            tile_class = (
                "rc-image-tile-44"
                if grid_type == "4x4"
                else "rc-image-tile-33"
            )
            try:
                img_src = bframe.locator(
                    f"img.{tile_class}"
                ).first.get_attribute("src", timeout=3000)
                if img_src and (
                    _is_recaptcha_url(img_src)
                    or img_src.startswith("data:")
                ):
                    resp = page.request.get(img_src)
                    if resp.status == 200:
                        body = resp.body()
                        if body and len(body) <= _MAX_PAYLOAD_BYTES:
                            image_bytes = body
            except Exception:
                pass

        if not image_bytes:
            logger.debug("Could not get grid image, reloading")
            cur_x, cur_y = _click_reload(
                solver, page, bframe, cur_x, cur_y,
            )
            continue

        grid_image = Image.open(io.BytesIO(image_bytes))

        if grid_type == "4x4":
            if det_session is None:
                logger.debug("4x4 grid but no detection model, reloading")
                cur_x, cur_y = _click_reload(
                    solver, page, bframe, cur_x, cur_y,
                )
                continue

            # 4x4 grids: COCO object detection on full image.
            # Resolve COCO class from keyword.
            coco_class = EXTRA_COCO.get(keyword_lower)
            if coco_class is None and target_class is not None:
                coco_class = CLASS_TO_COCO.get(target_class)

            if coco_class is None:
                # No COCO equivalent (bridge, chimney, etc.) - reload for 3x3
                logger.info(
                    "4x4 grid, no COCO class for %r, reloading",
                    keyword_lower,
                )
                _collect_det_grid(
                    keyword_lower, grid_type, "no_coco_class", image_bytes,
                )
                cur_x, cur_y = _click_reload(
                    solver, page, bframe, cur_x, cur_y,
                )
                continue

            cells = _detect_in_grid(
                det_session, grid_image, coco_class, grid_cols=4,
            )
            grid_size = 4

            if not cells:
                # Object not present - click skip (verify button says "SKIP")
                logger.info("4x4 grid: no detections, clicking skip")
                time.sleep(random.uniform(0.3, 0.7))
                cur_x, cur_y = _click_verify(
                    solver, page, bframe, cur_x, cur_y,
                )
                time.sleep(random.uniform(0.5, 1.0))
                from wafer.browser._recaptcha import _check_token

                if _check_token(page):
                    logger.info(
                        "reCAPTCHA image grid solved (skip) on attempt %d",
                        attempt + 1,
                    )
                    _collect_det_grid(
                        keyword_lower, grid_type, "solved_skip", image_bytes,
                        {"coco_class": coco_class},
                    )
                    return True
                # Skip was wrong - object was present but detection missed it
                _collect_det_grid(
                    keyword_lower, grid_type, "skip_wrong", image_bytes,
                    {"coco_class": coco_class},
                )
                continue

            logger.info(
                "4x4 COCO detection: cells=%s (coco_class=%d)",
                cells, coco_class,
            )
        else:
            # 3x3 grids: tile-by-tile classification
            if cls_session is None:
                logger.debug("3x3 grid but no classification model, skipping")
                break

            grid_size = 3
            tiles = _split_grid(image_bytes, grid_size=3)
            probs = _classify_tiles_batch(cls_session, tiles)

            if target_class is not None:
                cells = _select_tiles(probs, target_class)
            else:
                # COCO-only keywords (boats, parking meters) on 3x3
                coco_class = coco_direct
                if coco_class is None or det_session is None:
                    logger.debug(
                        "No class/det mapping for keyword %r, reloading",
                        keyword_lower,
                    )
                    cur_x, cur_y = _click_reload(
                        solver, page, bframe, cur_x, cur_y,
                    )
                    continue
                cells = _detect_in_grid(
                    det_session, grid_image, coco_class, grid_cols=3,
                )

            # Debug: log per-tile probabilities for the target class
            if target_class is not None:
                tile_scores = [
                    f"{i}:{probs[i, target_class]:.3f}"
                    + ("*" if probs.argmax(axis=1)[i] == target_class else "")
                    for i in range(len(tiles))
                ]
                logger.info(
                    "Tile scores (class %d): %s",
                    target_class, " ".join(tile_scores),
                )

            # Collect tiles for training data
            _collect_tiles(
                image_bytes, probs, target_class,
                keyword_lower, grid_type, cells,
            )

            if not cells:
                logger.info("No tiles selected, reloading")
                _collect_det_grid(
                    keyword_lower, grid_type, "no_tiles_selected", image_bytes,
                )
                cur_x, cur_y = _click_reload(
                    solver, page, bframe, cur_x, cur_y,
                )
                continue

        logger.info(
            "Selected cells: %s (grid=%s)", cells, grid_type,
        )

        # Click tiles in random order
        random.shuffle(cells)
        for cell in cells:
            time.sleep(random.uniform(0.15, 0.45))
            cur_x, cur_y = _click_tile(
                solver, page, bframe, cell, grid_size, cur_x, cur_y,
            )

        # Handle dynamic replacements - wait for new tiles to appear
        if grid_type == "dynamic_3x3":
            # Wait for animation (tiles fade out then fade in)
            time.sleep(random.uniform(1.0, 1.5))
            cur_x, cur_y = _handle_dynamic_replacements(
                solver, page, bframe, cells, target_class,
                cls_session, grid_size, cur_x, cur_y, deadline,
                keyword=keyword_lower,
            )

        # Detect if this is an intermediate "Next" or final "Verify"
        is_next = False
        try:
            btn_text = bframe.locator(
                "#recaptcha-verify-button"
            ).text_content(timeout=2000)
            is_next = btn_text and "next" in btn_text.strip().lower()
        except Exception:
            pass

        # Click verify/next
        time.sleep(random.uniform(0.3, 0.7))
        cur_x, cur_y = _click_verify(
            solver, page, bframe, cur_x, cur_y,
        )

        if is_next:
            # Intermediate round in 4x4 sequence - not a pass/fail yet
            logger.info(
                "4x4 sequence: clicked Next on attempt %d", attempt + 1,
            )
            time.sleep(random.uniform(0.5, 1.0))
            continue

        # Final round - check for token
        time.sleep(random.uniform(0.5, 1.0))
        from wafer.browser._recaptcha import _check_token

        if _check_token(page):
            logger.info(
                "reCAPTCHA image grid solved on attempt %d", attempt + 1,
            )
            _collect_det_grid(
                keyword_lower, grid_type, "solved", image_bytes,
                {"cells_selected": sorted(cells)},
            )
            return True

        # Check for error messages
        try:
            has_error = bframe.locator(
                ".rc-imageselect-error-select-more,"
                ".rc-imageselect-error-dynamic-more"
            ).first.is_visible(timeout=500)
            if has_error:
                logger.info("Need more tiles, reloading")
                _collect_det_grid(
                    keyword_lower, grid_type, "need_more_tiles", image_bytes,
                    {"cells_selected": sorted(cells)},
                )
                cur_x, cur_y = _click_reload(
                    solver, page, bframe, cur_x, cur_y,
                )
                continue
        except Exception:
            pass

        # Check if IP is blocked by clicking audio button and reading message
        try:
            audio_btn = bframe.locator("#recaptcha-audio-button")
            if audio_btn.is_visible(timeout=500):
                audio_btn.click()
                time.sleep(0.5)
                body_text = bframe.locator("body").text_content(timeout=2000)
                if body_text and "automated queries" in body_text.lower():
                    logger.warning(
                        "IP blocked by reCAPTCHA - aborting (not a real failure)"
                    )
                    return False
        except Exception:
            pass

        # Wrong answer after Verify - genuine failure
        logger.info("Wrong answer on attempt %d", attempt + 1)
        _collect_det_grid(
            keyword_lower, grid_type, "wrong_answer", image_bytes,
            {"cells_selected": sorted(cells)},
        )
        time.sleep(random.uniform(0.5, 1.0))

    return False
