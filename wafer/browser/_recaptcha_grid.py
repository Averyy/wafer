"""reCAPTCHA v2 image grid solver (classification + D-FINE detection).

Uses two ONNX models hosted on HuggingFace (Averyyyyyy/wafer-models):
- Classification (wafer_cls_{s,x}.onnx): 14-class tile classifier for 3x3 grids
- Detection (wafer_det_{s,x}.onnx): D-FINE COCO detector for 4x4 grids

Models are lazy-loaded on first encounter via huggingface_hub.
If unavailable, returns False and the escalation chain continues.
"""

import hashlib
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

# Opt-in only: a live diagnostic can prove that the response intercepted at
# checkbox time is the same image currently exposed by the challenge DOM.
# Logs contain SHA-256 digests, never payload URLs, cookies, or image bytes.
_PAYLOAD_DIAGNOSTICS = os.environ.get("WAFER_RECAPTCHA_PAYLOAD_DIAGNOSTICS", "") == "1"

# ---------------------------------------------------------------------------
# Tile collection for training data (CLS grids only)
# ---------------------------------------------------------------------------

# 16 class names - indices 0-13 match current CLS model output,
# indices 14-15 are collection-only until the model is retrained.
_CLS_NAMES = [
    "Bicycle",
    "Bridge",
    "Bus",
    "Car",
    "Chimney",
    "Crosswalk",
    "Hydrant",
    "Motorcycle",
    "Mountain",
    "Other",
    "Palm",
    "Stair",
    "Tractor",
    "Traffic Light",
    "Boat",
    "Parking Meter",
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
            tile = img.crop(
                (
                    (idx % 3) * tw,
                    (idx // 3) * th,
                    (idx % 3 + 1) * tw,
                    (idx // 3 + 1) * th,
                )
            )
            _collect_single_tile(
                tile,
                probs[idx] if probs is not None else None,
                target_class,
                cells is not None and idx in cells,
                keyword,
                source_grid=grid_type,
                cell=idx,
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
    cell: int | None = None,
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
        if cell is not None:
            entry["cell"] = cell

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


def _collect_challenge_snapshot(bframe, deadline: float) -> str | None:
    """Persist an opt-in visual diagnostic without exposing response URLs."""

    if not _COLLECT_DET_DIR:
        return None
    try:
        timeout = _remaining_timeout_ms(deadline, 3000)
        if timeout is None:
            return None
        image_bytes = bframe.locator(
            ".rc-imageselect-challenge"
        ).screenshot(type="png", timeout=timeout)
        if not image_bytes or len(image_bytes) > _MAX_PAYLOAD_BYTES:
            return None
        filename = f"{uuid.uuid4()}.png"
        output_path = Path(_COLLECT_DET_DIR) / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(image_bytes)
        return filename
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ONNX model loading (lazy, thread-safe)
# ---------------------------------------------------------------------------

_cls_session = None
_det_session = None
_models_unavailable = False
_model_lock = threading.Lock()
_inference_lock = threading.Lock()
_warmup_done = threading.Event()
_model_load_started = False
_model_load_done = threading.Event()
_model_start_lock = threading.Lock()


_HF_REPO = "Averyyyyyy/wafer-models"
_HF_REVISION = "ee0a26676466f7c6845d75ea7f6ea46a4306bbba"
_HF_MODELS = {
    "wafer_cls_s.onnx": (
        16_572_199,
        "7a012f058e0c64160aaa9511923da66c65ca424579f18fc96a483f8638dccc65",
    ),
    "wafer_det_s.onnx": (
        41_550_413,
        "6b27ce390befa8afa7de37416084ea79b87d101635d3783f04f5308191da001b",
    ),
}


def _validate_model_asset(path: str, expected_size: int, expected_sha256: str):
    """Return ``path`` only when the pinned model bytes match provenance."""

    model_path = Path(path)
    try:
        if model_path.stat().st_size != expected_size:
            return None
        digest = hashlib.sha256()
        with model_path.open("rb") as model_file:
            for chunk in iter(lambda: model_file.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected_sha256:
            return None
    except OSError:
        return None
    return str(model_path)


def _hf_local_files_only() -> bool:
    return os.environ.get("HF_HUB_OFFLINE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _ensure_models():
    """Download + load ONNX models from HuggingFace. Thread-safe, lazy.

    Returns (cls_session, det_session). Either may be None if unavailable.
    Detection and classification are independent - one can work without the other.
    """
    global _cls_session, _det_session, _models_unavailable

    if _models_unavailable or (_cls_session is not None and _det_session is not None):
        return _cls_session, _det_session

    with _model_lock:
        if _models_unavailable or (
            _cls_session is not None and _det_session is not None
        ):
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
        cls = _cls_session
        try:
            filename = "wafer_cls_s.onnx"
            if cls is None:
                p = hf_hub_download(
                    _HF_REPO,
                    filename,
                    revision=_HF_REVISION,
                    local_files_only=_hf_local_files_only(),
                )
                p = _validate_model_asset(p, *_HF_MODELS[filename])
                if p is None:
                    logger.warning(
                        "Pinned reCAPTCHA classifier failed size/digest validation"
                    )
                else:
                    cls = ort.InferenceSession(
                        p, opts, providers=["CPUExecutionProvider"]
                    )
        except Exception:
            pass

        # det: only download "s" - "x" exists on HF as backup (248 MB vs 42 MB)
        # but hasn't been benchmarked against reCAPTCHA grids.
        det = _det_session
        try:
            filename = "wafer_det_s.onnx"
            if det is None:
                p = hf_hub_download(
                    _HF_REPO,
                    filename,
                    revision=_HF_REVISION,
                    local_files_only=_hf_local_files_only(),
                )
                p = _validate_model_asset(p, *_HF_MODELS[filename])
                if p is None:
                    logger.warning(
                        "Pinned reCAPTCHA detector failed size/digest validation"
                    )
                else:
                    det = ort.InferenceSession(
                        p, opts, providers=["CPUExecutionProvider"]
                    )
        except Exception:
            pass

        # Constructing an ONNX session is not sufficient evidence that it is
        # usable.  Run the pinned models' real zero-input contract before
        # publishing either session.  The old daemon warmup reported success
        # before this work completed and could crash an interpreter while ORT
        # still owned native threads during shutdown.
        import numpy as np

        if cls is not None and cls is not _cls_session:
            try:
                cls.run(
                    None,
                    {
                        cls.get_inputs()[0].name: np.zeros(
                            (1, 3, 224, 224), dtype=np.float32
                        )
                    },
                )
            except Exception:
                logger.warning("Pinned reCAPTCHA classifier warmup failed")
                cls = None

        if det is not None and det is not _det_session:
            try:
                det.run(
                    None,
                    {
                        "images": np.zeros((1, 3, 640, 640), dtype=np.float32),
                        "orig_target_sizes": np.array([[640, 640]], dtype=np.int64),
                    },
                )
            except Exception:
                logger.warning("Pinned reCAPTCHA detector warmup failed")
                det = None

        if cls is None and det is None:
            logger.debug("Could not prepare any ONNX models from %s", _HF_REPO)
            return None, None

        _cls_session = cls
        _det_session = det
        _warmup_done.set()

        loaded = []
        if cls:
            loaded.append("cls")
        if det:
            loaded.append("det")
        logger.info("ONNX models loaded: %s", " + ".join(loaded))
        return _cls_session, _det_session


# Budget held back from a cold model load so the returned sessions are usable.
_MODEL_WAIT_SOLVE_RESERVE = 10.0


def _ensure_models_before(deadline: float):
    """Start lazy model preparation without blocking past ``deadline``.

    Hugging Face downloads and ONNX session construction are synchronous and
    can take much longer than a browser challenge's remaining lifetime on a
    cold installation.  Keep the one shared load running in a daemon thread so
    a later challenge can reuse it, while the current solve fails closed at its
    absolute deadline instead of pinning BrowserSolver's only worker.
    """

    global _model_load_started

    if _models_unavailable or (_cls_session is not None and _det_session is not None):
        return _cls_session, _det_session

    with _model_start_lock:
        if (
            _model_load_done.is_set()
            and not (_cls_session is not None and _det_session is not None)
            and not _models_unavailable
        ):
            # An unexpected loader exception is retryable.  Normal download
            # failures set ``_models_unavailable`` and deliberately stay
            # fail-closed for this process.
            _model_load_done.clear()
            _model_load_started = False
        if not _model_load_started:
            _model_load_started = True

            def _load():
                try:
                    _ensure_models()
                except Exception:
                    logger.warning(
                        "Unexpected reCAPTCHA model preparation failure",
                        exc_info=True,
                    )
                finally:
                    _model_load_done.set()

            threading.Thread(
                target=_load,
                name="wafer-recaptcha-model-loader",
                daemon=True,
            ).start()

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None, None
    if remaining == float("inf"):
        loaded = _model_load_done.wait()
    else:
        # Reserve time to actually USE the models. Handing them back with the
        # deadline already spent just burns what is left on detection,
        # classification and clicks that cannot finish. The loader is a daemon
        # thread that keeps running either way, so giving up early here still
        # leaves the next challenge with warm models -- which is the whole
        # point of loading off-thread.
        reserve = min(_MODEL_WAIT_SOLVE_RESERVE, remaining * 0.5)
        wait_for = remaining - reserve
        if wait_for <= 0:
            return None, None
        loaded = _model_load_done.wait(timeout=wait_for)
    if not loaded:
        logger.warning("reCAPTCHA model preparation exceeded the challenge deadline")
        return None, None
    return _cls_session, _det_session


def preload_recaptcha_models(timeout: float | None = None) -> bool:
    """Prepare both pinned reCAPTCHA ONNX models.

    ``timeout`` bounds only the caller's wait.  A timed-out first download
    continues on the shared daemon loader so a later call can reuse it.  The
    function returns ``True`` only when both the classifier and detector are
    loaded; a partial model set is not browser-complete.
    """

    if timeout is not None and (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout < 0
    ):
        raise ValueError("timeout must be a non-negative number or None")
    deadline = float("inf") if timeout is None else time.monotonic() + float(timeout)
    cls_session, det_session = _ensure_models_before(deadline)
    return cls_session is not None and det_session is not None


def preflight_recaptcha_models(timeout: float | None = None) -> None:
    """Require both pinned reCAPTCHA models to be loadable.

    Deployment startup checks should use this raising form so a browser-complete
    service cannot begin listening with image-grid solving silently disabled.
    """

    if not preload_recaptcha_models(timeout=timeout):
        raise RuntimeError(
            "reCAPTCHA classifier and detector models are not both ready"
        )


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
    "boats": 8,
    "a boat": 8,
    "parking meters": 12,
    "a parking meter": 12,
}

# Classifier class index → COCO80 class mapping for 4x4 grid detection.
CLASS_TO_COCO: dict[int, int] = {
    0: 1,  # bicycle
    2: 5,  # bus
    3: 2,  # car
    6: 10,  # fire hydrant
    7: 3,  # motorcycle
    13: 9,  # traffic light
    14: 8,  # boat
    15: 12,  # parking meter
}


# ---------------------------------------------------------------------------
# Inference functions
# ---------------------------------------------------------------------------

# The classifier was trained/exported with torchvision's ImageNet transform
# (see training/recaptcha/train_mps.py and predict_cls.py).  Keep this contract
# here beside the production inference path: passing only [0, 1] RGB values
# shifts every class score and can confidently select the wrong tiles.
_CLS_MEAN = (0.485, 0.456, 0.406)
_CLS_STD = (0.229, 0.224, 0.225)


def _split_grid(image_bytes: bytes, grid_size: int = 3):
    """Split combined grid image into individual tile PIL Images."""
    from PIL import Image

    img = Image.open(io.BytesIO(image_bytes))
    w, h = img.size
    tw, th = w // grid_size, h // grid_size
    tiles = []
    for row in range(grid_size):
        for col in range(grid_size):
            tiles.append(img.crop((col * tw, row * th, (col + 1) * tw, (row + 1) * th)))
    return tiles


def _classify_tiles_batch(session, tile_images, size: int = 224):
    """Classify ImageNet-normalized RGB tiles; return (N, 14) probabilities."""
    import numpy as np
    from PIL import Image

    mean = np.asarray(_CLS_MEAN, dtype=np.float32)
    std = np.asarray(_CLS_STD, dtype=np.float32)
    blobs = []
    for img in tile_images:
        arr = np.array(
            # Match the shipped predictor exactly.  ``resize``'s default has
            # changed across Pillow releases and disagrees with the exported
            # model metadata on real grid tiles.
            img.convert("RGB").resize((size, size), Image.Resampling.BILINEAR),
            dtype=np.float32,
        )
        blobs.append((arr / 255.0 - mean) / std)
    batch = np.stack(blobs).transpose(0, 3, 1, 2)  # (N, 3, H, W)

    with _inference_lock:
        logits = session.run(None, {session.get_inputs()[0].name: batch})[0]  # (N, 14)

    # Softmax per row
    e = np.exp(logits - logits.max(axis=1, keepdims=True))
    return e / e.sum(axis=1, keepdims=True)


def _detect_in_grid(
    session,
    full_image,
    target_coco_class: int,
    grid_cols: int = 4,
    conf_thresh: float = 0.25,
    size: int = 640,
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
    blob = (np.array(padded, dtype=np.float32) / 255.0).transpose(2, 0, 1)[
        np.newaxis, ...
    ]  # (1, 3, 640, 640)

    # D-FINE: 2 inputs (images + orig_target_sizes), 3 outputs (labels, boxes, scores)
    with _inference_lock:
        labels, boxes_raw, scores = session.run(
            None,
            {
                "images": blob,
                "orig_target_sizes": np.array([[size, size]], dtype=np.int64),
            },
        )
    labels = labels[0]  # (300,)
    boxes_raw = boxes_raw[0]  # (300, 4) - x1,y1,x2,y2 in input-size coords
    scores = scores[0]  # (300,)

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
_MIN_TILE_CONFIDENCE = 0.10  # tile must exceed this to be selected


def _select_tiles(
    probs,
    target_class: int | None,
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
        if argmaxes[i] == target_class and probs[i, target_class] >= min_confidence
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
_MAX_USERVERIFY_BYTES = 64 * 1024

_RECAPTCHA_DOMAINS = frozenset(
    {
        "google.com",
        "gstatic.com",
        "recaptcha.net",
    }
)


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


def _is_userverify_url(url: str) -> bool:
    """Match only Google's exact HTTPS image-verification endpoints."""

    if not _is_recaptcha_url(url):
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    return parsed.scheme == "https" and parsed.path in {
        "/recaptcha/api2/userverify",
        "/recaptcha/enterprise/userverify",
    }


def _setup_payload_intercept(page):
    """Set up response listener to capture reCAPTCHA payload images.

    Must be called BEFORE checkbox click (payload fires during challenge load).
    Returns a dict with "payload" key (populated on capture) and "cleanup"
    callable to remove the listener when done.
    """
    captured = {
        "payload": None,
        "verify_statuses": [],
        "verify_summaries": [],
        "cleanup": lambda: None,
    }

    def _on_response(response):
        url = response.url
        if _is_userverify_url(url):
            try:
                # Retain a bounded, URL-free submission signal for live
                # diagnostics. Never retain the raw response: it can contain
                # the response token and signed continuation state.
                if len(captured["verify_statuses"]) < 8:
                    captured["verify_statuses"].append(int(response.status))
                    captured["verify_summaries"].append(
                        _safe_userverify_summary(response.body())
                    )
            except Exception:
                if (
                    len(captured["verify_summaries"])
                    < len(captured["verify_statuses"])
                ):
                    captured["verify_summaries"].append(
                        {"classification": "unreadable"}
                    )
        if _is_recaptcha_url(url) and (
            "/recaptcha/api2/payload" in url or "/recaptcha/enterprise/payload" in url
        ):
            try:
                # Keep the checkbox-era payload. Dynamic replacement payloads
                # arrive later and must be read from the current grid DOM;
                # overwriting this value made a first-grid comparison ambiguous.
                if captured["payload"] is not None:
                    return
                body = response.body()
                if len(body) <= _MAX_PAYLOAD_BYTES:
                    captured["payload"] = body
            except Exception:
                pass

    page.on("response", _on_response)
    captured["cleanup"] = lambda: page.remove_listener("response", _on_response)
    return captured


def _safe_userverify_summary(body) -> dict[str, object]:
    """Classify a Google ``uvresp`` without retaining response secrets."""

    if not isinstance(body, bytes):
        return {"classification": "unreadable"}
    if not body or len(body) > _MAX_USERVERIFY_BYTES:
        return {
            "classification": "empty" if not body else "oversize",
        }
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return {"classification": "invalid_encoding"}
    if text.startswith(")]}'"):
        text = text[4:].lstrip("\r\n")
    try:
        payload = json.loads(text)
    except (TypeError, ValueError):
        return {"classification": "invalid_json"}
    if (
        not isinstance(payload, list)
        or not payload
        or payload[0] != "uvresp"
        or len(payload) > 32
    ):
        return {"classification": "unknown_schema"}

    token = payload[1] if len(payload) > 1 else None
    token_present = isinstance(token, str) and 0 < len(token) <= 8192
    success_value = payload[2] if len(payload) > 2 else None
    success_flag = success_value is True or (
        type(success_value) is int and success_value == 1
    )
    error_present = len(payload) > 4 and payload[4] is not None
    continuation_present = len(payload) > 7 and payload[7] is not None
    if error_present:
        classification = "error"
    elif continuation_present:
        classification = "continued"
    elif success_flag and token_present:
        classification = "protocol_solved"
    else:
        classification = "unknown"
    return {
        "classification": classification,
        "token_present": token_present,
        "success_flag": success_flag,
        "error_present": error_present,
        "continuation_present": continuation_present,
    }


# ---------------------------------------------------------------------------
# Tile clicking
# ---------------------------------------------------------------------------


def _remaining_timeout_ms(deadline: float, maximum_ms: int) -> int | None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    if remaining == float("inf"):
        return maximum_ms
    return max(1, min(maximum_ms, int(remaining * 1000)))


def _sleep_with_deadline(deadline: float, duration: float) -> bool:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    if remaining == float("inf"):
        time.sleep(duration)
        return True
    time.sleep(min(duration, remaining))
    return time.monotonic() < deadline


def _click_tile(
    solver, page, bframe, cell, grid_size, cur_x, cur_y, deadline=float("inf")
):
    """Click a grid tile using mouse path replay.

    Args:
        cell: 0-based cell index (row-major).
        grid_size: 3 or 4.
        cur_x, cur_y: Current mouse position.

    Returns ``(target_x, target_y, dispatched)``. Coordinates alone cannot
    prove that a physical click reached the live tile.
    """
    tile = _grid_cell_locator(bframe, cell, grid_size)

    timeout = _remaining_timeout_ms(deadline, 3000)
    if timeout is None:
        return cur_x, cur_y, False
    try:
        box = tile.bounding_box(timeout=timeout)
    except Exception:
        return cur_x, cur_y, False

    if not box:
        return cur_x, cur_y, False

    target_x = box["x"] + box["width"] * random.uniform(0.25, 0.75)
    target_y = box["y"] + box["height"] * random.uniform(0.25, 0.75)

    # Use grid recordings if available, fall back to regular paths
    pool = solver._grid_recordings or solver._path_recordings or None
    try:
        if pool:
            replayed = solver._replay_path(
                page,
                cur_x,
                cur_y,
                target_x,
                target_y,
                pool=pool,
                deadline=deadline,
            )
            if not replayed:
                return cur_x, cur_y, False
        else:
            page.mouse.move(target_x, target_y)
    except Exception:
        page.mouse.move(target_x, target_y)

    if not _sleep_with_deadline(deadline, random.uniform(0.05, 0.15)):
        return cur_x, cur_y, False
    # Sample after path replay has entered hover and after the natural dwell.
    # A pre-movement baseline would mistake hover-only CSS changes for click
    # acknowledgment.
    before = _tile_dom_state(tile, deadline)
    if before is None:
        return cur_x, cur_y, False
    settle_deadline = min(deadline, time.monotonic() + 1.0)
    settled = None
    stable = False
    while time.monotonic() < settle_deadline:
        if not _sleep_with_deadline(settle_deadline, 0.12):
            break
        settled = _tile_dom_state(tile, settle_deadline)
        if settled is None:
            break
        if settled == before and settled["visible_image_count"] > 0:
            before = settled
            stable = True
            break
        before = settled
    if not stable:
        logger.info(
            "reCAPTCHA tile DOM did not settle before click for cell %d",
            cell,
        )
        return cur_x, cur_y, False
    page.mouse.click(target_x, target_y)

    # A non-throwing Playwright call only proves local event dispatch. Require
    # the exact live cell to acknowledge the click before the solver mutates
    # any other tile or presses Verify. Static grids add the selected class;
    # dynamic grids may replace the image before that class can be observed.
    acknowledge_deadline = min(deadline, time.monotonic() + 4.0)
    after = None
    while time.monotonic() < acknowledge_deadline:
        after = _tile_dom_state(tile, acknowledge_deadline)
        reason = (
            _tile_ack_reason(before, after) if after is not None else None
        )
        if reason is not None:
            logger.info(
                "reCAPTCHA tile click acknowledged for cell %d reason=%s",
                cell,
                reason,
            )
            return target_x, target_y, True
        if not _sleep_with_deadline(acknowledge_deadline, 0.1):
            break
    snapshot = _collect_challenge_snapshot(bframe, deadline)
    _collect_det_grid(
        "",
        f"{grid_size}x{grid_size}",
        "unacknowledged_click",
        extra={
            "cell": cell,
            "phase": "replacement" if before["replacement_src"] else "initial",
            "snapshot": snapshot,
            "before": _safe_tile_dom_state(before),
            "after": _safe_tile_dom_state(after),
        },
    )
    logger.info(
        "reCAPTCHA tile click was not acknowledged for cell %d",
        cell,
    )
    return target_x, target_y, False


def _grid_cell_locator(bframe, cell: int, grid_size: int):
    """Resolve one row-major cell without relying on a stale element handle."""

    column_selector = (
        f"td.rc-imageselect-tile:nth-child({(cell % grid_size) + 1})"
    )
    row_idx = cell // grid_size
    table_class = (
        "rc-imageselect-table-33"
        if grid_size == 3
        else "rc-imageselect-table-44"
    )
    return bframe.locator(
        f"table.{table_class} tr:nth-child({row_idx + 1}) "
        f"{column_selector}"
    )


def _tile_dom_state(tile, deadline: float) -> dict | None:
    """Read bounded in-memory acknowledgment state for one exact grid cell."""

    timeout = _remaining_timeout_ms(deadline, 500)
    if timeout is None:
        return None
    try:
        state = tile.evaluate(
            """td => {
                const replacement = td.querySelector('img.rc-image-tile-11');
                const base = td.querySelector('img.rc-image-tile-33');
                const imageStates = Array.from(
                    td.querySelectorAll('img')
                ).map(image => {
                    const style = getComputedStyle(image);
                    const rect = image.getBoundingClientRect();
                    const visible = (
                        style.display !== 'none'
                        && style.visibility !== 'hidden'
                        && Number.parseFloat(style.opacity || '1') > 0
                        && rect.width > 0
                        && rect.height > 0
                    );
                    return {
                        signature: [
                            image.className,
                            image.src,
                            style.display,
                            style.visibility,
                            style.opacity
                        ].join('|'),
                        visible
                    };
                });
                const imageSignature = imageStates.map(
                    state => state.signature
                ).join('\\n');
                const elements = [td, ...td.querySelectorAll('*')];
                const domParts = [`nodes=${elements.length}`];
                let remaining = 65536;
                for (const element of elements.slice(0, 256)) {
                    const attributes = Array.from(element.attributes)
                        .slice(0, 32)
                        .map(attribute => (
                            `${attribute.name}=${attribute.value.slice(0, 1024)}`
                        ))
                        .join(';');
                    const part = [
                        element.tagName,
                        `children=${element.childElementCount}`,
                        attributes
                    ].join('|');
                    if (part.length > remaining) {
                        domParts.push(part.slice(0, Math.max(0, remaining)));
                        remaining = 0;
                        break;
                    }
                    domParts.push(part);
                    remaining -= part.length;
                }
                const domSignature = domParts.join('\\n');
                let baseVisible = false;
                if (base) {
                    const style = getComputedStyle(base);
                    const rect = base.getBoundingClientRect();
                    baseVisible = (
                        style.display !== 'none'
                        && style.visibility !== 'hidden'
                        && Number.parseFloat(style.opacity || '1') > 0
                        && rect.width > 0
                        && rect.height > 0
                    );
                }
                return {
                    selected: td.classList.contains(
                        'rc-imageselect-tileselected'
                    ),
                    base_visible: baseVisible,
                    dom_signature: domSignature,
                    image_signature: imageSignature,
                    visible_image_count: imageStates.filter(
                        state => state.visible
                    ).length,
                    replacement_src: replacement ? replacement.src : ''
                };
            }""",
            timeout=timeout,
        )
    except Exception:
        return None
    if not isinstance(state, dict):
        return None
    selected = state.get("selected")
    base_visible = state.get("base_visible")
    dom_signature = state.get("dom_signature")
    image_signature = state.get("image_signature")
    visible_image_count = state.get("visible_image_count")
    replacement_src = state.get("replacement_src")
    if (
        not isinstance(selected, bool)
        or not isinstance(base_visible, bool)
        or not isinstance(dom_signature, str)
        or not isinstance(image_signature, str)
        or not isinstance(visible_image_count, int)
        or isinstance(visible_image_count, bool)
        or visible_image_count < 0
        or not isinstance(replacement_src, str)
    ):
        return None
    return {
        "selected": selected,
        "base_visible": base_visible,
        # Exact-cell markup is compared only after hover and never persisted.
        "dom_signature": dom_signature,
        "visible_image_count": visible_image_count,
        # Signed response URLs remain only in this in-memory equality marker.
        "image_signature": image_signature,
        # The signed URL is used only for in-memory equality and never logged.
        "replacement_src": replacement_src,
    }


def _grid_dom_states(bframe, grid_size: int, deadline: float):
    """Return exact per-cell state, or ``None`` if any cell is unresolved."""

    states = []
    for cell in range(grid_size * grid_size):
        state = _tile_dom_state(
            _grid_cell_locator(bframe, cell, grid_size),
            deadline,
        )
        if state is None:
            return None
        states.append(state)
    return states


def _wait_for_grid_stable(bframe, grid_size: int, deadline: float) -> bool:
    """Require a fully visible grid to remain unchanged before Verify."""

    settle_deadline = min(deadline, time.monotonic() + 3.0)
    previous = None
    while time.monotonic() < settle_deadline:
        current = _grid_dom_states(bframe, grid_size, settle_deadline)
        if (
            current is not None
            and all(state["visible_image_count"] > 0 for state in current)
            and current == previous
        ):
            return True
        previous = current
        if not _sleep_with_deadline(settle_deadline, 0.25):
            break
    return False


def _dynamic_base_selection_complete(
    bframe,
    grid_size: int,
    pending: set[int],
    expected_keyword: str,
    deadline: float,
) -> bool:
    """Recognize a stable base-grid selection that produced no replacements.

    Google can render a 3x3 challenge with the dynamic prompt/class while
    retaining selected base tiles instead of replacing them.  This fallback
    applies only to that exact state: every cell must still expose its base
    image, no replacement image may exist, exactly the dispatched cells must
    remain selected, and the complete DOM state must be identical for three
    observations.  A missing click or an in-flight replacement therefore
    remains a hard failure.
    """

    if not pending or not expected_keyword:
        return False
    confirmation_started = time.monotonic()
    confirmation_seconds = 2.0
    minimum_stable_seconds = 1.5
    # Do not weaken the proof merely because the outer operation is nearly
    # out of time.
    if deadline - confirmation_started < confirmation_seconds:
        return False
    settle_deadline = confirmation_started + confirmation_seconds
    previous = None
    stable_since = None
    while time.monotonic() < settle_deadline:
        current = _dynamic_base_selection_state(
            bframe,
            grid_size,
            pending,
            expected_keyword,
            settle_deadline,
        )
        observed_at = time.monotonic()
        if current is not None:
            if current == previous and stable_since is not None:
                if observed_at - stable_since >= minimum_stable_seconds:
                    return True
            else:
                stable_since = observed_at
        else:
            stable_since = None
        previous = current
        if not _sleep_with_deadline(settle_deadline, 0.25):
            break
    return False


def _dynamic_base_selection_state(
    bframe,
    grid_size: int,
    expected_cells: set[int],
    expected_keyword: str,
    deadline: float,
):
    """Return the exact fallback state only while every invariant holds."""

    snapshot = _atomic_dynamic_base_snapshot(bframe, grid_size, deadline)
    if snapshot is None:
        return None
    current = snapshot["states"]
    current_keyword = snapshot["keyword"]
    if (
        len(current) != grid_size * grid_size
        or current_keyword.lower().strip() != expected_keyword.lower().strip()
        or any(
            state["visible_image_count"] <= 0
            or not state["base_visible"]
            or bool(state["replacement_src"])
            for state in current
        )
        or {
            cell
            for cell, state in enumerate(current)
            if state["selected"]
        }
        != expected_cells
    ):
        return None
    return current


def _atomic_dynamic_base_snapshot(bframe, grid_size: int, deadline: float):
    """Read prompt and every exact cell in one browser event-loop turn."""

    timeout = _remaining_timeout_ms(deadline, 500)
    if timeout is None:
        return None
    table_class = (
        "rc-imageselect-table-33"
        if grid_size == 3
        else "rc-imageselect-table-44"
    )
    try:
        snapshot = bframe.locator("body").evaluate(
            """(body, tableClass) => {
                const prompts = Array.from(body.querySelectorAll(
                    '.rc-imageselect-desc-wrapper strong'
                )).filter(prompt => {
                    const style = getComputedStyle(prompt);
                    const rect = prompt.getBoundingClientRect();
                    return (
                        Boolean((prompt.textContent || '').trim())
                        && style.display !== 'none'
                        && style.visibility !== 'hidden'
                        && Number.parseFloat(style.opacity || '1') > 0
                        && rect.width > 0
                        && rect.height > 0
                    );
                });
                const cells = Array.from(body.querySelectorAll(
                    `table.${CSS.escape(tableClass)} ` +
                    'td.rc-imageselect-tile'
                ));
                const states = cells.map(td => {
                    const replacement = td.querySelector(
                        'img.rc-image-tile-11'
                    );
                    const base = td.querySelector('img.rc-image-tile-33');
                    const imageStates = Array.from(
                        td.querySelectorAll('img')
                    ).map(image => {
                        const style = getComputedStyle(image);
                        const rect = image.getBoundingClientRect();
                        return {
                            signature: [
                                image.className,
                                image.src,
                                style.display,
                                style.visibility,
                                style.opacity
                            ].join('|'),
                            visible: (
                                style.display !== 'none'
                                && style.visibility !== 'hidden'
                                && Number.parseFloat(style.opacity || '1') > 0
                                && rect.width > 0
                                && rect.height > 0
                            )
                        };
                    });
                    const elements = [td, ...td.querySelectorAll('*')];
                    const domParts = [`nodes=${elements.length}`];
                    let remaining = 65536;
                    for (const element of elements.slice(0, 256)) {
                        const attributes = Array.from(element.attributes)
                            .slice(0, 32)
                            .map(attribute => (
                                `${attribute.name}=` +
                                attribute.value.slice(0, 1024)
                            ))
                            .join(';');
                        const part = [
                            element.tagName,
                            `children=${element.childElementCount}`,
                            attributes
                        ].join('|');
                        if (part.length > remaining) {
                            domParts.push(part.slice(
                                0,
                                Math.max(0, remaining)
                            ));
                            remaining = 0;
                            break;
                        }
                        domParts.push(part);
                        remaining -= part.length;
                    }
                    let baseVisible = false;
                    if (base) {
                        const style = getComputedStyle(base);
                        const rect = base.getBoundingClientRect();
                        baseVisible = (
                            style.display !== 'none'
                            && style.visibility !== 'hidden'
                            && Number.parseFloat(style.opacity || '1') > 0
                            && rect.width > 0
                            && rect.height > 0
                        );
                    }
                    return {
                        selected: td.classList.contains(
                            'rc-imageselect-tileselected'
                        ),
                        base_visible: baseVisible,
                        dom_signature: domParts.join('\\n'),
                        image_signature: imageStates.map(
                            state => state.signature
                        ).join('\\n'),
                        visible_image_count: imageStates.filter(
                            state => state.visible
                        ).length,
                        replacement_src: replacement ? replacement.src : ''
                    };
                });
                return {
                    keyword: (
                        prompts.length === 1
                            ? prompts[0].textContent
                            : null
                    ),
                    states
                };
            }""",
            table_class,
            timeout=timeout,
        )
    except Exception:
        return None
    if not isinstance(snapshot, dict):
        return None
    keyword = snapshot.get("keyword")
    states = snapshot.get("states")
    if not isinstance(keyword, str) or not keyword.strip():
        return None
    if not isinstance(states, list) or len(states) != grid_size * grid_size:
        return None
    validated = []
    for state in states:
        if not isinstance(state, dict):
            return None
        selected = state.get("selected")
        base_visible = state.get("base_visible")
        dom_signature = state.get("dom_signature")
        image_signature = state.get("image_signature")
        visible_image_count = state.get("visible_image_count")
        replacement_src = state.get("replacement_src")
        if (
            not isinstance(selected, bool)
            or not isinstance(base_visible, bool)
            or not isinstance(dom_signature, str)
            or not isinstance(image_signature, str)
            or not isinstance(visible_image_count, int)
            or isinstance(visible_image_count, bool)
            or visible_image_count < 0
            or not isinstance(replacement_src, str)
        ):
            return None
        validated.append(
            {
                "selected": selected,
                "base_visible": base_visible,
                "dom_signature": dom_signature,
                "image_signature": image_signature,
                "visible_image_count": visible_image_count,
                "replacement_src": replacement_src,
            }
        )
    return {"keyword": keyword, "states": validated}


def _safe_dynamic_base_summary(
    bframe,
    grid_size: int,
    expected_cells: set[int],
    expected_keyword: str,
    deadline: float,
) -> dict[str, object]:
    """Summarize fallback predicates without retaining DOM or image URLs."""

    snapshot = _atomic_dynamic_base_snapshot(bframe, grid_size, deadline)
    if snapshot is None:
        return {"readable": False}
    states = snapshot["states"]
    return {
        "readable": True,
        "keyword_match": (
            snapshot["keyword"].lower().strip()
            == expected_keyword.lower().strip()
        ),
        "cell_count": len(states),
        "selected_cells": [
            cell
            for cell, state in enumerate(states)
            if state["selected"]
        ],
        "expected_cells": sorted(expected_cells),
        "base_visible_count": sum(
            bool(state["base_visible"]) for state in states
        ),
        "replacement_count": sum(
            bool(state["replacement_src"]) for state in states
        ),
        "all_cells_visible": all(
            state["visible_image_count"] > 0 for state in states
        ),
    }


def _current_grid_keyword(bframe, deadline: float) -> str | None:
    """Return the exact current target keyword for round-identity checks."""

    timeout = _remaining_timeout_ms(deadline, 250)
    if timeout is None:
        return None
    try:
        keyword = bframe.locator(
            ".rc-imageselect-desc-wrapper strong"
        ).text_content(timeout=timeout)
    except Exception:
        return None
    if not isinstance(keyword, str) or not keyword.strip():
        return None
    return keyword


def _tile_ack_reason(before: dict, after: dict) -> str | None:
    """Return the exact non-final UI transition acknowledging one click."""

    if after["selected"] and not before["selected"]:
        return "selected"
    if (
        after["replacement_src"]
        and after["replacement_src"] != before["replacement_src"]
    ):
        return "replacement_src"
    if (
        before["visible_image_count"] > 0
        and after["visible_image_count"] == 0
    ):
        return "all_images_hidden"
    if before["base_visible"] and not after["base_visible"]:
        return "base_hidden"
    if after["dom_signature"] != before["dom_signature"]:
        return "dom_mutation"
    return None


def _safe_tile_dom_state(state: dict | None) -> dict | None:
    """Hash image identities before opt-in diagnostics reach disk."""

    if state is None:
        return None
    return {
        "selected": state["selected"],
        "base_visible": state["base_visible"],
        "visible_image_count": state["visible_image_count"],
        "replacement_present": bool(state["replacement_src"]),
        "image_signature_sha256": hashlib.sha256(
            state["image_signature"].encode()
        ).hexdigest(),
        "dom_signature_sha256": hashlib.sha256(
            state["dom_signature"].encode()
        ).hexdigest(),
    }


def _click_verify(
    solver,
    page,
    bframe,
    cur_x,
    cur_y,
    deadline=float("inf"),
    *,
    preclick_guard=None,
):
    """Wait for an actionable Verify button, then click it by mouse path."""
    button = bframe.locator("#recaptcha-verify-button")
    ready_deadline = min(deadline, time.monotonic() + 3.0)
    box = None
    while time.monotonic() < ready_deadline:
        timeout = _remaining_timeout_ms(ready_deadline, 300)
        if timeout is None:
            return cur_x, cur_y, False
        try:
            visible = button.is_visible(timeout=timeout)
            enabled = button.is_enabled(timeout=timeout)
            disabled = button.get_attribute("disabled", timeout=timeout)
            aria_disabled = button.get_attribute("aria-disabled", timeout=timeout)
            class_name = button.get_attribute("class", timeout=timeout) or ""
            disabled_class = "disabled" in class_name.lower().split()
            logger.info(
                "reCAPTCHA diagnostic: phase=verify-ready visible=%s "
                "enabled=%s disabled_attr=%s aria_disabled=%s "
                "disabled_class=%s",
                bool(visible),
                bool(enabled),
                bool(disabled is not None),
                aria_disabled == "true",
                disabled_class,
            )
            if (
                visible
                and enabled
                and disabled is None
                and aria_disabled != "true"
                and not disabled_class
            ):
                box = button.bounding_box(timeout=timeout)
                if box:
                    break
        except Exception:
            pass
        if not _sleep_with_deadline(ready_deadline, 0.1):
            return cur_x, cur_y, False

    if not box:
        return cur_x, cur_y, False

    target_x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
    target_y = box["y"] + box["height"] * random.uniform(0.3, 0.7)

    pool = solver._grid_recordings or solver._path_recordings or None
    try:
        if pool:
            replayed = solver._replay_path(
                page,
                cur_x,
                cur_y,
                target_x,
                target_y,
                pool=pool,
                deadline=deadline,
            )
            if not replayed:
                return cur_x, cur_y, False
        else:
            page.mouse.move(target_x, target_y)
    except Exception:
        page.mouse.move(target_x, target_y)

    if not _sleep_with_deadline(deadline, random.uniform(0.08, 0.22)):
        return cur_x, cur_y, False
    if preclick_guard is not None:
        try:
            guard_ready = bool(preclick_guard())
        except Exception:
            guard_ready = False
        if not guard_ready:
            logger.info(
                "reCAPTCHA pre-Verify fallback invariants changed; "
                "preserving grid",
            )
            return cur_x, cur_y, False
    page.mouse.click(target_x, target_y)
    try:
        timeout = _remaining_timeout_ms(deadline, 300)
        focused = (
            button.evaluate("el => document.activeElement === el", timeout=timeout)
            if timeout is not None
            else False
        )
    except Exception:
        focused = False
    logger.info(
        "reCAPTCHA diagnostic: phase=verify-clicked focused=%s",
        bool(focused),
    )
    return target_x, target_y, True


def _click_reload(solver, page, bframe, cur_x, cur_y, deadline=float("inf")):
    """Click the reload button to get a new challenge."""
    timeout = _remaining_timeout_ms(deadline, 3000)
    if timeout is None:
        return cur_x, cur_y, False
    try:
        box = bframe.locator("#recaptcha-reload-button").bounding_box(timeout=timeout)
    except Exception:
        return cur_x, cur_y, False
    if not box:
        return cur_x, cur_y, False

    target_x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
    target_y = box["y"] + box["height"] * random.uniform(0.3, 0.7)

    pool = solver._path_recordings or None
    try:
        if pool:
            replayed = solver._replay_path(
                page,
                cur_x,
                cur_y,
                target_x,
                target_y,
                pool=pool,
                deadline=deadline,
            )
            if not replayed:
                return cur_x, cur_y, False
        else:
            page.mouse.move(target_x, target_y)
    except Exception:
        page.mouse.move(target_x, target_y)

    if not _sleep_with_deadline(deadline, random.uniform(0.08, 0.22)):
        return cur_x, cur_y, False
    page.mouse.click(target_x, target_y)
    _sleep_with_deadline(deadline, random.uniform(1.5, 2.5))
    return target_x, target_y, True


# ---------------------------------------------------------------------------
# Dynamic replacement handler (3x3 grids where tiles refresh after clicking)
# ---------------------------------------------------------------------------


def _handle_dynamic_replacements(
    solver,
    page,
    bframe,
    clicked_cells,
    target_class,
    cls_session,
    grid_size,
    cur_x,
    cur_y,
    deadline,
    keyword: str = "",
    trace: list[dict] | None = None,
):
    """Poll for replacement tiles and re-classify them.

    After clicking correct tiles in a dynamic 3x3 grid, reCAPTCHA replaces
    them with new images. The original tile (img.rc-image-tile-33) is removed
    and a new individual tile (img.rc-image-tile-11) appears in its place.
    We detect these replacements, download and classify the new tiles,
    and click any new matches.
    """
    from PIL import Image

    if target_class is None or cls_session is None:
        # Dynamic replacement tiles are individual images. Without a CLS
        # target we cannot safely carry a whole-grid COCO decision into those
        # replacements; never silently drop them and submit a partial answer.
        logger.info("Dynamic grid has no replacement classifier target")
        return cur_x, cur_y, False

    pending = set(clicked_cells)
    seen_urls: set[str] = set()  # Track URLs we've already classified
    round_num = 0

    logger.info(
        "Dynamic replacement: watching cells %s",
        sorted(pending),
    )

    while pending and time.monotonic() < deadline:
        round_num += 1

        # Wait for NEW replacement tiles (rc-image-tile-11) to appear.
        # After clicking a tile-33, it gets removed and a tile-11 appears.
        # After clicking a tile-11, it gets replaced with a new tile-11.
        new_tiles: dict[int, str] = {}
        wait_deadline = min(deadline, time.monotonic() + 5.0)
        while time.monotonic() < wait_deadline:
            if not _sleep_with_deadline(wait_deadline, 0.4):
                break
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
            stable_base_selection = _dynamic_base_selection_complete(
                bframe,
                grid_size,
                pending,
                keyword,
                deadline,
            )
            fallback_summary = (
                None
                if stable_base_selection
                else _safe_dynamic_base_summary(
                    bframe,
                    grid_size,
                    pending,
                    keyword,
                    deadline,
                )
            )
            snapshot = (
                None
                if stable_base_selection
                else _collect_challenge_snapshot(bframe, deadline)
            )
            if trace is not None:
                trace.append(
                    {
                        "round": round_num,
                        "pending": sorted(pending),
                        "outcome": (
                            "stable_base_selection"
                            if stable_base_selection
                            else "no_replacements"
                        ),
                        "snapshot": snapshot,
                        **(
                            {"fallback_summary": fallback_summary}
                            if not stable_base_selection
                            else {}
                        ),
                    }
                )
            if stable_base_selection:
                logger.info(
                    "Dynamic round %d retained an exact stable base-grid "
                    "selection; proceeding to authoritative Verify",
                    round_num,
                )
                return cur_x, cur_y, True
            logger.info(
                "Dynamic base-grid fallback rejected: %s",
                fallback_summary,
            )
            logger.info(
                "Dynamic round %d: no new tiles for cells %s",
                round_num,
                sorted(pending),
            )
            # A transition can be slow, absent, or follow a missed click.
            # None of those states proves that the previous selection is
            # complete, so never submit it as though it did.
            return cur_x, cur_y, False

        if set(new_tiles) != pending:
            logger.info(
                "Dynamic round %d missing replacement cells %s",
                round_num,
                sorted(pending - set(new_tiles)),
            )
            return cur_x, cur_y, False

        logger.info(
            "Dynamic round %d: %d new tiles, classifying",
            round_num,
            len(new_tiles),
        )

        # Mark these URLs as seen
        seen_urls.update(new_tiles.values())

        # Download and classify replacement tiles
        unresolved = set(pending)
        new_matches = []
        round_trace = {
            "round": round_num,
            "pending": sorted(pending),
            "observed_cells": sorted(new_tiles),
            "classifications": [],
            "clicks": [],
        }
        for cell, tile_url in new_tiles.items():
            try:
                if not _is_recaptcha_url(tile_url):
                    continue
                timeout = _remaining_timeout_ms(deadline, 5000)
                if timeout is None:
                    break
                resp = page.request.get(tile_url, timeout=timeout)
                if resp.status != 200:
                    continue
                body = resp.body()
                if not body or len(body) > _MAX_PAYLOAD_BYTES:
                    continue
                tile_img = Image.open(io.BytesIO(body))
                probs = _classify_tiles_batch(cls_session, [tile_img])
                unresolved.discard(cell)
                is_target = (
                    probs.argmax(axis=1)[0] == target_class
                    and probs[0, target_class] >= _MIN_TILE_CONFIDENCE
                )
                logger.info(
                    "Replacement cell %d: score=%.3f argmax=%d %s",
                    cell,
                    probs[0, target_class],
                    probs.argmax(axis=1)[0],
                    "MATCH" if is_target else "skip",
                )
                round_trace["classifications"].append(
                    {
                        "cell": cell,
                        "target_score": round(float(probs[0, target_class]), 4),
                        "argmax": int(probs.argmax(axis=1)[0]),
                        "selected": bool(is_target),
                    }
                )
                # Collect replacement tile for training
                _collect_single_tile(
                    tile_img,
                    probs[0],
                    target_class,
                    is_target,
                    keyword,
                    source_grid="dynamic_3x3",
                    cell=cell,
                )
                if is_target:
                    new_matches.append(cell)
            except Exception:
                continue

        if unresolved:
            if trace is not None:
                trace.append(round_trace)
            logger.info(
                "Dynamic round %d has unresolved replacement cells %s",
                round_num,
                sorted(unresolved),
            )
            return cur_x, cur_y, False
        if not new_matches:
            if trace is not None:
                trace.append(round_trace)
            logger.info("Dynamic round %d: no matches", round_num)
            # Every observed replacement was classified as non-target, which
            # completes this dynamic branch and permits the final Verify.
            pending.clear()
            continue

        logger.info(
            "Dynamic round %d: clicking %s",
            round_num,
            new_matches,
        )

        pending = set()
        random.shuffle(new_matches)
        for cell in new_matches:
            if not _sleep_with_deadline(deadline, random.uniform(0.2, 0.5)):
                break
            cur_x, cur_y, dispatched = _click_tile(
                solver,
                page,
                bframe,
                cell,
                grid_size,
                cur_x,
                cur_y,
                deadline,
            )
            if not dispatched:
                round_trace["clicks"].append({"cell": cell, "dispatched": False})
                if trace is not None:
                    trace.append(round_trace)
                logger.info(
                    "Dynamic round %d: click did not dispatch for cell %d",
                    round_num,
                    cell,
                )
                return cur_x, cur_y, False
            round_trace["clicks"].append({"cell": cell, "dispatched": True})
            pending.add(cell)

        if trace is not None:
            trace.append(round_trace)

    return cur_x, cur_y, not pending


# ---------------------------------------------------------------------------
# Grid type detection
# ---------------------------------------------------------------------------


def _detect_grid_type(bframe, deadline: float = float("inf")):
    """Detect grid type from DOM structure.

    Uses the actual table class (rc-imageselect-table-33 vs table-44)
    and tile count to determine grid type, avoiding locale-dependent
    text matching.

    Returns ("static_3x3" | "dynamic_3x3" | "4x4", keyword_text).
    """
    # Extract target keyword from <strong> element
    timeout = _remaining_timeout_ms(deadline, 3000)
    if timeout is None:
        return None, None
    try:
        keyword = bframe.locator(".rc-imageselect-desc-wrapper strong").text_content(
            timeout=timeout
        )
    except Exception:
        keyword = None

    if not keyword:
        return None, None

    # Detect 4x4 by table class (rc-imageselect-table-44)
    timeout = _remaining_timeout_ms(deadline, 500)
    if timeout is None:
        return None, None
    try:
        is_4x4 = bframe.locator("table.rc-imageselect-table-44").is_visible(
            timeout=timeout
        )
        if is_4x4:
            return "4x4", keyword
    except Exception:
        pass

    # 3x3 grid - detect dynamic vs static by checking if the
    # desc uses the "no" class (rc-imageselect-desc-no-canonical)
    # which indicates "select all matching images" (dynamic replacement)
    timeout = _remaining_timeout_ms(deadline, 500)
    if timeout is None:
        return None, None
    try:
        is_dynamic = bframe.locator(".rc-imageselect-desc-no-canonical").is_visible(
            timeout=timeout
        )
        if is_dynamic:
            return "dynamic_3x3", keyword
    except Exception:
        pass

    return "static_3x3", keyword


def _grid_state_marker(bframe, deadline: float):
    """Return a non-content marker for detecting a replacement challenge."""

    try:
        timeout = _remaining_timeout_ms(deadline, 250)
        if timeout is None:
            return None
        image_src = bframe.locator(
            "img.rc-image-tile-33, img.rc-image-tile-44"
        ).first.get_attribute("src", timeout=timeout)
        timeout = _remaining_timeout_ms(deadline, 250)
        if timeout is None:
            return None
        prompt = bframe.locator(".rc-imageselect-desc-wrapper").text_content(
            timeout=timeout
        )
        timeout = _remaining_timeout_ms(deadline, 250)
        if timeout is None:
            return None
        button = bframe.locator("#recaptcha-verify-button").text_content(
            timeout=timeout
        )
        return (
            image_src or "",
            prompt or "",
            button or "",
        )
    except Exception:
        return None


def _safe_grid_state_marker(marker):
    """Return diagnostic state without persisting signed payload URLs."""

    if marker is None:
        return None
    image_src, prompt, button = marker
    return {
        "image_src_sha256": hashlib.sha256(image_src.encode()).hexdigest(),
        "prompt": prompt,
        "button": button,
    }


def _wait_for_post_verify_outcome(
    page,
    bframe,
    deadline: float,
    previous_marker,
    token_baseline: set[str] | None = None,
    token_widget=None,
    *,
    maximum: float = 10.0,
    protocol_intermediate_ready=None,
) -> str:
    """Poll authoritative image-grid outcomes without switching CAPTCHA mode."""

    from wafer.browser._recaptcha import _check_token

    outcome_deadline = min(deadline, time.monotonic() + maximum)
    while time.monotonic() < outcome_deadline:
        if _check_token(page, token_baseline, token_widget):
            return "solved"
        if protocol_intermediate_ready is not None:
            try:
                if protocol_intermediate_ready():
                    return "protocol_intermediate"
            except Exception:
                pass
        for selector, outcome in (
            (
                ".rc-imageselect-error-select-more,.rc-imageselect-error-dynamic-more",
                "more",
            ),
            (".rc-imageselect-incorrect-response", "incorrect"),
        ):
            timeout = _remaining_timeout_ms(outcome_deadline, 250)
            if timeout is None:
                return "pending"
            try:
                if bframe.locator(selector).first.is_visible(timeout=timeout):
                    return outcome
            except Exception:
                pass
        marker = _grid_state_marker(bframe, outcome_deadline)
        if (
            previous_marker is not None
            and marker is not None
            and marker != previous_marker
        ):
            return "changed"
        if not _sleep_with_deadline(outcome_deadline, 0.2):
            break
    return "pending"


def _has_new_protocol_solved_response(
    diagnostics: dict | None,
    count_before: int,
) -> bool:
    """Require one aligned, exact-200, token-bearing accepted ``uvresp``."""

    if diagnostics is None:
        return False
    statuses = diagnostics.get("verify_statuses")
    summaries = diagnostics.get("verify_summaries")
    if (
        not isinstance(statuses, list)
        or not isinstance(summaries, list)
        or len(statuses) != len(summaries)
        or len(statuses) <= count_before
        or statuses[-1] != 200
        or not isinstance(summaries[-1], dict)
    ):
        return False
    return summaries[-1].get("classification") == "protocol_solved"


# ---------------------------------------------------------------------------
# Main solve loop
# ---------------------------------------------------------------------------


def solve_image_grid(
    solver,
    page,
    bframe,
    state,
    deadline,
    payload: bytes | None = None,
    diagnostics: dict | None = None,
    token_baseline: set[str] | None = None,
    token_widget=None,
    max_attempts: int = 12,
    protocol_completion_is_intermediate: bool = False,
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
    logger.info(
        "reCAPTCHA diagnostic: phase=grid-model-prepare remaining_ms=%d",
        max(0, int((deadline - time.monotonic()) * 1000)),
    )
    cls_session, det_session = _ensure_models_before(deadline)
    if cls_session is None and det_session is None:
        logger.debug("No ONNX models available, skipping image grid solver")
        return False
    logger.info(
        "reCAPTCHA diagnostic: phase=grid-model-ready remaining_ms=%d",
        max(0, int((deadline - time.monotonic()) * 1000)),
    )

    # Ensure recordings are loaded (for mouse replay).  Keep an explicit,
    # bounded timing trace here: a cold recording load and an unready grid
    # look identical from outside the browser, but need different fixes.
    recordings_started = time.monotonic()
    logger.info(
        "reCAPTCHA diagnostic: phase=recordings-prepare remaining_ms=%d",
        max(0, int((deadline - recordings_started) * 1000)),
    )
    recordings_ready = solver._ensure_recordings()
    logger.info(
        "reCAPTCHA diagnostic: phase=recordings-ready loaded=%s "
        "elapsed_ms=%d remaining_ms=%d",
        bool(recordings_ready),
        max(0, int((time.monotonic() - recordings_started) * 1000)),
        max(0, int((deadline - time.monotonic()) * 1000)),
    )
    if time.monotonic() >= deadline:
        return False

    cur_x = state.current_x if state else random.uniform(400, 700)
    cur_y = state.current_y if state else random.uniform(300, 500)
    for attempt in range(max_attempts):
        if time.monotonic() > deadline:
            logger.debug("Image grid solver deadline exceeded")
            break

        # Detect grid type and target
        detect_started = time.monotonic()
        grid_type, keyword = _detect_grid_type(bframe, deadline)
        logger.info(
            "reCAPTCHA diagnostic: phase=grid-detect "
            "selector_present=%s grid_type=%s keyword=%s elapsed_ms=%d "
            "remaining_ms=%d",
            bool(grid_type),
            grid_type or "none",
            (keyword or "none").lower().strip(),
            max(0, int((time.monotonic() - detect_started) * 1000)),
            max(0, int((deadline - time.monotonic()) * 1000)),
        )
        if not grid_type or not keyword:
            if attempt < 3:
                # Challenge may still be loading
                logger.debug(
                    "Grid type not ready (attempt %d), waiting...",
                    attempt,
                )
                if not _sleep_with_deadline(deadline, 1.5):
                    break
                continue
            logger.debug("Could not detect grid type or keyword")
            break

        keyword_lower = keyword.lower().strip()
        target_class = KEYWORD_TO_CLASS.get(keyword_lower)
        prediction_summary = None
        click_dispatches: list[dict] = []
        dynamic_trace: list[dict] = []

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
                    "rc-image-tile-44" if grid_type == "4x4" else "rc-image-tile-33"
                )
                timeout = _remaining_timeout_ms(deadline, 3000)
                if timeout is None:
                    break
                img_src = bframe.locator(f"img.{tile_class}").first.get_attribute(
                    "src", timeout=timeout
                )
                if img_src and (
                    _is_recaptcha_url(img_src) or img_src.startswith("data:")
                ):
                    timeout = _remaining_timeout_ms(deadline, 5000)
                    if timeout is None:
                        break
                    resp = page.request.get(img_src, timeout=timeout)
                    if resp.status == 200:
                        body = resp.body()
                        if body and len(body) <= _MAX_PAYLOAD_BYTES:
                            _collect_det_grid(
                                keyword_lower,
                                grid_type,
                                "unknown_keyword",
                                body,
                            )
            except Exception:
                _collect_det_grid(keyword_lower, grid_type, "unknown_keyword")
            cur_x, cur_y, reloaded = _click_reload(
                solver,
                page,
                bframe,
                cur_x,
                cur_y,
                deadline,
            )
            if not reloaded:
                return False
            continue

        logger.info(
            "reCAPTCHA image grid attempt %d: %s, keyword=%r, class=%s",
            attempt + 1,
            grid_type,
            keyword_lower,
            target_class if target_class is not None else f"coco:{coco_direct}",
        )

        # Get payload image - try intercepted payload first (attempt 1)
        from PIL import Image

        image_bytes = None
        intercepted_payload = False
        dom_payload_resolved = False
        if payload is not None and attempt == 0:
            image_bytes = payload
            payload = None  # Only use intercepted payload once
            intercepted_payload = True

        # Always resolve the current bframe payload. An interception from a
        # different widget or a stale replacement must never become model
        # input merely because it arrived first.
        if not image_bytes or intercepted_payload:
            # Tiles are CSS-cropped from a single payload image.
            # Both 3x3 (rc-image-tile-33) and 4x4 (rc-image-tile-44)
            # share the same src URL across all tiles.
            tile_class = (
                "rc-image-tile-44" if grid_type == "4x4" else "rc-image-tile-33"
            )
            try:
                timeout = _remaining_timeout_ms(deadline, 3000)
                if timeout is None:
                    break
                img_src = bframe.locator(f"img.{tile_class}").first.get_attribute(
                    "src", timeout=timeout
                )
                if img_src and (
                    _is_recaptcha_url(img_src) or img_src.startswith("data:")
                ):
                    timeout = _remaining_timeout_ms(deadline, 5000)
                    if timeout is None:
                        break
                    resp = page.request.get(img_src, timeout=timeout)
                    if resp.status == 200:
                        body = resp.body()
                        if body and len(body) <= _MAX_PAYLOAD_BYTES:
                            if intercepted_payload:
                                payload_matches_dom = body == image_bytes
                                if _PAYLOAD_DIAGNOSTICS:
                                    logger.info(
                                        "reCAPTCHA diagnostic: "
                                        "phase=payload-dom-compare match=%s "
                                        "intercept_sha256=%s dom_sha256=%s",
                                        payload_matches_dom,
                                        hashlib.sha256(image_bytes).hexdigest(),
                                        hashlib.sha256(body).hexdigest(),
                                    )
                                # The DOM payload is authoritative even when
                                # the optional diagnostic reports a mismatch.
                                image_bytes = body
                            else:
                                image_bytes = body
                            dom_payload_resolved = True
            except Exception:
                pass

        if intercepted_payload and not dom_payload_resolved:
            # Do not guess from an interception whose widget identity could
            # not be verified against the visible challenge.
            image_bytes = None

        if not image_bytes:
            logger.debug("Could not get grid image, reloading")
            cur_x, cur_y, reloaded = _click_reload(
                solver,
                page,
                bframe,
                cur_x,
                cur_y,
                deadline,
            )
            if not reloaded:
                return False
            continue

        grid_image = Image.open(io.BytesIO(image_bytes))

        if grid_type == "4x4":
            if det_session is None:
                logger.debug("4x4 grid but no detection model, reloading")
                cur_x, cur_y, reloaded = _click_reload(
                    solver,
                    page,
                    bframe,
                    cur_x,
                    cur_y,
                    deadline,
                )
                if not reloaded:
                    return False
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
                    keyword_lower,
                    grid_type,
                    "no_coco_class",
                    image_bytes,
                )
                cur_x, cur_y, reloaded = _click_reload(
                    solver,
                    page,
                    bframe,
                    cur_x,
                    cur_y,
                    deadline,
                )
                if not reloaded:
                    return False
                continue

            cells = _detect_in_grid(
                det_session,
                grid_image,
                coco_class,
                grid_cols=4,
            )
            grid_size = 4

            if not cells:
                # A Skip is still a submission: route it through the same
                # state machine as Verify so a delayed token/new grid is not
                # mislabelled as a detector error.
                logger.info("4x4 grid: no detections, submitting Skip")

            logger.info(
                "4x4 COCO detection: cells=%s (coco_class=%d)",
                cells,
                coco_class,
            )
        else:
            # 3x3 grids: tile-by-tile classification
            if cls_session is None:
                logger.debug("3x3 grid but no classification model, skipping")
                break

            grid_size = 3
            tiles = _split_grid(image_bytes, grid_size=3)
            probs = _classify_tiles_batch(cls_session, tiles)
            prediction_summary = [
                {
                    "cell": index,
                    "target_score": round(float(probs[index, target_class]), 4)
                    if target_class is not None
                    else None,
                    "argmax": int(probs[index].argmax()),
                    "argmax_score": round(float(probs[index].max()), 4),
                }
                for index in range(len(tiles))
            ]

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
                    cur_x, cur_y, reloaded = _click_reload(
                        solver,
                        page,
                        bframe,
                        cur_x,
                        cur_y,
                        deadline,
                    )
                    if not reloaded:
                        return False
                    continue
                cells = _detect_in_grid(
                    det_session,
                    grid_image,
                    coco_class,
                    grid_cols=3,
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
                    target_class,
                    " ".join(tile_scores),
                )

            # Collect tiles for training data
            _collect_tiles(
                image_bytes,
                probs,
                target_class,
                keyword_lower,
                grid_type,
                cells,
            )

            if not cells:
                logger.info("No tiles selected, reloading")
                _collect_det_grid(
                    keyword_lower,
                    grid_type,
                    "no_tiles_selected",
                    image_bytes,
                )
                cur_x, cur_y, reloaded = _click_reload(
                    solver,
                    page,
                    bframe,
                    cur_x,
                    cur_y,
                    deadline,
                )
                if not reloaded:
                    return False
                continue

        logger.info(
            "Selected cells: %s (grid=%s)",
            cells,
            grid_type,
        )

        # Click tiles in random order. A no-op path or lost target must never
        # be followed by Verify on a partial selection.
        random.shuffle(cells)
        clicked_cells = []
        for cell in cells:
            if not _sleep_with_deadline(deadline, random.uniform(0.15, 0.45)):
                return False
            cur_x, cur_y, dispatched = _click_tile(
                solver,
                page,
                bframe,
                cell,
                grid_size,
                cur_x,
                cur_y,
                deadline,
            )
            if not dispatched:
                click_dispatches.append({"cell": cell, "dispatched": False})
                logger.info("Grid tile click did not dispatch for cell %d", cell)
                return False
            click_dispatches.append({"cell": cell, "dispatched": True})
            clicked_cells.append(cell)
        if time.monotonic() >= deadline:
            break

        # Handle dynamic replacements - wait for new tiles to appear
        dynamic_base_fallback = False
        if grid_type == "dynamic_3x3":
            # Wait for animation (tiles fade out then fade in)
            if not _sleep_with_deadline(deadline, random.uniform(1.0, 1.5)):
                break
            cur_x, cur_y, dynamic_complete = _handle_dynamic_replacements(
                solver,
                page,
                bframe,
                clicked_cells,
                target_class,
                cls_session,
                grid_size,
                cur_x,
                cur_y,
                deadline,
                keyword=keyword_lower,
                trace=dynamic_trace,
            )
            if not dynamic_complete:
                logger.info(
                    "Dynamic replacements unresolved; preserving grid without Verify"
                )
                _collect_det_grid(
                    keyword_lower,
                    grid_type,
                    "dynamic_unresolved",
                    image_bytes,
                    {
                        "cells_selected": sorted(cells),
                        "target_class": target_class,
                        "initial_predictions": prediction_summary,
                        "initial_clicks": click_dispatches,
                        "dynamic_trace": dynamic_trace,
                    },
                )
                return False
            dynamic_base_fallback = bool(
                dynamic_trace
                and dynamic_trace[-1].get("outcome")
                == "stable_base_selection"
            )

        # Submit Skip, Next, or Verify through the same authoritative state
        # transition observation. Button text is presentation, not evidence.
        if not _sleep_with_deadline(deadline, random.uniform(0.3, 0.7)):
            break
        if not _wait_for_grid_stable(bframe, grid_size, deadline):
            snapshot = _collect_challenge_snapshot(bframe, deadline)
            _collect_det_grid(
                keyword_lower,
                grid_type,
                "unstable_before_verify",
                image_bytes,
                {
                    "cells_selected": sorted(cells),
                    "target_class": target_class,
                    "initial_predictions": prediction_summary,
                    "initial_clicks": click_dispatches,
                    "dynamic_trace": dynamic_trace,
                    "snapshot": snapshot,
                },
            )
            logger.info(
                "reCAPTCHA grid did not settle before Verify; preserving grid"
            )
            return False
        if dynamic_base_fallback and _dynamic_base_selection_state(
            bframe,
            grid_size,
            set(clicked_cells),
            keyword_lower,
            deadline,
        ) is None:
            snapshot = _collect_challenge_snapshot(bframe, deadline)
            _collect_det_grid(
                keyword_lower,
                grid_type,
                "fallback_changed_before_verify",
                image_bytes,
                {
                    "cells_selected": sorted(cells),
                    "target_class": target_class,
                    "initial_predictions": prediction_summary,
                    "initial_clicks": click_dispatches,
                    "dynamic_trace": dynamic_trace,
                    "snapshot": snapshot,
                },
            )
            logger.info(
                "reCAPTCHA fallback invariants changed before Verify; "
                "preserving grid"
            )
            return False
        previous_marker = _grid_state_marker(bframe, deadline)
        # Capture before the physical click: Google can return userverify
        # while path replay/click focus handling is still unwinding.
        verify_count_before = len(
            diagnostics.get("verify_statuses", []) if diagnostics else []
        )
        cur_x, cur_y, submitted = _click_verify(
            solver,
            page,
            bframe,
            cur_x,
            cur_y,
            deadline,
            preclick_guard=(
                (
                    lambda: _dynamic_base_selection_state(
                        bframe,
                        grid_size,
                        set(clicked_cells),
                        keyword_lower,
                        deadline,
                    )
                    is not None
                )
                if dynamic_base_fallback
                else None
            ),
        )
        if not submitted:
            logger.info("reCAPTCHA submit did not dispatch; preserving grid")
            return False

        # Final round: wait for an authoritative outcome. Do not click the
        # audio control as a diagnostic; that switches CAPTCHA modes and can
        # turn a still-valid image flow into an unrelated audio-endpoint block.
        outcome = _wait_for_post_verify_outcome(
            page,
            bframe,
            deadline,
            previous_marker,
            token_baseline,
            token_widget,
            protocol_intermediate_ready=(
                (
                    lambda: _has_new_protocol_solved_response(
                        diagnostics,
                        verify_count_before,
                    )
                )
                if protocol_completion_is_intermediate is True
                else None
            ),
        )
        verify_statuses = diagnostics.get("verify_statuses", []) if diagnostics else []
        verify_summaries = (
            diagnostics.get("verify_summaries", []) if diagnostics else []
        )
        latest_summary = (
            verify_summaries[-1]
            if len(verify_summaries) == len(verify_statuses)
            and len(verify_summaries) > verify_count_before
            and isinstance(verify_summaries[-1], dict)
            else None
        )
        latest_status = (
            verify_statuses[-1] if latest_summary is not None else None
        )
        logger.info(
            "reCAPTCHA diagnostic: phase=userverify-response "
            "new_count=%d total_count=%d statuses=%s classifications=%s",
            len(verify_statuses) - verify_count_before,
            len(verify_statuses),
            ",".join(str(status) for status in verify_statuses),
            ",".join(
                str(summary.get("classification", "unknown"))
                for summary in verify_summaries
                if isinstance(summary, dict)
            ),
        )
        if (
            outcome in {"pending", "protocol_intermediate"}
            and protocol_completion_is_intermediate is True
            and latest_status == 200
            and latest_summary is not None
            and latest_summary.get("classification") == "protocol_solved"
        ):
            # A successful uvresp is authoritative only for Google's widget.
            # TMD has a stronger outer contract: BrowserSolver keeps this
            # exact context alive and requires a new target-scoped x5sec
            # before reporting success to the HTTP client. Return promptly so
            # the wrapper can propagate the accepted token while that outer
            # cookie gate polls; generic reCAPTCHA callers never enable this.
            logger.info(
                "reCAPTCHA protocol accepted; handing off to the "
                "authoritative outer clearance gate",
            )
            _collect_det_grid(
                keyword_lower,
                grid_type,
                "protocol_intermediate",
                image_bytes,
                {
                    "cells_selected": sorted(cells),
                    "target_class": target_class,
                    "initial_predictions": prediction_summary,
                    "initial_clicks": click_dispatches,
                    "dynamic_trace": dynamic_trace,
                    "verify_statuses": verify_statuses,
                    "verify_summaries": verify_summaries,
                },
            )
            return True
        if (
            outcome == "pending"
            and len(verify_statuses) > verify_count_before
            and time.monotonic() < deadline
        ):
            # The physical submission reached Google's userverify endpoint,
            # so an unchanged grid is an in-flight result rather than a lost
            # click. Enterprise TMD wrappers can apply the returned state well
            # after the first observation window. Keep watching the exact
            # submitted grid; never reload or toggle its selected tiles.
            logger.info(
                "reCAPTCHA userverify reached the server; extending "
                "challenge-state observation",
            )
            outcome = _wait_for_post_verify_outcome(
                page,
                bframe,
                deadline,
                previous_marker,
                token_baseline,
                token_widget,
                maximum=30.0,
            )
        token_observation = None
        if (
            outcome == "pending"
            and latest_status == 200
            and latest_summary is not None
            and latest_summary.get("classification") == "protocol_solved"
        ):
            from wafer.browser._recaptcha import _token_observation

            token_observation = _token_observation(
                page,
                token_baseline,
                token_widget,
            )
            logger.info(
                "reCAPTCHA diagnostic: phase=protocol-token-propagation "
                "anchor_checked=%s scoped_values=%d new_values=%d",
                token_observation["anchor_checked"],
                token_observation["scoped_value_count"],
                token_observation["new_value_count"],
            )
        if outcome == "solved":
            logger.info(
                "reCAPTCHA image grid solved on attempt %d",
                attempt + 1,
            )
            _collect_det_grid(
                keyword_lower,
                grid_type,
                "solved",
                image_bytes,
                {
                    "cells_selected": sorted(cells),
                    "target_class": target_class,
                    "initial_predictions": prediction_summary,
                    "initial_clicks": click_dispatches,
                    "dynamic_trace": dynamic_trace,
                    "verify_statuses": verify_statuses,
                    "verify_summaries": verify_summaries,
                },
            )
            return True

        if outcome == "changed":
            logger.info(
                "reCAPTCHA supplied another image round after attempt %d",
                attempt + 1,
            )
            continue

        if outcome == "pending":
            # A missing immediate token is not a wrong answer.  In
            # particular, Enterprise can keep the correctly answered dynamic
            # grid visible while it validates the final replacement set.
            # Do not reload (which destroys that valid state) or re-enter the
            # outer loop (which could toggle already-selected tiles).
            logger.info(
                "reCAPTCHA Verify still pending after bounded observation; "
                "preserving current grid",
            )
            _collect_det_grid(
                keyword_lower,
                grid_type,
                "pending",
                image_bytes,
                {
                    "cells_selected": sorted(cells),
                    "target_class": target_class,
                    "initial_predictions": prediction_summary,
                    "initial_clicks": click_dispatches,
                    "dynamic_trace": dynamic_trace,
                    "verify_statuses": verify_statuses,
                    "verify_summaries": verify_summaries,
                    "token_observation": token_observation,
                    "pre_submit_marker": _safe_grid_state_marker(previous_marker),
                    "snapshot": _collect_challenge_snapshot(bframe, deadline),
                },
            )
            return False

        logger.info(
            "reCAPTCHA image attempt %d outcome=%s; loading a fresh grid",
            attempt + 1,
            outcome,
        )
        _collect_det_grid(
            keyword_lower,
            grid_type,
            "need_more_tiles" if outcome == "more" else outcome,
            image_bytes,
            {
                "cells_selected": sorted(cells),
                "target_class": target_class,
                "initial_predictions": prediction_summary,
                "initial_clicks": click_dispatches,
                "dynamic_trace": dynamic_trace,
                "verify_statuses": verify_statuses,
                "verify_summaries": verify_summaries,
                "pre_submit_marker": _safe_grid_state_marker(previous_marker),
                "post_submit_marker": _safe_grid_state_marker(
                    _grid_state_marker(bframe, deadline)
                ),
            },
        )
        cur_x, cur_y, reloaded = _click_reload(
            solver,
            page,
            bframe,
            cur_x,
            cur_y,
            deadline,
        )
        if not reloaded:
            return False

    return False
