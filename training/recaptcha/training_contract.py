"""Pure, dependency-light contracts for reproducible classifier training."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

try:
    from .classes import CLS_NAMES, NUM_CLASSES
except ImportError:
    from classes import CLS_NAMES, NUM_CLASSES

SIZES = {
    "s": "efficientnet_b0",
    "x": "efficientnet_b1",
}

CHECKPOINT_VERSION = 2
RUN_CONFIG_KEYS = {
    "batch",
    "epochs",
    "imgsz",
    "lr",
    "patience",
    "seed",
    "workers",
}
RNG_STATE_KEYS = {
    "loader_generator",
    "numpy",
    "python",
    "torch_cpu",
    "torch_mps",
}
CHECKPOINT_REQUIRED_KEYS = {
    "best_checkpoint_name",
    "best_state_dict_sha256",
    "best_val_acc",
    "checkpoint_version",
    "classes",
    "epoch",
    "history",
    "manifest_sha256",
    "model_name",
    "num_classes",
    "optimizer_state_dict",
    "patience_counter",
    "rng_state",
    "run_config",
    "scheduler_state_dict",
    "size",
    "size_seed",
    "state_dict",
    "state_dict_sha256",
    "val_acc",
}
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_BEST_CHECKPOINT_RE = re.compile(r"best-epoch-(\d{4,})-([0-9a-f]{16})\.pth\.tar")


def validate_class_contract(classes: Sequence[str]) -> None:
    """Reject any class omission, substitution, or index-order drift."""

    if tuple(classes) != CLS_NAMES:
        raise ValueError(
            "Manifest classes do not match production classifier index order"
        )


def size_seed(seed: int, size: str) -> int:
    """Return a stable per-size seed independent of ``--sizes`` ordering."""

    if size not in SIZES:
        raise ValueError(f"Unknown model size: {size}")
    return int.from_bytes(hashlib.sha256(f"{seed}:{size}".encode()).digest()[:8], "big")


def validate_training_request(
    sizes: Sequence[str],
    resume: str | Path | None,
) -> tuple[tuple[str, ...], Path | None]:
    """Validate all sizes and resolve an unambiguous explicit resume path."""

    normalized = tuple(size.strip() for size in sizes)
    if not normalized or any(not size for size in normalized):
        raise ValueError("At least one model size is required")
    unknown = sorted(set(normalized) - SIZES.keys())
    if unknown:
        raise ValueError(f"Unknown model sizes: {unknown}")
    if len(set(normalized)) != len(normalized):
        raise ValueError("Model sizes must not contain duplicates")

    if resume is None:
        return normalized, None
    if len(normalized) != 1:
        raise ValueError("--resume requires exactly one --sizes value")
    resume_path = Path(resume)
    if not resume_path.is_file():
        raise FileNotFoundError(f"Resume checkpoint does not exist: {resume_path}")
    return normalized, resume_path


def _metric(value: object, name: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or not 0.0 <= value <= 1.0
    ):
        raise RuntimeError(f"Checkpoint has invalid {name}")
    return float(value)


def state_dict_sha256(state_dict: Mapping) -> str:
    """Hash tensor bytes plus key/dtype/shape metadata deterministically."""

    if not isinstance(state_dict, Mapping) or not state_dict:
        raise RuntimeError("Checkpoint has invalid state_dict")
    keys = tuple(state_dict)
    if any(not isinstance(key, str) for key in keys):
        raise RuntimeError("Checkpoint state_dict keys must be strings")
    digest = hashlib.sha256()
    for key in sorted(keys):
        value = state_dict[key]
        if isinstance(value, bytes):
            metadata = b"bytes"
            payload = value
        else:
            try:
                import torch

                if not torch.is_tensor(value):
                    raise TypeError
                tensor = value.detach().cpu().contiguous()
                metadata = f"{tensor.dtype}:{tuple(tensor.shape)}".encode()
                # BatchNorm counters and other buffers can be 0-D. Flatten
                # before reinterpreting bytes because PyTorch rejects a scalar
                # dtype-size-changing view (for example Long -> Byte).
                payload = tensor.reshape(-1).view(torch.uint8).numpy().tobytes()
            except (ImportError, RuntimeError, TypeError) as exc:
                raise RuntimeError(
                    f"Checkpoint state_dict has invalid value for {key}"
                ) from exc
        key_bytes = key.encode()
        for part in (key_bytes, metadata, payload):
            digest.update(len(part).to_bytes(8, "big"))
            digest.update(part)
    return digest.hexdigest()


def best_checkpoint_name(epoch: int, digest: str) -> str:
    """Return the immutable best-artifact filename bound into ``last``."""

    if (
        not isinstance(epoch, int)
        or isinstance(epoch, bool)
        or epoch < 1
        or not _DIGEST_RE.fullmatch(digest)
    ):
        raise ValueError("Invalid best checkpoint identity")
    return f"best-epoch-{epoch:04d}-{digest[:16]}.pth.tar"


def _validate_run_config(run_config: Mapping) -> None:
    if set(run_config) != RUN_CONFIG_KEYS:
        raise RuntimeError("Current training configuration is incomplete")
    for key in ("batch", "epochs", "imgsz", "patience"):
        value = run_config[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise RuntimeError(f"Current training configuration has invalid {key}")
    workers = run_config["workers"]
    seed = run_config["seed"]
    lr = run_config["lr"]
    if not isinstance(workers, int) or isinstance(workers, bool) or workers < 0:
        raise RuntimeError("Current training configuration has invalid workers")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise RuntimeError("Current training configuration has invalid seed")
    if (
        not isinstance(lr, (int, float))
        or isinstance(lr, bool)
        or not math.isfinite(lr)
        or lr <= 0
    ):
        raise RuntimeError("Current training configuration has invalid lr")


def _validate_checkpoint(
    checkpoint: Mapping,
    size: str,
    manifest_sha256: str,
    run_config: Mapping,
) -> None:
    """Validate checkpoint structure and all state-continuity invariants."""

    fields = set(checkpoint)
    missing = CHECKPOINT_REQUIRED_KEYS - fields
    if missing:
        raise RuntimeError(
            f"Resume checkpoint is missing required state: {sorted(missing)}"
        )
    unexpected = fields - CHECKPOINT_REQUIRED_KEYS
    if unexpected:
        raise RuntimeError(
            f"Resume checkpoint has unsupported state: {sorted(unexpected)}"
        )
    if checkpoint["checkpoint_version"] != CHECKPOINT_VERSION:
        raise RuntimeError("Resume checkpoint version is unsupported")
    if size not in SIZES or checkpoint["size"] != size:
        raise RuntimeError("Resume checkpoint size does not match")
    if checkpoint["model_name"] != SIZES[size]:
        raise RuntimeError("Resume checkpoint architecture does not match size")
    if checkpoint["num_classes"] != NUM_CLASSES:
        raise RuntimeError("Resume checkpoint class count does not match")
    validate_class_contract(checkpoint["classes"])
    if not _DIGEST_RE.fullmatch(manifest_sha256):
        raise RuntimeError("Current training manifest digest is invalid")
    if checkpoint["manifest_sha256"] != manifest_sha256:
        raise RuntimeError("Refusing checkpoint with a different training manifest")

    _validate_run_config(run_config)
    if checkpoint["run_config"] != dict(run_config):
        raise RuntimeError("Resume checkpoint training configuration does not match")
    expected_seed = size_seed(int(run_config["seed"]), size)
    if checkpoint["size_seed"] != expected_seed:
        raise RuntimeError("Resume checkpoint per-size seed does not match")

    for key in ("state_dict", "optimizer_state_dict", "scheduler_state_dict"):
        if not isinstance(checkpoint[key], Mapping) or not checkpoint[key]:
            raise RuntimeError(f"Resume checkpoint has invalid {key}")
    if not _DIGEST_RE.fullmatch(str(checkpoint["state_dict_sha256"])) or checkpoint[
        "state_dict_sha256"
    ] != state_dict_sha256(checkpoint["state_dict"]):
        raise RuntimeError("Resume checkpoint state_dict digest does not match")
    if not _DIGEST_RE.fullmatch(str(checkpoint["best_state_dict_sha256"])):
        raise RuntimeError("Resume checkpoint best state digest is invalid")
    rng_state = checkpoint["rng_state"]
    if (
        not isinstance(rng_state, Mapping)
        or set(rng_state) != RNG_STATE_KEYS
        or any(value is None for value in rng_state.values())
    ):
        raise RuntimeError("Resume checkpoint has invalid RNG state")

    history = checkpoint["history"]
    epoch = checkpoint["epoch"]
    if (
        not isinstance(epoch, int)
        or isinstance(epoch, bool)
        or epoch < 1
        or not isinstance(history, list)
        or not history
        or any(not isinstance(item, Mapping) for item in history)
        or history[-1].get("epoch") != epoch
        or [item.get("epoch") for item in history] != list(range(1, epoch + 1))
    ):
        raise RuntimeError("Resume checkpoint has invalid epoch history")

    history_metrics = [
        _metric(item.get("val_acc"), "history val_acc") for item in history
    ]
    val_acc = _metric(checkpoint["val_acc"], "val_acc")
    best_val_acc = _metric(checkpoint["best_val_acc"], "best_val_acc")
    if not math.isclose(val_acc, history_metrics[-1], rel_tol=0.0, abs_tol=1e-12):
        raise RuntimeError("Resume checkpoint val_acc does not match history")
    history_best = max(history_metrics)
    if not math.isclose(best_val_acc, history_best, rel_tol=0.0, abs_tol=1e-12):
        raise RuntimeError("Resume checkpoint best_val_acc does not match history")

    best_epoch_index = next(
        index
        for index, metric in enumerate(history_metrics)
        if math.isclose(metric, history_best, rel_tol=0.0, abs_tol=1e-12)
    )
    expected_patience = len(history_metrics) - best_epoch_index - 1
    expected_best_name = best_checkpoint_name(
        best_epoch_index + 1,
        checkpoint["best_state_dict_sha256"],
    )
    if (
        not _BEST_CHECKPOINT_RE.fullmatch(str(checkpoint["best_checkpoint_name"]))
        or checkpoint["best_checkpoint_name"] != expected_best_name
    ):
        raise RuntimeError("Resume checkpoint best artifact identity does not match")
    patience_counter = checkpoint["patience_counter"]
    if (
        not isinstance(patience_counter, int)
        or isinstance(patience_counter, bool)
        or patience_counter != expected_patience
    ):
        raise RuntimeError("Resume checkpoint patience counter does not match history")


def build_checkpoint(
    *,
    size: str,
    manifest_sha256: str,
    run_config: Mapping,
    state_dict: Mapping,
    optimizer_state_dict: Mapping,
    scheduler_state_dict: Mapping,
    patience_counter: int,
    history: list[Mapping],
    val_acc: float,
    best_val_acc: float,
    epoch: int,
    rng_state: Mapping,
    best_state_dict_sha256: str,
    best_checkpoint_name: str,
) -> dict:
    """Build and self-validate one complete resumable checkpoint."""

    if size not in SIZES:
        raise ValueError(f"Unknown model size: {size}")
    checkpoint = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "model_name": SIZES[size],
        "size": size,
        "num_classes": NUM_CLASSES,
        "classes": list(CLS_NAMES),
        "manifest_sha256": manifest_sha256,
        "run_config": dict(run_config),
        "size_seed": size_seed(int(run_config["seed"]), size),
        "state_dict": state_dict,
        "state_dict_sha256": state_dict_sha256(state_dict),
        "best_state_dict_sha256": best_state_dict_sha256,
        "best_checkpoint_name": best_checkpoint_name,
        "optimizer_state_dict": optimizer_state_dict,
        "scheduler_state_dict": scheduler_state_dict,
        "patience_counter": patience_counter,
        "history": [dict(item) for item in history],
        "val_acc": val_acc,
        "best_val_acc": best_val_acc,
        "epoch": epoch,
        "rng_state": dict(rng_state),
    }
    _validate_checkpoint(checkpoint, size, manifest_sha256, run_config)
    return checkpoint


def validate_resume_checkpoint(
    checkpoint: Mapping,
    size: str,
    manifest_sha256: str,
    run_config: Mapping,
) -> None:
    """Fail closed unless a checkpoint continues the selected run state."""

    _validate_checkpoint(checkpoint, size, manifest_sha256, run_config)
    epoch = checkpoint["epoch"]
    epochs = run_config["epochs"]
    if epoch >= epochs:
        raise RuntimeError("Resume checkpoint already completed configured epochs")
    if checkpoint["patience_counter"] >= run_config["patience"]:
        raise RuntimeError("Resume checkpoint already reached early stopping")


def validate_best_checkpoint(
    best_checkpoint: Mapping,
    resume_checkpoint: Mapping,
    size: str,
    manifest_sha256: str,
    run_config: Mapping,
) -> None:
    """Validate the best-model artifact paired with a resume checkpoint."""

    _validate_checkpoint(
        best_checkpoint,
        size,
        manifest_sha256,
        run_config,
    )
    if (
        best_checkpoint["patience_counter"] != 0
        or not math.isclose(
            best_checkpoint["val_acc"],
            best_checkpoint["best_val_acc"],
            rel_tol=0.0,
            abs_tol=1e-12,
        )
        or not math.isclose(
            best_checkpoint["best_val_acc"],
            resume_checkpoint["best_val_acc"],
            rel_tol=0.0,
            abs_tol=1e-12,
        )
        or best_checkpoint["state_dict_sha256"]
        != resume_checkpoint["best_state_dict_sha256"]
        or best_checkpoint["best_state_dict_sha256"]
        != resume_checkpoint["best_state_dict_sha256"]
        or best_checkpoint["best_checkpoint_name"]
        != resume_checkpoint["best_checkpoint_name"]
        or best_checkpoint["epoch"] > resume_checkpoint["epoch"]
        or best_checkpoint["history"]
        != resume_checkpoint["history"][: best_checkpoint["epoch"]]
    ):
        raise RuntimeError("Best checkpoint does not match resume checkpoint history")


def publish_epoch_checkpoints(
    checkpoint: Mapping,
    weights_dir: Path,
    *,
    improved: bool,
    save_checkpoint,
) -> Path:
    """Publish an immutable best first, then the current resumable epoch."""

    weights_dir = Path(weights_dir)
    selected = weights_dir / checkpoint["best_checkpoint_name"]
    if improved:
        if checkpoint["state_dict_sha256"] != checkpoint["best_state_dict_sha256"]:
            raise RuntimeError("Improved checkpoint is not its selected best state")
        save_checkpoint(checkpoint, selected)
        save_checkpoint(checkpoint, weights_dir / "best.pth.tar")
    save_checkpoint(checkpoint, weights_dir / "last.pth.tar")
    return selected
