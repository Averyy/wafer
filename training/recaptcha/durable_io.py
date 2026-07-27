"""Crash-durable atomic file publication for training artifacts."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(
    path: Path,
    writer: Callable[[BinaryIO], None],
) -> None:
    """Publish one binary file with unique temp, fsync, and atomic replace."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            writer(handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_text(
    path: Path,
    value: str,
) -> None:
    """Publish one UTF-8 text file with the same durability guarantees."""

    atomic_write(path, lambda handle: handle.write(value.encode("utf-8")))


def atomic_write_json(path: Path, value: object) -> None:
    """Durably publish stable, reviewable JSON."""

    atomic_write_text(
        path,
        json.dumps(value, indent=2, sort_keys=True) + "\n",
    )
