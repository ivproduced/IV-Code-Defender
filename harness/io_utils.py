# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Private, crash-durable artifact writes."""
from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, TextIO

try:
    import fcntl
except ImportError:  # pragma: no cover - unsupported sandbox host
    fcntl = None


PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700


class ResultsLockError(RuntimeError):
    """Another orchestrator owns the mutable results directory."""


def ensure_private_dir(path: str | Path) -> Path:
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    try:
        directory.chmod(PRIVATE_DIR_MODE)
    except OSError:
        pass
    return directory


def atomic_write_bytes(path: str | Path, data: bytes) -> None:
    destination = Path(path)
    parent = ensure_private_dir(destination.parent)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=parent)
    try:
        os.fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        _fsync_directory(parent)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def atomic_write_text(path: str | Path, value: str) -> None:
    atomic_write_bytes(path, value.encode("utf-8"))


def atomic_write_json(path: str | Path, value: Any, *, indent: int = 2) -> None:
    atomic_write_text(path, json.dumps(value, indent=indent))


def append_jsonl(path: str | Path, value: Any) -> None:
    """Append one locked and fsynced JSON line."""
    destination = Path(path)
    ensure_private_dir(destination.parent)
    fd = os.open(
        destination, os.O_WRONLY | os.O_CREAT | os.O_APPEND, PRIVATE_FILE_MODE
    )
    try:
        os.fchmod(fd, PRIVATE_FILE_MODE)
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        remaining = memoryview((json.dumps(value) + "\n").encode("utf-8"))
        while remaining:
            remaining = remaining[os.write(fd, remaining):]
        os.fsync(fd)
    finally:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def open_private_text(path: str | Path, mode: str = "w") -> TextIO:
    destination = Path(path)
    ensure_private_dir(destination.parent)
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_APPEND if "a" in mode else os.O_TRUNC
    fd = os.open(destination, flags, PRIVATE_FILE_MODE)
    os.fchmod(fd, PRIVATE_FILE_MODE)
    return os.fdopen(fd, mode, encoding="utf-8")


@contextmanager
def exclusive_lock(path: str | Path) -> Iterator[None]:
    """Hold a non-blocking process lock for a mutable results directory."""
    if fcntl is None:  # pragma: no cover - unsupported sandbox host
        raise RuntimeError("results locking requires fcntl")
    destination = Path(path)
    ensure_private_dir(destination.parent)
    fd = os.open(
        destination, os.O_WRONLY | os.O_CREAT, PRIVATE_FILE_MODE
    )
    try:
        os.fchmod(fd, PRIVATE_FILE_MODE)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ResultsLockError(
                f"results directory is already in use: {destination.parent}"
            ) from exc
        os.ftruncate(fd, 0)
        os.write(fd, f"pid={os.getpid()}\n".encode())
        os.fsync(fd)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
