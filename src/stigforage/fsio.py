"""Small file helpers shared by all readers and writers."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path

from stigforage.model import ChecklistError

__all__ = [
    "MAX_BYTES",
    "atomic_write_bytes",
    "atomic_write_text",
    "check_write_target",
    "read_limited",
]

# Real checklists and benchmarks are a few MB. The cap stops a hostile or corrupt file from
# exhausting memory.
MAX_BYTES = 128 * 1024 * 1024


def read_limited(path: Path) -> bytes:
    """Read a whole file, refusing anything over MAX_BYTES. Raises ChecklistError, OSError."""
    size = path.stat().st_size
    if size > MAX_BYTES:
        raise ChecklistError(f"{path}: file is {size} bytes, over the {MAX_BYTES} byte limit")
    return path.read_bytes()


def check_write_target(path: Path, *, force: bool = False) -> None:
    """Raise OSError if `atomic_write_text` would refuse `path`.

    `atomic_write_text` calls this itself, and dry runs call it so they report the same refusals
    as a real write. It cannot predict permission, disk-space or race failures; only the real
    write reveals those.
    """
    if path.is_dir():
        raise IsADirectoryError(f"{path} is a directory")
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists (use --force to overwrite)")
    if not path.parent.is_dir():
        # Checked up front: otherwise mkstemp fails naming its own temp file, not `path`.
        raise FileNotFoundError(f"directory {path.parent} does not exist")


def atomic_write_bytes(path: Path, payload: bytes, *, force: bool = False) -> None:
    """Write `payload` to `path` atomically.

    Refuses to overwrite an existing file unless `force` is set (see `check_write_target`). The
    write goes to a temp file in the destination directory and is renamed into place, so a crash
    never leaves a half-written file. The checks are not race-free; that is accepted for a
    single-user CLI.
    """
    check_write_target(path, force=force)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        tmp.replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def atomic_write_text(path: Path, payload: str, *, force: bool = False) -> None:
    """Write `payload` to `path` atomically as UTF-8, newlines exactly as given."""
    atomic_write_bytes(path, payload.encode("utf-8"), force=force)
