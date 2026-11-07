"""Small file helpers shared by all readers and writers."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path

from stigforage.model import ChecklistError

__all__ = ["MAX_BYTES", "atomic_write_text", "read_limited"]

# Real checklists and benchmarks are a few MB. The cap stops a hostile or corrupt file from
# exhausting memory.
MAX_BYTES = 128 * 1024 * 1024


def read_limited(path: Path) -> bytes:
    """Read a whole file, refusing anything over MAX_BYTES. Raises ChecklistError, OSError."""
    size = path.stat().st_size
    if size > MAX_BYTES:
        raise ChecklistError(f"{path}: file is {size} bytes, over the {MAX_BYTES} byte limit")
    return path.read_bytes()


def atomic_write_text(path: Path, payload: str, *, force: bool = False) -> None:
    """Write `payload` to `path` atomically as UTF-8.

    Refuses to overwrite an existing file unless `force` is set. The write goes to a temp file in
    the destination directory and is renamed into place, so a crash never leaves a half-written
    file. The exists-check is not race-free; that is accepted for a single-user CLI.
    """
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists (use --force to overwrite)")
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        tmp.replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
