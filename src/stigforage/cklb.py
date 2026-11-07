"""Read and write DISA STIG Viewer 3 `.cklb` (JSON) checklists.

Trust boundary: everything parsed here is untrusted input. Errors are raised as
`ChecklistError` with a JSON-path locator and are never swallowed.

Normalisation on write: optional keys that were absent on read (for example `comments`) are
written back with their default value. Keys this module does not model are preserved verbatim.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, NoReturn, cast

from stigforage.model import Checklist, ChecklistError, Rule, Status, Stig

__all__ = ["MAX_BYTES", "dump", "dumps", "load", "loads", "to_dict"]

# Real checklists are a few MB. The cap stops a hostile or corrupt file from exhausting memory.
MAX_BYTES = 128 * 1024 * 1024

_RULE_KEYS = frozenset(
    {
        "group_id",
        "rule_id",
        "rule_version",
        "severity",
        "status",
        "uuid",
        "rule_id_src",
        "rule_title",
        "comments",
        "finding_details",
        "overrides",
        "ccis",
    }
)
_STIG_KEYS = frozenset(
    {"stig_name", "display_name", "stig_id", "release_info", "rules", "version", "uuid"}
)
_CHECKLIST_KEYS = frozenset({"title", "id", "target_data", "stigs"})


# --- typed field accessors ------------------------------------------------------------------


def _fail(path: str, message: str) -> NoReturn:
    raise ChecklistError(f"{path}: {message}")


def _req_str(d: Mapping[str, Any], key: str, path: str) -> str:
    if key not in d:
        _fail(path, f"missing required key {key!r}")
    value = d[key]
    if not isinstance(value, str):
        _fail(f"{path}.{key}", f"expected string, got {type(value).__name__}")
    return value


def _opt_str(d: Mapping[str, Any], key: str, path: str, default: str = "") -> str:
    if key not in d or d[key] is None:
        return default
    return _req_str(d, key, path)


def _nullable_str(d: Mapping[str, Any], key: str, path: str) -> str | None:
    if key not in d or d[key] is None:
        return None
    return _req_str(d, key, path)


def _opt_version(d: Mapping[str, Any], key: str, path: str) -> int | str | None:
    """STIG version appears as a string in 20 of 25 public fixtures and an int in the rest.

    The original type is preserved so a round trip does not rewrite it.
    """
    if key not in d or d[key] is None:
        return None
    value = d[key]
    # bool is an int subclass; `true` as a version number is corrupt, not 1.
    if isinstance(value, bool) or not isinstance(value, int | str):
        _fail(f"{path}.{key}", f"expected integer or string, got {type(value).__name__}")
    return value


def _dict(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, f"expected object, got {type(value).__name__}")
    return cast("dict[str, Any]", value)


def _list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(path, f"expected array, got {type(value).__name__}")
    return value


# --- parsing --------------------------------------------------------------------------------


def _rule_from_dict(d: dict[str, Any], path: str) -> Rule:
    raw_status = _req_str(d, "status", path)
    try:
        status = Status(raw_status)
    except ValueError:
        valid = ", ".join(s.value for s in Status)
        _fail(f"{path}.status", f"unknown status {raw_status!r} (valid: {valid})")
    ccis_raw = _list(d.get("ccis", []), f"{path}.ccis")
    ccis: list[str] = []
    for i, cci in enumerate(ccis_raw):
        if not isinstance(cci, str):
            _fail(f"{path}.ccis[{i}]", f"expected string, got {type(cci).__name__}")
        ccis.append(cci)
    overrides = d.get("overrides", {})
    return Rule(
        group_id=_req_str(d, "group_id", path),
        rule_id=_req_str(d, "rule_id", path),
        rule_version=_req_str(d, "rule_version", path),
        severity=_req_str(d, "severity", path),
        status=status,
        uuid=_opt_str(d, "uuid", path),
        rule_id_src=_nullable_str(d, "rule_id_src", path),
        rule_title=_opt_str(d, "rule_title", path),
        comments=_nullable_str(d, "comments", path),
        finding_details=_nullable_str(d, "finding_details", path),
        overrides=_dict(overrides, f"{path}.overrides"),
        ccis=ccis,
        extra={k: v for k, v in d.items() if k not in _RULE_KEYS},
    )


def _stig_from_dict(d: dict[str, Any], path: str) -> Stig:
    rules_raw = _list(d.get("rules"), f"{path}.rules")
    rules = [
        _rule_from_dict(_dict(r, f"{path}.rules[{i}]"), f"{path}.rules[{i}]")
        for i, r in enumerate(rules_raw)
    ]
    return Stig(
        stig_name=_req_str(d, "stig_name", path),
        display_name=_opt_str(d, "display_name", path),
        stig_id=_req_str(d, "stig_id", path),
        release_info=_opt_str(d, "release_info", path),
        rules=rules,
        version=_opt_version(d, "version", path),
        uuid=_opt_str(d, "uuid", path),
        extra={k: v for k, v in d.items() if k not in _STIG_KEYS},
    )


def _checklist_from_dict(d: dict[str, Any]) -> Checklist:
    if "stigs" not in d:
        _fail("$", "missing required key 'stigs'")
    stigs_raw = _list(d["stigs"], "$.stigs")
    return Checklist(
        title=_opt_str(d, "title", "$"),
        id=_opt_str(d, "id", "$"),
        target_data=_dict(d.get("target_data", {}), "$.target_data"),
        stigs=[
            _stig_from_dict(_dict(s, f"$.stigs[{i}]"), f"$.stigs[{i}]")
            for i, s in enumerate(stigs_raw)
        ],
        extra={k: v for k, v in d.items() if k not in _CHECKLIST_KEYS},
    )


def _reject_constant(name: str) -> NoReturn:
    # json.loads accepts NaN/Infinity by default; they are not valid JSON and never legitimate here.
    raise ChecklistError(f"$: invalid JSON constant {name!r}")


def loads(text: str) -> Checklist:
    """Parse CKLB JSON text into a `Checklist`."""
    try:
        data = json.loads(text, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise ChecklistError(
            f"$: invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}"
        ) from exc
    return _checklist_from_dict(_dict(data, "$"))


def load(path: Path) -> Checklist:
    """Read and parse a `.cklb` file. Raises `ChecklistError`, `OSError`."""
    size = path.stat().st_size
    if size > MAX_BYTES:
        raise ChecklistError(f"{path}: file is {size} bytes, over the {MAX_BYTES} byte limit")
    try:
        # utf-8-sig: tolerate a BOM, which some Windows tooling writes.
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ChecklistError(f"{path}: not valid UTF-8: {exc.reason}") from exc
    try:
        return loads(text)
    except ChecklistError as exc:
        raise ChecklistError(f"{path}: {exc}") from exc


# --- writing --------------------------------------------------------------------------------


def _rule_to_dict(rule: Rule) -> dict[str, Any]:
    return {
        "uuid": rule.uuid,
        "group_id": rule.group_id,
        "rule_id": rule.rule_id,
        "rule_id_src": rule.rule_id_src,
        "rule_version": rule.rule_version,
        "rule_title": rule.rule_title,
        "severity": rule.severity,
        "status": rule.status.value,
        "comments": rule.comments,
        "finding_details": rule.finding_details,
        "overrides": rule.overrides,
        "ccis": rule.ccis,
        **rule.extra,
    }


def _stig_to_dict(stig: Stig) -> dict[str, Any]:
    out: dict[str, Any] = {
        "stig_name": stig.stig_name,
        "display_name": stig.display_name,
        "stig_id": stig.stig_id,
        "release_info": stig.release_info,
        "uuid": stig.uuid,
        "rules": [_rule_to_dict(r) for r in stig.rules],
        **stig.extra,
    }
    if stig.version is not None:
        out["version"] = stig.version
    return out


def to_dict(checklist: Checklist) -> dict[str, Any]:
    """Serialise to a plain dict in CKLB shape."""
    return {
        "title": checklist.title,
        "id": checklist.id,
        "target_data": checklist.target_data,
        "stigs": [_stig_to_dict(s) for s in checklist.stigs],
        **checklist.extra,
    }


def dumps(checklist: Checklist, *, indent: int | None = 2) -> str:
    return json.dumps(to_dict(checklist), indent=indent, ensure_ascii=False, allow_nan=False)


def dump(checklist: Checklist, path: Path, *, force: bool = False) -> None:
    """Atomically write `checklist` to `path`.

    Refuses to overwrite an existing file unless `force` is set. The write goes to a temp file in
    the destination directory and is renamed into place, so a crash never leaves a half-written
    checklist. The exists-check is not race-free; that is accepted for a single-user CLI.
    """
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists (use --force to overwrite)")
    payload = dumps(checklist)
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
