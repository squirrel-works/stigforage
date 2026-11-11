"""Read InSpec / MITRE Heimdall Data Format (HDF) results as scans for `import-results`.

HDF is JSON: `profiles[].controls[]`, each control with an `id` (a V-number in STIG profiles),
`impact`, `tags` (`gid`, `rid`, sometimes `STIGRef`) and `results[]` with a `status` of passed,
failed, skipped or error. Policy (ADR 0003 decision 3 as revised, and the unit 2 notes):

- A control's result follows Heimdall's own order (inspecjs `compute_status`), so a checklist
  agrees with what Heimdall shows: any error (or a result with a backtrace) -> error; waived ->
  waived; impact 0 -> notapplicable; no results -> no_results; any failed -> fail; any passed
  -> pass; else skipped. One deliberate difference: Heimdall shows a waived control as Not
  Applicable, but a waiver accepts the risk of a requirement that does apply, so it is not
  imported and is left for the assessor. Only fail, pass and notapplicable are imported.
- HDF names no DISA benchmark, so scans carry no STIG id and pair by V-number.
- Release identity, when present, comes from a `STIGRef` tag ("Version 1, Release: 3") or a
  `vNrN` in a profile title. HDF names no host, so the host is never checked.
- Overlays: everything, impact included, comes from the control that ran (the base profile),
  as Heimdall does ("use root for all data operations"). Outer layers only name the scan and
  may carry the release in their title.

Trust boundary: HDF files are untrusted; malformed content raises ChecklistError with a locator.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, NoReturn

from stigforage.fsio import read_limited
from stigforage.model import ChecklistError
from stigforage.results import RuleResult, Scan

__all__ = ["load_hdf", "loads_hdf"]

_STIGREF_RE = re.compile(r"Version\s*(\d+),\s*(Release:\s*\d+)", re.IGNORECASE)
_TITLE_VR_RE = re.compile(r"\bv(\d+)r(\d+)\b", re.IGNORECASE)


def _fail(path: str, message: str) -> NoReturn:
    raise ChecklistError(f"{path}: {message}")


def _reject_constant(name: str) -> NoReturn:
    # json.loads accepts NaN/Infinity by default; they are not valid JSON.
    raise ChecklistError(f"$: invalid JSON constant {name!r}")


def _list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(path, f"expected array, got {type(value).__name__}")
    return value


def _dict(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, f"expected object, got {type(value).__name__}")
    return value


def _str(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _effective_result(control: dict[str, Any], path: str) -> tuple[str, str]:
    """(result value, details) for one control, per the order in the module docstring."""
    statuses: list[str] = []
    lines: list[str] = []
    for i, raw in enumerate(_list(control.get("results", []), f"{path}.results")):
        result = _dict(raw, f"{path}.results[{i}]")
        status = _str(result.get("status"))
        if status not in ("passed", "failed", "skipped", "error"):
            _fail(f"{path}.results[{i}].status", f"unknown status {result.get('status')!r}")
        if result.get("backtrace"):
            status = "error"  # as Heimdall does: a backtrace means the test itself broke
        statuses.append(status)
        text = _str(result.get("code_desc"))
        why = _str(result.get("message")) or _str(result.get("skip_message"))
        lines.append(f"[{status}] {text}" + (f": {why}" if why else ""))
    waiver = control.get("waiver_data")
    waived = isinstance(waiver, dict) and bool(waiver.get("skipped_due_to_waiver"))
    return _classify(set(statuses), control.get("impact"), waived), "\n".join(lines)


def _classify(statuses: set[str], impact: Any, waived: bool) -> str:
    """Heimdall's order, first match wins; `waived` replaces its Not Applicable."""
    order = (
        ("error", "error" in statuses),
        ("waived", waived),
        ("notapplicable", impact == 0),
        ("no_results", not statuses),
        ("fail", "failed" in statuses),
        ("pass", "passed" in statuses),
    )
    return next((name for name, hit in order if hit), "skipped")


def _release(layers: list[dict[str, Any]], controls: list[dict[str, Any]]) -> tuple[str, str]:
    """(version, release_info) in the forms `results.release_id` reads, or ("", "").

    A STIGRef tag on any control first, then a vNrN in a profile title, outermost first.
    """
    for control in controls:
        ref = _str(_dict(control.get("tags", {}), "tags").get("STIGRef"))
        if match := _STIGREF_RE.search(ref):
            return match[1], match[2]
    for profile in reversed(layers):
        if match := _TITLE_VR_RE.search(_str(profile.get("title"))):
            return f"V{match[1]}R{match[2]}", ""
    return "", ""


def _layers(profile: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """The profile and every profile wrapping it via parent_profile, innermost first."""
    layers, seen = [profile], {_str(profile.get("name"))}
    while (parent := _str(layers[-1].get("parent_profile"))) and parent in by_name:
        if parent in seen:
            _fail(f"profile {_str(profile.get('name'))!r}", "parent_profile links form a loop")
        seen.add(parent)
        layers.append(by_name[parent])
    return layers


def loads_hdf(text: str, *, source: str = "HDF") -> list[Scan]:
    """Parse HDF JSON into one Scan per profile that holds results."""
    try:
        doc = _dict(json.loads(text, parse_constant=_reject_constant), source)
    except json.JSONDecodeError as exc:
        raise ChecklistError(
            f"{source}: invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}"
        ) from exc
    profiles = [
        _dict(p, f"{source}.profiles[{i}]")
        for i, p in enumerate(_list(doc.get("profiles"), f"{source}.profiles"))
    ]
    by_name = {_str(p.get("name")): p for p in profiles}
    raw_platform = doc.get("platform")
    platform: dict[str, Any] = raw_platform if isinstance(raw_platform, dict) else {}
    on = " ".join(x for x in (_str(platform.get("name")), _str(platform.get("release"))) if x)
    scans: list[Scan] = []
    for pi, profile in enumerate(profiles):
        ppath = f"{source}.profiles[{pi}]"
        controls = [
            _dict(c, f"{ppath}.controls[{ci}]")
            for ci, c in enumerate(_list(profile.get("controls", []), f"{ppath}.controls"))
        ]
        if not any(c.get("results") for c in controls):
            continue  # an overlay layer: metadata only, no results
        layers = _layers(profile, by_name)
        outer = layers[-1]
        results: list[RuleResult] = []
        times: list[str] = []
        for ci, control in enumerate(controls):
            cpath = f"{ppath}.controls[{ci}]"
            control_id = _str(control.get("id"))
            if not control_id:
                _fail(cpath, "control has no id")
            tags = _dict(control.get("tags", {}), f"{cpath}.tags")
            value, details = _effective_result(control, cpath)
            group = _str(tags.get("gid")) or (control_id if control_id.startswith("V-") else "")
            results.append(RuleResult(_str(tags.get("rid")), group, value, details))
            times += [
                _str(r.get("start_time")) for r in control.get("results", []) if isinstance(r, dict)
            ]
        version, release_info = _release(layers, controls)
        name = _str(outer.get("name")) or "unnamed profile"
        scans.append(
            Scan(
                source=name,  # replaced below once the number of scans is known
                tool=f"{name} {_str(outer.get('version'))}".strip() + f" (HDF, {on or '?'})",
                end_time=max((t for t in times if t), default=""),
                stig_id="",
                version=version,
                release_info=release_info,
                hosts=(),
                results=results,
            )
        )
    if not scans:
        raise ChecklistError(f"{source}: no profile holds any results")
    # One scan (the usual case, overlays included) is named by the file alone.
    for scan in scans:
        scan.source = source if len(scans) == 1 else f"{source} ({scan.source})"
    return scans


def load_hdf(path: Path) -> list[Scan]:
    """Read an HDF `.json` file. Raises ChecklistError, OSError."""
    data = read_limited(path)
    try:
        return loads_hdf(data.decode("utf-8-sig"), source=str(path))
    except UnicodeDecodeError as exc:
        raise ChecklistError(f"{path}: not valid UTF-8: {exc.reason}") from exc
