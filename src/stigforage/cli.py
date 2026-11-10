"""Command line interface.

Exit codes: 0 success, 1 validation errors found, 2 a file could not be read, parsed or written.
Progress and diagnostics go to stderr via structlog; results go to stdout.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO, cast

from stigforage import __version__, ckl, cklb, xccdf
from stigforage.diff import ChecklistDiff, RuleDiff, StigDiff, diff_checklists
from stigforage.fsio import atomic_write_text, check_write_target, read_limited
from stigforage.log import configure, get_logger
from stigforage.model import Checklist, ChecklistError, ImportResult, Issue, Status, validate
from stigforage.schema import check_supported, validate_instance

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_UNREADABLE = 2

_INPUT_HELP = ".cklb, .ckl, XCCDF/SCAP .xml, or a .zip containing benchmarks"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stigforage",
        description="Offline STIG checklist toolkit. File-only; never uses the network.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging on stderr")
    parser.add_argument("-q", "--quiet", action="store_true", help="warnings and errors only")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    info = sub.add_parser("info", help="summarise one or more checklists or benchmarks")
    info.add_argument("files", nargs="+", type=Path, metavar="FILE", help=_INPUT_HELP)

    val = sub.add_parser("validate", help="check checklists for structural problems")
    val.add_argument("files", nargs="+", type=Path, metavar="FILE", help=_INPUT_HELP)
    val.add_argument("--strict", action="store_true", help="treat warnings as errors (exit 1)")
    val.add_argument(
        "--schema",
        type=Path,
        metavar="PATH",
        help=(
            "also validate against this JSON Schema (e.g. DISA's SV3_CKLB_1_0_JSON_SCHEMA.json). "
            ".cklb files are checked as written; other inputs are checked after conversion"
        ),
    )

    conv = sub.add_parser(
        "convert",
        help="convert between .cklb, .ckl and XCCDF/SCAP (benchmarks become blank checklists)",
        description=(
            "Convert INPUT to the format implied by the -o extension (.cklb or .ckl). "
            "Dry-run by default: nothing is written unless --apply is given. "
            "INPUT is never modified."
        ),
    )
    conv.add_argument("input", type=Path, metavar="INPUT", help=_INPUT_HELP)
    conv.add_argument("-o", "--output", required=True, type=Path, help="output .cklb or .ckl path")
    conv.add_argument("--apply", action="store_true", help="actually write the output file")
    conv.add_argument("--force", action="store_true", help="overwrite an existing output file")

    dif = sub.add_parser(
        "diff",
        help="compare two checklists or benchmarks rule by rule",
        description=(
            "Compare OLD with NEW, STIG by STIG. Rules are matched by rule_id_src, then by "
            "group_id when unambiguous. Read-only; exit 0 whether or not differences exist."
        ),
    )
    dif.add_argument("old", type=Path, metavar="OLD", help=_INPUT_HELP)
    dif.add_argument("new", type=Path, metavar="NEW", help=_INPUT_HELP)
    return parser


def _load_any(path: Path) -> ImportResult:
    """Load any supported input. Raises ChecklistError, OSError."""
    suffix = path.suffix.lower()
    if suffix == ".cklb":
        return ImportResult(cklb.load(path))
    if suffix == ".ckl":
        return ckl.load(path)
    if suffix in (".xml", ".zip"):
        return xccdf.load(path)
    raise ChecklistError(f"{path}: unsupported file type {suffix!r}")


def _format_info(checklist: Checklist, out: TextIO) -> None:
    out.write(f"host: {checklist.host_name or '(none)'}  title: {checklist.title or '(none)'}\n")
    for stig in checklist.stigs:
        counts = stig.status_counts()
        sev = stig.severity_counts()
        out.write(
            f"  {stig.stig_id}  v{stig.version if stig.version is not None else '?'}  "
            f"{stig.release_info or '(no release info)'}\n"
        )
        out.write(
            f"    rules: {len(stig.rules)}  "
            f"CAT I: {sev.get('high', 0)}  CAT II: {sev.get('medium', 0)}  "
            f"CAT III: {sev.get('low', 0)}\n"
        )
        out.write(
            "    status: " + "  ".join(f"{s.value}={counts.get(s, 0)}" for s in Status) + "\n"
        )


def _load_schema(path: Path) -> dict[str, Any]:
    """Load a JSON Schema file and reject constructs this tool cannot honour."""
    try:
        doc = json.loads(read_limited(path).decode("utf-8-sig"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ChecklistError(f"{path}: not valid JSON: {exc}") from exc
    check_supported(doc)
    return cast("dict[str, Any]", doc)


_INDEX_RE = re.compile(r"\[\d+\]")


def _group_issues(issues: list[Issue]) -> list[tuple[Issue, int, str]]:
    """Collapse repeats (same message at the same path shape) into (first_issue, count, shape).

    A single systematic problem, such as a null in every rule, would otherwise print thousands
    of lines.
    """
    groups: dict[tuple[str, str, str], list[Issue]] = {}
    for issue in issues:
        key = (issue.level, _INDEX_RE.sub("[*]", issue.path), issue.message)
        groups.setdefault(key, []).append(issue)
    return [(members[0], len(members), key[1]) for key, members in groups.items()]


_TEXT_FIELDS = frozenset({"check_content", "fix_text", "discussion", "comments", "finding_details"})


def _show(name: str, value: Any) -> str:
    """Short display form: long text is summarised by size, never dumped."""
    if name in _TEXT_FIELDS:
        return f"<{len(value)} chars>" if value else "<empty>"
    return str(value) if value != "" else "<empty>"


def _format_rule_diff(rd: RuleDiff, out: TextIO) -> None:
    how = "" if rd.matched_by == "rule_id_src" else f"  [matched by group_id; was {rd.old.rule_id}]"
    out.write(f"  ~ {rd.new.group_id} {rd.new.rule_id}{how}\n")
    for change in rd.changes:
        if change.name == "rule_id" and rd.matched_by == "group_id":
            continue  # already shown in the header
        out.write(f"      {change.name}: {_show(change.name, change.old)} -> ")
        out.write(f"{_show(change.name, change.new)}\n")


def _format_stig_diff(sd: StigDiff, out: TextIO) -> None:
    m = sd.matching
    out.write(f"{sd.stig_id}: {sd.old_release or '?'} -> {sd.new_release or '?'}\n")
    out.write(
        f"  matched={len(m.pairs)} unchanged={sd.unchanged} "
        f"added={len(m.new_only)} removed={len(m.old_only)}\n"
    )
    for rule in m.new_only:
        out.write(f"  + {rule.group_id} {rule.rule_id}  {rule.severity}  {rule.rule_title}\n")
    for rule in m.old_only:
        out.write(f"  - {rule.group_id} {rule.rule_id}  {rule.severity}  {rule.rule_title}\n")
    for rd in sd.rules:
        if rd.changes or rd.matched_by != "rule_id_src":
            _format_rule_diff(rd, out)
    for group_id in m.ambiguous:
        out.write(f"  ? {group_id}: several rules share this group_id; not matched\n")


def _format_diff(diff: ChecklistDiff, out: TextIO) -> None:
    for sd in diff.stigs:
        _format_stig_diff(sd, out)
    for stig_id in diff.new_only_stigs:
        out.write(f"+ STIG only in NEW: {stig_id}\n")
    for stig_id in diff.old_only_stigs:
        out.write(f"- STIG only in OLD: {stig_id}\n")


def _run_diff(args: argparse.Namespace, out: TextIO) -> int:
    log = get_logger()
    loaded: list[Checklist] = []
    for n, path in enumerate((args.old, args.new), start=1):
        log.info("reading", step=f"{n}/2", file=str(path))
        try:
            result = _load_any(path)
        except (ChecklistError, OSError) as exc:
            log.error("cannot read checklist", file=str(path), error=str(exc))
            return EXIT_UNREADABLE
        for warning in result.warnings:
            log.warning("import", detail=warning)
        loaded.append(result.checklist)
    log.info("comparing")
    diff = diff_checklists(loaded[0], loaded[1])
    _format_diff(diff, out)
    log.info(
        "done",
        stigs=len(diff.stigs),
        only_old=len(diff.old_only_stigs),
        only_new=len(diff.new_only_stigs),
    )
    return EXIT_OK


def _run_convert(args: argparse.Namespace, out: TextIO) -> int:
    log = get_logger()
    src: Path = args.input
    dest: Path = args.output
    fmt = dest.suffix.lower()
    if fmt not in (".cklb", ".ckl"):
        log.error("unsupported output type", output=str(dest), expected=".cklb or .ckl")
        return EXIT_UNREADABLE
    if dest.resolve() == src.resolve():
        log.error("output would overwrite the input", path=str(dest))
        return EXIT_UNREADABLE

    log.info("step", n="1/3", action="reading", file=str(src))
    try:
        result = _load_any(src)
    except (ChecklistError, OSError) as exc:
        log.error("cannot read input", file=str(src), error=str(exc))
        return EXIT_UNREADABLE
    for warning in result.warnings:
        log.warning("import", detail=warning)
    checklist = result.checklist
    rule_count = sum(len(s.rules) for s in checklist.stigs)
    log.info("step", n="2/3", action="parsed", stigs=len(checklist.stigs), rules=rule_count)

    # A dry run goes through everything except the final write (serialising, export warnings,
    # output checks), so it fails exactly where --apply would.
    export_warnings: list[str] = []
    if fmt == ".cklb":
        text = cklb.dumps(checklist)
    else:
        text, export_warnings = ckl.dumps(checklist)
    for warning in export_warnings:
        log.warning("export", detail=warning)
    try:
        if args.apply:
            log.info("step", n="3/3", action="writing", file=str(dest))
            atomic_write_text(dest, text, force=args.force)  # runs check_write_target itself
        else:
            check_write_target(dest, force=args.force)
    except OSError as exc:
        log.error("cannot write output", file=str(dest), error=str(exc))
        return EXIT_UNREADABLE

    if args.apply:
        out.write(f"wrote {len(checklist.stigs)} STIG(s), {rule_count} rule(s) to {dest}\n")
    else:
        out.write(
            f"dry run: would write {len(checklist.stigs)} STIG(s), {rule_count} rule(s) "
            f"to {dest} ({fmt[1:]}); re-run with --apply to write\n"
        )
    return EXIT_OK


def _run_inspect(args: argparse.Namespace, out: TextIO) -> int:
    log = get_logger()
    files: list[Path] = args.files
    total = len(files)
    unreadable = 0
    invalid = 0
    schema_doc: dict[str, Any] | None = None
    if args.command == "validate" and args.schema is not None:
        log.info("loading schema", file=str(args.schema))
        try:
            schema_doc = _load_schema(args.schema)
        except (ChecklistError, OSError) as exc:
            log.error("cannot use schema", file=str(args.schema), error=str(exc))
            return EXIT_UNREADABLE
    for n, path in enumerate(files, start=1):
        log.info("reading", step=f"{n}/{total}", file=str(path))
        try:
            result = _load_any(path)
        except (ChecklistError, OSError) as exc:
            log.error("cannot read checklist", file=str(path), error=str(exc))
            unreadable += 1
            continue
        for warning in result.warnings:
            log.warning("import", detail=warning)

        if args.command == "info":
            out.write(f"{path}\n")
            _format_info(result.checklist, out)
            continue

        issues = validate(result.checklist)
        if schema_doc is not None:
            instance = (
                cklb.load_raw(path)
                if path.suffix.lower() == ".cklb"
                else cklb.to_dict(result.checklist)
            )
            issues += validate_instance(instance, schema_doc)
        errors = [i for i in issues if i.level == "error"]
        warnings = [i for i in issues if i.level == "warning"]
        for issue, count, shape in _group_issues(issues):
            if count > 1:
                detail = f"{shape}: {issue.message} (x{count}, first at {issue.path})"
            else:
                detail = f"{issue.path}: {issue.message}"
            out.write(f"{path}: {issue.level}: {detail}\n")
        if errors or (args.strict and warnings):
            invalid += 1
        log.info("validated", file=str(path), errors=len(errors), warnings=len(warnings))

    log.info("done", files=total, unreadable=unreadable, invalid=invalid)
    if unreadable:
        return EXIT_UNREADABLE
    return EXIT_INVALID if invalid else EXIT_OK


def run(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    """Entry point with injectable output stream for tests."""
    out = out if out is not None else sys.stdout
    args = _build_parser().parse_args(argv)
    configure(-1 if args.quiet else 1 if args.verbose else 0)
    get_logger().info("starting", command=args.command)
    if args.command == "convert":
        return _run_convert(args, out)
    if args.command == "diff":
        return _run_diff(args, out)
    return _run_inspect(args, out)


def main() -> int:
    """Console-script entry point."""
    return run()


if __name__ == "__main__":
    sys.exit(main())
