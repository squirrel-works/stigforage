"""Command line interface.

Exit codes: 0 success, 1 validation errors found, 2 a file could not be read or parsed.
Progress and diagnostics go to stderr via structlog; results go to stdout.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from stigforage import __version__, cklb
from stigforage.log import configure, get_logger
from stigforage.model import Checklist, ChecklistError, Status, validate

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_UNREADABLE = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stigforage",
        description="Offline STIG checklist toolkit. File-only; never uses the network.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging on stderr")
    parser.add_argument("-q", "--quiet", action="store_true", help="warnings and errors only")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    info = sub.add_parser("info", help="summarise one or more .cklb checklists")
    info.add_argument("files", nargs="+", type=Path, metavar="FILE", help=".cklb checklist(s)")

    val = sub.add_parser("validate", help="check .cklb checklists for structural problems")
    val.add_argument("files", nargs="+", type=Path, metavar="FILE", help=".cklb checklist(s)")
    val.add_argument("--strict", action="store_true", help="treat warnings as errors (exit code 1)")
    return parser


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


def run(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    """Entry point with injectable output stream for tests."""
    out = out if out is not None else sys.stdout
    args = _build_parser().parse_args(argv)
    configure(-1 if args.quiet else 1 if args.verbose else 0)
    log = get_logger()

    files: list[Path] = args.files
    total = len(files)
    unreadable = 0
    invalid = 0
    log.info("starting", command=args.command, files=total)

    for n, path in enumerate(files, start=1):
        log.info("reading", step=f"{n}/{total}", file=str(path))
        try:
            checklist = cklb.load(path)
        except (ChecklistError, OSError) as exc:
            log.error("cannot read checklist", file=str(path), error=str(exc))
            unreadable += 1
            continue

        if args.command == "info":
            out.write(f"{path}\n")
            _format_info(checklist, out)
            continue

        issues = validate(checklist)
        errors = [i for i in issues if i.level == "error"]
        warnings = [i for i in issues if i.level == "warning"]
        for issue in issues:
            out.write(f"{path}: {issue.level}: {issue.path}: {issue.message}\n")
        if errors or (args.strict and warnings):
            invalid += 1
        log.info("validated", file=str(path), errors=len(errors), warnings=len(warnings))

    log.info("done", files=total, unreadable=unreadable, invalid=invalid)
    if unreadable:
        return EXIT_UNREADABLE
    if invalid:
        return EXIT_INVALID
    return EXIT_OK


def main() -> int:
    """Console-script entry point."""
    return run()


if __name__ == "__main__":
    sys.exit(main())
