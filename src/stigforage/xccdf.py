"""Turn DISA XCCDF benchmarks into blank CKLB checklists.

Accepted inputs: a bare XCCDF 1.1/1.2 `Benchmark` XML file, a SCAP 1.2/1.3 data stream collection
(every embedded Benchmark is used), or a ZIP containing either. ZIPs are read in memory only:
nothing is extracted to disk and entry names are never used as paths.

Verified against the three truncated DISA-derived benchmarks in the public STIG Manager fixtures.
NOT verified: a real DISA SCAP data stream (none is available in the public fixtures), so the
data stream path rests on the SCAP 1.2 source-data-stream layout rather than a real file.
"""

from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any

from stigforage.fsio import MAX_BYTES, read_limited
from stigforage.model import (
    ChecklistError,
    IdFactory,
    ImportResult,
    Rule,
    Stig,
    default_target_data,
    make_checklist,
    make_rule,
    make_stig,
    new_uuid,
    parse_version,
    pretty_group_id,
)
from stigforage.xmlsafe import local_name, parse_xml

__all__ = ["load", "loads"]

_CCI_SYSTEM = "http://cyber.mil/cci"
_LEGACY_SYSTEM = "http://cyber.mil/legacy"
_DC_IDENTIFIER = "{http://purl.org/dc/elements/1.1/}identifier"
# The <description> of a DISA rule is itself an escaped XML fragment of these elements.
_DESCRIPTION_TAGS = {
    "VulnDiscussion": "discussion",
    "FalsePositives": "false_positives",
    "FalseNegatives": "false_negatives",
    "Documentable": "documentable",
    "Mitigations": "mitigations",
    "SeverityOverrideGuidance": "security_override_guidance",
    "PotentialImpacts": "potential_impacts",
    "ThirdPartyTools": "third_party_tools",
    "MitigationControl": "mitigation_control",
    "Responsibility": "responsibility",
    "IAControls": "ia_controls",
}
_DESCRIPTION_RE = {
    tag: re.compile(rf"<{tag}>(.*?)</{tag}>", re.DOTALL) for tag in _DESCRIPTION_TAGS
}

_ZIP_MAX_ENTRIES = 500
_ZIP_TOTAL_LIMIT = 512 * 1024 * 1024
_SNIFF_BYTES = 8192


def _child(parent: ET.Element, ns: str, name: str) -> ET.Element | None:
    return parent.find(f"{ns}{name}")


def _child_text(parent: ET.Element, ns: str, name: str) -> str:
    child = _child(parent, ns, name)
    return (child.text or "") if child is not None else ""


def _description_fields(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for tag, field_name in _DESCRIPTION_TAGS.items():
        match = _DESCRIPTION_RE[tag].search(raw)
        if match:
            # The fragment was escaped once more than XML parsing undoes, hence the second pass.
            out[field_name] = html.unescape(match.group(1))
    return out


def _check_fields(rule: ET.Element, ns: str) -> dict[str, Any]:
    """Manual-check text and reference from the first <check> that has check-content."""
    for check in rule.findall(f"{ns}check"):
        content = _child(check, ns, "check-content")
        if content is None:
            continue
        out: dict[str, Any] = {"check_content": content.text or ""}
        ref = _child(check, ns, "check-content-ref")
        if ref is not None:
            out["check_content_ref"] = {"href": ref.get("href", ""), "name": ref.get("name", "")}
        return out
    return {}


def _reference_identifier(rule: ET.Element, ns: str) -> str | None:
    """The DPMS target identifier from <reference><dc:identifier>, as the schema describes."""
    reference = _child(rule, ns, "reference")
    if reference is None:
        return None
    identifier = reference.find(_DC_IDENTIFIER)
    value = (identifier.text or "").strip() if identifier is not None else ""
    return value or None


def _idents(rule: ET.Element, ns: str) -> tuple[list[str], list[str]]:
    ccis: list[str] = []
    legacy: list[str] = []
    for ident in rule.findall(f"{ns}ident"):
        value = (ident.text or "").strip()
        if ident.get("system") == _CCI_SYSTEM:
            ccis.append(value)
        elif ident.get("system") == _LEGACY_SYSTEM:
            legacy.append(value)
    return ccis, legacy


def _rule(
    rule: ET.Element,
    group: ET.Element,
    ns: str,
    stig_uuid: str,
    new_id: IdFactory,
    where: str,
    warnings: list[str],
) -> Rule:
    rule_id = rule.get("id")
    severity = rule.get("severity")
    if not rule_id:
        raise ChecklistError(f"{where}: Rule has no id attribute")
    if not severity:
        # "unknown" is the XCCDF-specified default and is allowed by the CKLB schema.
        severity = "unknown"
        warnings.append(f"{where}: Rule {rule_id!r} has no severity attribute; using 'unknown'")
    rule_version = _child_text(rule, ns, "version")
    if not rule_version:
        raise ChecklistError(f"{where}: Rule {rule_id!r} has no version element")

    fields: dict[str, Any] = _description_fields(_child_text(rule, ns, "description"))
    fix = _child_text(rule, ns, "fixtext")
    if fix:
        fields["fix_text"] = fix
    fields.update(_check_fields(rule, ns))
    if rule.get("weight"):
        fields["weight"] = rule.get("weight")
    ccis, legacy = _idents(rule, ns)

    group_id = group.get("id")
    if not group_id:
        raise ChecklistError(f"{where}: Group has no id attribute")
    identifier = _reference_identifier(rule, ns)
    return make_rule(
        new_id=new_id,
        stig_uuid=stig_uuid,
        group_id=pretty_group_id(group_id),
        rule_id_src=rule_id,
        rule_version=rule_version,
        severity=severity,
        rule_title=_child_text(rule, ns, "title"),
        ccis=ccis,
        legacy_ids=legacy,
        group_id_src=group_id,
        group_title=_child_text(group, ns, "title"),
        group_description=_child_text(group, ns, "description"),
        target_key=identifier,
        reference_identifier=identifier,
        **fields,
    )


def _benchmark_to_stig(
    benchmark: ET.Element, source: str, new_id: IdFactory, warnings: list[str]
) -> Stig:
    ns = benchmark.tag[: benchmark.tag.index("}") + 1] if benchmark.tag.startswith("{") else ""
    stig_id = benchmark.get("id")
    if not stig_id:
        raise ChecklistError(f"{source}: Benchmark has no id attribute")
    title = _child_text(benchmark, ns, "title")
    if not title:
        raise ChecklistError(f"{source}: Benchmark {stig_id!r} has no title")
    release_info = ""
    for plain in benchmark.findall(f"{ns}plain-text"):
        if plain.get("id") == "release-info":
            release_info = plain.text or ""
    if not release_info:
        warnings.append(f"{source}: Benchmark {stig_id!r} has no release-info")
    if benchmark.findall(f"{ns}Rule"):
        warnings.append(f"{source}: Rules outside a Group in {stig_id!r} were skipped")

    stig_uuid = new_id()
    rules = [
        _rule(rule, group, ns, stig_uuid, new_id, f"{source}: {stig_id}", warnings)
        for group in benchmark.iter(f"{ns}Group")
        for rule in group.findall(f"{ns}Rule")
    ]
    if not rules:
        warnings.append(f"{source}: Benchmark {stig_id!r} contains no rules")
    return make_stig(
        new_id=new_id,
        stig_uuid=stig_uuid,
        stig_name=title,
        stig_id=stig_id,
        release_info=release_info,
        rules=rules,
        version=parse_version(_child_text(benchmark, ns, "version")),
    )


def _find_benchmarks(root: ET.Element, source: str) -> list[ET.Element]:
    kind = local_name(root.tag)
    if kind == "Benchmark":
        return [root]
    if kind == "data-stream-collection":
        found = [e for e in root.iter() if local_name(e.tag) == "Benchmark"]
        if not found:
            raise ChecklistError(f"{source}: data stream collection contains no Benchmark")
        return found
    raise ChecklistError(
        f"{source}: root element {kind!r} is neither a Benchmark nor a data stream collection"
    )


def _finish(stigs: list[Stig], warnings: list[str], new_id: IdFactory) -> ImportResult:
    checklist = make_checklist(
        new_id=new_id,
        title=stigs[0].stig_name if stigs else "",
        target_data=default_target_data(),
        stigs=stigs,
    )
    return ImportResult(checklist, warnings)


def loads(data: bytes, *, source: str = "XCCDF", new_id: IdFactory = new_uuid) -> ImportResult:
    """Parse XCCDF / data stream XML bytes."""
    warnings: list[str] = []
    root = parse_xml(data, source=source)
    stigs = [
        _benchmark_to_stig(b, source, new_id, warnings) for b in _find_benchmarks(root, source)
    ]
    return _finish(stigs, warnings, new_id)


def _load_zip(path: Path, new_id: IdFactory) -> ImportResult:
    warnings: list[str] = []
    stigs: list[Stig] = []
    skipped = 0
    total = 0
    try:
        with zipfile.ZipFile(path) as zf:
            entries = [i for i in zf.infolist() if i.filename.lower().endswith(".xml")]
            if len(entries) > _ZIP_MAX_ENTRIES:
                raise ChecklistError(f"{path}: more than {_ZIP_MAX_ENTRIES} XML entries")
            for entry in entries:
                if entry.file_size > MAX_BYTES:
                    raise ChecklistError(f"{path}: entry {entry.filename!r} is over the size limit")
                # Read with a hard cap: the declared size in a ZIP header can lie.
                with zf.open(entry) as fh:
                    data = fh.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    raise ChecklistError(f"{path}: entry {entry.filename!r} is over the size limit")
                total += len(data)
                if total > _ZIP_TOTAL_LIMIT:
                    raise ChecklistError(f"{path}: archive expands past {_ZIP_TOTAL_LIMIT} bytes")
                head = data[:_SNIFF_BYTES]
                if b"Benchmark" not in head and b"data-stream-collection" not in head:
                    skipped += 1
                    continue
                source = f"{path}!{entry.filename}"
                root = parse_xml(data, source=source)
                stigs.extend(
                    _benchmark_to_stig(b, source, new_id, warnings)
                    for b in _find_benchmarks(root, source)
                )
    except zipfile.BadZipFile as exc:
        raise ChecklistError(f"{path}: not a valid ZIP file: {exc}") from exc
    if not stigs:
        raise ChecklistError(f"{path}: no XCCDF Benchmark found in archive")
    if skipped:
        warnings.append(f"{path}: skipped {skipped} XML entries that are not benchmarks")
    return _finish(stigs, warnings, new_id)


def load(path: Path, *, new_id: IdFactory = new_uuid) -> ImportResult:
    """Read an XCCDF XML, SCAP data stream XML, or ZIP of either. Raises ChecklistError, OSError."""
    if path.suffix.lower() == ".zip":
        return _load_zip(path, new_id)
    return loads(read_limited(path), source=str(path), new_id=new_id)
