"""Read and write legacy STIG Viewer 2 `.ckl` (XML) checklists.

The element layout and attribute names follow the CKL files in the public STIG Manager fixtures.
The writer has NOT been tested against STIG Viewer 2.x or eMASS; treat its output as unverified
until you have opened it in those tools.

Anything that cannot be carried across formats is reported in `ImportResult.warnings` (reading)
or the returned list (writing) instead of being dropped silently.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from stigforage.fsio import atomic_write_text, read_limited
from stigforage.model import (
    NULL_WHEN_EMPTY,
    Checklist,
    ChecklistError,
    IdFactory,
    ImportResult,
    Rule,
    Status,
    Stig,
    default_target_data,
    make_checklist,
    make_rule,
    make_stig,
    new_uuid,
    parse_version,
)
from stigforage.xmlsafe import parse_xml

__all__ = ["dump", "dumps", "load", "loads"]

_STATUS_IN = {
    "NotAFinding": Status.NOT_A_FINDING,
    "Open": Status.OPEN,
    "Not_Applicable": Status.NOT_APPLICABLE,
    "Not_Reviewed": Status.NOT_REVIEWED,
}
_STATUS_OUT = {v: k for k, v in _STATUS_IN.items()}

# CKL STIG_DATA attribute name -> make_rule keyword.
_ATTR_TO_FIELD = {
    "Weight": "weight",
    "Class": "classification",
    "Group_Title": "group_title",
    "Vuln_Discuss": "discussion",
    "IA_Controls": "ia_controls",
    "Check_Content": "check_content",
    "Fix_Text": "fix_text",
    "False_Positives": "false_positives",
    "False_Negatives": "false_negatives",
    "Documentable": "documentable",
    "Mitigations": "mitigations",
    "Potential_Impact": "potential_impacts",
    "Third_Party_Tools": "third_party_tools",
    "Mitigation_Control": "mitigation_control",
    "Responsibility": "responsibility",
    "Security_Override_Guidance": "security_override_guidance",
    "STIGRef": "stig_ref",
    "TargetKey": "target_key",
}
# Attributes we understand but deliberately do not map (no CKLB counterpart).
_IGNORED_ATTRS = frozenset({"Vuln_Num", "Severity", "Rule_ID", "Rule_Ver", "Rule_Title"}) | {
    "STIG_UUID",
    "Check_Content_Ref",
    "CCI_REF",
    "LEGACY_ID",
}
_ASSET_TO_TARGET = {
    "ROLE": "role",
    "ASSET_TYPE": "target_type",
    "HOST_NAME": "host_name",
    "HOST_IP": "ip_address",
    "HOST_MAC": "mac_address",
    "HOST_FQDN": "fqdn",
    "TARGET_COMMENT": "comments",
    "TECH_AREA": "technology_area",
    "WEB_DB_SITE": "web_db_site",
    "WEB_DB_INSTANCE": "web_db_instance",
}


def _text(element: ET.Element | None) -> str:
    return (element.text or "") if element is not None else ""


def _vuln_to_rule(
    vuln: ET.Element, path: str, stig_uuid: str, new_id: IdFactory, warnings: list[str]
) -> Rule:
    single: dict[str, str] = {}
    ccis: list[str] = []
    legacy: list[str] = []
    for sd in vuln.findall("STIG_DATA"):
        name = _text(sd.find("VULN_ATTRIBUTE")).strip()
        value = _text(sd.find("ATTRIBUTE_DATA"))
        if name == "CCI_REF":
            ccis.append(value.strip())
        elif name == "LEGACY_ID":
            legacy.append(value.strip())
        elif name:
            single.setdefault(name, value)
    for required in ("Vuln_Num", "Severity", "Rule_ID", "Rule_Ver"):
        if not single.get(required):
            raise ChecklistError(f"{path}: missing or empty STIG_DATA {required!r}")
    raw_status = _text(vuln.find("STATUS")).strip()
    if raw_status not in _STATUS_IN:
        valid = ", ".join(_STATUS_IN)
        raise ChecklistError(f"{path}.STATUS: {raw_status!r} is not one of {valid}")
    if (
        _text(vuln.find("SEVERITY_OVERRIDE")).strip()
        or _text(vuln.find("SEVERITY_JUSTIFICATION")).strip()
    ):
        warnings.append(
            f"{path}: severity override not carried over (CKLB override layout unverified)"
        )
    for name in single:
        if name not in _ATTR_TO_FIELD and name not in _IGNORED_ATTRS:
            warnings.append(f"{path}: unrecognised STIG_DATA attribute {name!r} not carried over")
    fields: dict[str, Any] = {}
    for attr, field_name in _ATTR_TO_FIELD.items():
        if attr in single:
            value = single[attr]
            fields[field_name] = None if (field_name in NULL_WHEN_EMPTY and not value) else value
    return make_rule(
        new_id=new_id,
        stig_uuid=stig_uuid,
        group_id=single["Vuln_Num"],
        rule_id_src=single["Rule_ID"],
        rule_version=single["Rule_Ver"],
        severity=single["Severity"],
        rule_title=single.get("Rule_Title", ""),
        status=_STATUS_IN[raw_status],
        comments=_text(vuln.find("COMMENTS")),
        finding_details=_text(vuln.find("FINDING_DETAILS")),
        ccis=ccis,
        legacy_ids=legacy,
        reference_identifier=fields.get("target_key"),
        **fields,
    )


def _istig_to_stig(istig: ET.Element, path: str, new_id: IdFactory, warnings: list[str]) -> Stig:
    info = istig.find("STIG_INFO")
    if info is None:
        raise ChecklistError(f"{path}: missing STIG_INFO")
    sid: dict[str, str] = {}
    for si in info.findall("SI_DATA"):
        name = _text(si.find("SID_NAME")).strip()
        if name:
            sid.setdefault(name, _text(si.find("SID_DATA")))
    for required in ("stigid", "title"):
        if not sid.get(required):
            raise ChecklistError(f"{path}.STIG_INFO: missing SI_DATA {required!r}")
    stig_uuid = new_id()
    rules = [
        _vuln_to_rule(v, f"{path}.VULN[{i}]", stig_uuid, new_id, warnings)
        for i, v in enumerate(istig.findall("VULN"))
    ]
    return make_stig(
        new_id=new_id,
        stig_uuid=stig_uuid,
        stig_name=sid["title"],
        display_name=sid.get("customname") or sid["title"],
        stig_id=sid["stigid"],
        release_info=sid.get("releaseinfo", ""),
        rules=rules,
        version=parse_version(sid.get("version", "")),
    )


def loads(data: bytes, *, source: str = "CKL", new_id: IdFactory = new_uuid) -> ImportResult:
    """Parse CKL XML bytes. `new_id` supplies the UUIDs CKLB needs (injectable for tests)."""
    root = parse_xml(data, source=source)
    if root.tag != "CHECKLIST":
        raise ChecklistError(f"{source}: root element is {root.tag!r}, expected 'CHECKLIST'")
    asset = root.find("ASSET")
    if asset is None:
        raise ChecklistError(f"{source}: missing ASSET element")
    stigs_el = root.find("STIGS")
    if stigs_el is None:
        raise ChecklistError(f"{source}: missing STIGS element")
    warnings: list[str] = []
    target = default_target_data()
    for child in asset:
        if child.tag in _ASSET_TO_TARGET:
            target[_ASSET_TO_TARGET[child.tag]] = _text(child)
        elif child.tag == "WEB_OR_DATABASE":
            target["is_web_database"] = _text(child).strip().lower() == "true"
        elif child.tag == "MARKING" and _text(child).strip() not in ("", "NONE"):
            warnings.append(
                f"{source}: ASSET/MARKING {_text(child).strip()!r} not carried over "
                "(CKLB marking field unverified)"
            )
    stigs = [
        _istig_to_stig(s, f"{source}: iSTIG[{i}]", new_id, warnings)
        for i, s in enumerate(stigs_el.findall("iSTIG"))
    ]
    checklist = make_checklist(
        new_id=new_id, title=target["host_name"], target_data=target, stigs=stigs
    )
    return ImportResult(checklist, warnings)


def load(path: Path, *, new_id: IdFactory = new_uuid) -> ImportResult:
    """Read and parse a `.ckl` file. Raises ChecklistError, OSError."""
    return loads(read_limited(path), source=str(path), new_id=new_id)


# --- writing --------------------------------------------------------------------------------


def _add(parent: ET.Element, tag: str, text: str | None = "") -> ET.Element:
    element = ET.SubElement(parent, tag)
    element.text = text or ""
    return element


def _stig_data(vuln: ET.Element, name: str, value: str | None) -> None:
    sd = ET.SubElement(vuln, "STIG_DATA")
    _add(sd, "VULN_ATTRIBUTE", name)
    _add(sd, "ATTRIBUTE_DATA", value)


def _rule_to_vuln(
    parent: ET.Element, rule: Rule, stig: Stig, warnings: list[str], path: str
) -> None:
    x = rule.extra
    vuln = ET.SubElement(parent, "VULN")
    for name, value in (
        ("Vuln_Num", rule.group_id),
        ("Severity", rule.severity),
        ("Weight", x.get("weight")),
        ("Group_Title", x.get("group_title")),
        ("Rule_ID", rule.rule_id_src or f"{rule.rule_id}_rule"),
        ("Rule_Ver", rule.rule_version),
        ("Rule_Title", rule.rule_title),
        ("Vuln_Discuss", x.get("discussion")),
        ("IA_Controls", x.get("ia_controls")),
        ("Check_Content", x.get("check_content")),
        ("Fix_Text", x.get("fix_text")),
        ("False_Positives", x.get("false_positives")),
        ("False_Negatives", x.get("false_negatives")),
        ("Documentable", x.get("documentable")),
        ("Mitigations", x.get("mitigations")),
        ("Potential_Impact", x.get("potential_impacts")),
        ("Third_Party_Tools", x.get("third_party_tools")),
        ("Mitigation_Control", x.get("mitigation_control")),
        ("Responsibility", x.get("responsibility")),
        ("Security_Override_Guidance", x.get("security_override_guidance")),
        (
            "STIGRef",
            x.get("stig_ref")
            or f"{stig.stig_name} :: Version {stig.version or ''}, {stig.release_info}",
        ),
    ):
        _stig_data(vuln, name, value)
    for legacy_id in x.get("legacy_ids") or []:
        _stig_data(vuln, "LEGACY_ID", str(legacy_id))
    for cci in rule.ccis:
        _stig_data(vuln, "CCI_REF", cci)
    _add(vuln, "STATUS", _STATUS_OUT[rule.status])
    _add(vuln, "FINDING_DETAILS", rule.finding_details)
    _add(vuln, "COMMENTS", rule.comments)
    _add(vuln, "SEVERITY_OVERRIDE")
    _add(vuln, "SEVERITY_JUSTIFICATION")
    if rule.overrides:
        warnings.append(f"{path}: rule overrides not written (CKLB override layout unverified)")


def _build(checklist: Checklist) -> tuple[ET.Element, list[str]]:
    warnings: list[str] = []
    root = ET.Element("CHECKLIST")
    td = checklist.target_data
    asset = ET.SubElement(root, "ASSET")
    for tag, value in (
        ("ROLE", td.get("role")),
        ("ASSET_TYPE", td.get("target_type")),
        ("MARKING", "NONE"),
        ("HOST_NAME", td.get("host_name")),
        ("HOST_IP", td.get("ip_address")),
        ("HOST_MAC", td.get("mac_address")),
        ("HOST_GUID", ""),
        ("HOST_FQDN", td.get("fqdn")),
        ("TARGET_COMMENT", td.get("comments")),
        ("TECH_AREA", td.get("technology_area")),
        ("TARGET_KEY", ""),
        ("WEB_OR_DATABASE", "true" if td.get("is_web_database") else "false"),
        ("WEB_DB_SITE", td.get("web_db_site")),
        ("WEB_DB_INSTANCE", td.get("web_db_instance")),
    ):
        _add(asset, tag, value if isinstance(value, str) else "")
    stigs_el = ET.SubElement(root, "STIGS")
    for si, stig in enumerate(checklist.stigs):
        istig = ET.SubElement(stigs_el, "iSTIG")
        info = ET.SubElement(istig, "STIG_INFO")
        for name, value in (
            ("version", "" if stig.version is None else str(stig.version)),
            ("classification", ""),
            ("customname", ""),
            ("stigid", stig.stig_id),
            ("description", ""),
            ("filename", ""),
            ("releaseinfo", stig.release_info),
            ("title", stig.stig_name),
            ("uuid", stig.uuid),
            ("notice", "terms-of-use"),
            ("source", ""),
        ):
            data = ET.SubElement(info, "SI_DATA")
            _add(data, "SID_NAME", name)
            if value:  # the public fixtures omit SID_DATA entirely when empty
                _add(data, "SID_DATA", value)
        for ri, rule in enumerate(stig.rules):
            _rule_to_vuln(istig, rule, stig, warnings, f"stigs[{si}].rules[{ri}]")
    return root, warnings


_XML_FORBIDDEN = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")


def dumps(checklist: Checklist) -> tuple[str, list[str]]:
    """Serialise to CKL XML text. Returns (xml, warnings)."""
    root, warnings = _build(checklist)
    for element in root.iter():
        if element.text and _XML_FORBIDDEN.search(element.text):
            # Control characters are illegal in XML 1.0; strip them rather than emit a file
            # that no XML parser (including ours) can read back.
            element.text = _XML_FORBIDDEN.sub("", element.text)
            warnings.append(f"<{element.tag}>: illegal XML control characters were removed")
    ET.indent(root, space="  ")
    body = ET.tostring(root, encoding="unicode", short_empty_elements=False)
    return f'<?xml version="1.0" encoding="UTF-8"?>\n{body}\n', warnings


def dump(checklist: Checklist, path: Path, *, force: bool = False) -> list[str]:
    """Atomically write a CKL file. Returns warnings about data that could not be written."""
    text, warnings = dumps(checklist)
    atomic_write_text(path, text, force=force)
    return warnings
