"""XCCDF / SCAP / ZIP import tests."""

from __future__ import annotations

import io
import json
import re
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from conftest import FIXTURES, ORACLE_SCHEMA_DEVIATIONS, VOLATILE, rules_without, stig_header
from stigforage import cklb, xccdf
from stigforage.model import ChecklistError, Status
from stigforage.xmlsafe import UnsafeXmlError

XDIR = FIXTURES / "xccdf"
RHEL9 = XDIR / "U_RHEL_9_STIG_V1R1_Manual-xccdf-truncated.xml"
RHEL8 = XDIR / "U_RHEL_8_STIG_V1R12_Manual-xccdf-truncated.xml"
VPN = XDIR / "U_VPN_SRG_V2R5_Manual-xccdf-truncated.xml"
ORACLE = XDIR / "RHEL_9_TRUNCATED-V1R1.oracle.cklb"


def test_matches_independent_blank_checklist(id_factory: Callable[[], str]) -> None:
    """The oracle is the blank checklist STIG Manager produced from the same benchmark."""
    mine = cklb.to_dict(xccdf.load(RHEL9, new_id=id_factory).checklist)
    oracle = json.loads(ORACLE.read_text("utf-8-sig"))

    # Deliberate difference: we keep the real check-content-ref href; the oracle blanks it.
    # group_id_src is additive (the oracle lacks it); see conftest for ORACLE_SCHEMA_DEVIATIONS.
    drop = VOLATILE | ORACLE_SCHEMA_DEVIATIONS | {"check_content_ref", "group_id_src"}
    assert rules_without(mine, drop) == rules_without(oracle, drop)
    assert stig_header(mine) == stig_header(oracle)


@pytest.mark.parametrize(
    ("path", "stig_id", "version", "release"),
    [
        (RHEL9, "RHEL_9_TRUNCATED", 1, "Release: 1 Benchmark Date: 22 Sep 2023"),
        (RHEL8, "RHEL_8_TRUNCATED", 1, None),
        (VPN, "VPN_TRUNCATED", 2, "Release: 5 Benchmark Date: 07 Jun 2023"),
    ],
)
def test_real_benchmarks_load(path: Path, stig_id: str, version: int, release: str | None) -> None:
    result = xccdf.load(path)
    stig = result.checklist.stigs[0]
    assert (stig.stig_id, stig.version) == (stig_id, version)
    if release:
        assert stig.release_info == release
    assert len(stig.rules) == 10
    assert all(r.status is Status.NOT_REVIEWED and r.ccis for r in stig.rules)
    assert result.warnings == []


def test_description_fragment_is_unescaped() -> None:
    rule = xccdf.load(RHEL9).checklist.stigs[0].rules[0]
    assert rule.extra["discussion"].startswith("An operating system release is considered")
    assert rule.extra["documentable"] == "false"
    assert rule.extra["false_positives"] == ""


def _benchmark(
    rule_attrs: str = 'severity="medium"', description: str = "", extra: str = ""
) -> bytes:
    return f"""<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="B1">
<title>Bench</title><plain-text id="release-info">Release: 3</plain-text><version>7</version>
<Group id="V-1"><title>G</title><description>&lt;GroupDescription&gt;&lt;/GroupDescription&gt;</description>
<Rule id="SV-1r1_rule" {rule_attrs}><version>R-1</version><title>T</title>
<description>{description}</description>{extra}
<fixtext>fix it</fixtext>
<check system="c"><check-content-ref href="x.xml" name="M"/><check-content>do it</check-content></check>
</Rule></Group></Benchmark>""".encode()


def test_nested_escaping_in_description_is_resolved() -> None:
    desc = "&lt;VulnDiscussion&gt;a &amp;lt;b&amp;gt; &amp;amp; c&lt;/VulnDiscussion&gt;"
    rule = xccdf.loads(_benchmark(description=desc)).checklist.stigs[0].rules[0]
    assert rule.extra["discussion"] == "a <b> & c"


def test_fields_from_minimal_benchmark() -> None:
    extra = (
        '<ident system="http://cyber.mil/cci">CCI-000366</ident>'
        '<ident system="http://cyber.mil/legacy">V-99</ident>'
        '<ident system="http://other">ignored</ident>'
    )
    result = xccdf.loads(_benchmark(extra=extra))
    stig = result.checklist.stigs[0]
    rule = stig.rules[0]
    assert (stig.stig_name, stig.stig_id, stig.version, stig.release_info) == (
        "Bench", "B1", 7, "Release: 3",
    )  # fmt: skip
    assert (rule.rule_id, rule.rule_id_src, rule.rule_version) == ("SV-1r1", "SV-1r1_rule", "R-1")
    assert rule.ccis == ["CCI-000366"]
    assert rule.extra["legacy_ids"] == ["V-99"]
    assert rule.extra["fix_text"] == "fix it"
    assert rule.extra["check_content"] == "do it"
    assert rule.extra["check_content_ref"] == {"href": "x.xml", "name": "M"}
    assert rule.extra["group_title"] == "G"
    assert rule.extra["weight"] == "10.0"


def test_rule_weight_attribute_is_used() -> None:
    rule = (
        xccdf.loads(_benchmark(rule_attrs='severity="high" weight="5.0"'))
        .checklist.stigs[0]
        .rules[0]
    )
    assert rule.extra["weight"] == "5.0"
    assert rule.severity == "high"


def test_xccdf_1_2_namespace_is_accepted() -> None:
    data = _benchmark().replace(b"xccdf/1.1", b"xccdf/1.2")
    assert len(xccdf.loads(data).checklist.stigs[0].rules) == 1


def test_blank_checklist_has_default_target_and_title(id_factory: Callable[[], str]) -> None:
    checklist = xccdf.loads(_benchmark(), new_id=id_factory).checklist
    assert checklist.title == "Bench"
    assert checklist.target_data["host_name"] == ""
    assert checklist.id == "id-0003"  # stig uuid, rule uuid, then the checklist id


# --- data streams ---------------------------------------------------------------------------


def _wrap_in_datastream(benchmark_xml: bytes, count: int = 1) -> bytes:
    body = re.sub(rb"^<\?xml[^>]*\?>\s*", b"", benchmark_xml)
    body = re.sub(rb"<\?xml-stylesheet[^>]*\?>", b"", body)
    comps = b"".join(
        b'<ds:component id="c%d" timestamp="2023-01-01T00:00:00">%s</ds:component>' % (i, body)
        for i in range(count)
    )
    return (
        b'<ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2" '
        b'id="dsc">' + comps + b"</ds:data-stream-collection>"
    )


def test_synthetic_data_stream_yields_one_stig_per_benchmark() -> None:
    # Synthetic: wraps a real benchmark in the SCAP 1.2 source data stream layout. A real DISA
    # data stream has not been available to test against.
    result = xccdf.loads(_wrap_in_datastream(RHEL9.read_bytes(), count=2))
    assert [s.stig_id for s in result.checklist.stigs] == ["RHEL_9_TRUNCATED"] * 2
    assert all(len(s.rules) == 10 for s in result.checklist.stigs)


def test_data_stream_without_benchmark_is_an_error() -> None:
    data = b'<d:data-stream-collection xmlns:d="urn:x"><d:component/></d:data-stream-collection>'
    with pytest.raises(ChecklistError, match="contains no Benchmark"):
        xccdf.loads(data)


# --- ZIP ------------------------------------------------------------------------------------


def _zip(tmp_path: Path, members: dict[str, bytes]) -> Path:
    path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def test_zip_with_benchmark_and_other_xml(tmp_path: Path) -> None:
    path = _zip(
        tmp_path,
        {
            "U_X/RHEL-xccdf.xml": RHEL9.read_bytes(),
            "U_X/RHEL-oval.xml": b"<oval_definitions><huge/></oval_definitions>",
            "U_X/notes.txt": b"ignored",
            "../../evil/../path.xml": b"<other/>",
        },
    )
    result = xccdf.load(path)
    assert [s.stig_id for s in result.checklist.stigs] == ["RHEL_9_TRUNCATED"]
    assert any("skipped 2 XML entries" in w for w in result.warnings)
    assert not (tmp_path / "evil").exists()  # entry names are never used as paths


def test_zip_without_benchmark(tmp_path: Path) -> None:
    with pytest.raises(ChecklistError, match="no XCCDF Benchmark found"):
        xccdf.load(_zip(tmp_path, {"a.xml": b"<other/>"}))


def test_not_a_zip(tmp_path: Path) -> None:
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"this is not a zip")
    with pytest.raises(ChecklistError, match="not a valid ZIP"):
        xccdf.load(bad)


def test_zip_entry_over_size_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xccdf, "MAX_BYTES", 100)
    with pytest.raises(ChecklistError, match="over the size limit"):
        xccdf.load(_zip(tmp_path, {"a-xccdf.xml": RHEL9.read_bytes()}))


def test_zip_total_expansion_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xccdf, "_ZIP_TOTAL_LIMIT", 10)
    with pytest.raises(ChecklistError, match="expands past"):
        xccdf.load(_zip(tmp_path, {"a-xccdf.xml": b"<Benchmark/>" + b" " * 20}))


def test_zip_entry_count_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xccdf, "_ZIP_MAX_ENTRIES", 2)
    members = {f"f{i}.xml": b"<x/>" for i in range(3)}
    with pytest.raises(ChecklistError, match="more than 2 XML entries"):
        xccdf.load(_zip(tmp_path, members))


def test_zip_entry_with_dtd_is_refused(tmp_path: Path) -> None:
    evil = b'<!DOCTYPE Benchmark [<!ENTITY x "y">]><Benchmark id="x"/>'
    with pytest.raises(UnsafeXmlError):
        xccdf.load(_zip(tmp_path, {"evil-xccdf.xml": evil}))


# --- failure paths --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (
            lambda b: b.replace(
                b'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="B1">',
                b'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">',
            ),
            "Benchmark has no id",
        ),
        (lambda b: b.replace(b"<title>Bench</title>", b""), "has no title"),
        (lambda b: b.replace(b"<version>R-1</version>", b""), "has no version element"),
        (lambda b: b.replace(b'<Rule id="SV-1r1_rule"', b"<Rule"), "Rule has no id"),
        (lambda b: b.replace(b'<Group id="V-1">', b"<Group>"), "Group has no id"),
    ],
)
def test_incomplete_benchmarks_fail_loudly(mutate: Callable[[bytes], bytes], match: str) -> None:
    with pytest.raises(ChecklistError, match=match):
        xccdf.loads(mutate(_benchmark()))


def test_missing_severity_defaults_to_unknown_with_warning() -> None:
    result = xccdf.loads(_benchmark().replace(b' severity="medium"', b""))
    assert result.checklist.stigs[0].rules[0].severity == "unknown"
    assert any("no severity" in w for w in result.warnings)


def test_wrong_root_element() -> None:
    with pytest.raises(ChecklistError, match="neither a Benchmark nor a data stream"):
        xccdf.loads(b"<CHECKLIST/>")


def test_benchmark_without_rules_warns() -> None:
    data = b'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="B"><title>t</title></Benchmark>'
    result = xccdf.loads(data)
    assert any("contains no rules" in w for w in result.warnings)
    assert any("no release-info" in w for w in result.warnings)


def test_dtd_in_benchmark_is_refused() -> None:
    with pytest.raises(UnsafeXmlError):
        xccdf.loads(b'<!DOCTYPE a [<!ENTITY x "y">]>' + _benchmark())


def test_bytes_io_zip_member_names_with_traversal_are_inert(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../escape-xccdf.xml", RHEL9.read_bytes())
    path = tmp_path / "t.zip"
    path.write_bytes(buf.getvalue())
    result = xccdf.load(path)
    assert len(result.checklist.stigs) == 1
    assert list(tmp_path.iterdir()) == [path]
