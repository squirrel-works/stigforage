"""`export poam`: the eMASS template filler and the POA&M items (ADR 0005, unit 3 revision)."""

from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Callable, Mapping, Sequence
from datetime import date, datetime
from pathlib import Path
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

import pytest

from conftest import DISA_CCI_ZIP, FIXTURES, SYNTHETIC_CCI_XML
from stigforage import cklb
from stigforage.cci import CciList
from stigforage.cli import EXIT_OK, EXIT_UNREADABLE, run
from stigforage.exports import (
    NO_HOST,
    POAM_FIELDS,
    FindingRow,
    PoamOptions,
    finding_rows,
    poam_columns,
    poam_items,
    poam_template,
    to_poam_xlsx,
)
from stigforage.model import ChecklistError, Status
from stigforage.xlsx import (
    MAX_CELL,
    Template,
    column_letter,
    fill_template,
    normalize_header,
    read_template,
)
from stigforage.xmlsafe import local_name, parse_xml

MULTI_A = FIXTURES / "cklb" / "Asset_a-multi-stig.cklb"
MULTI_B = FIXTURES / "cklb" / "Asset_b-multi-stig.cklb"

NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG = "http://schemas.openxmlformats.org/package/2006/relationships"
MAIN = "application/vnd.openxmlformats-officedocument.spreadsheetml"
HEAD = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
MARKER = "Control Vulnerability Description"
BANNER = "***** CONTROLLED UNCLASSIFIED INFORMATION *****"

# eMASS's field names in a shuffled order, with the quirks real templates have (a trailing space,
# a line break, case and spacing): columns must be found by header, never by position.
TEMPLATE_HEADERS = (
    "POA&M Item ID",
    "Severity",
    "Devices Affected",
    "Raw  Severity",
    "Comments",
    "OFFICE/ORG",
    "Identification Source ",
    "Identification Source Details",
    "Milestone Scheduled\nCompletion Date",
    "Milestone Status",
    "Milestone Description",
    "POA&M Scheduled Completion Date",
    "POA&M Status",
    "Security Checks",
    "Controls / APs",
    "Control Vulnerability Description",
    "Resources Required",
)
FIRST_COLUMN = 1  # headers start in column B, as eMASS's do
HEADER_ROW = 3
# Cell formats: 0 the default, 1 wrapped text (every column's style), 2 a short date.
CELL_XFS = (
    '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
    '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1">'
    '<alignment wrapText="1" vertical="top"/></xf>'
    '<xf numFmtId="14" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>'
)
SERIAL_2000_01_01 = "36526"  # Excel's serial number for 2000-01-01


def col(field: str) -> str:
    """The synthetic template's column letter for `field`."""
    [index] = [
        i for i, h in enumerate(TEMPLATE_HEADERS) if normalize_header(h) == normalize_header(field)
    ]
    return column_letter(FIRST_COLUMN + index)


def zip_bytes(entries: Mapping[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, blob in entries.items():
            zf.writestr(name, blob)
    return buffer.getvalue()


def make_template(
    headers: Sequence[str] = TEMPLATE_HEADERS,
    *,
    shared: bool = True,
    prefix: str = "",
    below: str = "",
    cols: Sequence[tuple[int, int, int]] = ((1, 30, 1),),
    workbook_type: str = f"{MAIN}.sheet.main+xml",
    sheet_name: str = "POA&M",
) -> bytes:
    """A small eMASS-like template: a banner, headers in row 3 from column B, an Instructions
    sheet listed first, and a part that nothing should touch."""
    p = prefix
    xmlns = f'xmlns:{p[:-1]}="{NS}"' if p else f'xmlns="{NS}"'
    strings: list[str] = []

    def text(ref: str, value: str) -> str:
        if shared:
            strings.append(value)
            return f'<{p}c r="{ref}" s="1" t="s"><{p}v>{len(strings) - 1}</{p}v></{p}c>'
        return (
            f'<{p}c r="{ref}" s="1" t="inlineStr"><{p}is><{p}t>{escape(value)}</{p}t></{p}is>'
            f"</{p}c>"
        )

    banner = text("A1", BANNER)
    header = "".join(
        text(f"{column_letter(FIRST_COLUMN + i)}{HEADER_ROW}", h) for i, h in enumerate(headers)
    )
    last = column_letter(FIRST_COLUMN + len(headers) - 1)
    col_xml = "".join(
        f'<{p}col min="{a}" max="{b}" width="20" style="{s}" customWidth="1"/>' for a, b, s in cols
    )
    sheet = (
        f'{HEAD}<{p}worksheet {xmlns} xmlns:r="{REL}" '
        'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
        'xmlns:x14ac="http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac" '
        f'mc:Ignorable="x14ac"><{p}dimension ref="A1:{last}{HEADER_ROW}"/>'
        + (f"<{p}cols>{col_xml}</{p}cols>" if cols else "")
        + f'<{p}sheetData><{p}row r="1">{banner}</{p}row>'
        f'<{p}row r="2" x14ac:dyDescent="0.25"><{p}c r="A2" s="1"/></{p}row>'
        f'<{p}row r="{HEADER_ROW}">{header}</{p}row>{below}</{p}sheetData>'
        f'<{p}dataValidations count="1"><{p}dataValidation type="list" sqref="B4:B9">'
        f'<{p}formula1>"Ongoing,Risk Accepted"</{p}formula1></{p}dataValidation>'
        f"</{p}dataValidations></{p}worksheet>"
    )
    instructions = (
        f'{HEAD}<{p}worksheet {xmlns}><{p}sheetData><{p}row r="1"><{p}c r="A1" t="inlineStr">'
        f"<{p}is><{p}t>Instructions</{p}t></{p}is></{p}c></{p}row></{p}sheetData></{p}worksheet>"
    )
    xfs = re.sub(r"<(/?)(xf|alignment)\b", rf"<\1{p}\2", CELL_XFS)
    styles = (
        f'{HEAD}<{p}styleSheet {xmlns}><{p}fonts count="1"><{p}font/></{p}fonts>'
        f'<{p}fills count="1"><{p}fill><{p}patternFill patternType="none"/></{p}fill></{p}fills>'
        f'<{p}borders count="1"><{p}border/></{p}borders>'
        f'<{p}cellStyleXfs count="1"><{p}xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>'
        f'</{p}cellStyleXfs><{p}cellXfs count="3">{xfs}</{p}cellXfs>'
        f'<{p}cellStyles count="1"><{p}cellStyle name="Normal" xfId="0" builtinId="0"/>'
        f"</{p}cellStyles></{p}styleSheet>"
    )
    workbook = (
        f'{HEAD}<{p}workbook {xmlns} xmlns:r="{REL}"><{p}sheets>'
        f'<{p}sheet name="Instructions" sheetId="2" r:id="rId2"/>'
        f'<{p}sheet name="{escape(sheet_name)}" sheetId="1" r:id="rId1"/></{p}sheets></{p}workbook>'
    )

    def rels(*items: tuple[str, str, str]) -> str:
        return (
            f'{HEAD}<Relationships xmlns="{PKG}">'
            + "".join(
                f'<Relationship Id="{i}" Type="{REL}/{kind}" Target="{target}"/>'
                for i, kind, target in items
            )
            + "</Relationships>"
        )

    shared_rel = [("rId4", "sharedStrings", "sharedStrings.xml")] if shared else []
    sst = (
        f'{HEAD}<{p}sst {xmlns} count="{len(strings)}" uniqueCount="{len(strings)}">'
        + "".join(f"<{p}si><{p}t>{escape(s)}</{p}t></{p}si>" for s in strings)
        + f"</{p}sst>"
    )
    overrides = {
        "/xl/workbook.xml": workbook_type,
        "/xl/worksheets/sheet1.xml": f"{MAIN}.worksheet+xml",
        "/xl/worksheets/sheet2.xml": f"{MAIN}.worksheet+xml",
        "/xl/styles.xml": f"{MAIN}.styles+xml",
        **({"/xl/sharedStrings.xml": f"{MAIN}.sharedStrings+xml"} if shared else {}),
    }
    types = (
        f'{HEAD}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        + "".join(f'<Override PartName="{k}" ContentType="{v}"/>' for k, v in overrides.items())
        + "</Types>"
    )
    entries = {
        "[Content_Types].xml": types,
        "_rels/.rels": rels(("rId1", "officeDocument", "xl/workbook.xml")),
        "xl/workbook.xml": workbook,
        "xl/_rels/workbook.xml.rels": rels(
            ("rId1", "worksheet", "worksheets/sheet1.xml"),
            ("rId2", "worksheet", "/xl/worksheets/sheet2.xml"),  # absolute targets are legal
            ("rId3", "styles", "styles.xml"),
            *shared_rel,
        ),
        "xl/worksheets/sheet1.xml": sheet,
        "xl/worksheets/sheet2.xml": instructions,
        "xl/styles.xml": styles,
        **({"xl/sharedStrings.xml": sst} if shared else {}),
        "customXml/item1.xml": f"{HEAD}<untouched/>",
    }
    return zip_bytes({k: v.encode("utf-8") for k, v in entries.items()})


def parts(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


def with_part(data: bytes, name: str, edit: Callable[[str], str]) -> bytes:
    entries = parts(data)
    before = entries[name].decode("utf-8")
    after = edit(before)
    assert after != before, "the edit did not apply"
    entries[name] = after.encode("utf-8")
    return zip_bytes(entries)


def cells(data: bytes, name: str = "xl/worksheets/sheet1.xml") -> dict[str, tuple[str | None, ...]]:
    """{reference: (type, style, text)} for every cell of a worksheet, read with the stdlib."""
    entries = parts(data)
    shared = [
        "".join(t.text or "" for t in si.iter() if local_name(t.tag) == "t")
        for si in parse_xml(entries.get("xl/sharedStrings.xml", b"<sst/>"))
        if local_name(si.tag) == "si"
    ]
    found: dict[str, tuple[str | None, ...]] = {}
    for c in (e for e in parse_xml(entries[name]).iter() if local_name(e.tag) == "c"):
        kind = c.get("t")
        if kind == "inlineStr":
            text = "".join(t.text or "" for t in c.iter() if local_name(t.tag) == "t")
        else:
            v = next((x for x in c if local_name(x.tag) == "v"), None)
            raw = "" if v is None else v.text or ""
            text = shared[int(raw)] if kind == "s" else raw
        found[c.get("r", "")] = (kind, c.get("s"), text)
    return found


def row_numbers(data: bytes, name: str = "xl/worksheets/sheet1.xml") -> list[int]:
    return [int(r.get("r", "0")) for r in parse_xml(parts(data)[name]).iter()
            if local_name(r.tag) == "row"]  # fmt: skip


def cell_formats(data: bytes) -> ET.Element:
    styles = parse_xml(parts(data)["xl/styles.xml"])
    return next(e for e in styles.iter() if local_name(e.tag) == "cellXfs")


def template(data: bytes | None = None) -> Template:
    return read_template(data or make_template(), sheet="POA&M", marker=MARKER)


def _row(group: str = "V-1", host: str = "h1", **kw: object) -> FindingRow:
    base: dict[str, object] = {
        "host": host, "stig_id": "S", "release": "V1R1",
        "release_info": "Release: 1 Benchmark Date: x", "group_id": group,
        "rule_id": f"S{group}r1", "rule_version": "X-1", "severity": "medium",
        "status": Status.OPEN, "title": "title", "comments": "", "finding_details": "",
        "discussion": "why", "ccis": ("CCI-000366",), "controls": ("CM-6",),
        "references": ("CM-6 b",), "notes": (),
    }  # fmt: skip
    return FindingRow(**{**base, **kw})  # type: ignore[arg-type]


def _cli(*argv: str | Path) -> tuple[int, str]:
    out = io.StringIO()
    return run([str(a) for a in argv], out=out), out.getvalue()


# --- reading a template ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("index", "letters"),
    [(0, "A"), (25, "Z"), (26, "AA"), (701, "ZZ"), (702, "AAA"), (16383, "XFD")],
)
def test_column_letters(index: int, letters: str) -> None:
    assert column_letter(index) == letters


@pytest.mark.parametrize("index", [-1, 16384])
def test_column_letter_refuses_columns_outside_a_to_xfd(index: int) -> None:
    with pytest.raises(ValueError, match="outside A to XFD"):
        column_letter(index)


def test_headers_compare_with_whitespace_and_case_normalised() -> None:
    assert normalize_header("Identification Source ") == normalize_header("identification source")
    assert normalize_header("Personnel Resources: \nCost Code") == "personnel resources: cost code"


@pytest.mark.parametrize(("shared", "prefix"), [(True, ""), (False, ""), (True, "x:")])
def test_the_header_row_and_its_columns_are_located(shared: bool, prefix: str) -> None:
    found = template(make_template(shared=shared, prefix=prefix))
    assert (found.header_row, found.sheet_part) == (HEADER_ROW, "xl/worksheets/sheet1.xml")
    assert found.headers[normalize_header("Severity")] == [FIRST_COLUMN + 1]
    assert found.headers[normalize_header("Identification Source")] == [FIRST_COLUMN + 6]
    assert (found.column_style(5), found.column_style(40)) == (1, None)


def test_rows_and_cells_without_references_follow_the_previous_one() -> None:
    data = with_part(make_template(), "xl/worksheets/sheet1.xml",
                     lambda s: re.sub(r' r="[A-Z]*\d+"', "", s))  # fmt: skip
    found = template(data)
    assert found.header_row == HEADER_ROW
    assert found.headers[normalize_header("POA&M Item ID")] == [0]  # A, without a reference
    assert row_numbers(fill_template(found, [{1: "x"}]))[-1] == HEADER_ROW + 1


def test_a_rich_text_header_reads_as_its_text() -> None:
    rich = (
        "<si><r><t>Control Vulnerability </t></r><r><rPr><b/></rPr><t>Description</t></r>"
        '<rPh sb="0" eb="1"><t>X</t></rPh></si>'
    )
    data = with_part(make_template(), "xl/sharedStrings.xml",
                     lambda s: s.replace(f"<si><t>{MARKER}</t></si>", rich))  # fmt: skip
    assert template(data).headers[normalize_header(MARKER)] == [FIRST_COLUMN + 15]


def test_the_sheet_is_found_by_its_name_not_its_position() -> None:
    assert template(make_template(sheet_name="poa&m ")).header_row == HEADER_ROW
    with pytest.raises(ChecklistError, match=r"no worksheet named 'POA&M'.*'Instructions'"):
        template(make_template(sheet_name="Sheet1"))


def test_an_ambiguous_or_non_worksheet_sheet_is_refused() -> None:
    twice = with_part(make_template(), "xl/workbook.xml", lambda s: s.replace(
        "</sheets>", '<sheet name="poa&amp;m" sheetId="3" r:id="rId2"/></sheets>'))  # fmt: skip
    with pytest.raises(ChecklistError, match="more than one worksheet named 'POA&M'"):
        template(twice)
    chart = with_part(make_template(), "xl/_rels/workbook.xml.rels", lambda s: s.replace(
        'Id="rId1" Type="' + REL + '/worksheet"', 'Id="rId1" Type="' + REL + '/chartsheet"'))  # fmt: skip
    with pytest.raises(ChecklistError, match="'POA&M' is not a worksheet"):
        template(chart)


def test_a_template_without_the_header_row_is_refused() -> None:
    with pytest.raises(ChecklistError, match="no header row with 'Nothing Like This'"):
        read_template(make_template(), sheet="POA&M", marker="Nothing Like This")


@pytest.mark.parametrize(
    "below",
    [
        '<row r="4"><c r="C4" t="inlineStr"><is><t>an old item</t></is></c></row>',
        '<row r="4"><c r="C4" t="s"><v>0</v></c></row>',
        '<row r="4"><c r="C4"><f>1+1</f></c></row>',
    ],
)
def test_a_template_with_entries_below_its_header_is_refused(below: str) -> None:
    with pytest.raises(ChecklistError, match=r"already has entries below its header \(row 4\)"):
        template(make_template(below=below))


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"not a zip", "not an .xlsx workbook"),
        (zip_bytes({"a.txt": b"x"}), "no single main document"),
        (make_template(workbook_type="application/vnd.ms-excel.sheet.macroEnabled.main+xml"),
         "macro-enabled"),
        (make_template(workbook_type=f"{MAIN}.template.main+xml"), "save it as an .xlsx workbook"),
    ],
)  # fmt: skip
def test_files_that_are_not_plain_workbooks_are_refused(data: bytes, message: str) -> None:
    with pytest.raises(ChecklistError, match=re.escape(message)):
        template(data)


def test_a_package_with_a_duplicate_entry_is_refused() -> None:
    entries = parts(make_template())
    buffer = io.BytesIO()
    with (
        pytest.warns(UserWarning, match="Duplicate name"),
        zipfile.ZipFile(buffer, "w") as zf,
    ):
        for name, blob in entries.items():
            zf.writestr(name, blob)
        zf.writestr("xl/workbook.xml", entries["xl/workbook.xml"])
    with pytest.raises(ChecklistError, match=re.escape("duplicate entry 'xl/workbook.xml'")):
        template(buffer.getvalue())


@pytest.mark.parametrize(
    ("limit", "value", "message"),
    [("_MAX_ENTRIES", 5, "more than 5 entries"), ("MAX_BYTES", 2000, "over the size limit")],
)
def test_oversized_packages_are_refused(
    monkeypatch: pytest.MonkeyPatch, limit: str, value: int, message: str
) -> None:
    monkeypatch.setattr(f"stigforage.xlsx.{limit}", value)
    with pytest.raises(ChecklistError, match=message):
        template()


# --- filling it -----------------------------------------------------------------------------


def test_rows_go_below_the_header_as_inline_text_in_the_column_style() -> None:
    data = fill_template(template(), [{2: "one\ntwo", 3: "<&> \"'"}, {2: "  pad  ", 5: "=1+1"}])
    got = cells(data)
    assert got["C4"] == ("inlineStr", "1", "one\ntwo")
    assert got["D4"] == ("inlineStr", "1", "<&> \"'")
    assert got["C5"][2] == "  pad  "
    assert got["F5"] == ("inlineStr", "1", "=1+1")  # text: an inline string is never a formula
    assert got["A1"][2] == BANNER
    # Excel would trim the spaces without this.
    assert '<t xml:space="preserve">  pad  </t>' in parts(data)["xl/worksheets/sheet1.xml"].decode()


def test_empty_text_is_left_out_and_unstyled_columns_get_no_style() -> None:
    got = cells(fill_template(template(make_template(cols=())), [{2: "", 3: "x"}]))
    assert "C4" not in got
    assert got["D4"] == ("inlineStr", None, "x")


def test_dates_are_serial_numbers_in_a_new_date_format() -> None:
    data = fill_template(template(), [{2: date(2000, 1, 1), 3: date(2000, 1, 1)}])
    got = cells(data)
    assert got["C4"] == got["D4"] == (None, "3", SERIAL_2000_01_01)
    formats = cell_formats(data)
    assert (len(formats), formats.get("count")) == (4, "4")  # one new format for both columns
    added = formats[3]
    assert (added.get("numFmtId"), added.get("applyNumberFormat")) == ("14", "1")
    [alignment] = list(added)  # the column's own formatting is kept
    assert alignment.get("wrapText") == "1"


def test_a_column_already_formatted_as_a_date_keeps_its_style() -> None:
    found = template(make_template(cols=((1, 2, 1), (3, 3, 2), (4, 30, 1))))
    data = fill_template(found, [{2: date(2000, 1, 1)}])
    assert cells(data)["C4"] == (None, "2", SERIAL_2000_01_01)
    assert parts(data)["xl/styles.xml"] == found.parts["xl/styles.xml"]


def test_a_prefixed_worksheet_gets_prefixed_rows() -> None:
    found = template(make_template(prefix="x:"))
    data = fill_template(found, [{2: "x", 3: date(2000, 1, 1)}])
    assert '<x:row r="4"><x:c r="C4" s="1" t="inlineStr">' in parts(data)[found.sheet_part].decode()
    assert cells(data)["D4"] == (None, "3", SERIAL_2000_01_01)


def test_everything_but_the_worksheet_is_kept_byte_for_byte() -> None:
    found = template()
    out = parts(fill_template(found, [{2: "x"}]))
    assert list(out) == list(found.parts)  # the same entries, in the same order
    assert {n for n in out if out[n] != found.parts[n]} == {found.sheet_part}


def test_the_worksheet_keeps_its_markup_and_widens_its_used_range() -> None:
    found = template()
    xml = parts(fill_template(found, [{2: "x"}, {20: "y"}]))[found.sheet_part].decode()
    assert 'mc:Ignorable="x14ac"' in xml and 'x14ac:dyDescent="0.25"' in xml
    assert '<dimension ref="A1:U5"/>' in xml  # was A1:R3
    assert '<dataValidation type="list" sqref="B4:B9">' in xml


def test_formatting_only_rows_below_the_header_give_way_or_stay() -> None:
    below = (
        '<row r="4" ht="30" customHeight="1"><c r="C4" s="1"/></row>'
        '<row r="9" ht="30" customHeight="1"><c r="C9" s="1"/></row>'
    )
    found = template(make_template(below=below))
    data = fill_template(found, [{2: "a"}, {2: "b"}])
    assert row_numbers(data) == [1, 2, 3, 4, 5, 9]
    assert cells(data)["C4"][2] == "a"


def test_illegal_characters_and_carriage_returns_and_long_cells() -> None:
    long_text = "y" * (MAX_CELL + 10)
    row: dict[int, str | date] = {2: f"a{chr(1)}b{chr(11)}c", 3: "x\r\ny\rz", 4: long_text}
    got = cells(fill_template(template(), [row]))
    assert got["C4"][2] == "abc"
    assert got["D4"][2] == "x\ny\nz"  # XML's own line-end handling, as Excel reads it too
    text = got["E4"][2] or ""
    assert len(text) == MAX_CELL
    assert text.endswith("over Excel's 32,767-character cell limit]")


def test_the_same_template_and_rows_give_the_same_bytes() -> None:
    found = template()
    data = fill_template(found, [{2: "x"}])
    assert data == fill_template(found, [{2: "x"}])
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        assert {i.date_time for i in zf.infolist()} == {(1980, 1, 1, 0, 0, 0)}


def test_no_rows_leave_the_worksheet_as_it_was() -> None:
    found = template()
    assert parts(fill_template(found, []))[found.sheet_part] == found.parts[found.sheet_part]


@pytest.mark.parametrize(
    ("row", "message"),
    [({16384: "x"}, "outside A to XFD"), ({2: date(1900, 2, 28)}, "before 1900-03-01")],
)
def test_cells_excel_cannot_hold_are_refused(row: dict[int, str | date], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        fill_template(template(), [row])


def test_openpyxl_reads_the_filled_template(tmp_path: Path) -> None:
    # Cross-check with an independent reader (a pinned dev dependency; skips without it).
    openpyxl = pytest.importorskip("openpyxl")
    path = tmp_path / "x.xlsx"
    rows: list[dict[int, str | date]] = [
        {2: "one\ntwo", 3: date(2026, 12, 31), 4: "État ✓"},
        {2: "=1+1"},
    ]
    path.write_bytes(fill_template(template(), rows))
    workbook = openpyxl.load_workbook(path)
    assert workbook.sheetnames == ["Instructions", "POA&M"]
    ws = workbook["POA&M"]
    assert ws["A1"].value == BANNER
    assert [c.value for c in ws[HEADER_ROW]][FIRST_COLUMN:] == list(TEMPLATE_HEADERS)
    assert [ws["C4"].value, ws["D4"].value, ws["E4"].value, ws["C5"].value] == [
        "one\ntwo",
        datetime(2026, 12, 31),
        "État ✓",
        "=1+1",
    ]
    assert ws["D4"].is_date and ws["C4"].alignment.wrap_text
    assert workbook["Instructions"]["A1"].value == "Instructions"


# --- POA&M items ----------------------------------------------------------------------------


def test_poam_columns_follow_the_headers_wherever_they_are() -> None:
    columns = poam_columns(poam_template(make_template()))
    assert set(columns) == set(POAM_FIELDS)
    assert columns["Raw Severity"] == FIRST_COLUMN + 3  # headed "Raw  Severity"
    assert columns["Milestone Scheduled Completion Date"] == FIRST_COLUMN + 8  # a line break


def test_a_template_missing_or_repeating_a_field_is_refused() -> None:
    without = [h for h in TEMPLATE_HEADERS if h != "POA&M Status"]
    with pytest.raises(ChecklistError, match="no column headed 'POA&M Status'"):
        poam_template(make_template(without))
    with pytest.raises(ChecklistError, match="more than one column headed 'Comments'"):
        poam_template(make_template([*TEMPLATE_HEADERS, "comments"]))


def test_stig_managers_older_layout_is_refused() -> None:
    # Its single "Status" and "Milestone with Completion Dates" predate eMASS's current template.
    old = ["POA&M Item ID", MARKER, "Controls / APs", "Office/Org", "Security Checks",
           "Scheduled Completion Date", "Milestone with Completion Dates", "Status", "Comments"]  # fmt: skip
    with pytest.raises(ChecklistError, match="no column headed 'POA&M Status'"):
        poam_template(make_template(old))


def test_only_open_rules_become_items_and_the_rest_are_counted() -> None:
    rows = [
        _row("V-1", status=Status.OPEN),
        _row("V-2", status=Status.NOT_REVIEWED),
        _row("V-3", status=Status.NOT_A_FINDING),
        _row("V-4", status=Status.NOT_APPLICABLE),
    ]
    items, summary = poam_items(rows, PoamOptions())
    assert [i["Security Checks"] for i in items] == ["SV-1r1"]
    assert (summary.items, summary.open_rules, summary.not_reviewed) == (1, 1, 1)


def test_one_item_per_vulnerability_across_hosts_and_revisions() -> None:
    rows = [
        _row("V-1", host="web01", rule_id="SV-1r1", severity="medium", ccis=("CCI-1",)),
        _row("V-1", host="web02", rule_id="SV-1r2", severity="high", ccis=("CCI-1", "CCI-2"),
             controls=("CM-6", "AC-3"), release="V1R2", release_info="Release: 2"),
    ]  # fmt: skip
    [item], summary = poam_items(rows, PoamOptions())
    assert item["Devices Affected"] == "web01\nweb02"
    assert item["Security Checks"] == "SV-1r1;SV-1r2"  # semicolons, as eMASS asks
    assert item["Controls / APs"] == "CM-6;AC-3"
    assert (item["Raw Severity"], item["Severity"]) == ("High", "High")  # the most severe
    assert item["Comments"] == "CCI-1\nCCI-2"
    assert item["Identification Source Details"] == (
        "S\nV1R1\nRelease: 1 Benchmark Date: x\n\nS\nV1R2\nRelease: 2"
    )
    assert (summary.items, summary.open_rules) == (1, 2)


def test_ongoing_items_get_one_open_milestone() -> None:
    due = date(2026, 12, 31)
    [item], _ = poam_items([_row()], PoamOptions(office="ISSM", completion_date=due))
    assert (item["POA&M Status"], item["Office/Org"]) == ("Ongoing", "ISSM")
    assert item["POA&M Scheduled Completion Date"] == due
    assert item["Milestone Scheduled Completion Date"] == due
    assert (item["Milestone Description"], item["Milestone Status"]) == (
        "Resolve this finding.",
        "Open",
    )
    [undated], _ = poam_items([_row()], PoamOptions())
    assert not {"POA&M Scheduled Completion Date", "Milestone Scheduled Completion Date"} & set(
        undated
    )
    assert undated["Milestone Description"] == "Resolve this finding."


def test_risk_accepted_items_get_no_milestone() -> None:
    [item], _ = poam_items([_row()], PoamOptions(status="Risk Accepted"))
    assert item["POA&M Status"] == "Risk Accepted"
    assert not [k for k in item if k.startswith("Milestone") or "Completion" in k]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"status": "Completed"}, "not one of"),
        ({"status": "Risk Accepted", "completion_date": date(2026, 12, 31)}, "no completion date"),
    ],
)
def test_poam_options_refuse_what_emass_would(kwargs: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        PoamOptions(**kwargs)  # type: ignore[arg-type]


def test_description_and_severity_and_no_risk_analysis() -> None:
    [item], _ = poam_items([_row(title="T", discussion="D", severity="low")], PoamOptions())
    assert item["Control Vulnerability Description"] == "Title:\nT\n\nDescription:\nD"
    assert (item["Raw Severity"], item["Severity"]) == ("Low", "Low")
    assert set(item) <= set(POAM_FIELDS)  # likelihood, impact and residual risk: the assessor's


def test_crosswalk_notes_follow_the_ccis_in_comments() -> None:
    [item], _ = poam_items(
        [_row(ccis=("CCI-002132",), controls=(), notes=("CCI-002132: no Rev 5 reference",))],
        PoamOptions(),
    )
    assert "Controls / APs" not in item
    assert item["Comments"] == "CCI-002132\n\nCCI-002132: no Rev 5 reference"


def test_unknown_severity_and_missing_host() -> None:
    [item], _ = poam_items([_row(severity="unknown", host="")], PoamOptions())
    assert not {"Raw Severity", "Severity"} & set(item)
    assert item["Devices Affected"] == NO_HOST


def test_items_are_ordered_cat_i_first_then_stig_then_v_number() -> None:
    rows = [
        _row("V-10", severity="medium"),
        _row("V-9", severity="medium"),
        _row("V-5", severity="low"),
        _row("V-7", severity="high"),
        _row("V-1", severity="medium", stig_id="A"),
    ]
    items, _ = poam_items(rows, PoamOptions())
    assert [(i["Raw Severity"], i["Security Checks"]) for i in items] == [
        ("High", "SV-7r1"),
        ("Moderate", "SV-1r1"),  # STIG "A" sorts before "S"
        ("Moderate", "SV-9r1"),  # V-9 before V-10: numeric, not text, order
        ("Moderate", "SV-10r1"),
        ("Low", "SV-5r1"),
    ]


def test_fields_emass_requires_that_stay_empty_are_reported() -> None:
    _, bare = poam_items([_row(), _row("V-2")], PoamOptions())
    assert bare.empty_required == (
        ("POA&M Scheduled Completion Date", 2),
        ("Office/Org", 2),
        ("Resources Required", 2),
        ("Identification Source", 2),
        ("Milestone Scheduled Completion Date", 2),
    )
    _, filled = poam_items([_row()], PoamOptions(office="ISSM", completion_date=date(2026, 1, 2)))
    assert filled.empty_required == (("Resources Required", 1), ("Identification Source", 1))
    _, accepted = poam_items(
        [_row(ccis=(), notes=()), _row("V-2")], PoamOptions(office="ISSM", status="Risk Accepted")
    )
    assert accepted.empty_required == (
        ("Resources Required", 2),
        ("Comments", 1),
        ("Identification Source", 2),
    )


def test_the_poam_fills_the_template_by_header(synthetic_cci_list: CciList) -> None:
    rows, _ = finding_rows([cklb.load(MULTI_A), cklb.load(MULTI_B)], synthetic_cci_list)
    options = PoamOptions(office="ISSM", completion_date=date(2000, 1, 1))
    data, summary = to_poam_xlsx(rows, options, poam_template(make_template()))
    got = cells(data)
    items = range(HEADER_ROW + 1, HEADER_ROW + 1 + summary.items)
    assert summary.items == 8
    assert row_numbers(data) == [1, 2, HEADER_ROW, *items]
    assert {got[f"{col('Office/Org')}{r}"][2] for r in items} == {"ISSM"}
    assert {got[f"{col('POA&M Status')}{r}"][2] for r in items} == {"Ongoing"}
    assert {got[f"{col('Milestone Scheduled Completion Date')}{r}"][2] for r in items} == {
        SERIAL_2000_01_01
    }
    assert not [r for r in items if f"{col('POA&M Item ID')}{r}" in got]  # eMASS assigns it


# --- CLI ------------------------------------------------------------------------------------


@pytest.fixture
def template_file(tmp_path: Path) -> Path:
    path = tmp_path / "template.xlsx"
    path.write_bytes(make_template())
    return path


def test_cli_export_poam_is_a_dry_run_by_default(tmp_path: Path, template_file: Path) -> None:
    dest = tmp_path / "poam.xlsx"
    code, out = _cli("export", "poam", MULTI_A, MULTI_B, "--template", template_file, "-o", dest)
    assert code == EXIT_OK
    assert "POA&M: 8 item(s) from 8 open rule(s); 42 not-reviewed rule(s) are counted" in out
    assert "dry run: would write 8 POA&M item(s) from 2 checklist(s)" in out
    assert not dest.exists()


def test_cli_export_poam_fills_a_copy_of_the_template(
    tmp_path: Path, template_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cci = tmp_path / "U_CCI_List.xml"
    cci.write_bytes(SYNTHETIC_CCI_XML)
    dest = tmp_path / "poam.xlsx"
    before = template_file.read_bytes()
    code, _ = _cli("export", "poam", MULTI_A, MULTI_B, "--template", template_file,
                   "--cci-list", cci, "--office", "ISSM", "--completion-date", "2000-01-01",
                   "-o", dest, "--apply")  # fmt: skip
    assert code == EXIT_OK
    assert template_file.read_bytes() == before
    got = cells(dest.read_bytes())
    assert got[f"{col('Office/Org')}{HEADER_ROW + 1}"][2] == "ISSM"
    assert got[f"{col('POA&M Scheduled Completion Date')}{HEADER_ROW + 1}"][2] == SERIAL_2000_01_01
    err = capsys.readouterr().err
    assert "eMASS requires this field" in err
    assert "Resources Required" in err and "Identification Source" in err
    assert "Office/Org" not in err


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["poam", "-o", "out.xlsx"], "export poam needs --template"),
        (["poam", "--template", "T", "--poam-status", "Risk Accepted", "--completion-date",
          "2026-12-31", "-o", "out.xlsx"], "does not apply to Risk Accepted"),
        (["poam", "--template", "T", "-o", "T"], "output would overwrite an input"),
        (["poam", "-o", "out.csv"], "unsupported output type"),
        (["csv", "--template", "T", "-o", "out.csv"], "only apply to the poam"),
        (["csv", "--office", "x", "-o", "out.csv"], "only apply to the poam"),
        (["csv", "--poam-status", "Risk Accepted", "-o", "out.csv"], "only apply to the poam"),
    ],
)  # fmt: skip
def test_cli_export_refuses_missing_and_mismatched_options(
    tmp_path: Path,
    template_file: Path,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    message: str,
) -> None:
    named = {"T": str(template_file), "out.xlsx": str(tmp_path / "out.xlsx"),
             "out.csv": str(tmp_path / "out.csv")}  # fmt: skip
    argv = [argv[0], str(MULTI_A), *(named.get(a, a) for a in argv[1:])]
    assert _cli("export", *argv)[0] == EXIT_UNREADABLE
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"not a workbook", "not an .xlsx workbook"),
        (make_template(below='<row r="4"><c r="C4" t="inlineStr"><is><t>x</t></is></c></row>'),
         "already has entries below its header"),
        (make_template([h for h in TEMPLATE_HEADERS if h != "Severity"]),
         "no column headed 'Severity'"),
    ],
)  # fmt: skip
def test_cli_export_refuses_templates_it_cannot_fill(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], data: bytes, message: str
) -> None:
    bad = tmp_path / "bad.xlsx"
    bad.write_bytes(data)
    code, _ = _cli("export", "poam", MULTI_A, "--template", bad, "-o", tmp_path / "p.xlsx")
    assert code == EXIT_UNREADABLE
    err = capsys.readouterr().err
    assert "cannot read POA&M template" in err and message in err


@pytest.mark.parametrize(
    "argv",
    [
        ["--completion-date", "31/12/2026"],
        ["--completion-date", "2026-02-30"],
        ["--completion-date", "1900-02-28"],  # before Excel's dates are reliable
        ["--poam-status", "Completed"],
    ],
)
def test_cli_poam_option_values_are_checked(tmp_path: Path, argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        _cli("export", "poam", MULTI_A, *argv, "-o", tmp_path / "p.xlsx")
    assert exc.value.code == 2


def test_cli_export_poam_with_disas_real_cci_list(
    tmp_path: Path, template_file: Path, disa_cci_list: CciList
) -> None:
    # Local only: skips when the CCI list has not been downloaded (as in CI).
    dest = tmp_path / "poam.xlsx"
    code, _ = _cli("export", "poam", MULTI_A, MULTI_B, "--template", template_file,
                   "--cci-list", DISA_CCI_ZIP, "-o", dest, "--apply")  # fmt: skip
    assert code == EXIT_OK
    got = cells(dest.read_bytes())
    items = range(HEADER_ROW + 1, HEADER_ROW + 9)
    controls = {r: got.get(f"{col('Controls / APs')}{r}", (None, None, ""))[2] for r in items}
    assert "AC-17(2)" in controls.values()
    # V-257780's only CCI has no Revision 5 reference: no control, and Comments says why.
    [gap] = [r for r, c in controls.items() if not c]
    assert got[f"{col('Security Checks')}{gap}"][2] == "SV-257780r925327"
    assert got[f"{col('Comments')}{gap}"][2] == "CCI-001233\n\nCCI-001233: no Rev 5 reference"


def test_real_emass_templates_are_filled_by_header(tmp_path: Path, emass_template: Path) -> None:
    # Local only: the current Navy, Army and Marine Corps templates (see conftest).
    openpyxl = pytest.importorskip("openpyxl")
    dest = tmp_path / "poam.xlsx"
    code, _ = _cli("export", "poam", MULTI_A, MULTI_B, "--template", emass_template,
                   "--office", "ISSM", "--completion-date", "2026-12-31", "-o", dest,
                   "--apply")  # fmt: skip
    assert code == EXIT_OK
    original = openpyxl.load_workbook(emass_template)["POA&M"]
    ws = openpyxl.load_workbook(dest)["POA&M"]
    header = {normalize_header(c.value): c.column_letter for c in ws[7] if isinstance(c.value, str)}

    def at(field: str, row: int = 8) -> object:
        return ws[f"{header[normalize_header(field)]}{row}"].value

    assert (at("POA&M Status"), at("Office/Org"), at("Milestone Status")) == (
        "Ongoing",
        "ISSM",
        "Open",
    )
    assert at("Milestone Scheduled Completion Date") == datetime(2026, 12, 31)
    assert at("Raw Severity") == at("Severity") == "High"  # CAT I first
    assert ws.max_row == 7 + 8
    banner = {"max_row": 7, "max_col": original.max_column, "values_only": True}
    assert list(ws.iter_rows(**banner)) == list(original.iter_rows(**banner))
    before, after = parts(emass_template.read_bytes()), parts(dest.read_bytes())
    assert list(after) == list(before)
    assert {n for n in after if after[n] != before[n]} <= {
        "xl/worksheets/sheet1.xml",
        "xl/styles.xml",
    }
