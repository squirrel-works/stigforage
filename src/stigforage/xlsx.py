"""Fill a worksheet of an `.xlsx` template with rows, on the standard library (ADR 0005).

The POA&M export writes into the user's own eMASS template rather than a workbook of its own:
eMASS revises its template and each service branch has its own, so the template the user
exports from eMASS is the layout most likely to import. Everything in the template is kept as it
is (banner, styles, validation lists, other sheets, document properties). Only the target
worksheet gains rows below its header, and the stylesheet gains a date style when a date column
has none.

The worksheet and stylesheet are edited as text, not re-serialised: ElementTree renames
namespace prefixes and drops declarations that only `mc:Ignorable` refers to, which Excel then
reports as a corrupt file. Each edit is checked by parsing the result again.

New text cells are inline strings, so the shared-string table is untouched and nothing is ever
evaluated as a formula; dates are Excel serial numbers with a date format. XML-illegal control
characters are removed, and a cell longer than Excel's 32,767-character limit is truncated with
a marker. ZIP entries carry a fixed timestamp, so the same template and rows give the same bytes.

Pure functions only: no I/O.
"""

from __future__ import annotations

import io
import posixpath
import re
import zipfile
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from stigforage.fsio import MAX_BYTES
from stigforage.model import ChecklistError
from stigforage.xmlsafe import local_name, parse_xml

__all__ = [
    "FIRST_DATE",
    "MAX_CELL",
    "Cell",
    "Template",
    "column_letter",
    "fill_template",
    "normalize_header",
    "read_template",
]

type Cell = str | date

MAX_CELL = 32767  # Excel's limit on characters in one cell
_MAX_COLUMNS = 16384  # A to XFD
# Excel's serial numbers are off by one before this date (it treats 1900 as a leap year).
FIRST_DATE = date(1900, 3, 1)
_EPOCH = date(1899, 12, 30)
_TRUNCATED = "\n[truncated by stigforage: over Excel's 32,767-character cell limit]"
_XML_FORBIDDEN = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")
_FIXED_TIME = (1980, 1, 1, 0, 0, 0)  # the earliest a ZIP entry can carry
_MAX_ENTRIES = 1000  # an eMASS template holds about 30 parts
_SHEET_MAIN = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
_DATE_FORMATS = frozenset({14, 15, 16, 17, 22})  # Excel's built-in date number formats
_SHORT_DATE = 14
_REF = re.compile(r"([A-Z]{1,3})(\d+)")


@dataclass(frozen=True)
class Template:
    """A worksheet located in an `.xlsx` template by `read_template`, with its header row."""

    source: str
    parts: dict[str, bytes]  # every ZIP entry, in the template's order
    sheet_part: str
    styles_part: str | None
    row_numbers: tuple[int, ...]  # of every row element in the worksheet, in order
    header_row: int  # 1-based, as Excel numbers rows
    headers: dict[str, list[int]]  # normalised header text -> zero-based columns
    column_styles: tuple[tuple[int, int, int], ...]  # (first, last, style), zero-based columns

    def column_style(self, column: int) -> int | None:
        """The style Excel gives an empty cell in `column`, if the template sets one."""
        for first, last, style in self.column_styles:
            if first <= column <= last:
                return style
        return None


def normalize_header(text: str) -> str:
    """Header text for matching: whitespace collapsed (line breaks included), case folded."""
    return " ".join(text.split()).casefold()


def column_letter(index: int) -> str:
    """Spreadsheet column name for a zero-based index: 0 -> A, 25 -> Z, 26 -> AA."""
    if not 0 <= index < _MAX_COLUMNS:
        raise ValueError(f"column index {index} is outside A to XFD")
    letters = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        letters = chr(ord("A") + rem) + letters
    return letters


def _column_index(letters: str) -> int:
    index = 0
    for ch in letters:
        index = index * 26 + ord(ch) - ord("A") + 1
    return index - 1


def _clean(text: str) -> str:
    text = _XML_FORBIDDEN.sub("", text)
    if len(text) > MAX_CELL:
        text = text[: MAX_CELL - len(_TRUNCATED)] + _TRUNCATED
    return text


def _serial(value: date) -> int:
    if value < FIRST_DATE:
        raise ValueError(f"{value.isoformat()} is before {FIRST_DATE.isoformat()}")
    return (value - _EPOCH).days


def _int(value: str | None, what: str, source: str) -> int:
    try:
        return int(value or "")
    except ValueError as exc:
        raise ChecklistError(f"{source}: {what} {value!r} is not a number") from exc


# --- reading --------------------------------------------------------------------------------


def _unzip(data: bytes, source: str) -> dict[str, bytes]:
    """Every entry of the package, read in memory with size caps."""
    parts: dict[str, bytes] = {}
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > _MAX_ENTRIES:
                raise ChecklistError(f"{source}: more than {_MAX_ENTRIES} entries")
            for info in infos:
                if info.filename in parts:
                    raise ChecklistError(f"{source}: duplicate entry {info.filename!r}")
                if info.flag_bits & 0x1:
                    raise ChecklistError(f"{source}: {info.filename!r} is encrypted")
                if info.file_size > MAX_BYTES:
                    raise ChecklistError(f"{source}: {info.filename!r} is over the size limit")
                with zf.open(info) as fh:
                    blob = fh.read(MAX_BYTES + 1)  # the size in a ZIP header can lie
                total += len(blob)
                if len(blob) > MAX_BYTES or total > MAX_BYTES:
                    raise ChecklistError(f"{source}: over the size limit when unpacked")
                parts[info.filename] = blob
    except (zipfile.BadZipFile, zlib.error, NotImplementedError, EOFError) as exc:
        raise ChecklistError(
            f"{source}: not an .xlsx workbook (a password-protected workbook cannot be read; "
            f"save an unprotected copy): {exc}"
        ) from exc
    return parts


def _parse(parts: Mapping[str, bytes], name: str, source: str) -> ET.Element:
    if name not in parts:
        raise ChecklistError(f"{source}: the package has no {name!r} part")
    return parse_xml(parts[name], source=f"{source}: {name}")


def _relationships(
    parts: Mapping[str, bytes], part: str, source: str
) -> dict[str, tuple[str, str]]:
    """Relationship id -> (type, target part) for `part` ("" for the package itself)."""
    directory, name = posixpath.split(part)
    rels_part = posixpath.join(directory, "_rels", f"{name}.rels")
    if rels_part not in parts:
        return {}
    found: dict[str, tuple[str, str]] = {}
    for rel in _parse(parts, rels_part, source):
        if local_name(rel.tag) != "Relationship" or rel.get("TargetMode") == "External":
            continue
        target = rel.get("Target", "")
        resolved = (
            target.lstrip("/")
            if target.startswith("/")
            else posixpath.normpath(posixpath.join(directory, target))
        )
        found[rel.get("Id", "")] = (rel.get("Type", "").rsplit("/", 1)[-1], resolved)
    return found


def _workbook_part(parts: Mapping[str, bytes], source: str) -> str:
    """The main document, which must be a plain workbook: not macro-enabled, not a template."""
    rels = _relationships(parts, "", source)
    targets = [target for kind, target in rels.values() if kind == "officeDocument"]
    if len(targets) != 1:
        raise ChecklistError(f"{source}: not an .xlsx workbook (no single main document)")
    overrides = {
        e.get("PartName", "").lstrip("/"): e.get("ContentType", "")
        for e in _parse(parts, "[Content_Types].xml", source)
        if local_name(e.tag) == "Override"
    }
    content_type = overrides.get(targets[0], "")
    if content_type == _SHEET_MAIN:
        return targets[0]
    if "macroenabled" in content_type.lower():
        problem = "a macro-enabled workbook"
    elif "template" in content_type:
        problem = "an Excel template file; open it in Excel and save it as an .xlsx workbook"
    else:
        problem = f"not an Excel workbook (content type {content_type or 'missing'!r})"
    raise ChecklistError(f"{source}: {problem}; only an .xlsx workbook can be filled")


def _rich_text(element: ET.Element) -> str:
    """The text of a shared-string item or inline string: plain, or rich-text runs.

    Phonetic runs (`rPh`) are a reading aid, not part of the text."""
    pieces = []
    for child in element:
        if local_name(child.tag) == "t":
            pieces.append(child.text or "")
        elif local_name(child.tag) == "r":
            pieces.extend(t.text or "" for t in child if local_name(t.tag) == "t")
    return "".join(pieces)


def _child(element: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in element if local_name(c.tag) == name), None)


def _cell_text(cell: ET.Element, strings: Sequence[str], source: str) -> str | None:
    """A cell's value as text, or None when it holds nothing (a formatted, empty cell)."""
    if cell.get("t") == "inlineStr":
        inline = _child(cell, "is")
        return _rich_text(inline) if inline is not None else ""
    value = _child(cell, "v")
    if value is None:
        return "" if _child(cell, "f") is not None else None
    if cell.get("t") == "s":
        index = _int(value.text, f"cell {cell.get('r')} string index", source)
        if not 0 <= index < len(strings):
            raise ChecklistError(f"{source}: cell {cell.get('r')} has a bad string index")
        return strings[index]
    return value.text or ""


def _rows(
    sheet: ET.Element, strings: Sequence[str], source: str
) -> list[tuple[int, dict[int, str]]]:
    """(row number, {column: text}) for every row element, in order, empty rows included."""
    data = _child(sheet, "sheetData")
    if data is None:
        raise ChecklistError(f"{source}: the worksheet has no sheetData")
    rows = []
    number = 0
    for row in (r for r in data if local_name(r.tag) == "row"):
        # Row and cell references are optional: without one, it follows the previous.
        number = _int(row.get("r"), "row number", source) if row.get("r") else number + 1
        cells: dict[int, str] = {}
        column = -1
        for cell in (c for c in row if local_name(c.tag) == "c"):
            found = _REF.fullmatch(cell.get("r") or "")
            column = _column_index(found.group(1)) if found else column + 1
            text = _cell_text(cell, strings, source)
            if text is not None:
                cells[column] = text
        rows.append((number, cells))
    return rows


def _column_styles(sheet: ET.Element, source: str) -> tuple[tuple[int, int, int], ...]:
    styles = []
    for cols in (e for e in sheet if local_name(e.tag) == "cols"):
        for col in (c for c in cols if local_name(c.tag) == "col"):
            if col.get("style") is not None:
                first = _int(col.get("min"), "column", source) - 1
                last = _int(col.get("max"), "column", source) - 1
                styles.append((first, last, _int(col.get("style"), "style", source)))
    return tuple(styles)


def read_template(data: bytes, *, sheet: str, marker: str, source: str = "template") -> Template:
    """Locate worksheet `sheet` of an `.xlsx` and its header row: the first row with a cell
    reading `marker`. Names and headers are compared normalised (`normalize_header`).

    The worksheet must hold nothing below its header, so filling it cannot mix new rows with
    old ones. Raises ChecklistError for anything that is not such a template.
    """
    parts = _unzip(data, source)
    workbook_part = _workbook_part(parts, source)
    rels = _relationships(parts, workbook_part, source)
    sheets = [
        e for e in _parse(parts, workbook_part, source).iter() if local_name(e.tag) == "sheet"
    ]
    wanted = [e for e in sheets if normalize_header(e.get("name", "")) == normalize_header(sheet)]
    if len(wanted) != 1:
        names = ", ".join(repr(e.get("name", "")) for e in sheets) or "none"
        problem = "more than one worksheet" if wanted else "no worksheet"
        raise ChecklistError(f"{source}: {problem} named {sheet!r} (it has {names})")
    rel_id = next((v for k, v in wanted[0].attrib.items() if k.endswith("}id")), "")
    kind, sheet_part = rels.get(rel_id, ("", ""))
    if kind != "worksheet":
        raise ChecklistError(f"{source}: {sheet!r} is not a worksheet")
    strings_part = next((t for k, t in rels.values() if k == "sharedStrings"), None)
    strings = (
        [_rich_text(si) for si in _parse(parts, strings_part, source) if local_name(si.tag) == "si"]
        if strings_part
        else []
    )
    root = _parse(parts, sheet_part, source)
    rows = _rows(root, strings, source)
    key = normalize_header(marker)
    header = next((r for r in rows if key in map(normalize_header, r[1].values())), None)
    if header is None:
        raise ChecklistError(f"{source}: sheet {sheet!r} has no header row with {marker!r}")
    header_row, header_cells = header
    below = next((n for n, cells in rows if n > header_row and cells), None)
    if below is not None:
        raise ChecklistError(
            f"{source}: sheet {sheet!r} already has entries below its header (row {below}); "
            "use a blank template"
        )
    headers: dict[str, list[int]] = {}
    for column, text in sorted(header_cells.items()):
        headers.setdefault(normalize_header(text), []).append(column)
    return Template(
        source=source,
        parts=parts,
        sheet_part=sheet_part,
        styles_part=next((t for k, t in rels.values() if k == "styles"), None),
        row_numbers=tuple(n for n, _ in rows),
        header_row=header_row,
        headers=headers,
        column_styles=_column_styles(root, source),
    )


# --- filling --------------------------------------------------------------------------------


def _decode(template: Template, part: str) -> str:
    try:
        return template.parts[part].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ChecklistError(f"{template.source}: {part} is not UTF-8") from exc


def _reparse(xml: str, tag: str, where: str) -> ET.Element:
    """Element `tag` of edited XML, parsed again to prove the edit left it well formed."""
    found = next(
        (
            e
            for e in parse_xml(xml.encode("utf-8"), source=where).iter()
            if local_name(e.tag) == tag
        ),
        None,
    )
    if found is None:
        raise ChecklistError(f"{where}: {tag} went missing while editing")
    return found


def _element_span(xml: str, tag: str, where: str) -> tuple[str, int, int, int]:
    """(namespace prefix, start of the opening tag, end of it, start of the closing tag)."""
    opening = re.search(rf"<([A-Za-z_][\w.\-]*:)?{tag}\b[^>]*>", xml)
    if opening is None or opening.group(0).endswith("/>"):
        raise ChecklistError(f"{where}: no {tag} element to fill")
    prefix = opening.group(1) or ""
    close = xml.find(f"</{prefix}{tag}>", opening.end())
    if close < 0:
        raise ChecklistError(f"{where}: {tag} is not closed")
    return prefix, opening.start(), opening.end(), close


def _segments(inner: str, prefix: str, tag: str, where: str) -> list[str]:
    """The `tag` elements making up `inner`, which must hold nothing else but whitespace."""
    p = re.escape(prefix)
    pattern = re.compile(rf"<{p}{tag}\b[^>]*?/>|<{p}{tag}\b.*?</{p}{tag}>", re.S)
    if pattern.sub("", inner).strip():
        raise ChecklistError(f"{where}: unexpected content among the {tag} elements")
    return pattern.findall(inner)


def _as_date_style(xf: str, prefix: str) -> str:
    """A copy of cell format `xf` showing Excel's short date (built-in format 14)."""
    found = re.match(rf"(<{re.escape(prefix)}xf\b[^>]*?)(/?>)", xf)
    if found is None:
        raise ChecklistError(f"unexpected cell format {xf[:60]!r}")
    opening = re.sub(r"""\s(?:numFmtId|applyNumberFormat)=("[^"]*"|'[^']*')""", "", found[1])
    return f'{opening} numFmtId="{_SHORT_DATE}" applyNumberFormat="1"{found[2]}{xf[found.end():]}'


def _date_styles(template: Template, bases: set[int]) -> tuple[dict[int, int], str | None]:
    """A date style for each base style, and the stylesheet text if formats had to be added.

    A column already formatted as a date keeps its style; any other gets a copy of its style
    with Excel's short date, which Excel shows in the reader's own date order.
    """
    if not bases:
        return {}, None
    where = f"{template.source}: styles"
    if template.styles_part is None:
        raise ChecklistError(f"{template.source}: no stylesheet, so dates cannot be formatted")
    xml = _decode(template, template.styles_part)
    prefix, start, open_end, close = _element_span(xml, "cellXfs", where)
    formats = _segments(xml[open_end:close], prefix, "xf", where)
    styles: dict[int, int] = {}
    added: list[str] = []
    for base in sorted(bases):
        if base >= len(formats):
            raise ChecklistError(f"{where}: cell format {base} is not defined")
        number_format = re.search(r"""\snumFmtId=["'](\d+)["']""", formats[base].split(">", 1)[0])
        if number_format and int(number_format[1]) in _DATE_FORMATS:
            styles[base] = base
        else:
            styles[base] = len(formats) + len(added)
            added.append(_as_date_style(formats[base], prefix))
    if not added:
        return styles, None
    count = len(formats) + len(added)
    head = re.sub(r"""\scount=["']\d+["']""", f' count="{count}"', xml[start:open_end])
    xml = xml[:start] + head + xml[open_end:close] + "".join(added) + xml[close:]
    if len(_reparse(xml, "cellXfs", where)) != count:
        raise ChecklistError(f"{where}: adding date formats failed")
    return styles, xml


def _row_xml(
    prefix: str,
    number: int,
    cells: Mapping[int, Cell],
    template: Template,
    date_styles: Mapping[int, int],
) -> str:
    p = prefix
    out = []
    for column in sorted(cells):
        value = cells[column]
        ref = f"{column_letter(column)}{number}"
        if isinstance(value, date):
            style = date_styles[template.column_style(column) or 0]
            out.append(f'<{p}c r="{ref}" s="{style}"><{p}v>{_serial(value)}</{p}v></{p}c>')
            continue
        text = _clean(value)
        if not text:
            continue
        style_index = template.column_style(column)
        s = f' s="{style_index}"' if style_index is not None else ""
        out.append(
            f'<{p}c r="{ref}"{s} t="inlineStr"><{p}is><{p}t xml:space="preserve">'
            f"{escape(text)}</{p}t></{p}is></{p}c>"
        )
    return f'<{p}row r="{number}">{"".join(out)}</{p}row>'


def _dimension(xml: str, prefix: str, last_row: int, last_column: int) -> str:
    """Widen the worksheet's declared used range to take in the new rows."""
    found = re.search(rf'<{re.escape(prefix)}dimension\b[^>]*?\sref="([^"]*)"', xml)
    span = re.fullmatch(r"([A-Z]+)(\d+)(?::([A-Z]+)(\d+))?", found[1]) if found else None
    if found is None or span is None:
        return xml
    end_column = max(_column_index(span[3] or span[1]), last_column)
    end_row = max(int(span[4] or span[2]), last_row)
    ref = f"{span[1]}{span[2]}:{column_letter(end_column)}{end_row}"
    return xml[: found.start(1)] + ref + xml[found.end(1) :]


def fill_template(template: Template, rows: Sequence[Mapping[int, Cell]]) -> bytes:
    """The template with `rows` written below its header, each a {zero-based column: value}.

    Empty text is left out. A text cell takes its column's style, a date its column's style
    shown as a date. Raises ChecklistError if the worksheet cannot be edited safely, and
    ValueError for a column outside A to XFD or a date before `FIRST_DATE`.
    """
    where = f"{template.source}: {template.sheet_part}"
    columns = {c for row in rows for c in row}
    for column in columns:
        column_letter(column)  # ValueError outside A to XFD, before any work
    for row in rows:
        for value in row.values():
            if isinstance(value, date):
                _serial(value)  # ValueError before FIRST_DATE
    bases = {
        template.column_style(c) or 0
        for row in rows
        for c, value in row.items()
        if isinstance(value, date)
    }
    date_styles, styles_xml = _date_styles(template, bases)

    xml = _decode(template, template.sheet_part)
    prefix, _, open_end, close = _element_span(xml, "sheetData", where)
    segments = _segments(xml[open_end:close], prefix, "row", where)
    if len(segments) != len(template.row_numbers):
        raise ChecklistError(f"{where}: the worksheet's rows could not be located")
    first_new = template.header_row + 1
    last_new = template.header_row + len(rows)
    kept = [s for s, n in zip(segments, template.row_numbers, strict=True) if n < first_new]
    # Rows in the new rows' place are empty (read_template checked) and give way to them;
    # formatting-only rows further down stay.
    later = [s for s, n in zip(segments, template.row_numbers, strict=True) if n > last_new]
    new = [
        _row_xml(prefix, first_new + i, row, template, date_styles) for i, row in enumerate(rows)
    ]
    xml = xml[:open_end] + "".join(kept + new + later) + xml[close:]
    if rows:
        xml = _dimension(xml, prefix, last_new, max(columns, default=0))
    written = _reparse(xml, "sheetData", where)
    if sum(1 for r in written if local_name(r.tag) == "row") != len(kept) + len(new) + len(later):
        raise ChecklistError(f"{where}: writing the rows failed")

    parts = dict(template.parts)
    parts[template.sheet_part] = xml.encode("utf-8")
    if styles_xml is not None and template.styles_part is not None:
        parts[template.styles_part] = styles_xml.encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, blob in parts.items():
            info = zipfile.ZipInfo(name, date_time=_FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, blob)
    return buffer.getvalue()
