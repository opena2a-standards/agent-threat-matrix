#!/usr/bin/env python3
"""Assert every page that defines an evidence tier quotes docs/evidence-tiers.md.

docs/evidence-tiers.md is the single definition of the evidence tiers: one table row per
tier, ``| Observed | `observed` | <definition> |``. README.md, CONTRIBUTING.md and
EVIDENCE_AUDIT.md restate those definitions for their own readers, and before this check
existed they carried three different wordings per tier.

A quoting page defines a tier on a line that names the tier in bold, either as the first
cell of a table row (``| **Observed** | <definition> | ...``) or as the label of a list item
(``- **OBSERVED**: <definition>``). Every such line must carry the canonical definition word
for word, and every quoting page must define every tier. A list-item definition must also
end on its own line: the page must end after it, or the next line must be a bulleted list
item with text (``-``, ``*`` or ``+``, a space or tab, then text) indented no further than
it, or the next line must be blank (nothing but spaces and tabs) and the first line after
the blank lines that is not blank, if there is one, must be indented less than the
definition's label. Any other line there is read as continuing the definition, as Markdown
reads an indented line or a line of plain text directly after a list item, and a line
indented as far as the item's text after a blank line as a further paragraph of the item,
and the definition is reported even when the joined text matches: keep each definition on
one line and alone in its list item. Lines end at ``\\n``, ``\\r\\n`` or ``\\r`` only, as in
CommonMark: a form feed, U+0085 or U+2028 does not end a line. Indentation is counted in
columns, a tab reaching the next stop of four, and a no-break space or other white space
character is not a space or tab here. A definition written in any other form, such as
inside a block quote, is not read, and neither is a page other than these three. Fenced
code blocks are skipped.

The tiers are the ``evidenceTier`` enum in the schema, so a tier added there fails this check
until the canonical page defines it and every quoting page quotes it.

Exit 0 when all of the above holds, 1 otherwise, printing ``file:line`` for each definition
that differs or continues past its line and naming each page that leaves a tier out.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schema" / "threat-matrix-v1.2.schema.json"
CANONICAL = "docs/evidence-tiers.md"
QUOTING = ("README.md", "CONTRIBUTING.md", "EVIDENCE_AUDIT.md")

FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
VALUE_RE = re.compile(r"`([a-z]+)`")
# A quoting page's definition is the rest of the cell, or of the line for a list item,
# stripped of white space after the match. Stripped by the pattern, with white space on both
# sides of a lazy definition, a long run of white space followed by more text took quadratic
# time.
TABLE_ROW_RE = re.compile(r"^\|\s*\*\*([A-Za-z]+)\*\*\s*\|([^|]*)")
LIST_ITEM_RE = re.compile(r"^\s*[-*+]\s+\*\*([A-Za-z]+)\*\*:(.*)")
# The white space before and after the marker of a line LIST_ITEM_RE matches, which places
# the item's text.
ITEM_START_RE = re.compile(r"(\s*)[-*+](\s*)")
# A bulleted list item with text. CommonMark separates the marker from the text with spaces
# or tabs only, so a marker followed by any other white space character is plain text.
BULLET_RE = re.compile(r"^([ \t]*)[-*+][ \t]+\S")
INDENT_RE = re.compile(r"[ \t]*")
LINE_END_RE = re.compile(r"\r\n|\r|\n")


def tiers_from_schema():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    return schema["$defs"]["technique"]["properties"]["evidenceTier"]["enum"]


def split_lines(text):
    """Split at CommonMark's line endings only. ``str.splitlines`` also breaks at a form feed,
    U+0085, U+2028 and other characters that CommonMark keeps inside a line."""
    lines = LINE_END_RE.split(text)
    return lines[:-1] if lines[-1] == "" else lines


def width(prefix):
    """The column ``prefix`` ends at: a tab reaches the next stop of four columns, and any
    other character takes one."""
    column = 0
    for c in prefix:
        column += 4 - column % 4 if c == "\t" else 1
    return column


def prose_lines(text):
    """Yield (line number, line) for every line outside a fenced code block."""
    fence = None
    for n, line in enumerate(split_lines(text), 1):
        m = FENCE_RE.match(line)
        if fence is None:
            if m:
                fence = m.group(1)
                continue
            yield n, line
        elif m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
            fence = None


def canonical_row(line):
    """(name, value, definition) for a row ``| Name | `value` | definition |``, else None.

    The line is split on "|" and each cell stripped of white space. One pattern for the whole
    row took cubic time on a line that starts with "|" and a long run of white space and does
    not complete the row, as the white space around a cell and the cell itself divided the
    run between them in every way. The definition runs from the third "|" to the last one,
    after which only white space may follow; the name holds no backtick.
    """
    cells = line.split("|")
    if cells[0] or len(cells) < 5 or cells[-1].strip() or not cells[1] or "`" in cells[1]:
        return None
    value = VALUE_RE.fullmatch(cells[2].strip())
    if not value:
        return None
    return cells[1].strip(), value.group(1), "|".join(cells[3:-1]).strip()


def canonical_definitions(text, tiers, failures):
    """Map each tier to (line, name, definition) from the canonical page's tier table."""
    found = {}
    for n, line in prose_lines(text):
        row = canonical_row(line)
        if not row or row[1] not in tiers:
            continue
        name, value, definition = row
        if value in found:
            failures.append(f"{CANONICAL}:{n}: defines `{value}` a second time "
                            f"(first at line {found[value][0]})")
            continue
        if name != value.capitalize():
            failures.append(f"{CANONICAL}:{n}: the tier named \"{name}\" carries the value "
                            f"`{value}`; name it \"{value.capitalize()}\"")
        if not definition:
            failures.append(f"{CANONICAL}:{n}: `{value}` has an empty definition")
        found[value] = (n, value.capitalize(), definition)
    for value in tiers:
        if value not in found:
            failures.append(f"{CANONICAL} does not define the `{value}` tier, which the "
                            f"schema's evidenceTier enum lists")
    return found


def continuation(lines, n, item):
    """The number of the line on which list item ``item``, on line ``n`` of ``lines``,
    continues, or None when it ends on its own line.

    The next line continues it when it holds a character other than a space or tab and is
    not a bulleted list item with text indented no further than ``item``. After one or more
    blank lines, the first line that is not blank continues it when it is indented as far as
    the item's text, which starts after the marker and the spaces and tabs after it, or one
    column after the marker when those reach five columns, as CommonMark reads indented code
    there.
    """
    start = ITEM_START_RE.match(item)
    indent = width(start.group(1))
    content = width(start.group(1) + "-" + start.group(2))
    if content - indent - 1 > 4:
        content = indent + 2
    i = n
    while i < len(lines) and not lines[i].strip(" \t"):
        i += 1
    if i == len(lines):
        return None
    if i > n:
        return i + 1 if width(INDENT_RE.match(lines[i]).group()) >= content else None
    bullet = BULLET_RE.match(lines[n])
    return None if bullet and width(bullet.group(1)) <= indent else n + 1


def quoted_definitions(text, tiers):
    """Yield (line, tier, definition, continued) for every tier definition on a quoting page,
    where ``continued`` is the number of the line on which a list-item definition continues,
    or None."""
    lines = split_lines(text)
    for n, line in prose_lines(text):
        m = TABLE_ROW_RE.match(line)
        continued = None
        if not m:
            m = LIST_ITEM_RE.match(line)
            continued = continuation(lines, n, line) if m else None
        if m and m.group(1).lower() in tiers:
            yield n, m.group(1).lower(), m.group(2).strip(), continued


def check(root=ROOT):
    failures = []
    tiers = tiers_from_schema()
    canonical = canonical_definitions((root / CANONICAL).read_text(encoding="utf-8"),
                                      tiers, failures)
    for page in QUOTING:
        seen = set()
        for n, tier, definition, continued in quoted_definitions(
                (root / page).read_text(encoding="utf-8"), tiers):
            seen.add(tier)
            if tier not in canonical:
                continue
            want = canonical[tier][2]
            if definition != want:
                failures.append(f"{page}:{n}: {canonical[tier][1]} reads \"{definition}\"; "
                                f"quote {CANONICAL}: \"{want}\"")
            if continued:
                failures.append(f"{page}:{n}: {canonical[tier][1]} continues on line "
                                f"{continued}; keep the definition on one line and alone in "
                                f"its list item, with the next list item or a blank line "
                                f"after it, and quote {CANONICAL}: \"{want}\"")
        for tier in tiers:
            if tier not in seen and tier in canonical:
                failures.append(f"{page} does not define {canonical[tier][1]}; quote "
                                f"{CANONICAL}: \"{canonical[tier][2]}\"")
    return tiers, failures


def main():
    tiers, failures = check()
    if failures:
        print(f"Evidence tier definitions differ from {CANONICAL}:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"Evidence tier definitions match {CANONICAL}: {len(tiers)} tiers quoted on "
          f"{', '.join(QUOTING)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
