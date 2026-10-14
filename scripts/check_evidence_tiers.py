#!/usr/bin/env python3
"""Assert every page that defines an evidence tier quotes docs/evidence-tiers.md.

docs/evidence-tiers.md is the single definition of the evidence tiers: one table row per
tier, ``| Observed | `observed` | <definition> |``. README.md, CONTRIBUTING.md and
EVIDENCE_AUDIT.md restate those definitions for their own readers, and before this check
existed they carried three different wordings per tier.

A quoting page defines a tier on a line that names the tier in bold, either as the first
cell of a table row (``| **Observed** | <definition> | ...``) or as the label of a list item
(``- **OBSERVED**: <definition>``). Every such line must carry the canonical definition word
for word, and every quoting page must define every tier.

A list-item definition is read on a line that starts a bulleted list item as CommonMark
reads one: the marker (``-``, ``*`` or ``+``) is followed by a space or tab and is indented
less than four columns past the text of the innermost list item the line is inside, or past
the margin when it is inside none. A line that only looks like one is not a definition: a
marker followed by a no-break space, a line that starts with one, or a line indented four
or more columns, which is indented code or more of the paragraph before it. A page whose
only definition of a tier is written that way is reported as leaving the tier out.

A list-item definition must also end on its own line: the page must end after it, or the
next line must start a bulleted list item with text, its marker indented no further than
the definition's, or the next line must be blank (nothing but spaces and tabs) and the
first line after the blank lines that is not blank, if there is one, must be indented less
than the text of the definition's list item. That text starts after the marker and the
spaces and tabs that follow it, or one column after the marker when those cover five or
more columns, where CommonMark reads the label as indented code. Any other line there is
read as continuing the definition, as Markdown reads an indented line or a line of plain
text directly after a list item, and a line indented as far as the item's text after a
blank line as a further paragraph of the item, and the definition is reported even when
the joined text matches: keep each definition on one line and alone in its list item. This
rule is stricter than CommonMark, which also ends the list item at a bullet with no text,
a numbered item, a bullet indented further than the definition's marker and short of its
text, a thematic break (``* * *``) and other lines that start a block: each of those is
reported as continuing the definition.

Lines end at ``\\n``, ``\\r\\n`` or ``\\r`` only, as in CommonMark: a form feed, U+0085 or
U+2028 does not end a line. Indentation is counted in columns, a tab reaching the next stop
of four, and a no-break space or other white space character is not a space or tab here.
Code blocks are skipped as CommonMark delimits them. A fence opens on a run of three or
more backticks or tildes, with no backtick later on the line when the run is backticks,
closes on a line that holds a run of the same character at least as long and nothing after
it but spaces and tabs, and ends with the list item it is in. A line indented four or more
columns that does not continue a paragraph is indented code. A definition written in any
other form, such as inside a block quote or after another list marker on its line, is not
read, and neither is a page other than these three. List items and fences inside a block
quote are not followed, and neither are HTML blocks and tables, whose lines are read as
paragraph text.

A message that quotes a definition from a quoting page writes each character in it that
does not print as an escape, ``\\xa0`` for a no-break space and ``\\u2028`` for U+2028.

The tiers are the ``evidenceTier`` enum in the schema, so a tier added there fails this check
until the canonical page defines it and every quoting page quotes it.

Exit 0 when all of the above holds, 1 otherwise, printing ``file:line`` for each definition
that differs or continues past its line and naming each page that leaves a tier out.
"""

import bisect
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schema" / "threat-matrix-v1.2.schema.json"
CANONICAL = "docs/evidence-tiers.md"
QUOTING = ("README.md", "CONTRIBUTING.md", "EVIDENCE_AUDIT.md")

VALUE_RE = re.compile(r"`([a-z]+)`")
# A quoting page's definition is the rest of the cell, or of the line for a list item,
# stripped of white space after the match. Stripped by the pattern, with white space on both
# sides of a lazy definition, a long run of white space followed by more text took quadratic
# time.
TABLE_ROW_RE = re.compile(r"^\|\s*\*\*([A-Za-z]+)\*\*\s*\|([^|]*)")
# The label and definition of a list item, matched from where the item's text starts. White
# space that is not a space or tab may stand before the label: it is part of the text.
LABEL_RE = re.compile(r"\s*\*\*([A-Za-z]+)\*\*:(.*)")
# The patterns below are matched at a position in the line, after its indentation or after
# a list marker, never searched for.
# A list marker and the spaces and tabs after it. CommonMark separates the marker from the
# text with spaces or tabs only, so a marker followed by any other character, a no-break
# space included, is plain text.
MARKER_RE = re.compile(r"([-*+]|[0-9]{1,9}[.)])([ \t]+|$)")
# A code fence: the run of backticks or tildes, then the info string of an opening line.
FENCE_RE = re.compile(r"(`{3,}|~{3,})(.*)")
HEADING_RE = re.compile(r"#{1,6}(?:[ \t]|$)")
UNDERLINE_RE = re.compile(r"(?:=+|-+)[ \t]*$")
QUOTE_RE = re.compile(r"[> \t]*")
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


def width(prefix, column=0):
    """The column ``prefix`` ends at when it starts at ``column``: a tab reaches the next
    stop of four columns, and any other character takes one."""
    for c in prefix:
        column += 4 - column % 4 if c == "\t" else 1
    return column


def thematic_break(line, pos, ends):
    """Whether ``line`` from ``pos`` on is a thematic break: three or more of one of ``-``,
    ``*`` and ``_``, with nothing but spaces and tabs between and after them. ``ends`` keeps,
    for each of the three, where the last character that cannot stand in such a break ends,
    so that a line of many list markers is not read again at each of them."""
    c = line[pos]
    if c not in "-*_":
        return False
    if c not in ends:
        ends[c] = len(line.rstrip(c + " \t"))
    return pos >= ends[c] and line.count(c, pos) >= 3


def blocks(text):
    """Yield (line number, line, bullet) for every line outside a code block, and for a line
    that starts a bulleted list item and opens a fenced code block in it.

    ``bullet`` is (marker column, text column, text offset) when the line starts a bulleted
    list item as CommonMark reads one, and None otherwise. The text column is where the
    item's text starts: after the marker and the spaces and tabs after it, or one column
    after the marker when those reach five columns (CommonMark reads the text as indented
    code there) or nothing follows the marker.

    The lines are read as CommonMark reads list items, paragraphs and code. A line is inside
    each open list item whose text column it is indented as far as, and a list item, a fence
    or a line of indented code starts less than four columns, or four or more for the code,
    past the text column of the innermost item the line is inside (past the margin when it
    is inside none). An open paragraph takes a line that starts nothing else, however it is
    indented, and so keeps the list items around it open. A fenced code block ends with the
    list item it is in. Headings, thematic breaks and the first line of a block quote end a
    paragraph and the list items the line is outside of. List items and fences inside a block
    quote are not followed, and neither are HTML blocks and tables, whose lines are read as
    paragraph text.
    """
    items = []      # the text column of each open list item, outermost first
    empty = False   # the innermost open list item holds nothing yet
    para = False    # a paragraph is open, which the next line may continue
    apart = False   # that paragraph is inside a block quote, which the next line is not
    fence = None    # (character, length) of the open fenced code block, inside all of items
    for n, line in enumerate(split_lines(text), 1):
        pos = INDENT_RE.match(line).end()
        column = width(line[:pos])
        if pos == len(line):
            if fence is None:
                if empty:
                    items.pop()     # a blank line ends a list item that holds nothing
                empty = para = False
                yield n, line, None
            continue
        empty = False
        depth = bisect.bisect_right(items, column)
        if fence:
            if depth == len(items):
                m = FENCE_RE.match(line, pos)
                if (column - (items[-1] if items else 0) < 4 and m
                        and m.group(1)[0] == fence[0] and len(m.group(1)) >= fence[1]
                        and not m.group(2).strip(" \t")):
                    fence = None
                continue
            fence = None            # the list item that holds the fence ends here
        if column - (items[depth - 1] if depth else 0) >= 4:
            if para:
                yield n, line, None
            else:
                del items[depth:]   # indented code
            continue
        # Whether the line is inside everything the open paragraph is inside, and so its
        # next line unless it starts something else. A line outside one of the list items
        # around the paragraph, or its block quote, continues it too but is never the
        # underline of a heading, and any list item may start on it.
        direct = para and not apart and depth == len(items)
        bullet, first, quoted, opened, ends = None, True, False, False, {}
        while True:
            c = line[pos]
            if c == ">":
                del items[depth:]
                pos = QUOTE_RE.match(line, pos).end()
                para, direct, quoted, depth = False, False, True, len(items)
                if pos == len(line):
                    break
                continue
            m = FENCE_RE.match(line, pos)
            if m and not (c == "`" and "`" in m.group(2)):
                del items[depth:]
                para = False
                if not quoted:
                    fence, opened = (c, len(m.group(1))), True
                break
            if direct and UNDERLINE_RE.match(line, pos):
                para = False        # the underline of a setext heading
                break
            if HEADING_RE.match(line, pos) or thematic_break(line, pos, ends):
                del items[depth:]
                para = False
                break
            m = MARKER_RE.match(line, pos)
            # A list item that starts on the next line of a paragraph must hold text and,
            # when numbered, start at 1.
            if m and not (direct and (m.end() == len(line)
                                      or int(m.group(1)[:-1] or 1) != 1)):
                del items[depth:]
                after = column + len(m.group(1))
                start = width(m.group(2), after)
                bare = m.end() == len(line) or start - after > 4
                if not quoted:
                    items.append(after + 1 if bare else start)
                    empty = m.end() == len(line)
                    if first and c in "-*+":
                        bullet = (column, items[-1], m.end())
                para, direct, first, depth = False, False, False, len(items)
                if bare:
                    break
                pos, column = m.end(), start
                continue
            if not para:
                del items[depth:]
                para, apart = True, quoted
            break
        if bullet or not opened:
            yield n, line, bullet


def prose_lines(text):
    """Yield (line number, line) for every line outside a code block."""
    for n, line, _ in blocks(text):
        yield n, line


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


def continuation(lines, bullets, n):
    """The number of the line on which the list item that line ``n`` of ``lines`` starts
    continues, or None when it ends on its own line. ``bullets`` maps the number of each
    line that starts a bulleted list item to what ``blocks`` yields for it.

    The next line continues it when it holds a character other than a space or tab and does
    not start a bulleted list item with text whose marker is indented no further than the
    marker on line ``n``. After one or more blank lines, the first line that is not blank
    continues it when it is indented as far as the item's text.
    """
    indent, content, _ = bullets[n]
    i = n
    while i < len(lines) and not lines[i].strip(" \t"):
        i += 1
    if i == len(lines):
        return None
    if i > n:
        return i + 1 if width(INDENT_RE.match(lines[i]).group()) >= content else None
    after = bullets.get(n + 1)
    return None if after and after[2] < len(lines[n]) and after[0] <= indent else n + 1


def quoted_definitions(text, tiers):
    """Yield (line, tier, definition, continued) for every tier definition on a quoting page,
    where ``continued`` is the number of the line on which a list-item definition continues,
    or None."""
    lines = split_lines(text)
    rows = list(blocks(text))
    bullets = {n: bullet for n, _, bullet in rows if bullet}
    for n, line, bullet in rows:
        m = TABLE_ROW_RE.match(line)
        continued = None
        if not m and bullet:
            m = LABEL_RE.match(line, bullet[2])
            continued = continuation(lines, bullets, n) if m else None
        if m and m.group(1).lower() in tiers:
            yield n, m.group(1).lower(), m.group(2).strip(), continued


def shown(text):
    """``text`` with each character that does not print written as an escape, such as
    ``\\xa0`` for a no-break space and ``\\u2028`` for a line separator, so that a message
    shows the character to delete."""
    return "".join(c if c.isprintable() else c.encode("unicode_escape").decode("ascii")
                   for c in text)


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
                failures.append(f"{page}:{n}: {canonical[tier][1]} reads "
                                f"\"{shown(definition)}\"; quote {CANONICAL}: \"{want}\"")
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
