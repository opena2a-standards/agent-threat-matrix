#!/usr/bin/env python3
"""Fail when a technique or tactic page disagrees with matrix.json on the data it carries.

matrix.json is canonical. The per-technique pages under techniques/ are hand-written
prose, but these lines are data that also lives in matrix.json:

- the ``# T-NNNN: name`` title and the first line under ``## Description``
- ``**Tactic:**`` and ``**Attack Class:**``
- ``- **DVAA Validation:**`` (absent when matrix.json has no ``dvaaValidation``; the
  Procedure Examples section then reads "No documented procedures yet.")
- ``- **HMA Checks:**``, ``- **OASB Controls:**`` and ``- **Evidence Tier:**``
- the two References links, ``- Attack Class: [...]`` and ``- Tactic: [...]``

Each must appear once outside fenced code blocks and equal its rendering from the data.
Only two of them were checked until 2026-10-11: when matrix.json moved T-1006 and T-5002
to A2A-EXPOSE on 2026-08-25, their HMA Checks lines and four References class links kept
the old values while CI stayed green.

The pages under tactics/ carry nothing but data (name, kill chain stage, description and
a table of the tactic's techniques in matrix.json order), so each must equal its full
rendering from matrix.json. Their tables kept the same four superseded classes.

Run with ``--fix`` to rewrite those lines and tactic pages from the data. Every other line
of a technique page is left alone. A missing or repeated technique-page line has no single
place to write the data to, so ``--fix`` reports it and still exits 1.
"""

from __future__ import annotations  # "X | None" annotations also load on Python 3.9

import bisect
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NO_PROCEDURES = "No documented procedures yet."
DVAA_LABEL = "DVAA Validation"

# (label, pattern whose group ``line`` is the data line, rendering from a technique).
# A rendering of None means the page must not carry the line.
FIELD_PATTERNS = (
    ("Title", r"^(?P<line># .*)$", lambda t: f"# {t['id']}: {t['name']}"),
    ("Tactic", r"^(?P<line>\*\*Tactic:\*\*.*)$", lambda t: f"**Tactic:** {t['tactic']}"),
    ("Attack Class", r"^(?P<line>\*\*Attack Class:\*\*.*)$",
     lambda t: f"**Attack Class:** {t.get('attackClass') or ''}"),
    ("Description", r"^## Description\n\n(?P<line>.*)$", lambda t: t.get("description") or ""),
    (DVAA_LABEL, r"^(?P<line>- \*\*DVAA Validation:\*\*.*)$",
     lambda t: f"- **DVAA Validation:** {t['dvaaValidation']}" if t.get("dvaaValidation") else None),
    ("HMA Checks", r"^(?P<line>- \*\*HMA Checks:\*\*.*)$",
     lambda t: f"- **HMA Checks:** {', '.join(t.get('hmaChecks') or [])}"),
    ("OASB Controls", r"^(?P<line>- \*\*OASB Controls:\*\*.*)$",
     lambda t: f"- **OASB Controls:** {', '.join(t.get('oasbControls') or [])}"),
    ("Evidence Tier", r"^(?P<line>- \*\*Evidence Tier:\*\*.*)$",
     lambda t: f"- **Evidence Tier:** {t.get('evidenceTier') or ''}"),
    ("References attack class", r"^(?P<line>- Attack Class: .*)$",
     lambda t: f"- Attack Class: [{t.get('attackClass')}](../attack-classes/{t.get('attackClass')}.md)"),
    ("References tactic", r"^(?P<line>- Tactic: .*)$",
     lambda t: f"- Tactic: [{t['tactic']}](../tactics/{t['tactic']}.md)"),
)
FIELDS = tuple((label, re.compile(pattern, re.M), render) for label, pattern, render in FIELD_PATTERNS)
NO_PROCEDURES_RE = re.compile(rf"^(?P<line>{re.escape(NO_PROCEDURES)})$", re.M)
# Block structure, matched in a line from where the markers and indentation of the block
# quotes and list items that hold it end, after tabs are expanded to stops of four columns.
# A fence line: up to three spaces, a run of one fence character, then the rest of the line.
FENCE_RE = re.compile(r" {0,3}(?P<run>`{3,}|~{3,})(?P<rest>.*)")
LIST_MARKER_RE = re.compile(r"(?P<marker> {0,3}(?:[-+*]|(?P<number>[0-9]{1,9})[.)]))(?P<space> *)")
QUOTE_MARKER_RE = re.compile(r" {0,3}> ?")
THEMATIC_BREAK_RE = re.compile(r" {0,3}(?:(?:\*[ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})\r?")
SETEXT_UNDERLINE_RE = re.compile(r" {0,3}(?:=+|-+)[ \t]*\r?")
HEADING_RE = re.compile(r" {0,3}#{1,6}(?:[ \t\r]|$)")
COMMENT_START_RE = re.compile(r" {0,3}<!--")
SPACES_RE = re.compile(" *")
# Leaf blocks other than a fence, which is held as its opening run.
PARAGRAPH, INDENTED_CODE, COMMENT = "paragraph", "indented code", "comment"


class _Line:
    """One line with tabs expanded, and where its text ends (trailing spaces and a carriage
    return are not text)."""

    def __init__(self, line: str):
        self.text = line.expandtabs(4)
        self.end = len(self.text.rstrip(" \r"))
        # A thematic break runs to the end of the line, so it can only start inside the
        # longest tail made of one of its characters and spaces. Finding that tail once
        # keeps a line of many nested list markers from being rescanned at each marker.
        last = self.text[self.end - 1] if self.end else ""
        self.break_tail = self.end
        if last in ("*", "-", "_"):
            self.break_tail = len(self.text[:self.end].rstrip(last + " "))

    def text_start(self, pos: int) -> int:
        return SPACES_RE.match(self.text, pos).end()

    def thematic_break(self, pos: int) -> bool:
        start = self.text_start(pos)
        return start - pos <= 3 and start >= self.break_tail and start < self.end \
            and bool(THEMATIC_BREAK_RE.fullmatch(self.text, pos))

    def fence_opener(self, pos: int) -> re.Match | None:
        """The fence this line opens at ``pos``, or None. A backtick run followed by another
        backtick on the same line is an inline code span, not a fence."""
        m = FENCE_RE.fullmatch(self.text, pos)
        if m and not (m["run"][0] == "`" and "`" in m["rest"]):
            return m
        return None

    def list_item(self, pos: int, interrupting: bool) -> tuple[int, bool] | None:
        """For a list item that starts at ``pos``, its content column and whether its first
        line is blank; None when no list item starts there. An item that would interrupt a
        paragraph must have text and, when ordered, start at 1."""
        m = LIST_MARKER_RE.match(self.text, pos)
        if not m:
            return None
        blank = m.end() >= self.end
        if not (m["space"] or blank):
            return None
        if interrupting and (blank or (m["number"] is not None and int(m["number"]) != 1)):
            return None
        if blank or len(m["space"]) > 4:
            # An item that starts blank, or with indented code, has its content one column
            # after the marker.
            return m.end("marker") + 1, blank
        return m.end(), False

    def starts_block(self, pos: int) -> bool:
        """True when a block that ends a paragraph starts at ``pos``, so the line is not a
        lazy continuation of that paragraph."""
        return bool(self.thematic_break(pos) or QUOTE_MARKER_RE.match(self.text, pos)
                    or self.list_item(pos, interrupting=False) or self.fence_opener(pos)
                    or HEADING_RE.match(self.text, pos) or COMMENT_START_RE.match(self.text, pos))


def fenced_spans(text: str) -> list[tuple[int, int]]:
    """Return the (start, end) offsets of each fenced code block, fence lines included.

    A line in a code example, such as a ``# comment`` in a shell block, is not a data line
    of the page. The fence rules are CommonMark's: a backtick run followed by another
    backtick on the same line is an inline code span and opens nothing; a fence closes on a
    line of the same character, at least as long as the opening run, with nothing after
    it; a fence inside a list item or block quote ends with it, so a fence opened in a list
    item ends at the first non-blank line indented less than the item's content (only
    paragraph text continues lazily); a fence line inside an HTML comment (from a line that
    starts with ``<!--`` to the line that holds ``-->``) opens nothing; and an unclosed
    fence runs to the end of the page. Lines end at ``\\n`` only, as they do for the field
    patterns, so a form feed or U+2028 does not start a line.

    To place each fence, the block quotes and list items that hold it are followed by
    CommonMark's rules, including lazy continuation lines, a list item that interrupts a
    paragraph (it must have text, and an ordered one must start at 1) and a list item that
    starts with a blank line (a second blank line ends it). Of the HTML blocks only the
    comment is followed: a fence line inside any other, such as a ``<div>`` block that runs
    to the next blank line, still opens a fence. A comment ends at ``-->`` or with the list
    item or block quote that holds it, not at a blank line, as the CommonMark specification
    reads it; markdown-it ends a comment inside a list item at a blank line. Data lines
    inside an HTML comment are still read. Each line is read once, so the cost is linear in
    the length of the page.
    """
    spans = []
    # Open containers, outermost first: None for a block quote, and for a list item the
    # width from where the item's line starts inside its parent to the item's content.
    containers = []
    leaf = None  # PARAGRAPH, INDENTED_CODE, COMMENT, or the opening run of a fence
    fence_start = 0
    blank_item = False  # the innermost container is a list item whose only line is blank
    offset = 0
    for raw in text.split("\n"):
        line_start, offset = offset, offset + len(raw) + 1
        line = _Line(raw)
        text_at = line.text_start(0)

        # The open containers this line continues: a block quote by its marker, a list item
        # by indentation to its content or by a blank line. Indentation is counted from the
        # end of the enclosing container's marker on this line, as CommonMark counts it.
        pos = matched = 0
        for width in containers:
            if width is None:
                m = QUOTE_MARKER_RE.match(line.text, pos)
                if not m:
                    break
                pos = m.end()
                text_at = line.text_start(pos)
            elif text_at < line.end:
                if text_at - pos < width:
                    break
                pos += width
            matched += 1
        blank = text_at >= line.end
        was_blank_item, blank_item = blank_item, False

        if matched < len(containers):
            if leaf == PARAGRAPH and not blank and not line.starts_block(pos):
                continue  # a lazy continuation line keeps every container and the paragraph
            del containers[matched:]
            if leaf not in (None, PARAGRAPH, INDENTED_CODE, COMMENT):
                spans.append((fence_start, line_start))  # the fence ends with its container
            leaf = None
        elif was_blank_item and blank:
            containers.pop()  # a list item can begin with at most one blank line
            leaf = None

        if leaf == COMMENT:
            if line.text.find("-->", pos) >= 0:
                leaf = None
            continue
        if leaf not in (None, PARAGRAPH, INDENTED_CODE):
            m = FENCE_RE.fullmatch(line.text, pos)
            if m and m["run"][0] == leaf[0] and len(m["run"]) >= len(leaf) \
                    and not m["rest"].strip(" \t\r"):
                spans.append((fence_start, offset))
                leaf = None
            continue
        if blank:
            if leaf == PARAGRAPH:
                leaf = None
            continue
        if leaf == INDENTED_CODE:
            if text_at - pos >= 4:
                continue
            leaf = None

        # New containers: block quote markers and list markers, in the order they appear.
        # Each marker pattern allows at most three spaces before the marker, so a line
        # indented four columns past its containers opens none.
        interrupting = leaf == PARAGRAPH
        while text_at < line.end and not line.thematic_break(pos):
            if m := QUOTE_MARKER_RE.match(line.text, pos):
                containers.append(None)
                pos = m.end()
            elif item := line.list_item(pos, interrupting):
                column, blank_item = item
                containers.append(column - pos)
                pos = column
            else:
                break
            text_at = line.text_start(pos)
            leaf = None
            interrupting = False

        # The leaf block, if this line starts one.
        if text_at >= line.end:
            continue
        if text_at - pos >= 4:
            if leaf != PARAGRAPH:
                leaf = INDENTED_CODE
        elif line.thematic_break(pos) or HEADING_RE.match(line.text, pos) or (
                leaf == PARAGRAPH and SETEXT_UNDERLINE_RE.fullmatch(line.text, pos)):
            leaf = None
        elif opener := line.fence_opener(pos):
            leaf, fence_start = opener["run"], line_start
        elif COMMENT_START_RE.match(line.text, pos):
            leaf = None if line.text.find("-->", pos) >= 0 else COMMENT
        else:
            leaf = PARAGRAPH
    if leaf not in (None, PARAGRAPH, INDENTED_CODE, COMMENT):
        spans.append((fence_start, len(text)))
    return spans


def find_lines(regex: re.Pattern, text: str) -> list[re.Match]:
    """Return the matches of ``regex`` that start outside every fenced code block."""
    spans = fenced_spans(text)
    starts = [start for start, _ in spans]

    def fenced(position: int) -> bool:
        # The spans are in page order and do not overlap, so only the last one that starts
        # at or before the position can hold it.
        index = bisect.bisect_right(starts, position) - 1
        return index >= 0 and position < spans[index][1]

    return [m for m in regex.finditer(text) if not fenced(m.start())]


def check_technique_page(technique: dict, text: str) -> tuple[list[str], str]:
    """Return the page's disagreements with the data and the page with them rewritten."""
    tid = technique["id"]
    failures = []
    updated = text
    for label, regex, render in FIELDS:
        want = render(technique)
        found = find_lines(regex, updated)
        if len(found) > 1:
            failures.append(f"{tid}: page has {len(found)} '{label}' lines")
            continue
        if want is None:
            if found:
                failures.append(f"{tid}: page has a '{label}' line, matrix.json has none")
                updated = _remove_procedure_line(updated, found[0])
            continue
        if not found:
            failures.append(f"{tid}: page has no '{label}' line")
            placeholders = find_lines(NO_PROCEDURES_RE, updated) if label == DVAA_LABEL else []
            if placeholders:
                updated = _replace(updated, placeholders[0], want)
            continue
        have = found[0].group("line")
        if have != want:
            failures.append(f"{tid}: {label} line is '{have}', matrix.json says '{want}'")
            updated = _replace(updated, found[0], want)
    return failures, updated


def _replace(text: str, match: re.Match, line: str) -> str:
    start, end = match.span("line")
    return text[:start] + line + text[end:]


def _remove_procedure_line(text: str, match: re.Match) -> str:
    """Drop a data line; a section left with no content gets the no-procedures placeholder."""
    start, end = match.span("line")
    if text[:start].endswith("\n\n") and text[end:].startswith("\n\n"):
        return text[:start] + NO_PROCEDURES + text[end:]
    return text[:start] + text[end + 1:]


def render_tactic_page(tactic: dict, techniques: list[dict]) -> str:
    lines = [
        f"# {tactic['name']}",
        "",
        f"**Kill Chain Stage:** {tactic['order']}",
        "",
        "## Description",
        "",
        tactic["description"],
        "",
        "## Techniques",
        "",
        "| ID | Name | Evidence tier | Attack class |",
        "|----|------|---------------|--------------|",
    ]
    for t in techniques:
        if t["tactic"] == tactic["id"]:
            lines.append(f"| [{t['id']}](../techniques/{t['id']}.md) | {t['name']} "
                         f"| {t['evidenceTier']} | {t['attackClass']} |")
    return "\n".join(lines) + "\n"


def check_tactic_page(rel: str, have: str, want: str) -> list[str]:
    have_lines, want_lines = have.splitlines(), want.splitlines()
    failures = []
    for i in range(max(len(have_lines), len(want_lines))):
        h = have_lines[i] if i < len(have_lines) else None
        w = want_lines[i] if i < len(want_lines) else None
        if h == w:
            continue
        if w is None:
            failures.append(f"{rel}: line {i + 1} is '{h}', matrix.json has no such line")
        elif h is None:
            failures.append(f"{rel}: line {i + 1} is missing, matrix.json says '{w}'")
        else:
            failures.append(f"{rel}: line {i + 1} is '{h}', matrix.json says '{w}'")
    if not failures and have != want:
        failures.append(f"{rel}: differs from matrix.json in whitespace or line endings")
    return failures


def check_pages(matrix: dict, fix: bool) -> list[str]:
    """Return every page disagreement; with ``fix``, rewrite what the data can render."""
    failures = []
    for technique in matrix["techniques"]:
        page = ROOT / "techniques" / f"{technique['id']}.md"
        if not page.exists():
            failures.append(f"{technique['id']}: no page at techniques/{technique['id']}.md")
            continue
        text = page.read_text(encoding="utf-8")
        page_failures, updated = check_technique_page(technique, text)
        failures.extend(page_failures)
        if fix and updated != text:
            page.write_text(updated, encoding="utf-8")

    for tactic in matrix["tactics"]:
        rel = f"tactics/{tactic['id']}.md"
        page = ROOT / rel
        want = render_tactic_page(tactic, matrix["techniques"])
        if not page.exists():
            failures.append(f"{rel}: no page")
        else:
            failures.extend(check_tactic_page(rel, page.read_text(encoding="utf-8"), want))
        if fix and (not page.exists() or page.read_text(encoding="utf-8") != want):
            page.write_text(want, encoding="utf-8")
    return failures


def report(heading: str, failures: list[str]) -> None:
    print(f"{heading} {len(failures)} technique- or tactic-page line(s) that disagree with matrix.json:")
    for failure in failures:
        print(f"  - {failure}")


def main(argv: list[str]) -> int:
    fix = "--fix" in argv
    with open(ROOT / "matrix.json") as f:
        matrix = json.load(f)

    failures = check_pages(matrix, fix)
    if failures and not fix:
        report("FAIL: found", failures)
        return 1
    if failures:
        # A missing or repeated line has no single place to write the data to; it stays.
        remaining = check_pages(matrix, fix=False)
        fixed = [f for f in failures if f not in remaining]
        if fixed:
            report("FIXED: rewrote", fixed)
        if remaining:
            report("FAIL: could not rewrite", remaining)
            return 1

    print(f"OK: {len(matrix['techniques'])} technique pages and {len(matrix['tactics'])} tactic "
          "pages agree with matrix.json on every data line")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
