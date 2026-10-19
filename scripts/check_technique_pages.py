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

The ``## Mitigation`` section of a technique page is data too: it lists the OASB controls
in ``oasbControls``, and says "No documented mitigations yet." only for a technique that
maps none. Every page said that while every technique mapped to one or more controls. The
section runs from its heading to the next ``## `` heading outside fenced code blocks. A
technique page also carries no ``**Severity:**`` line: matrix.json has no severity field,
and every page printed the label with an empty value.

A page whose technique is ``adapted`` in matrix.json states its evidence gap in words, in
one ``- **Evidence Gap:**`` line, and no other page carries that line. The three adapted
pages showed only ``Evidence Tier: adapted`` while EVIDENCE_AUDIT.md said they stated the
gap.

Run with ``--fix`` to rewrite those lines, the Mitigation section and the tactic pages from
the data, to drop a Severity line or an Evidence Gap line the data does not back, and to add
a missing Evidence Gap line directly under the Evidence Tier line. Every other line of a
technique page is left alone. Any other missing technique-page line, a repeated line or
Mitigation section, and a missing Mitigation section have no single place to write the data
to, and a Mitigation section that holds a fenced code block may hold the rest of the page
behind an unclosed fence, so ``--fix`` reports each of them and still exits 1.

A read of matrix.json that raises an OSError, a ValueError or a RecursionError (see
``read_matrix``) is reported in one line on standard error,
``FAIL: matrix.json is missing or does not parse: <reason>``, and the run exits 1 without
checking or writing a page, with ``--fix`` as without it. So is a matrix.json that parses but
does not hold what this check needs from it (see ``SHAPE``), in the line
``FAIL: matrix.json parses but has the wrong shape: <reason>``: an object whose
``techniques`` array holds objects with a string ``id``, a ``name``, a ``tactic``, an
``attackClass`` and an ``evidenceTier``, a ``description`` that is absent, null or a string,
and ``hmaChecks`` and ``oasbControls`` that are each absent, null or an array of strings, and
whose ``tactics`` array holds objects with a string ``id``, a ``name``, an ``order`` and a
string ``description``.
"""

from __future__ import annotations  # "X | None" annotations also load on Python 3.9

import bisect
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NO_PROCEDURES = "No documented procedures yet."
NO_MITIGATION = "No documented mitigations yet."
OASB_URL = "https://oasb.ai"
DVAA_LABEL = "DVAA Validation"
ADAPTED_GAP = ("- **Evidence Gap:** Adapted from traditional environments. This technique has no "
               "agent-specific observation and no lab reproduction yet.")
GAP_RE = re.compile(r"^(?P<line>- \*\*Evidence Gap:\*\*.*)$", re.M)
SEVERITY_RE = re.compile(r"^(?P<line>\*\*Severity:\*\*.*)$", re.M)
MITIGATION_RE = re.compile(r"^(?P<line>## Mitigation)$", re.M)
SECTION_RE = re.compile(r"^(?P<line>## .*)$", re.M)

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
TIER_RE = next(regex for label, regex, _ in FIELDS if label == "Evidence Tier")
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

    severity = find_lines(SEVERITY_RE, updated)
    if severity:
        count = "a Severity line" if len(severity) == 1 else f"{len(severity)} Severity lines"
        failures.append(f"{tid}: page has {count}, and matrix.json has no severity field")
        for match in reversed(severity):
            start, end = match.span("line")
            updated = updated[:start] + updated[end + 1:]

    gap_failures, updated = check_evidence_gap(technique, updated)
    failures.extend(gap_failures)
    mitigation_failures, updated = check_mitigation(technique, updated)
    failures.extend(mitigation_failures)
    return failures, updated


def check_evidence_gap(technique: dict, text: str) -> tuple[list[str], str]:
    """Return the Evidence Gap line's disagreement with the tier and the page rewritten. An
    adapted page carries the line once; a missing one goes directly under the tier line."""
    tid = technique["id"]
    tier = technique.get("evidenceTier")
    found = find_lines(GAP_RE, text)
    if tier != "adapted":
        if not found:
            return [], text
        for match in reversed(found):
            start, end = match.span("line")
            text = text[:start] + text[end + 1:]
        return [f"{tid}: page has an Evidence Gap line, and matrix.json tier is '{tier}', not adapted"], text
    if len(found) > 1:
        return [f"{tid}: page has {len(found)} 'Evidence Gap' lines"], text
    if found:
        have = found[0].group("line")
        if have == ADAPTED_GAP:
            return [], text
        return ([f"{tid}: Evidence Gap line is '{have}', the adapted tier says '{ADAPTED_GAP}'"],
                _replace(text, found[0], ADAPTED_GAP))
    tiers = find_lines(TIER_RE, text)
    if len(tiers) == 1:
        end = tiers[0].end("line")
        text = text[:end] + "\n" + ADAPTED_GAP + text[end:]
    return [f"{tid}: adapted page does not state its evidence gap; matrix.json tier adapted "
            f"says '{ADAPTED_GAP}'"], text


def expected_mitigation(technique: dict) -> str:
    """The Mitigation section body: one line per OASB control matrix.json maps."""
    controls = technique.get("oasbControls") or []
    if not controls:
        return NO_MITIGATION
    lines = [f"Apply the [OASB-1]({OASB_URL}) controls that matrix.json maps to this technique:", ""]
    lines += [f"- OASB {control}" for control in controls]
    return "\n".join(lines)


def check_mitigation(technique: dict, text: str) -> tuple[list[str], str]:
    """Return the Mitigation section's disagreement with the data and the page with the
    section rewritten. A section that holds a fenced code block is not rewritten."""
    tid = technique["id"]
    headings = find_lines(MITIGATION_RE, text)
    if len(headings) > 1:
        return [f"{tid}: page has {len(headings)} '## Mitigation' sections"], text
    if not headings:
        return [f"{tid}: page has no '## Mitigation' section"], text
    start = headings[0].end("line")
    following = [m.start() for m in find_lines(SECTION_RE, text) if m.start() > start]
    end = following[0] if following else len(text)
    want = expected_mitigation(technique)
    if text[start:end].strip("\n") == want:
        return [], text
    controls = ", ".join(technique.get("oasbControls") or []) or "none"
    failures = [f"{tid}: Mitigation section does not list the OASB controls matrix.json maps ({controls})"]
    if any(start <= fence_start < end for fence_start, _ in fenced_spans(text)):
        return failures, text
    trailer = "\n\n" if end < len(text) else "\n"
    return failures, text[:start] + "\n\n" + want + trailer + text[end:]


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
    print(f"{heading} {len(failures)} technique- or tactic-page line(s) or section(s) that disagree "
          "with matrix.json:")
    for failure in failures:
        print(f"  - {failure}")


def read_matrix():
    """(matrix.json parsed, None), or (None, the reason it could not be read or parsed).

    The reasons are the ones scripts/validate_matrix.py gives for the same file: "no such
    file", "a directory, not a file", the system's reason for another OSError, its strerror,
    as in "Permission denied", the message of a ValueError, raised for a syntax error, an
    integer longer than Python's int string conversion limit and bytes that are not UTF-8,
    among others, and the message of the RecursionError, which is not a ValueError, that
    json.loads raises for arrays or objects nested deeper than it parses.
    """
    try:
        return json.loads((ROOT / "matrix.json").read_text(encoding="utf-8")), None
    except FileNotFoundError:
        return None, "no such file"
    except IsADirectoryError:
        return None, "a directory, not a file"
    except OSError as exc:
        return None, exc.strerror or str(exc)
    except (ValueError, RecursionError) as exc:
        return None, str(exc)


# What ``wrong_shape`` asks of a key it reads from an object: present, with any value;
# present, as a string; absent, null or a string; absent, null or an array of strings. Each
# but the first is worded as the reason line words it.
ANY, STRING = "any value", "a string"
STRING_OR_NULL, STRINGS_OR_NULL = "a string or null", "an array of strings or null"

# What this check needs from matrix.json, in the order ``wrong_shape`` checks it: each array
# and the keys of its objects, with what each must hold. An id is a string, as
# scripts/check_canonical_classes.py asks; another value only compared or written into a line
# may hold any value, and one joined into a page or spliced into its text must be a string.
# ``dvaaValidation``, written into a line only when it is set, is not listed.
SHAPE = (
    ("techniques", (("id", STRING), ("name", ANY), ("tactic", ANY), ("attackClass", ANY),
                    ("description", STRING_OR_NULL), ("hmaChecks", STRINGS_OR_NULL),
                    ("oasbControls", STRINGS_OR_NULL), ("evidenceTier", ANY))),
    ("tactics", (("id", STRING), ("name", ANY), ("order", ANY), ("description", STRING))),
)


def json_type(value: object) -> str:
    """The JSON type of a parsed value, with its article, as in "an array" or "null"."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "an array"
    return "an object"


def wrong_value(item: dict, field: str, kind: str, where: str) -> str | None:
    """None when the object ``item`` holds ``field`` as ``kind`` asks, or the reason it does
    not; ``where`` names the object, as in "techniques[0]"."""
    if field not in item:
        return None if kind in (STRING_OR_NULL, STRINGS_OR_NULL) else f"{where} has no {field}"
    value = item[field]
    if kind == ANY or (value is None and kind != STRING):
        return None
    if kind == STRINGS_OR_NULL:
        if not isinstance(value, list):
            return f"{where}.{field} is {json_type(value)}, not {kind}"
        for n, entry in enumerate(value):
            if not isinstance(entry, str):
                return f"{where}.{field}[{n}] is {json_type(entry)}, not a string"
        return None
    if not isinstance(value, str):
        return f"{where}.{field} is {json_type(value)}, not {kind}"
    return None


def wrong_shape(matrix: object) -> str | None:
    """None when the parsed matrix.json holds what ``SHAPE`` says this check needs from it,
    or the reason it does not, naming the first place that fails in the words
    scripts/check_canonical_classes.py uses, as in "techniques[0] has no id"."""
    if not isinstance(matrix, dict):
        return f"the top level is {json_type(matrix)}, not an object"
    for key, fields in SHAPE:
        if key not in matrix:
            return f"the top level has no {key} key"
        items = matrix[key]
        if not isinstance(items, list):
            return f"{key} is {json_type(items)}, not an array"
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                return f"{key}[{index}] is {json_type(item)}, not an object"
            for field, kind in fields:
                cause = wrong_value(item, field, kind, f"{key}[{index}]")
                if cause is not None:
                    return cause
    return None


def main(argv: list[str]) -> int:
    fix = "--fix" in argv
    matrix, cause = read_matrix()
    if cause is not None:
        print(f"FAIL: matrix.json is missing or does not parse: {cause}", file=sys.stderr)
        return 1
    cause = wrong_shape(matrix)
    if cause is not None:
        print(f"FAIL: matrix.json parses but has the wrong shape: {cause}", file=sys.stderr)
        return 1

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
          "pages agree with matrix.json on every data line and Mitigation section, every adapted "
          "page states its evidence gap, and no technique page carries a Severity line")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
