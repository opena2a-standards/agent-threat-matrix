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
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")


def fenced_spans(text: str) -> list[tuple[int, int]]:
    """Return the (start, end) offsets of each fenced code block, fence lines included.

    A line in a code example, such as a ``# comment`` in a shell block, is not a data line
    of the page. An unclosed fence runs to the end of the page, as in CommonMark.
    """
    spans = []
    fence = None
    start = offset = 0
    for line in text.splitlines(keepends=True):
        m = FENCE_RE.match(line)
        if fence is None:
            if m:
                fence, start = m.group(1), offset
        elif m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) \
                and not line.strip().strip(fence[0]):
            spans.append((start, offset + len(line)))
            fence = None
        offset += len(line)
    if fence is not None:
        spans.append((start, offset))
    return spans


def find_lines(regex: re.Pattern, text: str) -> list[re.Match]:
    """Return the matches of ``regex`` that start outside every fenced code block."""
    spans = fenced_spans(text)
    return [m for m in regex.finditer(text) if not any(s <= m.start() < e for s, e in spans)]


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
