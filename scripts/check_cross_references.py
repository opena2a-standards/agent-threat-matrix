#!/usr/bin/env python3
"""Enforce the technique overlap partition in cross-references/ against matrix.json.

matrix.json is canonical for what the Agent Threat Matrix contains. The three files
under cross-references/ are an analyst reading of two external frameworks against it.
This checker keeps that reading honest and keeps every count on the published pages
derived rather than typed. It reads cross-references/ and matrix.json only; it makes no
statement about what an external framework contains.

Seven properties:

- C1 every ``T-####`` in cross-references/ exists in matrix.json.
- C2 every attack-class id in cross-references/ exists in matrix.json.attackClasses.
- C3 the OWASP-named set (owasp-llm-mapping.md mapping table) and the no-counterpart set
     (technique-overlap-index.md) are DISJOINT.
- C4 those two sets union to exactly the technique ids in matrix.json.
- C5 the generated block between the BEGIN/END markers in technique-overlap-index.md
     re-renders byte-identically to the committed text.
- C6 no ``~`` immediately precedes a digit anywhere in cross-references/.
- C7 none of ``coverage``, ``covered``, ``covers`` or ``gap analysis`` appears in a
     heading line or a table header row in cross-references/.

Run with ``--fix`` to rewrite only the generated block from matrix.json and the mapping
table. Every other line is left alone; there is no other rewrite, because C3 and C4 are
editorial placements, not text a script may invent. Exit 0 when all seven hold, 1
otherwise, printing one line per violation.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CROSSREF = ROOT / "cross-references"
INDEX_NAME = "technique-overlap-index.md"
OWASP_NAME = "owasp-llm-mapping.md"

BEGIN = "<!-- BEGIN GENERATED: overlap-counts -->"
END = "<!-- END GENERATED: overlap-counts -->"

BANNED_HEADING_WORDS = ("coverage", "covered", "covers", "gap analysis")

TECH_ID_RE = re.compile(r"T-\d{4}")
OWASP_ROW_RE = re.compile(r"^\|\s*\*\*(LLM\d\d)\*\*[^|]*\|([^|]*)\|")
NO_COUNTERPART_ROW_RE = re.compile(r"^\|\s*(T-\d{4})\s*\|")
CLASS_ID_RE = re.compile(r"\b([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)\b")
TILDE_DIGIT_RE = re.compile(r"~\d")
HEADING_RE = re.compile(r"^#{1,6}\s")
TABLE_SEP_RE = re.compile(r"^\s*\|[\s:|-]*-[\s:|-]*\|?\s*$")

# The section of CONTRIBUTING.md the C3/C4 failure text points a contributor at.
PLACEMENT_SECTION = 'CONTRIBUTING.md, "Placing a new technique"'


def load_matrix(root: Path):
    matrix = json.loads((root / "matrix.json").read_text())
    version = matrix.get("version")
    ids = {t["id"] for t in matrix["techniques"]}
    classes = {c["id"] for c in matrix["attackClasses"]}
    return version, ids, classes


def crossref_files(root: Path):
    return sorted((root / "cross-references").glob("*.md"))


def parse_owasp_named(text: str) -> set:
    """Distinct technique ids named in the OWASP mapping-table rows (set A)."""
    named = set()
    for line in text.splitlines():
        m = OWASP_ROW_RE.match(line)
        if m:
            named.update(TECH_ID_RE.findall(m.group(2)))
    return named


def parse_no_counterpart(text: str) -> set:
    """Technique ids whose row leads a table in the overlap index (set B)."""
    return {m.group(1) for line in text.splitlines() if (m := NO_COUNTERPART_ROW_RE.match(line))}


def class_ids_in(text: str) -> set:
    out = set()
    for token in CLASS_ID_RE.findall(text):
        if token.startswith("T-") and token[2:].isdigit():
            continue
        out.add(token)
    return out


def render_block(version, total: int, named: int) -> str:
    not_named = total - named
    return (
        f"`matrix.json` version {version} holds {total} techniques. The mapping table in\n"
        f"`owasp-llm-mapping.md` names {named} of them and does not name {not_named}. `mitre-atlas-mapping.md`\n"
        f"maps ATLAS tactics to ATM tactics and names no technique in its mapping table."
    )


def extract_block(text: str):
    """Return (before, body, after) around the generated block, or None if absent."""
    if BEGIN not in text or END not in text:
        return None
    before, rest = text.split(BEGIN, 1)
    body, after = rest.split(END, 1)
    # body is everything between the markers; the committed form is
    # "\n<content>\n". Compare the content without those framing newlines.
    return before, body, after


def is_table_header_rows(lines):
    """Yield indices of lines that are markdown table header rows."""
    for i in range(len(lines) - 1):
        if lines[i].lstrip().startswith("|") and TABLE_SEP_RE.match(lines[i + 1]):
            yield i


def run_checks(root: Path) -> list:
    failures = []
    version, ids, classes = load_matrix(root)
    files = crossref_files(root)

    index_path = root / "cross-references" / INDEX_NAME
    owasp_path = root / "cross-references" / OWASP_NAME
    index_text = index_path.read_text() if index_path.exists() else ""
    owasp_text = owasp_path.read_text() if owasp_path.exists() else ""

    # C1 -- every technique id referenced exists in matrix.json.
    for path in files:
        text = path.read_text()
        for tid in sorted(set(TECH_ID_RE.findall(text))):
            if tid not in ids:
                failures.append(f"C1 {path.name}: {tid} is not a technique id in matrix.json")

    # C2 -- every attack-class id referenced exists in matrix.json.attackClasses.
    for path in files:
        text = path.read_text()
        for cid in sorted(class_ids_in(text)):
            if cid not in classes:
                failures.append(f"C2 {path.name}: {cid} is not an attack-class id in matrix.json")

    named = parse_owasp_named(owasp_text)          # set A
    no_counterpart = parse_no_counterpart(index_text)  # set B

    # C3 -- the two lists are disjoint.
    for tid in sorted(named & no_counterpart):
        failures.append(
            f"C3 {tid} is in both published lists at once. It is named against an OWASP item in "
            f"cross-references/{OWASP_NAME} AND listed with no counterpart in "
            f"cross-references/{INDEX_NAME}. A technique sits in exactly one list. Resolve it "
            f"against the OWASP item's PUBLISHED TEXT. See {PLACEMENT_SECTION}. A title is not evidence."
        )

    # C4 -- the two lists union to exactly the matrix technique ids.
    for tid in sorted(ids - named - no_counterpart):
        failures.append(
            f"C4: {tid} is in matrix.json but appears in neither published list. Every technique "
            f"sits in exactly one of: (A) cross-references/{OWASP_NAME} -- add the id to one OWASP "
            f"item's row; (B) cross-references/{INDEX_NAME} -- add a row with the agent-layer "
            f"property it depends on. Choose (A) only if all three tests pass against that OWASP "
            f"item's PUBLISHED TEXT. See {PLACEMENT_SECTION}. A title is not evidence."
        )
    for tid in sorted((named | no_counterpart) - ids):
        failures.append(
            f"C4: {tid} appears in a published list but is not a technique id in matrix.json"
        )

    # C5 -- the generated block re-renders byte-identically.
    parts = extract_block(index_text)
    if parts is None:
        failures.append(f"C5 {INDEX_NAME}: the generated block markers are missing")
    else:
        _before, body, _after = parts
        want = render_block(version, len(ids), len(named))
        if body != f"\n{want}\n":
            failures.append(
                f"C5 {INDEX_NAME}: the generated block differs from the rendering of matrix.json "
                f"and the mapping table; run scripts/check_cross_references.py --fix"
            )

    # C6 -- no tilde immediately precedes a digit.
    for path in files:
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if TILDE_DIGIT_RE.search(line):
                failures.append(f"C6 {path.name}:{lineno}: a tilde immediately precedes a digit")

    # C7 -- no banned verdict word in a heading or a table header row.
    for path in files:
        lines = path.read_text().splitlines()
        flagged = set()
        for lineno, line in enumerate(lines, 1):
            if HEADING_RE.match(line):
                flagged.add(lineno)
        for i in is_table_header_rows(lines):
            flagged.add(i + 1)
        for lineno in sorted(flagged):
            low = lines[lineno - 1].lower()
            for word in BANNED_HEADING_WORDS:
                if word in low:
                    failures.append(
                        f"C7 {path.name}:{lineno}: heading or table header contains '{word}'"
                    )

    return failures


def fix_block(root: Path) -> bool:
    """Rewrite the generated block from the data. Returns True if the file changed."""
    version, ids, _classes = load_matrix(root)
    owasp_path = root / "cross-references" / OWASP_NAME
    index_path = root / "cross-references" / INDEX_NAME
    named = parse_owasp_named(owasp_path.read_text())
    text = index_path.read_text()
    parts = extract_block(text)
    if parts is None:
        return False
    before, _body, after = parts
    want = render_block(version, len(ids), len(named))
    rebuilt = f"{before}{BEGIN}\n{want}\n{END}{after}"
    if rebuilt != text:
        index_path.write_text(rebuilt)
        return True
    return False


def main(argv: list) -> int:
    fix = "--fix" in argv
    if fix:
        changed = fix_block(ROOT)
        print("FIXED: rewrote the generated block" if changed else "OK: generated block already current")

    failures = run_checks(ROOT)
    if failures:
        print(f"FAIL: {len(failures)} cross-reference check(s) failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    version, ids, _classes = load_matrix(ROOT)
    named = parse_owasp_named((ROOT / "cross-references" / OWASP_NAME).read_text())
    no_counterpart = parse_no_counterpart((ROOT / "cross-references" / INDEX_NAME).read_text())
    print(
        f"OK: {len(named)} techniques named in the OWASP mapping table, "
        f"{len(no_counterpart)} with no counterpart named, disjoint, "
        f"union equals the {len(ids)} techniques in matrix.json"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
