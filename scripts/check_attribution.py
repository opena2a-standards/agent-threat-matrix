#!/usr/bin/env python3
"""Enforce the attribution partition in ATTRIBUTION.md against matrix.json.

matrix.json is canonical for what the Agent Threat Matrix contains. ATTRIBUTION.md is
the published record of where each technique came from: every technique id sits in
exactly one of two lists -- externally contributed (with the contributor's credit as
they gave it and the issue or pull request the submission arrived in) or authored
in-house. This checker keeps that record a partition on the same terms as the
cross-reference placement checker, and keeps credit recorded rather than guessed: an
external entry with no real submission reference is refused, never accepted on trust.

Six properties:

- A1 ATTRIBUTION.md exists and carries both published-list headings.
- A2 every technique id in either list exists in matrix.json.
- A3 the externally-contributed list and the authored-in-house list are DISJOINT.
- A4 those two lists union to exactly the technique ids in matrix.json.
- A5 every externally-contributed row names the issue or pull request the submission
     arrived in: ``#123`` or a GitHub issue/pull URL. Empty cells and placeholders
     (TBD, N/A, ...) are refused.
- A6 every externally-contributed row carries a credit: the contributor's name or
     handle as they gave it, or the literal declined marker ``(credit declined)``.
     Empty cells and placeholders are refused -- a declined credit is recorded as
     declined, never dropped or moved in-house.

There is no ``--fix`` mode: both placements and every credit string are facts about
where content came from, not text a script may invent. Exit 0 when all six hold, 1
otherwise, printing one line per violation.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECORD_NAME = "ATTRIBUTION.md"

EXTERNAL_HEADING = "## Externally contributed"
INHOUSE_HEADING = "## Authored in-house"

TECH_ID_RE = re.compile(r"T-\d{4}")
# An externally-contributed row: | T-#### | credit | submission |
EXTERNAL_ROW_RE = re.compile(r"^\|\s*(T-\d{4})\s*\|([^|]*)\|([^|]*)\|")
# An authored-in-house row: | T-#### |
INHOUSE_ROW_RE = re.compile(r"^\|\s*(T-\d{4})\s*\|")

# A real submission reference: this repository's #123 form, or a full GitHub issue or
# pull request URL.
SUBMISSION_RE = re.compile(
    r"^(#\d+|https://github\.com/[\w.-]+/[\w.-]+/(issues|pull)/\d+)$"
)

# Cell values that record nothing. Compared after stripping markdown emphasis.
PLACEHOLDERS = {"", "-", "--", "—", "?", "n/a", "na", "none", "tbd", "todo", "unknown", "..."}

DECLINED_MARKER = "(credit declined)"

# The section of CONTRIBUTING.md the failure text points a contributor at.
CREDIT_SECTION = 'CONTRIBUTING.md, "Contributor credit"'


def load_matrix_ids(root: Path) -> set:
    matrix = json.loads((root / "matrix.json").read_text())
    return {t["id"] for t in matrix["techniques"]}


def _strip_cell(cell: str) -> str:
    return cell.strip().strip("*_`").strip()


def split_sections(text: str):
    """Return (external_section, inhouse_section, missing_headings)."""
    missing = [h for h in (EXTERNAL_HEADING, INHOUSE_HEADING) if h not in text]
    if missing:
        return "", "", missing
    after_external = text.split(EXTERNAL_HEADING, 1)[1]
    external, inhouse = after_external.split(INHOUSE_HEADING, 1)
    return external, inhouse, []


def parse_external(section: str) -> dict:
    """Technique id -> (credit cell, submission cell) for each external row."""
    rows = {}
    for line in section.splitlines():
        m = EXTERNAL_ROW_RE.match(line)
        if m:
            rows[m.group(1)] = (m.group(2).strip(), m.group(3).strip())
    return rows


def parse_inhouse(section: str) -> set:
    return {m.group(1) for line in section.splitlines() if (m := INHOUSE_ROW_RE.match(line))}


def run_checks(root: Path) -> list:
    failures = []
    ids = load_matrix_ids(root)
    record_path = root / RECORD_NAME

    # A1 -- the record exists and carries both published-list headings.
    if not record_path.exists():
        return [f"A1 {RECORD_NAME} does not exist. See {CREDIT_SECTION}."]
    text = record_path.read_text()
    external_section, inhouse_section, missing = split_sections(text)
    if missing:
        return [f"A1 {RECORD_NAME}: heading {h!r} is missing. See {CREDIT_SECTION}." for h in missing]

    external = parse_external(external_section)
    inhouse = parse_inhouse(inhouse_section)

    # A2 -- every id in a published list exists in matrix.json.
    for tid in sorted((set(external) | inhouse) - ids):
        failures.append(
            f"A2 {tid} appears in a published list in {RECORD_NAME} but is not a "
            f"technique id in matrix.json"
        )

    # A3 -- the two lists are disjoint.
    for tid in sorted(set(external) & inhouse):
        failures.append(
            f"A3 {tid} is in both published lists at once. It is listed as externally "
            f"contributed AND as authored in-house in {RECORD_NAME}. A technique sits in "
            f"exactly one list. See {CREDIT_SECTION}."
        )

    # A4 -- the two lists union to exactly the matrix technique ids.
    for tid in sorted(ids - set(external) - inhouse):
        failures.append(
            f"A4: {tid} is in matrix.json but appears in neither published list. Every "
            f"technique sits in exactly one of: externally contributed (with the "
            f"contributor's credit as they gave it and the submission it arrived in) or "
            f"authored in-house. See {CREDIT_SECTION}. Credit is recorded, never guessed."
        )

    # A5 -- every external row names the submission it arrived in.
    for tid in sorted(external):
        submission = _strip_cell(external[tid][1])
        if submission.lower() in PLACEHOLDERS or not SUBMISSION_RE.match(submission):
            failures.append(
                f"A5 {tid}: the externally-contributed row's submission cell "
                f"({external[tid][1]!r}) is not an issue or pull request reference "
                f"(#123 or a GitHub issue/pull URL). An external entry names the "
                f"submission it arrived in or it is not recorded. See {CREDIT_SECTION}."
            )

    # A6 -- every external row carries a credit as given, or the declined marker.
    for tid in sorted(external):
        credit = _strip_cell(external[tid][0])
        if credit.lower() in PLACEHOLDERS:
            failures.append(
                f"A6 {tid}: the externally-contributed row's credit cell "
                f"({external[tid][0]!r}) is empty or a placeholder. Record the "
                f"contributor's name or handle as they gave it, or "
                f"{DECLINED_MARKER!r} if they declined. See {CREDIT_SECTION}."
            )

    return failures


def main(argv: list) -> int:
    failures = run_checks(ROOT)
    if failures:
        print(f"FAIL: {len(failures)} attribution check(s) failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    ids = load_matrix_ids(ROOT)
    external_section, inhouse_section, _ = split_sections((ROOT / RECORD_NAME).read_text())
    external = parse_external(external_section)
    inhouse = parse_inhouse(inhouse_section)
    print(
        f"OK: {len(external)} techniques externally contributed, "
        f"{len(inhouse)} authored in-house, disjoint, "
        f"union equals the {len(ids)} techniques in matrix.json"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
