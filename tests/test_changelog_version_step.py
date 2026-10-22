"""Unreleased CHANGELOG entries for normative changes name their version step.

GOVERNANCE.md says every normative change carries an entry under "Unreleased" in
CHANGELOG.md that names the technique ids it touches and the version step of "The version
rule". The entry that populated `attackMapping` and `atlasMapping` in `matrix.json` and the
entry that changed the data source schema named no version step. An entry that opens with
`matrix.json` or a path under `schema/` in backticks is read as a normative change; the data
source entry opens with its subject in words and is named by its opening phrase. A version
step is written "Version step: MAJOR, <reason>" or "Version step: MINOR, <reason>".
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
SUBJECT_RE = re.compile(r"^- `(?:matrix\.json|schema/[^`]*)`")
NAMED_ENTRIES = ("- The data source vocabulary admits only telemetry",)
STEP_RE = re.compile(r"Version step: (?:MAJOR|MINOR), \S")
STEP_WORDS_RE = re.compile(r"version step", re.IGNORECASE)


def unreleased_entries(text: str):
    """Return [(line number, entry text)] for the list items of the Unreleased section."""
    out, inside = [], False
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.startswith("## "):
            inside = line[3:].strip().strip("[]").strip().lower() == "unreleased"
            continue
        if not inside:
            continue
        if line.startswith("- "):
            out.append([lineno, line])
        elif line.strip() and not line.startswith("#") and out:
            out[-1][1] += " " + line.strip()
    return [(lineno, entry) for lineno, entry in out]


def is_normative(entry: str) -> bool:
    return bool(SUBJECT_RE.match(entry)) or entry.startswith(NAMED_ENTRIES)


def problems(text: str):
    found = []
    for lineno, entry in unreleased_entries(text):
        if STEP_WORDS_RE.search(entry) and not STEP_RE.search(entry):
            found.append(f"{lineno}: names a version step that is not "
                         f"'Version step: MAJOR, <reason>' or 'Version step: MINOR, <reason>'")
        elif is_normative(entry) and not STEP_RE.search(entry):
            found.append(f"{lineno}: a normative change that names no version step")
    return found


def test_unreleased_normative_entries_name_a_version_step():
    found = problems(CHANGELOG.read_text(encoding="utf-8"))
    assert not found, "CHANGELOG.md: " + "; ".join(found)


def test_named_entries_are_in_the_unreleased_section():
    entries = [entry for _, entry in unreleased_entries(CHANGELOG.read_text(encoding="utf-8"))]
    missing = [name for name in NAMED_ENTRIES if not any(e.startswith(name) for e in entries)]
    assert not missing, f"CHANGELOG.md: no Unreleased entry opens with {missing}"


def test_problems_name_entries_without_a_step():
    text = ("# Changelog\n\n## Unreleased\n\n### Added\n\n"
            "- `matrix.json`: technique-level `attackMapping` is populated.\n\n"
            "- `schema/x.json`: a field is added.\n  Version step: MINOR, a new field.\n\n"
            "### Changed\n\n"
            "- The data source vocabulary admits only telemetry that a tool reads.\n"
            "- `scripts/x.py` reads `matrix.json`.\n\n"
            "## v1.2 (2026-09-08)\n\n- `matrix.json`: an old entry.\n")
    assert problems(text) == [
        "7: a normative change that names no version step",
        "14: a normative change that names no version step",
    ]


def test_problems_accept_a_step_with_a_reason_and_refuse_one_without():
    text = ("## Unreleased\n\n"
            "- `matrix.json`: a field is added. Version step: MINOR, a new technique field.\n"
            "- `matrix.json`: a field is removed. Version step: MAJOR\n"
            "- `matrix.json`: values change. version step: minor, a change to normative content.\n")
    assert problems(text) == [
        "4: names a version step that is not "
        "'Version step: MAJOR, <reason>' or 'Version step: MINOR, <reason>'",
        "5: names a version step that is not "
        "'Version step: MAJOR, <reason>' or 'Version step: MINOR, <reason>'",
    ]
