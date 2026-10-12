"""CHANGELOG.md puts the Unreleased section first and gives each section one subsection per kind.

The Unreleased section sat between v1.2.0 and v1.1 and held two `### Changed` subsections,
so a reader who stopped at the first `### Changed` under Unreleased missed the other one,
and a reader who started at the top read v1.2.0 as the newest changes. A subsection's kind
is its heading without a trailing parenthetical, so `### Fixed (2026-07-02)` is a Fixed
subsection.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
KIND_RE = re.compile(r"\s*\(.*\)\s*$")


def sections(text: str):
    """Return [(line number, heading, [(line number, kind), ...])] for each `## ` section."""
    out, fence = [], None
    for lineno, line in enumerate(text.splitlines(), 1):
        m = FENCE_RE.match(line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = None
            continue
        if m:
            fence = m.group(1)
        elif line.startswith("## "):
            out.append((lineno, line[3:].strip(), []))
        elif line.startswith("### ") and out:
            out[-1][2].append((lineno, KIND_RE.sub("", line[4:].strip())))
    return out


def is_unreleased(heading: str) -> bool:
    return heading.strip("[]").strip().lower() == "unreleased"


def problems(text: str):
    found = []
    secs = sections(text)
    unreleased = [(lineno, head) for lineno, head, _ in secs if is_unreleased(head)]
    for lineno, head in unreleased[1:]:
        found.append(f"{lineno}: a second '## {head}' section (first at line {unreleased[0][0]})")
    if unreleased and not is_unreleased(secs[0][1]):
        found.append(f"{unreleased[0][0]}: '## {unreleased[0][1]}' is not the first section "
                     f"('## {secs[0][1]}' at line {secs[0][0]} comes before it)")
    for _, head, subs in secs:
        seen = {}
        for lineno, kind in subs:
            if kind in seen:
                found.append(f"{lineno}: a second '### {kind}' in '## {head}' "
                             f"(first at line {seen[kind]})")
            else:
                seen[kind] = lineno
    return found


def test_changelog_layout():
    found = problems(CHANGELOG.read_text(encoding="utf-8"))
    assert not found, "CHANGELOG.md: " + "; ".join(found)


def test_problems_name_the_old_layout():
    text = ("# Changelog\n\n## v1.2.0 (2026-09-08)\n\n### Added\n\n- a\n\n"
            "## Unreleased\n\n### Changed\n\n- b\n\n### Fixed\n\n- c\n\n### Changed\n\n- d\n\n"
            "## v1.1\n\n### Fixed (2026-07-02)\n\n- e\n")
    assert problems(text) == [
        "9: '## Unreleased' is not the first section ('## v1.2.0 (2026-09-08)' at line 3 comes before it)",
        "19: a second '### Changed' in '## Unreleased' (first at line 11)",
    ]


def test_problems_accept_unreleased_first_with_one_subsection_per_kind():
    text = ("# Changelog\n\n## [Unreleased]\n\n### Added\n\n### Changed\n\n### Fixed\n\n"
            "## v1.1\n\n### Fixed (2026-07-02)\n\n```\n## v0.9\n### Fixed\n```\n")
    assert problems(text) == []


def test_problems_name_a_repeated_kind_and_a_second_unreleased():
    text = ("# Changelog\n\n## Unreleased\n\n### Fixed\n\n### Fixed (2026-07-02)\n\n"
            "## unreleased\n")
    assert problems(text) == [
        "9: a second '## unreleased' section (first at line 3)",
        "7: a second '### Fixed' in '## Unreleased' (first at line 5)",
    ]
