#!/usr/bin/env python3
"""Assert every page that defines an evidence tier quotes docs/evidence-tiers.md.

docs/evidence-tiers.md is the single definition of the evidence tiers: one table row per
tier, ``| Observed | `observed` | <definition> |``. README.md, CONTRIBUTING.md and
EVIDENCE_AUDIT.md restate those definitions for their own readers, and before this check
existed they carried three different wordings per tier.

A quoting page defines a tier on a line that names the tier in bold, either as the first
cell of a table row (``| **Observed** | <definition> | ...``) or as the label of a list item
(``- **OBSERVED**: <definition>``). Every such line must carry the canonical definition word
for word, and every quoting page must define every tier. A definition wrapped over two lines
does not match: keep each definition on one line. Fenced code blocks are skipped.

The tiers are the ``evidenceTier`` enum in the schema, so a tier added there fails this check
until the canonical page defines it and every quoting page quotes it.

Exit 0 when every quoted definition matches, 1 otherwise, printing ``file:line`` for each
difference.
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
CANONICAL_ROW_RE = re.compile(r"^\|\s*([^|`]+?)\s*\|\s*`([a-z]+)`\s*\|\s*(.*?)\s*\|\s*$")
TABLE_ROW_RE = re.compile(r"^\|\s*\*\*([A-Za-z]+)\*\*\s*\|\s*(.*?)\s*(?:\||$)")
LIST_ITEM_RE = re.compile(r"^\s*[-*+]\s+\*\*([A-Za-z]+)\*\*:\s*(.*?)\s*$")


def tiers_from_schema():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    return schema["$defs"]["technique"]["properties"]["evidenceTier"]["enum"]


def prose_lines(text):
    """Yield (line number, line) for every line outside a fenced code block."""
    fence = None
    for n, line in enumerate(text.splitlines(), 1):
        m = FENCE_RE.match(line)
        if fence is None:
            if m:
                fence = m.group(1)
                continue
            yield n, line
        elif m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
            fence = None


def canonical_definitions(text, tiers, failures):
    """Map each tier to (line, name, definition) from the canonical page's tier table."""
    found = {}
    for n, line in prose_lines(text):
        m = CANONICAL_ROW_RE.match(line)
        if not m or m.group(2) not in tiers:
            continue
        name, value, definition = m.groups()
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


def quoted_definitions(text, tiers):
    """Yield (line, tier, definition) for every tier definition on a quoting page."""
    for n, line in prose_lines(text):
        m = TABLE_ROW_RE.match(line) or LIST_ITEM_RE.match(line)
        if m and m.group(1).lower() in tiers:
            yield n, m.group(1).lower(), m.group(2)


def check(root=ROOT):
    failures = []
    tiers = tiers_from_schema()
    canonical = canonical_definitions((root / CANONICAL).read_text(encoding="utf-8"),
                                      tiers, failures)
    for page in QUOTING:
        seen = set()
        for n, tier, definition in quoted_definitions(
                (root / page).read_text(encoding="utf-8"), tiers):
            seen.add(tier)
            if tier not in canonical:
                continue
            want = canonical[tier][2]
            if definition != want:
                failures.append(f"{page}:{n}: {canonical[tier][1]} reads \"{definition}\"; "
                                f"quote {CANONICAL}: \"{want}\"")
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
