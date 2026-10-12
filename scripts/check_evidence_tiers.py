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
end on its own line: the page must end after it, or the next line must be blank (nothing but
spaces and tabs) or a bulleted list item with text (``-``, ``*`` or ``+``, white space, then
text) indented no further than it. Any other line there is read as continuing the
definition, as Markdown reads an indented line or a line of plain text directly after a list
item, and the definition is reported even when the joined text matches: keep each
definition on one line. A definition written in any other form, such as inside a block
quote, is not read, and neither is a page other than these three. Fenced code blocks are
skipped.

The tiers are the ``evidenceTier`` enum in the schema, so a tier added there fails this check
until the canonical page defines it and every quoting page quotes it.

Exit 0 when all of the above holds, 1 otherwise, printing ``file:line`` for each definition
that differs or continues onto the next line and naming each page that leaves a tier out.
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
BULLET_RE = re.compile(r"^(\s*)[-*+]\s+\S")


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


def continues(lines, n, item):
    """Whether list item ``item``, on line ``n`` of ``lines``, continues onto the next line:
    there is a next line, it holds a character other than a space or tab, and it is not a
    bulleted list item with text indented no further than ``item``."""
    if n >= len(lines) or not lines[n].strip(" \t"):
        return False
    bullet = BULLET_RE.match(lines[n])
    return not (bullet and len(bullet.group(1)) <= len(item) - len(item.lstrip()))


def quoted_definitions(text, tiers):
    """Yield (line, tier, definition, continued) for every tier definition on a quoting page,
    where ``continued`` says whether a list-item definition continues onto the next line."""
    lines = text.splitlines()
    for n, line in prose_lines(text):
        m = TABLE_ROW_RE.match(line)
        continued = False
        if not m:
            m = LIST_ITEM_RE.match(line)
            continued = bool(m) and continues(lines, n, line)
        if m and m.group(1).lower() in tiers:
            yield n, m.group(1).lower(), m.group(2), continued


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
                failures.append(f"{page}:{n}: {canonical[tier][1]} continues on line {n + 1}; "
                                f"keep the definition on one line, with a blank line or the "
                                f"next list item after it, and quote {CANONICAL}: \"{want}\"")
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
