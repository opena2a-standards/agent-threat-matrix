#!/usr/bin/env python3
"""Assert every counted claim in README.md matches matrix.json.

The README states counts (tactics, techniques, attack classes, evidence tiers)
and coverage claims (detection, defensive control, lab scenario). Those are
measurements, not prose, so they are checked here and in CI rather than
maintained by hand.

The attack-class tables are a rendering of matrix.json.attackClasses, held
between the BEGIN/END GENERATED markers. Typed by hand, they reworded 34 of the
40 class descriptions and four of them described a different attack. The block
must re-render byte-identically; run with ``--fix`` to rewrite only that block.

Exit 0 when every claim matches the data, 1 otherwise.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MATRIX = ROOT / "matrix.json"
README = ROOT / "README.md"

CLASS_BEGIN = "<!-- BEGIN GENERATED: attack-class-tables -->"
CLASS_END = "<!-- END GENERATED: attack-class-tables -->"

# Section labels for matrix.json attackClasses[].category. A category missing here
# is titled from its slug, so a new category still renders.
CATEGORY_LABELS = {
    "governance": "Governance",
    "supply-chain": "Supply Chain",
    "infrastructure": "Infrastructure",
    "nemoclaw": "NemoClaw-Specific",
    "identity": "Identity",
    "sandbox": "Sandbox",
}


def table_cell(text):
    """A matrix.json string as one Markdown table cell. A spaced em dash becomes a
    colon, as on the attack-classes/ pages, and a pipe is escaped."""
    return text.replace(" — ", ": ").replace("|", "\\|")


def render_class_tables(matrix):
    """The attack-class tables: one per category, in order of first appearance in
    matrix.json, classes sorted by id. Members are the techniques the class declares
    plus those whose primary attackClass is the class, as on the class pages."""
    primary = {}
    for t in matrix["techniques"]:
        primary.setdefault(t.get("attackClass"), set()).add(t["id"])

    by_category = {}
    for cls in matrix.get("attackClasses", []):
        by_category.setdefault(cls["category"], []).append(cls)

    sections = []
    for category, classes in by_category.items():
        label = CATEGORY_LABELS.get(category, category.replace("-", " ").title())
        noun = "class" if len(classes) == 1 else "classes"
        lines = [
            f"### {label} ({len(classes)} {noun})",
            "| Class | Description | Techniques |",
            "|-------|-------------|------------|",
        ]
        for cls in sorted(classes, key=lambda c: c["id"]):
            members = sorted(set(cls.get("techniques") or []) | primary.get(cls["id"], set()))
            lines.append(
                f"| [{cls['id']}](attack-classes/{cls['id']}.md) "
                f"| {table_cell(cls['description'])} | {', '.join(members)} |"
            )
        sections.append("\n".join(lines))
    return f"{CLASS_BEGIN}\n\n" + "\n\n".join(sections) + f"\n\n{CLASS_END}"


def class_block_span(readme):
    """(start, end) offsets of the generated block including its markers, or None
    unless each marker occurs exactly once, BEGIN first."""
    if readme.count(CLASS_BEGIN) != 1 or readme.count(CLASS_END) != 1:
        return None
    start = readme.index(CLASS_BEGIN)
    end = readme.index(CLASS_END)
    if end < start:
        return None
    return start, end + len(CLASS_END)


def check_class_tables(matrix, readme):
    """Failure lines for the generated attack-class block; empty when it is current."""
    span = class_block_span(readme)
    if span is None:
        return [
            f"README.md: the attack-class tables need exactly one '{CLASS_BEGIN}' "
            f"followed by exactly one '{CLASS_END}'"
        ]
    start, end = span
    have = readme[start:end].split("\n")
    want = render_class_tables(matrix).split("\n")
    first_line = readme.count("\n", 0, start) + 1
    for i, (h, w) in enumerate(zip(have, want)):
        if h != w:
            return [
                f"README.md:{first_line + i}: the attack-class tables differ from matrix.json "
                f"(expected \"{w}\"); run python3 scripts/check_readme_claims.py --fix"
            ]
    if len(have) != len(want):
        line = first_line + min(len(have), len(want))
        return [
            f"README.md:{line}: the attack-class tables have {len(have)} lines, matrix.json "
            f"renders {len(want)}; run python3 scripts/check_readme_claims.py --fix"
        ]
    return []


def fix_class_tables(matrix, readme):
    """README text with only the generated block re-rendered; unchanged when the
    markers are missing or out of order."""
    span = class_block_span(readme)
    if span is None:
        return readme
    start, end = span
    return readme[:start] + render_class_tables(matrix) + readme[end:]


def empty(value):
    """A mapping field counts as absent when null, empty, or all-empty strings."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple)):
        return all(empty(v) for v in value) if value else True
    return False


def main(argv):
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    readme = README.read_text(encoding="utf-8")

    if "--fix" in argv:
        fixed = fix_class_tables(matrix, readme)
        if fixed != readme:
            README.write_text(fixed, encoding="utf-8")
            readme = fixed
            print("FIXED: rewrote the attack-class tables from matrix.json")
        else:
            print("OK: attack-class tables already current")

    tactics = matrix["tactics"]
    techniques = matrix["techniques"]
    classes = matrix.get("attackClasses", [])

    tiers = {}
    for t in techniques:
        tiers[t.get("evidenceTier")] = tiers.get(t.get("evidenceTier"), 0) + 1

    with_detection = sum(1 for t in techniques if not empty(t.get("hmaChecks")))
    with_control = sum(1 for t in techniques if not empty(t.get("oasbControls")))
    with_lab = sum(1 for t in techniques if not empty(t.get("dvaaValidation")))

    total = len(techniques)
    failures = []

    def require(pattern, expected, label):
        """The README states this wording at least once, and every occurrence carries
        the measured number(s).

        `pattern` captures each stated number as a group, in the order of `expected`.
        Checking every occurrence, rather than that the right number appears
        somewhere, is what catches a count repeated in a second section (Use cases,
        Purpose) going stale while the first copy still matches.
        """
        want = tuple(str(v) for v in expected)
        found = list(re.finditer(pattern, readme))
        if not found:
            failures.append(f"README does not state {label} ({', '.join(want)})")
        for m in found:
            if m.groups() != want:
                line = readme.count("\n", 0, m.start()) + 1
                failures.append(
                    f"README.md:{line}: \"{m.group(0)}\" does not match matrix.json "
                    f"({label}: {', '.join(want)})"
                )

    observed = tiers.get("observed", 0)
    validated = tiers.get("validated", 0)
    adapted = tiers.get("adapted", 0)

    require(r"\b(\d+) tactics\b", [len(tactics)], "tactics")
    require(r"\*\*(\d+) techniques\*\*", [total], "techniques")
    require(r"\b(\d+) tactics and (\d+) techniques\b", [len(tactics), total],
            "tactics and techniques")
    require(r"\b(\d+) attack classes\b", [len(classes)], "attack classes")
    require(r"\*\*(\d+) attack classes\*\*", [len(classes)], "attack classes")

    # Evidence tiers, in the overview wording and in the Use cases wording.
    require(r"\*\*(\d+) techniques with real-world evidence\*\*", [observed], "observed")
    require(r"\b(\d+) of the (\d+) techniques carry real-world evidence\b",
            [observed, total], "observed of total")
    require(r"\*\*(\d+) techniques validated in controlled lab environments\*\*",
            [validated], "validated")
    require(r"\b(\d+) are validated in controlled lab environments\b", [validated],
            "validated")
    require(r"\*\*(\d+) techniques adapted from traditional environments\*\*",
            [adapted], "adapted")
    require(r"\b(\d+) are adapted from traditional environments\b", [adapted], "adapted")

    # Coverage claims. Detection and defensive control are stated as universal,
    # so they must actually hold for every technique. The lab-scenario claim is
    # stated as a ratio because it does not.
    if with_detection != total:
        gaps = [t["id"] for t in techniques if empty(t.get("hmaChecks"))]
        failures.append(
            f"README claims every technique maps to automated detection, "
            f"but {total - with_detection} do not: {gaps}"
        )
    if with_control != total:
        gaps = [t["id"] for t in techniques if empty(t.get("oasbControls"))]
        failures.append(
            f"README claims every technique maps to a defensive control, "
            f"but {total - with_control} do not: {gaps}"
        )
    require(
        r"\b(\d+) of the (\d+) (?:also )?carry a reproducible lab scenario\b",
        [with_lab, total],
        "lab scenario of total",
    )

    failures.extend(check_class_tables(matrix, readme))

    tier_total = sum(tiers.values())
    if tier_total != total:
        failures.append(
            f"evidence tiers sum to {tier_total}, expected {total} "
            f"(every technique needs exactly one tier; got {tiers})"
        )

    if failures:
        print("README claims do not match matrix.json:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print(
            f"\nmeasured: {len(tactics)} tactics, {total} techniques, "
            f"{len(classes)} attack classes, tiers={tiers}, "
            f"detection={with_detection}/{total}, control={with_control}/{total}, "
            f"lab={with_lab}/{total}",
            file=sys.stderr,
        )
        return 1

    print(
        f"README claims match matrix.json: {len(tactics)} tactics, {total} techniques, "
        f"{len(classes)} attack classes, tiers={tiers}, "
        f"detection={with_detection}/{total}, control={with_control}/{total}, "
        f"lab={with_lab}/{total}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
