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

The README also states figures about related projects. Those are measured in the
other project, so they are pinned in related-projects.json with the release and
commit each was read from, and every README line naming the project must state the
pinned number wherever it uses one of the wordings read here. For DVAA those are
"N agents", "N deliberately vulnerable", "N hardened reference", "N control-protected
variant(s)", "N vulnerable agent(s)" and "N categories", where up to two words, each a
run of ASCII letters and hyphens, may stand between the number and "categories". Each
is read in any letter case with one space between words; a figure worded any other way
is not checked. DVAA was
described as "21 vulnerable agents" while DVAA labels one of the 21 a hardened
reference and four control-protected variants.

Exit 0 when every claim matches the data, 1 otherwise.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MATRIX = ROOT / "matrix.json"
README = ROOT / "README.md"
RELATED = ROOT / "related-projects.json"

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


def lines_naming(text, name):
    """`text` with every line that does not contain `name` blanked, so a match
    offset still converts to its README line number."""
    return "\n".join(line if name in line else "" for line in text.split("\n"))


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

    def require(pattern, expected, label, text=readme, source="matrix.json", stated=True,
                flags=0):
        """The README states this wording at least once, and every occurrence carries
        the measured number(s).

        `pattern` captures each stated number as a group, in the order of `expected`.
        Checking every occurrence, rather than that the right number appears
        somewhere, is what catches a count repeated in a second section (Use cases,
        Purpose) going stale while the first copy still matches. `text` is the README
        or a line-preserving subset of it; with `stated=False` the wording may be
        absent, but any occurrence must still carry the measured number(s).
        """
        want = tuple(str(v) for v in expected)
        found = list(re.finditer(pattern, text, flags))
        if not found and stated:
            failures.append(f"README does not state {label} ({', '.join(want)})")
        for m in found:
            if m.groups() != want:
                line = text.count("\n", 0, m.start()) + 1
                failures.append(
                    f"README.md:{line}: \"{m.group(0)}\" does not match {source} "
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

    # Related-project figures, read only from the README lines that name the project.
    related = json.loads(RELATED.read_text(encoding="utf-8"))
    dvaa = related["dvaa"]
    kinds = {kind: entry["count"] for kind, entry in dvaa["agentsByKind"].items()}
    if sum(kinds.values()) != dvaa["agents"]:
        failures.append(
            f"related-projects.json: dvaa.agentsByKind counts sum to {sum(kinds.values())}, "
            f"dvaa.agents is {dvaa['agents']}"
        )
    dvaa_lines = lines_naming(readme, "DVAA")
    pinned = "related-projects.json"
    # Every DVAA wording is read in any letter case: DVAA itself writes "Attack Categories".
    # re.ASCII keeps that to ASCII letters and digits: without it "[A-Za-z]" also matches
    # U+0130, U+0131, U+017F (long s) and U+212A (Kelvin sign), and an "i" or "s" in a
    # wording matches the first three. re.ASCII would also narrow \b to ASCII word
    # characters and read "é21 agents" as "21 agents", so each wording is bounded by a
    # Unicode word boundary instead: a wording glued to a letter or digit of any script
    # is not read.
    on_dvaa_lines = dict(text=dvaa_lines, source=pinned, flags=re.IGNORECASE | re.ASCII)

    def wording(words):
        """The pattern for "N <words>", bounded on both sides by a Unicode word boundary."""
        return r"(?u:\b)(\d+) " + words + r"(?u:\b)"

    require(wording("agents"), [dvaa["agents"]], "DVAA agents", **on_dvaa_lines)
    require(wording("deliberately vulnerable"), [kinds["deliberatelyVulnerable"]],
            "DVAA deliberately vulnerable agents", **on_dvaa_lines)
    require(wording("hardened reference"), [kinds["hardenedReference"]],
            "DVAA hardened reference agents", **on_dvaa_lines)
    require(wording("control-protected variants?"), [kinds["controlProtectedVariant"]],
            "DVAA control-protected variants", **on_dvaa_lines)
    # "N vulnerable agents" counts only the agents DVAA labels vulnerable.
    require(wording("(?:deliberately )?vulnerable agents?"), [kinds["deliberatelyVulnerable"]],
            "DVAA vulnerable agents", stated=False, **on_dvaa_lines)
    # The count is read under any name: "N categories" with up to two words, each a run
    # of ASCII letters and hyphens, between the number and the noun.
    require(wording("(?:[A-Za-z-]+ ){0,2}categories"), [dvaa["vulnerabilityCategories"]],
            "DVAA vulnerability categories", **on_dvaa_lines)
    dvaa_summary = (
        f"DVAA {dvaa['sourceVersion']}: {dvaa['agents']} agents "
        f"({', '.join(f'{k}={v}' for k, v in kinds.items())}), "
        f"{dvaa['vulnerabilityCategories']} vulnerability categories"
    )

    tier_total = sum(tiers.values())
    if tier_total != total:
        failures.append(
            f"evidence tiers sum to {tier_total}, expected {total} "
            f"(every technique needs exactly one tier; got {tiers})"
        )

    if failures:
        print("README claims do not match matrix.json and related-projects.json:\n",
              file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print(
            f"\nmeasured: {len(tactics)} tactics, {total} techniques, "
            f"{len(classes)} attack classes, tiers={tiers}, "
            f"detection={with_detection}/{total}, control={with_control}/{total}, "
            f"lab={with_lab}/{total}\npinned: {dvaa_summary}",
            file=sys.stderr,
        )
        return 1

    print(
        f"README claims match matrix.json: {len(tactics)} tactics, {total} techniques, "
        f"{len(classes)} attack classes, tiers={tiers}, "
        f"detection={with_detection}/{total}, control={with_control}/{total}, "
        f"lab={with_lab}/{total}; and related-projects.json: {dvaa_summary}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
