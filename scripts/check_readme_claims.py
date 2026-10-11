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
is not checked. DVAA was described as "21 vulnerable agents" while DVAA labels one of
the 21 a hardened reference and four control-protected variants.

A line naming DVAA fails when it carries a format character (Unicode category Cf, such
as U+00AD SOFT HYPHEN or U+200B ZERO WIDTH SPACE), a control character (category Cc)
other than a tab, a Hangul filler (U+115F, U+1160, U+3164, U+FFA0), one of the
combining marks Unicode lists as default ignorable (U+034F, U+17B4, U+17B5, U+180B to
U+180D, U+180F, U+FE00 to U+FE0F, U+E0100 to U+E01EF) or one of the code points Unicode
lists as default ignorable without assigning them (U+2065, U+FFF0 to U+FFF8, U+E0000,
U+E0002 to U+E001F, U+E0080 to U+E00FF, U+E01F0 to U+E0FFF). Inside a wording such a
character keeps the wording from being read, and a Hangul filler or combining mark does
so directly beside a DVAA wording, while a character that renders as nothing leaves the
figure in the rendered line. A line names DVAA when it contains "DVAA" once such
characters are removed, so one written inside the name does not take the line out of the
check, and a line that states one of the matrix.json counts once they are removed fails
the same way when it carries one. Each failure names the line, the column of the
character's first occurrence on it, counted in characters from 1, and the character.

Exit 0 when every claim matches the data, 1 otherwise.
"""

import json
import pathlib
import re
import sys
import unicodedata

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

# Letters (category Lo) that render as blank space. Each is a word character, so a DVAA
# wording directly beside one is not read, and neither is a matrix.json count wording
# bounded by \b, which does not hold between a filler and a digit or letter beside it.
HANGUL_FILLERS = (
    "\N{HANGUL CHOSEONG FILLER}\N{HANGUL JUNGSEONG FILLER}"
    "\N{HANGUL FILLER}\N{HALFWIDTH HANGUL FILLER}"
)

# The combining marks (category Mn) Unicode lists as default ignorable code points, which
# render as nothing: U+034F COMBINING GRAPHEME JOINER, two Khmer inherent vowels, the
# Mongolian free variation selectors and the variation selectors, 263 code points.
IGNORABLE_MARKS = frozenset(
    chr(code)
    for low, high in ((0x034F, 0x034F), (0x17B4, 0x17B5), (0x180B, 0x180D), (0x180F, 0x180F),
                      (0xFE00, 0xFE0F), (0xE0100, 0xE01EF))
    for code in range(low, high + 1)
)

# The code points Unicode lists as default ignorable without assigning them (category Cn):
# U+2065, U+FFF0 to U+FFF8 and the unassigned part of the tag and variation selector
# blocks, 3,769 code points. A renderer may draw one as nothing.
UNASSIGNED_IGNORABLES = frozenset(
    chr(code)
    for low, high in ((0x2065, 0x2065), (0xFFF0, 0xFFF8), (0xE0000, 0xE0000),
                      (0xE0002, 0xE001F), (0xE0080, 0xE00FF), (0xE01F0, 0xE0FFF))
    for code in range(low, high + 1)
)


def is_mark(code):
    """Whether code point `code` is a combining mark (Unicode category M: Mn, Mc or Me)."""
    return 0 <= code <= sys.maxunicode and unicodedata.category(chr(code)).startswith("M")


def combining_marks_in(text):
    """A regex character class body holding, as one range each, the runs of consecutive
    combining marks that hold a mark occurring in `text`. A mark that occurs nowhere in
    `text` can stand beside no wording in it, so the class need not hold every mark there
    is. Listed one by one, each mark outside the Basic Multilingual Plane is a separate
    entry that every test of the class walks; as runs, the class has no more ranges than
    a table of every mark."""
    ranges = []
    for code in sorted(ord(c) for c in set(text) if is_mark(ord(c))):
        if ranges and code <= ranges[-1][1]:
            continue
        lo = hi = code
        while is_mark(lo - 1):
            lo -= 1
        while is_mark(hi + 1):
            hi += 1
        ranges.append((lo, hi))
    return "".join(f"\\U{lo:08x}-\\U{hi:08x}" for lo, hi in ranges)


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


def lines_naming(lines, name):
    """The README with every line blanked that does not contain `name` once the characters
    `hiding_kind` names are removed, so a match offset still converts to its README line
    number. `lines` holds each README line as `classified` returns it. "DV" U+200B "AA"
    shows as DVAA, so that line names DVAA."""
    return "\n".join(line if name in shown else "" for line, shown, _ in lines)


def hiding_kind(c):
    """What `c` is when it fails a line that names DVAA or states a count, else None: a
    character that can keep a wording from being read."""
    category = unicodedata.category(c)
    if category == "Cf":
        return "a format character"
    if category == "Cc" and c != "\t":
        return "a control character"
    if c in HANGUL_FILLERS:
        return "a Hangul filler"
    if c in IGNORABLE_MARKS:
        return "a default-ignorable combining mark"
    if c in UNASSIGNED_IGNORABLES:
        return "an unassigned default-ignorable code point"
    return None


def classified(line):
    """(line, shown, hidden) for `line`: `shown` is `line` with every character
    `hiding_kind` names removed, and `hidden` holds (column, character) for the first
    occurrence of each such character, the column counted in characters from 1. One
    lookup per character gives both; a repeat of a character already found is removed
    without another."""
    shown = []
    hidden = []
    seen = set()
    for column, c in enumerate(line, 1):
        if c in seen:
            continue
        if hiding_kind(c):
            seen.add(c)
            hidden.append((column, c))
        else:
            shown.append(c)
    return line, "".join(shown), hidden


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

    count_wordings = []

    def count(pattern, expected, label):
        """`require` for a matrix.json count, which any README line may state."""
        count_wordings.append(pattern)
        require(pattern, expected, label)

    observed = tiers.get("observed", 0)
    validated = tiers.get("validated", 0)
    adapted = tiers.get("adapted", 0)

    count(r"\b(\d+) tactics\b", [len(tactics)], "tactics")
    count(r"\*\*(\d+) techniques\*\*", [total], "techniques")
    count(r"\b(\d+) tactics and (\d+) techniques\b", [len(tactics), total],
          "tactics and techniques")
    count(r"\b(\d+) attack classes\b", [len(classes)], "attack classes")
    count(r"\*\*(\d+) attack classes\*\*", [len(classes)], "attack classes")

    # Evidence tiers, in the overview wording and in the Use cases wording.
    count(r"\*\*(\d+) techniques with real-world evidence\*\*", [observed], "observed")
    count(r"\b(\d+) of the (\d+) techniques carry real-world evidence\b",
          [observed, total], "observed of total")
    count(r"\*\*(\d+) techniques validated in controlled lab environments\*\*",
          [validated], "validated")
    count(r"\b(\d+) are validated in controlled lab environments\b", [validated],
          "validated")
    count(r"\*\*(\d+) techniques adapted from traditional environments\*\*",
          [adapted], "adapted")
    count(r"\b(\d+) are adapted from traditional environments\b", [adapted], "adapted")

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
    count(
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
    # Each README line is classified once: the lookups that find the characters failing a
    # line also give the line as it shows, and that decides whether it names DVAA.
    lines = [classified(line) for line in readme.split("\n")]
    dvaa_lines = lines_naming(lines, "DVAA")
    pinned = "related-projects.json"
    # Every DVAA wording is read in any letter case: DVAA itself writes "Attack Categories".
    # re.ASCII keeps that to ASCII letters and digits: without it "[A-Za-z]" also matches
    # U+0130, U+0131, U+017F (long s) and U+212A (Kelvin sign), and an "i" or "s" in a
    # wording matches the first three. re.ASCII would also narrow \b to ASCII word
    # characters and read "é21 agents" as "21 agents". A Unicode \b is not enough either:
    # it counts no combining mark as a word character, so "é" written as "e" and U+0301
    # was read. Each wording is bounded instead by the absence of a Unicode word character
    # or a combining mark on either side: a wording glued to a letter, digit or combining
    # mark of any script is not read. Both bounds stay inside the pattern, so that where
    # one start position matches at several lengths ("13 categories x categories" holds
    # "13 categories") a mark glued to the longer wording leaves the shorter one read.
    # The mark part of the class is built from the DVAA lines alone, not from every code
    # point: a mark that stands on none of them can stand beside no wording. It holds each
    # run of consecutive marks that has a mark on those lines, so it is never larger than
    # a table of every mark.
    on_dvaa_lines = dict(text=dvaa_lines, source=pinned, flags=re.IGNORECASE | re.ASCII)
    glue = r"(?u:[\w" + combining_marks_in(dvaa_lines) + r"])"

    def wording(words):
        """The pattern for "N <words>", with no Unicode word character and no combining
        mark directly before or after it."""
        return r"(?<!" + glue + r")(\d+) " + words + r"(?!" + glue + r")"

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

    # A wording is not read when a character `hiding_kind` names stands inside it ("age"
    # U+00AD "nts", "22" U+200B " agents", "tac" U+00AD "tics"), or when a Hangul filler or
    # combining mark is glued to a DVAA wording (U+3164 "22 agents", "agents" U+034F), so
    # the character fails the line instead of leaving its figure unchecked. That holds for
    # every line that names DVAA or states a matrix.json count once such characters are
    # removed: "DV" U+200B "AA" names DVAA, and "8 tac" U+00AD "tics" states a count the
    # check cannot read.
    for number, (line, shown, hidden) in enumerate(lines, 1):
        if not hidden:
            continue
        readers = []
        if "DVAA" in shown:
            readers.append(("naming DVAA", "DVAA"))
        if any(re.search(pattern, shown) for pattern in count_wordings):
            readers.append(("stating a matrix.json count", "count"))
        if not readers:
            continue
        where = " and ".join(phrase for phrase, _ in readers)
        wordings = " and ".join(name for _, name in readers)
        for column, c in hidden:
            named = " ".join(filter(None, (f"U+{ord(c):04X}", unicodedata.name(c, ""))))
            failures.append(
                f"README.md:{number}:{column}: a line {where} carries {named}, "
                f"{hiding_kind(c)}, which can hide a figure from the {wordings} wordings; "
                f"remove it"
            )

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
