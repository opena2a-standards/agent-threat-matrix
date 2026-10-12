"""README claim checker tests.

Every case runs scripts/check_readme_claims.py against a scratch copy of README.md and
matrix.json so the committed files are never perturbed. The shipped tree must be green.
Each count the README states is then changed by one in a single place and the checker
must go red, including the counts repeated in the "Use cases" section: the checker used
to accept a claim when the right number appeared anywhere, so a stale repeat passed
while the overview copy still matched. The same holds for the per-tactic table, the
evidence-tier counts and percentages, the "Attack Classes (N)" heading and the HackMyAgent
and OASB figures pinned in related-projects.json, which the checker did not read at all,
so a HackMyAgent check count went stale without failing CI.

The attack-class tables are generated from matrix.json: a reworded description, a
description changed in matrix.json alone, and a missing marker must each go red, and
``--fix`` must re-render the block without touching the rest of the README. An argument
other than ``--fix``, ``--help`` or ``-h`` must exit 2 without checking or writing anything.
Given together with ``--help`` or ``-h``, in either order, such an argument must leave the
run printing the usage and exiting 0, again without checking or writing anything.

The DVAA figures are measured in DVAA, not in matrix.json, and are pinned in
related-projects.json. Every README line naming DVAA must state the pinned numbers: the
line that called all 21 agents vulnerable, while DVAA labels one hardened and four
control-protected, must go red. A README line naming DVAA that carries a format character,
a control character other than a tab, a Hangul filler, a default-ignorable combining mark
or an unassigned default-ignorable code point must go red too, and so must a line that
states a matrix.json count once such characters are removed. Inside a wording such a
character keeps the wording from being read, and a Hangul filler or combining mark does so
directly beside a DVAA wording, while a character that renders as nothing leaves the figure
in the rendered line. Markup, a character reference or a confusable letter written inside
the name as the cases below write it leaves the line read, and so does a backtick written in
a link destination, a link title, two table cells, an autolink or an HTML attribute holding
"<"; a character that fails a line still fails a line that names DVAA only in that way.
Written with a combining mark directly after it, or with a "!" inside it that does not
stand before a "[", the name does not name DVAA; on a line that also carries a character
that fails it, a mark directly after the name leaves the line naming DVAA, and the line
goes red. The three steps README states for reading the name are also written below as a
plain scan, which must read generated lines as the checker does, so the sentence and the
checker's patterns cannot drift apart with every test passing.
"""

import html
import html.entities
import importlib.util
import json
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = ("README.md", "matrix.json", "related-projects.json", "scripts/check_readme_claims.py")
BEGIN = "<!-- BEGIN GENERATED: attack-class-tables -->"
END = "<!-- END GENERATED: attack-class-tables -->"
GATEWAY_DESCRIPTION = (
    "Modifying gateway or proxy configurations to intercept, redirect, or manipulate agent traffic"
)


def scratch_tree() -> Path:
    td = Path(tempfile.mkdtemp(prefix="atm-readme-"))
    for rel in FILES:
        dst = td / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    return td


def run_checker(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(root / "scripts" / "check_readme_claims.py"), *args],
                          capture_output=True, text=True, timeout=120)


def mutate_readme(root: Path, old: str, new: str) -> None:
    readme = root / "README.md"
    text = readme.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"mutation target must occur exactly once: {old!r}"
    readme.write_text(text.replace(old, new), encoding="utf-8")


def test_shipped_readme_is_green():
    td = scratch_tree()
    try:
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
        assert "README claims match matrix.json" in r.stdout
    finally:
        shutil.rmtree(td)


# (old, new): one stated number moved off the measured value in one place.
MUTATIONS = [
    # Use cases: the threat-list paragraph.
    ("into 9 tactics and 61 techniques along a kill chain",
     "into 8 tactics and 61 techniques along a kill chain"),
    ("into 9 tactics and 61 techniques along a kill chain",
     "into 9 tactics and 62 techniques along a kill chain"),
    ("and 58 of the 61 carry a reproducible lab scenario",
     "and 59 of the 61 carry a reproducible lab scenario"),
    # Use cases: the evidence-tier sentence.
    ("16 of the 61 techniques carry real-world evidence",
     "15 of the 61 techniques carry real-world evidence"),
    ("16 of the 61 techniques carry real-world evidence",
     "16 of the 60 techniques carry real-world evidence"),
    ("42 are validated in controlled lab environments",
     "41 are validated in controlled lab environments"),
    ("3 are adapted from traditional environments",
     "4 are adapted from traditional environments"),
    # Purpose.
    ("into 9 tactics and 61 techniques, organized by kill chain stage",
     "into 9 tactics and 60 techniques, organized by kill chain stage"),
    ("58 of the 61 also carry a reproducible lab scenario",
     "60 of the 61 also carry a reproducible lab scenario"),
    # Matrix overview.
    ("**61 techniques** across 9 tactics", "**61 techniques** across 10 tactics"),
    ("**40 attack classes**", "**41 attack classes**"),
    ("**16 techniques with real-world evidence**", "**17 techniques with real-world evidence**"),
    ("**42 techniques validated in controlled lab environments**",
     "**43 techniques validated in controlled lab environments**"),
    ("**3 techniques adapted from traditional environments**",
     "**2 techniques adapted from traditional environments**"),
    # Cross-framework mapping: the DVAA figures pinned in related-projects.json.
    ("(21 agents: 16 deliberately vulnerable", "(22 agents: 16 deliberately vulnerable"),
    ("(21 agents: 16 deliberately vulnerable", "(21 agents: 17 deliberately vulnerable"),
    ("1 hardened reference", "2 hardened reference"),
    ("4 control-protected variants", "3 control-protected variants"),
    ("variants; 12 vulnerability categories", "variants; 13 vulnerability categories"),
    # DVAA's own table is titled Attack Categories; the count is read under either name.
    ("variants; 12 vulnerability categories", "variants; 13 attack categories"),
    ("variants; 12 vulnerability categories", "variants; 13 categories"),
    # Up to two words may stand between the number and "categories".
    ("variants; 12 vulnerability categories", "variants; 13 distinct attack categories"),
    # Every DVAA wording is read in any letter case, and the singular nouns are read too.
    ("variants; 12 vulnerability categories", "variants; 13 Attack Categories"),
    ("variants; 12 vulnerability categories", "variants; 13 VULNERABILITY CATEGORIES"),
    ("(21 agents: 16 deliberately vulnerable", "(22 Agents: 16 deliberately vulnerable"),
    ("4 control-protected variants", "3 control-protected variant"),
    # The DVAA row counted all 21 agents as vulnerable.
    ("Lab validation (21 agents: 16 deliberately vulnerable, 1 hardened reference, "
     "4 control-protected variants; 12 vulnerability categories)",
     "Lab validation (21 vulnerable agents, 12 vulnerability categories)"),
    # Related projects.
    ("environment (21 agents, 12 vulnerability categories)",
     "environment (20 agents, 12 vulnerability categories)"),
    ("environment (21 agents, 12 vulnerability categories)",
     "environment (21 agents, 11 vulnerability categories)"),
    ("environment (21 agents, 12 vulnerability categories)",
     "environment (21 vulnerable agents, 12 vulnerability categories)"),
    # Matrix overview: the per-tactic table (kill chain stage, technique count, name).
    ("| [Initial Access](tactics/initial-access.md) | 2 | 9 |",
     "| [Initial Access](tactics/initial-access.md) | 2 | 8 |"),
    ("| [Impact](tactics/impact.md) | 9 | 6 |", "| [Impact](tactics/impact.md) | 8 | 6 |"),
    ("| [Collection](tactics/collection.md) |", "| [Data Collection](tactics/collection.md) |"),
    # Evidence Standard: the tier table counts and percentages.
    ("| 16 (26%) |", "| 16 (27%) |"),
    ("| 42 (69%) |", "| 43 (69%) |"),
    ("| 3 (5%) |", "| 3 (4%) |"),
    # Attack Classes: the section heading.
    ("## Attack Classes (40)", "## Attack Classes (41)"),
    # The HackMyAgent and OASB figures pinned in related-projects.json, in Cross-Framework
    # Mapping and in Related Projects.
    ("(318 static checks, 164 attack payloads)", "(310 static checks, 164 attack payloads)"),
    ("(318 static checks, 164 attack payloads)", "(318 static checks, 165 attack payloads)"),
    ("(318 static checks, 164 payloads)", "(310 static checks, 164 payloads)"),
    ("(318 static checks, 164 payloads)", "(318 static checks, 163 payloads)"),
    ("(46 controls across 10 domains)", "(45 controls across 10 domains)"),
    ("(46 controls across 10 domains)", "(46 controls across 11 domains)"),
    ("Defensive benchmark (46 controls)", "Defensive benchmark (47 controls)"),
]


@pytest.mark.parametrize("old,new", MUTATIONS, ids=[n for _, n in MUTATIONS])
def test_a_wrong_count_in_one_place_is_red(old, new):
    td = scratch_tree()
    try:
        mutate_readme(td, old, new)
        text = (td / "README.md").read_text(encoding="utf-8")
        line = text[:text.index(new)].count("\n") + 1
        r = run_checker(td)
        assert r.returncode == 1, f"checker passed with {new!r}:\n{r.stdout}"
        assert f"README.md:{line}:" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_claim_reworded_out_of_the_readme_is_red():
    td = scratch_tree()
    try:
        mutate_readme(td, "16 of the 61 techniques carry real-world evidence",
                      "some techniques carry real-world evidence")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert "README does not state observed of total" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def mutate_related(root: Path, edit, project: str = "dvaa") -> None:
    path = root / "related-projects.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    edit(data[project])
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def line_of(root: Path, needle: str) -> int:
    text = (root / "README.md").read_text(encoding="utf-8")
    return text[:text.index(needle)].count("\n") + 1


def test_dvaa_kinds_must_add_up_to_the_agent_count():
    td = scratch_tree()
    try:
        mutate_related(td, lambda d: d["agentsByKind"]["hardenedReference"].update(count=2))
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert ("related-projects.json: dvaa.agentsByKind counts sum to 22, "
                "dvaa.agents is 21") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_dvaa_figure_changed_in_the_pinned_file_is_red_on_every_readme_line():
    td = scratch_tree()
    try:
        mutate_related(td, lambda d: d.update(vulnerabilityCategories=13))
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for needle in ("variants; 12 vulnerability categories",
                       "environment (21 agents, 12 vulnerability categories)"):
            assert f"README.md:{line_of(td, needle)}:" in r.stderr, r.stderr
        assert "related-projects.json (DVAA vulnerability categories: 13)" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_refreshed_hackmyagent_figure_turns_every_stale_readme_copy_red():
    # A HackMyAgent release changes the check count: the pinned file is refreshed and both
    # README copies of the old figure must fail, each named by line.
    td = scratch_tree()
    try:
        mutate_related(td, lambda d: d.update(staticChecks=319), project="hackmyagent")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for needle in ("(318 static checks, 164 attack payloads)",
                       "(318 static checks, 164 payloads)"):
            assert f"README.md:{line_of(td, needle)}:" in r.stderr, r.stderr
        assert ("related-projects.json (hackmyagent.staticChecks, read from release 0.33.2: "
                "319)") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


@pytest.mark.parametrize("project,field", [("oasb", "domains"), ("hackmyagent", "attackPayloads")])
def test_a_pinned_figure_missing_from_the_file_is_red(project, field):
    td = scratch_tree()
    try:
        mutate_related(td, lambda d: d.pop(field), project=project)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert f"related-projects.json: {project}.{field} is not a whole number" in r.stderr, \
            r.stderr
    finally:
        shutil.rmtree(td)


def test_a_tactic_row_dropped_from_the_overview_table_is_red():
    td = scratch_tree()
    try:
        text = (td / "README.md").read_text(encoding="utf-8")
        row = next(l for l in text.splitlines(keepends=True)
                   if l.startswith("| [Persistence](tactics/persistence.md) |"))
        mutate_readme(td, row, "")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert "README per-tactic table has no row for tactic persistence" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_category_count_with_three_words_before_the_noun_is_not_read():
    # README states that a DVAA figure worded any other way than the wordings it lists is
    # not checked; three words between the number and "categories" is such a wording.
    td = scratch_tree()
    try:
        mutate_readme(td, "variants; 12 vulnerability categories",
                      "variants; 13 distinct attack vulnerability categories")
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


# Lines that hold a non-ASCII letter where README says each DVAA wording has ASCII letters.
# Under re.IGNORECASE alone, "[A-Za-z]" matches U+0130, U+0131, U+017F and U+212A, and the
# "s" of "agents" matches U+017F, so each of these used to be read and fail on its number.
NOT_ASCII_WORDINGS = [
    ("U+0130 between the number and categories",
     "variants; 12 vulnerability categories", "variants; 13 İ categories"),
    ("U+0131 between the number and categories",
     "variants; 12 vulnerability categories", "variants; 13 ı categories"),
    ("U+017F between the number and categories",
     "variants; 12 vulnerability categories", "variants; 13 ſ categories"),
    ("U+212A between the number and categories",
     "variants; 12 vulnerability categories", "variants; 13 \N{KELVIN SIGN} categories"),
    ("U+017F for the s of agents",
     "(21 agents: 16 deliberately vulnerable", "(22 agentſ: 16 deliberately vulnerable"),
]


@pytest.mark.parametrize("old,new", [(o, n) for _, o, n in NOT_ASCII_WORDINGS],
                         ids=[name for name, _, _ in NOT_ASCII_WORDINGS])
def test_a_wording_with_a_non_ascii_letter_is_not_read(old, new):
    td = scratch_tree()
    try:
        mutate_readme(td, old, new)
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


# Lines where a letter or digit outside ASCII is glued to a DVAA wording. re.ASCII also
# narrows \b to ASCII word characters, so each of these used to be read as the wording
# beside it ("é22 agents" as "22 agents") and fail on its number. A Unicode \b counts no
# combining mark as a word character, so the cases with a combining mark were still read
# under it: "é" written as "e" and U+0301 failed where the precomposed U+00E9 passed.
GLUED_WORDINGS = [
    ("U+00E9 before the agent count",
     "(21 agents: 16 deliberately vulnerable", "(é22 agents: 16 deliberately vulnerable"),
    ("U+00E9 after agents",
     "(21 agents: 16 deliberately vulnerable", "(22 agentsé: 16 deliberately vulnerable"),
    ("U+0662 (Arabic-Indic two) before the agent count",
     "(21 agents: 16 deliberately vulnerable", "(٢22 agents: 16 deliberately vulnerable"),
    ("U+00E9 before the category count",
     "variants; 12 vulnerability categories", "variants; é13 vulnerability categories"),
    ("U+00E9 after categories",
     "variants; 12 vulnerability categories", "variants; 13 vulnerability categoriesé"),
    ("e and U+0301 before the agent count",
     "(21 agents: 16 deliberately vulnerable",
     "(e\N{COMBINING ACUTE ACCENT}22 agents: 16 deliberately vulnerable"),
    ("U+0915 U+093F (Devanagari ki) before the agent count",
     "(21 agents: 16 deliberately vulnerable",
     "(कि22 agents: 16 deliberately vulnerable"),
    ("U+05D1 U+05BC (Hebrew bet with dagesh) before the agent count",
     "(21 agents: 16 deliberately vulnerable",
     "(בּ22 agents: 16 deliberately vulnerable"),
    ("U+0301 on the s of agents",
     "(21 agents: 16 deliberately vulnerable",
     "(22 agents\N{COMBINING ACUTE ACCENT}: 16 deliberately vulnerable"),
    ("U+0301 on the s of categories",
     "variants; 12 vulnerability categories",
     "variants; 13 vulnerability categories\N{COMBINING ACUTE ACCENT}"),
    # An enclosing mark (category Me) is a combining mark as much as a nonspacing (Mn) or
    # spacing (Mc) one, so it glues a wording too.
    ("U+20DD (combining enclosing circle) before the agent count",
     "(21 agents: 16 deliberately vulnerable",
     "(\N{COMBINING ENCLOSING CIRCLE}22 agents: 16 deliberately vulnerable"),
    ("U+20DD (combining enclosing circle) on the s of agents",
     "(21 agents: 16 deliberately vulnerable",
     "(22 agents\N{COMBINING ENCLOSING CIRCLE}: 16 deliberately vulnerable"),
    # The wordings below are stated once in README, so each glued copy is added beside
    # the original rather than replacing it.
    ("U+00E9 before the deliberately vulnerable count",
     "16 deliberately vulnerable,", "16 deliberately vulnerable, é17 deliberately vulnerable,"),
    ("U+00E9 after deliberately vulnerable",
     "16 deliberately vulnerable,", "16 deliberately vulnerable, 17 deliberately vulnerableé,"),
    ("U+00E9 before the hardened reference count",
     "1 hardened reference,", "1 hardened reference, é2 hardened reference,"),
    ("U+00E9 after hardened reference",
     "1 hardened reference,", "1 hardened reference, 2 hardened referenceé,"),
    ("U+00E9 before the control-protected variant count",
     "4 control-protected variants;",
     "4 control-protected variants, é5 control-protected variants;"),
    ("U+00E9 after control-protected variants",
     "4 control-protected variants;",
     "4 control-protected variants, 5 control-protected variantsé;"),
    ("U+00E9 before the vulnerable agent count",
     "16 deliberately vulnerable,", "16 deliberately vulnerable, é17 vulnerable agents,"),
    ("U+00E9 after vulnerable agents",
     "16 deliberately vulnerable,", "16 deliberately vulnerable, 17 vulnerable agentsé,"),
]


@pytest.mark.parametrize("old,new", [(o, n) for _, o, n in GLUED_WORDINGS],
                         ids=[name for name, _, _ in GLUED_WORDINGS])
def test_a_wording_glued_to_a_non_ascii_letter_or_digit_is_not_read(old, new):
    td = scratch_tree()
    try:
        mutate_readme(td, old, new)
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


def column_of(root: Path, needle: str, named: str) -> int:
    """The column, counted in characters from 1, of the first occurrence of the character
    `named` (as "U+XXXX ...") on the README line holding `needle`."""
    character = chr(int(re.match(r"U\+([0-9A-F]+)", named).group(1), 16))
    text = (root / "README.md").read_text(encoding="utf-8")
    start = text.rindex("\n", 0, text.index(needle)) + 1
    return text.index(character, start) - start + 1


# Lines naming DVAA that carry a character which fails such a line. Each case but the last
# hides the wording it stands in or beside from the check ("age" U+00AD "nts" is not read,
# and neither is "22 agents" glued to U+3164 or "categories" glued to U+17B4); the last
# carries U+FEFF between two wordings that state the pinned numbers. Each line must fail,
# naming the line, the column of the character and the character.
AGENT_COUNT = "(21 agents: 16 deliberately vulnerable"
CATEGORY_COUNT = "variants; 12 vulnerability categories"
INVISIBLE_CHARACTERS = [
    ("U+3164 HANGUL FILLER before the agent count", AGENT_COUNT,
     "(\N{HANGUL FILLER}22 agents: 16 deliberately vulnerable",
     "U+3164 HANGUL FILLER, a Hangul filler"),
    ("U+FFA0 HALFWIDTH HANGUL FILLER before the agent count", AGENT_COUNT,
     "(\N{HALFWIDTH HANGUL FILLER}22 agents: 16 deliberately vulnerable",
     "U+FFA0 HALFWIDTH HANGUL FILLER, a Hangul filler"),
    ("U+115F HANGUL CHOSEONG FILLER after agents", AGENT_COUNT,
     "(22 agents\N{HANGUL CHOSEONG FILLER}: 16 deliberately vulnerable",
     "U+115F HANGUL CHOSEONG FILLER, a Hangul filler"),
    ("U+1160 HANGUL JUNGSEONG FILLER before the category count", CATEGORY_COUNT,
     "variants; \N{HANGUL JUNGSEONG FILLER}13 vulnerability categories",
     "U+1160 HANGUL JUNGSEONG FILLER, a Hangul filler"),
    ("U+00AD SOFT HYPHEN inside agents", AGENT_COUNT,
     "(22 age\N{SOFT HYPHEN}nts: 16 deliberately vulnerable",
     "U+00AD SOFT HYPHEN, a format character"),
    ("U+200B ZERO WIDTH SPACE between the number and the noun", AGENT_COUNT,
     "(22 \N{ZERO WIDTH SPACE}agents: 16 deliberately vulnerable",
     "U+200B ZERO WIDTH SPACE, a format character"),
    ("U+2060 WORD JOINER between the category count and the noun", CATEGORY_COUNT,
     "variants; 13\N{WORD JOINER} vulnerability categories",
     "U+2060 WORD JOINER, a format character"),
    ("U+008B, a control character, inside agents", AGENT_COUNT,
     "(22 age\x8bnts: 16 deliberately vulnerable",
     "U+008B, a control character"),
    ("U+007F, a control character, between the category count and the noun", CATEGORY_COUNT,
     "variants; 13\x7f vulnerability categories",
     "U+007F, a control character"),
    ("U+034F COMBINING GRAPHEME JOINER inside agents", AGENT_COUNT,
     "(22 age\N{COMBINING GRAPHEME JOINER}nts: 16 deliberately vulnerable",
     "U+034F COMBINING GRAPHEME JOINER, a default-ignorable combining mark"),
    ("U+FE0F VARIATION SELECTOR-16 between the number and the noun", AGENT_COUNT,
     "(22\N{VARIATION SELECTOR-16} agents: 16 deliberately vulnerable",
     "U+FE0F VARIATION SELECTOR-16, a default-ignorable combining mark"),
    ("U+180B MONGOLIAN FREE VARIATION SELECTOR ONE before the agent count", AGENT_COUNT,
     "(\N{MONGOLIAN FREE VARIATION SELECTOR ONE}22 agents: 16 deliberately vulnerable",
     "U+180B MONGOLIAN FREE VARIATION SELECTOR ONE, a default-ignorable combining mark"),
    ("U+180F MONGOLIAN FREE VARIATION SELECTOR FOUR inside agents", AGENT_COUNT,
     "(22 age\N{MONGOLIAN FREE VARIATION SELECTOR FOUR}nts: 16 deliberately vulnerable",
     "U+180F MONGOLIAN FREE VARIATION SELECTOR FOUR, a default-ignorable combining mark"),
    ("U+17B4 KHMER VOWEL INHERENT AQ after categories", CATEGORY_COUNT,
     "variants; 13 vulnerability categories\N{KHMER VOWEL INHERENT AQ}",
     "U+17B4 KHMER VOWEL INHERENT AQ, a default-ignorable combining mark"),
    ("U+E0100 VARIATION SELECTOR-17 inside categories", CATEGORY_COUNT,
     "variants; 13 vulnerability categ\N{VARIATION SELECTOR-17}ories",
     "U+E0100 VARIATION SELECTOR-17, a default-ignorable combining mark"),
    ("U+2065, unassigned, inside agents", AGENT_COUNT,
     "(22 age\U00002065nts: 16 deliberately vulnerable",
     "U+2065, an unassigned default-ignorable code point"),
    ("U+FFF8, unassigned, between the number and the noun", AGENT_COUNT,
     "(22\U0000fff8 agents: 16 deliberately vulnerable",
     "U+FFF8, an unassigned default-ignorable code point"),
    ("U+E0000, unassigned, inside categories", CATEGORY_COUNT,
     "variants; 13 vulnerability categ\U000e0000ories",
     "U+E0000, an unassigned default-ignorable code point"),
    ("U+E0FFF, unassigned, between the category count and the noun", CATEGORY_COUNT,
     "variants; 13\U000e0fff vulnerability categories",
     "U+E0FFF, an unassigned default-ignorable code point"),
    ("U+FEFF on a line naming DVAA with the right numbers",
     "environment (21 agents, 12 vulnerability categories)",
     "environment (21 agents,\N{ZERO WIDTH NO-BREAK SPACE} 12 vulnerability categories)",
     "U+FEFF ZERO WIDTH NO-BREAK SPACE, a format character"),
]


@pytest.mark.parametrize("old,new,named", [(o, n, c) for _, o, n, c in INVISIBLE_CHARACTERS],
                         ids=[name for name, _, _, _ in INVISIBLE_CHARACTERS])
def test_a_dvaa_line_carrying_an_invisible_character_is_red(old, new, named):
    td = scratch_tree()
    try:
        mutate_readme(td, old, new)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f"README.md:{line_of(td, new)}:{column_of(td, new, named)}: a line naming DVAA "
                f"carries {named}, which can hide a figure from the DVAA wordings; "
                "remove it") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# Lines that state a matrix.json count once the character is removed. Each case but the
# last hides a count from the check ("8 tac" U+00AD "tics" is not read, and neither is
# U+3164 glued to "62 techniques"), while another statement of the same count still
# matches; the last carries U+200B at the end of a line whose counts are right. Each line
# must fail, naming the line, the column of the character and the character.
COUNT_LINE_CHARACTERS = [
    ("U+00AD SOFT HYPHEN inside tactics", "**61 techniques** across 9 tactics",
     "**61 techniques** across 8 tac\N{SOFT HYPHEN}tics",
     "U+00AD SOFT HYPHEN, a format character"),
    ("U+3164 HANGUL FILLER before the technique count",
     "into 9 tactics and 61 techniques along a kill chain",
     "into 9 tactics and \N{HANGUL FILLER}62 techniques along a kill chain",
     "U+3164 HANGUL FILLER, a Hangul filler"),
    ("U+034F COMBINING GRAPHEME JOINER inside the observed count",
     "16 of the 61 techniques carry real-world evidence",
     "15 of the 61 tech\N{COMBINING GRAPHEME JOINER}niques carry real-world evidence",
     "U+034F COMBINING GRAPHEME JOINER, a default-ignorable combining mark"),
    ("U+007F, a control character, between the class count and the noun",
     "**40 attack classes**", "**41\x7f attack classes**", "U+007F, a control character"),
    ("U+E0080, unassigned, inside techniques",
     "**61 techniques** across 9 tactics", "**62 tech\U000e0080niques** across 9 tactics",
     "U+E0080, an unassigned default-ignorable code point"),
    ("U+00AD SOFT HYPHEN in the only count a line states", "cite, and build upon.",
     "cite, and build upon. It spans 8 tac\N{SOFT HYPHEN}tics.",
     "U+00AD SOFT HYPHEN, a format character"),
    ("U+200B on a line stating the right counts", "and each is marked as such.",
     "and each is marked as such.\N{ZERO WIDTH SPACE}",
     "U+200B ZERO WIDTH SPACE, a format character"),
]


@pytest.mark.parametrize("old,new,named", [(o, n, c) for _, o, n, c in COUNT_LINE_CHARACTERS],
                         ids=[name for name, _, _, _ in COUNT_LINE_CHARACTERS])
def test_a_count_line_carrying_an_invisible_character_is_red(old, new, named):
    td = scratch_tree()
    try:
        mutate_readme(td, old, new)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f"README.md:{line_of(td, new)}:{column_of(td, new, named)}: a line stating a "
                f"matrix.json count carries {named}, which can hide a figure from the count "
                "wordings; remove it") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# A character that fails a line, written inside the name "DVAA". The line contains the
# name once the character is removed, so it names DVAA: its DVAA figures are read and the
# character fails it. Read only where "DVAA" is written unbroken, such a line was not read
# at all and two wrong figures passed.
DVAA_LINK = ("[DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) "
             "| Lab validation environment (21 agents, 12 vulnerability categories)")
NAME_CHARACTERS = [
    ("U+200B ZERO WIDTH SPACE", "DV\N{ZERO WIDTH SPACE}AA",
     "U+200B ZERO WIDTH SPACE, a format character"),
    ("U+00AD SOFT HYPHEN", "D\N{SOFT HYPHEN}VAA", "U+00AD SOFT HYPHEN, a format character"),
    ("U+007F, a control character", "DVA\x7fA", "U+007F, a control character"),
    ("U+FFA0 HALFWIDTH HANGUL FILLER", "DV\N{HALFWIDTH HANGUL FILLER}AA",
     "U+FFA0 HALFWIDTH HANGUL FILLER, a Hangul filler"),
    ("U+034F COMBINING GRAPHEME JOINER", "DVA\N{COMBINING GRAPHEME JOINER}A",
     "U+034F COMBINING GRAPHEME JOINER, a default-ignorable combining mark"),
    ("U+2065, unassigned", "DV\U00002065AA", "U+2065, an unassigned default-ignorable code point"),
]


# A character that fails a line, written where removing it puts a combining mark directly
# after the name. Such a line names DVAA, so its figures are read and the character fails
# it.
JOINING_CHARACTERS = [
    ("U+200B ZERO WIDTH SPACE between the name and U+0301",
     "DVAA\N{ZERO WIDTH SPACE}\N{COMBINING ACUTE ACCENT}",
     "U+200B ZERO WIDTH SPACE, a format character"),
    ("U+200B ZERO WIDTH SPACE between the name and U+20DD in strong emphasis",
     "**DVAA\N{ZERO WIDTH SPACE}\N{COMBINING ENCLOSING CIRCLE}**",
     "U+200B ZERO WIDTH SPACE, a format character"),
]


CHARACTER_CASES = NAME_CHARACTERS + JOINING_CHARACTERS


@pytest.mark.parametrize("name,named", [(n, c) for _, n, c in CHARACTER_CASES],
                         ids=[case for case, _, _ in CHARACTER_CASES])
def test_a_character_inside_the_name_dvaa_leaves_the_line_read(name, named):
    td = scratch_tree()
    try:
        new = (DVAA_LINK.replace("[DVAA]", f"[{name}]")
               .replace("(21 agents, 12 vulnerability", "(22 agents, 13 vulnerability"))
        mutate_readme(td, DVAA_LINK, new)
        line = line_of(td, new)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"README.md:{line}: \"22 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"README.md:{line}: \"13 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
            f"README.md:{line}:{column_of(td, new, named)}: a line naming DVAA carries {named}, "
            "which can hide a figure from the DVAA wordings; remove it",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# The characters Unicode lists as confusable with A, D, V or a run of them that NFKC leaves
# unchanged, each with the letters it reads as. They are written out here apart from the
# checker's table, so that an entry changed there alone goes red.
CONFUSABLE_LETTERS = {
    0x0391: "A", 0x0410: "A", 0x0474: "V", 0x0667: "V", 0x06F7: "V", 0x13A0: "D",
    0x13AA: "A", 0x13D9: "V", 0x142F: "V", 0x15C5: "A", 0x15DE: "D", 0x15EA: "D",
    0x2D38: "V", 0xA4D3: "D", 0xA4E6: "V", 0xA4EE: "A", 0xA6DF: "V", 0xA732: "AA",
    0xA738: "AV", 0xA73A: "AV", 0x102A0: "A", 0x1051D: "V", 0x118A0: "V", 0x16F08: "V",
    0x16F40: "A", 0x1D20D: "V",
}


def confusable_case(code):
    return f"U+{code:04X} {unicodedata.name(chr(code))}"


# The name "DVAA" written with markup, a character reference or a confusable letter inside
# it, each of which a renderer shows as DVAA. Read only where "DVAA" stood in the source
# text once the characters that fail a line were removed, such a line was not read at all
# and two wrong figures passed. Each confusable character stands in place of the letters it
# reads as.
DVAA_URL = "(https://github.com/opena2a-org/damn-vulnerable-ai-agent)"
WRITTEN_NAMES = [
    ("decimal reference to U+200B", f"[DV&#8203;AA]{DVAA_URL}"),
    ("hexadecimal reference to D", f"[&#x44;VAA]{DVAA_URL}"),
    ("named reference to U+200B", f"[DV&ZeroWidthSpace;AA]{DVAA_URL}"),
    ("reference to U+0410", f"[DVA&#x410;]{DVAA_URL}"),
    ("strong emphasis", f"[**DV**AA]{DVAA_URL}"),
    ("strikethrough", f"[~~DV~~AA]{DVAA_URL}"),
    ("code span", f"[`DV`AA]{DVAA_URL}"),
    ("HTML comment", f"[DV<!-- -->AA]{DVAA_URL}"),
    ("HTML tag", f"[<b>DV</b>AA]{DVAA_URL}"),
    ("HTML tag with a quoted attribute", f'[DV<span title="d">AA]{DVAA_URL}'),
    ("self-closing HTML tag", f"[DV<span/>AA]{DVAA_URL}"),
    ("processing instruction", f"[DV<?x?>AA]{DVAA_URL}"),
    ("CDATA section", f"[DV<![CDATA[]]>AA]{DVAA_URL}"),
    ("declaration", f"[DV<!x>AA]{DVAA_URL}"),
    # The comment stands in the link title and ends after the ")" that the link
    # destination pattern would take as the end of the destination.
    ("HTML comment in a link title", f'[DV]{DVAA_URL[:-1]} "<!-- ) -->")AA'),
    ("link text", f"[DV]{DVAA_URL}AA"),
    ("emphasis with underscores", f"[_DV_]{DVAA_URL}AA"),
    # No backslash escape is read: the backslash is removed with the Markdown characters.
    ("backslash before an asterisk", f"[DV\\*AA]{DVAA_URL}"),
    # The "!" of an image is removed, so the name reads "DVAA"; it was kept, and the name
    # read "DV!AA".
    ("image with no alternative text", f"[DV![](x.png)AA]{DVAA_URL}"),
    # A no-break or ideographic space after a tag name, read as ending it, makes a tag of
    # the text to the final ">", which takes "AA" with it. The line is also read with only
    # a space, a tab or "/" ending a tag name: there "<b" and the space are removed with the
    # link title and the name reads "DVAA>".
    ("U+00A0 NO-BREAK SPACE after a tag name in a link title",
     f'[DV]({DVAA_URL[1:-1]} "<b\N{NO-BREAK SPACE}x=")AA>'),
    ("U+3000 IDEOGRAPHIC SPACE after a tag name in a link title",
     f'[DV]({DVAA_URL[1:-1]} "<b\N{IDEOGRAPHIC SPACE}x=")AA>'),
    # In that second reading a space, a tab or "/" after a tag name ends it, so the tag
    # inside the name is removed too.
    ("space after a tag name in the second reading",
     f'[D<b x>V]({DVAA_URL[1:-1]} "<b\N{NO-BREAK SPACE}x=")AA>'),
    ("tab after a tag name in the second reading",
     f'[D<b\tx>V]({DVAA_URL[1:-1]} "<b\N{NO-BREAK SPACE}x=")AA>'),
    ("slash after a tag name in the second reading",
     f'[D<br/>V]({DVAA_URL[1:-1]} "<b\N{NO-BREAK SPACE}x=")AA>'),
    # Read with the no-break space ending the tag name, "<b" U+00A0 "x>" is removed.
    ("U+00A0 NO-BREAK SPACE after a tag name", f"[DV<b\N{NO-BREAK SPACE}x>AA]{DVAA_URL}"),
    # A combining mark after the first "DVAA" leaves the second one read.
    ("U+20DD COMBINING ENCLOSING CIRCLE after a first DVAA",
     f"[DVAA\N{COMBINING ENCLOSING CIRCLE} DVAA]{DVAA_URL}"),
    # A combining mark that stands after markup rather than directly after a letter, and a
    # character reference to a mark, do not count as directly after the name.
    ("U+20DD COMBINING ENCLOSING CIRCLE after strong emphasis",
     f"[DV**AA**\N{COMBINING ENCLOSING CIRCLE}]{DVAA_URL}"),
    ("U+0301 COMBINING ACUTE ACCENT after strong emphasis",
     f"[DV**AA**\N{COMBINING ACUTE ACCENT}]{DVAA_URL}"),
    ("reference to U+20DD after strong emphasis", f"[DV**AA**&#x20dd;]{DVAA_URL}"),
    ("reference to U+20DD after the name", f"[DVAA&#x20dd;]{DVAA_URL}"),
    ("reference to U+20DD after the name in strong emphasis",
     f"[DV**AA&#x20dd;**]{DVAA_URL}"),
    # Such a mark is also kept apart from the name, so that NFKC does not join U+0301 to
    # the last A and read "DVA" U+00C1.
    ("reference to U+0301 after strong emphasis", f"[DV**AA**&#x301;]{DVAA_URL}"),
    ("reference to U+0301 after the name in strong emphasis",
     f"[DV**AA&#x301;**]{DVAA_URL}"),
    ("fullwidth letters",
     "[\N{FULLWIDTH LATIN CAPITAL LETTER D}\N{FULLWIDTH LATIN CAPITAL LETTER V}"
     f"\N{FULLWIDTH LATIN CAPITAL LETTER A}\N{FULLWIDTH LATIN CAPITAL LETTER A}]{DVAA_URL}"),
    ("mathematical bold letters",
     "[\N{MATHEMATICAL BOLD CAPITAL D}\N{MATHEMATICAL BOLD CAPITAL V}"
     f"\N{MATHEMATICAL BOLD CAPITAL A}\N{MATHEMATICAL BOLD CAPITAL A}]{DVAA_URL}"),
] + [
    (confusable_case(code), f"[{'DVAA'.replace(letters, chr(code), 1)}]{DVAA_URL}")
    for code, letters in CONFUSABLE_LETTERS.items() if letters in "DVAA"
]


@pytest.mark.parametrize("written", [w for _, w in WRITTEN_NAMES],
                         ids=[case for case, _ in WRITTEN_NAMES])
def test_a_name_written_with_markup_a_reference_or_a_confusable_letter_leaves_the_line_read(
        written):
    td = scratch_tree()
    try:
        new = (DVAA_LINK.replace(f"[DVAA]{DVAA_URL}", written)
               .replace("(21 agents, 12 vulnerability", "(22 agents, 13 vulnerability"))
        mutate_readme(td, DVAA_LINK, new)
        line = line_of(td, new)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"README.md:{line}: \"22 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"README.md:{line}: \"13 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# The DVAA row of the related-projects table rewritten with "DVAA" in markup beside a
# backtick and two wrong figures: the backtick stands in a link destination, in a link
# title, in each of two table cells, in an autolink, or in an HTML attribute that holds
# "<", and the line ends with another backtick. No code span is read, so each backtick is
# removed with the Markdown characters and the line goes red on both figures.
DVAA_ROW = f"| {DVAA_LINK} |"
BACKTICK_LINES = [
    ("backtick in a link destination",
     f"| [DV]({DVAA_URL[1:-1]}`)AA | Lab validation environment "
     "(99 agents, 77 vulnerability categories) ` |"),
    ("backtick in a link title",
     f'| [DV]({DVAA_URL[1:-1]} "`")AA | Lab validation environment '
     "(99 agents, 77 vulnerability categories) ` |"),
    ("backticks in two table cells",
     "| Lab ` | **DV**AA environment (99 agents, 77 vulnerability categories) ` |"),
    ("backtick in an autolink",
     "| <https://example.org/`> | **DV**AA environment "
     "(99 agents, 77 vulnerability categories) ` |"),
    ("backtick in an HTML attribute that holds <",
     "| <span title='<`'>**DV**AA</span> | Lab validation environment "
     "(99 agents, 77 vulnerability categories) ` |"),
]


@pytest.mark.parametrize("line", [line for _, line in BACKTICK_LINES],
                         ids=[case for case, _ in BACKTICK_LINES])
def test_a_backtick_beside_the_name_dvaa_leaves_the_line_read(line):
    td = scratch_tree()
    try:
        mutate_readme(td, DVAA_ROW, line)
        number = line_of(td, line)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"README.md:{number}: \"99 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"README.md:{number}: \"77 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# Names the check does not read as DVAA: a reference to "*" or "&" shows that character
# rather than marking up text, a letter with an accent is not confusable with A, NFKC
# leaves U+00C1 composed, a comment that no line closes shows as text and runs to the end
# of the line, a character read as letters that do not stand together in "DVAA" shows them
# in another order, "DVAA" directly followed by a combining mark does not name DVAA, and a
# "!" that does not stand before a "[" stays. Such a line does not name DVAA, so its
# figures are not read.
OTHER_NAMES = [
    ("reference to an asterisk", "[DV&#42;AA]"),
    ("reference to an ampersand", "[DV&amp;AA]"),
    ("hyphen", "[DV-AA]"),
    ("U+00C1 LATIN CAPITAL LETTER A WITH ACUTE", "[DV\N{LATIN CAPITAL LETTER A WITH ACUTE}A]"),
    ("U+00C1 LATIN CAPITAL LETTER A WITH ACUTE for the last A",
     "[DVA\N{LATIN CAPITAL LETTER A WITH ACUTE}]"),
    ("comment opened in a link destination that no line closes", "[DV](x <!-- y)AA"),
    ("U+0301 COMBINING ACUTE ACCENT after the name", "[DVAA\N{COMBINING ACUTE ACCENT}]"),
    ("U+0301 COMBINING ACUTE ACCENT after U+0410",
     "[DVA\N{CYRILLIC CAPITAL LETTER A}\N{COMBINING ACUTE ACCENT}]"),
    ("U+20DD COMBINING ENCLOSING CIRCLE after the name", "[DVAA\N{COMBINING ENCLOSING CIRCLE}]"),
    ("exclamation mark", "[DV!AA]"),
] + [
    (confusable_case(code), f"[D{chr(code)}A]")
    for code, letters in CONFUSABLE_LETTERS.items() if letters not in "DVAA"
]


@pytest.mark.parametrize("written", [w for _, w in OTHER_NAMES],
                         ids=[case for case, _ in OTHER_NAMES])
def test_a_name_that_shows_as_another_name_does_not_name_dvaa(written):
    td = scratch_tree()
    try:
        new = (DVAA_LINK.replace("[DVAA]", written)
               .replace("(21 agents, 12 vulnerability", "(22 agents, 13 vulnerability"))
        mutate_readme(td, DVAA_LINK, new)
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


def test_each_confusable_reads_as_a_run_of_dvaa_letters_and_is_left_by_nfkc():
    # The table holds only what NFKC leaves unchanged; NFKC maps the fullwidth and
    # mathematical letters itself.
    checker = load_checker()
    for code, letters in checker.CONFUSABLES.items():
        assert unicodedata.normalize("NFKC", chr(code)) == chr(code), f"U+{code:04X}"
        assert letters and set(letters) <= set("ADV"), f"U+{code:04X}"


def test_each_confusable_reads_as_the_letters_written_out_here():
    # Checked only for being a run of A, D and V, an entry could be changed to other such
    # letters (U+13A0 from D to A) with every test passing.
    assert load_checker().CONFUSABLES == CONFUSABLE_LETTERS


# A line that names DVAA only once markup is removed, a reference is decoded or a confusable
# letter is read, with U+00AD inside "agents". The character keeps "21 agents" from being
# read, and it must fail the line by the name the line reads as, not only where "DVAA"
# stands unbroken.
NAMES_READ_BY_THE_STEPS = [
    ("strong emphasis", "[**DV**AA]"),
    ("decimal reference to U+200B", "[DV&#8203;AA]"),
    ("U+0410 CYRILLIC CAPITAL LETTER A", "[DVA\N{CYRILLIC CAPITAL LETTER A}]"),
]


@pytest.mark.parametrize("written", [w for _, w in NAMES_READ_BY_THE_STEPS],
                         ids=[case for case, _ in NAMES_READ_BY_THE_STEPS])
def test_a_character_fails_a_line_that_names_dvaa_only_by_the_steps(written):
    td = scratch_tree()
    try:
        new = (DVAA_LINK.replace("[DVAA]", written)
               .replace("(21 agents,", "(21 age\N{SOFT HYPHEN}nts,"))
        mutate_readme(td, DVAA_LINK, new)
        named = "U+00AD SOFT HYPHEN, a format character"
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f"README.md:{line_of(td, new)}:{column_of(td, new, named)}: a line naming DVAA "
                f"carries {named}, which can hide a figure from the DVAA wordings; "
                "remove it") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# What a line reads as, where each case turns on one part of the three steps README
# states: the HTML is removed before the link spans, each kind of HTML is removed, closed
# or running to the end of the line, a tag ends after a quoted attribute, U+00A0 or "/",
# the "][...]" span goes as the "](...)" span does whether or not a link is made, a "!"
# goes where it stands before a "[" once the link spans are removed and stays elsewhere,
# "_" is removed, a reference that fails a line leaves nothing, a reference to "*" shows
# it, and NFKC composes a mark with the letter before it.
NAME_FORMS = [
    ("HTML before the link spans", '[DV](url "<!-- ) -->")AA', "DVAA"),
    ("tag with a quoted attribute", 'DV<span title="x">AA', "DVAA"),
    ("tag with U+00A0 after its name", "DV<span\N{NO-BREAK SPACE}title=x>AA", "DVAA"),
    ("tag with / after its name", "DV<span/>AA", "DVAA"),
    ("processing instruction", "DV<?x?>AA", "DVAA"),
    ("CDATA section", "DV<![CDATA[x]]>AA", "DVAA"),
    ("declaration", "DV<!x>AA", "DVAA"),
    ("comment no close follows", "DV<!-- AA", "DV"),
    ("processing instruction no close follows", "DV<? AA", "DV"),
    ("CDATA section no close follows", "DV<![CDATA[ AA", "DV"),
    ("declaration no close follows", "DV<!X AA", "DV"),
    ("tag whose quote does not close", '<b x=")AA>', ""),
    ("closing tag with text after its name", '</b ")AA>', ""),
    ("reference label", "[DV][dvaa]AA", "DVAA"),
    ("link span that makes no link", "[x](see **DV**AA)", "x"),
    ("image", "DV![](x.png)AA", "DVAA"),
    ("exclamation mark before a link span", "DV!](x)[A]A", "DVAA"),
    ("exclamation mark not before a [", "DV!AA", "DV!AA"),
    ("underscores", "_DV_AA", "DVAA"),
    ("reference to U+200B", "DV&#8203;AA", "DVAA"),
    ("reference to an asterisk", "DV&#42;AA", "DV*AA"),
    ("combining mark after the last A", "DVAA\N{COMBINING ACUTE ACCENT}",
     "DVA\N{LATIN CAPITAL LETTER A WITH ACUTE}"),
]


@pytest.mark.parametrize("text,form", [(t, f) for _, t, f in NAME_FORMS],
                         ids=[case for case, _, _ in NAME_FORMS])
def test_each_step_reads_a_line_as_stated(text, form):
    checker = load_checker()
    assert checker.name_form(text) == form
    assert stated_name_form(checker, text) == form


TAG_NAME = string.ascii_letters + string.digits + "-"


def ascii_letter_at(text, i):
    return i < len(text) and text[i] in string.ascii_letters


def stated_html_end(line, i, any_space=True):
    """Where the HTML that README states starts at the "<" at line[i] ends, or None. With
    `any_space` false, as in the second reading README states where white space other than
    a space or tab follows a tag name, only a space, a tab or "/" lets a tag run on past
    its name to a ">"."""
    for opening, close in (("<!--", "-->"), ("<?", "?>"), ("<![CDATA[", "]]>")):
        if line.startswith(opening, i):
            end = line.find(close, i + len(opening))
            return len(line) if end < 0 else end + len(close)
    if line.startswith("<!", i) and ascii_letter_at(line, i + 2):
        end = line.find(">", i + 3)
        return len(line) if end < 0 else end + 1
    j = i + 2 if line.startswith("</", i) else i + 1
    if not ascii_letter_at(line, j):
        return None
    while j < len(line) and line[j] in TAG_NAME:
        j += 1
    if j < len(line) and line[j] == ">":
        return j + 1
    if j < len(line) and (line[j] == "/" or (line[j].isspace() if any_space
                                              else line[j] in " \t")):
        for k in range(j + 1, len(line)):
            if line[k] in "<>":
                return k + 1 if line[k] == ">" else None
    return None


def stated_reference_end(text, i):
    """Where the character reference CommonMark reads at the "&" at text[i] ends, or None."""
    end = text.find(";", i)
    if end < 0:
        return None
    body = text[i + 1:end]
    if body.startswith(("#x", "#X")):
        number, digits, most = body[2:], string.hexdigits, 6
    elif body.startswith("#"):
        number, digits, most = body[1:], string.digits, 7
    else:
        return end + 1 if f"{body};" in html.entities.html5 else None
    return end + 1 if 0 < len(number) <= most and all(c in digits for c in number) else None


def stated_name_form(checker, line, any_space=True):
    """`line` read by the three steps README states, as a plain scan rather than with the
    checker's patterns, and with `any_space` false as in the second reading. A reference is
    decoded by html.unescape, as in the checker, and a decoded character that fails a line
    is dropped."""
    # First, going along the line, its HTML is removed wherever it stands.
    kept, i = [], 0
    while i < len(line):
        end = stated_html_end(line, i, any_space) if line[i] == "<" else None
        if end is None:
            kept.append(line[i])
            i += 1
        else:
            i = end
    text = "".join(kept)
    # Second, going along what remains, each "]" followed by "(" or "[" goes with the text
    # after it to the first ")" or "]" if no further "(" or "[" comes first, then each "!"
    # directly before a "[", and then the Markdown characters.
    kept, i = [], 0
    while i < len(text):
        if text[i] == "]" and text[i + 1:i + 2] in ("(", "["):
            opening = text[i + 1]
            close = ")" if opening == "(" else "]"
            j = i + 2
            while j < len(text) and text[j] not in (opening, close):
                j += 1
            if j < len(text) and text[j] == close:
                i = j + 1
                continue
        kept.append(text[i])
        i += 1
    kept = [c for k, c in enumerate(kept) if c != "!" or kept[k + 1:k + 2] != ["["]]
    text = "".join(c for c in kept if c not in "*_~`\\[]")
    # Third, its character references are decoded, less the characters that fail a line,
    # and it is brought to NFKC with each confusable character read as its letters.
    kept, i = [], 0
    while i < len(text):
        end = stated_reference_end(text, i) if text[i] == "&" else None
        if end is None:
            kept.append(text[i])
            i += 1
        else:
            kept.extend(c for c in html.unescape(text[i:end]) if not checker.hiding_kind(c))
            i = end
    return unicodedata.normalize("NFKC", "".join(kept)).translate(CONFUSABLE_LETTERS)


# The generated lines are made of characters the first two steps act on and, for two
# pieces in five, of longer pieces: the openings and closes of HTML, character references,
# white space other than a space, and characters NFKC or the confusables read as A, D or V
# or leave beside them. With these, each pattern alternative and each step, changed or
# taken out of order, reads at least 30 of the 200,000 lines differently, with three
# exceptions a case above also pins: removing each "!" before the link spans rather than
# after them reads 2 lines differently ("exclamation mark before a link span"), and in
# the second reading letting only a space and "/" end a tag name reads 13 differently
# ("tab after a tag name in the second reading") and letting only a space and a tab end
# it reads 22 differently ("slash after a tag name in the second reading").
MARKUP_CHARACTERS = "[]()DVAx \"*_~`\\<>"
PIECES = [
    *"/-!?=1&#;\t", "<x", "</A", "<!--", "-->", "<?", "?>", "<![CDATA[", "]]>", "<!",
    "&#68;", "&#x41;", "&#8203;", "&DD;", "&amp;", "&ast;", "&lowbar;",
    "\N{NO-BREAK SPACE}", "\N{IDEOGRAPHIC SPACE}", "\N{COMBINING ACUTE ACCENT}",
    "\N{LATIN CAPITAL LETTER A WITH ACUTE}", "\N{CYRILLIC CAPITAL LETTER A}",
    "\N{FULLWIDTH LATIN CAPITAL LETTER A}", "\N{LATIN CAPITAL LETTER AV}",
    "\N{CHEROKEE LETTER A}",
]
STATED_LINES = 200_000


def generated_line(rng):
    return "".join(rng.choice(PIECES) if rng.random() < 0.4 else rng.choice(MARKUP_CHARACTERS)
                   for _ in range(rng.randint(1, 16)))


def test_the_stated_steps_read_every_generated_line_as_the_checker_does():
    # README, the script's description and the changelog state the steps in words, and the
    # checker takes them with three patterns; a step that drifted from its pattern used to
    # leave every test passing. Any line the two read differently names the step. A line
    # with white space other than a space or tab is also read the second way README states,
    # with only a space, a tab or "/" ending a tag name; on any other line the two ways
    # remove the same HTML.
    checker = load_checker()
    rng = random.Random(80)
    for _ in range(STATED_LINES):
        line = generated_line(rng)
        assert checker.name_form(line) == stated_name_form(checker, line), ascii(line)
        if any(c.isspace() and c not in " \t" for c in line):
            assert (checker.name_form(line, checker.SPACE_OR_TAB_HTML)
                    == stated_name_form(checker, line, any_space=False)), ascii(line)


def test_nfkc_gives_what_unicodedata_normalize_gives():
    # nfkc puts each run of combining characters in order itself. The pieces hold marks of
    # several combining classes, U+0344 COMBINING GREEK DIALYTIKA TONOS, which decomposes
    # into two marks, U+0F73 TIBETAN VOWEL SIGN II, a starter that decomposes into two marks,
    # U+09BE and U+0B3E, the Bengali and Oriya vowel signs AA, starters that compose with the
    # vowel sign before them, Hangul jamo and a syllable, and compatibility characters. Each
    # is written as an escape: saved in NFC, U+0344, U+0F73 and U+2126 OHM SIGN written raw
    # become other characters, and U+00A0 and U+3000 read as the space beside them.
    checker = load_checker()
    pieces = [
        *"AaeouDVx ",
        "\N{COMBINING ACUTE ACCENT}", "\N{COMBINING GRAVE ACCENT BELOW}",
        "\N{COMBINING DIAERESIS}", "\N{COMBINING DOT BELOW}",
        "\N{COMBINING GREEK DIALYTIKA TONOS}", "\N{HEBREW POINT SHEVA}",
        "\N{HEBREW POINT DAGESH OR MAPIQ}", "\N{DEVANAGARI SIGN NUKTA}",
        "\N{DEVANAGARI SIGN VIRAMA}", "\N{TIBETAN VOWEL SIGN AA}", "\N{TIBETAN VOWEL SIGN I}",
        "\N{TIBETAN VOWEL SIGN II}", "\N{TIBETAN VOWEL SIGN REVERSED I}",
        "\N{COMBINING ENCLOSING CIRCLE}", "\U0001d165", "\U0001d16d",
        "\N{BENGALI VOWEL SIGN E}", "\N{BENGALI VOWEL SIGN AA}", "\N{ORIYA VOWEL SIGN E}",
        "\N{ORIYA VOWEL SIGN AA}", "\N{HANGUL CHOSEONG KIYEOK}", "\N{HANGUL JUNGSEONG A}",
        "\N{HANGUL JONGSEONG KIYEOK}", "\N{HANGUL SYLLABLE GA}",
        "\N{LATIN CAPITAL LETTER A WITH ACUTE}", "\N{LATIN SMALL LETTER LONG S WITH DOT ABOVE}",
        "\N{OHM SIGN}", "\N{LATIN SMALL LIGATURE FFI}", "\N{FULLWIDTH LATIN CAPITAL LETTER A}",
        "\N{IDEOGRAPHIC SPACE}", "\N{NO-BREAK SPACE}", "\N{CYRILLIC CAPITAL LETTER A}",
    ]
    rng = random.Random(80)
    for _ in range(50_000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
        assert checker.nfkc(text) == unicodedata.normalize("NFKC", text), ascii(text)


# nfkc puts a run of combining marks in order where the run ends: at the starter that follows
# it, or after its loop when the run ends the text. Each case times one of the two. Timed on
# the marks alone, only the second was, and the first could go back to moving one mark at a
# time with every test passing. Between the two starters, "A" composes with one U+0301: once
# in order, only marks of a lower combining class stand between them.
MARK_PAIRS = 100_000
OUT_OF_ORDER = "\N{COMBINING ACUTE ACCENT}\N{COMBINING GRAVE ACCENT BELOW}" * MARK_PAIRS
LONG_MARK_RUNS = [
    ("a run that ends the text", OUT_OF_ORDER,
     "\N{COMBINING GRAVE ACCENT BELOW}" * MARK_PAIRS + "\N{COMBINING ACUTE ACCENT}" * MARK_PAIRS),
    ("a run between two starters", "A" + OUT_OF_ORDER + "B",
     "\N{LATIN CAPITAL LETTER A WITH ACUTE}" + "\N{COMBINING GRAVE ACCENT BELOW}" * MARK_PAIRS
     + "\N{COMBINING ACUTE ACCENT}" * (MARK_PAIRS - 1) + "B"),
]


@pytest.mark.parametrize("text,form", [(t, f) for _, t, f in LONG_MARK_RUNS],
                         ids=[name for name, _, _ in LONG_MARK_RUNS])
def test_name_form_reads_a_long_run_of_combining_marks_in_n_log_n_time(text, form):
    # unicodedata.normalize puts a run of combining marks in order by moving one mark at a
    # time: in name_form, U+0301 U+0316 repeated to 100,000 characters took about 2 s on
    # Python 3.14 and 200,000 about four times as long. Put in order by a sort first,
    # 200,000 take a few hundredths of a second.
    checker = load_checker()
    start = time.perf_counter()
    read = checker.name_form(text)
    seconds = time.perf_counter() - start
    assert read == form
    assert seconds < 1, f"{seconds:.2f} s"


def test_names_reads_a_long_run_of_combining_marks_after_the_name_in_linear_time():
    # names decomposes each name form with unicodedata.normalize("NFKD"), which puts a run of
    # combining marks in order by moving one mark at a time. It is linear only because nfkc
    # has already put the form in order: on this line, U+0301 U+0316 repeated 100,000 times
    # took about 0.3 s on Python 3.14 and 400,000 about 1 s. Decomposed as written, out of
    # order, the run took about 2 s at 50,000 and about four times as long at each doubling.
    # The no-break space after "<b" adds the second reading, and the form holds the name only
    # once decomposed, as "A" composes with one U+0301, so the line is read with every step.
    checker = load_checker()
    line = "<b\N{NO-BREAK SPACE} DVAA" + OUT_OF_ORDER
    start = time.perf_counter()
    named = checker.names(line, "DVAA")
    seconds = time.perf_counter() - start
    assert not named
    assert seconds < 3, f"{seconds:.2f} s"


def test_a_mark_after_markup_or_written_as_a_reference_is_put_apart():
    checker = load_checker()
    assert checker.name_form("DV![](x.png)AA") == "DVAA"
    assert checker.detached("DV**AA**\N{COMBINING ENCLOSING CIRCLE}") == (
        "DV**AA**" + checker.BREAK + "\N{COMBINING ENCLOSING CIRCLE}")
    assert checker.detached("DVAA&#x20dd;") == "DVAA" + checker.BREAK + "&#x20dd;"
    for attached in ("DVAA\N{COMBINING ENCLOSING CIRCLE}",
                     "DVAA\N{COMBINING ACUTE ACCENT}\N{COMBINING ENCLOSING CIRCLE}",
                     "DVA\N{CYRILLIC CAPITAL LETTER A}\N{COMBINING ACUTE ACCENT}",
                     "DVAA&#65;"):
        assert checker.detached(attached) == attached
    # No ASCII character is a combining mark, so none after the name needs a lookup.
    assert not any(checker.is_mark(code) for code in range(128))


def test_a_line_naming_dvaa_and_stating_a_count_names_both():
    td = scratch_tree()
    try:
        new = "environment (21 agents, 12 vulnerability categories; 9\N{ZERO WIDTH SPACE} tactics)"
        mutate_readme(td, "environment (21 agents, 12 vulnerability categories)", new)
        named = "U+200B ZERO WIDTH SPACE, a format character"
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f"README.md:{line_of(td, new)}:{column_of(td, new, named)}: a line naming DVAA "
                f"and stating a matrix.json count carries {named}, which can hide a figure from "
                "the DVAA and count wordings; remove it") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_character_repeated_on_a_line_fails_it_once():
    # One failure line per character per line, at the column of its first occurrence.
    td = scratch_tree()
    try:
        new = ("environment\N{ZERO WIDTH SPACE} (21 agents,\N{SOFT HYPHEN} 12\N{ZERO WIDTH SPACE} "
               "vulnerability categories)")
        mutate_readme(td, "environment (21 agents, 12 vulnerability categories)", new)
        line = line_of(td, new)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        on_line = [f for f in r.stderr.split("\n") if f.startswith(f"  - README.md:{line}:")]
        assert on_line == [
            f"  - README.md:{line}:{column_of(td, new, named)}: a line naming DVAA carries "
            f"{named}, which can hide a figure from the DVAA wordings; remove it"
            for named in ("U+200B ZERO WIDTH SPACE, a format character",
                          "U+00AD SOFT HYPHEN, a format character")
        ], r.stderr
    finally:
        shutil.rmtree(td)


# A tab is the one control character that does not fail a line: it renders as space.
TABS = [
    ("on a line naming DVAA", "environment (21 agents, 12 vulnerability categories)",
     "environment\t(21 agents, 12 vulnerability categories)"),
    ("on a line stating a count", "**61 techniques** across 9 tactics",
     "**61 techniques**\tacross 9 tactics"),
]


@pytest.mark.parametrize("old,new", [(o, n) for _, o, n in TABS], ids=[name for name, _, _ in TABS])
def test_a_tab_does_not_fail_a_line(old, new):
    td = scratch_tree()
    try:
        mutate_readme(td, old, new)
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


def test_an_invisible_character_on_a_line_naming_neither_dvaa_nor_a_count_passes():
    td = scratch_tree()
    try:
        mutate_readme(td, "Apache-2.0. The framework is free to use, cite, and build upon.",
                      "Apache-2.0. The framework is free to use,\N{ZERO WIDTH SPACE} cite, "
                      "and build upon.")
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_wording_beside_punctuation_is_still_read():
    # The Unicode word boundary still holds at the punctuation README puts around a figure.
    td = scratch_tree()
    try:
        mutate_readme(td, "(21 agents: 16 deliberately vulnerable",
                      "(22 agents: 16 deliberately vulnerable")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert "related-projects.json (DVAA agents: 21)" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_wording_a_space_away_from_a_combining_mark_is_still_read():
    # Only a combining mark directly beside the wording glues it; a space still bounds it.
    td = scratch_tree()
    try:
        mutate_readme(td, "(21 agents: 16 deliberately vulnerable",
                      "(e\N{COMBINING ACUTE ACCENT} 22 agents: 16 deliberately vulnerable")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert "related-projects.json (DVAA agents: 21)" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_wording_at_the_start_of_the_readme_is_read_beside_a_final_combining_mark():
    # The character before a wording at offset 0 is no character, not the last one in
    # the README: a combining mark ending the README does not glue the first wording.
    td = scratch_tree()
    try:
        readme = td / "README.md"
        text = readme.read_text(encoding="utf-8").rstrip("\n")
        readme.write_text(f"22 agents in DVAA\n{text}\nDVAA\N{COMBINING ACUTE ACCENT}",
                          encoding="utf-8")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert ('README.md:1: "22 agents" does not match related-projects.json '
                "(DVAA agents: 21)") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_shorter_categories_wording_at_the_same_start_is_read_when_the_longer_is_glued():
    # "N categories" allows up to two words before the noun, so one start position can
    # match at several lengths. A combining mark glued to the longest, "13 categories x
    # categories", must not hide the shorter "13 categories" at the same start.
    td = scratch_tree()
    try:
        readme = td / "README.md"
        text = readme.read_text(encoding="utf-8").rstrip("\n") + "\n"
        readme.write_text(f"{text}DVAA: 13 categories x categories\N{COMBINING ACUTE ACCENT}\n",
                          encoding="utf-8")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        line = text.count("\n") + 1
        assert (f'README.md:{line}: "13 categories" does not match related-projects.json '
                "(DVAA vulnerability categories: 12)") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# Runs the checker in-process with unicodedata.category counted, then prints the count.
COUNT_CATEGORY_CALLS = """
import importlib.util, sys, unicodedata
calls = 0
category = unicodedata.category
def counted(c):
    global calls
    calls += 1
    return category(c)
unicodedata.category = counted
spec = importlib.util.spec_from_file_location("check_readme_claims", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
status = module.main([])
print(f"status={status} calls={calls}")
"""


@pytest.mark.parametrize("old, new", [
    (None, None),
    # Three combining marks on a line naming DVAA: U+0301 and U+0308 stand in the run
    # U+0300 to U+036F, which is walked once, and U+20DD in the run U+20D0 to U+20F0.
    ("The DVAA figures are pinned in",
     "The DVAA figures (Jose\N{COMBINING ACUTE ACCENT}, Mo\N{COMBINING DIAERESIS}bius, "
     "O\N{COMBINING ENCLOSING CIRCLE}) are pinned in"),
])
def test_the_check_reads_the_categories_of_readme_characters_only(old, new):
    # The combining-mark test used to rebuild a character class from all 1,114,112 code
    # points on every run. The check now looks up the category of each README character
    # outside the line breaks once, to find the characters that fail a line, and of each
    # distinct character of the text of the lines naming DVAA, line break included, once
    # more, to build the combining-mark class. Walking each run of consecutive combining
    # marks that holds a mark of that text, to find where the run ends, it then looks up
    # every code point of the run but the mark it starts from, and the code point on either
    # side of the run. The budget is that sum, so a second lookup of every README character
    # fails the test.
    # The lookups that find the characters that fail a line also decide which lines name
    # DVAA once the characters they find are removed.
    td = scratch_tree()
    try:
        if old is not None:
            mutate_readme(td, old, new)
        r = subprocess.run(["python3", "-c", COUNT_CATEGORY_CALLS,
                            str(td / "scripts" / "check_readme_claims.py")],
                           capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, r.stderr
        last = r.stdout.strip().splitlines()[-1]
        assert last.startswith("status=0 calls="), r.stdout
        calls = int(last.rsplit("=", 1)[1])
        text = (td / "README.md").read_text(encoding="utf-8")
        dvaa_text = "\n".join(line if "DVAA" in line else "" for line in text.split("\n"))
        marks = {ord(c) for c in dvaa_text if unicodedata.category(c).startswith("M")}
        walked = [(lo, hi) for lo, hi in mark_runs() if any(lo <= code <= hi for code in marks)]
        budget = (len(text) - text.count("\n") + len(set(dvaa_text))
                  + sum(hi - lo + 2 for lo, hi in walked))
        assert calls <= budget, f"{last}, budget {budget}"
    finally:
        shutil.rmtree(td)


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "check_readme_claims", ROOT / "scripts" / "check_readme_claims.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mark_runs():
    """Every run of consecutive combining marks (category M), as (first, last) code points."""
    runs = []
    for code in range(sys.maxunicode + 1):
        if unicodedata.category(chr(code)).startswith("M"):
            if runs and runs[-1][1] == code - 1:
                runs[-1][1] = code
            else:
                runs.append([code, code])
    return [tuple(run) for run in runs]


def class_ranges(body):
    """The (first, last) code points of a class body written as \\U ranges only."""
    pairs = re.findall(r"\\U([0-9a-f]{8})-\\U([0-9a-f]{8})", body)
    assert "".join(f"\\U{lo}-\\U{hi}" for lo, hi in pairs) == body, ascii(body[:40])
    return [(int(lo, 16), int(hi, 16)) for lo, hi in pairs]


def test_the_combining_mark_class_holds_one_range_per_run_of_marks():
    # Listed one by one, each combining mark outside the Basic Multilingual Plane is a
    # separate entry that every test of the class walks, so a DVAA line carrying many of
    # them slowed matching past a table of every mark. The class holds each run of
    # consecutive marks that has a mark in the text as one range instead.
    checker = load_checker()
    runs = mark_runs()
    every_mark = "".join(chr(code) for lo, hi in runs for code in range(lo, hi + 1))
    assert class_ranges(checker.combining_marks_in(every_mark)) == runs
    # Marks scattered over a run, with other characters between them, still take one range.
    some = runs[::7]
    scattered = "DVAA " + " ".join(f"{chr(lo)}x{chr(hi)}" for lo, hi in some)
    assert class_ranges(checker.combining_marks_in(scattered)) == some
    assert checker.combining_marks_in("DVAA: 21 agents") == ""


# The Default_Ignorable_Code_Point ranges of Unicode 16.0 (DerivedCoreProperties.txt).
DEFAULT_IGNORABLE = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)


def test_every_default_ignorable_code_point_fails_a_line():
    # A renderer may draw each as nothing, so each, assigned or not, is a character that
    # fails a line naming DVAA or stating a count.
    checker = load_checker()
    unnamed = [f"U+{code:04X}" for low, high in DEFAULT_IGNORABLE
               for code in range(low, high + 1) if not checker.hiding_kind(chr(code))]
    assert unnamed == [], unnamed


def test_a_value_outside_the_code_point_range_is_no_mark():
    # The walk over a run of marks steps to the code point on either side of it. U+0000
    # (Cc) and U+10FFFF (Cn) are no marks, so the walk never leaves the code point range,
    # but is_mark answers for any integer instead of raising from chr().
    checker = load_checker()
    assert checker.is_mark(-1) is False
    assert checker.is_mark(sys.maxunicode + 1) is False
    assert checker.is_mark(0) is False
    assert checker.is_mark(sys.maxunicode) is False
    assert checker.is_mark(0x0301) is True


def source_lines():
    """(path from the repository root, line number, line) for each line of scripts/*.py and
    tests/*.py."""
    for path in sorted([*ROOT.glob("scripts/*.py"), *ROOT.glob("tests/*.py")]):
        for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            yield path.relative_to(ROOT), number, line


def written_raw(named):
    """`file:line:column: U+XXXX` for each character of scripts/*.py and tests/*.py that
    `named` holds for."""
    return [f"{path}:{number}:{column}: U+{ord(c):04X}"
            for path, number, line in source_lines()
            for column, c in enumerate(line, 1) if named(c)]


def test_the_scripts_and_tests_write_each_character_that_fails_a_line_as_an_escape():
    # Written raw, such a character reads as plain text in an editor or a diff: "DV" U+2065
    # "AA" in the cases inside the name read as "DVAA". Each is written as an escape
    # (\N{...}, \x or \U) instead.
    checker = load_checker()
    raw = written_raw(checker.hiding_kind)
    assert raw == [], raw


def reads_as_name_letters(c):
    """Whether `c`, a character outside ASCII, reads as A, D, V or a run of them in a name:
    it is a key of the confusables table, or NFKC maps it to such letters or to such a key,
    as it does U+FF21 FULLWIDTH LATIN CAPITAL LETTER A and U+1D6A8 MATHEMATICAL BOLD CAPITAL
    ALPHA."""
    form = unicodedata.normalize("NFKC", c).translate(CONFUSABLE_LETTERS)
    return not c.isascii() and form != "" and set(form) <= set("ADV")


def test_the_scripts_and_tests_write_each_letter_read_as_a_d_or_v_as_an_escape():
    # Written raw, U+0410 CYRILLIC CAPITAL LETTER A looks like the Latin A in an editor or a
    # diff, so a case that holds it reads as one that holds "A". Only a character that fails
    # a line had to be an escape, so that letter written raw in the nfkc comparison left
    # every test passing.
    read = ["\N{CYRILLIC CAPITAL LETTER A}", "\N{LATIN CAPITAL LETTER AV}",
            "\N{FULLWIDTH LATIN CAPITAL LETTER A}", "\N{ROMAN NUMERAL FIVE}",
            "\N{MATHEMATICAL BOLD CAPITAL ALPHA}"]
    assert [ascii(c) for c in read if not reads_as_name_letters(c)] == []
    others = [*"ADVa", "\N{LATIN CAPITAL LETTER A WITH ACUTE}", "\N{ROMAN NUMERAL SIX}"]
    assert [ascii(c) for c in others if reads_as_name_letters(c)] == []
    raw = written_raw(reads_as_name_letters)
    assert raw == [], raw


def test_the_scripts_and_tests_write_each_space_other_than_u_0020_as_an_escape():
    # Written raw, U+00A0 NO-BREAK SPACE and U+3000 IDEOGRAPHIC SPACE read as the space
    # beside them in an editor or a diff. Each separator (category Zs, Zl or Zp) other than
    # U+0020 is written as an escape instead.
    raw = written_raw(lambda c: c != " " and unicodedata.category(c).startswith("Z"))
    assert raw == [], raw


def test_the_scripts_and_tests_are_unchanged_by_nfc():
    # An editor or tool that saves a file in NFC turns U+0344 into U+0308 U+0301, U+0F73
    # into U+0F71 U+0F72, U+2126 OHM SIGN into U+03A9, U+212A KELVIN SIGN into "K" and "e"
    # U+0301 into U+00E9 with no visible change, after which a case no longer holds the
    # character it names. Each character NFC changes where it stands is written as an
    # escape instead. A line that fails is given with the column where NFC first changes it.
    changed = []
    for path, number, line in source_lines():
        composed = unicodedata.normalize("NFC", line)
        if composed != line:
            column = next(i for i, (a, b) in enumerate(zip(line, composed), 1) if a != b)
            changed.append(f"{path}:{number}:{column}")
    assert changed == [], changed


def test_the_dvaa_category_count_must_be_stated():
    td = scratch_tree()
    try:
        mutate_readme(td, "variants; 12 vulnerability categories",
                      "variants; 12 vulnerability classes")
        mutate_readme(td, "environment (21 agents, 12 vulnerability categories)",
                      "environment (21 agents, 12 vulnerability classes)")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert "README does not state DVAA vulnerability categories (12)" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_dvaa_figures_are_only_read_from_lines_naming_dvaa():
    td = scratch_tree()
    try:
        mutate_readme(td, "Apache-2.0. The framework is free to use, cite, and build upon.",
                      "Apache-2.0. The framework is free to use, cite, and build upon. "
                      "A team running 3 agents can cite it.")
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


def test_readme_describes_every_class_as_matrix_json_does():
    matrix = json.loads((ROOT / "matrix.json").read_text(encoding="utf-8"))
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    block = text[text.index(BEGIN):text.index(END)]
    missing = []
    for cls in matrix["attackClasses"]:
        cell = cls["description"].replace(" — ", ": ").replace("|", "\\|")
        if f"| [{cls['id']}](attack-classes/{cls['id']}.md) | {cell} |" not in block:
            missing.append(cls["id"])
    assert missing == [], f"README rows not matching matrix.json: {missing}"


def test_a_reworded_class_description_is_red():
    td = scratch_tree()
    try:
        mutate_readme(td, f"| {GATEWAY_DESCRIPTION} |",
                      "| Misconfigured API gateways exposing agent infrastructure |")
        text = (td / "README.md").read_text(encoding="utf-8")
        line = text[:text.index("Misconfigured API gateways")].count("\n") + 1
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert f"README.md:{line}: the attack-class tables differ from matrix.json" in r.stderr, \
            r.stderr
    finally:
        shutil.rmtree(td)


def test_a_class_changed_in_matrix_json_is_red_until_fixed():
    td = scratch_tree()
    try:
        path = td / "matrix.json"
        matrix = json.loads(path.read_text(encoding="utf-8"))
        for cls in matrix["attackClasses"]:
            if cls["id"] == "GATEWAY-EXPLOIT":
                cls["description"] = "Rewritten in the data — with a pipe a|b"
        path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")
        before = (td / "README.md").read_text(encoding="utf-8")

        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert "the attack-class tables differ from matrix.json" in r.stderr, r.stderr

        r = run_checker(td, "--fix")
        assert r.returncode == 0, r.stderr
        assert "FIXED: rewrote the attack-class tables" in r.stdout
        after = (td / "README.md").read_text(encoding="utf-8")
        assert "| Rewritten in the data: with a pipe a\\|b |" in after
        assert GATEWAY_DESCRIPTION not in after
        # Only the generated block moved.
        assert after[:after.index(BEGIN)] == before[:before.index(BEGIN)]
        assert after[after.index(END):] == before[before.index(END):]

        r = run_checker(td, "--fix")
        assert r.returncode == 0, r.stderr
        assert "OK: attack-class tables already current" in r.stdout
    finally:
        shutil.rmtree(td)


@pytest.mark.parametrize("marker", [BEGIN, END])
def test_a_missing_class_table_marker_is_red(marker):
    td = scratch_tree()
    try:
        mutate_readme(td, marker, "")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert "the attack-class tables need exactly one" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


@pytest.mark.parametrize("args,status,unknown", [
    (["--bogus"], 2, "--bogus"),
    (["--fixx"], 2, "--fixx"),
    (["--fi"], 2, "--fi"),
    (["fix"], 2, "fix"),
    (["--fix", "--bogus"], 2, "--bogus"),
    (["--help"], 0, None),
    (["-h"], 0, None),
    (["--fixx", "--help"], 0, None),
    (["--help", "--fixx"], 0, None),
    (["--bogus", "-h"], 0, None),
    (["-h", "--bogus"], 0, None),
    (["fix", "--help"], 0, None),
    (["--fix", "--bogus", "--help"], 0, None),
    (["--help", "--fix", "--bogus"], 0, None),
])
def test_an_argument_other_than_fix_checks_and_writes_nothing(args, status, unknown):
    # The check used to look only for --fix in its arguments, so an unknown one printed
    # the normal report and exited 0, and "--fix --bogus" rewrote the tables. The class
    # tables differ from matrix.json here, so a run that checks exits 1 and --fix writes.
    # Help takes precedence over an unknown argument in either order: the run prints the
    # usage on standard output and exits 0, and with --fix beside them it still writes
    # nothing.
    td = scratch_tree()
    try:
        path = td / "matrix.json"
        matrix = json.loads(path.read_text(encoding="utf-8"))
        for cls in matrix["attackClasses"]:
            if cls["id"] == "GATEWAY-EXPLOIT":
                cls["description"] = "Rewritten in the data"
        path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")
        before = (td / "README.md").read_text(encoding="utf-8")

        r = run_checker(td, *args)
        assert r.returncode == status, r.stdout + r.stderr
        if unknown:
            assert r.stdout == "", r.stdout
            assert r.stderr.startswith("usage: check_readme_claims.py"), r.stderr
            assert f"unrecognized arguments: {unknown}\n" in r.stderr, r.stderr
        else:
            assert r.stdout.startswith("usage: check_readme_claims.py"), r.stdout
            assert "--fix" in r.stdout
            assert r.stderr == "", r.stderr
        assert (td / "README.md").read_text(encoding="utf-8") == before
    finally:
        shutil.rmtree(td)


def test_help_prints_the_usage_under_python_oo():
    # -OO strips docstrings, so the help description cannot be read from __doc__.
    r = subprocess.run(["python3", "-OO", str(ROOT / "scripts" / "check_readme_claims.py"),
                        "--help"], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert load_checker().DESCRIPTION in r.stdout


def test_the_description_states_what_help_and_other_arguments_do():
    module = load_checker()
    doc = module.__doc__
    assert module.DESCRIPTION == doc.splitlines()[0]
    assert "``--help`` (or ``-h``) prints\nthe usage and exits 0." in doc
    assert ("Any other argument, such as a mistyped ``--fixx``, prints the\n"
            "usage and exits 2 without checking or writing anything.") in doc
    # The description read as if an unknown argument exited 2 whatever stood beside it,
    # while "--fixx --help" printed the usage and exited 0.
    assert ("Help takes precedence over an\n"
            "argument the script does not know: given together in either order, as in\n"
            "``--fixx --help`` or ``-h --bogus``, they print the usage and exit 0, again "
            "without\nchecking or writing anything.") in doc
