"""README claim checker tests.

Every case runs scripts/check_readme_claims.py against a scratch copy of README.md and
matrix.json so the committed files are never perturbed. The shipped tree must be green.
Each count the README states is then changed by one in a single place and the checker
must go red, including the counts repeated in the "Use cases" section: the checker used
to accept a claim when the right number appeared anywhere, so a stale repeat passed
while the overview copy still matched.

The attack-class tables are generated from matrix.json: a reworded description, a
description changed in matrix.json alone, and a missing marker must each go red, and
``--fix`` must re-render the block without touching the rest of the README.

The DVAA figures are measured in DVAA, not in matrix.json, and are pinned in
related-projects.json. Every README line naming DVAA must state the pinned numbers: the
line that called all 21 agents vulnerable, while DVAA labels one hardened and four
control-protected, must go red. A README line naming DVAA that carries a format character,
a control character other than a tab, a Hangul filler, a default-ignorable combining mark
or an unassigned default-ignorable code point must go red too, and so must a line that
states a matrix.json count once such characters are removed. Inside a wording such a
character keeps the wording from being read, and a Hangul filler or combining mark does so
directly beside a DVAA wording, while a character that renders as nothing leaves the figure
in the rendered line.
"""

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
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
    ("and 60 of the 61 carry a reproducible lab scenario",
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
    ("60 of the 61 also carry a reproducible lab scenario",
     "61 of the 61 also carry a reproducible lab scenario"),
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


def mutate_related(root: Path, edit) -> None:
    path = root / "related-projects.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    edit(data["dvaa"])
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
     "variants; 12 vulnerability categories", "variants; 13 K categories"),
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
     "(21 agents: 16 deliberately vulnerable", "(é22 agents: 16 deliberately vulnerable"),
    ("U+0915 U+093F (Devanagari ki) before the agent count",
     "(21 agents: 16 deliberately vulnerable",
     "(कि22 agents: 16 deliberately vulnerable"),
    ("U+05D1 U+05BC (Hebrew bet with dagesh) before the agent count",
     "(21 agents: 16 deliberately vulnerable",
     "(בּ22 agents: 16 deliberately vulnerable"),
    ("U+0301 on the s of agents",
     "(21 agents: 16 deliberately vulnerable", "(22 agentś: 16 deliberately vulnerable"),
    ("U+0301 on the s of categories",
     "variants; 12 vulnerability categories", "variants; 13 vulnerability categorieś"),
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
     "(22 age⁥nts: 16 deliberately vulnerable",
     "U+2065, an unassigned default-ignorable code point"),
    ("U+FFF8, unassigned, between the number and the noun", AGENT_COUNT,
     "(22￸ agents: 16 deliberately vulnerable",
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
                      "(é 22 agents: 16 deliberately vulnerable")
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


def test_the_check_reads_the_categories_of_readme_characters_only():
    # The combining-mark test used to rebuild a character class from all 1,114,112 code
    # points on every run. The check now looks up the category of each README character
    # outside the line breaks once, to find the characters that fail a line, and of each
    # distinct character of the text of the lines naming DVAA, line break included, once
    # more, to build the combining-mark class. The budget is that sum, so a second lookup
    # of every README character fails the test.
    td = scratch_tree()
    try:
        r = subprocess.run(["python3", "-c", COUNT_CATEGORY_CALLS,
                            str(td / "scripts" / "check_readme_claims.py")],
                           capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, r.stderr
        last = r.stdout.strip().splitlines()[-1]
        assert last.startswith("status=0 calls="), r.stdout
        calls = int(last.rsplit("=", 1)[1])
        text = (td / "README.md").read_text(encoding="utf-8")
        dvaa_text = "\n".join(line if "DVAA" in line else "" for line in text.split("\n"))
        budget = len(text) - text.count("\n") + len(set(dvaa_text))
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
