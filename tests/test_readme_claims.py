"""README claim checker tests.

Every case runs scripts/check_readme_claims.py against a scratch copy of README.md, the
pages that took its reference text (the checker's PAGES) and matrix.json so the committed
files are never perturbed. "The README" below is README.md together with those pages: a
passage that moved to one of them is changed there, and its failure is named by that page
and line. The shipped tree must be green.
Each count the README states is then changed by one in a single place and the checker
must go red, including the counts repeated in the "Use cases" section: the checker used
to accept a claim when the right number appeared anywhere, so a stale repeat passed
while the overview copy still matched. The same holds for the per-tactic table, the
evidence-tier counts and percentages, the "Attack Classes (N)" heading and the HackMyAgent
and OASB figures pinned in related-projects.json, which the checker did not read at all,
so a HackMyAgent check count went stale without failing CI.

The attack-class tables are generated from matrix.json: a reworded description, a
description changed in matrix.json alone, and a missing marker must each go red, and
``--fix`` must re-render the block without touching the rest of the README. With a marker
missing, the two out of order or on two pages, ``--fix`` must write nothing and say so on
standard error rather than report the tables current. An argument
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
A tag inside the name whose quoted attribute value holds "<" or ">", as in 'DV<b x="<">AA'
and "DV<b title='>'>AA", leaves the name showing "DVAA" too, as its own paragraph and
between "<div>" and "</div>": the check read no DVAA on either line and exited 0, and each
must now go red on both figures. A numeric character reference with no closing ";", or with
more digits than CommonMark reads, written inside the name in an HTML block, as in
"DVA&#65", leaves the name showing "DVAA" too, as a browser decodes it there where it stands
as written, before it reads any tag, so "&#x30<b>D<x\\>VAA" shows "0DVAA": each such line
must go red on both figures, and each line the check read as naming DVAA before must still
go red. A browser applies these rules at once in an HTML block, so 'DV<x\\ y=">">AA', a tag
named "x\\" holding the value ">", 'DV<b x=">" <c>AA', a tag "b" holding it with an
attribute "<c", and "DV<b x='>'>A&#65" show "DVAA" there too, while each reading of the
check applied one of them alone, found no DVAA and exited 0: each must now go red on both
figures, and a line where a tag name holds a quote must still be read in linear time.
Written with a combining mark directly after it, or with
a "!" inside it that does not stand before a "[", the name does not name DVAA; on a line
that also carries a character that fails it, a mark directly after the name leaves the
line naming DVAA, and the line goes red. The three steps README states for reading the
name are also written below as a plain scan, which must read generated lines as the
checker does, so the sentence and the checker's patterns cannot drift apart with every
test passing. The example README and the checker's description give of a no-break space
after a tag name must be a form that only the second reading names, and the two must give
the same form.

A "]" directly followed by a link label the page does not define makes no reference link:
CommonMark shows the "]" and reads the "[" after it on, so "[x][DV](y)AA" shows "[x]DVAA".
The check removed every "][...]" span whether or not it made a link, read "x(y)AA", and the
line passed with two wrong figures, as did "[x][\\[DV](y)AA"; each must now go red, as
"[DV](y)AA" did. A label the page defines, in any letter case and spacing, and a blank one
are removed with the "]" before them, also after a label the page does not define on the
same line. The line is also read with no label removed, so a definition-like line in a
fenced code block, which CommonMark does not read as a definition, leaves the figures read,
and a definition on another page defines nothing on this one. A line holding four or more
labels the page defines was read with all of them removed and with none only, so on a
README that defines t, a and b, with DV only in a fenced code block,
"[x][DV](u)[A][t]A [y][a] [z][b]", which CommonMark shows as "[x]DVAA y z", passed with two
wrong figures, as did the line with "`][a]` `][b]`" in place of "[y][a] [z][b]"; each must
now go red, read with the labels the page defines on a definition line removed and DV kept.

A "]" followed by "(" makes no link either where no "[" before it opens one: CommonMark
shows "x](DV**AA**) (99 agents, 77 vulnerability categories)", set as its own paragraph
after README's licence line, as "x](DVAA) (99 agents, 77 vulnerability categories)", and a
browser shows the line with "DV<style>x</style>AA" in place of "DV**AA**" so too, as it does
the line with "DV<x\\>AA" there between "<div>" and "</div>". The check removed every
"](...)" span whether or not it made a link, read "x (99 agents, 77 vulnerability
categories)" and exited 0 on each line; each must now go red on both figures, read with
every such span kept, and the plain scan of the stated steps must read generated lines with
the spans kept as the checker does.

A browser shows no text of a style, script or template element, so "DV<style>x</style>AA
(99 agents, 77 vulnerability categories)", set as its own paragraph after README's licence
line, shows "DVAA (99 agents, 77 vulnerability categories)". The check removed the two tags,
kept the text between them, read "DVxAA" and exited 0, and did so with script or template
in place of style, and with a style start tag holding "<" in a quoted attribute value; each
must now go red on both figures. A table of cases pins where an element starts and ends, a
tag name ends where a browser and the HTML block reading end one, at a tab, line feed, form
feed, space, "/" or ">", and at no other character Python's \\s matches, so that U+00A0 or
U+3000 after the name of an element opens or closes none in any reading, the plain scan of
the stated steps reads the element rule as the checker does on 100,000 generated lines,
the reading that passes over quoted attribute values among them, and each of three lines
of 50,000 elements is read with their text removed in under 3 seconds.

The matrix version the README states under the title and in the framework citation is read
against matrix.json, and a month and year on either line against the CHANGELOG.md heading
that released that version. Neither was read, so a wrong version or month passed: each must
now go red, and so must a month on a line stating a version no heading releases, and a line
stating the version that carries a character which fails a line. The citation must state
the version; the line under the title may leave it out.

The technique ids the README writes, the name, tactic and evidence tier written beside
them, and the link and year of the technique citation were not read either, so an id
matrix.json does not hold, a wrong name, tactic or tier, a citation linking another
technique and a wrong year passed. Each must now go red, and so must a citation year when
no CHANGELOG.md heading releases the version, a README without the technique citation and
a line stating an id that carries a character which fails a line. A tactic or tier beside
an id is read in any letter case.

The STIX version the README states ("ships as a STIX 2.1 bundle"), on README.md, on the
schema page and in the repository tree on CONTRIBUTING.md, was not read either, so "STIX
2.0" passed. Each must now go red against the spec_version the objects of the committed
bundle carry, and so must a missing bundle, a bundle whose objects carry two spec_version
values, and a line stating the STIX version that carries a character which fails a line.
The version is read from the bundle, not typed in the checker: a bundle whose objects
carry 2.2 fails the README that states 2.1.
"""

import functools
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
FILES = ("matrix.json", "related-projects.json", "CHANGELOG.md",
         "stix/agent-threat-matrix-bundle.json", "scripts/check_readme_claims.py")
STIX_BUNDLE = "stix/agent-threat-matrix-bundle.json"
# The attack-class tables moved from README.md to this page, which links up one level.
CLASS_PAGE = "docs/attack-classes.md"
BEGIN = "<!-- BEGIN GENERATED: attack-class-tables -->"
END = "<!-- END GENERATED: attack-class-tables -->"
GATEWAY_DESCRIPTION = (
    "Modifying gateway or proxy configurations to intercept, redirect, or manipulate agent traffic"
)


@functools.lru_cache(maxsize=None)
def readme_pages() -> tuple:
    """README.md and the pages that took its reference text, in the order the checker reads
    them."""
    return load_checker().PAGES


def scratch_tree() -> Path:
    td = Path(tempfile.mkdtemp(prefix="atm-readme-"))
    for rel in (*FILES, *readme_pages()):
        dst = td / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    return td


def run_checker(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(root / "scripts" / "check_readme_claims.py"), *args],
                          capture_output=True, text=True, timeout=120)


def locate(root: Path, needle: str):
    """(page, text, offset): the first page, in the order the checker reads them, holding
    `needle`, its text and the offset of `needle` in it."""
    for rel in readme_pages():
        text = (root / rel).read_text(encoding="utf-8")
        if needle in text:
            return rel, text, text.index(needle)
    raise AssertionError(f"no README page holds {needle!r}")


def where_of(root: Path, needle: str) -> str:
    """"<page>:<line>" of the first occurrence of `needle` on the README pages."""
    rel, text, offset = locate(root, needle)
    return f"{rel}:{text[:offset].count(chr(10)) + 1}"


def mutate_readme(root: Path, old: str, new: str) -> None:
    """Replace `old` on the README page that holds it, README.md or a page that took its
    reference text; `old` must occur exactly once across those pages."""
    counts = [(root / rel).read_text(encoding="utf-8").count(old) for rel in readme_pages()]
    assert sum(counts) == 1, f"mutation target must occur exactly once: {old!r}"
    page = root / readme_pages()[next(i for i, n in enumerate(counts) if n)]
    text = page.read_text(encoding="utf-8")
    page.write_text(text.replace(old, new), encoding="utf-8")


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
        where = where_of(td, new)
        r = run_checker(td)
        assert r.returncode == 1, f"checker passed with {new!r}:\n{r.stdout}"
        assert f"{where}:" in r.stderr, r.stderr
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


def set_matrix_version(root: Path, version: str) -> None:
    path = root / "matrix.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["version"] = version
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# (old, new, message): the matrix version under the title or in the framework citation, or
# a month and year on one of those lines, moved off matrix.json or the CHANGELOG.md heading
# that released the version. Neither was read, so each passed.
VERSION_MUTATIONS = [
    ("**Version 1.2**", "**Version 1.3**",
     '"Version 1.3" does not match matrix.json (matrix version: 1.2)'),
    ("Threat Matrix v1.2.", "Threat Matrix v1.1.",
     '"Threat Matrix v1.1" does not match matrix.json (matrix version: 1.2)'),
    ("**Version 1.2** | September 2026", "**Version 1.2** | October 2026",
     '"October 2026" does not match CHANGELOG.md (version 1.2 released September 2026)'),
    ('v1.2." September 2026.', 'v1.2." September 2025.',
     '"September 2025" does not match CHANGELOG.md (version 1.2 released September 2026)'),
]


@pytest.mark.parametrize("old,new,message", VERSION_MUTATIONS,
                         ids=[n for _, n, _ in VERSION_MUTATIONS])
def test_a_wrong_version_or_release_month_is_red(old, new, message):
    td = scratch_tree()
    try:
        mutate_readme(td, old, new)
        r = run_checker(td)
        assert r.returncode == 1, f"checker passed with {new!r}:\n{r.stdout}"
        assert f"{where_of(td, new)}: {message}" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_the_framework_citation_must_state_the_version():
    td = scratch_tree()
    try:
        mutate_readme(td, "Threat Matrix v1.2.", "Threat Matrix, version 1.2.")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert "README does not state matrix version (1.2)" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_the_line_under_the_title_may_leave_the_version_out():
    td = scratch_tree()
    try:
        mutate_readme(td, "**Version 1.2** | September 2026 | ", "")
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_release_month_is_red_when_the_changelog_does_not_release_the_version():
    td = scratch_tree()
    try:
        set_matrix_version(td, "1.3")
        mutate_readme(td, "**Version 1.2**", "**Version 1.3**")
        mutate_readme(td, "Threat Matrix v1.2.", "Threat Matrix v1.3.")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for line in ("**Version 1.3** | September 2026", 'v1.3." September 2026.'):
            assert (f'{where_of(td, line)}: "September 2026" is read against the CHANGELOG.md '
                    "release heading of version 1.3, and there is none") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# (version, heading added to CHANGELOG.md, month and year the heading releases it in):
# "## v1.3.0 (2026-12-01)" releases 1.3, and the shipped "## v1.1" heading writes its date
# after a dash rather than in parentheses.
RELEASES = [
    ("1.3", "## v1.3.0 (2026-12-01)", "December 2026"),
    ("1.1", None, "June 2026"),
]


@pytest.mark.parametrize("version,heading,released", RELEASES,
                         ids=[v for v, _, _ in RELEASES])
def test_the_release_month_is_read_from_the_changelog_heading_of_the_version(
        version, heading, released):
    td = scratch_tree()
    try:
        if heading:
            changelog = td / "CHANGELOG.md"
            text = changelog.read_text(encoding="utf-8")
            assert text.count("## Unreleased\n") == 1
            changelog.write_text(text.replace("## Unreleased\n", f"{heading}\n\n## Unreleased\n"),
                                 encoding="utf-8")
        set_matrix_version(td, version)
        mutate_readme(td, "**Version 1.2**", f"**Version {version}**")
        mutate_readme(td, "Threat Matrix v1.2.", f"Threat Matrix v{version}.")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f'"September 2026" does not match CHANGELOG.md (version {version} released '
                f"{released})") in r.stderr, r.stderr
        mutate_readme(td, f"**Version {version}** | September 2026",
                      f"**Version {version}** | {released}")
        mutate_readme(td, f'v{version}." September 2026.', f'v{version}." {released}.')
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_version_line_carrying_an_invisible_character_is_red():
    # "Ver" U+00AD "sion 1.3" is not read as stating the version, so the character fails
    # the line instead of leaving a wrong version unchecked.
    td = scratch_tree()
    try:
        new = "**Ver\N{SOFT HYPHEN}sion 1.3**"
        named = "U+00AD SOFT HYPHEN, a format character"
        mutate_readme(td, "**Version 1.2**", new)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f"{where_of(td, new)}:{column_of(td, new, named)}: a line stating the matrix "
                f"version carries {named}, which can hide a figure from the version wordings; "
                "remove it") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# (old, new, message): a technique id the README writes, in prose, in code or on an attack
# path, the name, tactic or evidence tier written beside it, or the link or year of the
# technique citation, moved off matrix.json or the CHANGELOG.md heading that released the
# matrix version. None was read, so each passed.
TECHNIQUE_MUTATIONS = [
    ('(e.g., "ATM T-2001")', '(e.g., "ATM T-2099")',
     '"T-2099" is not a technique id in matrix.json'),
    ('.id == "T-3006")', '.id == "T-3060")', '"T-3060" is not a technique id in matrix.json'),
    ("T-2001 \N{RIGHTWARDS ARROW} T-3001 \N{RIGHTWARDS ARROW} T-5004",
     "T-2001 \N{RIGHTWARDS ARROW} T-30011 \N{RIGHTWARDS ARROW} T-5004",
     '"T-30011" is not a technique id in matrix.json'),
    ("T-2001 (Direct Prompt Injection)", "T-2001 (Indirect Prompt Injection)",
     '"T-2001 (Indirect Prompt Injection)" does not match matrix.json '
     "(T-2001 name: Direct Prompt Injection)"),
    ("Indirect Prompt Injection (T-2002", "Indirect Prompt Injection (T-2001",
     'the text before "(T-2001" does not end with its name in matrix.json '
     "(T-2001 name: Direct Prompt Injection)"),
    ("Credential Leak (T-3006", "Credential Exposure (T-3006",
     'the text before "(T-3006" does not end with its name in matrix.json '
     "(T-3006 name: Context Window Credential Leak)"),
    ("catalogued: Indirect Prompt", "catalogued: Non-Indirect Prompt",
     'the text before "(T-2002" does not end with its name in matrix.json '
     "(T-2002 name: Indirect Prompt Injection)"),
    ("(T-2002, initial access,", "(T-2002, credential harvest,",
     '"credential harvest" does not match matrix.json (T-2002 tactic: Initial Access)'),
    ("validated in the lab)", "adapted in the lab)",
     '"adapted in the lab" does not match matrix.json (T-3006 evidence tier: validated)'),
    ("techniques/T-2001", "techniques/T-2002",
     '"T-2002" on the citation of T-2001 names another technique'),
    ("OpenA2A, 2026.", "OpenA2A, 2025.",
     '"2025" does not match CHANGELOG.md (version 1.2 released 2026)'),
]


@pytest.mark.parametrize("old,new,message", TECHNIQUE_MUTATIONS,
                         ids=[n for _, n, _ in TECHNIQUE_MUTATIONS])
def test_a_technique_id_name_tactic_tier_or_citation_off_the_data_is_red(old, new, message):
    td = scratch_tree()
    try:
        mutate_readme(td, old, new)
        r = run_checker(td)
        assert r.returncode == 1, f"checker passed with {new!r}:\n{r.stdout}"
        assert f"{where_of(td, new)}: {message}" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_tactic_or_tier_beside_a_technique_id_is_read_in_any_letter_case():
    td = scratch_tree()
    try:
        mutate_readme(td, "(T-2002, initial access, observed in the wild)",
                      "(T-2002, Initial Access, Observed in the wild)")
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


def test_the_technique_citation_must_be_stated():
    td = scratch_tree()
    try:
        mutate_readme(td, "> AI Agent Threat Matrix T-2001",
                      "> AI Agent Threat Matrix, technique T-2001")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert 'README does not state a technique citation ("Threat Matrix T-N")' in r.stderr, \
            r.stderr
    finally:
        shutil.rmtree(td)


def test_a_citation_year_is_red_when_the_changelog_does_not_release_the_version():
    td = scratch_tree()
    try:
        set_matrix_version(td, "1.3")
        mutate_readme(td, "**Version 1.2**", "**Version 1.3**")
        mutate_readme(td, "Threat Matrix v1.2.", "Threat Matrix v1.3.")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f'{where_of(td, "OpenA2A, 2026.")}: "2026" is read against the CHANGELOG.md '
                "release heading of version 1.3, and there is none") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_the_citation_year_is_read_from_the_changelog_heading_of_the_version():
    td = scratch_tree()
    try:
        changelog = td / "CHANGELOG.md"
        text = changelog.read_text(encoding="utf-8")
        assert text.count("## Unreleased\n") == 1
        changelog.write_text(
            text.replace("## Unreleased\n", "## v1.3.0 (2027-01-15)\n\n## Unreleased\n"),
            encoding="utf-8")
        set_matrix_version(td, "1.3")
        mutate_readme(td, "**Version 1.2** | September 2026", "**Version 1.3** | January 2027")
        mutate_readme(td, 'Threat Matrix v1.2." September 2026.',
                      'Threat Matrix v1.3." January 2027.')
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f'{where_of(td, "OpenA2A, 2026.")}: "2026" does not match CHANGELOG.md '
                "(version 1.3 released 2027)") in r.stderr, r.stderr
        mutate_readme(td, "OpenA2A, 2026.", "OpenA2A, 2027.")
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_technique_id_line_carrying_an_invisible_character_is_red():
    # The line holds "T-2002" once U+00AD is removed, so the character fails the line.
    td = scratch_tree()
    try:
        new = "(such as `T-20\N{SOFT HYPHEN}02`)"
        named = "U+00AD SOFT HYPHEN, a format character"
        mutate_readme(td, "(such as `T-2002`)", new)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f"{where_of(td, new)}:{column_of(td, new, named)}: a line stating a technique "
                f"id carries {named}, which can hide a figure from the technique id wordings; "
                "remove it") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# (old, new, message): the STIX version the README states, on README.md, on the schema page
# and in the repository tree on CONTRIBUTING.md, moved off the spec_version the objects of
# the committed bundle carry. It was not read, so each passed.
STIX_MUTATIONS = [
    ("as a STIX 2.1 bundle", "as a STIX 2.0 bundle",
     f'"STIX 2.0" does not match {STIX_BUNDLE} (STIX version: 2.1)'),
    ("a STIX 2.1 rendering", "a STIX 2.11 rendering",
     f'"STIX 2.11" does not match {STIX_BUNDLE} (STIX version: 2.1)'),
    ("# STIX 2.1 bundle rendered", "# STIX 3 bundle rendered",
     f'"STIX 3" does not match {STIX_BUNDLE} (STIX version: 2.1)'),
]


@pytest.mark.parametrize("old,new,message", STIX_MUTATIONS,
                         ids=[n for _, n, _ in STIX_MUTATIONS])
def test_a_stix_version_off_the_bundle_is_red(old, new, message):
    td = scratch_tree()
    try:
        mutate_readme(td, old, new)
        r = run_checker(td)
        assert r.returncode == 1, f"checker passed with {new!r}:\n{r.stdout}"
        assert f"{where_of(td, new)}: {message}" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def set_bundle_spec_versions(root: Path, versions) -> None:
    """Give the bundle's objects the spec_version values in `versions`, in turn."""
    path = root / STIX_BUNDLE
    data = json.loads(path.read_text(encoding="utf-8"))
    for i, obj in enumerate(data["objects"]):
        obj["spec_version"] = versions[i % len(versions)]
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def test_the_stix_version_is_read_from_the_bundle_objects():
    td = scratch_tree()
    try:
        set_bundle_spec_versions(td, ["2.2"])
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f'{where_of(td, "as a STIX 2.1 bundle")}: "STIX 2.1" does not match '
                f"{STIX_BUNDLE} (STIX version: 2.2)") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_missing_bundle_is_red():
    td = scratch_tree()
    try:
        (td / STIX_BUNDLE).unlink()
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f"{STIX_BUNDLE}: missing; the STIX version the README states is read from "
                "its objects' spec_version") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_bundle_whose_objects_carry_two_spec_versions_is_red():
    td = scratch_tree()
    try:
        set_bundle_spec_versions(td, ["2.1", "2.2"])
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f"{STIX_BUNDLE}: its objects carry 2 spec_version values (2.1, 2.2), and "
                "the STIX version the README states is read from the one they share"
                ) in r.stderr, r.stderr
        assert "STIX version: " not in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_stix_version_line_carrying_an_invisible_character_is_red():
    # The line holds "STIX 2.1" once U+00AD is removed, so the character fails the line.
    td = scratch_tree()
    try:
        new = "as a ST\N{SOFT HYPHEN}IX 2.1 bundle"
        named = "U+00AD SOFT HYPHEN, a format character"
        mutate_readme(td, "as a STIX 2.1 bundle", new)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f"{where_of(td, new)}:{column_of(td, new, named)}: a line stating the STIX "
                f"version carries {named}, which can hide a figure from the STIX version "
                "wordings; remove it") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def mutate_related(root: Path, edit, project: str = "dvaa") -> None:
    path = root / "related-projects.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    edit(data[project])
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


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
            assert f"{where_of(td, needle)}:" in r.stderr, r.stderr
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
            assert f"{where_of(td, needle)}:" in r.stderr, r.stderr
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


def test_a_tactic_or_tier_row_written_another_way_is_not_read():
    # The script's description says a row is read only in the forms it shows: a stale tactic
    # row with no link and a stale tier row with a space after its last "|" are not read.
    td = scratch_tree()
    try:
        text = (td / "README.md").read_text(encoding="utf-8")
        row = next(l for l in text.splitlines(keepends=True)
                   if l.startswith("| [Impact](tactics/impact.md) |"))
        mutate_readme(td, row,
                      row + "| Impact | 9 | 5 | stale |\n| **Observed** | dup | 17 (28%) | \n")
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


@pytest.mark.parametrize("line,kilobytes,last", [
    # Lines that start a tactic row and never close its bracket. With a name class that
    # crossed line breaks, the row pattern scanned from each such line to the end of the
    # README and back: these 200 KB took about 16 s on Python 3.14.
    ("| [a\n", 200, None),
    # Copies of a tactic row, each reported as a second row for the tactic. Counting the
    # line breaks before each reported row to name its line took about 28 s for these.
    ("| [Impact](tactics/impact.md) | 9 | 6 | Modify data |\n", 3200,
     "second row for tactic impact"),
], ids=["unclosed tactic row starts", "repeated tactic rows"])
def test_many_tactic_row_lines_are_read_in_linear_time(line, kilobytes, last):
    td = scratch_tree()
    try:
        readme = td / "README.md"
        text = readme.read_text(encoding="utf-8")
        copies = kilobytes * 1024 // len(line)
        readme.write_text(text + line * copies, encoding="utf-8")
        start = time.perf_counter()
        r = run_checker(td)
        seconds = time.perf_counter() - start
        if last is None:
            assert r.returncode == 0, r.stderr
        else:
            # The last copy is reported at its own line.
            assert r.returncode == 1, r.stdout
            assert f"README.md:{text.count(chr(10)) + copies}: {last} " in r.stderr, \
                r.stderr[-2000:]
        assert seconds < 6, f"{seconds:.2f} s"
    finally:
        shutil.rmtree(td)


def test_many_differing_count_wordings_are_read_in_linear_time():
    # Each line states a tactic count that differs from matrix.json and is reported at its own
    # line. Counting the line breaks from the start of the README for each one took about 9 s
    # for 80,000 such lines on Python 3.14.
    td = scratch_tree()
    try:
        readme = td / "README.md"
        text = readme.read_text(encoding="utf-8")
        copies = 120_000
        readme.write_text(text + "1 tactics\n" * copies, encoding="utf-8")
        start = time.perf_counter()
        r = run_checker(td)
        seconds = time.perf_counter() - start
        assert r.returncode == 1, r.stdout
        # The first and the last copy are each reported at their own line.
        for line in (text.count("\n") + 1, text.count("\n") + copies):
            assert f"README.md:{line}: \"1 tactics\" does not match matrix.json" in r.stderr, \
                r.stderr[-2000:]
        assert seconds < 6, f"{seconds:.2f} s"
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


# Lines where a letter, digit or combining mark outside ASCII is glued to a DVAA wording.
# re.ASCII also narrows \b to ASCII word characters, so each of these used to be read as
# the wording beside it ("é22 agents" as "22 agents") and fail on its number. A Unicode \b
# counts no combining mark as a word character, so the cases with a combining mark were
# still read under it: "é" written as "e" and U+0301 failed where the precomposed U+00E9
# passed.
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
    # A mark outside the Basic Multilingual Plane glues a wording as one inside it does.
    ("U+1D165 (musical symbol combining stem, Mc) before the agent count",
     "(21 agents: 16 deliberately vulnerable",
     "(\N{MUSICAL SYMBOL COMBINING STEM}22 agents: 16 deliberately vulnerable"),
    ("U+1D165 (musical symbol combining stem, Mc) on the s of agents",
     "(21 agents: 16 deliberately vulnerable",
     "(22 agents\N{MUSICAL SYMBOL COMBINING STEM}: 16 deliberately vulnerable"),
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
def test_a_wording_glued_to_a_non_ascii_letter_digit_or_combining_mark_is_not_read(old, new):
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
    _, text, offset = locate(root, needle)
    start = text.rindex("\n", 0, offset) + 1
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
        assert (f"{where_of(td, new)}:{column_of(td, new, named)}: a line naming DVAA "
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
        assert (f"{where_of(td, new)}:{column_of(td, new, named)}: a line stating a "
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
    # NFKC leaves U+20DD apart from the A, so "DVAA" U+20DD names DVAA without the
    # character; U+0301 past U+0332 is joined to it.
    ("U+200B ZERO WIDTH SPACE between the name and U+0332 U+0301 in strong emphasis",
     "**DVAA\N{ZERO WIDTH SPACE}\N{COMBINING LOW LINE}\N{COMBINING ACUTE ACCENT}**",
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
        line = where_of(td, new)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"{line}: \"22 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"{line}: \"13 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
            f"{line}:{column_of(td, new, named)}: a line naming DVAA carries {named}, "
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
    # A code span shows its text less one space at each end, and an escaped parenthesis
    # does not end a link destination. Read with the backticks and the backslash removed
    # wherever they stood, the first read "DV AA" and the second "DVx)AA".
    ("code span with a space at each end", f"[` DV `AA]{DVAA_URL}"),
    ("escaped parenthesis in the link destination", f"[DV]({DVAA_URL[1:-1]}\\)x)AA"),
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
    ("U+0301 COMBINING ACUTE ACCENT after a first DVAA",
     f"[DVAA\N{COMBINING ACUTE ACCENT} DVAA]{DVAA_URL}"),
    # A combining mark that NFKC leaves apart from the last A, drawn under, through or
    # around it, does not make another name; at 0d1bad2 each such line was read, and
    # treating any mark after the name as making one took it out of the check.
    ("U+0332 COMBINING LOW LINE after the name", f"[DVAA\N{COMBINING LOW LINE}]{DVAA_URL}"),
    ("U+0335 COMBINING SHORT STROKE OVERLAY after the name",
     f"[DVAA\N{COMBINING SHORT STROKE OVERLAY}]{DVAA_URL}"),
    ("U+0338 COMBINING LONG SOLIDUS OVERLAY after the name",
     f"[DVAA\N{COMBINING LONG SOLIDUS OVERLAY}]{DVAA_URL}"),
    ("U+20DD COMBINING ENCLOSING CIRCLE after the name",
     f"[DVAA\N{COMBINING ENCLOSING CIRCLE}]{DVAA_URL}"),
    ("U+0332 U+0338 after the name",
     f"[DVAA\N{COMBINING LOW LINE}\N{COMBINING LONG SOLIDUS OVERLAY}]{DVAA_URL}"),
    # U+20DD has combining class 0, so NFKC joins no mark after it to the A.
    ("U+20DD U+0301 after the name",
     f"[DVAA\N{COMBINING ENCLOSING CIRCLE}\N{COMBINING ACUTE ACCENT}]{DVAA_URL}"),
    ("U+0332 COMBINING LOW LINE after U+0410",
     f"[DVA\N{CYRILLIC CAPITAL LETTER A}\N{COMBINING LOW LINE}]{DVAA_URL}"),
    ("U+0332 COMBINING LOW LINE after strong emphasis",
     f"[DV**AA**\N{COMBINING LOW LINE}]{DVAA_URL}"),
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
    ("reference to U+0301 after the name", f"[DVAA&#x301;]{DVAA_URL}"),
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
        line = where_of(td, new)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"{line}: \"22 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"{line}: \"13 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# DVAA written in an HTML block, between "<div>" and "</div>", where a browser reads a tag
# name to a tab, line feed, form feed, space, "/" or ">": "<x\>" is a tag named "x\",
# "<D\\</b>" a tag named "d\\<" with an attribute "b", and "<x" U+00A0 "<y>" a tag named
# "x" U+00A0 "<y", so each line shows "DVAA (99 agents, ...)". Each was read as text, as a
# tag name of ASCII letters, digits and hyphens ends at "\" and "<", and one that runs to
# white space ends at U+00A0 and U+3000 IDEOGRAPHIC SPACE, and the check found no DVAA on
# the line and exited 0. A browser also reads a "<" after a tag name and white space as part
# of an attribute name or unquoted value, so "<a <b>" is a tag named "a" with an attribute
# "<b", and "<a <b" U+00A0 "D<x\>" a tag named "a" with an attribute "<b" U+00A0 "d<x\":
# the check ended a tag at the first ">" only where no "<" came first, removed only "<b>"
# and "<b" U+00A0 "D<x\>" from the last two lines, read "DV<a AA" and "D<a VAA" and exited
# 0. U+00A0 and U+3000 are written as escapes, as saved raw they read as the space beside
# them.
LICENSE_LINE = "Apache-2.0. The framework is free to use, cite, and build upon.\n"
HTML_BLOCK_NAMES = [
    ("plain name", "DVAA"),
    ("tag with a backslash in its name", "DV<x\\>AA"),
    ("tag with a backslash and a < in its name", "D<D\\\\</b>VAA"),
    ("tag with U+00A0 and a < in its name", "DV<x\N{NO-BREAK SPACE}<y>AA"),
    ("tag with U+3000 and a < in its name", "DV<x\N{IDEOGRAPHIC SPACE}<y>AA"),
    ("tag with a < after its name and a space", "DV<a <b>AA"),
    ("tag with a < after its name and a space, then U+00A0 and a tag name with a <",
     "D<a <b\N{NO-BREAK SPACE}D<x\\>VAA"),
]


@pytest.mark.parametrize("written", [w for _, w in HTML_BLOCK_NAMES],
                         ids=[case for case, _ in HTML_BLOCK_NAMES])
def test_a_name_in_an_html_block_hidden_by_a_tag_a_browser_reads_leaves_the_line_read(
        written):
    td = scratch_tree()
    try:
        figures = f"{written} (99 agents, 77 vulnerability categories)"
        mutate_readme(td, LICENSE_LINE, f"{LICENSE_LINE}\n<div>\n{figures}\n</div>\n")
        line = where_of(td, figures)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"{line}: \"99 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"{line}: \"77 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# DVAA written in an HTML block with a numeric character reference that CommonMark does not
# read, as it has no closing ";" or more than seven decimal or six hexadecimal digits. A
# browser decodes each there, so each line shows "DVAA (99 agents, ...)", the last with
# U+0301 over the last A, which is kept apart from the name, as in "DVAA&#x301;", since it is
# written as a reference. The check decoded a reference only as CommonMark reads one, found
# no DVAA on any of these lines and exited 0.
HTML_BLOCK_REFERENCE_NAMES = [
    ("decimal reference with no closing ;", "DVA&#65"),
    ("hexadecimal reference with no closing ;", "DVA&#x41"),
    ("hexadecimal reference with an X and no closing ;", "DVA&#X41"),
    ("decimal reference ended by a letter", "DV&#65A"),
    ("decimal reference with eight digits", "DVA&#00000065;"),
    ("hexadecimal reference with seven digits", "DVA&#x0000041;"),
    ("reference to U+200B with no closing ;", "DV&#8203AA"),
    ("reference to U+0301 with no closing ; after the name", "DVA&#65&#x301"),
    # A browser reads a reference where it stands as written, before it reads any tag, so
    # "<" ends "&#x30" and the line shows "0DVAA (99 agents, ...)". Decoded once the tags
    # are removed, "&#x30D" would stand for U+030D before "VAA" and the reading would find
    # no DVAA on the line.
    ("reference with no closing ; ended by a tag before the name", "&#x30<b>D<x\\>VAA"),
    ("references with no closing ; on both sides of a tag", "&#x3<b>DVA&#65"),
]


@pytest.mark.parametrize("written", [w for _, w in HTML_BLOCK_REFERENCE_NAMES],
                         ids=[case for case, _ in HTML_BLOCK_REFERENCE_NAMES])
def test_a_name_in_an_html_block_written_with_a_reference_a_browser_reads_leaves_the_line_read(
        written):
    td = scratch_tree()
    try:
        figures = f"{written} (99 agents, 77 vulnerability categories)"
        mutate_readme(td, LICENSE_LINE, f"{LICENSE_LINE}\n<div>\n{figures}\n</div>\n")
        line = where_of(td, figures)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"{line}: \"99 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"{line}: \"77 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# Lines the check read as naming DVAA before it decoded a reference with no closing ";" or
# with more digits than CommonMark reads, as a browser does in an HTML block: the reading
# that removes the tags a browser reads and leaves such a reference as written, decoding
# the others once the HTML is removed, finds "DVAA" on each, and it is kept, so each line
# still fails on both figures. Decoded where it stands, "&#x3D" stands for "=" and the line
# shows "=VAA (99 agents, ...)", and "&#6" stands for U+0006 before "5;".
NAMES_READ_BEFORE = [
    ("hexadecimal reference with no closing ; before a tag", "&#x3DV<x\\>AA"),
    ("decimal reference with its ; past a tag", "DVA&#6<x\\>5;"),
]


@pytest.mark.parametrize("written", [w for _, w in NAMES_READ_BEFORE],
                         ids=[case for case, _ in NAMES_READ_BEFORE])
def test_a_line_read_as_naming_dvaa_before_references_were_decoded_as_written_still_is(
        written):
    checker = load_checker()
    assert checker.holds(checker.name_form(written, checker.HtmlBlockHtml()), "DVAA")
    assert not checker.holds(checker.name_form(written, checker.HtmlBlockHtml(),
                                               references=checker.HTML_BLOCK_REFERENCE), "DVAA")
    td = scratch_tree()
    try:
        figures = f"{written} (99 agents, 77 vulnerability categories)"
        mutate_readme(td, LICENSE_LINE, f"{LICENSE_LINE}\n<div>\n{figures}\n</div>\n")
        line = where_of(td, figures)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"{line}: \"99 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"{line}: \"77 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# What a line reads as in the HTML block reading that decodes a numeric character reference
# with or without a closing ";" and whatever its number of digits, where it stands as
# written, as a browser reads one before it reads any tag: the decimal digits end at a
# letter, while the hexadecimal digits run on over "A", so "&#x41A" stands for U+041A; a
# tag or a Markdown character ends the digits, so "&#x30<b>D" stands for "0" before the
# "D", and "&#6**5" for U+0006, a control character, before the "5"; a number past
# U+10FFFF stands for U+FFFD; "&#" or "&#x" with no digit after it is no reference; and a
# named reference is read as CommonMark reads one, only with its ";". Decoded once the tags
# and the Markdown characters are removed, "&#x30<b>D" would stand for U+030D, a combining
# mark, and the line would read U+030D "VAA", naming no DVAA.
HTML_BLOCK_FORMS = [
    ("decimal reference with no closing ;", "DVA&#65", "DVAA"),
    ("hexadecimal reference with no closing ;", "DVA&#x41", "DVAA"),
    ("decimal digits ended by a letter", "DV&#65A", "DVAA"),
    ("hexadecimal digits running on over a letter", "DV&#x41A",
     "DV\N{CYRILLIC CAPITAL LETTER KA}"),
    ("decimal reference with eight digits", "DVA&#00000065;", "DVAA"),
    ("hexadecimal reference with seven digits", "DVA&#x0000041;", "DVAA"),
    ("reference to U+200B with no closing ;", "DV&#8203AA", "DVAA"),
    ("number past U+10FFFF", "DVA&#1114112 A", "DVA\N{REPLACEMENT CHARACTER} A"),
    ("no decimal digit", "DVA&#;A", "DVA&#;A"),
    ("no hexadecimal digit", "DVA&#xyA", "DVA&#xyA"),
    ("named reference with no closing ;", "DV&ampAA", "DV&ampAA"),
    ("hexadecimal digits ended by a tag before a hexadecimal letter", "&#x30<b>D<x\\>VAA",
     "0DVAA"),
    ("hexadecimal digits ended by a tag before a digit", "DVA&#x4<b>1", "DVA1"),
    ("decimal digits ended by a Markdown character", "DV&#6**5**A", "DV5A"),
    ("references on both sides of a tag", "&#x3<b>DVA&#65", "DVAA"),
    ("reference to a star", "DV&#42AA", "DV*AA"),
]


@pytest.mark.parametrize("text,form", [(t, f) for _, t, f in HTML_BLOCK_FORMS],
                         ids=[case for case, _, _ in HTML_BLOCK_FORMS])
def test_the_html_block_reading_decodes_a_numeric_reference_as_stated(text, form):
    checker = load_checker()
    assert checker.name_form(text, checker.HtmlBlockHtml(),
                             references=checker.HTML_BLOCK_REFERENCE) == form
    assert stated_name_form(checker, text, html_block=True, references=True) == form


@pytest.mark.parametrize("digits", ["0" * 100_000 + "65", "x" + "0" * 100_000 + "41"],
                         ids=["decimal", "hexadecimal"])
def test_a_reference_with_any_number_of_digits_is_decoded_in_linear_time(digits):
    # html.unescape reads the digits of a decimal reference with int, which by default
    # refuses a string of more than 4,300 digits with a ValueError. Read with its leading
    # zeros dropped, each reference stands for "A", and each line, of 100,000 zeros, is read
    # in about 0.01 s on Python 3.14.
    checker = load_checker()
    start = time.perf_counter()
    assert checker.names(f"DVA&#{digits}", "DVAA")
    seconds = time.perf_counter() - start
    assert seconds < 3, f"{seconds:.2f} s"


def test_a_reference_with_more_digits_than_u10ffff_has_stands_for_u_fffd():
    # Once its leading zeros are dropped, a reference with more digits than U+10FFFF has,
    # seven decimal or six hexadecimal, is a number past U+10FFFF, which a browser reads as
    # U+FFFD, as html.unescape gives for such a number of fewer digits: the 5,000 nines are
    # more digits than int reads by default. A reference of fewer digits reads as
    # html.unescape gives it.
    checker = load_checker()
    for reference in ("&#" + "9" * 5_000, "&#x" + "F" * 7, "&#00001114112;", "&#x110000"):
        assert checker.reference_text(reference) == "\N{REPLACEMENT CHARACTER}", reference
    assert html.unescape("&#1114112;") == "\N{REPLACEMENT CHARACTER}"
    for reference in ("&#65", "&#00000065", "&#x0000041;", "&#1114111", "&#X10fffd", "&#0"):
        assert checker.reference_text(reference) == html.unescape(reference), reference


# DVAA set as its own paragraph after README's licence line, with a style, script or
# template element holding text inside the name, the last a style element whose start tag
# holds "<" in a quoted attribute value, which only the reading that passes over quoted
# values and the HTML block reading read as a tag. A browser shows no text of such an
# element, so each line shows
# "DVAA (99 agents, 77 vulnerability categories)", while the check removed the two tags,
# kept the text between them, read "DVxAA", found no DVAA and exited 0.
ELEMENT_NAMES = [
    ("plain name", "DVAA"),
    ("style element", "DV<style>x</style>AA"),
    ("script element", "DV<script>x</script>AA"),
    ("template element", "DV<template>x</template>AA"),
    ("style element with a quoted < in its start tag", 'DV<style title="<">x</style>AA'),
]


@pytest.mark.parametrize("written", [w for _, w in ELEMENT_NAMES],
                         ids=[case for case, _ in ELEMENT_NAMES])
def test_a_name_holding_an_element_a_browser_shows_no_text_of_leaves_the_line_read(written):
    td = scratch_tree()
    try:
        figures = f"{written} (99 agents, 77 vulnerability categories)"
        mutate_readme(td, LICENSE_LINE, f"{LICENSE_LINE}\n{figures}\n")
        line = where_of(td, figures)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"{line}: \"99 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"{line}: \"77 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_tag_name_a_browser_reads_is_removed_only_in_the_html_block_reading():
    checker = load_checker()
    for written in ("DV<x\\>AA", "D<D\\\\</b>VAA", "DV<x\N{NO-BREAK SPACE}<y>AA",
                    "DV<x\N{IDEOGRAPHIC SPACE}<y>AA"):
        assert checker.OTHER_CHARACTER_IN_TAG_NAME.search(written)
        assert not checker.holds(checker.name_form(written), "DVAA"), written
        assert checker.name_form(written, checker.HtmlBlockHtml()) == "DVAA", written
        assert checker.names(written, "DVAA"), written
    assert checker.name_form("DV<a</b>AA", checker.HtmlBlockHtml()) == "DVAA"
    assert checker.name_form("DV<a<</b>AA", checker.HtmlBlockHtml()) == "DVAA"
    # A "<" after a tag name and a space, a tab or "/" does not end the tag in an HTML
    # block, where a browser reads it as part of an attribute name or value.
    for written in ("DV<a <b>AA", "D<a <b\N{NO-BREAK SPACE}D<x\\>VAA", "DV<a\t<b>AA",
                    "DV<a/<b>AA", "DV</a x<b>AA"):
        assert checker.LESS_THAN_AFTER_TAG_NAME.search(written), ascii(written)
        assert not checker.holds(checker.name_form(written), "DVAA"), ascii(written)
        assert checker.name_form(written, checker.HtmlBlockHtml()) == "DVAA", ascii(written)
        assert checker.names(written, "DVAA"), ascii(written)
    assert not checker.OTHER_CHARACTER_IN_TAG_NAME.search("DV<a <b>AA")
    # HtmlBlockHtml does not look for a tag after the last ">" of a line, where none finds
    # a ">", and gives what the pattern gives from every "<".
    rng = random.Random(153)
    pieces = [*"<</\\>ab /-\t\"'`*", "\N{NO-BREAK SPACE}", "<!--", "-->", "DV", "AA"]
    for _ in range(50_000):
        line = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 16)))
        assert (checker.step_one(line, checker.HtmlBlockHtml())
                == checker.step_one(line, checker.HTML_BLOCK_HTML)), ascii(line)
        # On a line the HTML block way is not read on, it would remove what RAW_HTML does.
        if not block_read(checker, line):
            assert (checker.step_one(line, checker.HTML_BLOCK_HTML)
                    == checker.step_one(line)), ascii(line)
    # Where every tag name ends at a tab, a space, "/", ">" or the end of the line, and no
    # "<" follows a tab, a space or "/" after one before any ">", the reading is not added;
    # white space other than a tab or space does not end a tag name in an HTML block, so a
    # tag name followed by it adds the reading, and so does "<a" followed by a tab and "<p".
    for line, added in (("DV<b>AA <i x='1'> <br/> <a\t>p <a", False),
                        ("DV<b>AA <i x='1'> <br/> <a\t<p", True)):
        assert not checker.OTHER_CHARACTER_IN_TAG_NAME.search(line), ascii(line)
        assert bool(checker.LESS_THAN_AFTER_TAG_NAME.search(line)) == added, ascii(line)
    for space in ("\N{NO-BREAK SPACE}", "\N{IDEOGRAPHIC SPACE}", "\N{EM SPACE}"):
        assert checker.OTHER_CHARACTER_IN_TAG_NAME.search(f"DV<b{space}x>AA"), ascii(space)
        assert checker.HTML_BLOCK_TAG_NAME.match(f"b{space}x>").end() == 3, ascii(space)


def test_one_html_block_reading_reads_a_line_alike_each_time():
    # One HtmlBlockHtml gives what HTML_BLOCK_HTML gives however many times it reads a line,
    # so the readings `names` makes of one line can share an instance. In
    # "DV<y\>AA <q\" the tag "<q\" finds no ">", and a later reading of the line, which
    # starts again from its first character, still removes "<y\>" before it: a tag is
    # passed over only after the last ">" of the line.
    checker = load_checker()
    line = "DV<y\\>AA <q\\"
    reading = checker.HtmlBlockHtml()
    for _ in range(3):
        assert checker.name_form(line, reading) == "DVAA <q\\"
    # One instance reads lines picked from a set, each one to three times in a row, so a
    # reading often follows another of the same line, as well as readings of other lines.
    rng = random.Random(1531)
    pieces = [*"<</\\>ab /-\t\"'`*", "\N{NO-BREAK SPACE}", "<!--", "-->", "DV", "AA"]
    lines = ["".join(rng.choice(pieces) for _ in range(rng.randint(1, 16)))
             for _ in range(500)]
    reading = checker.HtmlBlockHtml()
    for _ in range(50_000):
        line = rng.choice(lines)
        expected = checker.step_one(line, checker.HTML_BLOCK_HTML)
        for _ in range(rng.randint(1, 3)):
            assert checker.step_one(line, reading) == expected, ascii(line)


@pytest.mark.parametrize("line", ["DV" + "<a" * 50_000, "DV" + "<a\\" * 40_000 + "AA",
                                  "DV" + "<a</" * 30_000 + "AA",
                                  "DV" + "<a\N{NO-BREAK SPACE}" * 40_000 + "AA",
                                  "DV" + "<a " * 40_000 + "AA",
                                  "DV" + "<a <b" * 30_000 + "AA"])
def test_the_html_block_reading_reads_a_long_line_in_linear_time(line):
    # A tag in that reading runs past any "<" in its name and attributes, so a tag that
    # finds no ">" runs past every "<" after it; looked for again from each "<" on a line of
    # "<a" or "<a ", every look would scan to the end of the line, in time quadratic in its
    # length.
    checker = load_checker()
    start = time.perf_counter()
    checker.names(line, "DVAA")
    seconds = time.perf_counter() - start
    assert seconds < 3, f"{seconds:.2f} s"


# The DVAA row of the related-projects table rewritten with "DVAA" in markup beside a
# backtick and two wrong figures: the backtick stands in a link destination, in a link
# title, in each of two table cells, in an autolink, or in an HTML attribute that holds
# "<", and the line ends with another backtick. None of these makes a code span of the
# text between the two backticks, and the check reads none: code spans stop being read at
# a link span holding a backtick or quote, at a code span whose text holds a "|", which
# ends a cell in a table row, and at a "<" with a backtick or quote before the first ">"
# after it. Each backtick is then removed with the Markdown characters and the line goes
# red on both figures.
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
        number = where_of(td, line)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"{number}: \"99 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"{number}: \"77 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# Lines that show "DVAA" with two wrong figures where a backtick could open a code span
# that hides the name, each set as its own paragraph after README's licence line; the
# line with the figures is read. Code spans stop being read at a "<" with a quote before
# the first ">" after it, at a link span that holds a backtick, quote or backslash or
# meets a further "(" first, and at a code span whose text holds "<" or "&", which a
# browser reads in an HTML block; and none is read after a line that leaves a backtick,
# a comment or a link destination open. Read as a code span, the text between two of
# these backticks would hold "**DV**AA" or "D<b></b>VAA" as written, and the line would
# not name DVAA.
FIGURES = "(99 agents, 77 vulnerability categories)"
LICENCE = "Apache-2.0. The framework is free to use, cite, and build upon."
PARAGRAPH_LINES = [
    ("quote in a tag", [f"<span title='>`'> **DV**AA {FIGURES} `x`"]),
    ("backtick in a link destination", [f"[x](`) **DV**AA {FIGURES} `x`"]),
    ("parenthesis pair in a link destination", [f"[x](a(b)`) **DV**AA {FIGURES} `x`"]),
    ("escaped parenthesis in a link destination", [f"[x](a\\)`) **DV**AA {FIGURES} `x`"]),
    ("link title holding a parenthesis", [f'[x](a ")`") **DV**AA {FIGURES} `x`']),
    ("backtick in a reference label", [f"[x][a`] **DV**AA {FIGURES} `x`"]),
    ("< in a code span in an HTML block", ["<div>", f"` D<b></b>VAA {FIGURES} `", "</div>"]),
    ("& in a code span in an HTML block", ["<div>", f"` D&#86;AA {FIGURES} `", "</div>"]),
    ("backtick open on the line before", ["a `", f"` **DV**AA {FIGURES} `x`"]),
    ("comment open on the line before", ["a <!--", f"` --> **DV**AA {FIGURES} `x`"]),
    ("link destination open on the line before", ["[x](", f"`) **DV**AA {FIGURES} `x`"]),
]


@pytest.mark.parametrize("lines", [lines for _, lines in PARAGRAPH_LINES],
                         ids=[case for case, _ in PARAGRAPH_LINES])
def test_a_backtick_that_could_hide_the_name_dvaa_leaves_the_line_read(lines):
    td = scratch_tree()
    try:
        mutate_readme(td, LICENCE, LICENCE + "\n\n" + "\n".join(lines) + "\n\n")
        number = where_of(td, next(line for line in lines if FIGURES in line))
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"{number}: \"99 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"{number}: \"77 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_blank_line_ends_what_the_line_before_left_open():
    # Its own paragraph, the line holds one code span with "**DV**AA" as written.
    td = scratch_tree()
    try:
        mutate_readme(td, LICENCE, f"{LICENCE}\n\na `\n\n` **DV**AA {FIGURES} `x`\n\n")
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


# DVAA written with a tag inside it whose quoted attribute value holds "<" or ">", which
# CommonMark and a browser read as part of the value, so each line shows "DVAA (99 agents,
# 77 vulnerability categories)", as its own paragraph after README's licence line and
# between "<div>" and "</div>". The check ended a tag at the first ">" after its name and
# found none where a "<" came first: it removed nothing from the first name and only
# "<b title='>" from the second, read 'DV<b x="<">AA' and "DV'>AA", found no DVAA and
# exited 0.
QUOTED_VALUE_NAMES = [
    ("double-quoted value holding <", 'DV<b x="<">AA'),
    ("single-quoted value holding >", "DV<b title='>'>AA"),
]
QUOTED_VALUE_LINES = [
    (f"{case} as its own paragraph", [f"{written} {FIGURES}"])
    for case, written in QUOTED_VALUE_NAMES
] + [
    (f"{case} in an HTML block", ["<div>", f"{written} {FIGURES}", "</div>"])
    for case, written in QUOTED_VALUE_NAMES
]


@pytest.mark.parametrize("lines", [lines for _, lines in QUOTED_VALUE_LINES],
                         ids=[case for case, _ in QUOTED_VALUE_LINES])
def test_a_tag_whose_quoted_value_holds_lt_or_gt_leaves_the_name_dvaa_read(lines):
    td = scratch_tree()
    try:
        mutate_readme(td, LICENCE, LICENCE + "\n\n" + "\n".join(lines) + "\n\n")
        number = where_of(td, next(line for line in lines if FIGURES in line))
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"{number}: \"99 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"{number}: \"77 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_quoted_value_is_passed_over_only_in_the_quoted_value_reading():
    checker = load_checker()
    for _, written in QUOTED_VALUE_NAMES:
        assert checker.QUOTE_AFTER_TAG_NAME.search(written)
        for other in (checker.RAW_HTML, checker.SPACE_OR_TAB_HTML):
            assert not checker.holds(checker.name_form(written, other), "DVAA"), written
        assert checker.name_form(written, checker.QUOTED_HTML) == "DVAA", written
        assert checker.names(written, "DVAA"), written
    # The HTML block reading ends a tag at the first ">" after it, also in a quoted value,
    # and reads a "<" after the tag name and a space as part of the tag, quoted or not.
    assert checker.name_form("DV<b title='>'>AA", checker.HtmlBlockHtml()) == "DV'>AA"
    assert checker.name_form('DV<b x="<">AA', checker.HtmlBlockHtml()) == "DVAA"
    # Where no tag name is followed by "/" or white space and then by a quote before any "<"
    # or ">", the reading is not added.
    assert not checker.QUOTE_AFTER_TAG_NAME.search("DV<b>AA <i x=1> '<' \"<\" <b\"x\"> <a")


@pytest.mark.parametrize("line", [
    "DV" + '<a x="' + '<a "="' * 20_000 + "AA",
    "DV" + "<a x='" + "<a '='" * 20_000 + "AA",
    "DV" + '<a x="' + "<a '\"='" * 20_000 + "AA",
])
def test_the_quoted_value_reading_reads_a_long_line_in_linear_time(line):
    # Read only after an "=", as CommonMark reads a quoted value, the quote after each "="
    # here would open a value holding the next "<a", so every tag would start inside a
    # quoted value of the tag before it, fall into step with it at the next quote and read
    # on to the end of the line: the first line took about 17 s so. Read wherever it stands
    # in a tag, the quote before each "=" opens a value that the quote after it closes, and
    # each tag stops at the next "<".
    checker = load_checker()
    assert checker.QUOTE_AFTER_TAG_NAME.search(line)
    start = time.perf_counter()
    checker.names(line, "DVAA")
    seconds = time.perf_counter() - start
    assert seconds < 3, f"{seconds:.2f} s"


# DVAA written in an HTML block with a tag whose quoted attribute value holds ">" on a line
# that also needs another rule a browser applies there: a tag name read as a browser reads
# one, "x\", 'x"y' or "x<y", a "<" after a tag name and a space, before or after the value,
# which a browser reads as part of an attribute name, or a numeric character reference with
# no closing ";". A browser applies them at once there, so each line shows "DVAA (99 agents,
# 77 vulnerability categories)"; Python 3.14's html.parser reads each tag as one, with the
# value whole. Each reading of the check applied one of these rules alone: the HTML block
# reading ended the tag at the ">" in the value, the reading that passes over quoted values
# read no tag at a "<" whose name a browser reads past "\", '"' or "<", or where a "<" that
# stands in no value came before the ">" that ends the tag, and in the last line the reading
# that decodes "&#65" ended the tag at the ">" in its value, while the reading that passes
# over it left "&#65" as written. The check found no DVAA on any of these lines and exited
# 0. A quoted value holding "<" alone needs no other rule there: the HTML block reading
# reads "DV<x\ y='<'>AA" past the "<".
HTML_BLOCK_QUOTED_NAMES = [
    ("tag name with a backslash and a quoted value holding >", 'DV<x\\ y=">">AA'),
    ("tag name with a quote and a quoted value holding >", 'DV<x"y z=">">AA'),
    ("tag name with a < and a quoted value holding >", 'DV<x<y z=">">AA'),
    ("< after a tag name and a space, then a quoted value holding >", 'DV<a <b x=">">AA'),
    ("quoted value holding > followed by a space and a <", 'DV<b x=">" <c>AA'),
    ("quoted value holding > before a reference with no closing ;", "DV<b x='>'>A&#65"),
]


@pytest.mark.parametrize("written", [w for _, w in HTML_BLOCK_QUOTED_NAMES],
                         ids=[case for case, _ in HTML_BLOCK_QUOTED_NAMES])
def test_a_name_in_an_html_block_needing_a_quoted_value_and_another_rule_leaves_the_line_read(
        written):
    td = scratch_tree()
    try:
        figures = f"{written} (99 agents, 77 vulnerability categories)"
        mutate_readme(td, LICENSE_LINE, f"{LICENSE_LINE}\n<div>\n{figures}\n</div>\n")
        line = where_of(td, figures)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"{line}: \"99 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"{line}: \"77 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_only_an_html_block_reading_with_quoted_values_passed_over_names_these_lines():
    # No reading the check made before names DVAA on these lines; each HTML block reading
    # made with quoted values passed over does, and `names` makes it where a quote stands on
    # a line read as a browser reads an HTML block or with quoted values passed over.
    checker = load_checker()
    for _, written in HTML_BLOCK_QUOTED_NAMES:
        for reading, references in ((checker.RAW_HTML, None), (checker.SPACE_OR_TAB_HTML, None),
                                    (checker.HtmlBlockHtml(), None), (checker.QUOTED_HTML, None),
                                    (checker.HtmlBlockHtml(), checker.HTML_BLOCK_REFERENCE)):
            assert not checker.holds(checker.name_form(written, reading, references=references),
                                     "DVAA"), (written, reading)
        assert checker.name_form(written, checker.HtmlBlockQuotedHtml(),
                                 references=checker.HTML_BLOCK_REFERENCE) == "DVAA", written
        if "&#" not in written:
            assert block_quoted_read(checker, written), written
            assert checker.name_form(written, checker.HtmlBlockQuotedHtml()) == "DVAA", written
        assert checker.names(written, "DVAA"), written
    # On 'DV<b x=">" <c>AA' no tag name is followed by another character, nor by a space and
    # a "<" before any ">": the reading is made there as the line is read with quoted values
    # passed over.
    written = 'DV<b x=">" <c>AA'
    assert not block_read(checker, written)
    assert checker.QUOTE_AFTER_TAG_NAME.search(written)
    # Where a quoted value holds "<" alone, the HTML block reading already reads the tag past
    # it.
    assert checker.name_form("DV<x\\ y='<'>AA", checker.HtmlBlockHtml()) == "DVAA"


@pytest.mark.parametrize("line", [
    'DV<a x="' + '<a" x="' * 20_000 + "AA",
    "DV<a x='" + "<a' x='" * 20_000 + "A&#65",
    "DV" + '<a x=">" ' * 30_000 + "AA",
    "DV" + '<a x=">" ' * 30_000 + ">AA",
], ids=["double quotes", "single quotes and a reference", "values holding > and no other >",
        "values holding > and a > at the end"])
def test_the_html_block_quoted_reading_reads_a_long_line_in_linear_time(line):
    # A tag name read as a browser reads one can hold a quote, which opens no value there. On
    # the first two lines the name of each tag after the first ends in the quote that closes
    # the value the tag before it opened, so it falls into step with that tag there and reads
    # on with it to the end of the line: step_one with HTML_BLOCK_QUOTED_HTML read the first
    # line, of 140,010 characters, in about 30 s on Python 3.14. HtmlBlockQuotedHtml notes
    # once where each tag name ends and where the text of each tag stops. A tag runs past
    # each "<" after its name and a space, so on the third line the pattern reads on from
    # each "<" to the end of the line and finds no ">" that stands in no value, and on the
    # last the tag from the first "<" runs to the ">" at the end.
    checker = load_checker()
    assert block_quoted_read(checker, line)
    start = time.perf_counter()
    checker.names(line, "DVAA")
    for references in (None, checker.HTML_BLOCK_REFERENCE):
        checker.name_form(line, checker.HtmlBlockQuotedHtml(), references=references)
    seconds = time.perf_counter() - start
    assert seconds < 3, f"{seconds:.2f} s"


# Lines that show "DVAA" with two wrong figures where a "]" stands directly before a "[",
# each set as its own paragraph after README's licence line, with the text the case gives
# added at the end of README.md. Where README.md defines no label DV, "[x]" in
# "[x][DV](y)AA" makes no link and CommonMark shows "[x]DVAA", DV linking to y; removing
# "][DV]" whether or not it made a link read "x(y)AA", and the first and third lines passed
# with exit 0, while the second, the same name with no "[x]", failed on both figures. A
# label the page defines, in another letter case too, and a blank label go with the "]"
# before them, also after a label the page does not define on the same line; and as a
# definition-like line in a fenced code block counts as a definition, the line is also read
# with no label removed and, holding two or three labels the page defines, with each mix of
# them removed and kept. With t defined and
# DV only in a fenced code block, CommonMark shows "[x][DV](u)[A][t]A" as "[x]DVAA", DV
# linking to u and A to t's destination: read with both labels removed it gave "x(u)AA",
# and with none "xDVAtA", and the line passed with exit 0. With a and b defined too,
# CommonMark shows "[x][DV](u)[A][t]A [y][a] [z][b]" as "[x]DVAA y z", and with "`][a]`
# `][b]`" in place of "[y][a] [z][b]" as "[x]DVAA ][a] ][b]": holding four labels the page
# defines, the "][" in a code span counted too, each line was read with all of them removed
# and with none only, and passed with exit 0. DV is defined on no definition line, so each
# is now also read with t, a and b removed and DV kept.
DEFINITION = "[d]: https://example.org"
FOUR_DEFINITIONS = ("[t]: https://example.org\n[a]: https://example.org\n"
                    "[b]: https://example.org\n\n```\n[DV]: https://example.org\n```")
LABEL_LINES = [
    ("label the page does not define", "[x][DV](y)AA", ""),
    ("link span with no label before it", "[DV](y)AA", ""),
    ("escaped bracket in a label the page does not define", "[x][\\[DV](y)AA", ""),
    ("label the page defines", "[DV][d]AA", DEFINITION),
    ("label the page defines in another letter case", "[DV][ D ]AA", DEFINITION),
    ("blank label", "[DV][ ]AA", ""),
    ("escaped bracket in a label the page defines", "[DV][d\\]]AA",
     "[d\\]]: https://example.org"),
    ("label the page defines after one it does not", "[q][DV](y)[A][d]A", DEFINITION),
    ("definition-like line in a fenced code block", "[x][DV](y)AA",
     "```\n[DV]: https://example.org\n```"),
    ("label the page defines beside one only a fenced code block defines",
     "[x][DV](u)[A][t]A", "[t]: https://example.org\n\n```\n[DV]: https://example.org\n```"),
    ("four labels the page defines, one only in a fenced code block",
     "[x][DV](u)[A][t]A [y][a] [z][b]", FOUR_DEFINITIONS),
    ("four labels the page defines, two after a ] in a code span",
     "[x][DV](u)[A][t]A `][a]` `][b]`", FOUR_DEFINITIONS),
]


@pytest.mark.parametrize("written,defined", [(w, d) for _, w, d in LABEL_LINES],
                         ids=[case for case, _, _ in LABEL_LINES])
def test_a_link_label_leaves_the_name_dvaa_read_as_commonmark_shows_it(written, defined):
    td = scratch_tree()
    try:
        line = f"{written} {FIGURES}"
        mutate_readme(td, LICENCE, f"{LICENCE}\n\n{line}\n")
        if defined:
            readme = td / "README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + f"\n{defined}\n",
                              encoding="utf-8")
        number = where_of(td, line)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"{number}: \"99 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"{number}: \"77 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def mixed_label_line(letters, removed):
    """A line whose name form holds `letters` read with the labels in `removed` removed, of
    the labels `letters` read as, each case folded: a letter whose label is removed is
    written "[D][d]", or "[*][d]D" for the last letter, which reads "D" with that label
    removed and "Dd", or "dD", with it kept, and any other "[*][D](u)", which reads "D" with
    the label kept and "(u)" with it removed."""
    segments = []
    for i, c in enumerate(letters):
        key = c.casefold()
        if key not in removed:
            segments.append(f"[*][{c}](u)")
        elif i < len(letters) - 1:
            segments.append(f"[{c}][{key}]")
        else:
            segments.append(f"[*][{key}]{c}")
    return "".join(segments)


def subsets(keys):
    return [frozenset(k for i, k in enumerate(keys) if mask >> i & 1)
            for mask in range(1 << len(keys))]


def test_a_line_with_three_labels_is_read_with_each_mix_removed_and_kept():
    # The page defines d, v and a, as `defined_labels` reads a page, and the line shows DVAA
    # where CommonMark finds a definition for exactly the labels removed, the others standing
    # only in a code block. Read with all three removed and with none, only two of the eight
    # lines named DVAA.
    checker = load_checker()
    labels = frozenset("dva")
    for removed in subsets("dva"):
        line = mixed_label_line("DVA", removed) + "A"
        assert checker.name_form(line, labels=removed) == "DVAA", line
        assert checker.names(line, "DVAA", labels=labels), line
        # A reading that removes some of the labels leaves code spans read wherever the
        # reading that removes none does, the reading span_lines takes.
        assert not checker.step_one(line, labels=removed)[1] or checker.step_one(line)[1]


def test_a_line_with_four_labels_is_read_with_all_removed_and_with_none_only():
    # U+FF21 FULLWIDTH LATIN CAPITAL LETTER A reads as A and case folds to a label of its own.
    # Every mix of four labels would be 16 readings of the line, each reading all of it. None
    # of the four is in `unsure` here.
    checker = load_checker()
    letters = "DVA\N{FULLWIDTH LATIN CAPITAL LETTER A}"
    keys = [c.casefold() for c in letters]
    labels = frozenset(keys)
    assert checker.MIXED_LABELS == 3
    for removed in subsets(keys):
        line = mixed_label_line(letters, removed)
        assert checker.name_form(line, labels=removed) == "DVAA", line
        assert checker.names(line, "DVAA", labels=labels) == (len(removed) in (0, 4)), line


def test_a_line_with_four_labels_is_read_with_each_mix_of_those_defined_on_no_definition_line():
    # As above, with the labels in `unsure` defined on no definition line, where CommonMark
    # may read no definition: one to three of them on the line are also read with each mix
    # of them removed and kept and the other labels removed, while four are read with all
    # removed and with none only, as with none in `unsure`. Of the 16 lines, those that a
    # reading removes exactly the labels of name DVAA, for each of the 16 sets in `unsure`.
    checker = load_checker()
    letters = "DVA\N{FULLWIDTH LATIN CAPITAL LETTER A}"
    keys = [c.casefold() for c in letters]
    labels = frozenset(keys)
    for unsure in subsets(keys):
        mixed = 0 < len(unsure) <= checker.MIXED_LABELS
        for removed in subsets(keys):
            line = mixed_label_line(letters, removed)
            read = len(removed) in (0, 4) or mixed and labels - unsure <= removed
            assert checker.names(line, "DVAA", labels=labels, unsure=unsure) == read, (
                line, sorted(unsure))


def test_a_definition_on_another_page_defines_no_label_on_this_one():
    # docs/overview.md defines d and README.md does not, so CommonMark shows "[DV][d]AA" on
    # README.md as written, which does not name DVAA, and its figures are not read; removing
    # every "][...]" span read "DVAA" there.
    td = scratch_tree()
    try:
        mutate_readme(td, LICENCE, f"{LICENCE}\n\n[DV][d]AA {FIGURES}\n")
        overview = td / "docs" / "overview.md"
        overview.write_text(overview.read_text(encoding="utf-8") + f"\n{DEFINITION}\n",
                            encoding="utf-8")
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
    finally:
        shutil.rmtree(td)


# A line where a "]" stands directly before a "[" and a tag name is followed by "\", set as
# its own paragraph after README's licence line on a page that defines the label DV:
# "[x][DV](url)A<y\>A <q\" names DVAA only read with no label removed and as a browser
# reads "<y\>" in an HTML block, as a tag named "y\". `names` reads the line with one
# HtmlBlockHtml with the label DV removed and then with none, and the first reading leaves
# it holding "<q\", a tag that finds no ">", which comes after "<y\>": holding it must not
# keep the reading with no label removed from removing "<y\>", or the line would pass with
# two wrong figures.
LABEL_AND_TAG_LINE = "[x][DV](url)A<y\\>A <q\\"


def test_a_tag_a_browser_reads_leaves_the_name_read_in_each_label_reading():
    td = scratch_tree()
    try:
        line = f"{LABEL_AND_TAG_LINE} {FIGURES}"
        mutate_readme(td, LICENCE, f"{LICENCE}\n\n{line}\n")
        readme = td / "README.md"
        readme.write_text(readme.read_text(encoding="utf-8")
                          + "\n[DV]: https://example.org\n", encoding="utf-8")
        number = where_of(td, line)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"{number}: \"99 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"{number}: \"77 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_one_html_block_reading_reads_a_line_alike_in_each_label_reading():
    checker = load_checker()
    labels = frozenset({"dv"})
    assert checker.names(LABEL_AND_TAG_LINE, "DVAA", labels=labels)
    for raw_html in (checker.RAW_HTML, checker.SPACE_OR_TAB_HTML):
        for removal in (labels, None):
            form = checker.name_form(LABEL_AND_TAG_LINE, raw_html, labels=removal)
            assert not checker.holds(form, "DVAA"), (form, removal)
    assert not checker.holds(checker.name_form(LABEL_AND_TAG_LINE, checker.HtmlBlockHtml(),
                                               labels=labels), "DVAA")
    # In the order `names` takes them, and again, one instance reads the line in each label
    # reading as a new one does.
    reading = checker.HtmlBlockHtml()
    for removal, form in ((labels, "x(url)AA <q\\"), (None, "xDVAA <q\\"),
                          (labels, "x(url)AA <q\\"), (None, "xDVAA <q\\")):
        assert checker.name_form(LABEL_AND_TAG_LINE, reading, labels=removal) == form
        assert checker.name_form(LABEL_AND_TAG_LINE, checker.HtmlBlockHtml(),
                                 labels=removal) == form


# Lines that show "DVAA" with two wrong figures where a "]" followed by "(" makes no link,
# as no "[" before it opens one, each set as its own paragraph after README's licence line.
# CommonMark shows "x](DV**AA**) (99 agents, 77 vulnerability categories)" as "x](DVAA) (99
# agents, 77 vulnerability categories)", and a browser shows the line with a style element
# holding text inside the name so too, and the line with a tag named "x\" inside the name
# between "<div>" and "</div>", in an HTML block. The check removed each "](...)" span
# whether or not it made a link, read "x (99 agents, 77 vulnerability categories)", found
# no DVAA and exited 0 on each line.
UNLINKED_SPAN_LINES = [
    ("strong emphasis in the name", [f"x](DV**AA**) {FIGURES}"]),
    ("style element in the name", [f"x](DV<style>x</style>AA) {FIGURES}"]),
    ("tag a browser reads in an HTML block in the name",
     ["<div>", f"x](DV<x\\>AA) {FIGURES}", "</div>"]),
]


@pytest.mark.parametrize("lines", [lines for _, lines in UNLINKED_SPAN_LINES],
                         ids=[case for case, _ in UNLINKED_SPAN_LINES])
def test_a_name_in_a_link_span_that_makes_no_link_leaves_the_line_read(lines):
    td = scratch_tree()
    try:
        mutate_readme(td, LICENCE, LICENCE + "\n\n" + "\n".join(lines) + "\n\n")
        number = where_of(td, next(line for line in lines if FIGURES in line))
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        for failure in (
            f"{number}: \"99 agents\" does not match related-projects.json "
            "(DVAA agents: 21)",
            f"{number}: \"77 vulnerability categories\" does not match "
            "related-projects.json (DVAA vulnerability categories: 12)",
        ):
            assert failure in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_each_reading_is_also_made_with_every_link_span_kept():
    checker = load_checker()
    # Removing every span leaves "x" of each line; keeping them, the name. The last line
    # holds a span only once the first step has removed the tags between "]" and "(":
    # CommonMark shows "x]<b></b>(DV**AA**)" as "x](DVAA)" too.
    for line, hide in (("x](DV**AA**)", False), ("x](DV<style>x</style>AA)", True),
                       ("x]<b></b>(DV**AA**)", False)):
        assert checker.name_form(line, hide_elements=hide) == "x", line
        for form in (checker.name_form(line, hide_elements=hide, link_spans=False),
                     stated_name_form(checker, line, hide_elements=hide, link_spans=False)):
            assert form == "x(DVAA)", (line, form)
        assert checker.names(line, "DVAA"), line
    # Read with RAW_HTML, "<x\>" is no tag, and only the HTML block reading with the span
    # kept holds the name.
    line = "x](DV<x\\>AA)"
    assert checker.name_form(line, checker.HtmlBlockHtml()) == "x"
    assert not checker.holds(checker.name_form(line, link_spans=False), "DVAA")
    assert checker.name_form(line, checker.HtmlBlockHtml(), link_spans=False) == "x(DVAA)"
    assert checker.names(line, "DVAA")
    # Written after "*", the mark counts as none directly after the name, but NFKC joins it
    # to the A in the form with the span kept: only the line `detached` gives, read with the
    # span kept, holds the name.
    line = "x](DV**AA**\N{COMBINING ACUTE ACCENT})"
    assert not checker.holds(checker.name_form(line, link_spans=False), "DVAA")
    assert checker.holds(checker.name_form(checker.detached(line), link_spans=False), "DVAA")
    assert checker.names(line, "DVAA")
    # A span that makes a link still goes with the reading that removes it.
    assert checker.name_form("[DV](url)AA") == "DVAA"
    assert checker.names("[DV](url)AA", "DVAA")


# Names the check does not read as DVAA: a reference to "*" or "&" shows that character
# rather than marking up text, a letter with an accent is not confusable with A, NFKC
# leaves U+00C1 composed, a comment that no line closes shows as text and runs to the end
# of the line, a character read as letters that do not stand together in "DVAA" shows them
# in another order, "DVAA" directly followed by a combining mark that NFKC joins to the last
# A shows another letter, also where the mark is joined past one NFKC leaves apart, and a
# "!" that does not stand before a "[" stays. A character a backslash escapes shows as
# itself, as does a backslash before a letter, and a code span shows its text as written.
# Such a line does not name DVAA, so its figures are not read. Read with the backticks and
# backslashes removed wherever they stood, each name from "backslash before an asterisk"
# to "backslash before an image" was read as DVAA.
OTHER_NAMES = [
    ("reference to an asterisk", "[DV&#42;AA]"),
    ("reference to an ampersand", "[DV&amp;AA]"),
    ("backslash before an asterisk", "[DV\\*AA]"),
    ("code span holding an asterisk", "[`DV*AA`]"),
    ("code span holding strong emphasis", "[`DV**AA**`]"),
    ("backslash before a backtick", "[DV\\`AA]"),
    ("backslash before a letter", "[D\\VAA]"),
    ("backslash before a tag", "[DV\\<b>AA]"),
    ("backslash before a character reference", "[DV\\&#65;A]"),
    ("backslash before an image", "[DV\\![](x.png)AA]"),
    ("hyphen", "[DV-AA]"),
    ("U+00C1 LATIN CAPITAL LETTER A WITH ACUTE", "[DV\N{LATIN CAPITAL LETTER A WITH ACUTE}A]"),
    ("U+00C1 LATIN CAPITAL LETTER A WITH ACUTE for the last A",
     "[DVA\N{LATIN CAPITAL LETTER A WITH ACUTE}]"),
    ("comment opened in a link destination that no line closes", "[DV](x <!-- y)AA"),
    ("U+0301 COMBINING ACUTE ACCENT after the name", "[DVAA\N{COMBINING ACUTE ACCENT}]"),
    ("U+0301 COMBINING ACUTE ACCENT after U+0410",
     "[DVA\N{CYRILLIC CAPITAL LETTER A}\N{COMBINING ACUTE ACCENT}]"),
    ("U+0332 COMBINING LOW LINE and U+0301 after the name",
     "[DVAA\N{COMBINING LOW LINE}\N{COMBINING ACUTE ACCENT}]"),
    ("U+0301 COMBINING ACUTE ACCENT and U+0332 after the name",
     "[DVAA\N{COMBINING ACUTE ACCENT}\N{COMBINING LOW LINE}]"),
    ("U+0308 COMBINING DIAERESIS after the name", "[DVAA\N{COMBINING DIAERESIS}]"),
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
        assert (f"{where_of(td, new)}:{column_of(td, new, named)}: a line naming DVAA "
                f"carries {named}, which can hide a figure from the DVAA wordings; "
                "remove it") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


# What a line reads as, where each case turns on one part of the three steps README
# states: the HTML is removed before the link spans, each kind of HTML is removed, closed
# or running to the end of the line, a tag ends after a quoted attribute, U+00A0 or "/",
# the "](...)" span goes whether or not a link is made, a "!" goes where it stands before
# a "[" once the link spans are removed and stays elsewhere, "_" is removed, a reference
# that fails a line leaves nothing, a reference to "*" shows it, and NFKC composes a mark
# with the letter before it. LABEL_FORMS below holds the cases where a "]" stands directly
# before a "[".
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
    ("link span that makes no link", "[x](see **DV**AA)", "x"),
    ("image", "DV![](x.png)AA", "DVAA"),
    ("exclamation mark before a link span", "DV!](x)[A]A", "DVAA"),
    ("exclamation mark not before a [", "DV!AA", "DV!AA"),
    ("underscores", "_DV_AA", "DVAA"),
    ("reference to U+200B", "DV&#8203;AA", "DVAA"),
    ("reference to an asterisk", "DV&#42;AA", "DV*AA"),
    ("backslash before an asterisk", "DV\\*AA", "DV*AA"),
    ("backslash before a letter", "D\\VAA", "D\\VAA"),
    ("backslash before a tag", "DV\\<b>AA", "DV<b>AA"),
    ("backslash before a reference", "DV\\&#65;A", "DV&#65;A"),
    ("escaped backtick", "\\`DV`AA`", "`DVAA"),
    ("code span", "`DV*AA`", "DV*AA"),
    ("code span with a space at each end", "` DV `AA", "DVAA"),
    ("code span closed by a run as long", "``DV`AA``", "DV`AA"),
    ("run of backticks no run closes", "`DV``AA", "DVAA"),
    ("code span holding a |", "`DV|*AA`", "DV|AA"),
    ("code span holding a <", "`<b>`DV*AA", "DVAA"),
    ("code span after a tag", "<b>`DV*AA`", "DV*AA"),
    ("code span after a tag holding a quote", "<b title='x'>`DV*AA`", "DVAA"),
    ("code span after an autolink", "<https://x.org>`DV*AA`", "<https://x.org>DV*AA"),
    ("code span after a link span holding a backtick", "[x](`)`DV*AA`", "xDVAA"),
    ("code span after a link span", "[x](y)`DV*AA`", "xDV*AA"),
    ("combining mark after the last A", "DVAA\N{COMBINING ACUTE ACCENT}",
     "DVA\N{LATIN CAPITAL LETTER A WITH ACUTE}"),
]


@pytest.mark.parametrize("text,form", [(t, f) for _, t, f in NAME_FORMS],
                         ids=[case for case, _, _ in NAME_FORMS])
def test_each_step_reads_a_line_as_stated(text, form):
    checker = load_checker()
    assert checker.name_form(text) == form
    assert stated_name_form(checker, text) == form


# What a line reads as in the reading that passes over quoted attribute values, where "/" or
# white space after a tag name is followed by a quote before any "<" or ">": a quote opens a
# value wherever it stands after that "/" or white space, with or without an "=" before it,
# and the next such quote closes it, past any "<" or ">"; a quote that no such quote follows
# is read as any other character, and a tag with a "<" in no value before its ">" is no tag,
# as in the first reading.
QUOTED_FORMS = [
    ("double-quoted value holding <", 'DV<b x="<">AA', "DVAA"),
    ("single-quoted value holding >", "DV<b title='>'>AA", "DVAA"),
    ("space and tab around the =", 'DV<b x =\t"<">AA', "DVAA"),
    ("value holding the other quote", "DV<b x='\">' y=\"'<\">AA", "DVAA"),
    ("value in a closing tag", 'DV</b x=">">AA', "DVAA"),
    ("value after U+00A0 after a tag name", 'DV<b\N{NO-BREAK SPACE}x="<">AA', "DVAA"),
    ("value after / after a tag name", 'DV<b/x="<">AA', "DVAA"),
    ("quote with no = before it", 'DV<b "<">AA', "DVAA"),
    ("text in the tag after a value", "DV<b x='>AA' y>", "DV"),
    ("quote that does not close", '<b x=")AA>', ""),
    ("< in no value", "DV<b x='<'<AA>", "DV<b x='<'"),
]


@pytest.mark.parametrize("text,form", [(t, f) for _, t, f in QUOTED_FORMS],
                         ids=[case for case, _, _ in QUOTED_FORMS])
def test_the_quoted_value_reading_reads_a_line_as_stated(text, form):
    checker = load_checker()
    assert checker.QUOTE_AFTER_TAG_NAME.search(text)
    assert checker.name_form(text, checker.QUOTED_HTML) == form
    assert stated_name_form(checker, text, quoted=True) == form


# What a line reads as in the HTML block readings made with quoted values passed over, where
# a quote stands on a line read as a browser reads an HTML block or with quoted values passed
# over, each with whether it is the one that decodes numeric references where they stand as
# written: a tag name runs from its first letter to the first tab, line feed, form feed,
# space, "/" or ">", over a quote, a "<" or U+00A0 too, and after the one of those that ends
# it each quote is passed over whole with the text up to the next such quote, as in the
# reading that passes over quoted values, and the tag runs past any "<" to the first ">"
# that stands in no such value, as in the HTML block reading; a reference in a quoted value
# goes with the tag, and the digits of one before a tag end at its "<".
HTML_BLOCK_QUOTED_FORMS = [
    ("tag name with a backslash", 'DV<x\\ y=">">AA', False, "DVAA"),
    ("tag name with a quote", 'DV<x"y z=">">AA', False, "DVAA"),
    ("tag name with a <", 'DV<x<y z=">">AA', False, "DVAA"),
    ("tag name with U+00A0", 'DV<x\N{NO-BREAK SPACE}y z="<">AA', False, "DVAA"),
    ("value after / after a tag name", 'DV<x\\/y="<">AA', False, "DVAA"),
    ("quote with no = before it", 'DV<x\\ "<">AA', False, "DVAA"),
    ("value in a closing tag", 'DV</x\\ y=">">AA', False, "DVAA"),
    ("text in the tag after a value", "DV<x\\ y='>AA' z>", False, "DV"),
    ("quote that does not close", 'DV<x\\ y=")AA>', False, "DV"),
    ("< in no value", "DV<x\\ y='<'<AA>", False, "DV"),
    ("< after a tag name and a space, before a value", 'DV<a <b x=">">AA', False, "DVAA"),
    ("< after a value and a space", 'DV<b x=">" <c>AA', False, "DVAA"),
    ("< in no value with no > after it in none", "DV<x\\ y='>'<AA", False,
     "DV<x\\ y='>'<AA"),
    ("reference after a tag with a quoted value", "DV<b x='>'>A&#65", True, "DVAA"),
    ("reference in a quoted value", "DV<b x='>A&#65'>A", True, "DVA"),
    ("reference ended by a tag with a quoted value", "&#x30<b x='>'>D<x\\ y=\">\">VAA", True,
     "0DVAA"),
]


@pytest.mark.parametrize("text,references,form",
                         [(t, r, f) for _, t, r, f in HTML_BLOCK_QUOTED_FORMS],
                         ids=[case for case, _, _, _ in HTML_BLOCK_QUOTED_FORMS])
def test_the_html_block_quoted_readings_read_a_line_as_stated(text, references, form):
    checker = load_checker()
    reference = checker.HTML_BLOCK_REFERENCE if references else None
    assert checker.name_form(text, checker.HtmlBlockQuotedHtml(), references=reference) == form
    assert stated_name_form(checker, text, html_block=True, quoted=True,
                            references=references) == form


# What a line reads as where a "]" stands directly before a "[", read with the labels the
# page defines, each written as the check compares it, or with None, the reading that
# removes no label. The label after the "]" goes with it where the page defines it, in any
# letter case and spacing, Unicode case folding U+1E9E LATIN CAPITAL LETTER SHARP S to "ss",
# or where it is blank, and is read as written, with no escape, code span or HTML read
# inside it; it ends at the first "]" no backslash escapes and is no label where an
# unescaped "[" comes first. Otherwise the "]" stays and the "[" after it is read on, so a
# link span it opens is removed, as in
# "[x][DV](y)AA", which CommonMark shows as "[x]DVAA" where the page does not define DV.
# Removing every "][...]" span read that line as "x(y)AA".
LABEL_FORMS = [
    ("label the page defines", "[DV][dvaa]AA", {"dvaa"}, "DVAA"),
    ("label the page does not define", "[DV][dvaa]AA", set(), "DVdvaaAA"),
    ("no label removed", "[DV][dvaa]AA", None, "DVdvaaAA"),
    ("label in another letter case with a space at each end", "[DV][ DvAA ]AA", {"dvaa"},
     "DVAA"),
    ("label with a run of white space inside", "[DV][d \t v]AA", {"d v"}, "DVAA"),
    ("label that case folds to the one defined", "[DV][\N{LATIN CAPITAL LETTER SHARP S}]AA",
     {"ss"}, "DVAA"),
    ("blank label", "[DV][ ]AA", set(), "DVAA"),
    ("blank label with no label removed", "[DV][ ]AA", None, "DV AA"),
    ("link span after a label the page does not define", "[x][DV](y)AA", set(), "xDVAA"),
    ("escaped bracket in a label the page does not define", "[x][\\[DV](y)AA", set(),
     "x[DVAA"),
    ("escaped bracket in a label the page defines", "[DV][a\\]b]AA", {"a\\]b"}, "DVAA"),
    ("code span in a label the page defines", "[DV][`x`]AA", {"`x`"}, "DVAA"),
    ("tag in a label the page defines", "[DV][a<b>]AA", {"a<b>"}, "DVAA"),
    ("tag in a label the page does not define", "[DV][a<b>]AA", set(), "DVaAA"),
    ("unescaped bracket in a label", "[DV][a[d]AA", {"a[d"}, "DVadAA"),
    ("label the page defines after one it does not", "[q][DV](y)[A][d]A", {"d"}, "qDVAA"),
    ("label longer than the 999 characters CommonMark allows", f"[DV][{'d' * 1000}]AA",
     {"d" * 1000}, "DVAA"),
]


@pytest.mark.parametrize("text,labels,form", [(t, l, f) for _, t, l, f in LABEL_FORMS],
                         ids=[case for case, _, _, _ in LABEL_FORMS])
def test_a_link_label_reads_as_stated(text, labels, form):
    checker = load_checker()
    defined = None if labels is None else frozenset(labels)
    assert checker.name_form(text, labels=defined) == form
    assert stated_name_form(checker, text, labels=defined) == form


# What a page defines: each label, read as a link label is, that a "[" no backslash escapes
# opens and ":" directly follows, wherever it stands, also across a line break or in a
# fenced code block, where CommonMark reads no definition; a blank label defines nothing.
DEFINITIONS = [
    ("definition", "[DVAA]: https://example.org", {"dvaa"}),
    ("indented definition with a title", '   [ D  v ]: <https://example.org> "t"', {"d v"}),
    ("escaped bracket in the label", "[a\\]b]: x", {"a\\]b"}),
    ("label across a line break", "[a\nb]: x", {"a b"}),
    ("definition-like line in a fenced code block", "```\n[DV]: x\n```", {"dv"}),
    ("escaped opening bracket", "\\[DV]: x", set()),
    ("escaped backslash before the opening bracket", "\\\\[DV]: x", {"dv"}),
    ("unescaped bracket in the label", "[a[DV]: x", {"dv"}),
    ("blank label", "[ ]: x", set()),
    ("label followed by a space", "[DV] : x", set()),
    ("reference link and link span", "[x][DV] and [DV](y)", set()),
    ("label longer than the 999 characters CommonMark allows", f"[{'d' * 1000}]: x",
     {"d" * 1000}),
]


@pytest.mark.parametrize("text,labels", [(t, l) for _, t, l in DEFINITIONS],
                         ids=[case for case, _, _ in DEFINITIONS])
def test_a_page_defines_the_labels_stated(text, labels):
    assert load_checker().defined_labels(text) == frozenset(labels)
    assert stated_defined_labels(text) == labels


# The labels a page defines on no definition line: a definition-like text stands on one
# where its "[" starts a line, after at most three spaces, outside a fenced code block. A
# fenced code block runs from a line that, after at most three spaces, starts with three or
# more backticks with no backtick after them on the line, or three or more tildes, to the
# first later line that is, after at most three spaces, a run of that character at least as
# long and nothing but spaces and tabs, or to the end of the page. A label defined on a
# definition line too is not one of them, and a text that defines nothing gives none.
UNSURE_DEFINITIONS = [
    ("definition line", "[t]: x", set()),
    ("definition line after three spaces", "   [t]: x", set()),
    ("definition-like text after four spaces", "    [t]: x", {"t"}),
    ("definition-like text after a tab", "\t[t]: x", {"t"}),
    ("definition-like text in a code span", "`[t]: x`", {"t"}),
    ("definition-like text after other text", "see [t]: x", {"t"}),
    ("definition-like text in a list item", "- [t]: x", {"t"}),
    ("definition-like text in a block quote", "> [t]: x", {"t"}),
    ("fenced code block", "```\n[t]: x\n```", {"t"}),
    ("fenced code block of tildes", "~~~\n[t]: x\n~~~", {"t"}),
    ("fenced code block after three spaces", "   ```\n[t]: x\n```", {"t"}),
    ("fenced code block with an info string", "```md\n[t]: x\n```", {"t"}),
    ("fenced code block that no line closes", "```\n[t]: x", {"t"}),
    ("definition line after a fenced code block", "```\n```\n[t]: x", set()),
    ("one label in a fenced code block and on a definition line",
     "```\n[t]: x\n```\n[t]: x", set()),
    ("shorter run in a fenced code block", "````\n```\n[t]: x\n````", {"t"}),
    ("run of the other character in a fenced code block", "```\n~~~\n[t]: x\n```", {"t"}),
    ("run with text after it in a fenced code block", "```\n``` x\n[t]: x\n```", {"t"}),
    ("closing run with spaces and a tab after it", "```\n[t]: x\n```  \t\n[a]: x", {"t"}),
    ("closing run after three spaces", "```\n[t]: x\n   ```\n[a]: x", {"t"}),
    ("run after four spaces in a fenced code block", "```\n    ```\n[t]: x", {"t"}),
    ("backtick run with a backtick after it", "```x`\n[t]: x", set()),
    ("tilde run with a backtick after it", "~~~x`\n[t]: x\n~~~", {"t"}),
    ("run after four spaces", "    ```\n[t]: x", set()),
    ("run of two backticks", "``\n[t]: x\n``", set()),
    ("label across a line break", "[a\nb]: x", set()),
    ("label across a line break after other text", "x [a\nb]: x", {"a b"}),
    ("escaped opening bracket", "\\[t]: x", set()),
    ("label followed by a space", "[t] : x", set()),
]


@pytest.mark.parametrize("text,labels", [(t, l) for _, t, l in UNSURE_DEFINITIONS],
                         ids=[case for case, _, _ in UNSURE_DEFINITIONS])
def test_a_page_defines_on_no_definition_line_the_labels_stated(text, labels):
    checker = load_checker()
    assert checker.unsure_labels(text) == frozenset(labels)
    assert checker.unsure_labels(text) <= checker.defined_labels(text)
    assert stated_unsure_labels(text) == labels


# What a line reads as with the text of each style, script and template element removed,
# the reading `names` adds where a "<" is followed by the name of one. An element runs from
# its start tag, in any ASCII letter case and with an attribute or a "/", to the end of the
# end tag of its name that closes it, or to the end of the line where none does; inside a
# style or script element no tag opens another, while a template element can hold any of
# the three, and an end tag closes the element opened last, only where it has that
# element's name. A "<" after a backslash starts no HTML, so it ends no element, and an end
# tag whose name is followed by U+00A0 or U+3000 closes none: a browser ends a tag name only
# at a tab, line feed, form feed, space, "/" or ">", so the name runs on past either.
# Rendered as a CommonMark paragraph and shown in Chromium, each line shows the text of its
# form but the last, which shows "DV-->AA": a browser ends the raw text of a style element
# at the first "</style>", here inside what CommonMark reads as a comment, which the first
# step removes whole. Neither names DVAA.
ELEMENT_FORMS = [
    ("style element", "DV<style>x</style>AA", "DVAA"),
    ("script element", "DV<script>x</script>AA", "DVAA"),
    ("template element", "DV<template>x</template>AA", "DVAA"),
    ("names in other letter cases", "DV<STYLE>x</Style>AA", "DVAA"),
    ("start tag with an attribute and end tag with a space",
     'DV<script type="a">x</script >AA', "DVAA"),
    ("start tag with a slash", "DV<style/>x</style>AA", "DVAA"),
    ("two elements", "D<style>x</style>V<script>y</script>AA", "DVAA"),
    ("element inside the name", "D<template>x</template>VAA", "DVAA"),
    ("no end tag follows", "DV<style>AA", "DV"),
    ("end tag of another element", "DV<style>x</script>AA", "DV"),
    ("template in a template", "DV<template><template></template>x</template>AA", "DVAA"),
    ("style in a template", "DV<template><style></template>x</style></template>AA", "DVAA"),
    ("template in a style", "DV<style><template>x</style>AA", "DVAA"),
    ("end tag of no open element", "DV<style><template></style>x</template>AA", "DVxAA"),
    ("code span in an element", "DV<style>`x`</style>AA", "DVAA"),
    ("end tag after a backslash", "DV<style>x\\</style>AA", "DV"),
    ("end tag with U+00A0 after the name", "DV<style>x</style\N{NO-BREAK SPACE}>AA", "DV"),
    ("end tag with U+3000 after the name", "DV<script>x</script\N{IDEOGRAPHIC SPACE}>AA",
     "DV"),
    ("end tag in a comment", "DV<style><!--</style>-->AA", "DV"),
]


@pytest.mark.parametrize("text,form", [(t, f) for _, t, f in ELEMENT_FORMS],
                         ids=[case for case, _, _ in ELEMENT_FORMS])
def test_the_text_of_an_element_is_removed_as_stated(text, form):
    checker = load_checker()
    assert checker.name_form(text, hide_elements=True) == form
    assert stated_name_form(checker, text, hide_elements=True) == form


# A browser ends a tag name only at a tab, line feed, form feed, space, "/" or ">", so
# "<style" U+00A0 ">" is a tag named "style" U+00A0, which opens no style element, and in a
# style element "</style" U+00A0 ">" is text. RAW_HTML removes either as a tag whose name
# ends at U+00A0; the element rule names it past that, in each reading, so the text after
# such a start tag stays and the text after such an end tag goes with the element to the
# end of the line. Neither line names DVAA.
def test_the_element_rule_ends_a_tag_name_where_a_browser_does():
    checker = load_checker()
    for end in "\t\n\f />":
        assert checker.TAG_START.match(f"<Style{end}x").group(2) == "Style", ascii(end)
    for space in ("\N{NO-BREAK SPACE}", "\N{IDEOGRAPHIC SPACE}", "\N{EM SPACE}"):
        assert checker.TAG_START.match(f"</style{space}x>").group(2) == f"style{space}x"
        for name in ("style", "script", "template"):
            for text, form in ((f"DV<{name}{space}>x</{name}>AA", "DVxAA"),
                               (f"DV<{name}>x</{name}{space}>AA", "DV")):
                for reading in (checker.RAW_HTML, checker.HtmlBlockHtml()):
                    assert (checker.name_form(text, reading, hide_elements=True)
                            == form), ascii(text)
                assert stated_name_form(checker, text, hide_elements=True) == form
                assert (stated_name_form(checker, text, html_block=True, hide_elements=True)
                        == form), ascii(text)
                assert not checker.names(text, "DVAA"), ascii(text)


# Where a tag name ends, read for each code point Python's \s matches, the white space an
# earlier element rule ended a name at, and for "/" and ">". The HTML block reading ends a
# tag name only at a tab, line feed, form feed, space, "/" or ">", as a browser does, and
# the element rule names a tag the same way in every reading, the checker with TAG_START
# and the plain scan with stated_tag: "<style" followed by any other white space opens no
# style element, and the HTML block reading, which removes it as a tag whose name holds
# that character, keeps the text after it.
def test_the_element_rule_ends_a_tag_name_where_the_html_block_reading_does():
    checker = load_checker()
    spaces = [chr(code) for code in range(sys.maxunicode + 1) if chr(code).isspace()]
    for c in spaces + ["/", ">"]:
        ends, tag = c in "\t\n\f />", f"<style{c}x>"
        assert (checker.TAG_START.match(tag).group(2) == "style") == ends, ascii(c)
        assert (checker.HTML_BLOCK_TAG_NAME.match(tag, 2).end() == 6) == ends, ascii(c)
        assert (stated_tag(tag, 0) == (False, "style")) == ends, ascii(c)
        if checker.hiding_kind(c) is None:
            text, form = f"DV<style{c}>x</style>AA", "DVAA" if ends else "DVxAA"
            assert (checker.name_form(text, checker.HtmlBlockHtml(), hide_elements=True)
                    == form), ascii(c)
            assert (stated_name_form(checker, text, html_block=True, hide_elements=True)
                    == form), ascii(c)
            assert checker.names(text, "DVAA") == ends, ascii(c)


# A start tag whose quoted attribute value holds "<" is a tag only in the reading that
# passes over quoted values and in the HTML block reading, which reads a "<" after a tag
# name and a space as part of the tag, and there it opens a style element as in the other
# readings: 'DV<style title="<">x</style>AA' names DVAA only read one of those ways with
# the text of the element removed, as a browser reads the value whole and shows no text of
# the element.
def test_a_start_tag_read_past_a_quoted_value_opens_an_element():
    checker = load_checker()
    line = 'DV<style title="<">x</style>AA'
    assert checker.QUOTE_AFTER_TAG_NAME.search(line)
    assert checker.LESS_THAN_AFTER_TAG_NAME.search(line)
    assert checker.name_form(line, checker.QUOTED_HTML, hide_elements=True) == "DVAA"
    assert stated_name_form(checker, line, quoted=True, hide_elements=True) == "DVAA"
    assert checker.name_form(line, checker.QUOTED_HTML) == "DVxAA"
    assert checker.name_form(line, checker.HtmlBlockHtml(), hide_elements=True) == "DVAA"
    assert stated_name_form(checker, line, html_block=True, hide_elements=True) == "DVAA"
    assert checker.name_form(line, checker.HtmlBlockHtml()) == "DVxAA"
    assert not checker.holds(checker.name_form(line, hide_elements=True), "DVAA")
    assert checker.names(line, "DVAA")


TAG_NAME = string.ascii_letters + string.digits + "-"

# The six characters at which a browser ends a tag name, the ones README states end a tag
# name in the HTML block reading and in the element rule of every reading: U+00A0, U+3000
# and the other white space Python's \s matches end none.
TAG_NAME_ENDS = "\t\n\f />"


def ascii_letter_at(text, i):
    return i < len(text) and text[i] in string.ascii_letters


def block_read(checker, line):
    """Whether `names` also reads `line` the HTML block way: where a tag name is followed by
    a character other than an ASCII letter, digit, hyphen, tab, line feed, form feed, space,
    "/" or ">", or by a tab, line feed, form feed, space or "/" and then by a "<" before any
    ">"."""
    return bool(checker.OTHER_CHARACTER_IN_TAG_NAME.search(line)
                or checker.LESS_THAN_AFTER_TAG_NAME.search(line))


def block_quoted_read(checker, line):
    """Whether `names` also reads `line` the HTML block way with quoted values passed over,
    with no numeric reference decoded: where a quote stands on a line it reads the HTML
    block way, and where "/" or white space after a tag name is followed by a quote before
    any "<" or ">"."""
    return bool(checker.QUOTE_AFTER_TAG_NAME.search(line)
                or (block_read(checker, line) and ('"' in line or "'" in line)))


def stated_html_end(line, i, any_space=True, html_block=False, quoted=False):
    """Where the HTML that README states starts at the "<" at line[i] ends, or None. With
    `any_space` false, as in the second reading README states where white space other than
    a space or tab follows a tag name, only a space, a tab or "/" lets a tag run on past
    its name to a ">". With `html_block` true, as in the reading README states where
    another character follows a tag name, or a "<" follows a tab, line feed, form feed,
    space or "/" after one, the name after its first letter runs on over any character
    other than a tab, line feed, form feed, space, "/" and ">", and after the name and one
    of the first five the tag runs on past any "<" to the first ">". With `quoted`
    true, as in the reading README states where a quote follows "/" or white space after a
    tag name, each quote after that "/" or white space is passed over with the text up to
    the next such quote, where one follows on the line."""
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
    j += 1
    while j < len(line) and (line[j] not in TAG_NAME_ENDS if html_block
                             else line[j] in TAG_NAME):
        j += 1
    if j < len(line) and line[j] == ">":
        return j + 1
    if j < len(line) and (line[j] == "/" or (line[j].isspace() if any_space
                                              else line[j] in " \t")):
        k = j + 1
        while k < len(line):
            if line[k] == ">":
                return k + 1
            if line[k] == "<" and not html_block:
                return None
            close = line.find(line[k], k + 1) if quoted and line[k] in "\"'" else -1
            k = close + 1 if close >= 0 else k + 1
    return None


def stated_numeric_end(line, i):
    """Where the numeric character reference a browser reads at the "&" at line[i] in an
    HTML block ends, as the line is written, or None: "&#" and the decimal digits after it
    or "&#x" or "&#X" and the hexadecimal digits after it run over every such digit and over
    a ";" directly after them, and need one digit or more."""
    if not line.startswith("&#", i):
        return None
    j, digits = i + 2, string.digits
    if line[j:j + 1] in ("x", "X"):
        j, digits = j + 1, string.hexdigits
    first = j
    while j < len(line) and line[j] in digits:
        j += 1
    if j == first:
        return None
    return j + 1 if line[j:j + 1] == ";" else j


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


def stated_label_end(text, start):
    """Where the link label README states opens at the "[" at text[start] ends, past its "]",
    or None: it runs to the first "]" that no backslash escapes, with no "[" that no
    backslash escapes before it, a backslash escaping the ASCII punctuation character after
    it."""
    escaped = False
    for k in range(start + 1, len(text)):
        if escaped:
            escaped = False
        elif text[k] == "\\":
            escaped = text[k + 1:k + 2] != "" and text[k + 1] in string.punctuation
        elif text[k] == "[":
            return None
        elif text[k] == "]":
            return k + 1
    return None


def stated_label_key(label):
    """Link label `label` as README states two labels are compared: after Unicode case
    folding, with white space at either end removed and each run of white space inside read
    as one space."""
    words, word = [], ""
    for c in label.casefold():
        if c.isspace():
            if word:
                words.append(word)
            word = ""
        else:
            word += c
    if word:
        words.append(word)
    return " ".join(words)


def stated_defined_labels(text):
    """The labels page `text` defines as README states: each label that a "[" no backslash
    escapes, one with an even run of backslashes before it, opens and ":" follows."""
    keys = set()
    for start, c in enumerate(text):
        run = 0
        while c == "[" and run < start and text[start - 1 - run] == "\\":
            run += 1
        end = stated_label_end(text, start) if c == "[" and not run % 2 else None
        if end is not None and text[end:end + 1] == ":" and stated_label_key(
                text[start + 1:end - 1]):
            keys.add(stated_label_key(text[start + 1:end - 1]))
    return keys


def stated_unsure_labels(text):
    """The labels page `text` defines on no definition line as README states: those of
    `stated_defined_labels` whose every definition-like text has its "[" anywhere but at
    the start of a line, after at most three spaces, outside a fenced code block, the page
    read line by line with a count of each run rather than the checker's patterns."""
    starts = set()
    fence = None  # the character and length of the run that opened the open block
    offset = 0
    for line in text.split("\n"):
        spaces = 0
        while line[spaces:spaces + 1] == " ":
            spaces += 1
        first = line[spaces:spaces + 1]
        run = 0
        while first in ("`", "~") and line[spaces + run:spaces + run + 1] == first:
            run += 1
        after = line[spaces + run:]
        fence_line = spaces <= 3 and run >= 3
        if fence is not None:
            if (fence_line and first == fence[0] and run >= fence[1]
                    and all(c in " \t" for c in after)):
                fence = None
        elif fence_line and not (first == "`" and "`" in after):
            fence = (first, run)
        elif spaces <= 3 and first == "[":
            starts.add(offset + spaces)
        offset += len(line) + 1
    sure, keys = set(), set()
    for start, c in enumerate(text):
        run = 0
        while c == "[" and run < start and text[start - 1 - run] == "\\":
            run += 1
        end = stated_label_end(text, start) if c == "[" and not run % 2 else None
        if end is not None and text[end:end + 1] == ":" and stated_label_key(
                text[start + 1:end - 1]):
            (sure if start in starts else keys).add(stated_label_key(text[start + 1:end - 1]))
    return keys - sure


def stated_name_form(checker, line, any_space=True, labels=None, html_block=False,
                     quoted=False, references=False, hide_elements=False, link_spans=True):
    """`line` read by the three steps README states, as a plain scan rather than with the
    checker's patterns, with `any_space` false as in the second reading, with `labels` the
    labels the page defines, or None for the reading that removes no label, with
    `html_block` true as in the HTML block readings, with `quoted` true as in the reading
    that passes over quoted attribute values, with `references` true, beside
    `html_block`, as in the HTML block reading that decodes each numeric reference where it
    stands as written, with or without a closing ";" and whatever its number of digits,
    with `hide_elements` true as in the readings that remove the text of style, script and
    template elements, and with `link_spans` false as in the readings that remove no "]"
    with the "(" and the text after it. A reference is decoded by html.unescape, as in the
    checker, and a decoded character that fails a line is dropped."""
    def shown(reference):
        return [c for c in html.unescape(reference) if not checker.hiding_kind(c)]

    # First, going along the line, its HTML is removed wherever it stands, the character a
    # backslash escapes and the text of each code span are kept as text, each pair marked,
    # and a "]" goes with the link label after it where the label is blank or defined; with
    # `references`, what a numeric reference shows, decoded where it stands, is kept as text
    # too.
    pairs = stated_first_step(line, any_space, labels=labels, html_block=html_block,
                              quoted=quoted, shown=shown if references else None,
                              hide_elements=hide_elements)[0]
    # Second, going along what remains, each "]" followed by "(" goes with the text after it
    # to the first ")" if no further "(" comes first, unless `link_spans` is false, then
    # each "!" directly before a "[", and then the Markdown characters, none of them kept as
    # text.
    def plain(k, chars):
        return k < len(pairs) and not pairs[k][1] and pairs[k][0] in chars

    kept, i = [], 0
    while i < len(pairs):
        if link_spans and plain(i, "]") and plain(i + 1, "("):
            j = i + 2
            while j < len(pairs) and not plain(j, "()"):
                j += 1
            if j < len(pairs) and pairs[j][0] == ")":
                i = j + 1
                continue
        kept.append(pairs[i])
        i += 1
    kept = [p for k, p in enumerate(kept)
            if p != ("!", False) or kept[k + 1:k + 2] != [("[", False)]]
    kept = [p for p in kept if p[1] or p[0] not in "*_~`[]"]
    # Third, its character references, of characters not kept as text, are decoded, less
    # the characters that fail a line, and it is brought to NFKC with each confusable
    # character read as its letters.
    text, i = [], 0
    while i < len(kept):
        if kept[i] == ("&", False):
            j = i
            while j < len(kept) and not kept[j][1]:
                j += 1
            run = "".join(c for c, _ in kept[i:j])
            end = stated_reference_end(run, 0)
            if end is not None:
                text.extend(shown(run[:end]))
                i += end
                continue
        text.append(kept[i][0])
        i += 1
    return unicodedata.normalize("NFKC", "".join(text)).translate(CONFUSABLE_LETTERS)


def stated_closed(line, i):
    """Whether a close follows the opening of the comment, processing instruction, CDATA
    section or declaration at line[i]; a tag always ends at its ">"."""
    for opening, close in (("<!--", "-->"), ("<?", "?>"), ("<![CDATA[", "]]>")):
        if line.startswith(opening, i):
            return line.find(close, i + len(opening)) >= 0
    return line.find(">", i + 3) >= 0 if line.startswith("<!", i) else True


def stated_stops_at_lt(line, i):
    """Whether code spans stop being read at the "<" at line[i], as README states."""
    end = stated_html_end(line, i)
    if end is not None:
        return not stated_closed(line, i) or any(c in "`'\"" for c in line[i:end])
    if line[i + 1:i + 2] in ("", " ", "\t") or not line[i + 1].isascii():
        return False
    close = line.find(">", i + 1)
    return close < 0 or any(c in "`'\"" for c in line[i + 1:close])


def stated_run_end(line, i):
    """Where the run of backticks starting at line[i] ends."""
    while i < len(line) and line[i] == "`":
        i += 1
    return i


def stated_tag(line, i):
    """(closing, name) for the tag README states at the "<" at line[i], `closing` whether it
    starts "</" and `name` its name with each ASCII capital letter written small, or None
    where no tag starts there. The name runs from its first letter to the first of
    TAG_NAME_ENDS, as a browser reads a tag name and as `stated_html_end` reads one in the
    HTML block reading, in every reading."""
    j = i + 2 if line.startswith("</", i) else i + 1
    if not ascii_letter_at(line, j):
        return None
    k = j + 1
    while k < len(line) and line[k] not in TAG_NAME_ENDS:
        k += 1
    name = "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in line[j:k])
    return j == i + 2, name


def stated_first_step(line, any_space=True, spans=True, labels=None, html_block=False,
                      quoted=False, shown=None, hide_elements=False):
    """(pairs, open): `line` after the first step README states, each character with
    whether it is kept as text, and whether the lines after it read no code span. A "]"
    directly followed by a link label that is blank or in `labels` goes with the label,
    which is not read further; with `labels` None no label goes. HTML is removed as
    `stated_html_end` reads it with `any_space`, `html_block` and `quoted`. With `shown`,
    which gives the characters a reference shows, each numeric reference
    `stated_numeric_end` reads at an "&" reached here, where it stands as written, goes with
    those characters, each kept as text. With `hide_elements` true, what stands from a
    start tag that opens a style, script or template element while none is open to the
    end of the end tag that closes it, or to the end of the line where none does, goes
    too: a start tag opens one unless a style or script element is open, and an end tag
    closes the one opened last where it has its name."""
    out, i, reading, unmatched = [], 0, spans, False
    # The style, script and template elements open, the last opened at the end, and how
    # many pairs `out` held where the first of them opened.
    open_elements, hidden_from = [], 0
    while i < len(line):
        c = line[i]
        if c == "<":
            if reading and stated_stops_at_lt(line, i):
                reading = False
            end = stated_html_end(line, i, any_space, html_block, quoted)
            if end is not None:
                tag = stated_tag(line, i) if hide_elements else None
                if tag is not None:
                    closing, name = tag
                    if closing and open_elements[-1:] == [name]:
                        open_elements.pop()
                        if not open_elements:
                            del out[hidden_from:]
                    elif (not closing and name in ("style", "script", "template")
                          and open_elements[-1:] not in (["style"], ["script"])):
                        if not open_elements:
                            hidden_from = len(out)
                        open_elements.append(name)
                i = end
                continue
        elif c == "\\" and line[i + 1:i + 2] != "" and line[i + 1] in string.punctuation:
            out.append((line[i + 1], True))
            i += 2
            continue
        elif c == "`":
            run = stated_run_end(line, i) - i
            if reading:
                close, j = None, i + run
                while j < len(line):
                    if line[j] != "`":
                        j += 1
                    elif stated_run_end(line, j) - j == run:
                        close = j
                        break
                    else:
                        j = stated_run_end(line, j)
                if close is None:
                    unmatched = True
                elif any(s in line[i + run:close] for s in "|<&"):
                    reading = False
                else:
                    text = line[i + run:close]
                    if text.startswith(" ") and text.endswith(" ") and text.strip(" "):
                        text = text[1:-1]
                    out.extend((t, True) for t in text)
                    i = close + run
                    continue
            out.extend((c, False) for _ in range(run))
            i += run
            continue
        elif c == "]" and line[i + 1:i + 2] in ("(", "["):
            if reading:
                close = ")" if line[i + 1] == "(" else "]"
                j = i + 2
                while j < len(line) and line[j] not in (line[i + 1], close):
                    j += 1
                if j == len(line) or line[j] != close or any(
                        u in line[i + 2:j] for u in "`'\"\\<"):
                    reading = False
            if labels is not None and line[i + 1] == "[":
                end = stated_label_end(line, i + 1)
                if end is not None and (not stated_label_key(line[i + 2:end - 1])
                                        or stated_label_key(line[i + 2:end - 1]) in labels):
                    i = end
                    continue
        elif c == "&" and shown is not None:
            end = stated_numeric_end(line, i)
            if end is not None:
                out.extend((s, True) for s in shown(line[i:end]))
                i = end
                continue
        out.append((c, False))
        i += 1
    if open_elements:
        del out[hidden_from:]
    return out, not reading or unmatched


# The generated lines are made of characters the first two steps act on, among them the
# backtick, the backslash, "|" and "'" that decide where code spans are read, and, for two
# pieces in five, of longer pieces: the openings and closes of HTML, character references,
# among them numeric ones that only the HTML block reading decodes, with no closing ";" or
# more digits than CommonMark reads, and ones whose digits a tag, a Markdown character or
# a letter ends as written, white space other than a space, and characters NFKC or
# the confusables read as A, D or V or leave beside them. Cases above pin orders of steps on
# their own: removing each "!" before the link spans rather than after them ("exclamation
# mark before a link span"), and in the second reading letting only a space and "/" end a
# tag name ("tab after a tag name in the second reading") or only a space and a tab ("slash
# after a tag name in the second reading").
MARKUP_CHARACTERS = "[]()DVAx \"*_~`\\<>|'"
PIECES = [
    *"/-!?=1&#;\t", "<x", "</A", "<!--", "-->", "<?", "?>", "<![CDATA[", "]]>", "<!",
    "&#68;", "&#x41;", "&#8203;", "&DD;", "&amp;", "&ast;", "&lowbar;",
    "&#86", "&#x41", "&#X44", "&#00000065;", "&#x0000056;", "&#x301", "&#x3", "&#6",
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
    # remove the same HTML. A line where a tag name is followed by another character, such
    # as "\", "<" or U+00A0, or by a space, a tab or "/" and then by a "<" before any ">",
    # is also read the HTML block way, with a tag name running to a tab, line feed, form
    # feed, space, "/" or ">" and a tag past any "<" after that to the first ">"; on any
    # other line that way reads the line as the first does. A line
    # where "/" or white space after a tag name is followed by a quote before any "<" or ">"
    # is also read with each quoted attribute value passed over whole; on any other line
    # that way reads the line as the first does. A line where "&" stands directly before "#"
    # is also read the HTML block way with each numeric reference decoded where it stands as
    # written, with or without a closing ";" and whatever its number of digits; on any other
    # line that way reads the line as the HTML block way does. A line holding a quote that
    # is read either HTML block way is also read that way with each quoted attribute value
    # passed over whole, and a line read the quoted value way is also read the first of
    # these new ways; on a line with no quote each of them reads the line as the HTML block
    # way it adds to does, on another line that the first is not read on, the first reads it
    # as the quoted value way does, and on a line with no "&#" the second reads it as the
    # first. A line holding "][" is also read with the labels in STATED_LABELS removed, the
    # first way and, where they apply, the HTML block ways and the quoted value way. A line
    # holding a "]" and a "(" is also read the first way with no "]" removed with the "("
    # and the text after it; on any other line the first step leaves no "]" followed by
    # "(", as it keeps each "]" and "(" it reads as text in a fullwidth form.
    checker = load_checker()
    rng = random.Random(80)
    for _ in range(STATED_LINES):
        line = generated_line(rng)
        plain = stated_name_form(checker, line)
        assert checker.name_form(line) == plain, ascii(line)
        assert checker.step_one(line)[1] == stated_first_step(line)[1], ascii(line)
        if "]" in line and "(" in line:
            assert (checker.name_form(line, link_spans=False)
                    == stated_name_form(checker, line, link_spans=False)), ascii(line)
        if any(c.isspace() and c not in " \t" for c in line):
            assert (checker.name_form(line, checker.SPACE_OR_TAB_HTML)
                    == stated_name_form(checker, line, any_space=False)), ascii(line)
        block = stated_name_form(checker, line, html_block=True)
        if block_read(checker, line):
            assert checker.name_form(line, checker.HtmlBlockHtml()) == block, ascii(line)
        else:
            assert block == plain, ascii(line)
        quoted = stated_name_form(checker, line, quoted=True)
        if checker.QUOTE_AFTER_TAG_NAME.search(line):
            assert checker.name_form(line, checker.QUOTED_HTML) == quoted, ascii(line)
        else:
            assert quoted == plain, ascii(line)
        decoded = stated_name_form(checker, line, html_block=True, references=True)
        if "&#" in line:
            assert (checker.name_form(line, checker.HtmlBlockHtml(),
                                      references=checker.HTML_BLOCK_REFERENCE)
                    == decoded), ascii(line)
        else:
            assert decoded == block, ascii(line)
        block_quoted = stated_name_form(checker, line, html_block=True, quoted=True)
        decoded_quoted = stated_name_form(checker, line, html_block=True, quoted=True,
                                          references=True)
        quote = '"' in line or "'" in line
        if not quote:
            assert block_quoted == block and decoded_quoted == decoded, ascii(line)
        elif block_quoted_read(checker, line):
            assert (checker.name_form(line, checker.HtmlBlockQuotedHtml())
                    == block_quoted), ascii(line)
        else:
            assert block_quoted == quoted, ascii(line)
        if quote and "&#" in line:
            assert (checker.name_form(line, checker.HtmlBlockQuotedHtml(),
                                      references=checker.HTML_BLOCK_REFERENCE)
                    == decoded_quoted), ascii(line)
        elif quote:
            assert decoded_quoted == block_quoted, ascii(line)
        if "][" in line:
            assert (checker.name_form(line, labels=STATED_LABELS)
                    == stated_name_form(checker, line, labels=STATED_LABELS)), ascii(line)
            if block_read(checker, line):
                stated = stated_name_form(checker, line, labels=STATED_LABELS,
                                          html_block=True)
                assert (checker.name_form(line, checker.HtmlBlockHtml(), labels=STATED_LABELS)
                        == stated), ascii(line)
            if checker.QUOTE_AFTER_TAG_NAME.search(line):
                stated = stated_name_form(checker, line, labels=STATED_LABELS, quoted=True)
                assert (checker.name_form(line, checker.QUOTED_HTML, labels=STATED_LABELS)
                        == stated), ascii(line)
            if "&#" in line:
                stated = stated_name_form(checker, line, labels=STATED_LABELS,
                                          html_block=True, references=True)
                assert (checker.name_form(line, checker.HtmlBlockHtml(), labels=STATED_LABELS,
                                          references=checker.HTML_BLOCK_REFERENCE)
                        == stated), ascii(line)
            if block_quoted_read(checker, line):
                stated = stated_name_form(checker, line, labels=STATED_LABELS,
                                          html_block=True, quoted=True)
                assert (checker.name_form(line, checker.HtmlBlockQuotedHtml(),
                                          labels=STATED_LABELS) == stated), ascii(line)
            if quote and "&#" in line:
                stated = stated_name_form(checker, line, labels=STATED_LABELS,
                                          html_block=True, quoted=True, references=True)
                assert (checker.name_form(line, checker.HtmlBlockQuotedHtml(),
                                          labels=STATED_LABELS,
                                          references=checker.HTML_BLOCK_REFERENCE)
                        == stated), ascii(line)


# Labels the generated lines are read with, as the check compares them, and the pieces of
# the lines and pages that the label rule reads: brackets, a backslash before each, the
# letters of those labels in either letter case, U+1E9E, which case folds to "ss", white
# space, a colon, and the characters that decide where code spans and HTML end.
STATED_LABELS = frozenset({"x", "dv", "a", "d v", "ss", "\\]"})
LABEL_PIECES = [
    *"[]()DVAadxs:` <>'\t\\", "\\[", "\\]", "\\\\", "][", "]:", "<b>",
    "\N{LATIN CAPITAL LETTER SHARP S}", "\N{NO-BREAK SPACE}",
]
LABEL_LINES_GENERATED = 100_000


def test_the_stated_label_rule_reads_every_generated_line_as_the_checker_does():
    # The label rule is stated in words in README and the script's description, and the
    # checker reads labels and definitions with its own scans; a clause that drifted from
    # them, such as a label ending at an escaped "]" or a definition opened by an escaped
    # "[", would leave the cases above passing. A removed label is passed over with the "]"
    # that closes it, so with labels removed code spans stop being read on no line where
    # they go on being read with none removed, the reading span_lines takes. A line where a
    # tag name is followed by another character, such as "\" or "[", or by a space, a tab or
    # "/" and then by a "<" before any ">", is read the HTML block way too, with one
    # HtmlBlockHtml in each label reading in turn, as `names` reads it, and
    # a line where "/" or white space after a tag name is followed by a quote before any "<"
    # or ">" is read the quoted value way in each label reading. Such a line holding "'", the
    # one quote among the pieces, and a line read the quoted value way, is also read the
    # HTML block way with quoted values passed over, with one HtmlBlockQuotedHtml in each
    # label reading in turn.
    checker = load_checker()
    rng = random.Random(152)
    for _ in range(LABEL_LINES_GENERATED):
        line = "".join(rng.choice(LABEL_PIECES) for _ in range(rng.randint(1, 16)))
        assert checker.defined_labels(line) == stated_defined_labels(line), ascii(line)
        for labels in (None, STATED_LABELS):
            assert (checker.name_form(line, labels=labels)
                    == stated_name_form(checker, line, labels=labels)), ascii(line)
            assert (checker.step_one(line, labels=labels)[1]
                    == stated_first_step(line, labels=labels)[1]), ascii(line)
        assert (not checker.step_one(line, labels=STATED_LABELS)[1]
                or checker.step_one(line)[1]), ascii(line)
        if block_read(checker, line):
            reading = checker.HtmlBlockHtml()
            for labels in (STATED_LABELS, None, STATED_LABELS):
                stated = stated_name_form(checker, line, labels=labels, html_block=True)
                assert checker.name_form(line, reading, labels=labels) == stated, ascii(line)
        if checker.QUOTE_AFTER_TAG_NAME.search(line):
            for labels in (STATED_LABELS, None):
                stated = stated_name_form(checker, line, labels=labels, quoted=True)
                assert (checker.name_form(line, checker.QUOTED_HTML, labels=labels)
                        == stated), ascii(line)
        if block_quoted_read(checker, line):
            reading = checker.HtmlBlockQuotedHtml()
            for labels in (STATED_LABELS, None, STATED_LABELS):
                stated = stated_name_form(checker, line, labels=labels, html_block=True,
                                          quoted=True)
                assert checker.name_form(line, reading, labels=labels) == stated, ascii(line)


# Pieces of the pages that the definition line rule reads: line breaks, spaces, a tab and
# other text before a "[" or a run, runs of backticks and tildes of each length that opens
# or closes a fenced code block or does neither, brackets, a colon, a backslash and letters.
DEFINITION_LINE_PIECES = [
    *"\n\n[]:`~\t\\tax", " ", "   ", "    ", "``", "```", "````", "~~~", "~~~~", "[t]: x",
    "\n```\n", "\n~~~\n", "\n[a]: x\n",
]
DEFINITION_PAGES_GENERATED = 100_000


def test_the_stated_definition_line_rule_reads_every_generated_page_as_the_checker_does():
    # The definition line rule is stated in words in README and the script's description,
    # and the checker reads it with FENCE and its own scan; a clause that drifted from them,
    # such as a run shorter than the one that opened a block closing it, or a run after four
    # spaces opening one, would leave the cases above passing. Of the labels a page defines,
    # those it defines on no definition line are a part.
    checker = load_checker()
    rng = random.Random(180)
    for _ in range(DEFINITION_PAGES_GENERATED):
        page = "".join(rng.choice(DEFINITION_LINE_PIECES) for _ in range(rng.randint(1, 24)))
        unsure = checker.unsure_labels(page)
        assert unsure == stated_unsure_labels(page), ascii(page)
        assert unsure <= checker.defined_labels(page), ascii(page)


# Pieces of lines that hold a tag with a quote after its name far more often than the lines
# above do: a tag name followed by a space, a tab, "/" or U+00A0, the quotes, "=", "<" and
# ">", "DV" and "AA", and the characters that decide where code spans and link spans end.
QUOTED_PIECES = [
    *"<>= \"'", "<x ", "</A\t", "<x/", "<x\N{NO-BREAK SPACE}", "DV", "AA", "`", "*", "\\",
    "](", ")", "[", "][",
]
QUOTED_LINES = 100_000


def test_the_stated_quoted_value_reading_reads_every_generated_line_as_the_checker_does():
    # Few of the lines above hold a quote after a tag name. Where one of these does, the
    # checker's QUOTED_HTML must read it as the plain scan that passes over quoted values
    # does; where none does, that scan must read it as the first reading does and
    # QUOTED_HTML must remove what RAW_HTML removes, so leaving the reading out there loses
    # nothing. At least 500 of the lines must read differently in the two readings, so the
    # comparison keeps meeting quoted values that hold "<" or ">".
    checker = load_checker()
    rng = random.Random(170)
    differing = 0
    for _ in range(QUOTED_LINES):
        line = "".join(rng.choice(QUOTED_PIECES) for _ in range(rng.randint(1, 16)))
        quoted = stated_name_form(checker, line, quoted=True)
        if checker.QUOTE_AFTER_TAG_NAME.search(line):
            form = checker.name_form(line, checker.QUOTED_HTML)
            assert form == quoted, ascii(line)
            differing += form != checker.name_form(line)
        else:
            assert quoted == stated_name_form(checker, line), ascii(line)
            assert (checker.step_one(line, checker.QUOTED_HTML)
                    == checker.step_one(line)), ascii(line)
    assert differing >= 500, differing


# Pieces of lines that hold, far more often than the lines above do, a tag name a browser
# reads past a character CommonMark ends one at, "\", a quote, "<" or U+00A0, beside quoted
# values, among them whole values holding ">" or "<", with numeric references with and
# without a closing ";", "DV" and "AA", and the characters that decide where code spans and
# link spans end.
BLOCK_QUOTED_PIECES = [
    *"<>= \"'/\t", "<x ", "<x\\ ", '<x"', "<x'", "<x<", "</A\\\t", "<x\N{NO-BREAK SPACE}",
    '">"', "'<'", "DV", "AA", "&#65", "&#x41;", "`", "*", "\\", "](", ")", "[", "][",
]
BLOCK_QUOTED_LINES = 100_000


def test_the_stated_html_block_quoted_readings_read_every_generated_line_as_the_checker_does():
    # At each place on a line, HtmlBlockQuotedHtml must match what HTML_BLOCK_QUOTED_HTML
    # matches there, and the HTML block readings made with it must read the line as the
    # plain scan that reads a tag name as a browser does and passes over quoted values does,
    # with and without numeric references decoded where they stand. One instance reads every
    # line, and at least 500 of the lines must read differently from both the HTML block
    # reading and the quoted value reading, so the comparison keeps meeting tags that only
    # the two rules at once read as a browser does.
    checker = load_checker()
    rng = random.Random(183)
    reading = checker.HtmlBlockQuotedHtml()
    differing = 0
    for _ in range(BLOCK_QUOTED_LINES):
        line = "".join(rng.choice(BLOCK_QUOTED_PIECES) for _ in range(rng.randint(1, 16)))
        for pos in range(len(line)):
            found = reading.match(line, pos)
            expected = checker.HTML_BLOCK_QUOTED_HTML.match(line, pos)
            assert ((found and found.span())
                    == (expected and expected.span())), (ascii(line), pos)
        for references in (False, True):
            form = checker.name_form(
                line, reading, references=checker.HTML_BLOCK_REFERENCE if references else None)
            assert form == stated_name_form(checker, line, html_block=True, quoted=True,
                                            references=references), ascii(line)
        form = checker.name_form(line, reading)
        differing += (form != checker.name_form(line, checker.HtmlBlockHtml())
                      and form != checker.name_form(line, checker.QUOTED_HTML))
    assert differing >= 500, differing


# Pieces of lines that hold, far more often than the lines above do, a tag whose name ends
# where CommonMark ends one, at a space or "/", with quoted values holding ">", a "<" after
# such a value, "DV" and "AA", and the characters that decide where code spans and link
# spans end.
PLAIN_NAME_QUOTED_PIECES = [
    *"<>= \"'/\t", "<x ", "</b ", "<x/", '">"', "'>'", "DV", "AA", "`", "*", "\\", "](", ")",
    "[", "][",
]
PLAIN_NAME_QUOTED_LINES = 100_000


def test_a_line_read_with_quoted_values_passed_over_is_read_the_html_block_way_with_them_too():
    # Where no tag name is followed by a character a browser reads on past, nor by white
    # space or "/" and a "<" before any ">", a "<" that stands in no quoted value can still
    # follow a value in a tag, as in 'DV<b x=">" <c>AA', where only the HTML block reading
    # made with quoted values passed over reads the tag on past it. `names` makes that
    # reading on each line it reads with quoted values passed over, and there the reading
    # must read the line as the plain scan does. On a line it does not make it on, the
    # reading must remove what the reading that passes over quoted values removes, or on a
    # line with no quote what the HTML block reading removes. At least 500 of the lines must
    # be read so only because the reading that passes over quoted values is made on them,
    # and read differently from it.
    checker = load_checker()
    rng = random.Random(184)
    reading = checker.HtmlBlockQuotedHtml()
    needed = 0
    for _ in range(PLAIN_NAME_QUOTED_LINES):
        line = "".join(rng.choice(PLAIN_NAME_QUOTED_PIECES)
                       for _ in range(rng.randint(1, 16)))
        form = checker.name_form(line, reading)
        if block_quoted_read(checker, line):
            assert form == stated_name_form(checker, line, html_block=True,
                                            quoted=True), ascii(line)
            needed += (not block_read(checker, line)
                       and form != checker.name_form(line, checker.QUOTED_HTML))
        elif '"' in line or "'" in line:
            assert form == checker.name_form(line, checker.QUOTED_HTML), ascii(line)
        else:
            assert form == checker.name_form(line, checker.HtmlBlockHtml()), ascii(line)
    assert needed >= 500, needed


# The pieces of the lines the element rule is read on: start and end tags of the three
# elements, in lower case and with capitals, with a space or "/" after the name, with
# U+00A0 or U+3000 after it, which a browser does not end a tag name at, with no ">", or
# with an attribute value opened by a quote, the tags of another element, a tag name the
# HTML block reading runs on past "\", the opening and close of a comment, and the
# characters that decide where code spans, escapes, link spans and link labels start and
# end.
ELEMENT_PIECES = [
    *"DVAx `\\<>/'\"|[]()!*&#;\t", "<style>", "</style>", "<script>", "</script>",
    "<template>", "</template>", "<STYLE ", "</Script", "<Template/", "<style",
    "</template ", "<script\N{NO-BREAK SPACE}", "</Style\N{IDEOGRAPHIC SPACE}", "<b>", "</b>",
    "<style\\", "<!--", "-->", "][", "\N{NO-BREAK SPACE}", "\N{IDEOGRAPHIC SPACE}",
    '<style x="',
]
ELEMENT_LINES_GENERATED = 100_000


class RecordedHtml:
    """A raw HTML pattern that records each place it is asked to match at."""

    def __init__(self, pattern):
        self.pattern, self.places = pattern, []

    def match(self, text, pos):
        self.places.append(pos)
        return self.pattern.match(text, pos)


def test_the_stated_element_rule_reads_every_generated_line_as_the_checker_does():
    # The element rule is stated in words on the cross-framework mapping page and in the
    # script's description, and the checker reads it with its own tag pattern; a clause that
    # drifted from them, such as a template opening inside a style element or an end tag
    # closing an element other than the one opened last, would leave the cases above
    # passing. Each line is read with the elements' text removed the first way and, where
    # they apply, the second way, the HTML block way, with one HtmlBlockHtml serving the
    # readings with and without the text removed, the way that passes over quoted attribute
    # values, the HTML block ways that pass over them, with one HtmlBlockQuotedHtml serving
    # those readings, and with the labels in STATED_LABELS removed. Removing an element's text
    # passes over no place on the line: `open` and the places the raw HTML is matched at do
    # not turn on it, and a line where no "<" is followed by the name of such an element
    # reads alike either way.
    checker = load_checker()
    rng = random.Random(172)
    for _ in range(ELEMENT_LINES_GENERATED):
        line = "".join(rng.choice(ELEMENT_PIECES) for _ in range(rng.randint(1, 16)))
        hidden = stated_name_form(checker, line, hide_elements=True)
        assert checker.name_form(line, hide_elements=True) == hidden, ascii(line)
        kept, removed = RecordedHtml(checker.RAW_HTML), RecordedHtml(checker.RAW_HTML)
        assert (checker.step_one(line, kept)[1]
                == checker.step_one(line, removed, hide_elements=True)[1]), ascii(line)
        assert kept.places == removed.places, ascii(line)
        if not checker.HIDDEN_ELEMENT_START.search(line):
            assert hidden == stated_name_form(checker, line), ascii(line)
        if any(c.isspace() and c not in " \t" for c in line):
            assert (checker.name_form(line, checker.SPACE_OR_TAB_HTML, hide_elements=True)
                    == stated_name_form(checker, line, any_space=False,
                                        hide_elements=True)), ascii(line)
        if block_read(checker, line):
            # One HtmlBlockHtml reads the line with and without the elements' text removed
            # in turn, as `names` reads it.
            reading = checker.HtmlBlockHtml()
            for hide in (True, False, True):
                stated = stated_name_form(checker, line, html_block=True, hide_elements=hide)
                assert (checker.name_form(line, reading, hide_elements=hide)
                        == stated), ascii(line)
        if checker.QUOTE_AFTER_TAG_NAME.search(line):
            assert (checker.name_form(line, checker.QUOTED_HTML, hide_elements=True)
                    == stated_name_form(checker, line, quoted=True,
                                        hide_elements=True)), ascii(line)
        if '"' in line or "'" in line:
            # One HtmlBlockQuotedHtml reads the line with and without the elements' text
            # removed, and with numeric references decoded where they stand, in turn.
            reading = checker.HtmlBlockQuotedHtml()
            for hide, references in ((True, False), (False, True), (True, True)):
                stated = stated_name_form(checker, line, html_block=True, quoted=True,
                                          references=references, hide_elements=hide)
                assert (checker.name_form(
                    line, reading, hide_elements=hide,
                    references=checker.HTML_BLOCK_REFERENCE if references else None)
                        == stated), ascii(line)
        if "][" in line:
            assert (checker.name_form(line, labels=STATED_LABELS, hide_elements=True)
                    == stated_name_form(checker, line, labels=STATED_LABELS,
                                        hide_elements=True)), ascii(line)


# Lines of 50,000 elements: templates opened one inside another and then closed, style
# elements one after another, and start tags inside one style element that no end tag
# closes. The text of an element is removed once, when the element that opened while none
# was open closes or the line ends. Removed by re.sub with a pattern from a start tag to
# the first end tag after it, which is tried at each start tag and reads on to the end of
# the line from each where no end tag follows, the last line took about 54 s on Python
# 3.14, and the same line of 10,000 start tags about 1.7 s.
ELEMENT_RUNS = 50_000
LONG_ELEMENT_LINES = [
    ("templates in templates",
     "DV" + "<template>" * ELEMENT_RUNS + "x" + "</template>" * ELEMENT_RUNS + "AA", "DVAA"),
    ("style elements one after another", "DV" + "<style>x</style>" * ELEMENT_RUNS + "AA",
     "DVAA"),
    ("start tags in a style element no end tag closes",
     "DV" + "<style>x" * ELEMENT_RUNS + "AA", "DV"),
]


@pytest.mark.parametrize("line,form", [(text, form) for _, text, form in LONG_ELEMENT_LINES],
                         ids=[case for case, _, _ in LONG_ELEMENT_LINES])
def test_the_element_reading_reads_a_long_line_in_linear_time(line, form):
    checker = load_checker()
    start = time.perf_counter()
    read = checker.name_form(line, hide_elements=True)
    seconds = time.perf_counter() - start
    assert read == form
    assert seconds < 3, f"{seconds:.2f} s"


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


LABEL_RUNS = 100_000
LONG_LABEL_TEXTS = [
    # A "[" and then escaped brackets only: no "[" that no backslash escapes follows the
    # first, so one scan reads to the end and no other starts.
    ("a page of escaped brackets", lambda checker: checker.defined_labels(
        "[" + "\\[" * LABEL_RUNS), frozenset()),
    # A label after each "]", every other one defined: each is scanned up to its own "]".
    ("a line of labels", lambda checker: checker.name_form(
        "[DV" + "][x][y" * LABEL_RUNS + "]AA", labels=frozenset({"x"})),
     "DV" + "y" * LABEL_RUNS + "AA"),
]


@pytest.mark.parametrize("read,result", [(r, v) for _, r, v in LONG_LABEL_TEXTS],
                         ids=[case for case, _, _ in LONG_LABEL_TEXTS])
def test_link_labels_and_definitions_are_read_in_linear_time(read, result):
    # A label is scanned only up to the first "[" or "]" after its "[" that no backslash
    # escapes, and a page only from each "[" that none escapes, so the page of 200,001
    # characters and the line of 600,006 here are each read in under a second.
    checker = load_checker()
    start = time.perf_counter()
    got = read(checker)
    seconds = time.perf_counter() - start
    assert got == result
    assert seconds < 1, f"{seconds:.2f} s"


def test_a_line_of_many_labels_the_page_defines_is_read_in_linear_time():
    # Read with each label removed on its own and kept on its own, a line of 8,895
    # characters holding 1,000 labels the page defines took about 3.5 s, as each of its
    # readings reads the whole line. A line holding more than MIXED_LABELS of them is
    # read with all removed and with none only: this line of 98,895 characters holding
    # 10,000 such labels took about 0.05 s.
    checker = load_checker()
    keys = [f"k{i}" for i in range(10_000)]
    line = "[q" + "".join(f"][{key}][y" for key in keys) + "]AA"
    start = time.perf_counter()
    named = checker.names(line, "DVAA", labels=frozenset(keys))
    seconds = time.perf_counter() - start
    assert not named
    assert len(checker.label_removals(line, frozenset(keys))) == 2
    assert seconds < 1, f"{seconds:.2f} s"


@pytest.mark.parametrize("page,unsure", [
    # A fenced code block of 100,000 definitions, 700,004 characters.
    ("```\n" + "[d]: x\n" * LABEL_RUNS, {"d"}),
    # A block that 100,000 shorter runs leave open, 400,011 characters.
    ("````\n" + "```\n" * LABEL_RUNS + "[d]: x", {"d"}),
], ids=["a fenced code block of definitions", "a fenced code block of shorter runs"])
def test_definition_lines_are_read_in_linear_time(page, unsure):
    # Each line of a page is read once for the definition line rule, and the page once for
    # its definition-like texts, so each of these pages is read in under a second.
    checker = load_checker()
    start = time.perf_counter()
    got = checker.unsure_labels(page)
    seconds = time.perf_counter() - start
    assert got == frozenset(unsure)
    assert seconds < 1, f"{seconds:.2f} s"


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
    # In the HTML block reading a reference with no closing ";" is a reference too, and one
    # to a mark is put apart; as CommonMark reads references, the line holds none, and
    # nothing is put apart.
    assert (checker.detached("DVA&#65&#x301", checker.HTML_BLOCK_REFERENCE)
            == "DVA&#65" + checker.BREAK + "&#x301")
    assert checker.detached("DVA&#65&#x301") == "DVA&#65&#x301"
    # No ASCII character is a combining mark, so none after the name needs a lookup.
    assert not any(checker.is_mark(code) for code in range(128))


def test_a_label_reads_alike_in_the_line_detached_gives():
    # NFKC joins the mark after "**AA**" to the A, so the line names DVAA only once detached
    # puts that mark apart; it puts apart the mark after "-" inside the label too, and the
    # label must still be the one the page defines for "][-" U+0301 "]" to be removed.
    checker = load_checker()
    line = "[DV][-\N{COMBINING ACUTE ACCENT}]**AA**\N{COMBINING ACUTE ACCENT}"
    assert checker.BREAK in checker.detached(line).split("]")[1]
    assert checker.names(line, "DVAA", labels=frozenset({"-\N{COMBINING ACUTE ACCENT}"}))
    assert not checker.names(line, "DVAA", labels=frozenset())


def test_the_no_break_space_example_is_a_form_only_the_second_reading_names():
    # README and the checker's description gave '[DV](url "<b' U+00A0 'x=")AA' as the form a
    # no-break space after a tag name no longer hides. No ">" follows it, so no tag is
    # removed and the first reading already named DVAA; with the final ">" the first reading
    # removes "AA" with the tag, and only the second reading names DVAA. The README's
    # description of the check moved to the cross-framework mapping page. The quote after
    # "x=" closes on no later quote, so the reading that passes over quoted values removes
    # "AA" with the tag as the first reading does.
    checker = load_checker()
    readme = (ROOT / "docs" / "cross-framework-mapping.md").read_text(encoding="utf-8")
    sentence = next(line for line in readme.split("\n") if "So the name written as" in line)
    examples = re.findall(r"`([^`]*)` U\+00A0 `([^`]*)`", sentence)
    assert len(examples) == 1, examples
    before, after = examples[0]
    assert f'"{before}" U+00A0 "{after}"' in " ".join(checker.__doc__.split())
    written = before + "\N{NO-BREAK SPACE}" + after
    assert checker.OTHER_SPACE_AFTER_TAG_NAME.search(written)
    assert not checker.holds(checker.name_form(written, checker.RAW_HTML), "DVAA")
    assert not checker.holds(checker.name_form(written, checker.QUOTED_HTML), "DVAA")
    assert checker.holds(checker.name_form(written, checker.SPACE_OR_TAB_HTML), "DVAA")
    assert checker.names(written, "DVAA")


def test_a_line_naming_dvaa_and_stating_a_count_names_both():
    td = scratch_tree()
    try:
        new = "environment (21 agents, 12 vulnerability categories; 9\N{ZERO WIDTH SPACE} tactics)"
        mutate_readme(td, "environment (21 agents, 12 vulnerability categories)", new)
        named = "U+200B ZERO WIDTH SPACE, a format character"
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert (f"{where_of(td, new)}:{column_of(td, new, named)}: a line naming DVAA "
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
        line = where_of(td, new)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        on_line = [f for f in r.stderr.split("\n") if f.startswith(f"  - {line}:")]
        assert on_line == [
            f"  - {line}:{column_of(td, new, named)}: a line naming DVAA carries "
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
    # A wording is bounded by the absence of a Unicode word character or combining mark,
    # and the punctuation README puts around a figure is neither, so it is still read.
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
    # The checker reads README.md and then each page in PAGES, closing each page with a
    # line break, and reads the DVAA wordings on the lines that name DVAA alone. So the
    # mark goes at the end of the last page, on a line that names DVAA: only there is it
    # the last character of the text the wording is read in but for that line break.
    td = scratch_tree()
    try:
        first, last = readme_pages()[0], readme_pages()[-1]
        readme = td / first
        readme.write_text("22 agents in DVAA\n" + readme.read_text(encoding="utf-8"),
                          encoding="utf-8")
        page = td / last
        ending = "DVAA e\N{COMBINING ACUTE ACCENT}"
        page.write_text(f"{page.read_text(encoding='utf-8').rstrip(chr(10))}\n{ending}",
                        encoding="utf-8")
        checker = load_checker()
        lines = [checker.classified(line) for line in checker.Pages(td).text.split("\n")]
        naming = [checker.names(stripped, "DVAA", bool(hidden))
                  for _, stripped, hidden in lines]
        read = checker.lines_naming(lines, naming)
        assert read.startswith("22 agents in DVAA\n"), read[:40]
        assert read.endswith(f"\n{ending}\n"), read[-40:]
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
        # The README as the check reads it: README.md and its pages, joined.
        text = load_checker().Pages(td).text
        dvaa_text ="\n".join(line if "DVAA" in line else "" for line in text.split("\n"))
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
    text = (ROOT / CLASS_PAGE).read_text(encoding="utf-8")
    block = text[text.index(BEGIN):text.index(END)]
    missing = []
    for cls in matrix["attackClasses"]:
        cell = cls["description"].replace(" — ", ": ").replace("|", "\\|")
        if f"| [{cls['id']}](../attack-classes/{cls['id']}.md) | {cell} |" not in block:
            missing.append(cls["id"])
    assert missing == [], f"README rows not matching matrix.json: {missing}"


def test_a_reworded_class_description_is_red():
    td = scratch_tree()
    try:
        mutate_readme(td, f"| {GATEWAY_DESCRIPTION} |",
                      "| Misconfigured API gateways exposing agent infrastructure |")
        line = where_of(td, "Misconfigured API gateways")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert f"{line}: the attack-class tables differ from matrix.json" in r.stderr, \
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
        pages = {rel: (td / rel).read_text(encoding="utf-8") for rel in readme_pages()}
        before = pages[CLASS_PAGE]

        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert "the attack-class tables differ from matrix.json" in r.stderr, r.stderr

        r = run_checker(td, "--fix")
        assert r.returncode == 0, r.stderr
        assert "FIXED: rewrote the attack-class tables" in r.stdout
        after = (td / CLASS_PAGE).read_text(encoding="utf-8")
        assert "| Rewritten in the data: with a pipe a\\|b |" in after
        assert GATEWAY_DESCRIPTION not in after
        # Only the generated block moved, and no other page was written.
        assert after[:after.index(BEGIN)] == before[:before.index(BEGIN)]
        assert after[after.index(END):] == before[before.index(END):]
        for rel, text in pages.items():
            if rel != CLASS_PAGE:
                assert (td / rel).read_text(encoding="utf-8") == text, rel

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


def end_class_table_marker_on_readme(root: Path) -> None:
    """BEGIN on the attack-classes page and END on README.md, which the checker reads
    first: END comes before BEGIN in the text."""
    mutate_readme(root, END, "")
    readme = root / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + END + "\n", encoding="utf-8")


def split_class_table_markers(root: Path) -> None:
    """BEGIN on the attack-classes page and END on the first line of the page the checker
    reads after it: each marker occurs once and BEGIN comes first."""
    pages = readme_pages()
    mutate_readme(root, END, "")
    after = root / pages[pages.index(CLASS_PAGE) + 1]
    after.write_text(END + "\n" + after.read_text(encoding="utf-8"), encoding="utf-8")


def test_class_table_end_marker_before_begin_is_red():
    # BEGIN on the attack-classes page and END on README.md, which the checker reads
    # first: END comes before BEGIN in the text.
    td = scratch_tree()
    try:
        end_class_table_marker_on_readme(td)
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert "the attack-class tables need exactly one" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_class_table_markers_on_two_pages_are_red():
    # BEGIN on the attack-classes page and END on the first line of the page the checker
    # reads after it: each marker occurs once and BEGIN comes first, so only the one-page
    # condition rejects the block, which neither the check nor --fix can read as one block.
    td = scratch_tree()
    try:
        split_class_table_markers(td)
        before = {rel: (td / rel).read_text(encoding="utf-8") for rel in readme_pages()}

        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert "the attack-class tables need exactly one" in r.stderr, r.stderr

        r = run_checker(td, "--fix")
        assert r.returncode == 1, r.stdout
        assert "the attack-class tables need exactly one" in r.stderr, r.stderr
        for rel, text in before.items():
            assert (td / rel).read_text(encoding="utf-8") == text, rel
    finally:
        shutil.rmtree(td)


@pytest.mark.parametrize("break_markers", [
    lambda root: mutate_readme(root, BEGIN, ""),
    lambda root: mutate_readme(root, END, ""),
    end_class_table_marker_on_readme,
    split_class_table_markers,
], ids=["no-begin", "no-end", "end-before-begin", "two-pages"])
def test_fix_says_it_wrote_nothing_when_it_cannot_find_the_class_tables(break_markers):
    # --fix used to print "OK: attack-class tables already current" here, on the same run
    # that then exited 1 because it could not find the tables.
    td = scratch_tree()
    try:
        break_markers(td)
        pages = {rel: (td / rel).read_text(encoding="utf-8") for rel in readme_pages()}
        r = run_checker(td, "--fix")
        assert r.returncode == 1, r.stdout
        assert "OK: attack-class tables already current" not in r.stdout, r.stdout
        assert "FIXED: rewrote" not in r.stdout, r.stdout
        assert ("NOT FIXED: wrote nothing, as the attack-class tables could not be found"
                in r.stderr), r.stderr
        assert "the attack-class tables need exactly one" in r.stderr, r.stderr
        for rel, text in pages.items():
            assert (td / rel).read_text(encoding="utf-8") == text, rel
    finally:
        shutil.rmtree(td)


def test_a_missing_readme_page_is_red():
    # A page README.md hands its reference text to takes the claims on it out of the check
    # when it is gone, so it fails the check instead.
    td = scratch_tree()
    try:
        (td / "docs" / "overview.md").unlink()
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert ("docs/overview.md: missing; README.md hands this page text that the check "
                "reads") in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_class_table_links_are_written_from_the_page_that_holds_them():
    checker = load_checker()
    assert checker.link_base("README.md") == ""
    assert checker.link_base(CLASS_PAGE) == "../"
    matrix = json.loads((ROOT / "matrix.json").read_text(encoding="utf-8"))
    assert "](attack-classes/GATEWAY-EXPLOIT.md)" in checker.render_class_tables(matrix)
    assert ("](../attack-classes/GATEWAY-EXPLOIT.md)"
            in checker.render_class_tables(matrix, checker.link_base(CLASS_PAGE)))


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
        before = {rel: (td / rel).read_text(encoding="utf-8") for rel in readme_pages()}

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
        assert {rel: (td / rel).read_text(encoding="utf-8") for rel in readme_pages()} == before
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
