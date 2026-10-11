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
control-protected, must go red.
"""

import json
import shutil
import subprocess
import tempfile
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
