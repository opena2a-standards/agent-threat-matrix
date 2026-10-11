"""Technique and tactic page checker tests.

Every case runs scripts/check_technique_pages.py against a scratch copy of matrix.json,
techniques/ and tactics/ so the committed files are never perturbed. The shipped tree must
be green. Each data line a technique page shares with matrix.json, and each row of a tactic
page's technique table, is then changed in one place: the checker must go red naming the
page and the line, and ``--fix`` must restore the shipped text. The checker used to compare
only the Attack Class and OASB Controls lines, so a class move in the data left the HMA
Checks line, the References class link and the tactic tables on the old values while CI
stayed green.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = "scripts/check_technique_pages.py"


def scratch_tree() -> Path:
    td = Path(tempfile.mkdtemp(prefix="atm-pages-"))
    (td / "scripts").mkdir()
    shutil.copy(ROOT / SCRIPT, td / SCRIPT)
    shutil.copy(ROOT / "matrix.json", td / "matrix.json")
    shutil.copytree(ROOT / "techniques", td / "techniques")
    shutil.copytree(ROOT / "tactics", td / "tactics")
    return td


def run_checker(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(root / SCRIPT), *args],
                          capture_output=True, text=True, timeout=120)


def mutate(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"mutation target must occur exactly once: {old!r}"
    path.write_text(text.replace(old, new), encoding="utf-8")


@pytest.fixture
def tree():
    td = scratch_tree()
    yield td
    shutil.rmtree(td, ignore_errors=True)


def test_shipped_tree_is_green():
    result = run_checker(ROOT)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.startswith("OK: 61 technique pages and 9 tactic pages agree with matrix.json")


# (page, label, shipped text, stale text). Each shipped text occurs once on its page.
TECHNIQUE_MUTATIONS = [
    ("T-1006", "Title", "# T-1006: Agent Card Discovery", "# T-1006: Agent Card Lookup"),
    ("T-1006", "Tactic", "**Tactic:** reconnaissance", "**Tactic:** collection"),
    ("T-1006", "Attack Class", "**Attack Class:** A2A-EXPOSE", "**Attack Class:** AGENT-IMPERSONATE"),
    ("T-1006", "Description",
     "Discover A2A agent cards to map agent identities, capabilities, and trust relationships",
     "Discover A2A agent cards"),
    ("T-1006", "DVAA Validation", "- **DVAA Validation:** Orchestrator /a2a/agent-card",
     "- **DVAA Validation:** Orchestrator /agent-card"),
    ("T-1006", "HMA Checks", "- **HMA Checks:** A2A-001, A2A-002", "- **HMA Checks:** AIM-001, AIM-002"),
    ("T-1006", "OASB Controls", "- **OASB Controls:** 7.1, 7.2, 7.3, 7.4", "- **OASB Controls:** 7.1"),
    ("T-1006", "Evidence Tier", "- **Evidence Tier:** observed", "- **Evidence Tier:** validated"),
    ("T-1006", "References attack class",
     "- Attack Class: [A2A-EXPOSE](../attack-classes/A2A-EXPOSE.md)",
     "- Attack Class: [AGENT-IMPERSONATE](../attack-classes/AGENT-IMPERSONATE.md)"),
    ("T-9006", "References attack class",
     "- Attack Class: [NEMO-SUPPLY-CHAIN](../attack-classes/NEMO-SUPPLY-CHAIN.md)",
     "- Attack Class: [ORG-SKILL-SPREAD](../attack-classes/ORG-SKILL-SPREAD.md)"),
    ("T-1006", "References tactic", "- Tactic: [reconnaissance](../tactics/reconnaissance.md)",
     "- Tactic: [collection](../tactics/collection.md)"),
]


@pytest.mark.parametrize("tid,label,shipped,stale", TECHNIQUE_MUTATIONS,
                         ids=[f"{m[0]}-{m[1]}" for m in TECHNIQUE_MUTATIONS])
def test_stale_technique_line_is_red_and_fixed(tree, tid, label, shipped, stale):
    page = tree / "techniques" / f"{tid}.md"
    before = page.read_text(encoding="utf-8")
    mutate(page, shipped, stale)

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert f"{tid}: {label} line is '{stale}', matrix.json says '{shipped}'" in result.stdout

    fixed = run_checker(tree, "--fix")
    assert fixed.returncode == 0, fixed.stdout
    assert page.read_text(encoding="utf-8") == before
    assert run_checker(tree).returncode == 0


def test_missing_technique_line_is_red(tree):
    mutate(tree / "techniques" / "T-5002.md", "- **HMA Checks:** A2A-001, A2A-002\n", "")
    result = run_checker(tree)
    assert result.returncode == 1
    assert "T-5002: page has no 'HMA Checks' line" in result.stdout

    fixed = run_checker(tree, "--fix")
    assert fixed.returncode == 1, "--fix cannot invent the line's place, so it stays red"
    assert "FAIL: could not rewrite 1" in fixed.stdout


def test_duplicate_technique_line_is_red(tree):
    mutate(tree / "techniques" / "T-5002.md", "- **HMA Checks:** A2A-001, A2A-002\n",
           "- **HMA Checks:** A2A-001, A2A-002\n- **HMA Checks:** AIM-001, AIM-002\n")
    result = run_checker(tree)
    assert result.returncode == 1
    assert "T-5002: page has 2 'HMA Checks' lines" in result.stdout
    assert run_checker(tree, "--fix").returncode == 1


def test_dvaa_line_on_a_technique_without_one_in_the_data_is_red_and_fixed(tree):
    page = tree / "techniques" / "T-8003.md"
    before = page.read_text(encoding="utf-8")
    mutate(page, "No documented procedures yet.", "- **DVAA Validation:** dns tunnel")

    result = run_checker(tree)
    assert result.returncode == 1
    assert "T-8003: page has a 'DVAA Validation' line, matrix.json has none" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


def test_dvaa_added_to_the_data_is_red_and_fixed(tree):
    matrix_path = tree / "matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    technique = next(t for t in matrix["techniques"] if t["id"] == "T-8003")
    technique["dvaaValidation"] = "dns tunnel"
    matrix_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 1
    assert "T-8003: page has no 'DVAA Validation' line" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    page = (tree / "techniques" / "T-8003.md").read_text(encoding="utf-8")
    assert "- **DVAA Validation:** dns tunnel" in page
    assert "No documented procedures yet." not in page
    assert run_checker(tree).returncode == 0


# (tactic page, shipped row, stale row)
TACTIC_MUTATIONS = [
    ("reconnaissance",
     "| [T-1006](../techniques/T-1006.md) | Agent Card Discovery | observed | A2A-EXPOSE |",
     "| [T-1006](../techniques/T-1006.md) | Agent Card Discovery | observed | AGENT-IMPERSONATE |"),
    ("lateral-movement",
     "| [T-5002](../techniques/T-5002.md) | A2A Agent Pivoting | validated | A2A-EXPOSE |",
     "| [T-5002](../techniques/T-5002.md) | A2A Agent Pivoting | adapted | A2A-EXPOSE |"),
    ("impact",
     "| [T-9006](../techniques/T-9006.md) | Supply Chain Compromise | observed | NEMO-SUPPLY-CHAIN |",
     "| [T-9006](../techniques/T-9006.md) | Supply Chain Compromise | observed | ORG-SKILL-SPREAD |"),
    ("impact", "**Kill Chain Stage:** 9", "**Kill Chain Stage:** 8"),
]


@pytest.mark.parametrize("tactic,shipped,stale", TACTIC_MUTATIONS,
                         ids=[f"{m[0]}-{i}" for i, m in enumerate(TACTIC_MUTATIONS)])
def test_stale_tactic_line_is_red_and_fixed(tree, tactic, shipped, stale):
    page = tree / "tactics" / f"{tactic}.md"
    before = page.read_text(encoding="utf-8")
    mutate(page, shipped, stale)

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert f"tactics/{tactic}.md: " in result.stdout
    assert f"is '{stale}', matrix.json says '{shipped}'" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


def test_missing_tactic_row_is_red_and_fixed(tree):
    page = tree / "tactics" / "impact.md"
    before = page.read_text(encoding="utf-8")
    mutate(page, "| [T-9006](../techniques/T-9006.md) | Supply Chain Compromise | observed | NEMO-SUPPLY-CHAIN |\n", "")

    result = run_checker(tree)
    assert result.returncode == 1
    assert "tactics/impact.md: line 18 is missing, matrix.json says '| [T-9006]" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


def test_tactic_row_follows_a_class_move_in_the_data(tree):
    matrix_path = tree / "matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    technique = next(t for t in matrix["techniques"] if t["id"] == "T-5002")
    technique["attackClass"] = "AGENT-IMPERSONATE"
    matrix_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 1
    assert "tactics/lateral-movement.md: line 14 is" in result.stdout
    assert "T-5002: References attack class line is" in result.stdout
