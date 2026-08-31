"""ATM-03 acceptance tests.

Leaf test names begin with the criterion id (ATM-03.ACn) so the QGF gate can trace each
criterion to a passing testcase in the JUnit output (ID_SCHEME.md 3.3): the id is the
first token of every parametrize id below.

The checker under test is scripts/check_cross_references.py. AC4 proves the C3 and C4
invariants RED on the pre-change inputs (fixtures under tests/fixtures/pre_change/) and
GREEN on the shipped tree, and proves the C4 gate fires on a synthetic 62nd technique.
"""

import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CROSSREF = ROOT / "cross-references"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "pre_change"
INDEX = CROSSREF / "technique-overlap-index.md"
OWASP = CROSSREF / "owasp-llm-mapping.md"
MITRE = CROSSREF / "mitre-atlas-mapping.md"


def _load_checker():
    spec = importlib.util.spec_from_file_location(
        "check_cross_references", ROOT / "scripts" / "check_cross_references.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHK = _load_checker()
MATRIX = json.loads((ROOT / "matrix.json").read_text())
MATRIX_IDS = {t["id"] for t in MATRIX["techniques"]}

# The four techniques the pre-change tree asserted both ways (C3), and the three it
# placed in neither list (C4). These are the readings AC4 records.
PRE_BOTH_WAYS = {"T-6001", "T-6002", "T-6006", "T-7004"}
PRE_NEITHER = {"T-1001", "T-1002", "T-1003"}


def owasp_named():
    return CHK.parse_owasp_named(OWASP.read_text())


def no_counterpart():
    return CHK.parse_no_counterpart(INDEX.read_text())


def owasp_rows():
    rows = {}
    for line in OWASP.read_text().splitlines():
        m = CHK.OWASP_ROW_RE.match(line)
        if m:
            rows[m.group(1)] = CHK.TECH_ID_RE.findall(m.group(2))
    return rows


# --------------------------------------------------------------------------- AC1

def _ac1_renamed_new_present():
    assert INDEX.exists(), "technique-overlap-index.md must exist"


def _ac1_old_absent_no_stub():
    assert not (CROSSREF / "gap-analysis.md").exists(), "gap-analysis.md must be gone, no stub"


def _ac1_no_coverage_summary_heading():
    for md in CROSSREF.glob("*.md"):
        for line in md.read_text().splitlines():
            if line.startswith("#"):
                assert "coverage summary" not in line.lower(), f"{md.name}: {line!r}"


def _ac1_aggregate_table_deleted():
    text = INDEX.read_text().lower()
    assert "partially covered" not in text, "the four-row aggregate table must be deleted"
    assert "coverage summary" not in text


def _ac1_no_banned_word_in_headings_or_headers():
    # C7 across the directory must be clean.
    failures = [f for f in CHK.run_checks(ROOT) if f.startswith("C7 ")]
    assert not failures, failures


def _ac1_readme_cell_updated():
    line80 = (ROOT / "README.md").read_text().splitlines()[79]
    assert "MITRE ATT&CK / ATLAS / OWASP LLM" in line80
    assert "which techniques this repository's mapping documents name" in line80
    assert "Gap analysis" not in line80


def _ac1_changelog_names_both_paths():
    text = (ROOT / "CHANGELOG.md").read_text()
    unreleased = text.split("## Unreleased", 1)[1].split("## v1.1", 1)[0]
    assert "cross-references/gap-analysis.md" in unreleased
    assert "cross-references/technique-overlap-index.md" in unreleased


def _ac1_git_mv_history_preserved():
    # A pure-rename commit makes the new path's history reach the old name. Under a
    # shallow checkout that predates the rename commit this cannot be observed; in that
    # case the tree facts above are the evidence and this check does not assert a false.
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "log", "--follow", "--name-status", "--format=",
             "--", "cross-references/technique-overlap-index.md"],
            capture_output=True, text=True, timeout=30,
        )
        count = subprocess.run(
            ["git", "-C", str(ROOT), "rev-list", "--count", "HEAD"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        pytest.skip("git not available")
    if count.stdout.strip().isdigit() and int(count.stdout.strip()) >= 2:
        assert "gap-analysis.md" in out.stdout, "git --follow must reach the old name"


AC1_CASES = [
    ("ATM-03.AC1 technique-overlap-index.md exists after the rename", _ac1_renamed_new_present),
    ("ATM-03.AC1 gap-analysis.md is gone with no stub or tombstone", _ac1_old_absent_no_stub),
    ("ATM-03.AC1 no cross-references heading reads Coverage Summary", _ac1_no_coverage_summary_heading),
    ("ATM-03.AC1 the four-row aggregate table is deleted", _ac1_aggregate_table_deleted),
    ("ATM-03.AC1 no banned word in any heading or table header", _ac1_no_banned_word_in_headings_or_headers),
    ("ATM-03.AC1 README line 80 cell is updated", _ac1_readme_cell_updated),
    ("ATM-03.AC1 CHANGELOG Unreleased names both paths", _ac1_changelog_names_both_paths),
    ("ATM-03.AC1 git mv preserved the file history", _ac1_git_mv_history_preserved),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC1_CASES])
def test_ac1(case):
    case()


# --------------------------------------------------------------------------- AC2

def _ac2_checker_passes_on_tree():
    assert CHK.run_checks(ROOT) == []


def _ac2_stdlib_only():
    src = (ROOT / "scripts" / "check_cross_references.py").read_text()
    imports = set(re.findall(r"^(?:import|from)\s+([a-zA-Z_][\w]*)", src, re.M))
    stdlib = {"json", "re", "sys", "pathlib"}
    assert imports <= stdlib, f"non-stdlib imports: {imports - stdlib}"


def _ac2_each_property_holds():
    failures = CHK.run_checks(ROOT)
    for code in ("C1", "C2", "C3", "C4", "C5", "C6", "C7"):
        hits = [f for f in failures if f.split()[0].rstrip(":") == code]
        assert not hits, f"{code}: {hits}"


def _ac2_wired_into_claims():
    wf = (ROOT / ".github" / "workflows" / "claims.yml").read_text()
    job = wf.split("readme-claims:", 1)[1].split("live-api-drift:", 1)[0]
    assert "scripts/check_cross_references.py" in job, "must be a step in readme-claims"


def _ac2_counts_are_emitted_not_typed():
    version = MATRIX["version"]
    want = CHK.render_block(version, len(MATRIX_IDS), len(owasp_named()))
    _before, body, _after = CHK.extract_block(INDEX.read_text())
    assert body == f"\n{want}\n", "the generated block must equal the script rendering"


def _ac2_exit_zero_via_cli():
    proc = subprocess.run(
        ["python3", str(ROOT / "scripts" / "check_cross_references.py")],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


AC2_CASES = [
    ("ATM-03.AC2 the checker reports no violation on the shipped tree", _ac2_checker_passes_on_tree),
    ("ATM-03.AC2 the checker imports only the standard library", _ac2_stdlib_only),
    ("ATM-03.AC2 properties C1 through C7 each hold", _ac2_each_property_holds),
    ("ATM-03.AC2 the checker is wired into the readme-claims job", _ac2_wired_into_claims),
    ("ATM-03.AC2 the published counts are emitted by the script", _ac2_counts_are_emitted_not_typed),
    ("ATM-03.AC2 the checker exits 0 on the shipped tree", _ac2_exit_zero_via_cli),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC2_CASES])
def test_ac2(case):
    case()


# --------------------------------------------------------------------------- AC3

def _ac3_t1003_named_against_llm01():
    assert "T-1003" in owasp_rows()["LLM01"]
    assert "T-1003" in owasp_named()
    assert "T-1003" not in no_counterpart()


def _ac3_t6006_moves_llm07_to_llm05():
    rows = owasp_rows()
    assert "T-6006" in rows["LLM05"]
    assert "T-6006" not in rows["LLM07"]
    assert "T-6006" not in no_counterpart()


def _ac3_llm09_technique_cell_empty():
    assert owasp_rows()["LLM09"] == [], "LLM09 must name no technique"
    assert {"T-6001", "T-6002"} <= no_counterpart()
    assert {"T-6001", "T-6002"}.isdisjoint(owasp_named())


def _ac3_t7004_stays_named_leaves_nocounterpart():
    assert "T-7004" in owasp_rows()["LLM06"]
    assert "T-7004" not in no_counterpart()


def _ac3_t1001_t1002_added_to_nocounterpart():
    assert {"T-1001", "T-1002"} <= no_counterpart()
    assert {"T-1001", "T-1002"}.isdisjoint(owasp_named())


def _ac3_partition_closes():
    A, B = owasp_named(), no_counterpart()
    assert len(A) == 30
    assert len(B) == 31
    assert A.isdisjoint(B)
    assert A | B == MATRIX_IDS
    assert len(A | B) == 61


def _ac3_numbers_not_committed_as_literals():
    # 30 and 31 must appear only inside the generated block.
    for md in CROSSREF.glob("*.md"):
        text = md.read_text()
        parts = CHK.extract_block(text)
        if parts is not None:
            before, _body, after = parts
            text = before + after
        for n in ("30", "31"):
            assert not re.search(rf"(?<![\d-]){n}(?![\d-])", text), f"{md.name} carries literal {n}"


AC3_CASES = [
    ("ATM-03.AC3 T-1003 is added to LLM01's row", _ac3_t1003_named_against_llm01),
    ("ATM-03.AC3 T-6006 moves from LLM07 to LLM05", _ac3_t6006_moves_llm07_to_llm05),
    ("ATM-03.AC3 LLM09's technique cell is emptied", _ac3_llm09_technique_cell_empty),
    ("ATM-03.AC3 T-7004 stays named and leaves the no-counterpart list", _ac3_t7004_stays_named_leaves_nocounterpart),
    ("ATM-03.AC3 T-1001 and T-1002 are added to the no-counterpart list", _ac3_t1001_t1002_added_to_nocounterpart),
    ("ATM-03.AC3 the partition closes at 30 named 31 not named union 61", _ac3_partition_closes),
    ("ATM-03.AC3 the two counts are never committed as literals", _ac3_numbers_not_committed_as_literals),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC3_CASES])
def test_ac3(case):
    case()


# --------------------------------------------------------------------------- AC4

def _pre_change_sets():
    A = CHK.parse_owasp_named((FIXTURES / "owasp-llm-mapping.md").read_text())
    B = CHK.parse_no_counterpart((FIXTURES / "no-counterpart-rows.md").read_text())
    return A, B


def _ac4_c3_red_on_pre_change():
    A, B = _pre_change_sets()
    assert A & B == PRE_BOTH_WAYS, "C3 must fail pre-change on the four doubly-listed techniques"


def _ac4_c4_red_on_pre_change():
    A, B = _pre_change_sets()
    assert (MATRIX_IDS - A - B) == PRE_NEITHER, "C4 must fail pre-change on the three unplaced techniques"


def _ac4_c3_green_after():
    A, B = owasp_named(), no_counterpart()
    assert A & B == set(), "C3 passes after the change"


def _ac4_c4_green_after():
    A, B = owasp_named(), no_counterpart()
    assert (MATRIX_IDS - A - B) == set(), "C4 passes after the change"
    assert A | B == MATRIX_IDS


def _ac4_synthetic_62nd_fires_c4():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        shutil.copytree(CROSSREF, tmp / "cross-references")
        matrix = json.loads((ROOT / "matrix.json").read_text())
        matrix["techniques"].append({
            "id": "T-9999", "name": "Synthetic Placement Probe", "tactic": "impact",
            "attackClass": matrix["techniques"][0]["attackClass"],
        })
        (tmp / "matrix.json").write_text(json.dumps(matrix))
        failures = CHK.run_checks(tmp)
        c4 = [f for f in failures if f.startswith("C4:") and "T-9999" in f]
        assert c4, f"C4 must fire on the synthetic 62nd technique; got {failures}"
        assert 'CONTRIBUTING.md, "Placing a new technique"' in c4[0]
        assert "neither published list" in c4[0]


AC4_CASES = [
    ("ATM-03.AC4 C3 is RED on the pre-change tree (four asserted both ways)", _ac4_c3_red_on_pre_change),
    ("ATM-03.AC4 C4 is RED on the pre-change tree (three in neither list)", _ac4_c4_red_on_pre_change),
    ("ATM-03.AC4 C3 is GREEN after the change", _ac4_c3_green_after),
    ("ATM-03.AC4 C4 is GREEN after the change", _ac4_c4_green_after),
    ("ATM-03.AC4 a synthetic 62nd technique makes the checker fail C4", _ac4_synthetic_62nd_fires_c4),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC4_CASES])
def test_ac4(case):
    case()


# --------------------------------------------------------------------------- AC5

def _ac5_matrix_json_unchanged():
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--name-only", "origin/main", "--", "matrix.json"],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode == 0:
        assert proc.stdout.strip() == "", "matrix.json must not be modified"


def _ac5_contributing_has_placement_section():
    text = (ROOT / "CONTRIBUTING.md").read_text()
    assert "## Placing a new technique" in text
    for token in ("Object test", "Effect test", "Mitigation test"):
        assert token in text, token


def _ac5_checker_failure_text_points_at_contributing():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        shutil.copytree(CROSSREF, tmp / "cross-references")
        matrix = json.loads((ROOT / "matrix.json").read_text())
        matrix["techniques"].append({"id": "T-9999", "name": "Probe", "tactic": "impact",
                                     "attackClass": matrix["techniques"][0]["attackClass"]})
        (tmp / "matrix.json").write_text(json.dumps(matrix))
        c4 = [f for f in CHK.run_checks(tmp) if f.startswith("C4:")]
    assert c4 and 'CONTRIBUTING.md, "Placing a new technique"' in c4[0]


AC5_CASES = [
    ("ATM-03.AC5 matrix.json is not modified", _ac5_matrix_json_unchanged),
    ("ATM-03.AC5 CONTRIBUTING carries the Placing a new technique section", _ac5_contributing_has_placement_section),
    ("ATM-03.AC5 the checker C4 text points at CONTRIBUTING by name", _ac5_checker_failure_text_points_at_contributing),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC5_CASES])
def test_ac5(case):
    case()
