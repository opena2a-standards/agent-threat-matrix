"""ATM-04 acceptance tests.

Leaf test names begin with the criterion id (ATM-04.ACn) so the QGF gate can trace each
criterion to a passing testcase in the JUnit output (ID_SCHEME.md 3.3): the id is the
first token of every parametrize id below.

The checker under test is scripts/check_canonical_classes.py. AC1 pins its CI wiring in
the readme-claims job with an untampered verdict; AC2 proves the check GREEN on the
shipped tree and RED on a scratch copy with one technique id dropped from a primary
array; AC3 and AC4 pin the CHANGELOG states (a resolvable docstring pointer, no
internal role name).
"""

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "claims.yml"
CHANGELOG = ROOT / "CHANGELOG.md"
DOCSTRING_SCRIPT = ROOT / "scripts" / "derive_class_checks.py"
CHECKER = ROOT / "scripts" / "check_canonical_classes.py"

GREEN_LINE = "canonical-classes.json OK: 61 technique ids across 10 classes"


def _readme_claims_job():
    wf = WORKFLOW.read_text()
    return wf.split("readme-claims:", 1)[1].split("live-api-drift:", 1)[0]


def _canonical_step_lines():
    """The step block that runs the checker: its lines up to the next step or job."""
    job = _readme_claims_job()
    lines = job.splitlines()
    start = next(i for i, l in enumerate(lines) if "check_canonical_classes.py" in l)
    while not lines[start].lstrip().startswith("- "):
        start -= 1
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.lstrip().startswith("- ") or line.strip().endswith(":") and not line.startswith(" " * 8):
            break
        block.append(line)
    return block


# --------------------------------------------------------------------------- AC1

def _ac1_step_in_readme_claims_job():
    assert "python3 scripts/check_canonical_classes.py" in _readme_claims_job()


def _ac1_follows_existing_step_pattern():
    job = _readme_claims_job()
    for script in ("check_readme_claims", "check_technique_pages",
                   "check_cross_references", "check_canonical_classes"):
        assert re.search(rf"run: python3 scripts/{script}\.py\s*$", job, re.M), script
    block = "\n".join(_canonical_step_lines())
    assert re.search(r"- name: .+", block), "the step carries a name like its siblings"


def _ac1_workflow_triggers_unchanged():
    wf = WORKFLOW.read_text()
    on = wf.split("\non:", 1)[1].split("\npermissions:", 1)[0]
    assert "push:" in on and "branches: [main]" in on
    assert "pull_request:" in on
    assert "schedule:" in on and '"50 6 * * *"' in on


def _ac1_no_continue_on_error():
    assert "continue-on-error" not in WORKFLOW.read_text()


def _ac1_no_skipping_if_on_step_or_job():
    job = _readme_claims_job()
    assert not re.search(r"^\s*if:", job, re.M), "no if: anywhere in the readme-claims job"


def _ac1_verdict_not_neutralized():
    block = "\n".join(_canonical_step_lines())
    run_lines = [l for l in block.splitlines() if "run:" in l]
    assert len(run_lines) == 1
    cmd = run_lines[0].split("run:", 1)[1].strip()
    assert cmd == "python3 scripts/check_canonical_classes.py"
    for bad in ("|| true", "|| :", "; true", "set +e", "; exit 0"):
        assert bad not in cmd, bad


AC1_CASES = [
    ("ATM-04.AC1 readme-claims runs check_canonical_classes.py", _ac1_step_in_readme_claims_job),
    ("ATM-04.AC1 the step follows the three existing check steps' pattern", _ac1_follows_existing_step_pattern),
    ("ATM-04.AC1 the workflow still triggers on push pull_request and schedule", _ac1_workflow_triggers_unchanged),
    ("ATM-04.AC1 no continue-on-error anywhere in the workflow", _ac1_no_continue_on_error),
    ("ATM-04.AC1 no skipping if condition on the step or its job", _ac1_no_skipping_if_on_step_or_job),
    ("ATM-04.AC1 the command string carries no verdict neutralizer", _ac1_verdict_not_neutralized),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC1_CASES])
def test_ac1(case):
    case()


# --------------------------------------------------------------------------- AC2

def _run_checker(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["python3", str(root / "scripts" / "check_canonical_classes.py")],
        capture_output=True, text=True, timeout=60,
    )


def _scratch_tree_missing(tid: str) -> Path:
    """A scratch copy of the tree with one technique id removed from its primary array."""
    td = Path(tempfile.mkdtemp(prefix="atm04-"))
    (td / "scripts").mkdir()
    shutil.copy(CHECKER, td / "scripts" / "check_canonical_classes.py")
    shutil.copy(ROOT / "matrix.json", td / "matrix.json")
    data = json.loads((ROOT / "canonical-classes.json").read_text())
    hit = 0
    for entry in data["classes"].values():
        if tid in entry["primary"]:
            entry["primary"].remove(tid)
            hit += 1
    assert hit == 1, f"{tid} must sit in exactly one primary array pre-change"
    (td / "canonical-classes.json").write_text(json.dumps(data, indent=2) + "\n")
    return td


def _ac2_green_on_the_shipped_tree():
    proc = _run_checker(ROOT)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip() == GREEN_LINE


def _ac2_red_on_scratch_missing_t7007():
    scratch = _scratch_tree_missing("T-7007")
    try:
        proc = _run_checker(scratch)
        assert proc.returncode == 1, proc.stdout + proc.stderr
        err = proc.stderr.splitlines()
        assert "V3 id missing from every primary array: T-7007" in err
        assert "canonical-classes.json: 1 violation(s)" in err
    finally:
        shutil.rmtree(scratch)


def _ac2_shipped_tree_not_perturbed():
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--name-only", "origin/main", "--",
         "canonical-classes.json", "matrix.json"],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode == 0:
        assert proc.stdout.strip() == "", "the drift is proven on a scratch copy only"


AC2_CASES = [
    ("ATM-04.AC2 the checker exits 0 on the shipped tree printing the OK line", _ac2_green_on_the_shipped_tree),
    ("ATM-04.AC2 dropping T-7007 from its primary array turns the checker red", _ac2_red_on_scratch_missing_t7007),
    ("ATM-04.AC2 the committed data files are not perturbed", _ac2_shipped_tree_not_perturbed),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC2_CASES])
def test_ac2(case):
    case()


# --------------------------------------------------------------------------- AC3

def _unreleased() -> str:
    return CHANGELOG.read_text().split("## Unreleased", 1)[1].split("## v1.1", 1)[0]


def _ac3_changelog_records_the_derivation_ruling():
    text = _unreleased()
    entry = next((l for l in text.splitlines() if "hmaChecks" in l and "2026-08-25" in l), None)
    assert entry, "Unreleased must carry the hmaChecks-derivation entry dated 2026-08-25"
    assert "TAXONOMY_MAP" in entry and "derive_class_checks.py" in entry


def _ac3_docstring_pointer_resolves_or_is_gone():
    doc = DOCSTRING_SCRIPT.read_text()
    if "see CHANGELOG" in doc:
        assert any("hmaChecks" in l and "2026-08-25" in l for l in _unreleased().splitlines()), \
            "a surviving pointer must land on the entry"


AC3_CASES = [
    ("ATM-04.AC3 CHANGELOG records the 2026-08-25 hmaChecks derivation ruling", _ac3_changelog_records_the_derivation_ruling),
    ("ATM-04.AC3 the derive_class_checks.py pointer resolves or is gone", _ac3_docstring_pointer_resolves_or_is_gone),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC3_CASES])
def test_ac3(case):
    case()


# --------------------------------------------------------------------------- AC4

def _oasb_entry() -> str:
    entry = next((l for l in CHANGELOG.read_text().splitlines()
                  if "OASB control mappings" in l and "re-derived" in l), None)
    assert entry, "the OASB re-derivation entry must survive"
    return entry


def _ac4_no_internal_role_named():
    assert "Chief Architect" not in CHANGELOG.read_text()


def _ac4_entry_keeps_its_technical_content():
    entry = _oasb_entry()
    for token in ("T-9001", "T-9003", "T-9004", "T-9005", "2026-08-25"):
        assert token in entry, token


def _ac4_attribution_takes_a_public_form():
    assert "(mapping review, 2026-08-25)" in _oasb_entry()


AC4_CASES = [
    ("ATM-04.AC4 CHANGELOG names no internal role", _ac4_no_internal_role_named),
    ("ATM-04.AC4 the OASB entry keeps its four techniques and its date", _ac4_entry_keeps_its_technical_content),
    ("ATM-04.AC4 the attribution takes a public form", _ac4_attribution_takes_a_public_form),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC4_CASES])
def test_ac4(case):
    case()
