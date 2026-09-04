"""ATM-06 acceptance tests.

Leaf test names begin with the criterion id (ATM-06.ACn) so the QGF gate can trace each
criterion to a passing testcase in the JUnit output (ID_SCHEME.md 3.3): the id is the
first token of every parametrize id below.

The checker under test is scripts/check_attribution.py. AC1 pins the two CONTRIBUTING.md
clauses (contributor credit, retained change control) around an unchanged tier table and
template; AC2 pins the committed submission entry point under .github/; AC3 proves the
attribution partition GREEN on the shipped tree; AC4 proves it RED in every direction on
fixtures the shipped tree does not share (tests/fixtures/atm06/), including a synthetic
62nd technique; AC5 pins the CI wiring with an untampered verdict; AC6 proves external
credit is recorded, never guessed: a source-less external entry is refused and a declined
credit stays external.
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
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "atm06"
RECORD = ROOT / "ATTRIBUTION.md"
CONTRIBUTING = ROOT / "CONTRIBUTING.md"
WORKFLOW = ROOT / ".github" / "workflows" / "claims.yml"
ISSUE_FORM = ROOT / ".github" / "ISSUE_TEMPLATE" / "technique-submission.yml"
PR_TEMPLATE = ROOT / ".github" / "pull_request_template.md"
CHECKER = ROOT / "scripts" / "check_attribution.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_attribution", CHECKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHK = _load_checker()
MATRIX = json.loads((ROOT / "matrix.json").read_text())
MATRIX_IDS = {t["id"] for t in MATRIX["techniques"]}


def _shipped_sets():
    external_section, inhouse_section, missing = CHK.split_sections(RECORD.read_text())
    assert not missing
    return CHK.parse_external(external_section), CHK.parse_inhouse(inhouse_section)


def _fixture_tree(record_name: str) -> Path:
    """A scratch root holding the fixture matrix.json and the named attribution record."""
    td = Path(tempfile.mkdtemp(prefix="atm06-"))
    shutil.copy(FIXTURES / "matrix.json", td / "matrix.json")
    shutil.copy(FIXTURES / record_name, td / "ATTRIBUTION.md")
    return td


def _fixture_failures(record_name: str) -> list:
    tree = _fixture_tree(record_name)
    try:
        return CHK.run_checks(tree)
    finally:
        shutil.rmtree(tree)


# --------------------------------------------------------------------------- AC1

def _ac1_credit_clause_present():
    text = CONTRIBUTING.read_text()
    assert "## Contributor credit" in text
    # What is credited, where the credit is published, and in what form.
    assert "ATTRIBUTION.md" in text, "the clause names the exact place the credit is published"
    assert "exactly as the contributor gives" in text, "the credit takes the form the contributor gives"


def _ac1_credit_clause_covers_decline():
    text = CONTRIBUTING.read_text()
    assert "To decline credit" in text
    assert "(credit declined)" in text
    assert "never reclassified as" in text


def _ac1_change_control_clause_present():
    text = CONTRIBUTING.read_text()
    assert "## Change control" in text
    assert "no entitlement to inclusion" in text
    assert "OpenA2A decides what enters the matrix" in text


def _ac1_change_control_names_the_four_powers_and_the_thread():
    text = CONTRIBUTING.read_text().split("## Change control", 1)[1]
    for token in ("edited", "re-tiered", "re-placed", "removed"):
        assert token in text, token
    assert "recorded on the submission\nthread" in text or "recorded on the submission thread" in text


def _ac1_tier_table_unchanged():
    text = CONTRIBUTING.read_text()
    for row in (
        "| **Observed** | Documented in a real-world production system, security incident report, or internet-wide exposure assessment |",
        "| **Validated** | Reproduced in a controlled lab environment with documented steps, expected output, and independent verification |",
    ):
        assert row in text, "the evidence-tier table is not rewritten"
    assert "We do not accept purely theoretical techniques." in text


def _ac1_technique_template_unchanged():
    text = CONTRIBUTING.read_text()
    assert "```markdown" in text
    fenced = text.split("```markdown", 1)[1].split("```", 1)[0]
    for heading in ("# T-XXXX: Technique Name", "## Procedure Example", "## Validation", "## References"):
        assert heading in fenced, heading


AC1_CASES = [
    ("ATM-06.AC1 CONTRIBUTING carries the contributor-credit clause naming the published place and form", _ac1_credit_clause_present),
    ("ATM-06.AC1 the credit clause says how a contributor declines credit", _ac1_credit_clause_covers_decline),
    ("ATM-06.AC1 CONTRIBUTING carries the retained-change-control clause with no entitlement", _ac1_change_control_clause_present),
    ("ATM-06.AC1 change control names edit re-tier re-place remove and the submission thread", _ac1_change_control_names_the_four_powers_and_the_thread),
    ("ATM-06.AC1 the evidence-tier table is unchanged", _ac1_tier_table_unchanged),
    ("ATM-06.AC1 the technique template is unchanged", _ac1_technique_template_unchanged),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC1_CASES])
def test_ac1(case):
    case()


# --------------------------------------------------------------------------- AC2

ISSUE_FORM_LABELS = (
    "Kill-chain stage (tactic)",
    "Technique name",
    "Description",
    "Attack class",
    "Evidence tier",
    "Evidence source (the tier's own requirement)",
    "Procedure example",
    "Detection logic",
    "DVAA validation",
    "Defensive controls",
    "References",
    "Credit preference",
)


def _ac2_issue_form_exists_with_every_field():
    assert ISSUE_FORM.exists(), ".github/ISSUE_TEMPLATE/technique-submission.yml must exist"
    text = ISSUE_FORM.read_text()
    for label in ISSUE_FORM_LABELS:
        assert f"label: {label}" in text, label


def _ac2_issue_form_fields_all_required():
    text = ISSUE_FORM.read_text()
    assert text.count("required: true") == len(ISSUE_FORM_LABELS), \
        "every field carries validations.required true"


def _ac2_issue_form_tier_options_are_the_three_published_tiers():
    text = ISSUE_FORM.read_text()
    tier_block = text.split("label: Evidence tier", 1)[1].split("- type:", 1)[0]
    assert re.findall(r"^\s+- (Observed|Validated|Adapted)\s*$", tier_block, re.M) == \
        ["Observed", "Validated", "Adapted"]


def _ac2_issue_form_source_field_states_each_tiers_own_bar():
    text = ISSUE_FORM.read_text()
    block = text.split("label: Evidence source", 1)[1].split("- type:", 1)[0]
    for token in (
        "production system", "incident report", "exposure",   # Observed
        "reproduction steps", "expected output",               # Validated
        "traditional technique", "differs",                    # Adapted
    ):
        assert token in block, token


def _ac2_pr_template_states_both_placement_obligations():
    assert PR_TEMPLATE.exists(), ".github/pull_request_template.md must exist"
    text = PR_TEMPLATE.read_text()
    assert "`canonical-classes.json` `primary`" in text
    assert "cross-references/" in text
    assert "owasp-llm-mapping.md" in text and "technique-overlap-index.md" in text
    assert "same commit" in text


def _ac2_pr_template_carries_credit_preference():
    text = PR_TEMPLATE.read_text()
    assert "Credit preference" in text
    assert "ATTRIBUTION.md" in text


AC2_CASES = [
    ("ATM-06.AC2 the technique-submission issue form exists with every evidence-bar field", _ac2_issue_form_exists_with_every_field),
    ("ATM-06.AC2 every issue-form field is required", _ac2_issue_form_fields_all_required),
    ("ATM-06.AC2 the tier dropdown offers exactly the three published tiers", _ac2_issue_form_tier_options_are_the_three_published_tiers),
    ("ATM-06.AC2 the source field states each tier's own required source", _ac2_issue_form_source_field_states_each_tiers_own_bar),
    ("ATM-06.AC2 the PR template states both same-commit placement obligations", _ac2_pr_template_states_both_placement_obligations),
    ("ATM-06.AC2 the PR template carries the credit preference", _ac2_pr_template_carries_credit_preference),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC2_CASES])
def test_ac2(case):
    case()


# --------------------------------------------------------------------------- AC3

def _ac3_record_partitions_the_matrix():
    external, inhouse = _shipped_sets()
    assert set(external).isdisjoint(inhouse)
    assert set(external) | inhouse == MATRIX_IDS
    assert len(set(external) | inhouse) == 61


def _ac3_checker_green_on_the_shipped_tree():
    assert CHK.run_checks(ROOT) == []


def _ac3_checker_exit_zero_via_cli():
    proc = subprocess.run(
        ["python3", str(CHECKER)], capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "union equals the 61 techniques in matrix.json" in proc.stdout


def _ac3_stdlib_only():
    imports = set(re.findall(r"^(?:import|from)\s+([a-zA-Z_][\w]*)", CHECKER.read_text(), re.M))
    stdlib = {"json", "re", "sys", "pathlib"}
    assert imports <= stdlib, f"non-stdlib imports: {imports - stdlib}"


def _ac3_failure_text_points_at_contributing():
    failures = _fixture_failures("both_lists.md")
    assert failures and 'CONTRIBUTING.md, "Contributor credit"' in failures[0]


AC3_CASES = [
    ("ATM-06.AC3 the record partitions all 61 technique ids into the two lists", _ac3_record_partitions_the_matrix),
    ("ATM-06.AC3 the checker reports no violation on the shipped tree", _ac3_checker_green_on_the_shipped_tree),
    ("ATM-06.AC3 the checker exits 0 on the shipped tree", _ac3_checker_exit_zero_via_cli),
    ("ATM-06.AC3 the checker imports only the standard library", _ac3_stdlib_only),
    ("ATM-06.AC3 the failure text points at the governing CONTRIBUTING section", _ac3_failure_text_points_at_contributing),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC3_CASES])
def test_ac3(case):
    case()


# --------------------------------------------------------------------------- AC4

def _ac4_both_lists_red():
    failures = _fixture_failures("both_lists.md")
    hits = [f for f in failures if "is in both published lists at once" in f and "T-1001" in f]
    assert hits, f"the both-lists direction must fire naming T-1001; got {failures}"


def _ac4_synthetic_62nd_red():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        shutil.copy(RECORD, tmp / "ATTRIBUTION.md")
        matrix = json.loads((ROOT / "matrix.json").read_text())
        matrix["techniques"].append({
            "id": "T-9999", "name": "Synthetic Attribution Probe", "tactic": "impact",
            "attackClass": matrix["techniques"][0]["attackClass"],
        })
        (tmp / "matrix.json").write_text(json.dumps(matrix))
        failures = CHK.run_checks(tmp)
    hits = [f for f in failures if "neither published list" in f and "T-9999" in f]
    assert hits, f"the neither-list direction must fire on the synthetic 62nd technique; got {failures}"


def _ac4_unknown_id_red():
    failures = _fixture_failures("unknown_id.md")
    hits = [f for f in failures if "T-9998" in f and "not a" in f and "technique id in matrix.json" in f]
    assert hits, f"an id absent from matrix.json must be refused naming T-9998; got {failures}"


def _ac4_shipped_tree_green():
    assert CHK.run_checks(ROOT) == []


def _ac4_fixtures_not_shared_with_the_shipped_tree():
    for name in ("both_lists.md", "unknown_id.md"):
        assert (FIXTURES / name).read_text() != RECORD.read_text()
    assert json.loads((FIXTURES / "matrix.json").read_text()) != MATRIX


AC4_CASES = [
    ("ATM-06.AC4 a technique in both sets fails with the both-lists message naming it", _ac4_both_lists_red),
    ("ATM-06.AC4 a synthetic 62nd technique with no placement fails with the neither-list message", _ac4_synthetic_62nd_red),
    ("ATM-06.AC4 a record naming an id absent from matrix.json fails naming that id", _ac4_unknown_id_red),
    ("ATM-06.AC4 the shipped tree passes", _ac4_shipped_tree_green),
    ("ATM-06.AC4 the red fixtures are not the shipped inputs", _ac4_fixtures_not_shared_with_the_shipped_tree),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC4_CASES])
def test_ac4(case):
    case()


# --------------------------------------------------------------------------- AC5

def _readme_claims_job():
    wf = WORKFLOW.read_text()
    return wf.split("readme-claims:", 1)[1].split("live-api-drift:", 1)[0]


def _attribution_step_lines():
    job = _readme_claims_job()
    lines = job.splitlines()
    start = next(i for i, l in enumerate(lines) if "check_attribution.py" in l)
    while not lines[start].lstrip().startswith("- "):
        start -= 1
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.lstrip().startswith("- "):
            break
        block.append(line)
    return block


def _ac5_step_in_readme_claims_job():
    assert "python3 scripts/check_attribution.py" in _readme_claims_job()


def _ac5_same_triggers_as_the_existing_checks():
    wf = WORKFLOW.read_text()
    on = wf.split("\non:", 1)[1].split("\npermissions:", 1)[0]
    assert "push:" in on and "branches: [main]" in on
    assert "pull_request:" in on


def _ac5_runs_beside_the_four_existing_checks():
    job = _readme_claims_job()
    for script in ("check_readme_claims", "check_technique_pages", "check_cross_references",
                   "check_canonical_classes", "check_attribution"):
        assert re.search(rf"run: python3 scripts/{script}\.py\s*$", job, re.M), script


def _ac5_no_continue_on_error():
    assert "continue-on-error" not in WORKFLOW.read_text()


def _ac5_no_skipping_condition():
    job = _readme_claims_job()
    assert not re.search(r"^\s*if:", job, re.M), "no if: anywhere in the readme-claims job"


def _ac5_verdict_not_neutralized():
    block = "\n".join(_attribution_step_lines())
    run_lines = [l for l in block.splitlines() if "run:" in l]
    assert len(run_lines) == 1
    cmd = run_lines[0].split("run:", 1)[1].strip()
    assert cmd == "python3 scripts/check_attribution.py"
    for bad in ("|| true", "|| :", "; true", "set +e", "; exit 0"):
        assert bad not in cmd, bad


AC5_CASES = [
    ("ATM-06.AC5 readme-claims runs check_attribution.py", _ac5_step_in_readme_claims_job),
    ("ATM-06.AC5 the workflow triggers on push main and pull_request", _ac5_same_triggers_as_the_existing_checks),
    ("ATM-06.AC5 the step sits beside the four existing check steps", _ac5_runs_beside_the_four_existing_checks),
    ("ATM-06.AC5 no continue-on-error anywhere in the workflow", _ac5_no_continue_on_error),
    ("ATM-06.AC5 no skipping if condition in the readme-claims job", _ac5_no_skipping_condition),
    ("ATM-06.AC5 the command string carries no verdict neutralizer", _ac5_verdict_not_neutralized),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC5_CASES])
def test_ac5(case):
    case()


# --------------------------------------------------------------------------- AC6

def _ac6_empty_source_refused():
    failures = _fixture_failures("empty_source.md")
    assert any("T-1001" in f and "submission cell" in f for f in failures), failures


def _ac6_placeholder_source_refused():
    failures = _fixture_failures("placeholder_source.md")
    assert any("T-1001" in f and "submission cell" in f for f in failures), failures


def _ac6_nonreference_source_refused():
    failures = _fixture_failures("nonreference_source.md")
    assert any("T-1001" in f and "submission cell" in f for f in failures), failures


def _ac6_empty_credit_refused():
    failures = _fixture_failures("empty_credit.md")
    assert any("T-1001" in f and "credit cell" in f for f in failures), failures


def _ac6_declined_credit_stays_external():
    tree = _fixture_tree("declined_credit.md")
    try:
        assert CHK.run_checks(tree) == [], "a declined credit with a real source is valid"
        ext_section, inh_section, _ = CHK.split_sections((tree / "ATTRIBUTION.md").read_text())
        external = CHK.parse_external(ext_section)
        assert "T-1001" in external, "the declined entry stays in the external list"
        assert "T-1001" not in CHK.parse_inhouse(inh_section), "never reclassified as in-house"
    finally:
        shutil.rmtree(tree)


def _ac6_shipped_record_invents_no_credit():
    # The repository's history establishes no external contributor for the 61 existing
    # techniques, so all 61 are placed in-house and the external list is empty: a wrong
    # attribution on a public record about a named person is not retractable.
    external, inhouse = _shipped_sets()
    assert external == {}, "no external credit is invented for the initial placement"
    assert inhouse == MATRIX_IDS


AC6_CASES = [
    ("ATM-06.AC6 an external entry with an empty source is refused", _ac6_empty_source_refused),
    ("ATM-06.AC6 an external entry with a placeholder source is refused", _ac6_placeholder_source_refused),
    ("ATM-06.AC6 an external entry whose source is not an issue or PR reference is refused", _ac6_nonreference_source_refused),
    ("ATM-06.AC6 an external entry with an empty credit cell is refused", _ac6_empty_credit_refused),
    ("ATM-06.AC6 a declined credit is recorded as declined and stays external", _ac6_declined_credit_stays_external),
    ("ATM-06.AC6 the shipped record places all 61 techniques in-house with no invented credit", _ac6_shipped_record_invents_no_credit),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC6_CASES])
def test_ac6(case):
    case()
