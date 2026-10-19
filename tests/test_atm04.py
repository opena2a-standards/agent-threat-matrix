"""ATM-04 acceptance tests.

Every parametrize id below begins with the criterion id (ATM-04.ACn) so each criterion
can be traced to a passing testcase in a JUnit report written by `pytest --junitxml`:
the testcase name is the test function followed by the parametrize id in brackets.

The checker under test is scripts/check_canonical_classes.py. AC1 pins its CI wiring in
the readme-claims job with an untampered verdict; AC2 proves the check GREEN on the
shipped tree and RED on a scratch copy with one technique id dropped from a primary
array, or with a matrixVersion stamp other than the matrix.json version or a matrixCommit
stamp that is not a 40-hex commit sha (V6), or with a canonical-classes.json that does not
parse (a syntax error, an integer of more than 4300 digits, bytes that are not UTF-8), which
it reports in one line, not a traceback; AC3 and AC4 pin the CHANGELOG states (a resolvable
docstring pointer, no internal role name).
"""

import json
import re
import shutil
import subprocess
import sys
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
        ["git", "-C", str(ROOT), "diff", "--name-only", "HEAD", "--",
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

def _unreleased(changelog: str) -> str:
    return changelog.split("## Unreleased", 1)[1].split("\n## ", 1)[0]


def _ac3_changelog_records_the_derivation_ruling():
    text = _unreleased(CHANGELOG.read_text())
    entry = next((l for l in text.splitlines() if "hmaChecks" in l and "2026-08-25" in l), None)
    assert entry, "Unreleased must carry the hmaChecks-derivation entry dated 2026-08-25"
    assert "TAXONOMY_MAP" in entry and "derive_class_checks.py" in entry


def _ac3_docstring_pointer_resolves_or_is_gone():
    doc = DOCSTRING_SCRIPT.read_text()
    if "see CHANGELOG" in doc:
        assert any("hmaChecks" in l and "2026-08-25" in l
                   for l in _unreleased(CHANGELOG.read_text()).splitlines()), \
            "a surviving pointer must land on the entry"


def _ac3_a_released_entry_is_not_read_as_unreleased():
    # The Unreleased section ends at the next section heading, so the derivation entry
    # standing only under a released version satisfies neither check above.
    changelog = ("# Changelog\n\n## Unreleased\n\n### Fixed\n\n- An unrelated fix.\n\n"
                 "## v1.2.0 (2026-09-08)\n\n### Changed\n\n"
                 "- Class-level `hmaChecks` are derived from `TAXONOMY_MAP` by "
                 "`scripts/derive_class_checks.py` (ruled 2026-08-25).\n\n"
                 "## v1.1 (2026-06-04)\n\n### Added\n\n- An earlier entry.\n")
    unreleased = _unreleased(changelog)
    assert "- An unrelated fix." in unreleased
    assert "hmaChecks" not in unreleased and "2026-08-25" not in unreleased


AC3_CASES = [
    ("ATM-04.AC3 CHANGELOG records the 2026-08-25 hmaChecks derivation ruling", _ac3_changelog_records_the_derivation_ruling),
    ("ATM-04.AC3 the derive_class_checks.py pointer resolves or is gone", _ac3_docstring_pointer_resolves_or_is_gone),
    ("ATM-04.AC3 a derivation entry under a released version is not read as Unreleased", _ac3_a_released_entry_is_not_read_as_unreleased),
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


def _names_internal_role(changelog: str) -> bool:
    """A role title is the word Chief and a capitalised word, across any white space."""
    return re.search(r"Chief\s+[A-Z]", changelog) is not None


def _ac4_no_internal_role_named():
    assert not _names_internal_role(CHANGELOG.read_text())


def _ac4_a_role_title_is_found_on_one_line_and_across_a_line_break():
    # The shipped CHANGELOG holds no title, so only a synthetic one shows the check fires.
    # The title is put together here so that this file names none.
    word = "Chief"
    head = "# Changelog\n\n## Unreleased\n\n### Changed\n\n- OASB control mappings re-derived "
    one_line = head + f"(reviewed by the {word} Archivist, 2026-08-25).\n"
    split = head + f"(reviewed by the {word}\n  Archivist, 2026-08-25).\n"
    public = head + "(mapping review, 2026-08-25).\n"
    assert _names_internal_role(one_line), "a title on one line"
    assert _names_internal_role(split), "a title split across a line break"
    assert not _names_internal_role(public)


def _ac4_entry_keeps_its_technical_content():
    entry = _oasb_entry()
    for token in ("T-9001", "T-9003", "T-9004", "T-9005", "2026-08-25"):
        assert token in entry, token


def _ac4_attribution_takes_a_public_form():
    assert "(mapping review, 2026-08-25)" in _oasb_entry()


AC4_CASES = [
    ("ATM-04.AC4 CHANGELOG names no internal role", _ac4_no_internal_role_named),
    ("ATM-04.AC4 a role title is found on one line and across a line break", _ac4_a_role_title_is_found_on_one_line_and_across_a_line_break),
    ("ATM-04.AC4 the OASB entry keeps its four techniques and its date", _ac4_entry_keeps_its_technical_content),
    ("ATM-04.AC4 the attribution takes a public form", _ac4_attribution_takes_a_public_form),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC4_CASES])
def test_ac4(case):
    case()


# --------------------------------------------------------------------------- V6 stamps

def _scratch_tree_stamped(**stamps) -> Path:
    """A scratch copy of the tree with canonical-classes.json stamps overridden."""
    td = Path(tempfile.mkdtemp(prefix="atm04-"))
    (td / "scripts").mkdir()
    shutil.copy(CHECKER, td / "scripts" / "check_canonical_classes.py")
    shutil.copy(ROOT / "matrix.json", td / "matrix.json")
    data = json.loads((ROOT / "canonical-classes.json").read_text())
    data.update(stamps)
    (td / "canonical-classes.json").write_text(json.dumps(data, indent=2) + "\n")
    return td


def _ac2_shipped_stamps_carry_the_matrix_version_and_a_full_commit():
    data = json.loads((ROOT / "canonical-classes.json").read_text())
    matrix = json.loads((ROOT / "matrix.json").read_text())
    assert data["matrixVersion"] == matrix["version"]
    assert re.match(r"^[0-9a-f]{40}$", data["matrixCommit"]), data["matrixCommit"]


def _ac2_stamp_turns_the_checker_red(stamps: dict, line: str):
    def case():
        scratch = _scratch_tree_stamped(**stamps)
        try:
            proc = _run_checker(scratch)
            assert proc.returncode == 1, proc.stdout + proc.stderr
            err = proc.stderr.splitlines()
            assert line in err
            assert "canonical-classes.json: 1 violation(s)" in err
        finally:
            shutil.rmtree(scratch)
    return case


AC2_STAMP_CASES = [
    ("ATM-04.AC2 the shipped stamps carry the matrix.json version and a 40-hex commit sha",
     _ac2_shipped_stamps_carry_the_matrix_version_and_a_full_commit),
    ("ATM-04.AC2 a stale matrixVersion turns the checker red with the V6 line",
     _ac2_stamp_turns_the_checker_red(
         {"matrixVersion": "1.1"}, "V6 matrixVersion '1.1' differs from matrix.json version '1.2'")),
    ("ATM-04.AC2 an abbreviated matrixCommit turns the checker red with the V6 line",
     _ac2_stamp_turns_the_checker_red(
         {"matrixCommit": "298eba0"}, "V6 matrixCommit '298eba0' is not a 40-hex commit sha")),
    ("ATM-04.AC2 the PENDING-AT-MERGE placeholder turns the checker red with the V6 line",
     _ac2_stamp_turns_the_checker_red(
         {"matrixCommit": "PENDING-AT-MERGE"},
         "V6 matrixCommit 'PENDING-AT-MERGE' is not a 40-hex commit sha")),
    ("ATM-04.AC2 a null matrixCommit turns the checker red with the V6 line",
     _ac2_stamp_turns_the_checker_red(
         {"matrixCommit": None}, "V6 matrixCommit None is not a 40-hex commit sha")),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC2_STAMP_CASES])
def test_ac2_stamps(case):
    case()


# --------------------------------------------------------------------------- V1 parse

INT_LIMIT = pytest.mark.skipif(
    getattr(sys, "get_int_max_str_digits", lambda: 0)() != 4300,
    reason="needs Python's default int string conversion limit of 4300 digits")


def _scratch_tree_holding(raw: bytes) -> Path:
    """A scratch copy of the tree whose canonical-classes.json holds raw."""
    td = Path(tempfile.mkdtemp(prefix="atm04-"))
    (td / "scripts").mkdir()
    shutil.copy(CHECKER, td / "scripts" / "check_canonical_classes.py")
    shutil.copy(ROOT / "matrix.json", td / "matrix.json")
    (td / "canonical-classes.json").write_bytes(raw)
    return td


def _with_long_integer(digits: int) -> bytes:
    """The shipped canonical-classes.json with a top-level key "huge" set to a digits-long
    integer by editing the text: json.dumps refuses an int past Python's int string
    conversion limit."""
    text = (ROOT / "canonical-classes.json").read_text(encoding="utf-8")
    assert text.startswith("{")
    return ('{"huge": ' + "1" * digits + "," + text[1:]).encode("utf-8")


def _line_matches(got: str, want: str) -> bool:
    """want in full, or, when it ends in "...", the start of got."""
    return got.startswith(want[:-3]) if want.endswith("...") else got == want


def _ac2_file_turns_the_checker_red(make, *lines: str):
    def case():
        scratch = _scratch_tree_holding(make())
        try:
            proc = _run_checker(scratch)
            assert proc.returncode == 1, proc.stdout + proc.stderr
            assert "Traceback" not in proc.stderr, proc.stderr
            assert proc.stdout == "", proc.stdout
            err = proc.stderr.splitlines()
            assert len(err) == len(lines) and all(map(_line_matches, err, lines)), proc.stderr
        finally:
            shutil.rmtree(scratch)
    return case


AC2_PARSE_CASES = [
    ("ATM-04.AC2 a syntax error turns the checker red with the parse line",
     _ac2_file_turns_the_checker_red(
         lambda: b"{",
         "canonical-classes.json does not parse: Expecting property name enclosed in double "
         "quotes: line 1 column 2 (char 1)"), ()),
    ("ATM-04.AC2 a 4301-digit integer turns the checker red with the parse line, not a traceback",
     _ac2_file_turns_the_checker_red(
         lambda: _with_long_integer(4301),
         "canonical-classes.json does not parse: Exceeds the limit (4300 digits) for integer "
         "string conversion: value has 4301 digits..."), INT_LIMIT),
    ("ATM-04.AC2 a 5000-digit integer turns the checker red with the parse line, not a traceback",
     _ac2_file_turns_the_checker_red(
         lambda: _with_long_integer(5000),
         "canonical-classes.json does not parse: Exceeds the limit (4300 digits) for integer "
         "string conversion: value has 5000 digits..."), INT_LIMIT),
    ("ATM-04.AC2 a 4300-digit integer parses and turns the checker red with the V1 line",
     _ac2_file_turns_the_checker_red(
         lambda: _with_long_integer(4300),
         "V1 unexpected top-level key: huge", "canonical-classes.json: 1 violation(s)"), ()),
    ("ATM-04.AC2 bytes that are not UTF-8 turn the checker red with the parse line, not a traceback",
     _ac2_file_turns_the_checker_red(
         lambda: b"\xff\xfe" + (ROOT / "canonical-classes.json").read_bytes(),
         "canonical-classes.json does not parse: 'utf-8' codec can't decode byte 0xff in "
         "position 0: invalid start byte"), ()),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name, marks=marks)
                                  for name, fn, marks in AC2_PARSE_CASES])
def test_ac2_parse(case):
    case()
