"""Schema 1.2 validator and STIX generator tests.

Every case runs scripts/validate_matrix.py against a scratch copy of the tree so the
committed files are never perturbed. The shipped tree must be green; each rule the
validator enforces is proven red on one minimal mutation.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = ("matrix.json", "technique-ids.json", "schema/threat-matrix-v1.2.schema.json",
         "schema/consumer-readiness.json", "scripts/validate_matrix.py",
         "scripts/generate_stix.py", "stix/agent-threat-matrix-bundle.json", "evidence-gaps.json")


def scratch_tree(td: Path = None) -> Path:
    td = td or Path(tempfile.mkdtemp(prefix="atm-schema-"))
    for rel in FILES:
        dst = td / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    return td


def run_validator(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(root / "scripts" / "validate_matrix.py")],
                          capture_output=True, text=True, timeout=120)


def load(root: Path, rel: str):
    return json.loads((root / rel).read_text())


def dump(root: Path, rel: str, data) -> None:
    (root / rel).write_text(json.dumps(data, indent=2) + "\n")


def regenerate_stix(root: Path) -> None:
    subprocess.run(["python3", str(root / "scripts" / "generate_stix.py")],
                   check=True, capture_output=True, text=True, timeout=120)


def sync_ids(root: Path) -> None:
    matrix = load(root, "matrix.json")
    ids = load(root, "technique-ids.json")
    ids["ids"] = sorted(t["id"] for t in matrix["techniques"])
    dump(root, "technique-ids.json", ids)


def add_subtechnique(root: Path) -> None:
    matrix = load(root, "matrix.json")
    base = next(t for t in matrix["techniques"] if t["id"] == "T-2001")
    sub = dict(base, id="T-2001.001", name="Sub of T-2001", parentId="T-2001")
    matrix["techniques"].append(sub)
    dump(root, "matrix.json", matrix)


def mutate(fn):
    """Apply fn to a scratch tree, run the validator, clean up, return the process."""
    root = scratch_tree()
    try:
        fn(root)
        return run_validator(root)
    finally:
        shutil.rmtree(root)


def test_shipped_tree_is_green():
    proc = run_validator(ROOT)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.startswith("matrix.json validates against schema 1.2: 61 techniques (0 sub-techniques)")


def test_committed_files_not_perturbed():
    proc = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--",
                           "matrix.json", "technique-ids.json", "stix", "schema", "evidence-gaps.json"],
                          capture_output=True, text=True, timeout=30)
    if proc.returncode == 0:
        assert proc.stdout.strip() == "", proc.stdout


def _red(proc: subprocess.CompletedProcess, needle: str) -> None:
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert needle in proc.stderr, proc.stderr


def test_schema_rejects_an_unknown_evidence_tier():
    def fn(root):
        m = load(root, "matrix.json")
        m["techniques"][0]["evidenceTier"] = "theoretical"
        dump(root, "matrix.json", m)
    _red(mutate(fn), "matrix.techniques[0].evidenceTier: 'theoretical' is not one of")


def test_schema_rejects_a_version_other_than_1_2():
    def fn(root):
        m = load(root, "matrix.json")
        m["version"] = "1.1"
        dump(root, "matrix.json", m)
    _red(mutate(fn), "matrix.version: expected '1.2', got '1.1'")


def test_schema_rejects_an_unknown_technique_field():
    def fn(root):
        m = load(root, "matrix.json")
        m["techniques"][0]["foitw"] = True
        dump(root, "matrix.json", m)
    _red(mutate(fn), "matrix.techniques[0]: unexpected property 'foitw'")


def test_schema_rejects_a_bad_attack_mapping_id():
    def fn(root):
        m = load(root, "matrix.json")
        m["techniques"][0]["attackMapping"] = [{"id": "T-1595", "relationship": "closeMatch"}]
        dump(root, "matrix.json", m)
    _red(mutate(fn), "matrix.techniques[0].attackMapping[0].id: 'T-1595' does not match")


def test_schema_reports_an_integer_too_large_for_a_float_in_an_integer_field_without_bounds():
    def fn(root):
        m = load(root, "matrix.json")
        m["tactics"][0]["order"] = 10 ** 400  # 401 digits
        dump(root, "matrix.json", m)
    proc = mutate(fn)
    _red(proc, "matrix.tactics[0].order: an integer of 401 digits is too large for a 64-bit float, "
               "so it is not a finite number")
    assert "Traceback" not in proc.stderr, proc.stderr


def test_schema_reports_an_integer_too_large_for_a_float_in_a_string_field_once():
    def fn(root):
        m = load(root, "matrix.json")
        m["created"] = 10 ** 400
        dump(root, "matrix.json", m)
    proc = mutate(fn)
    _red(proc, "matrix.created: expected type string, got int")
    assert "Traceback" not in proc.stderr, proc.stderr
    assert proc.stderr.count("matrix.created:") == 1, proc.stderr


def write_long_sample_count(root: Path, digits: int) -> None:
    """Set techniques[0].wildSampleCount to a digits-long integer by editing the text:
    json.dumps refuses an int past Python's int string conversion limit."""
    text = (root / "matrix.json").read_text()
    key = '"wildSampleCount": '
    start = text.index(key) + len(key)
    end = start
    while text[end].isdigit():
        end += 1
    (root / "matrix.json").write_text(text[:start] + "1" * digits + text[end:])


def test_integer_at_the_int_conversion_limit_is_reported_as_too_large():
    proc = mutate(lambda root: write_long_sample_count(root, 4300))
    _red(proc, "matrix.techniques[0].wildSampleCount: an integer of 4300 digits is too large "
               "for a 64-bit float, so it is not a finite number")
    assert "Traceback" not in proc.stderr, proc.stderr


INT_LIMIT = pytest.mark.skipif(
    getattr(sys, "get_int_max_str_digits", lambda: 0)() != 4300,
    reason="needs Python's default int string conversion limit of 4300 digits")


@INT_LIMIT
@pytest.mark.parametrize("digits", [4301, 5000])
def test_integer_past_the_int_conversion_limit_is_a_fail_line_not_a_traceback(digits):
    proc = mutate(lambda root: write_long_sample_count(root, digits))
    _red(proc, "FAIL: matrix.json is missing or does not parse: Exceeds the limit (4300 digits) "
               f"for integer string conversion: value has {digits} digits")
    assert "Traceback" not in proc.stderr, proc.stderr


def test_missing_matrix_names_the_cause():
    _red(mutate(lambda root: (root / "matrix.json").unlink()),
         "FAIL: matrix.json is missing or does not parse: no such file")


def replace_with_directory(rel: str):
    def fn(root):
        (root / rel).unlink()
        (root / rel).mkdir()
    return fn


@pytest.mark.parametrize("rel", ["matrix.json", "schema/threat-matrix-v1.2.schema.json",
                                 "schema/consumer-readiness.json"])
def test_directory_at_an_input_path_is_one_fail_line_not_a_traceback(rel):
    proc = mutate(replace_with_directory(rel))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stdout == "", proc.stdout
    assert proc.stderr.splitlines() == [
        f"FAIL: {rel} is missing or does not parse: a directory, not a file"], proc.stderr


def test_directory_at_technique_ids_is_the_s8_finding_not_a_traceback():
    proc = mutate(replace_with_directory("technique-ids.json"))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stderr.splitlines() == [
        "FAIL: matrix.json does not validate (1 finding(s)):",
        "  - S8 technique-ids.json is missing or does not parse"], proc.stderr


def test_file_where_the_schema_directory_should_be_names_the_system_reason():
    def fn(root):
        shutil.rmtree(root / "schema")
        (root / "schema").write_text("not a directory\n")
    proc = mutate(fn)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stderr.splitlines() == [
        "FAIL: schema/threat-matrix-v1.2.schema.json is missing or does not parse: Not a directory",
        "FAIL: schema/consumer-readiness.json is missing or does not parse: Not a directory",
    ], proc.stderr


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0,
                    reason="root reads a file whatever its mode")
def test_unreadable_matrix_names_the_system_reason():
    proc = mutate(lambda root: (root / "matrix.json").chmod(0))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stderr.splitlines() == [
        "FAIL: matrix.json is missing or does not parse: Permission denied"], proc.stderr


NESTING = 200000


def nested(kind: str) -> str:
    """A JSON array or object nested NESTING levels deep: json.loads raises a RecursionError
    on it, which is not a ValueError (tried on Python 3.12, 3.13 and 3.14)."""
    if kind == "array":
        return "[" * NESTING + "]" * NESTING
    return '{"a": ' * NESTING + "1" + "}" * NESTING


@pytest.mark.parametrize("kind", ["array", "object"])
@pytest.mark.parametrize("rel", ["matrix.json", "schema/threat-matrix-v1.2.schema.json",
                                 "schema/consumer-readiness.json"])
def test_input_nested_too_deep_to_parse_is_one_fail_line_not_a_traceback(rel, kind):
    proc = mutate(lambda root: (root / rel).write_text(nested(kind)))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stdout == "", proc.stdout
    lines = proc.stderr.splitlines()
    assert len(lines) == 1, proc.stderr
    assert lines[0].startswith(f"FAIL: {rel} is missing or does not parse: "), proc.stderr
    assert lines[0].endswith(f" while decoding a JSON {kind} from a unicode string"), proc.stderr


def test_technique_ids_nested_too_deep_to_parse_is_the_s8_finding_not_a_traceback():
    proc = mutate(lambda root: (root / "technique-ids.json").write_text(nested("array")))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stderr.splitlines() == [
        "FAIL: matrix.json does not validate (1 finding(s)):",
        "  - S8 technique-ids.json is missing or does not parse"], proc.stderr


def test_data_source_must_resolve_in_the_registry():
    def fn(root):
        m = load(root, "matrix.json")
        m["techniques"][0]["dataSources"] = ["honeypot"]
        dump(root, "matrix.json", m)
        regenerate_stix(root)
    _red(mutate(fn), "S4 T-1001: dataSources value 'honeypot' is not in the dataSources registry")


def test_data_source_resolves_when_registered():
    def fn(root):
        m = load(root, "matrix.json")
        m["dataSources"] = [{"id": "honeypot", "name": "Honeypot", "description": "Honeypot telemetry"}]
        m["techniques"][0]["dataSources"] = ["honeypot"]
        dump(root, "matrix.json", m)
        regenerate_stix(root)
    proc = mutate(fn)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 data sources" in proc.stdout


def test_deprecated_requires_replaced_by():
    def fn(root):
        m = load(root, "matrix.json")
        m["techniques"][0]["status"] = "deprecated"
        dump(root, "matrix.json", m)
        regenerate_stix(root)
    _red(mutate(fn), "S5 T-1001: status is deprecated but replacedBy is absent")


def test_replaced_by_requires_deprecated_and_must_resolve():
    def fn(root):
        m = load(root, "matrix.json")
        m["techniques"][0]["replacedBy"] = "T-9999"
        dump(root, "matrix.json", m)
        regenerate_stix(root)
    proc = mutate(fn)
    _red(proc, "S5 T-1001: replacedBy is present but status is 'active', not deprecated")
    assert "S5 T-1001: replacedBy 'T-9999' is not a technique id" in proc.stderr


def test_no_shipped_adapted_technique_names_a_lab_scenario():
    # Adapted means no lab reproduction; T-9004 and T-9005 named one and were counted
    # in the README lab-scenario ratio as well as in the adapted tier.
    adapted = [t for t in load(ROOT, "matrix.json")["techniques"] if t["evidenceTier"] == "adapted"]
    assert adapted
    assert [t["id"] for t in adapted if t.get("dvaaValidation")] == []


def test_adapted_technique_with_a_lab_scenario_is_red():
    def fn(root):
        m = load(root, "matrix.json")
        t = next(t for t in m["techniques"] if t["id"] == "T-8003")
        assert t["evidenceTier"] == "adapted"
        t["dvaaValidation"] = "dns-exfil"
        dump(root, "matrix.json", m)
        regenerate_stix(root)
    _red(mutate(fn), "S12 T-8003: evidenceTier is adapted (no lab reproduction) but dvaaValidation names 'dns-exfil'")


def test_validated_technique_with_a_lab_scenario_is_green():
    def fn(root):
        m = load(root, "matrix.json")
        t = next(t for t in m["techniques"] if t["id"] == "T-8003")
        t["evidenceTier"] = "validated"
        t["dvaaValidation"] = "dns-exfil"
        dump(root, "matrix.json", m)
        regenerate_stix(root)
    proc = mutate(fn)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_dotted_id_is_rejected_while_consumers_are_not_ready():
    def fn(root):
        add_subtechnique(root)
        sync_ids(root)
        regenerate_stix(root)
    proc = mutate(fn)
    _red(proc, "S7 T-2001.001: dotted ids are not accepted")
    assert "subTechniques false" in proc.stderr


def test_dotted_id_is_accepted_once_consumers_are_ready():
    def fn(root):
        add_subtechnique(root)
        sync_ids(root)
        readiness = load(root, "schema/consumer-readiness.json")
        readiness["subTechniques"] = True
        dump(root, "schema/consumer-readiness.json", readiness)
        regenerate_stix(root)
        bundle = load(root, "stix/agent-threat-matrix-bundle.json")
        rels = [o for o in bundle["objects"] if o.get("relationship_type") == "subtechnique-of"]
        assert len(rels) == 1
    proc = mutate(fn)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "62 techniques (1 sub-techniques)" in proc.stdout


def test_dotted_id_requires_a_matching_parent():
    def fn(root):
        add_subtechnique(root)
        m = load(root, "matrix.json")
        m["techniques"][-1]["parentId"] = "T-2002"
        dump(root, "matrix.json", m)
        sync_ids(root)
        readiness = load(root, "schema/consumer-readiness.json")
        readiness["subTechniques"] = True
        dump(root, "schema/consumer-readiness.json", readiness)
    _red(mutate(fn), "S6 T-2001.001: parentId 'T-2002' does not match the id prefix 'T-2001'")


def test_parent_id_is_only_allowed_on_a_dotted_id():
    def fn(root):
        m = load(root, "matrix.json")
        m["techniques"][0]["parentId"] = "T-1002"
        dump(root, "matrix.json", m)
        regenerate_stix(root)
    _red(mutate(fn), "S6 T-1001: parentId is only allowed on a dotted id")


def test_technique_ids_file_must_match():
    def fn(root):
        ids = load(root, "technique-ids.json")
        ids["ids"].remove("T-7007")
        dump(root, "technique-ids.json", ids)
    _red(mutate(fn), "S8 technique-ids.json ids differ from matrix.json: missing ['T-7007']")


# --------------------------------------------------------------------------- ATM-07 (S11)

SHA40_RE = r"[0-9a-f]{40}"


def _shipped_matrix_commit() -> str:
    return load(ROOT, "technique-ids.json")["matrixCommit"]


def _ac1_shipped_matrix_commit_is_a_full_sha():
    import re
    value = _shipped_matrix_commit()
    assert isinstance(value, str) and re.fullmatch(SHA40_RE, value), value
    assert value != "PENDING-AT-MERGE"


def _ac1_matrix_stix_and_schema_are_the_committed_bytes():
    # The stamped sha indexes the committed matrix.json: the data files carry no
    # uncommitted change alongside the stamp (skipped where the tree has no git).
    proc = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--",
                           "matrix.json", "stix", "schema"],
                          capture_output=True, text=True, timeout=30)
    if proc.returncode == 0:
        assert proc.stdout.strip() == "", proc.stdout


AC1_CASES = [
    ("ATM-07.AC1 shipped technique-ids.json matrixCommit is a 40-hex sha, not the placeholder",
     _ac1_shipped_matrix_commit_is_a_full_sha),
    ("ATM-07.AC1 matrix.json stix and schema carry no change beside the stamp",
     _ac1_matrix_stix_and_schema_are_the_committed_bytes),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC1_CASES])
def test_atm07_ac1(case):
    case()


def _plant_matrix_commit(value, present=True):
    def fn(root):
        ids = load(root, "technique-ids.json")
        if present:
            ids["matrixCommit"] = value
        else:
            ids.pop("matrixCommit", None)
        dump(root, "technique-ids.json", ids)
    return fn


def _ac2_placeholder_is_refused():
    _red(mutate(_plant_matrix_commit("PENDING-AT-MERGE")),
         "S11 technique-ids.json matrixCommit 'PENDING-AT-MERGE' is not a 40-hex commit sha")


def _ac2_truncated_sha_is_refused():
    short = _shipped_matrix_commit()[:12]
    _red(mutate(_plant_matrix_commit(short)),
         f"S11 technique-ids.json matrixCommit {short!r} is not a 40-hex commit sha")


def _ac2_trailing_newline_is_refused():
    # The scratch tree has no git history, so only the shape check runs; a "$" anchor
    # also matches before a trailing newline, which let this value pass.
    value = _shipped_matrix_commit() + "\n"
    _red(mutate(_plant_matrix_commit(value)),
         f"S11 technique-ids.json matrixCommit {value!r} is not a 40-hex commit sha")


def _ac2_missing_key_is_refused():
    _red(mutate(_plant_matrix_commit(None, present=False)),
         "S11 technique-ids.json matrixCommit None is not a 40-hex commit sha")


def _ac2_non_string_is_refused():
    _red(mutate(_plant_matrix_commit(1234567890123456789012345678901234567890)),
         "S11 technique-ids.json matrixCommit 1234567890123456789012345678901234567890 "
         "is not a 40-hex commit sha")


AC2_CASES = [
    ("ATM-07.AC2 PENDING-AT-MERGE planted turns the validator red with the S11 line",
     _ac2_placeholder_is_refused),
    ("ATM-07.AC2 a twelve-character abbreviation turns the validator red with the S11 line",
     _ac2_truncated_sha_is_refused),
    ("ATM-07.AC2 a sha with a trailing newline turns the validator red with the S11 line",
     _ac2_trailing_newline_is_refused),
    ("ATM-07.AC2 a missing matrixCommit key turns the validator red rendering None",
     _ac2_missing_key_is_refused),
    ("ATM-07.AC2 a non-string matrixCommit turns the validator red",
     _ac2_non_string_is_refused),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC2_CASES])
def test_atm07_ac2(case):
    case()


def _ac3_shipped_tree_green_and_summary_names_the_commit():
    proc = run_validator(ROOT)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.startswith(
        "matrix.json validates against schema 1.2: 61 techniques (0 sub-techniques)")
    head, _, tail = proc.stdout.partition("in sync")
    assert tail, proc.stdout
    assert _shipped_matrix_commit() in tail, proc.stdout


def _ac3_s8_pin_still_fires_beside_s11():
    def fn(root):
        ids = load(root, "technique-ids.json")
        ids["ids"].remove("T-7007")
        ids["matrixCommit"] = "PENDING-AT-MERGE"
        dump(root, "technique-ids.json", ids)
    proc = mutate(fn)
    _red(proc, "S8 technique-ids.json ids differ from matrix.json: missing ['T-7007']")
    assert "S11 technique-ids.json matrixCommit 'PENDING-AT-MERGE'" in proc.stderr


AC3_CASES = [
    ("ATM-07.AC3 the shipped tree is green and the summary names the matrixCommit after in sync",
     _ac3_shipped_tree_green_and_summary_names_the_commit),
    ("ATM-07.AC3 the S8 red pin still fires with S11 in place",
     _ac3_s8_pin_still_fires_beside_s11),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC3_CASES])
def test_atm07_ac3(case):
    case()


def _ac4_readme_schema_paragraph_documents_matrix_commit():
    # The README's Schema paragraph moved to its own page.
    text = (ROOT / "docs" / "schema.md").read_text(encoding="utf-8")
    schema_section = text.split("# Schema", 1)[1].split("\n---", 1)[0]
    sentence = next((s for s in schema_section.replace("\n", " ").split(". ")
                     if "`matrixCommit`" in s), None)
    assert sentence is not None, schema_section
    assert "40-character" in sentence and "refuses" in sentence, sentence


AC4_CASES = [
    ("ATM-07.AC4 README Schema paragraph states matrixCommit is the 40-character sha the validator refuses otherwise",
     _ac4_readme_schema_paragraph_documents_matrix_commit),
]


@pytest.mark.parametrize("case", [pytest.param(fn, id=name) for name, fn in AC4_CASES])
def test_atm07_ac4(case):
    case()


# --------------------------------------------------------------------------- S11 against git history

GIT_ENV = {key: value for key, value in os.environ.items()
           if key not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                          "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")}


def git(root: Path, *args, stdin: str = None) -> str:
    return subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=validator-test",
         "-c", "user.email=validator-test@example.invalid", "-c", "commit.gpgsign=false",
         "-c", "core.hooksPath=/dev/null", *args],
        check=True, capture_output=True, text=True, timeout=60, env=GIT_ENV,
        input=stdin).stdout.strip()


def commit_all(root: Path, message: str) -> str:
    git(root, "add", "--", *FILES)
    git(root, "commit", "-q", "-m", message)
    return git(root, "rev-parse", "HEAD")


def history_tree(stamp_fn=None) -> Path:
    """A scratch tree with git history whose technique-ids.json is stamped with an earlier commit.

    stamp_fn(root) commits whatever history the case needs and returns the sha to stamp;
    by default the stamp is the commit that holds the shipped matrix.json.
    """
    root = scratch_tree()
    git(root, "init", "-q")
    sha = stamp_fn(root) if stamp_fn else commit_all(root, "matrix")
    ids = load(root, "technique-ids.json")
    ids["matrixCommit"] = sha
    dump(root, "technique-ids.json", ids)
    commit_all(root, "stamp matrixCommit")
    return root


def run_on(root: Path) -> subprocess.CompletedProcess:
    try:
        return run_validator(root)
    finally:
        shutil.rmtree(root)


def test_matrix_commit_resolved_in_history_is_green():
    root = history_tree()
    sha = load(root, "technique-ids.json")["matrixCommit"]
    proc = run_on(root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"(matrixCommit {sha}, ids match matrix.json at that commit)" in proc.stdout, proc.stdout


def test_matrix_commit_naming_no_commit_is_refused_with_history():
    root = history_tree()
    ids = load(root, "technique-ids.json")
    ids["matrixCommit"] = "0" * 40
    dump(root, "technique-ids.json", ids)
    _red(run_on(root),
         f"S11 technique-ids.json matrixCommit {'0' * 40} does not name a commit in this repository")


def test_matrix_commit_indexing_a_different_matrix_is_refused():
    def stamp(root):
        shipped = (root / "matrix.json").read_bytes()
        matrix = load(root, "matrix.json")
        matrix["techniques"] = [t for t in matrix["techniques"] if t["id"] != "T-7007"]
        dump(root, "matrix.json", matrix)
        older = commit_all(root, "matrix without T-7007")
        (root / "matrix.json").write_bytes(shipped)
        commit_all(root, "matrix with T-7007")
        return older
    root = history_tree(stamp)
    sha = load(root, "technique-ids.json")["matrixCommit"]
    _red(run_on(root),
         f"S11 technique-ids.json matrixCommit {sha} indexes a matrix.json whose ids "
         f"differ from the list: extra ['T-7007']")


@INT_LIMIT
def test_matrix_commit_whose_matrix_has_an_integer_past_the_conversion_limit_is_refused():
    def stamp(root):
        shipped = (root / "matrix.json").read_bytes()
        write_long_sample_count(root, 4301)
        older = commit_all(root, "matrix with a 4301-digit sample count")
        (root / "matrix.json").write_bytes(shipped)
        commit_all(root, "shipped matrix")
        return older
    root = history_tree(stamp)
    sha = load(root, "technique-ids.json")["matrixCommit"]
    proc = run_on(root)
    _red(proc, f"S11 technique-ids.json matrixCommit {sha}: matrix.json at that commit does not parse")
    assert "Traceback" not in proc.stderr, proc.stderr


@INT_LIMIT
def test_head_matrix_with_an_integer_past_the_conversion_limit_skips_s13():
    root = history_tree()
    shipped = (root / "matrix.json").read_bytes()
    write_long_sample_count(root, 4301)
    commit_all(root, "matrix with a 4301-digit sample count")
    (root / "matrix.json").write_bytes(shipped)
    proc = run_on(root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Traceback" not in proc.stderr, proc.stderr


def test_matrix_commit_whose_matrix_is_nested_too_deep_to_parse_is_refused():
    def stamp(root):
        shipped = (root / "matrix.json").read_bytes()
        (root / "matrix.json").write_text(nested("array"))
        older = commit_all(root, "matrix nested 200000 arrays deep")
        (root / "matrix.json").write_bytes(shipped)
        commit_all(root, "shipped matrix")
        return older
    root = history_tree(stamp)
    sha = load(root, "technique-ids.json")["matrixCommit"]
    proc = run_on(root)
    _red(proc, f"S11 technique-ids.json matrixCommit {sha}: matrix.json at that commit does not parse")
    assert "Traceback" not in proc.stderr, proc.stderr


def test_head_matrix_nested_too_deep_to_parse_skips_s13():
    root = history_tree()
    shipped = (root / "matrix.json").read_bytes()
    (root / "matrix.json").write_text(nested("array"))
    commit_all(root, "matrix nested 200000 arrays deep")
    (root / "matrix.json").write_bytes(shipped)
    proc = run_on(root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Traceback" not in proc.stderr, proc.stderr


def test_matrix_commit_naming_a_tree_is_refused():
    root = history_tree()
    tree = git(root, "rev-parse", "HEAD^{tree}")
    ids = load(root, "technique-ids.json")
    ids["matrixCommit"] = tree
    dump(root, "technique-ids.json", ids)
    _red(run_on(root), f"S11 technique-ids.json matrixCommit {tree} names a tree object, not a commit")


def test_matrix_commit_without_a_matrix_is_refused():
    def stamp(root):
        git(root, "add", "--", "schema")
        git(root, "commit", "-q", "-m", "schema only")
        return git(root, "rev-parse", "HEAD")
    root = history_tree(stamp)
    sha = load(root, "technique-ids.json")["matrixCommit"]
    _red(run_on(root), f"S11 technique-ids.json matrixCommit {sha} has no matrix.json")


@pytest.mark.parametrize("mode,kind", [("040000", "tree"), ("160000", "commit")],
                         ids=["directory", "submodule"])
def test_matrix_commit_whose_matrix_is_not_a_file_is_refused(mode, kind):
    def stamp(root):
        commit_all(root, "matrix")
        # A submodule entry names a commit this repository does not hold, as a blob that a
        # partial clone left out is not held either.
        entry = git(root, "rev-parse", "HEAD^{tree}") if kind == "tree" else "1" * 40
        tree = git(root, "mktree", "--missing", stdin=f"{mode} {kind} {entry}\tmatrix.json\n")
        return git(root, "commit-tree", tree, "-m", "matrix.json is not a file")
    root = history_tree(stamp)
    sha = load(root, "technique-ids.json")["matrixCommit"]
    _red(run_on(root), f"S11 technique-ids.json matrixCommit {sha} has no matrix.json file: "
                       f"the entry at that commit is a {kind}, not a blob")


def test_repository_path_in_another_letter_case_still_reads_the_history():
    root = history_tree()
    sha = load(root, "technique-ids.json")["matrixCommit"]
    other_case = root.parent / root.name.swapcase()
    try:
        if not other_case.exists():
            pytest.skip("the filesystem is case-sensitive")
        proc = run_validator(other_case)
    finally:
        shutil.rmtree(root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"(matrixCommit {sha}, ids match matrix.json at that commit)" in proc.stdout, proc.stdout


def test_shallow_checkout_without_the_commit_checks_the_shape_only():
    source = history_tree()
    clone = Path(tempfile.mkdtemp(prefix="atm-shallow-")) / "clone"
    try:
        subprocess.run(["git", "clone", "-q", "--depth", "1", source.as_uri(), str(clone)],
                       check=True, capture_output=True, text=True, timeout=60, env=GIT_ENV)
        assert git(clone, "rev-parse", "--is-shallow-repository") == "true"
        proc = run_validator(clone)
    finally:
        shutil.rmtree(source)
        shutil.rmtree(clone.parent)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "shape only: shallow checkout without that commit)" in proc.stdout, proc.stdout


@pytest.mark.parametrize("filter_spec,note", [
    ("blob:none", "shape only: partial clone without matrix.json at that commit)"),
    ("tree:0", "shape only: partial clone without that commit's tree)"),
])
def test_partial_clone_without_the_objects_checks_the_shape_only(filter_spec, note):
    def stamp(root):
        # Same ids, different bytes: the stamped matrix.json is a blob the checkout never reads.
        shipped = (root / "matrix.json").read_bytes()
        (root / "matrix.json").write_bytes(shipped + b"\n")
        older = commit_all(root, "matrix with a trailing newline")
        (root / "matrix.json").write_bytes(shipped)
        commit_all(root, "matrix")
        return older
    source = history_tree(stamp)
    git(source, "config", "uploadpack.allowFilter", "true")
    clone = Path(tempfile.mkdtemp(prefix="atm-partial-")) / "clone"
    try:
        subprocess.run(["git", "clone", "-q", f"--filter={filter_spec}", source.as_uri(), str(clone)],
                       check=True, capture_output=True, text=True, timeout=60, env=GIT_ENV)
        assert git(clone, "config", "--get", "remote.origin.promisor") == "true"
        proc = run_validator(clone)
    finally:
        shutil.rmtree(source)
        shutil.rmtree(clone.parent)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert note in proc.stdout, proc.stdout


def test_copy_without_git_checks_the_shape_only():
    proc = run_on(scratch_tree())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "shape only: no git history at the repository root)" in proc.stdout, proc.stdout


def test_copy_nested_in_another_repository_checks_the_shape_only():
    outer = Path(tempfile.mkdtemp(prefix="atm-outer-"))
    try:
        git(outer, "init", "-q")
        (outer / "README").write_text("outer\n")
        git(outer, "add", "--", "README")
        git(outer, "commit", "-q", "-m", "outer")
        proc = run_validator(scratch_tree(outer / "vendored"))
    finally:
        shutil.rmtree(outer)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "shape only: no git history at the repository root)" in proc.stdout, proc.stdout


def test_stix_bundle_must_be_byte_identical():
    def fn(root):
        path = root / "stix" / "agent-threat-matrix-bundle.json"
        path.write_text(path.read_text().replace("Endpoint Enumeration", "Endpoint enumeration", 1))
    _red(mutate(fn), "S10 stix/agent-threat-matrix-bundle.json is not what scripts/generate_stix.py renders")


def test_stix_generator_is_deterministic_and_self_consistent():
    root = scratch_tree()
    try:
        regenerate_stix(root)
        first = (root / "stix" / "agent-threat-matrix-bundle.json").read_bytes()
        regenerate_stix(root)
        second = (root / "stix" / "agent-threat-matrix-bundle.json").read_bytes()
        assert first == second
        assert first == (ROOT / "stix" / "agent-threat-matrix-bundle.json").read_bytes()
        bundle = json.loads(first)
        matrix = load(root, "matrix.json")
        ids = [o["id"] for o in bundle["objects"]]
        assert len(ids) == len(set(ids))
        by_type = {}
        for obj in bundle["objects"]:
            by_type.setdefault(obj["type"], []).append(obj)
        assert len(by_type["attack-pattern"]) == len(matrix["techniques"])
        assert len(by_type["x-opena2a-tactic"]) == len(matrix["tactics"])
        assert len(by_type["grouping"]) == len(matrix["attackClasses"])
        controls = {c for t in matrix["techniques"] for c in t["oasbControls"]}
        assert len(by_type["course-of-action"]) == len(controls)
        mitigates = [r for r in by_type["relationship"] if r["relationship_type"] == "mitigates"]
        assert len(mitigates) == sum(len(t["oasbControls"]) for t in matrix["techniques"])
        identity = by_type["identity"][0]
        assert all(o["created_by_ref"] == identity["id"] for o in bundle["objects"])
        assert all(o["spec_version"] == "2.1" for o in bundle["objects"])
    finally:
        shutil.rmtree(root)


def test_stix_generator_runs_with_docstrings_stripped():
    # python3 -OO strips docstrings; the argument parser's description used to be read from
    # the module docstring and the run ended in an AttributeError.
    root = scratch_tree()
    try:
        proc = subprocess.run(["python3", "-OO", str(root / "scripts" / "generate_stix.py")],
                              capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert (root / "stix" / "agent-threat-matrix-bundle.json").read_bytes() \
            == (ROOT / "stix" / "agent-threat-matrix-bundle.json").read_bytes()
    finally:
        shutil.rmtree(root)


def test_stix_generator_description_is_its_docstring_summary():
    import importlib.util
    spec = importlib.util.spec_from_file_location("generate_stix", ROOT / "scripts" / "generate_stix.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.DESCRIPTION == mod.__doc__.splitlines()[0]


# --------------------------------------------------------------------------- S13 updated date


def git_scratch_tree(updated: str) -> Path:
    """A scratch tree with git history whose HEAD holds matrix.json with ``updated`` set to
    the given date, so S13 has a HEAD copy to compare against. technique-ids.json is
    stamped with the scratch commit that holds that matrix.json, so S11 resolves it there
    as it does in this repository."""
    def stamp(root):
        set_updated(root, updated)
        regenerate_stix(root)
        return commit_all(root, "base")
    return history_tree(stamp)


def edit_technique_name(root: Path, tid: str = "T-1006") -> None:
    m = load(root, "matrix.json")
    t = next(t for t in m["techniques"] if t["id"] == tid)
    t["name"] += " (edited)"
    dump(root, "matrix.json", m)


def edit_class_description(root: Path, cid: str = "PHANTOM-SOUL") -> None:
    m = load(root, "matrix.json")
    c = next(c for c in m["attackClasses"] if c["id"] == cid)
    c["description"] += " (edited)"
    dump(root, "matrix.json", m)


def set_updated(root: Path, updated: str) -> None:
    m = load(root, "matrix.json")
    m["updated"] = updated
    dump(root, "matrix.json", m)


def run_in_git_tree(updated_at_head: str, *edits) -> subprocess.CompletedProcess:
    root = git_scratch_tree(updated_at_head)
    try:
        for edit in edits:
            edit(root)
        regenerate_stix(root)
        return run_validator(root)
    finally:
        shutil.rmtree(root)


def today() -> str:
    return date.today().isoformat()


def test_s13_technique_change_without_moving_updated_is_red():
    proc = run_in_git_tree("2026-06-03", edit_technique_name)
    _red(proc, f"S13 matrix.json content differs from HEAD (techniques T-1006) but updated is "
               f"2026-06-03, older than today {today()}; set updated to {today()}")


def test_s13_class_change_without_moving_updated_is_red():
    proc = run_in_git_tree("2026-06-03", edit_class_description)
    _red(proc, "S13 matrix.json content differs from HEAD (attackClasses PHANTOM-SOUL) but updated is 2026-06-03")


def test_s13_updated_moved_but_still_older_than_today_is_red():
    proc = run_in_git_tree("2026-06-03", edit_technique_name, lambda r: set_updated(r, "2026-09-08"))
    _red(proc, f"but updated is 2026-09-08, older than today {today()}")


def test_s13_content_change_with_updated_set_to_today_is_green():
    proc = run_in_git_tree("2026-06-03", edit_technique_name, lambda r: set_updated(r, today()))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_s13_second_change_on_the_day_updated_was_set_is_green():
    proc = run_in_git_tree(today(), edit_class_description)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_s13_old_updated_with_no_content_change_is_green():
    proc = run_in_git_tree("2026-06-03")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_s13_is_skipped_where_the_tree_has_no_git():
    def fn(root):
        set_updated(root, "2026-06-03")
        edit_technique_name(root)
        regenerate_stix(root)
    proc = mutate(fn)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_shipped_updated_is_no_older_than_the_last_matrix_change():
    shallow = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--is-shallow-repository"],
                             capture_output=True, text=True, timeout=30, env=GIT_ENV)
    if shallow.returncode != 0 or shallow.stdout.strip() != "false":
        pytest.skip("needs the full git history of matrix.json")
    last = subprocess.run(["git", "-C", str(ROOT), "log", "-1", "--format=%ad", "--date=short",
                           "--", "matrix.json"], capture_output=True, text=True, timeout=30, env=GIT_ENV)
    assert last.returncode == 0, last.stderr
    assert load(ROOT, "matrix.json")["updated"] >= last.stdout.strip()


# --------------------------------------------------------------------------- S15 evidence references

TELEMETRY = "honeypot-telemetry"


def technique_of(matrix: dict, tid: str) -> dict:
    return next(t for t in matrix["techniques"] if t["id"] == tid)


def run_with_evidence(tid: str, entry: dict, render: bool = True):
    """Append entry to the evidence of technique tid in a scratch tree, render the STIX
    bundle again unless render is False, and validate the tree.

    Returns the process and the position the entry took in the technique's evidence[].
    """
    position = {}

    def fn(root):
        m = load(root, "matrix.json")
        evidence = technique_of(m, tid).setdefault("evidence", [])
        position["index"] = len(evidence)
        evidence.append(entry)
        dump(root, "matrix.json", m)
        if render:
            regenerate_stix(root)
    proc = mutate(fn)
    return proc, position["index"]


def test_evidence_fixture_with_a_dead_reference_is_red():
    # A path the registry endpoint does not serve: no source the validator reads stands
    # behind it, so the entry would cite a page nobody read.
    source = load(ROOT, "matrix.json")["wildPrevalenceSource"]
    dead = source["url"] + "/retired"
    proc, index = run_with_evidence("T-2001", {"type": TELEMETRY, "reference": dead, "date": source["read"]})
    _red(proc, f"S15 T-2001: evidence[{index}] reference {dead!r} does not resolve: a honeypot-telemetry "
               f"reference resolves only to the endpoint wildPrevalenceSource names, {source['url']}")


def test_telemetry_entry_dated_other_than_the_read_is_red():
    source = load(ROOT, "matrix.json")["wildPrevalenceSource"]
    proc, index = run_with_evidence("T-2001", {"type": TELEMETRY, "reference": source["url"],
                                               "date": "2026-01-01"})
    _red(proc, f"S15 T-2001: evidence[{index}] reference {source['url']!r} does not resolve: its date "
               f"2026-01-01 is not {source['read']}, the date wildPrevalenceSource says the endpoint was read")


def test_telemetry_entry_on_a_technique_the_endpoint_served_no_samples_for_is_red():
    matrix = load(ROOT, "matrix.json")
    assert technique_of(matrix, "T-1001")["wildSampleCount"] == 0
    source = matrix["wildPrevalenceSource"]
    proc, index = run_with_evidence("T-1001", {"type": TELEMETRY, "reference": source["url"],
                                               "date": source["read"]})
    _red(proc, f"S15 T-1001: evidence[{index}] reference {source['url']!r} does not resolve: the endpoint "
               f"served no samples for the technique on {source['read']}: its wildSampleCount is 0")


@pytest.mark.parametrize("kind", ["observation", "lab-reproduction", "publication", "advisory"])
def test_reference_of_a_kind_the_validator_reads_no_source_for_is_red(kind):
    reference = "https://example.org/no-such-page"
    proc, index = run_with_evidence("T-1001", {"type": kind, "reference": reference, "date": "2026-01-01"})
    _red(proc, f"S15 T-1001: evidence[{index}] reference {reference!r} does not resolve: the validator "
               f"reads no {kind} source, so it cannot show the reference was read")


def test_repeated_evidence_entry_is_red():
    matrix = load(ROOT, "matrix.json")
    entry = dict(technique_of(matrix, "T-2001")["evidence"][0])
    proc, index = run_with_evidence("T-2001", entry)
    _red(proc, f"S15 T-2001: evidence[{index}] repeats evidence[0] (the same type, reference and date)")


def test_evidence_reference_that_is_not_a_url_is_red_and_cannot_be_rendered():
    reference = "the vendor advisory"
    proc, index = run_with_evidence("T-1001", {"type": "advisory", "reference": reference,
                                               "date": "2026-01-01"}, render=False)
    _red(proc, f"S15 T-1001: evidence[{index}] reference {reference!r} does not resolve")
    assert (f"S10 scripts/generate_stix.py failed: FAIL: T-1001: evidence reference {reference!r} "
            f"is not an https URL") in proc.stderr, proc.stderr


def test_shipped_telemetry_entries_cite_the_read_on_each_technique_with_samples():
    matrix = load(ROOT, "matrix.json")
    source = matrix["wildPrevalenceSource"]
    for t in matrix["techniques"]:
        cites = [e for e in t.get("evidence", []) if e["type"] == TELEMETRY]
        if t["wildSampleCount"] > 0:
            assert [(e["reference"], e["date"]) for e in cites] == [(source["url"], source["read"])], t["id"]
        else:
            assert cites == [], t["id"]


def test_stix_attack_patterns_carry_each_evidence_reference():
    matrix = load(ROOT, "matrix.json")
    bundle = load(ROOT, "stix/agent-threat-matrix-bundle.json")
    patterns = {o["external_references"][0]["external_id"]: o for o in bundle["objects"]
                if o["type"] == "attack-pattern"}
    carried = 0
    for t in matrix["techniques"]:
        evidence = t.get("evidence", [])
        refs = patterns[t["id"]]["external_references"]
        tail = refs[len(refs) - len(evidence):] if evidence else []
        assert [(r["source_name"], r["url"]) for r in tail] == [(e["type"], e["reference"]) for e in evidence], t["id"]
        assert all(r["description"].startswith(f"{e['type']} evidence dated {e['date']}")
                   for r, e in zip(tail, evidence)), t["id"]
        carried += len(evidence)
    assert carried == sum(len(t.get("evidence", [])) for t in matrix["techniques"]) > 0


# --------------------------------------------------------------------------- S16 evidence gap list


def gap_ids(matrix: dict) -> list:
    return sorted(t["id"] for t in matrix["techniques"] if not t.get("evidence"))


def test_shipped_gap_list_names_every_technique_without_evidence():
    matrix = load(ROOT, "matrix.json")
    assert load(ROOT, "evidence-gaps.json")["ids"] == gap_ids(matrix)


def test_generator_prints_the_techniques_left_without_evidence():
    root = scratch_tree()
    try:
        (root / "evidence-gaps.json").unlink()
        proc = subprocess.run(["python3", str(root / "scripts" / "generate_stix.py")],
                              capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        matrix = load(root, "matrix.json")
        gaps = gap_ids(matrix)
        assert (f"{root / 'evidence-gaps.json'}: {len(gaps)} of {len(matrix['techniques'])} techniques "
                f"carry no evidence entry: {', '.join(gaps)}") in proc.stdout, proc.stdout
        assert (root / "evidence-gaps.json").read_bytes() == (ROOT / "evidence-gaps.json").read_bytes()
    finally:
        shutil.rmtree(root)


def test_gap_list_follows_the_evidence_when_the_files_are_rendered_again():
    def fn(root):
        m = load(root, "matrix.json")
        del technique_of(m, "T-2001")["evidence"]
        dump(root, "matrix.json", m)
        regenerate_stix(root)
        assert "T-2001" in load(root, "evidence-gaps.json")["ids"]
    proc = mutate(fn)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_s16_gap_list_edited_by_hand_is_red():
    def fn(root):
        gaps = load(root, "evidence-gaps.json")
        gaps["ids"] = gaps["ids"][1:]
        dump(root, "evidence-gaps.json", gaps)
    _red(mutate(fn), "S16 evidence-gaps.json is not what scripts/generate_stix.py renders from matrix.json")


def test_s16_gap_list_out_of_step_with_the_evidence_is_red():
    def fn(root):
        m = load(root, "matrix.json")
        del technique_of(m, "T-2001")["evidence"]
        dump(root, "matrix.json", m)
        path = root / "stix" / "agent-threat-matrix-bundle.json"
        subprocess.run(["python3", str(root / "scripts" / "generate_stix.py"), "--output", str(path),
                        "--gaps-output", str(root / "unused-gaps.json")],
                       check=True, capture_output=True, text=True, timeout=120)
    _red(mutate(fn), "S16 evidence-gaps.json is not what scripts/generate_stix.py renders from matrix.json")


def test_s16_missing_gap_list_is_red():
    _red(mutate(lambda root: (root / "evidence-gaps.json").unlink()),
         "S16 evidence-gaps.json is missing; run scripts/generate_stix.py")
