"""Schema 1.2 validator and STIX generator tests.

Every case runs scripts/validate_matrix.py against a scratch copy of the tree so the
committed files are never perturbed. The shipped tree must be green; each rule the
validator enforces is proven red on one minimal mutation.
"""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = ("matrix.json", "technique-ids.json", "schema/threat-matrix-v1.2.schema.json",
         "schema/consumer-readiness.json", "schema/evidence-sources.schema.json",
         "scripts/validate_matrix.py", "scripts/generate_stix.py",
         "stix/agent-threat-matrix-bundle.json", "evidence-gaps.json", "evidence-sources.json")
INPUT_SCHEMAS = ["schema/threat-matrix-v1.2.schema.json", "schema/consumer-readiness.json",
                 "schema/evidence-sources.schema.json"]


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


@pytest.mark.parametrize("rel", ["matrix.json"] + INPUT_SCHEMAS)
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
        f"FAIL: {rel} is missing or does not parse: Not a directory" for rel in INPUT_SCHEMAS
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
@pytest.mark.parametrize("rel", ["matrix.json"] + INPUT_SCHEMAS)
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


def reader(tool: str = "example-tool") -> dict:
    """A readBy citation with illustrative values: the validator checks its shape, not the file."""
    return {"tool": tool, "repository": "example-org/example-tool", "commit": "0" * 40,
            "path": "src/example.ts", "line": 1}


def data_source(source_id: str = "honeypot") -> dict:
    return {"id": source_id, "name": "Honeypot", "description": "Honeypot telemetry",
            "readBy": [reader()]}


def mapping(source: str = "honeypot", tool: str = "example-tool") -> dict:
    return {"source": source, "tool": tool, "kind": "sensorField", "ref": "request.path"}


SHIPPED_SOURCES = load(ROOT, "matrix.json")["dataSources"]


def with_data_sources(registry: list, technique_sources: list):
    """Return a mutation that puts the entries ahead of the shipped registry, so the first of
    them is dataSources[0], and sets the first technique's mappings."""
    def fn(root):
        m = load(root, "matrix.json")
        m["dataSources"] = registry + m["dataSources"]
        m["techniques"][0]["dataSources"] = technique_sources
        dump(root, "matrix.json", m)
        regenerate_stix(root)
    return fn


def test_data_source_must_resolve_in_the_registry():
    _red(mutate(with_data_sources([], [mapping()])),
         "S4 T-1001: dataSources source 'honeypot' is not in the dataSources registry")


def test_data_source_resolves_when_registered():
    proc = mutate(with_data_sources([data_source()], [mapping()]))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"{len(SHIPPED_SOURCES) + 1} data sources" in proc.stdout


def test_data_source_without_a_reader_citation_is_refused():
    entry = data_source()
    del entry["readBy"]
    _red(mutate(with_data_sources([entry], [])),
         "matrix.dataSources[0]: missing required property 'readBy'")


def test_data_source_with_an_empty_reader_list_is_refused():
    entry = dict(data_source(), readBy=[])
    _red(mutate(with_data_sources([entry], [])),
         "matrix.dataSources[0].readBy: 0 item(s), fewer than the minimum 1")


def test_reader_citation_needs_a_line_and_a_pinned_commit():
    citation = dict(reader(), commit="main")
    del citation["line"]
    proc = mutate(with_data_sources([dict(data_source(), readBy=[citation])], []))
    _red(proc, "matrix.dataSources[0].readBy[0]: missing required property 'line'")
    assert "matrix.dataSources[0].readBy[0].commit: 'main' does not match" in proc.stderr, proc.stderr


def test_technique_mapping_must_name_the_check_signature_or_sensor_field():
    bare = {"source": "honeypot", "tool": "example-tool"}
    proc = mutate(with_data_sources([data_source()], [bare]))
    _red(proc, "matrix.techniques[0].dataSources[0]: missing required property 'kind'")
    assert "matrix.techniques[0].dataSources[0]: missing required property 'ref'" in proc.stderr, proc.stderr


def test_technique_mapping_kind_is_a_check_a_signature_or_a_sensor_field():
    proc = mutate(with_data_sources([data_source()], [dict(mapping(), kind="rule")]))
    _red(proc, "matrix.techniques[0].dataSources[0].kind: 'rule' is not one of")


def test_technique_mapping_is_an_object_not_a_bare_source_id():
    _red(mutate(with_data_sources([data_source()], ["honeypot"])),
         "matrix.techniques[0].dataSources[0]: expected type object, got str")


def test_technique_mapping_names_a_tool_that_the_source_reader_citations_cite():
    _red(mutate(with_data_sources([data_source()], [mapping(tool="other-tool")])),
         "S4 T-1001: dataSources source 'honeypot' names tool 'other-tool', which its readBy "
         "does not cite (example-tool)")


def hma_source() -> dict:
    """A registry entry whose readBy cites hackmyagent, with illustrative citation values."""
    return dict(data_source(), readBy=[reader("hackmyagent")])


def hma_mapping(ref: str, kind: str = "check") -> dict:
    return {"source": "honeypot", "tool": "hackmyagent", "kind": kind, "ref": ref}


def test_a_hackmyagent_check_that_hma_checks_does_not_list_is_refused():
    # T-1001 lists WEBEXPOSE-001, WEBEXPOSE-002 and MCP-011; PROMPT-001 is another technique's.
    _red(mutate(with_data_sources([hma_source()], [hma_mapping("PROMPT-001")])),
         "S18 T-1001: dataSources source 'honeypot' names hackmyagent check 'PROMPT-001', which "
         "hmaChecks does not list; add the check to hmaChecks, or name a check that hmaChecks lists")


def test_a_hackmyagent_check_that_hma_checks_lists_is_accepted():
    proc = mutate(with_data_sources([hma_source()], [hma_mapping("WEBEXPOSE-001")]))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_hma_checks_rule_reads_only_hackmyagent_checks():
    entry = dict(data_source(), readBy=[reader("hackmyagent"), reader()])
    uses = [hma_mapping("PROMPT-001", kind="signature"),
            {"source": "honeypot", "tool": "example-tool", "kind": "check", "ref": "PROMPT-001"}]
    proc = mutate(with_data_sources([entry], uses))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_every_shipped_technique_carries_data_sources_and_its_hackmyagent_checks_are_listed():
    techniques = load(ROOT, "matrix.json")["techniques"]
    assert all("dataSources" in t for t in techniques)
    assert any(t["dataSources"] for t in techniques), "no technique maps a data source"
    for t in techniques:
        for use in t["dataSources"]:
            if use["tool"] == "hackmyagent" and use["kind"] == "check":
                assert use["ref"] in t["hmaChecks"], (t["id"], use)


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


def edit_technique_name(root: Path, tid: str = "T-1001") -> None:
    # T-1001 carries no evidence entry: a pinned page names a technique by its name, so
    # renaming a technique that cites one is an S15 finding as well as a content change.
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
    _red(proc, f"S13 matrix.json content differs from HEAD (techniques T-1001) but updated is "
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


@pytest.mark.parametrize("kind", ["observation", "publication", "advisory"])
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


# --------------------------------------------------------------------------- S15 lab-reproduction entries

LAB = "lab-reproduction"
DVAA = "https://github.com/opena2a-org/damn-vulnerable-ai-agent"
LATERAL = "scenarios/prompt-to-lateral-movement/README.md"
THRESH = "scenarios/agent-thresh-01/README.md"


def pinned_pages(root: Path = ROOT) -> list:
    return load(root, "evidence-sources.json")["dvaa"]["pages"]


def permalink(page: dict) -> str:
    return f"{DVAA}/blob/{page['commit']}/{page['path']}"


def page_entry(path: str, **change) -> dict:
    """The lab-reproduction entry that cites the pinned page at path, with change applied."""
    page = next(p for p in pinned_pages() if p["path"] == path)
    return dict({"type": LAB, "reference": permalink(page), "date": page["committed"]}, **change)


def test_shipped_lab_entries_cite_a_pinned_page_that_names_the_technique():
    pages = {permalink(page): page for page in pinned_pages()}
    cited = 0
    for t in load(ROOT, "matrix.json")["techniques"]:
        for entry in t.get("evidence", []):
            if entry["type"] == LAB and entry["reference"] in pages:
                page = pages[entry["reference"]]
                assert entry["date"] == page["committed"], t["id"]
                assert (t["id"], t["name"]) in [(n["technique"], n["label"]) for n in page["names"]], t["id"]
                cited += 1
    assert cited > 0


def test_every_pinned_name_that_is_its_technique_name_is_cited():
    techniques = {t["id"]: t for t in load(ROOT, "matrix.json")["techniques"]}
    for page in pinned_pages():
        entry = {"type": LAB, "reference": permalink(page), "date": page["committed"]}
        for name in page["names"]:
            t = techniques.get(name["technique"])
            if t is not None and t["name"] == name["label"]:
                assert entry in t.get("evidence", []), (page["path"], name)


def test_lab_entry_citing_a_page_no_pin_holds_is_red():
    # The commit is pinned, the page is not: no record stands behind the reference, so the
    # entry would cite a page nobody read.
    entry = page_entry(LATERAL)
    dead = entry["reference"].replace("prompt-to-lateral-movement", "no-such-scenario")
    proc, index = run_with_evidence("T-1001", dict(entry, reference=dead))
    _red(proc, f"S15 T-1001: evidence[{index}] reference {dead!r} does not resolve: evidence-sources.json "
               f"pins no page with this reference, so the validator cannot show it was read")


def test_lab_entry_citing_a_pinned_page_that_does_not_name_the_technique_is_red():
    entry = page_entry(LATERAL)
    proc, index = run_with_evidence("T-1001", entry)
    _red(proc, f"S15 T-1001: evidence[{index}] reference {entry['reference']!r} does not resolve: the page "
               f"evidence-sources.json pins at this reference names no T-1001")


@pytest.mark.parametrize("path, label", [(LATERAL, "Prompt Injection"), (THRESH, "Threshold Exhaustion")])
def test_lab_entry_citing_a_page_that_names_the_id_under_another_label_is_red(path, label):
    # Both pages name T-2001, under labels that are not Direct Prompt Injection.
    entry = page_entry(path)
    proc, index = run_with_evidence("T-2001", entry)
    _red(proc, f"S15 T-2001: evidence[{index}] reference {entry['reference']!r} does not resolve: the page "
               f"names T-2001 as {label!r}, not as 'Direct Prompt Injection', its name in matrix.json")


def test_lab_entry_dated_other_than_the_commit_that_wrote_the_page_is_red():
    entry = page_entry(LATERAL, date="2026-10-21")
    proc, index = run_with_evidence("T-1002", entry)
    _red(proc, f"S15 T-1002: evidence[{index}] reference {entry['reference']!r} does not resolve: its date "
               f"2026-10-21 is not {page_entry(LATERAL)['date']}, the date evidence-sources.json gives the "
               f"commit that wrote the page")


def test_renaming_a_technique_a_pinned_page_names_leaves_its_lab_entry_unresolved():
    # The page names T-1006 by the name it had when the page was pinned; pin the page again
    # once it names the technique as matrix.json does.
    def fn(root):
        edit_technique_name(root, "T-1006")
        regenerate_stix(root)
    reference = page_entry("scenarios/atc-forgery-attack/README.md")["reference"]
    _red(mutate(fn), f"S15 T-1006: evidence[0] reference {reference!r} does not resolve: the page names "
                     f"T-1006 as 'Agent Card Discovery', not as 'Agent Card Discovery (edited)', its name "
                     f"in matrix.json")


def test_repeated_lab_entry_is_red():
    proc, index = run_with_evidence("T-1002", page_entry(LATERAL))
    _red(proc, f"S15 T-1002: evidence[{index}] repeats evidence[0] (the same type, reference and date)")


def test_lab_entry_resolves_once_a_pinned_page_names_the_technique_under_its_name():
    # The validator before this rule refused every lab-reproduction entry; it reads the pins now.
    def fn(root):
        sources = load(root, "evidence-sources.json")
        page = next(p for p in sources["dvaa"]["pages"] if p["path"] == LATERAL)
        page["names"].append({"line": 99, "technique": "T-1001", "label": "Endpoint Enumeration"})
        dump(root, "evidence-sources.json", sources)
        m = load(root, "matrix.json")
        technique_of(m, "T-1001")["evidence"] = [page_entry(LATERAL)]
        dump(root, "matrix.json", m)
        regenerate_stix(root)
    proc = mutate(fn)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    shipped = load(ROOT, "matrix.json")
    # T-1001 carried no entry, so the tree has one entry more and one bare technique fewer.
    assert "evidence" not in technique_of(shipped, "T-1001")
    entries = sum(len(t.get("evidence", [])) for t in shipped["techniques"]) + 1
    bare = sum(1 for t in shipped["techniques"] if not t.get("evidence")) - 1
    assert f"{entries} evidence entries resolved ({bare} techniques with none)" in proc.stdout, proc.stdout


# --------------------------------------------------------------------------- S15 entries a dvaaValidation backs

CHALLENGE_FILE = "src/challenges/index.js"


def pinned_dvaa(root: Path = ROOT) -> dict:
    return load(root, "evidence-sources.json")["dvaa"]


def named_pins(root: Path = ROOT) -> dict:
    """The value a dvaaValidation names and the date of the file, by the permalink of each
    challenge and scenario page evidence-sources.json pins for a dvaaValidation."""
    dvaa = pinned_dvaa(root)
    pins = {}
    challenges = dvaa.get("challenges")
    for challenge in challenges["named"] if challenges else []:
        pins[f"{permalink(challenges)}#L{challenge['line']}"] = (challenge["id"], challenges["committed"])
    for page in dvaa.get("scenarios", []):
        pins[permalink(page)] = (page["path"].split("/")[1], page["committed"])
    return pins


def values_of(technique: dict) -> list:
    return [part.strip() for part in (technique["dvaaValidation"] or "").split(",") if part.strip()]


def named_entry(value: str, **change) -> dict:
    """The lab-reproduction entry that cites the challenge or scenario page pinned for value."""
    reference, (_, committed) = next((ref, pin) for ref, pin in named_pins().items() if pin[0] == value)
    return dict({"type": LAB, "reference": reference, "date": committed}, **change)


def test_shipped_lab_entries_that_cite_no_page_cite_what_their_dvaa_validation_names():
    pages = {permalink(page) for page in pinned_pages()}
    pins = named_pins()
    cited = 0
    for t in load(ROOT, "matrix.json")["techniques"]:
        for entry in t.get("evidence", []):
            if entry["type"] == LAB and entry["reference"] not in pages:
                value, committed = pins[entry["reference"]]
                assert entry["date"] == committed, t["id"]
                assert value in values_of(t), t["id"]
                cited += 1
    assert cited > 0


def test_every_challenge_and_scenario_page_pinned_for_a_dvaa_validation_is_cited_by_it():
    by_value = {value: (reference, committed) for reference, (value, committed) in named_pins().items()}
    for t in load(ROOT, "matrix.json")["techniques"]:
        for value in values_of(t):
            if value in by_value:
                reference, committed = by_value[value]
                entry = {"type": LAB, "reference": reference, "date": committed}
                assert entry in t.get("evidence", []), (t["id"], value)


def test_t2001_cites_the_dvaa_challenge_its_dvaa_validation_names():
    # The page that names T-2001 under its own name is a challenge, L1-03; neither scenario page
    # that names the id labels it Direct Prompt Injection.
    t2001 = technique_of(load(ROOT, "matrix.json"), "T-2001")
    challenges = pinned_dvaa()["challenges"]
    line = next(c["line"] for c in challenges["named"] if c["id"] == "L1-03")
    assert t2001["dvaaValidation"] == "L1-03"
    assert t2001["evidence"][0] == {
        "type": LAB, "reference": f"{DVAA}/blob/{challenges['commit']}/{CHALLENGE_FILE}#L{line}",
        "date": challenges["committed"]}


def test_challenge_entry_on_a_technique_whose_dvaa_validation_does_not_name_it_is_red():
    entry = named_entry("L1-03")
    proc, index = run_with_evidence("T-1001", entry)
    _red(proc, f"S15 T-1001: evidence[{index}] reference {entry['reference']!r} does not resolve: "
               f"evidence-sources.json pins the DVAA challenge L1-03 at this reference, and the "
               f"technique's dvaaValidation, 'All agents expose /health and /info', does not name it")


def test_scenario_entry_on_a_technique_whose_dvaa_validation_does_not_name_it_is_red():
    entry = named_entry("mcp-rug-pull")
    proc, index = run_with_evidence("T-1001", entry)
    _red(proc, f"S15 T-1001: evidence[{index}] reference {entry['reference']!r} does not resolve: "
               f"evidence-sources.json pins the DVAA scenario mcp-rug-pull at this reference, and the "
               f"technique's dvaaValidation, 'All agents expose /health and /info', does not name it")


def test_challenge_entry_dated_other_than_the_commit_that_wrote_the_file_is_red():
    entry = named_entry("L1-03", date="2026-10-21")
    proc, index = run_with_evidence("T-2001", entry)
    _red(proc, f"S15 T-2001: evidence[{index}] reference {entry['reference']!r} does not resolve: its date "
               f"2026-10-21 is not {named_entry('L1-03')['date']}, the date evidence-sources.json gives the "
               f"commit that wrote the file")


def test_challenge_entry_at_a_line_no_pin_holds_is_red():
    entry = named_entry("L1-03")
    line = int(entry["reference"].rsplit("#L", 1)[1])
    moved = entry["reference"].rsplit("#L", 1)[0] + f"#L{line + 1}"
    proc, index = run_with_evidence("T-2001", dict(entry, reference=moved))
    _red(proc, f"S15 T-2001: evidence[{index}] reference {moved!r} does not resolve: evidence-sources.json "
               f"pins no page with this reference, so the validator cannot show it was read")


def test_editing_a_dvaa_validation_leaves_its_entry_unresolved_and_its_pin_unnamed():
    def fn(root):
        m = load(root, "matrix.json")
        technique_of(m, "T-2001")["dvaaValidation"] = "L1-04"
        dump(root, "matrix.json", m)
        regenerate_stix(root)
    proc = mutate(fn)
    reference = named_entry("L1-03")["reference"]
    index = next(i for i, c in enumerate(pinned_dvaa()["challenges"]["named"]) if c["id"] == "L1-03")
    _red(proc,f"S15 T-2001: evidence[0] reference {reference!r} does not resolve: evidence-sources.json "
               f"pins the DVAA challenge L1-03 at this reference, and the technique's dvaaValidation, "
               f"'L1-04', does not name it")
    assert (f"S17 evidence-sources.dvaa.challenges.named[{index}] (L1-03): no technique's dvaaValidation "
            f"names it; a challenge is pinned for the techniques that name it") in proc.stderr, proc.stderr


def test_entry_resolves_once_a_dvaa_validation_names_a_pinned_challenge():
    # T-1001 names no lab work; once its dvaaValidation also lists L1-03, the entry citing the
    # pinned challenge resolves.
    def fn(root):
        m = load(root, "matrix.json")
        t1001 = technique_of(m, "T-1001")
        t1001["dvaaValidation"] += ", L1-03"
        t1001["evidence"] = [named_entry("L1-03")]
        dump(root, "matrix.json", m)
        regenerate_stix(root)
    proc = mutate(fn)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# --------------------------------------------------------------------------- S17 evidence-sources.json


def edit_sources(change):
    """A mutation that applies change to evidence-sources.json in a scratch tree."""
    def fn(root):
        sources = load(root, "evidence-sources.json")
        change(sources["dvaa"])
        dump(root, "evidence-sources.json", sources)
    return fn


def test_s17_missing_sources_file_is_red_and_no_lab_entry_resolves():
    proc = mutate(lambda root: (root / "evidence-sources.json").unlink())
    _red(proc, "S17 evidence-sources.json is missing or does not parse: no such file")
    assert "does not resolve: evidence-sources.json pins no page with this reference" in proc.stderr


def test_s17_directory_at_the_sources_file_is_red():
    _red(mutate(replace_with_directory("evidence-sources.json")),
         "S17 evidence-sources.json is missing or does not parse: a directory, not a file")


@pytest.mark.parametrize("change, needle", [
    (lambda d: d["pages"][0].update(blob="ef5db56"),
     "S17 evidence-sources.dvaa.pages[0].blob: 'ef5db56' does not match ^[0-9a-f]{40}$"),
    (lambda d: d.update(repository="https://github.com/example/fork"),
     "S17 evidence-sources.dvaa.repository: expected 'https://github.com/opena2a-org/damn-vulnerable-ai-agent', "
     "got 'https://github.com/example/fork'"),
    (lambda d: d["pages"][0].update(path="../README.md"),
     "S17 evidence-sources.dvaa.pages[0].path: '../README.md' does not match"),
    (lambda d: d["pages"][0]["names"][0].update(label="(Prompt Injection)"),
     "S17 evidence-sources.dvaa.pages[0].names[0].label: '(Prompt Injection)' does not match"),
    (lambda d: d["pages"][0]["names"][0].update(line=0),
     "S17 evidence-sources.dvaa.pages[0].names[0].line: 0 is below the minimum 1"),
    (lambda d: d["pages"][0].update(note="read in full"),
     "S17 evidence-sources.dvaa.pages[0]: unexpected property 'note'"),
    (lambda d: d.pop("head"), "S17 evidence-sources.dvaa: missing required property 'head'"),
    (lambda d: d["challenges"].update(path="src/challenges/other.js"),
     "S17 evidence-sources.dvaa.challenges.path: expected 'src/challenges/index.js', got 'src/challenges/other.js'"),
    (lambda d: d["challenges"]["named"][0].update(id="L1 01"),
     "S17 evidence-sources.dvaa.challenges.named[0].id: 'L1 01' does not match"),
    (lambda d: d["challenges"].pop("named"), "S17 evidence-sources.dvaa.challenges: missing required property 'named'"),
    (lambda d: d["scenarios"][0].update(names=[]),
     "S17 evidence-sources.dvaa.scenarios[0]: unexpected property 'names'"),
])
def test_s17_sources_file_outside_its_schema_is_red_and_no_lab_entry_resolves(change, needle):
    proc = mutate(edit_sources(change))
    _red(proc, needle)
    assert "does not resolve: evidence-sources.json pins no page with this reference" in proc.stderr


def test_s17_read_date_that_is_not_a_calendar_date_is_red():
    _red(mutate(edit_sources(lambda d: d.update(read="2026-02-30"))),
         "S17 evidence-sources.dvaa.read: '2026-02-30' is not a calendar date")


def test_s17_read_date_later_than_today_is_red():
    _red(mutate(edit_sources(lambda d: d.update(read="2999-01-01"))),
         f"S17 evidence-sources.dvaa.read: 2999-01-01 is later than today, {date.today().isoformat()}")


def test_s17_page_committed_later_than_the_read_is_red():
    def change(d):
        d["pages"][0]["committed"] = "2026-10-22"
        d["read"] = "2026-10-21"
    _red(mutate(edit_sources(change)),
         f"S17 evidence-sources.dvaa.pages[0] ({THRESH}): committed 2026-10-22 is later than read "
         f"2026-10-21, the date the clone was read")


def test_s17_committed_date_that_is_not_a_calendar_date_is_red():
    _red(mutate(edit_sources(lambda d: d["pages"][0].update(committed="2026-13-01"))),
         f"S17 evidence-sources.dvaa.pages[0] ({THRESH}): committed '2026-13-01' is not a calendar date")


def test_s17_page_that_names_no_technique_is_red():
    _red(mutate(edit_sources(lambda d: d["pages"][0].update(names=[]))),
         f"S17 evidence-sources.dvaa.pages[0] ({THRESH}): names no technique; a page is pinned for "
         f"the techniques it names")


def test_s17_sources_schema_keyword_outside_the_checker_subset_is_red():
    # The pinned pages meet the bound, so the keyword the checker does not read is the only
    # cause of the red run.
    def fn(root):
        schema = load(root, "schema/evidence-sources.schema.json")
        schema["$defs"]["dvaa"]["properties"]["pages"]["maxItems"] = len(pinned_pages(root))
        dump(root, "schema/evidence-sources.schema.json", schema)
    _red(mutate(fn), "S17 schema/evidence-sources.schema.json: schema keyword 'maxItems' at "
                     "evidence-sources.dvaa.pages is outside the supported subset")


def test_s17_page_pinned_twice_is_red():
    def change(d):
        d["pages"].append(dict(d["pages"][0], commit=d["head"]))
    proc = mutate(edit_sources(change))
    last = len(pinned_pages())
    _red(proc, f"S17 evidence-sources.dvaa.pages[{last}] ({THRESH}): evidence-sources.dvaa.pages[0] pins "
               f"this page already")


def test_s17_challenge_file_that_names_no_challenge_is_red():
    _red(mutate(edit_sources(lambda d: d["challenges"].update(named=[]))),
         "S17 evidence-sources.dvaa.challenges: names no challenge; the file is pinned for the challenges "
         "a dvaaValidation names")


def test_s17_challenge_listed_twice_is_red():
    named = pinned_dvaa()["challenges"]["named"]
    proc = mutate(edit_sources(lambda d: d["challenges"]["named"].append(dict(named[0]))))
    _red(proc, f"S17 evidence-sources.dvaa.challenges.named[{len(named)}] ({named[0]['id']}): "
               f"evidence-sources.dvaa.challenges.named[0] lists this challenge already")


def test_s17_challenge_no_dvaa_validation_names_is_red():
    named = pinned_dvaa()["challenges"]["named"]
    extra = {"line": 1, "id": "L9-99", "name": "A challenge no technique names"}
    proc = mutate(edit_sources(lambda d: d["challenges"]["named"].append(extra)))
    _red(proc, f"S17 evidence-sources.dvaa.challenges.named[{len(named)}] (L9-99): no technique's "
               f"dvaaValidation names it; a challenge is pinned for the techniques that name it")


def test_s17_challenge_file_committed_later_than_the_read_is_red():
    def change(d):
        d["challenges"]["committed"] = "2026-10-22"
        d["read"] = "2026-10-21"
    _red(mutate(edit_sources(change)),
         "S17 evidence-sources.dvaa.challenges: committed 2026-10-22 is later than read 2026-10-21, the "
         "date the clone was read")


def test_s17_scenarios_that_pin_no_page_is_red():
    _red(mutate(edit_sources(lambda d: d.update(scenarios=[]))),
         "S17 evidence-sources.dvaa.scenarios: pins no page; the key is written for the scenarios a "
         "dvaaValidation names")


def test_s17_scenario_page_pinned_twice_is_red():
    scenarios = pinned_dvaa()["scenarios"]
    proc = mutate(edit_sources(lambda d: d["scenarios"].append(dict(scenarios[0]))))
    _red(proc, f"S17 evidence-sources.dvaa.scenarios[{len(scenarios)}] ({scenarios[0]['path']}): "
               f"evidence-sources.dvaa.scenarios[0] pins this page already")


def test_s17_scenario_page_no_dvaa_validation_names_is_red():
    scenarios = pinned_dvaa()["scenarios"]
    extra = dict(scenarios[0], path="scenarios/no-technique-names-it/README.md")
    proc = mutate(edit_sources(lambda d: d["scenarios"].append(extra)))
    _red(proc, f"S17 evidence-sources.dvaa.scenarios[{len(scenarios)}] (scenarios/no-technique-names-it/"
               f"README.md): no technique's dvaaValidation names the scenario 'no-technique-names-it'; a "
               f"scenario page is pinned for the techniques that name it")


def test_s17_scenario_committed_date_that_is_not_a_calendar_date_is_red():
    path = pinned_dvaa()["scenarios"][0]["path"]
    _red(mutate(edit_sources(lambda d: d["scenarios"][0].update(committed="2026-13-01"))),
         f"S17 evidence-sources.dvaa.scenarios[0] ({path}): committed '2026-13-01' is not a calendar date")


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


# --------------------------------------------------------------------------- schema patterns
# A JSON Schema pattern is an ECMA-262 regular expression. Python's re reads some of the same
# text another way: its $ also matches before a final newline, so "T-1001\n" passed
# ^T-[0-9]{4}$, which ECMA-262 refuses.


@pytest.fixture(scope="module")
def validator():
    spec = importlib.util.spec_from_file_location("validate_matrix", ROOT / "scripts" / "validate_matrix.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def pattern_errors(validator, value: str, pattern: str) -> list:
    """What the shape pass reports for a string ``value`` against ``pattern``."""
    checker = validator.SchemaChecker({})
    checker.check(value, {"type": "string", "pattern": pattern}, "value")
    return checker.errors


def schema_patterns(node) -> set:
    """Every ``pattern`` the schema states."""
    if isinstance(node, dict):
        found = {node["pattern"]} if isinstance(node.get("pattern"), str) else set()
        return found.union(*(schema_patterns(value) for value in node.values()))
    if isinstance(node, list):
        return set().union(*(schema_patterns(value) for value in node))
    return set()


def test_reader_commit_and_mapping_ref_that_end_in_a_newline_are_refused():
    # Both passed, and scripts/check_technique_pages.py --fix then wrote the ref across two
    # lines of the technique page, which the runs after it reported as differing from
    # matrix.json.
    commit = "0" * 40 + "\n"
    registry = [dict(data_source(), readBy=[dict(reader(), commit=commit)])]
    proc = mutate(with_data_sources(registry, [dict(mapping(), ref="request.path\n")]))
    _red(proc, f"matrix.dataSources[0].readBy[0].commit: {commit!r} does not match ^[0-9a-f]{{40}}$")
    assert r"matrix.techniques[0].dataSources[0].ref: 'request.path\n' does not match ^\S(.*\S)?$" \
        in proc.stderr, proc.stderr


def test_every_schema_pattern_that_ends_in_a_dollar_refuses_its_value_with_a_newline_after_it(validator):
    """Each such pattern is tried on the first value checked against it in the shipped
    matrix, with a data source, a mapping and a versioned sub-technique added so that every
    pattern is reached."""
    schema = load(ROOT, "schema/threat-matrix-v1.2.schema.json")
    matrix = load(ROOT, "matrix.json")
    matrix["dataSources"] = [data_source()]
    first = matrix["techniques"][0]
    first["dataSources"] = [mapping()]
    matrix["techniques"].append(dict(first, id=first["id"] + ".001", parentId=first["id"],
                                     version="1.0.0"))
    samples = {}

    class Recorder(validator.SchemaChecker):
        def check(self, value, schema, path):
            if "pattern" in schema and isinstance(value, str):
                samples.setdefault(schema["pattern"], value)
            super().check(value, schema, path)

    recorder = Recorder(schema)
    recorder.check(matrix, schema, "matrix")
    assert recorder.errors == []
    patterns = schema_patterns(schema)
    assert patterns <= set(samples), sorted(patterns - set(samples))
    anchored = sorted(pattern for pattern in patterns if pattern.endswith("$"))
    assert anchored
    for pattern in anchored:
        value = samples[pattern]
        assert pattern_errors(validator, value, pattern) == [], pattern
        assert pattern_errors(validator, value + "\n", pattern) == [
            f"value: {value + chr(10)!r} does not match {pattern}"]


REF = ("dataSourceMapping", "ref")
READER_PATH = ("sourceReader", "path")


@pytest.mark.parametrize("field,value,accepted", [
    # ECMA-262's . does not match \r, U+2028 or U+2029; Python's does.
    (REF, "request\rpath", False),
    (REF, "request\N{LINE SEPARATOR}path", False),
    (REF, "request\N{PARAGRAPH SEPARATOR}path", False),
    # U+FEFF is white space to ECMA-262's \s and \S and not to Python's; U+001C and U+0085
    # are white space to Python's and not to ECMA-262's.
    (REF, "request.path\N{ZERO WIDTH NO-BREAK SPACE}", False),
    (REF, "request.path\x1c", True),
    (REF, "\x85request.path", True),
    (READER_PATH, "src/\N{ZERO WIDTH NO-BREAK SPACE}example.ts", False),
    (READER_PATH, "src/\x1cexample.ts", True),
    (READER_PATH, "\x85src/example.ts", True),
])
def test_schema_pattern_reads_dot_and_white_space_as_ecma_262_does(validator, field, value, accepted):
    definition, prop = field
    schema = load(ROOT, "schema/threat-matrix-v1.2.schema.json")
    pattern = schema["$defs"][definition]["properties"][prop]["pattern"]
    want = [] if accepted else [f"value: {value!r} does not match {pattern}"]
    assert pattern_errors(validator, value, pattern) == want


@pytest.mark.parametrize("pattern,value,accepted", [
    (r"^\d$", "\N{ARABIC-INDIC DIGIT THREE}", False),  # ECMA-262's \d is [0-9]
    (r"^\D$", "\N{ARABIC-INDIC DIGIT THREE}", True),
    (r"^\w$", "\N{LATIN SMALL LETTER E WITH ACUTE}", False),  # and its \w is [A-Za-z0-9_]
    (r"^\W$", "\N{LATIN SMALL LETTER E WITH ACUTE}", True),
    (r"^a\b", "a\N{LATIN SMALL LETTER E WITH ACUTE}", True),
    (r"^a\B", "a\N{LATIN SMALL LETTER E WITH ACUTE}", False),
    (r"^a[]", "ab", False),  # [] matches no character
    (r"^a[^]$", "a\n", True),  # [^] matches any character
    (r"^a[^]b$", "a\rb", True),
    (r"^[a\S]$", "\x1c", True),  # \S inside a class reads ECMA-262's white space too
    (r"^[a\S]$", "\N{ZERO WIDTH NO-BREAK SPACE}", False),
    (r"^[^a\S]$", "\N{ZERO WIDTH NO-BREAK SPACE}", True),
    (r"^[^a\S]$", "\x1c", False),
])
def test_pattern_constructs_the_schema_does_not_use_are_read_as_ecma_262_does(validator, pattern, value,
                                                                               accepted):
    want = [] if accepted else [f"value: {value!r} does not match {pattern}"]
    assert pattern_errors(validator, value, pattern) == want


def test_white_space_and_its_complement_are_the_code_points_ecma_262_names(validator):
    """Tab, vertical tab, form feed, U+FEFF and the Space_Separator (Zs) code points are
    white space; \\n, \\r, U+2028 and U+2029 are line terminators. ECMA_NOT_SPACE holds
    every other code point."""
    codes = range(0x110000)
    zs = {code for code in codes if unicodedata.category(chr(code)) == "Zs"}
    want = {0x09, 0x0B, 0x0C, 0xFEFF, 0x0A, 0x0D, 0x2028, 0x2029} | zs
    space = re.compile(f"[{validator.ECMA_SPACE}]")
    not_space = re.compile(f"[{validator.ECMA_NOT_SPACE}]")
    assert {code for code in codes if space.match(chr(code))} == want
    assert {code for code in codes if not_space.match(chr(code))} == set(codes) - want
