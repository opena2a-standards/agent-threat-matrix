"""Schema 1.2 validator and STIX generator tests.

Every case runs scripts/validate_matrix.py against a scratch copy of the tree so the
committed files are never perturbed. The shipped tree must be green; each rule the
validator enforces is proven red on one minimal mutation.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = ("matrix.json", "technique-ids.json", "schema/threat-matrix-v1.2.schema.json",
         "schema/consumer-readiness.json", "scripts/validate_matrix.py",
         "scripts/generate_stix.py", "stix/agent-threat-matrix-bundle.json")


def scratch_tree() -> Path:
    td = Path(tempfile.mkdtemp(prefix="atm-schema-"))
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
                           "matrix.json", "technique-ids.json", "stix", "schema"],
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
