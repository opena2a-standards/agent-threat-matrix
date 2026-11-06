"""crosswalks/technique-crosswalk.json is rendered from matrix.json, technique-ids.json and
vendor/, and scripts/check_technique_crosswalk.py fails when it is not.

Each failing case copies the files the rendering reads into a scratch root, breaks one rule
there, and runs the shipped check on that root, so the committed tree is never written. A
case that breaks an input renders the scratch crosswalk again first, so the failure it shows
is the rule under test, not a stale file. Every id resolves against its own family's list:
a payload id in a check column fails even though the payload list holds it, and a
``superseded_by`` value in retired-ids.yaml is not a retired id. The cases on the files git
ignores commit the scratch root to a repository built in the test.
"""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BUILDER = ROOT / "scripts" / "build_technique_crosswalk.py"
CHECKER = ROOT / "scripts" / "check_technique_crosswalk.py"
CROSSWALK = "crosswalks/technique-crosswalk.json"
AIIS = "vendor/aiis-signatures/crosswalks/technique-signatures.json"
RETIRED = "vendor/aiis-signatures/retired-ids.yaml"
INPUTS = ("matrix.json", "technique-ids.json", "vendor", CROSSWALK,
          "scripts/build_technique_crosswalk.py", "scripts/check_technique_crosswalk.py")
TOP_LEVEL = ["schemaVersion", "generated", "matrix", "inputs", "byTechnique", "byHmaCheck",
             "byOasbControl", "byAiisSignature", "byDvaaScenario", "byPayload", "unjoined",
             "notAssessed"]
# The live signatures retired-ids.yaml names only as superseded_by targets.
SUPERSEDING = ("AIIS-ATTR-EXFIL-URL-01", "AIIS-ATTR-IGNORE-INST-01",
               "AIIS-HIDDEN-JAILBREAK-DAN-01", "AIIS-HIDDEN-ROLE-INJECT-01")
# The tests' own git runs drop a repository location a git hook exports, and point
# core.hooksPath away from the host's hooks.
GIT_ENV = {key: value for key, value in os.environ.items()
           if key not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                          "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")}
GIT = ["git", "-c", "user.name=crosswalk-test", "-c", "user.email=crosswalk-test@example.invalid",
       "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"]
UNLISTED = "is not VENDOR.json, the generator or a file listed in files"
DS_STORE = "vendor/.DS_Store"
DS_STORE_LINES = ["X9 vendor/.DS_Store is a file directly under vendor/; every input is a "
                  "directory with a VENDOR.json"]
# Paths this repository's .gitignore excludes, each with the lines X9 prints when it judges it.
IGNORED = [
    ("vendor/damn-vulnerable-ai-agent/__pycache__/generate.cpython-314.pyc",
     [f"X9 vendor/damn-vulnerable-ai-agent/__pycache__/generate.cpython-314.pyc {UNLISTED}"]),
    ("vendor/hackmyagent/.DS_Store", [f"X9 vendor/hackmyagent/.DS_Store {UNLISTED}"]),
    (DS_STORE, DS_STORE_LINES),
    ("vendor/__pycache__/generate.cpython-314.pyc",
     ["X9 vendor/__pycache__/ has no VENDOR.json",
      f"X9 vendor/__pycache__/generate.cpython-314.pyc {UNLISTED}"]),
    ("vendor/node_modules/pkg/index.js",
     ["X9 vendor/node_modules/ has no VENDOR.json",
      f"X9 vendor/node_modules/pkg/index.js {UNLISTED}"]),
]


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BUILD = _load(BUILDER, "build_technique_crosswalk")
CHECK = _load(CHECKER, "check_technique_crosswalk")


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "tree"
    for rel in INPUTS:
        source, target = ROOT / rel, root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", ".DS_Store"))
        else:
            shutil.copyfile(source, target)
    return root


def git(root: Path, *args: str, env: dict = GIT_ENV) -> str:
    return subprocess.run([*GIT, "-C", str(root), *args], check=True, capture_output=True,
                          text=True, timeout=60, env=env).stdout


@pytest.fixture
def checkout(tree):
    """The scratch root committed to a git repository under this repository's ignore rules."""
    shutil.copyfile(ROOT / ".gitignore", tree / ".gitignore")
    git(tree, "init", "-q")
    git(tree, "add", "--", ".gitignore", *INPUTS)
    git(tree, "commit", "-q", "-m", "scratch")
    assert git(tree, "status", "--porcelain") == ""
    return tree


def place(root: Path, rel: str):
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text("stray\n", encoding="utf-8")


def check(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(CHECKER), str(root), *args],
                          capture_output=True, text=True, timeout=300)


def build(root: Path):
    proc = subprocess.run([sys.executable, str(BUILDER), str(root)], capture_output=True,
                          text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def read(root: Path, rel: str):
    return json.loads((root / rel).read_text(encoding="utf-8"))


def write(root: Path, rel: str, value):
    (root / rel).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")


def technique(matrix: dict, tid: str) -> dict:
    return next(t for t in matrix["techniques"] if t["id"] == tid)


def violations(proc: subprocess.CompletedProcess, rule: str) -> list:
    return [line for line in proc.stdout.splitlines() if line.startswith(f"{rule} ")]


def test_the_committed_crosswalk_passes():
    proc = check(ROOT)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.startswith("OK: crosswalks/technique-crosswalk.json matches")


def test_the_committed_crosswalk_is_a_fresh_rendering():
    assert (ROOT / CROSSWALK).read_bytes() == BUILD.render(ROOT).encode("utf-8")


def test_two_renderings_are_byte_identical(tree):
    build(tree)
    first = (tree / CROSSWALK).read_bytes()
    build(tree)
    assert (tree / CROSSWALK).read_bytes() == first
    assert BUILD.render(tree).encode("utf-8") == first


def test_the_file_has_its_format_and_dates_from_its_inputs():
    text = (ROOT / CROSSWALK).read_bytes().decode("utf-8")
    doc = json.loads(text)
    assert text == json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    assert "\r" not in text
    assert list(doc) == TOP_LEVEL
    assert doc["schemaVersion"] == 1
    reads = [m["read"] for m in (json.loads(p.read_text()) for p in
                                 (ROOT / "vendor").glob("*/VENDOR.json"))]
    assert doc["generated"] == max([read(ROOT, "matrix.json")["updated"], *reads])
    assert [f["path"] for f in doc["matrix"]["files"]] == ["matrix.json", "technique-ids.json"]
    for view in ("byTechnique", "byHmaCheck", "byOasbControl", "byAiisSignature",
                 "byDvaaScenario", "byPayload"):
        assert list(doc[view]) == sorted(doc[view]), view


def test_every_relation_is_null_and_every_payload_column_is_not_assessed():
    doc = read(ROOT, CROSSWALK)
    for view in ("byHmaCheck", "byOasbControl", "byAiisSignature", "byDvaaScenario"):
        for entries in doc[view].values():
            assert entries and all(e["relation"] is None for e in entries), view
    assert {e["attackPayloads"]["hackmyagent"] for e in doc["byTechnique"].values()} == {None}
    assert {e["attackPayloads"]["agentpwn"] for e in doc["byTechnique"].values()} == {None}
    assert doc["byPayload"] == {"agentpwn": None, "hackmyagent": None}
    assert doc["unjoined"]["payloadsInNoTechnique"] == {"agentpwn": None, "hackmyagent": None}
    assert [n["column"] for n in doc["notAssessed"]] == ["attackPayloads.agentpwn",
                                                         "attackPayloads.hackmyagent"]


def test_one_changed_byte_in_the_crosswalk_fails(tree):
    path = tree / CROSSWALK
    text = path.read_text(encoding="utf-8")
    m = re.search(r'"sha256": "([0-9a-f])', text)
    digit = "1" if m.group(1) == "0" else "0"
    path.write_text(text[:m.start(1)] + digit + text[m.end(1):], encoding="utf-8")
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X1") == [
        f"X1 {CROSSWALK} differs from a fresh rendering of matrix.json, technique-ids.json and "
        f"vendor/ (first difference at line {text[:m.start(1)].count(chr(10)) + 1}); run "
        f"python3 scripts/build_technique_crosswalk.py"]


def test_an_absent_crosswalk_fails(tree):
    (tree / CROSSWALK).unlink()
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X1") == [
        f"X1 {CROSSWALK} is absent; run python3 scripts/build_technique_crosswalk.py"]


def test_an_unknown_technique_id_fails(tree):
    aiis = read(tree, AIIS)
    aiis["bySignature"]["AIIS-UNICODE-TAG-BLOCK-01"]["relatedTechniqueIds"] = ["T-9999"]
    write(tree, AIIS, aiis)
    build(tree)
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X2") == [
        f"X2 {CROSSWALK} byAiisSignature.AIIS-UNICODE-TAG-BLOCK-01: technique T-9999 is not "
        f"in technique-ids.json"]


def test_an_unknown_oasb_control_fails(tree):
    matrix = read(tree, "matrix.json")
    technique(matrix, "T-1001")["oasbControls"].append("99.9")
    write(tree, "matrix.json", matrix)
    build(tree)
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X3") == [
        f"X3 {CROSSWALK} byTechnique.T-1001.oasbControls: OASB-1 control 99.9 is not in "
        f"vendor/hackmyagent/oasb-1-controls.json",
        f"X3 {CROSSWALK} byOasbControl: OASB-1 control 99.9 is not in "
        f"vendor/hackmyagent/oasb-1-controls.json"]


def test_an_unknown_check_id_fails_before_and_after_rendering(tree):
    matrix = read(tree, "matrix.json")
    technique(matrix, "T-1001")["hmaChecks"].append("NOPE-001")
    write(tree, "matrix.json", matrix)
    # Not rendered again: the fresh rendering names the id, and the stale file differs.
    stale = check(tree)
    assert stale.returncode == 1
    assert violations(stale, "X1")
    assert "X4 the fresh rendering byTechnique.T-1001.hmaChecks: check NOPE-001 is not in " \
           "vendor/hackmyagent/check-ids.json" in stale.stdout
    build(tree)
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X1") == []
    assert violations(proc, "X4") == [
        f"X4 {CROSSWALK} byTechnique.T-1001.hmaChecks: check NOPE-001 is not in "
        f"vendor/hackmyagent/check-ids.json",
        f"X4 {CROSSWALK} byHmaCheck: check NOPE-001 is not in vendor/hackmyagent/check-ids.json"]


def test_a_payload_id_in_a_check_column_fails(tree):
    payloads = set(read(tree, "vendor/hackmyagent/payload-ids.json")["payloadIds"])
    checks = set(read(tree, "vendor/hackmyagent/check-ids.json")["checkIds"])
    payload = sorted(payloads - checks)[0]
    matrix = read(tree, "matrix.json")
    technique(matrix, "T-2001")["hmaChecks"].append(payload)
    write(tree, "matrix.json", matrix)
    build(tree)
    proc = check(tree)
    assert proc.returncode == 1
    hint = "; it is a hackmyagent payload id, which resolves only in a payload column"
    assert violations(proc, "X4") == [
        f"X4 {CROSSWALK} byTechnique.T-2001.hmaChecks: check {payload} is not in "
        f"vendor/hackmyagent/check-ids.json{hint}",
        f"X4 {CROSSWALK} byHmaCheck: check {payload} is not in "
        f"vendor/hackmyagent/check-ids.json{hint}"]


def test_an_unknown_signature_id_fails(tree):
    doc = read(tree, CROSSWALK)
    doc["byTechnique"]["T-2006"]["aiisSignatures"].append(
        {"id": "AIIS-NOPE-01", "basis": "aiis-technique-id"})
    write(tree, CROSSWALK, doc)
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X1")
    assert violations(proc, "X5") == [
        f"X5 {CROSSWALK} byTechnique.T-2006.aiisSignatures: signature AIIS-NOPE-01 is not in "
        f"{AIIS} bySignature"]


def test_an_unknown_scenario_fails(tree):
    doc = read(tree, CROSSWALK)
    doc["byDvaaScenario"]["no-such-scenario"] = [
        {"techniqueId": "T-1001", "basis": "expected-check", "checks": ["MCP-011"],
         "relation": None}]
    write(tree, CROSSWALK, doc)
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X6") == [
        f"X6 {CROSSWALK} byDvaaScenario: scenario no-such-scenario is not in "
        f"vendor/damn-vulnerable-ai-agent/expected-checks.json"]


def test_a_retired_signature_id_fails(tree):
    retired = re.findall(r"^- id: (\S+)$", (tree / RETIRED).read_text(encoding="utf-8"), re.M)
    aiis = read(tree, AIIS)
    aiis["bySignature"][retired[0]] = {"techniqueId": "T-2001", "relatedTechniqueIds": []}
    write(tree, AIIS, aiis)
    build(tree)
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X1") == []
    assert violations(proc, "X5") == [
        f"X5 {CROSSWALK} byTechnique.T-2001.aiisSignatures: signature {retired[0]} is retired "
        f"in {RETIRED}",
        f"X5 {CROSSWALK} byAiisSignature: signature {retired[0]} is retired in {RETIRED}"]


def test_a_superseded_by_value_is_not_read_as_retired():
    text = (ROOT / RETIRED).read_text(encoding="utf-8")
    superseding = set(re.findall(r"^\s+superseded_by: (\S+)$", text, re.M))
    assert superseding == set(SUPERSEDING)
    report = CHECK.Report()
    retired = CHECK.retired_ids(ROOT, report)
    assert report.ordered() == []
    assert len(retired) == len(re.findall(r"^- ", text, re.M)) == 32
    assert retired.isdisjoint(SUPERSEDING)
    live = read(ROOT, AIIS)["bySignature"]
    assert set(SUPERSEDING) <= set(live)
    assert set(SUPERSEDING) <= set(read(ROOT, CROSSWALK)["byAiisSignature"])


@pytest.mark.parametrize("item", ["- id: 'AIIS-0099'", "- signature: AIIS-0099", "-"])
def test_the_retired_reader_refuses_another_list_item_form(tree, item):
    path = tree / RETIRED
    text = path.read_text(encoding="utf-8")
    path.write_text(text + item + "\n", encoding="utf-8")
    build(tree)
    proc = check(tree)
    assert proc.returncode == 1
    line = text.count("\n") + 1
    assert violations(proc, "X5") == [
        f"X5 {RETIRED}:{line} is a list item that is not '- id: <id>'; the reader takes no "
        f"other form"]


def test_a_payload_column_beside_no_mapping_file_fails(tree):
    doc = read(tree, CROSSWALK)
    doc["byTechnique"]["T-2001"]["attackPayloads"]["hackmyagent"] = [
        {"id": "NOPE-PAYLOAD", "basis": "producer-declared"}]
    write(tree, CROSSWALK, doc)
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X7") == [
        f"X7 {CROSSWALK} byTechnique.T-2001.attackPayloads.hackmyagent is not null, but "
        f"mappings/hackmyagent-payloads.json does not exist; a column with no source is null",
        f"X7 {CROSSWALK} byTechnique.T-2001.attackPayloads.hackmyagent: payload 'NOPE-PAYLOAD' "
        f"is not in vendor/hackmyagent/payload-ids.json"]


def test_a_null_payload_column_beside_its_mapping_file_fails(tree):
    (tree / "mappings").mkdir()
    (tree / "mappings" / "agentpwn-payloads.json").write_text("{}\n", encoding="utf-8")
    proc = check(tree)
    assert proc.returncode == 1
    found = violations(proc, "X7")
    techniques = len(read(tree, CROSSWALK)["byTechnique"])
    assert len(found) == techniques + 2
    assert f"X7 {CROSSWALK} byPayload.agentpwn is null while mappings/agentpwn-payloads.json " \
           f"exists" in found


def test_a_range_version_in_a_package_pin_fails(tree):
    rel = "vendor/hackmyagent/VENDOR.json"
    manifest = read(tree, rel)
    manifest["version"] = "^" + manifest["version"]
    write(tree, rel, manifest)
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X8") == [
        f"X8 {rel} version '{manifest['version']}' is not an exact version (MAJOR.MINOR.PATCH, "
        f"no range)"]


@pytest.mark.parametrize("source", ["aiis-signatures", "damn-vulnerable-ai-agent"])
def test_a_39_hex_commit_in_a_git_pin_fails(tree, source):
    rel = f"vendor/{source}/VENDOR.json"
    manifest = read(tree, rel)
    manifest["commit"] = manifest["commit"][:39]
    assert len(manifest["commit"]) == 39
    write(tree, rel, manifest)
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X8") == [
        f"X8 {rel} commit '{manifest['commit']}' is not 40 lower-case hex"]


def test_the_x8_text_states_what_is_read_in_a_git_version_and_names_the_tag_check():
    doc = " ".join(CHECK.__doc__.split())
    x8 = doc[doc.index("- X8 "):doc.index("- X9 ")]
    assert "``version`` (null or a non-empty string, whitespace alone counting as empty;" in x8
    assert "a string that names no tag passes here" in x8
    assert ("``scripts/check_vendor_integrity.py`` is the check that verifies the tag names "
            "the commit") in x8


@pytest.mark.parametrize("source", ["aiis-signatures", "damn-vulnerable-ai-agent"])
def test_a_git_version_that_names_no_tag_passes_and_is_recorded_in_inputs(tree, source):
    rel = f"vendor/{source}/VENDOR.json"
    manifest = read(tree, rel)
    manifest["version"] = "not a tag"
    write(tree, rel, manifest)
    build(tree)
    proc = check(tree)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.startswith("OK: ")
    assert read(tree, CROSSWALK)["inputs"][source]["version"] == "not a tag"


@pytest.mark.parametrize("value", ["", "   ", 5, True, ["v0.4.0"]])
def test_a_git_version_that_is_neither_null_nor_a_non_empty_string_fails(tree, value):
    rel = "vendor/aiis-signatures/VENDOR.json"
    manifest = read(tree, rel)
    manifest["version"] = value
    write(tree, rel, manifest)
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X8") == [
        f"X8 {rel} version {value!r} is neither null nor a non-empty string"]


def test_a_git_pin_without_a_version_fails(tree):
    rel = "vendor/aiis-signatures/VENDOR.json"
    manifest = read(tree, rel)
    del manifest["version"]
    write(tree, rel, manifest)
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X8") == [f"X8 {rel} has no version (null or a non-empty string)"]


def test_an_unknown_key_in_a_pin_fails(tree):
    rel = "vendor/aiis-signatures/VENDOR.json"
    manifest = read(tree, rel)
    manifest["branch"] = "main"
    write(tree, rel, manifest)
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X8") == [f"X8 {rel} carries keys a git pin does not: branch"]


@pytest.mark.parametrize("rel", ["vendor/aiis-signatures/notes.txt",
                                 "vendor/hackmyagent/dist/taxonomy.js",
                                 "vendor/aiis-signatures/generate.py"])
def test_an_unlisted_file_under_vendor_fails(tree, rel):
    (tree / rel).parent.mkdir(parents=True, exist_ok=True)
    (tree / rel).write_text("unlisted\n", encoding="utf-8")
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X9") == [
        f"X9 {rel} is not VENDOR.json, the generator or a file listed in files"]


def test_a_listed_file_that_is_absent_fails(tree):
    (tree / "vendor/hackmyagent/payload-ids.json").unlink()
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X9") == [
        "X9 vendor/hackmyagent/payload-ids.json is listed in files but absent"]


def test_a_vendor_directory_without_a_pin_fails(tree):
    (tree / "vendor/unpinned").mkdir()
    (tree / "vendor/unpinned/data.json").write_text("{}\n", encoding="utf-8")
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X9") == [
        "X9 vendor/unpinned/ has no VENDOR.json",
        "X9 vendor/unpinned/data.json is not VENDOR.json, the generator or a file listed in files"]


@pytest.mark.parametrize("rel", [rel for rel, _ in IGNORED])
def test_a_file_git_ignores_under_vendor_passes_in_a_checkout(checkout, rel):
    place(checkout, rel)
    assert git(checkout, "status", "--porcelain") == ""
    proc = check(checkout)
    assert proc.returncode == 0, proc.stdout
    assert proc.stdout.startswith("OK: crosswalks/technique-crosswalk.json matches")


@pytest.mark.parametrize("rel, lines", IGNORED)
def test_the_same_file_fails_on_a_tree_without_git(tree, rel, lines):
    shutil.copyfile(ROOT / ".gitignore", tree / ".gitignore")
    place(tree, rel)
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X9") == lines


@pytest.mark.parametrize("rel, lines", IGNORED)
def test_a_tracked_file_fails_where_an_ignore_rule_matches_it(checkout, rel, lines):
    place(checkout, rel)
    git(checkout, "add", "-f", "--", rel)
    proc = check(checkout)
    assert proc.returncode == 1
    assert violations(proc, "X9") == lines


@pytest.mark.parametrize("rel, lines", [
    ("vendor/aiis-signatures/notes.txt", [f"X9 vendor/aiis-signatures/notes.txt {UNLISTED}"]),
    ("vendor/notes.txt", ["X9 vendor/notes.txt is a file directly under vendor/; every input is "
                          "a directory with a VENDOR.json"]),
    ("vendor/unpinned/data.json", ["X9 vendor/unpinned/ has no VENDOR.json",
                                   f"X9 vendor/unpinned/data.json {UNLISTED}"]),
])
def test_an_untracked_file_git_does_not_ignore_fails_in_a_checkout(checkout, rel, lines):
    place(checkout, rel)
    proc = check(checkout)
    assert proc.returncode == 1
    assert violations(proc, "X9") == lines


def test_an_ignored_file_beside_an_unignored_one_leaves_only_the_unignored_one(checkout):
    place(checkout, "vendor/unpinned/data.json")
    place(checkout, "vendor/unpinned/.DS_Store")
    proc = check(checkout)
    assert proc.returncode == 1
    assert violations(proc, "X9") == ["X9 vendor/unpinned/ has no VENDOR.json",
                                      f"X9 vendor/unpinned/data.json {UNLISTED}"]


def test_a_listed_file_that_is_absent_fails_in_a_checkout(checkout):
    (checkout / "vendor/hackmyagent/payload-ids.json").unlink()
    proc = check(checkout)
    assert proc.returncode == 1
    assert violations(proc, "X9") == [
        "X9 vendor/hackmyagent/payload-ids.json is listed in files but absent"]


def test_an_ignore_rule_under_vendor_does_not_hide_what_is_tracked(checkout):
    (checkout / "vendor/hackmyagent/.gitignore").write_text("*\n", encoding="utf-8")
    place(checkout, "vendor/hackmyagent/notes.txt")
    git(checkout, "add", "-f", "--", "vendor/hackmyagent/.gitignore", "vendor/hackmyagent/notes.txt")
    proc = check(checkout)
    assert proc.returncode == 1
    assert violations(proc, "X9") == [f"X9 vendor/hackmyagent/.gitignore {UNLISTED}",
                                      f"X9 vendor/hackmyagent/notes.txt {UNLISTED}"]


def test_an_empty_directory_under_vendor_passes_in_a_checkout(checkout):
    (checkout / "vendor/empty").mkdir()
    assert git(checkout, "status", "--porcelain") == ""
    proc = check(checkout)
    assert proc.returncode == 0, proc.stdout


def test_an_empty_directory_under_vendor_fails_on_a_tree_without_git(tree):
    (tree / "vendor/empty").mkdir()
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X9") == ["X9 vendor/empty/ has no VENDOR.json"]


def test_a_nested_repository_in_an_ignored_directory_passes_in_a_checkout(checkout):
    nested = checkout / "vendor/node_modules/pkg"
    nested.mkdir(parents=True)
    git(nested, "init", "-q")
    place(nested, "index.js")
    assert git(checkout, "status", "--porcelain") == ""
    proc = check(checkout)
    assert proc.returncode == 0, proc.stdout


def test_a_nested_repository_git_does_not_ignore_fails_in_a_checkout(checkout):
    nested = checkout / "vendor/hackmyagent/nested"
    nested.mkdir()
    git(nested, "init", "-q")
    place(nested, "plain.txt")
    assert git(checkout, "status", "--porcelain") == "?? vendor/hackmyagent/nested/\n"
    proc = check(checkout)
    assert proc.returncode == 1
    assert f"X9 vendor/hackmyagent/nested/plain.txt {UNLISTED}" in violations(proc, "X9")


def test_a_case_variant_path_to_the_checkout_reads_git(checkout):
    variant = checkout.parent / checkout.name.upper()
    if not variant.exists():
        pytest.skip("case-sensitive filesystem: no case-variant path to the tree")
    place(checkout, DS_STORE)
    proc = check(variant)
    assert proc.returncode == 0, proc.stdout


def test_a_root_nested_in_another_work_tree_is_walked(tree, tmp_path):
    shutil.copyfile(ROOT / ".gitignore", tmp_path / ".gitignore")
    git(tmp_path, "init", "-q")
    place(tree, DS_STORE)
    git(tree, "check-ignore", "-q", DS_STORE)  # The outer repository's rule matches the file.
    proc = check(tree)
    assert proc.returncode == 1
    assert violations(proc, "X9") == DS_STORE_LINES


def test_a_repository_a_git_hook_exports_is_not_read_as_the_roots_checkout(tree, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    git(other, "init", "-q")
    (other / ".git/info").mkdir(exist_ok=True)
    (other / ".git/info/exclude").write_text(".DS_Store\n", encoding="utf-8")
    env = dict(GIT_ENV, GIT_DIR=str(other / ".git"))
    place(tree, DS_STORE)
    git(tree, "check-ignore", "-q", DS_STORE, env=env)  # That repository's rule matches the file.
    proc = subprocess.run([sys.executable, str(CHECKER), str(tree)], capture_output=True,
                          text=True, timeout=300, env=env)
    assert proc.returncode == 1
    assert violations(proc, "X9") == DS_STORE_LINES


def test_a_machine_without_git_walks_the_tree(checkout, tmp_path):
    place(checkout, DS_STORE)
    env = dict(GIT_ENV, PATH=str(tmp_path / "no-git-here"))
    proc = subprocess.run([sys.executable, str(CHECKER), str(checkout)], capture_output=True,
                          text=True, timeout=300, env=env)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert violations(proc, "X9") == DS_STORE_LINES


@pytest.mark.parametrize("args, code", [(["--bogus"], 2), (["extra"], 2), (["--help"], 0)])
def test_usage(tree, args, code):
    proc = check(tree, *args)
    assert proc.returncode == code
    assert "X1" not in proc.stdout


def test_a_root_that_names_no_directory_fails(tmp_path):
    proc = subprocess.run([sys.executable, str(CHECKER), str(tmp_path / "absent")],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 1
    assert proc.stdout.startswith("FAIL: the root argument")
