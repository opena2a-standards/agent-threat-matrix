"""scripts/pin_evidence_sources.py pins the DVAA pages that back lab-reproduction entries and writes the entries they back.

Every case runs the script on a scratch copy of the tree against a small git repository
built in the test and laid out as DVAA lays out its scenarios and its challenges, so no case
reads the network and the committed files are never written. The pages of that repository
are test data: their steps, labels, challenges and dates are written here.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = ("matrix.json", "technique-ids.json", "schema/threat-matrix-v1.2.schema.json",
         "schema/consumer-readiness.json", "schema/evidence-sources.schema.json",
         "scripts/validate_matrix.py", "scripts/generate_stix.py", "scripts/pin_evidence_sources.py",
         "stix/agent-threat-matrix-bundle.json", "evidence-gaps.json", "evidence-sources.json")
SCRIPT = "scripts/pin_evidence_sources.py"
STIX = "stix/agent-threat-matrix-bundle.json"
DVAA = "https://github.com/opena2a-org/damn-vulnerable-ai-agent"
LAB = "lab-reproduction"
TELEMETRY = "honeypot-telemetry"
GIT_ENV = {key: value for key, value in os.environ.items()
           if key not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                          "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")}

_spec = importlib.util.spec_from_file_location("pin_evidence_sources", ROOT / SCRIPT)
PIN = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(PIN)

CHAIN = "scenarios/chain/README.md"
PROBE = "scenarios/probe/README.md"
PAGES = {
    CHAIN: ("# Discovery to Lateral Movement\n"
            "\n"
            "**ATM Techniques:** T-1002, T-2001, T-9999\n"
            "\n"
            "## Attack Chain\n"
            "\n"
            "1. **T-1002 (Tool Discovery):** The agent lists the tools it can reach.\n"
            "\n"
            "2. **T-2001 (Threshold Exhaustion):** A step that gives the id another technique's name.\n"
            "\n"
            "3. **T-9999 (Unknown Step):** A step whose id is not in the matrix.\n"),
    # Names a technique only in the list and in a padded label, which is not the form read.
    "scenarios/plain/README.md": ("# A scenario\n\n**ATM Techniques:** T-1001\n\n"
                                  "1. **T-1005 ( Padded ):** A label with spaces inside its parentheses.\n"),
    # Not a scenario page: another file of a scenario, and a page outside scenarios/.
    "scenarios/chain/notes.md": "1. **T-1006 (Agent Card Discovery):** Not a scenario page.\n",
    "docs/README.md": "1. **T-1001 (Endpoint Enumeration):** Not under scenarios.\n",
}
PROBE_TEXT = "# Probe\n\n## Attack Chain\n\n1. **T-1004 (Security Level Probing):** The agent probes.\n"
FIRST = "2026-03-01T12:00:00-06:00"
# 2026-04-23 in UTC: the pin takes the date as the committer recorded it, as %cs prints it.
SECOND = "2026-04-22T18:27:45-06:00"
THIRD = "2026-05-01T09:00:00+02:00"
LATER = "2026-06-01T08:00:00+00:00"
NAMED = "2026-06-15T10:00:00-06:00"
AFTER = "2026-07-01T09:00:00-06:00"
CHALLENGE_FILE = "src/challenges/index.js"
RUG_PULL = "scenarios/mcp-rug-pull/README.md"
# Laid out as DVAA's challenge file: the challenges are the keys of the CHALLENGES object.
CHALLENGES_TEXT = ("/**\n"
                   " * Test data laid out as DVAA lays out its challenges.\n"
                   " */\n"
                   "\n"
                   "export const CHALLENGES = {\n"
                   "  // Level 1\n"
                   "\n"
                   "  'L1-03': {\n"
                   "    id: 'L1-03',\n"
                   "    level: 1,\n"
                   "    name: 'Basic Prompt Injection',\n"
                   "    successCriteria: {\n"
                   "      name: 'A nested property, not the name of the challenge',\n"
                   "    },\n"
                   "  },\n"
                   "\n"
                   "  'L9-01': {\n"
                   "    id: 'L9-01',\n"
                   "    name: 'A challenge no technique names',\n"
                   "  },\n"
                   "};\n"
                   "\n"
                   "export function getChallenge(id) {\n"
                   "  return CHALLENGES[id];\n"
                   "}\n")
# The page of a scenario a dvaaValidation names; it names no technique in bold.
RUG_PULL_TEXT = "# MCP Rug Pull\n\nA tool changes its description after it is approved.\n"


def today() -> str:
    return date.today().isoformat()


def git(repo: Path, *args: str, when: str = FIRST) -> str:
    env = dict(GIT_ENV, GIT_AUTHOR_DATE=when, GIT_COMMITTER_DATE=when)
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=pin-test", "-c", "user.email=pin-test@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
        check=True, capture_output=True, text=True, timeout=60, env=env).stdout.strip()


def write(repo: Path, rel: str, text) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")


def commit(repo: Path, message: str, when: str, *paths: str) -> str:
    git(repo, "add", "--", *paths)
    git(repo, "commit", "-q", "-m", message, when=when)
    return git(repo, "rev-parse", "HEAD")


def blob(repo: Path, commit_id: str, path: str) -> str:
    return git(repo, "rev-parse", f"{commit_id}:{path}")


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    for rel in FILES:
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    return root


@pytest.fixture
def dvaa(tmp_path: Path) -> SimpleNamespace:
    """A repository laid out as DVAA's: two scenario pages that name techniques, at head."""
    repo = tmp_path / "dvaa"
    repo.mkdir()
    git(repo, "init", "-q")
    for rel, text in PAGES.items():
        write(repo, rel, text)
    first = commit(repo, "scenarios", FIRST, *PAGES)
    write(repo, PROBE, PROBE_TEXT)
    second = commit(repo, "probe", SECOND, PROBE)
    write(repo, "docs/README.md", PAGES["docs/README.md"] + "More.\n")
    head = commit(repo, "docs", THIRD, "docs/README.md")
    return SimpleNamespace(path=repo, first=first, second=second, head=head)


@pytest.fixture
def named(dvaa: SimpleNamespace) -> SimpleNamespace:
    """That repository with a challenge file and the page of a scenario, at a later head: the
    challenge L1-03, which T-2001's dvaaValidation names in the shipped matrix.json, a challenge
    no technique names, and the page of mcp-rug-pull, which T-9006's dvaaValidation names."""
    write(dvaa.path, CHALLENGE_FILE, CHALLENGES_TEXT)
    write(dvaa.path, RUG_PULL, RUG_PULL_TEXT)
    dvaa.named = commit(dvaa.path, "challenges", NAMED, CHALLENGE_FILE, RUG_PULL)
    dvaa.head = dvaa.named
    return dvaa


def line_of(text: str, line: str) -> int:
    return text.split("\n").index(line) + 1


def run_pin(tree: Path, dvaa_path: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(GIT_ENV, GIT_CEILING_DIRECTORIES=str(Path(dvaa_path).parent))
    return subprocess.run([sys.executable, str(tree / SCRIPT), "--dvaa", str(dvaa_path), *args],
                          capture_output=True, text=True, timeout=300, env=env)


def run_validator(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(root / "scripts" / "validate_matrix.py")],
                          capture_output=True, text=True, timeout=120)


def load(root: Path, rel: str = "matrix.json"):
    return json.loads((root / rel).read_text(encoding="utf-8"))


def dump(root: Path, data, rel: str = "matrix.json") -> None:
    (root / rel).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def technique(matrix: dict, tid: str) -> dict:
    return next(t for t in matrix["techniques"] if t["id"] == tid)


def snapshot(root: Path) -> dict:
    return {rel: (root / rel).read_bytes() for rel in FILES if (root / rel).is_file()}


def not_dvaa(t: dict) -> list:
    """The entries of a technique that do not cite DVAA, which the script keeps."""
    return [e for e in t.get("evidence", []) if not PIN.written_here(e)]


def link(commit_id: str, path: str) -> str:
    return f"{DVAA}/blob/{commit_id}/{path}"


def expected_pins(d: SimpleNamespace, read: str) -> dict:
    return {"description": PIN.SOURCES_DESCRIPTION, "dvaa": {
        "repository": DVAA, "head": d.head, "read": read, "pages": [
            {"path": CHAIN, "commit": d.first, "committed": "2026-03-01", "blob": blob(d.path, d.first, CHAIN),
             "names": [{"line": 7, "technique": "T-1002", "label": "Tool Discovery"},
                       {"line": 9, "technique": "T-2001", "label": "Threshold Exhaustion"},
                       {"line": 11, "technique": "T-9999", "label": "Unknown Step"}]},
            {"path": PROBE, "commit": d.second, "committed": "2026-04-22", "blob": blob(d.path, d.second, PROBE),
             "names": [{"line": 5, "technique": "T-1004", "label": "Security Level Probing"}]},
        ]}}


# --------------------------------------------------------------------------- the shipped file

def test_shipped_pins_are_what_the_script_writes_from_them():
    shipped = load(ROOT, "evidence-sources.json")
    assert (ROOT / "evidence-sources.json").read_text(encoding="utf-8") == PIN.render_sources(shipped["dvaa"])


def test_script_names_the_dvaa_repository_related_projects_pins():
    assert PIN.REPOSITORY == load(ROOT, "related-projects.json")["dvaa"]["repository"] == DVAA


# --------------------------------------------------------------------------- pinning

def test_pins_each_scenario_page_that_names_a_technique(tree, dvaa):
    proc = run_pin(tree, dvaa.path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert load(tree, "evidence-sources.json") == expected_pins(dvaa, today())
    assert (f"Pinned the 2 DVAA scenario pages that name a technique at {dvaa.head}, read {today()}, "
            f"in evidence-sources.json.") in proc.stdout, proc.stdout
    assert (f"  {CHAIN}:9 T-2001 'Threshold Exhaustion'; matrix.json names it 'Direct Prompt Injection'"
            in proc.stdout), proc.stdout
    assert f"  {CHAIN}:11 T-9999 'Unknown Step'" in proc.stdout, proc.stdout


def test_writes_the_entries_the_pins_back_and_drops_the_ones_they_no_longer_back(tree, dvaa):
    shipped = load(ROOT)
    proc = run_pin(tree, dvaa.path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    matrix = load(tree)
    telemetry = [e for e in technique(shipped, "T-1002")["evidence"] if e["type"] == TELEMETRY]
    assert technique(matrix, "T-1002")["evidence"] == [
        {"type": LAB, "reference": link(dvaa.first, CHAIN), "date": "2026-03-01"}] + telemetry
    assert technique(matrix, "T-1004")["evidence"] == [
        {"type": LAB, "reference": link(dvaa.second, PROBE), "date": "2026-04-22"}]
    # A label that is not the technique's name backs no entry, and this clone defines no
    # challenge, so the challenge T-2001's dvaaValidation names backs none either.
    assert technique(matrix, "T-2001")["evidence"] == not_dvaa(technique(shipped, "T-2001"))
    # The shipped entries cite pages these pins do not hold, so they go, and with them an
    # evidence array left empty.
    for tid in ("T-1006", "T-4003", "T-5003", "T-7007"):
        assert {e["type"] for e in technique(shipped, tid)["evidence"]} == {LAB}, tid
        assert "evidence" not in technique(matrix, tid), tid
    # Every shipped entry that cites DVAA cites a page or file this clone does not hold.
    written = [t["id"] for t in shipped["techniques"] if not_dvaa(t) != t.get("evidence", [])]
    assert f"written on {', '.join(written)}; updated is {matrix['updated']}" in proc.stdout
    assert matrix["updated"] == max(shipped["updated"], today())
    gaps = sorted(t["id"] for t in matrix["techniques"] if not t.get("evidence"))
    assert load(tree, "evidence-gaps.json")["ids"] == gaps
    assert f"carry no evidence entry: {', '.join(gaps)}" in proc.stdout, proc.stdout
    validated = run_validator(tree)
    assert validated.returncode == 0, validated.stdout + validated.stderr


def test_other_entries_stay_where_they_were(tree, dvaa):
    matrix = load(tree)
    elsewhere = [{"type": LAB, "reference": "https://github.com/example/lab/blob/main/README.md",
                  "date": "2026-01-01"},
                 {"type": "publication", "reference": link(dvaa.first, "docs/README.md"), "date": "2026-03-01"}]
    technique(matrix, "T-1004")["evidence"] = list(elsewhere)
    dump(tree, matrix)
    proc = run_pin(tree, dvaa.path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert technique(load(tree), "T-1004")["evidence"] == [
        {"type": LAB, "reference": link(dvaa.second, PROBE), "date": "2026-04-22"}] + elsewhere


def test_running_again_writes_nothing_and_keeps_the_read_date(tree, dvaa):
    assert run_pin(tree, dvaa.path).returncode == 0
    sources = load(tree, "evidence-sources.json")
    sources["dvaa"]["read"] = "2026-06-02"
    dump(tree, sources, "evidence-sources.json")
    before = snapshot(tree)
    proc = run_pin(tree, dvaa.path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (f"evidence-sources.json already pins the 2 DVAA scenario pages that name a technique at "
            f"{dvaa.head}, read 2026-06-02, and matrix.json carries the 2 {LAB} entries they back; "
            f"nothing written") in proc.stdout, proc.stdout
    assert snapshot(tree) == before


def test_a_page_changed_after_the_pin_moves_it_and_its_entries(tree, dvaa):
    assert run_pin(tree, dvaa.path).returncode == 0
    write(dvaa.path, PROBE, PROBE_TEXT + "\n2. **T-1006 (Agent Card Discovery):** The agent reads the card.\n")
    later = commit(dvaa.path, "probe step", LATER, PROBE)
    # --check reads the clone at the head the file records, which still holds the pins.
    checked = run_pin(tree, dvaa.path, "--check")
    assert checked.returncode == 0, checked.stdout + checked.stderr
    proc = run_pin(tree, dvaa.path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    pins = load(tree, "evidence-sources.json")["dvaa"]
    assert pins["head"] == later
    assert pins["pages"][1] == {"path": PROBE, "commit": later, "committed": "2026-06-01",
                                "blob": blob(dvaa.path, later, PROBE),
                                "names": [{"line": 5, "technique": "T-1004", "label": "Security Level Probing"},
                                          {"line": 7, "technique": "T-1006", "label": "Agent Card Discovery"}]}
    entry = {"type": LAB, "reference": link(later, PROBE), "date": "2026-06-01"}
    matrix = load(tree)
    assert technique(matrix, "T-1004")["evidence"] == [entry]
    assert technique(matrix, "T-1006")["evidence"] == [entry]
    validated = run_validator(tree)
    assert validated.returncode == 0, validated.stdout + validated.stderr


def test_a_replace_ref_does_not_stand_in_for_the_pinned_commit(tree, dvaa):
    # A stand-in for the commit that added the probe page, with the same tree and a later
    # date: git reads it in place of that commit unless replace objects are off.
    tree_id = git(dvaa.path, "rev-parse", f"{dvaa.second}^{{tree}}")
    stand_in = git(dvaa.path, "commit-tree", tree_id, "-p", dvaa.first, "-m", "stand-in", when=LATER)
    git(dvaa.path, "replace", dvaa.second, stand_in)
    assert git(dvaa.path, "log", "-1", "--format=%cs", dvaa.second) == "2026-06-01"
    proc = run_pin(tree, dvaa.path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    probe = load(tree, "evidence-sources.json")["dvaa"]["pages"][1]
    assert (probe["path"], probe["commit"], probe["committed"]) == (PROBE, dvaa.second, "2026-04-22")


def test_head_pins_the_clone_at_another_commit(tree, dvaa):
    proc = run_pin(tree, dvaa.path, "--head", dvaa.first)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    pins = load(tree, "evidence-sources.json")["dvaa"]
    assert pins["head"] == dvaa.first
    assert [page["path"] for page in pins["pages"]] == [CHAIN]
    assert "evidence" not in technique(load(tree), "T-1004")


# --------------------------------------------------------------------------- what a dvaaValidation names

def challenge_entry(commit_id: str, text: str, date_: str) -> dict:
    line = line_of(text, "  'L1-03': {")
    return {"type": LAB, "reference": f"{link(commit_id, CHALLENGE_FILE)}#L{line}", "date": date_}


def test_pins_the_challenge_and_the_scenario_page_a_dvaa_validation_names(tree, named):
    shipped = load(ROOT)
    assert technique(shipped, "T-2001")["dvaaValidation"] == "L1-03"
    assert technique(shipped, "T-9006")["dvaaValidation"] == "mcp-rug-pull"
    proc = run_pin(tree, named.path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    want = expected_pins(named, today())
    want["dvaa"]["challenges"] = {
        "path": CHALLENGE_FILE, "commit": named.named, "committed": "2026-06-15",
        "blob": blob(named.path, named.named, CHALLENGE_FILE),
        "named": [{"line": line_of(CHALLENGES_TEXT, "  'L1-03': {"), "id": "L1-03",
                   "name": "Basic Prompt Injection"}]}
    want["dvaa"]["scenarios"] = [{"path": RUG_PULL, "commit": named.named, "committed": "2026-06-15",
                                  "blob": blob(named.path, named.named, RUG_PULL)}]
    # L9-01 is defined, and no technique names it, so it is not pinned.
    assert load(tree, "evidence-sources.json") == want
    assert (f"evidence-sources.json pins the 1 DVAA challenges and 1 scenario pages a technique's "
            f"dvaaValidation names at {named.head}, and matrix.json carries the 2 {LAB} entries they "
            f"back") in proc.stdout, proc.stdout
    # A value that names no challenge or scenario page the clone holds is printed with its
    # technique: T-1003 names L1-01, which this clone does not define.
    assert "  T-1001 'All agents expose /health and /info'" in proc.stdout, proc.stdout
    assert "  T-1003 'L1-01'" in proc.stdout, proc.stdout
    assert "  T-9001 'ToolBot write_file', 'DataBot SQL'" in proc.stdout, proc.stdout


def test_writes_the_entries_a_dvaa_validation_backs_after_the_page_entries(tree, named):
    shipped = load(ROOT)
    matrix = load(tree)
    technique(matrix, "T-1002")["dvaaValidation"] = "ToolBot tools/list, mcp-rug-pull"
    dump(tree, matrix)
    proc = run_pin(tree, named.path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    matrix = load(tree)
    scenario = {"type": LAB, "reference": link(named.named, RUG_PULL), "date": "2026-06-15"}
    challenge = challenge_entry(named.named, CHALLENGES_TEXT, "2026-06-15")
    assert technique(matrix, "T-2001")["evidence"] == [challenge] + not_dvaa(technique(shipped, "T-2001"))
    assert technique(matrix, "T-9006")["evidence"] == [scenario] + not_dvaa(technique(shipped, "T-9006"))
    # The page T-1002 is named on comes first, then what its dvaaValidation names, then the rest.
    assert technique(matrix, "T-1002")["evidence"] == [
        {"type": LAB, "reference": link(named.first, CHAIN), "date": "2026-03-01"}, scenario,
    ] + not_dvaa(technique(shipped, "T-1002"))
    validated = run_validator(tree)
    assert validated.returncode == 0, validated.stdout + validated.stderr


def test_check_passes_on_the_dvaa_validation_pins_and_fails_on_one_edited_by_hand(tree, named):
    assert run_pin(tree, named.path).returncode == 0
    before = snapshot(tree)
    checked = run_pin(tree, named.path, "--check")
    assert checked.returncode == 0, checked.stdout + checked.stderr
    assert snapshot(tree) == before
    sources = load(tree, "evidence-sources.json")
    sources["dvaa"]["challenges"]["named"][0]["line"] += 1
    dump(tree, sources, "evidence-sources.json")
    proc = run_pin(tree, named.path, "--check")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert (f"evidence-sources.json is not what {named.path} holds at {named.head}: {CHALLENGE_FILE} is "
            f"pinned with named other than the clone gives") in proc.stderr, proc.stderr


def test_check_fails_on_a_scenario_page_the_pins_leave_out(tree, named):
    assert run_pin(tree, named.path).returncode == 0
    sources = load(tree, "evidence-sources.json")
    del sources["dvaa"]["scenarios"]
    dump(tree, sources, "evidence-sources.json")
    proc = run_pin(tree, named.path, "--check")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"{RUG_PULL} is the page of a scenario a dvaaValidation names and is not pinned" in proc.stderr


def test_a_challenge_moved_after_the_pin_moves_its_line_and_its_entry(tree, named):
    assert run_pin(tree, named.path).returncode == 0
    text = CHALLENGES_TEXT.replace("  // Level 1\n", "  // Level 1: Beginner\n  // One line more.\n")
    write(named.path, CHALLENGE_FILE, text)
    later = commit(named.path, "challenge comment", AFTER, CHALLENGE_FILE)
    proc = run_pin(tree, named.path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    pins = load(tree, "evidence-sources.json")["dvaa"]
    assert (pins["challenges"]["commit"], pins["challenges"]["committed"]) == (later, "2026-07-01")
    assert pins["challenges"]["named"] == [
        {"line": line_of(CHALLENGES_TEXT, "  'L1-03': {") + 1, "id": "L1-03", "name": "Basic Prompt Injection"}]
    # The scenario page did not change, so it stays pinned at the commit that wrote it.
    assert pins["scenarios"][0]["commit"] == named.named
    assert technique(load(tree), "T-2001")["evidence"][0] == challenge_entry(later, text, "2026-07-01")
    validated = run_validator(tree)
    assert validated.returncode == 0, validated.stdout + validated.stderr


# --------------------------------------------------------------------------- --check

def test_check_passes_on_the_pins_and_writes_nothing(tree, dvaa):
    assert run_pin(tree, dvaa.path).returncode == 0
    before = snapshot(tree)
    proc = run_pin(tree, dvaa.path, "--check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (f"OK: evidence-sources.json pins the 2 DVAA scenario pages that name a technique at {dvaa.head}, "
            f"and matrix.json carries the 2 {LAB} entries they back") in proc.stdout, proc.stdout
    assert snapshot(tree) == before


def test_check_fails_on_a_label_edited_by_hand_and_writes_nothing(tree, dvaa):
    assert run_pin(tree, dvaa.path).returncode == 0
    sources = load(tree, "evidence-sources.json")
    sources["dvaa"]["pages"][0]["names"][1]["label"] = "Direct Prompt Injection"
    dump(tree, sources, "evidence-sources.json")
    before = snapshot(tree)
    proc = run_pin(tree, dvaa.path, "--check")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert (f"evidence-sources.json is not what {dvaa.path} holds at {dvaa.head}: {CHAIN} is pinned with "
            f"names other than the clone gives") in proc.stderr, proc.stderr
    assert snapshot(tree) == before


def test_check_fails_on_an_entry_dropped_by_hand(tree, dvaa):
    assert run_pin(tree, dvaa.path).returncode == 0
    matrix = load(tree)
    del technique(matrix, "T-1004")["evidence"]
    dump(tree, matrix)
    proc = run_pin(tree, dvaa.path, "--check")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert (f"the {LAB} entries citing DVAA pages in matrix.json are not the ones the pins back, on T-1004"
            in proc.stderr), proc.stderr


def test_check_fails_on_a_page_the_pins_leave_out(tree, dvaa):
    assert run_pin(tree, dvaa.path).returncode == 0
    sources = load(tree, "evidence-sources.json")
    del sources["dvaa"]["pages"][1]
    dump(tree, sources, "evidence-sources.json")
    proc = run_pin(tree, dvaa.path, "--check")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"{PROBE} names a technique and is not pinned" in proc.stderr, proc.stderr


def test_check_without_a_pin_file_is_refused(tree, dvaa):
    (tree / "evidence-sources.json").unlink()
    proc = run_pin(tree, dvaa.path, "--check")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FAIL: evidence-sources.json is missing; nothing is written" in proc.stderr, proc.stderr


# --------------------------------------------------------------------------- refusals

def test_a_path_that_is_not_a_directory_is_refused(tree, tmp_path):
    before = snapshot(tree)
    proc = run_pin(tree, tmp_path / "missing")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"FAIL: --dvaa {tmp_path / 'missing'} is not a directory; nothing is written" in proc.stderr
    assert snapshot(tree) == before


def test_a_directory_that_is_not_a_git_clone_is_refused(tree, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    proc = run_pin(tree, empty)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"FAIL: --dvaa {empty} is not a git clone; nothing is written" in proc.stderr, proc.stderr


def test_a_head_the_clone_does_not_hold_is_refused(tree, dvaa):
    proc = run_pin(tree, dvaa.path, "--head", "no-such-branch")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert (f"FAIL: the clone at {dvaa.path} holds no commit no-such-branch; fetch it first; "
            f"nothing is written") in proc.stderr, proc.stderr


def test_a_clone_with_no_scenario_page_naming_a_technique_is_refused(tree, tmp_path):
    repo = tmp_path / "other"
    repo.mkdir()
    git(repo, "init", "-q")
    write(repo, "scenarios/plain/README.md", PAGES["scenarios/plain/README.md"])
    head = commit(repo, "plain", FIRST, "scenarios/plain/README.md")
    before = snapshot(tree)
    proc = run_pin(tree, repo)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert (f"holds no scenarios/<name>/README.md at {head} that names a technique in bold as "
            f"**T-NNNN (Label):**, so it is not read as a DVAA clone") in proc.stderr, proc.stderr
    assert snapshot(tree) == before


def test_a_page_that_is_not_utf8_is_refused(tree, dvaa):
    write(dvaa.path, "scenarios/bad/README.md", b"1. **T-1002 (Tool Discovery):** \xff\n")
    head = commit(dvaa.path, "bad page", LATER, "scenarios/bad/README.md")
    before = snapshot(tree)
    proc = run_pin(tree, dvaa.path)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"FAIL: scenarios/bad/README.md at {head} is not valid UTF-8" in proc.stderr, proc.stderr
    assert snapshot(tree) == before


@pytest.mark.parametrize("text, needle", [
    ("export const OTHER = {\n};\n",
     "<file> at <head> holds no CHALLENGES object, an 'export const CHALLENGES = {' line closed by a "
     "'};' line, so its challenges are not read"),
    ("export const CHALLENGES = {\n  'L1-03': {\n    id: 'L1-03',\n",
     "<file> at <head> holds no CHALLENGES object"),
    ("export const CHALLENGES = {\n};\n",
     "<file> at <head> defines no challenge in its CHALLENGES object as a key '<id>': { two spaces in, "
     "so its challenges are not read"),
    ("export const CHALLENGES = {\n  'L1-03': {\n    id: 'L1-04',\n    name: 'Basic Prompt Injection',\n"
     "  },\n};\n",
     "<file>:2 at <head> defines 'L1-03' with id 'L1-04', so which challenge it is cannot be read"),
    ("export const CHALLENGES = {\n  'L1-03': {\n    name: 'Basic Prompt Injection',\n  },\n};\n",
     "<file>:2 at <head> defines 'L1-03' with no id: '<id>', line, so which challenge it is cannot be read"),
    ("export const CHALLENGES = {\n  'L1-03': {\n    id: 'L1-03',\n    name: 'Agent\\'s Prompt',\n  },\n};\n",
     "<file>:2 at <head> defines 'L1-03' with no name: '<name>', line holding a name with no quote or "
     "backslash in it"),
    ("export const CHALLENGES = {\n  'L1-03': {\n    id: 'L1-03',\n    name: 'One',\n  },\n"
     "  'L1-03': {\n    id: 'L1-03',\n    name: 'Two',\n  },\n};\n",
     "<file>:6 at <head> defines 'L1-03' again: line 2 defines it already"),
])
def test_a_challenge_file_the_script_cannot_read_is_refused(tree, dvaa, text, needle):
    write(dvaa.path, CHALLENGE_FILE, text)
    head = commit(dvaa.path, "challenges", LATER, CHALLENGE_FILE)
    before = snapshot(tree)
    proc = run_pin(tree, dvaa.path)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FAIL: " + needle.replace("<file>", CHALLENGE_FILE).replace("<head>", head) in proc.stderr, proc.stderr
    assert snapshot(tree) == before


def test_a_challenge_file_that_is_not_utf8_is_refused(tree, dvaa):
    write(dvaa.path, CHALLENGE_FILE, b"export const CHALLENGES = {\n  // \xff\n};\n")
    head = commit(dvaa.path, "challenges", LATER, CHALLENGE_FILE)
    before = snapshot(tree)
    proc = run_pin(tree, dvaa.path)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"FAIL: {CHALLENGE_FILE} at {head} is not valid UTF-8" in proc.stderr, proc.stderr
    assert snapshot(tree) == before


@pytest.mark.parametrize("args, needle", [
    (["--check", "--head", "HEAD"], "--check reads the clone at the head evidence-sources.json records; "
                                    "it takes no --head"),
    (["--head=-x"], "--head '-x' does not name a commit"),
    (["--head="], "--head '' does not name a commit"),
])
def test_usage_errors_exit_2(tree, dvaa, args, needle):
    proc = run_pin(tree, dvaa.path, *args)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert needle in proc.stderr, proc.stderr
