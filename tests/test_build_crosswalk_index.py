"""scripts/build_crosswalk_index.py records the release its input files carry and the day it
read them.

The script wrote the release and read fields of crosswalks/attack-release.json and
crosswalks/atlas-release.json from constants (ATT&CK 20.0, ATLAS 2026.09, read 2026-10-21), so
a snapshot built from a newer release on a later day still named the old release and date.
Each test here writes two small release files into a scratch directory and runs the script on
them with --out, so the committed snapshots are never written. The release comes from the file
name, or from --attack-release and --atlas-release when the name carries none; the read date
from --read, or the day of the run. A release neither gives, an option that differs from the
name or is not dotted numbers, a read date that is not YYYY-MM-DD, and an --out that names no
directory each exit 2 and write nothing.
"""

import datetime
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build_crosswalk_index.py"
COMMITTED = ROOT / "crosswalks" / "attack-release.json"

# A technique, its sub-technique and a revoked technique: the shapes attack_index reads.
BUNDLE = {"type": "bundle", "objects": [
    {"type": "attack-pattern", "name": "Active Scanning",
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1595"}]},
    {"type": "attack-pattern", "name": "Wordlist Scanning", "x_mitre_is_subtechnique": True,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1595.003"}]},
    {"type": "attack-pattern", "name": "Revoked Technique", "revoked": True,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1000"}]},
]}
# A technique and its sub-technique. JSON is valid YAML, so the file is written as JSON.
ATLAS = {"techniques": {"AML.T0051": {"name": "LLM Prompt Injection"},
                        "AML.T0051.000": {"name": "Direct"}}}

needs_yaml = pytest.mark.skipif(importlib.util.find_spec("yaml") is None,
                                reason="the script reads the ATLAS file with PyYAML")


def build(tmp_path: Path, attack_name: str, atlas_name: str, *options: str):
    """Run the script on release files named `attack_name` and `atlas_name`, writing into a
    fresh directory. Returns the process and {file name: snapshot} for what it wrote there."""
    (tmp_path / attack_name).write_text(json.dumps(BUNDLE), encoding="utf-8")
    (tmp_path / atlas_name).write_text(json.dumps(ATLAS), encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path / attack_name), str(tmp_path / atlas_name),
         "--out", str(out), *options],
        capture_output=True, text=True, timeout=120)
    written = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in sorted(out.iterdir())}
    return proc, written


@needs_yaml
def test_the_release_is_the_one_the_file_names_carry(tmp_path):
    proc, written = build(tmp_path, "enterprise-attack-21.0.json", "ATLAS-2026.12.yaml",
                          "--read", "2027-01-15")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    attack, atlas = written["attack-release.json"], written["atlas-release.json"]
    assert (attack["release"], attack["read"]) == ("21.0", "2027-01-15")
    assert (atlas["release"], atlas["read"]) == ("2026.12", "2027-01-15")
    assert attack["techniques"] == {"T1595": "Active Scanning",
                                    "T1595.003": "Active Scanning: Wordlist Scanning"}
    assert atlas["techniques"] == {"AML.T0051": "LLM Prompt Injection",
                                   "AML.T0051.000": "LLM Prompt Injection: Direct"}
    # The fields keep the order the committed snapshots hold them in.
    assert list(attack) == list(json.loads(COMMITTED.read_text(encoding="utf-8")))
    assert "attack 21.0: 2 techniques, read 2027-01-15" in proc.stdout, proc.stdout


@needs_yaml
def test_the_read_date_is_the_day_of_the_run_by_default(tmp_path):
    before = datetime.date.today().isoformat()
    proc, written = build(tmp_path, "enterprise-attack-21.0.json", "ATLAS-2026.12.yaml")
    after = datetime.date.today().isoformat()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert sorted(written) == ["atlas-release.json", "attack-release.json"]
    for snapshot in written.values():
        assert snapshot["read"] in (before, after), snapshot["read"]


@needs_yaml
def test_an_option_gives_the_release_of_a_file_whose_name_carries_none(tmp_path):
    proc, written = build(tmp_path, "enterprise-attack.json", "ATLAS.yaml",
                          "--attack-release", "21.0", "--atlas-release", "2026.12")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert written["attack-release.json"]["release"] == "21.0"
    assert written["atlas-release.json"]["release"] == "2026.12"


@pytest.mark.parametrize("names, options, message", [
    (("enterprise-attack.json", "ATLAS-2026.12.yaml"), (),
     "the name enterprise-attack.json carries no release; give it with --attack-release"),
    (("enterprise-attack-21.0.json", "ATLAS.yaml"), (),
     "the name ATLAS.yaml carries no release; give it with --atlas-release"),
    (("enterprise-attack-21.0.json", "ATLAS-2026.12.yaml"), ("--attack-release", "20.0"),
     "--attack-release 20.0 differs from release 21.0, which the name enterprise-attack-21.0.json carries"),
    (("enterprise-attack-21.0.json", "ATLAS-2026.12.yaml"), ("--atlas-release", "2026.09"),
     "--atlas-release 2026.09 differs from release 2026.12, which the name ATLAS-2026.12.yaml carries"),
    (("enterprise-attack.json", "ATLAS-2026.12.yaml"), ("--attack-release", "latest"),
     "'latest' is not a release written as dotted numbers"),
    (("enterprise-attack-21.0.json", "ATLAS-2026.12.yaml"), ("--read", "21-10-2026"),
     "'21-10-2026' is not a date written YYYY-MM-DD"),
    (("enterprise-attack-21.0.json", "ATLAS-2026.12.yaml"), ("--read", "2026-02-30"),
     "'2026-02-30' is not a date written YYYY-MM-DD"),
], ids=["attack-unnamed", "atlas-unnamed", "attack-differs", "atlas-differs", "not-a-release",
        "read-day-first", "read-no-such-day"])
def test_a_release_or_date_it_cannot_state_exits_2_and_writes_nothing(tmp_path, names, options, message):
    proc, written = build(tmp_path, *names, *options)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert message in proc.stderr, proc.stderr
    assert written == {}


def test_an_out_that_names_no_directory_exits_2_and_writes_nothing(tmp_path):
    missing = tmp_path / "missing"
    # The last --out given is the one read, so this one replaces the directory build() makes.
    proc, written = build(tmp_path, "enterprise-attack-21.0.json", "ATLAS-2026.12.yaml",
                          "--out", str(missing))
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert f"--out {missing} names no directory" in proc.stderr, proc.stderr
    assert written == {} and not missing.exists()
