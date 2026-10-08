"""The README's live-API sentence is checked against the live payload.

README.md states, in prose, which version the live API at api.oa2a.org labels the
matrix with, which version this repository is at, and that the technique and tactic
counts agree. scripts/check_live_api_drift.py fetches that payload, so it is the check
that must hold the sentence to it. Every case stubs the fetch: no network is used.
"""

import copy
import importlib.util
import io
import json
import shutil
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check_live_api_drift.py"
SPEC = json.loads((ROOT / "matrix.json").read_text())
README = (ROOT / "README.md").read_text()
CLAIM_LINE = next(n for n, line in enumerate(README.splitlines(), 1)
                  if "labels the matrix" in line)


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_live_api_drift", CHECKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHK = _load_checker()


def _live(version, drop_technique=False):
    """A live payload identical to matrix.json apart from the version it serves."""
    live = copy.deepcopy(SPEC)
    live["version"] = version
    if drop_technique:
        live["techniques"] = live["techniques"][:-1]
    return live


def _readme(live_version="1.1", repo_version="1.2"):
    shipped = "still labels the matrix 1.1 while this repository is at 1.2"
    assert README.count(shipped) == 1
    return README.replace(
        shipped,
        f"still labels the matrix {live_version} while this repository is at {repo_version}",
    )


def test_shipped_readme_matches_a_live_api_serving_1_1():
    assert CHK.readme_findings(README, _live("1.1"), SPEC) == []


def test_wrong_live_version_in_readme_is_reported():
    findings = CHK.readme_findings(_readme(live_version="1.0"), _live("1.1"), SPEC)
    assert findings == [
        f"README.md:{CLAIM_LINE} says the live API labels the matrix 1.0; it serves '1.1'"
    ]


def test_wrong_repository_version_in_readme_is_reported():
    findings = CHK.readme_findings(_readme(repo_version="1.3"), _live("1.1"), SPEC)
    assert findings == [
        f"README.md:{CLAIM_LINE} says this repository is at 1.3; matrix.json says '1.2'"
    ]


def test_sentence_must_go_once_the_live_api_catches_up():
    findings = CHK.readme_findings(README, _live("1.2"), SPEC)
    assert len(findings) == 1
    assert findings[0].startswith(
        f"README.md:{CLAIM_LINE} says the live API labels the matrix 1.1; it serves '1.2'")
    assert "remove the sentence" in findings[0]


def test_a_gap_stated_between_equal_versions_is_reported():
    findings = CHK.readme_findings(_readme(live_version="1.2"), _live("1.2"), SPEC)
    assert len(findings) == 1
    assert "remove the sentence" in findings[0]


def test_counts_agree_claim_is_checked():
    findings = CHK.readme_findings(README, _live("1.1", drop_technique=True), SPEC)
    n = len(SPEC["techniques"])
    assert findings == [
        f"README.md:{CLAIM_LINE} says the technique and tactic counts agree; "
        f"techniques: live API has {n - 1}, matrix.json has {n}"
    ]


def test_unparseable_live_version_claim_is_reported():
    text = README.replace("still labels the matrix 1.1", "still labels the matrix one-point-one")
    findings = CHK.readme_findings(text, _live("1.1"), SPEC)
    assert findings == [
        f"README.md:{CLAIM_LINE} states the live API's matrix version, but no version "
        f"number follows 'labels the matrix'"
    ]


# ------------------------------------------------------------------ main() wiring

def _run_main(monkeypatch, readme_text, live, event=None):
    td = Path(tempfile.mkdtemp(prefix="atm-live-readme-"))
    try:
        shutil.copy(ROOT / "matrix.json", td / "matrix.json")
        (td / "README.md").write_text(readme_text)
        body = json.dumps(live).encode()
        monkeypatch.setattr(CHK.urllib.request, "urlopen",
                            lambda url, timeout=None: io.BytesIO(body))
        if event:
            monkeypatch.setenv("GITHUB_EVENT_NAME", event)
        else:
            monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
        monkeypatch.chdir(td)
        return CHK.main()
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_main_fails_on_a_wrong_readme_version_that_is_otherwise_a_noted_drift(monkeypatch, capsys):
    # On a pull request the newer matrix version is a note, not a failure, so the
    # README sentence is the only thing wrong here.
    rc = _run_main(monkeypatch, _readme(live_version="1.0"), _live("1.1"), event="pull_request")
    out = capsys.readouterr().out
    assert rc == 1, out
    assert f"README.md:{CLAIM_LINE} says the live API labels the matrix 1.0" in out


def test_main_fails_when_the_registry_caught_up_but_the_readme_did_not(monkeypatch, capsys):
    rc = _run_main(monkeypatch, README, _live(SPEC["version"]))
    out = capsys.readouterr().out
    assert rc == 1, out
    assert "remove the sentence" in out


def test_main_passes_the_shipped_readme_on_a_pull_request(monkeypatch, capsys):
    rc = _run_main(monkeypatch, README, _live("1.1"), event="pull_request")
    out = capsys.readouterr().out
    assert rc == 0, out


def test_main_passes_once_the_sentence_is_removed_after_the_registry_catches_up(monkeypatch, capsys):
    text = "\n".join(line for line in README.splitlines() if "labels the matrix" not in line)
    rc = _run_main(monkeypatch, text, _live(SPEC["version"]))
    out = capsys.readouterr().out
    assert rc == 0, out
