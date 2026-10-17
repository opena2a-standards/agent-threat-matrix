"""Governance page checker tests.

scripts/check_governance.py must be green on the shipped tree, and GOVERNANCE.md must pass
scripts/check_docs_prose.py. Each property is then broken in a scratch copy of the tree and
must be reported with its id: the page removed (G1), an organization link dropped (G2), a
named path that does not exist or a file named as a directory (G3), a linking page without
the link (G4), a CODEOWNERS pattern that resolves to nothing (G5), and a relative link or a
heading fragment that resolves to nothing (G6). A CODEOWNERS file whose patterns all resolve
passes and is counted in the summary; an absent one is reported as absent and fails nothing.
A CODEOWNERS glob with no "/" other than a trailing one matches at any depth, and one that
starts with "/" matches at the root only.
"""

import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check_governance.py"
PROSE_CHECKER = ROOT / "scripts" / "check_docs_prose.py"
PAGE = "GOVERNANCE.md"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHK = _load(CHECKER, "check_governance")
PROSE = _load(PROSE_CHECKER, "check_docs_prose")


@pytest.fixture
def tree():
    td = Path(tempfile.mkdtemp(prefix="atm-governance-"))
    root = td / "tree"
    shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    yield root
    shutil.rmtree(td)


def run_checker(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(root / "scripts" / "check_governance.py")],
                          capture_output=True, text=True, timeout=120)


def mutate(root: Path, rel: str, old: str, new: str) -> int:
    """Replace every occurrence of `old` in `rel` and return how many there were."""
    path = root / rel
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    assert count, f"mutation target must occur in {rel}: {old!r}"
    path.write_text(text.replace(old, new), encoding="utf-8")
    return count


def test_shipped_tree_is_green():
    r = run_checker(ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.startswith(f"OK: {PAGE} links both organization documents"), r.stdout


def test_missing_page_is_reported(tree):
    (tree / PAGE).unlink()
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"G1 {PAGE} does not exist at the repository root" in r.stdout, r.stdout


@pytest.mark.parametrize("url", CHK.ORG_LINKS, ids=["governance", "contributing"])
def test_dropped_organization_link_is_reported(tree, url):
    mutate(tree, PAGE, url, url.replace("/blob/main/", "/blob/trunk/"))
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"G2 {PAGE} does not link {url}" in r.stdout, r.stdout


def test_named_path_that_does_not_exist_is_reported(tree):
    mutate(tree, PAGE, "`technique-ids.json`", "`technique-ids-v2.json`")
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"G3 {PAGE} names technique-ids-v2.json, which does not exist in the tree" in r.stdout, r.stdout


def test_file_named_as_a_directory_is_reported(tree):
    mutate(tree, PAGE, "`schema/`", "`matrix.json/`")
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"G3 {PAGE} names matrix.json/ as a directory, and it is a file" in r.stdout, r.stdout


def test_missing_paths_section_is_reported(tree):
    mutate(tree, PAGE, CHK.PATHS_SECTION, "## What is normative")
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"G3 {PAGE} has no section headed {CHK.PATHS_SECTION!r}" in r.stdout, r.stdout


@pytest.mark.parametrize("rel", CHK.LINKING_PAGES)
def test_linking_page_without_the_link_is_reported(tree, rel):
    mutate(tree, rel, f"[{PAGE}]({PAGE})", PAGE)
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"G4 {rel} does not link {PAGE}" in r.stdout, r.stdout


def _write_codeowners(root: Path, lines) -> Path:
    path = root / CHK.CODEOWNERS
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


RESOLVING_PATTERNS = [
    "# one line per normative path",
    "/matrix.json @example-owner",
    "schema/ @example-owner",
    "techniques/*.md @example-owner",
    "docs @example-owner",
]


def test_codeowners_pattern_that_resolves_to_nothing_is_reported(tree):
    _write_codeowners(tree, RESOLVING_PATTERNS + ["/does-not-exist.json @example-owner"])
    r = run_checker(tree)
    assert r.returncode == 1
    failures = [l for l in r.stdout.splitlines() if l.strip().startswith("- G")]
    assert failures == [
        f"  - G5 {CHK.CODEOWNERS}:6: pattern '/does-not-exist.json' resolves to no path in the tree"
    ], r.stdout


def test_codeowners_whose_patterns_resolve_passes_and_is_counted(tree):
    _write_codeowners(tree, RESOLVING_PATTERNS)
    r = run_checker(tree)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"the 4 patterns in {CHK.CODEOWNERS} each resolve to a path" in r.stdout, r.stdout


def test_codeowners_glob_without_a_slash_matches_at_any_depth(tree):
    # No .py or .yml file sits at the root; scripts/, tests/ and .github/ hold them.
    assert not list(tree.glob("*.py")) and not list(tree.glob("*.yml"))
    _write_codeowners(tree, ["*.py @example-owner", "*.yml @example-owner"])
    r = run_checker(tree)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"the 2 patterns in {CHK.CODEOWNERS} each resolve to a path" in r.stdout, r.stdout


def test_codeowners_glob_read_from_the_root_stays_at_the_root(tree):
    assert not list(tree.glob("*.py"))
    _write_codeowners(tree, ["/*.py @example-owner", "*.does-not-exist @example-owner"])
    r = run_checker(tree)
    assert r.returncode == 1
    failures = [l for l in r.stdout.splitlines() if l.strip().startswith("- G")]
    assert failures == [
        f"  - G5 {CHK.CODEOWNERS}:1: pattern '/*.py' resolves to no path in the tree",
        f"  - G5 {CHK.CODEOWNERS}:2: pattern '*.does-not-exist' resolves to no path in the tree",
    ], r.stdout


def test_absent_codeowners_is_reported_as_absent(tree):
    owners = tree / CHK.CODEOWNERS
    if owners.exists():
        owners.unlink()
    r = run_checker(tree)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"and {CHK.CODEOWNERS} is absent" in r.stdout, r.stdout


def test_link_to_a_page_that_does_not_exist_is_reported(tree):
    mutate(tree, PAGE, "(docs/overview.md#what-this-covers-and-what-it-doesnt)",
           "(docs/scope.md#what-this-covers-and-what-it-doesnt)")
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"G6 {PAGE} links docs/scope.md, which does not exist in the tree" in r.stdout, r.stdout


def test_fragment_that_names_no_heading_is_reported(tree):
    mutate(tree, PAGE, "(docs/evidence-tiers.md#evidence-standard)",
           "(docs/evidence-tiers.md#evidence-standards)")
    r = run_checker(tree)
    assert r.returncode == 1
    assert (f"G6 {PAGE} links docs/evidence-tiers.md#evidence-standards, and no heading on "
            "that page has that fragment") in r.stdout, r.stdout


def test_page_passes_the_docs_prose_check():
    text = (ROOT / PAGE).read_text(encoding="utf-8")
    assert PROSE.check_text(PAGE, text) == []


def test_heading_slug_follows_the_fragment_rule():
    assert CHK.heading_slug("What This Covers (and What It Doesn't)") == "what-this-covers-and-what-it-doesnt"
    assert CHK.heading_slug("Evidence Standard") == "evidence-standard"
    assert CHK.heading_slug("The `version` field") == "the-version-field"


def test_path_tokens_take_paths_and_leave_flags_and_words():
    assert list(CHK.path_tokens("python3 scripts/validate_matrix.py --check")) == ["scripts/validate_matrix.py"]
    assert list(CHK.path_tokens("schema/")) == ["schema/"]
    assert list(CHK.path_tokens("matrix.json,")) == ["matrix.json"]
    assert list(CHK.path_tokens("status")) == []
    assert list(CHK.path_tokens("MAJOR.MINOR")) == []
