"""`scripts/check_cross_references.py --fix` says what it did to the generated block.

With the BEGIN or END marker missing from technique-overlap-index.md, ``--fix`` printed
"OK: generated block already current" on the same run that then failed C5 and exited 1.
It must write nothing, print "NOT FIXED" ahead of the C5 failure and exit 1. With both
markers present it must still rewrite a stale block and report a current one as current.
Each case runs the script from a scratch copy of the tree, so the shipped pages are never
written.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = Path("scripts") / "check_cross_references.py"
INDEX = Path("cross-references") / "technique-overlap-index.md"
BEGIN = "<!-- BEGIN GENERATED: overlap-counts -->"
END = "<!-- END GENERATED: overlap-counts -->"
NOT_FIXED = "NOT FIXED: wrote nothing, as the generated block markers are missing"
MISSING = "C5 technique-overlap-index.md: the generated block markers are missing"


def scratch_tree() -> Path:
    """A copy of the script, matrix.json and cross-references/, the files the script reads."""
    td = Path(tempfile.mkdtemp(prefix="crossref-fix-"))
    (td / "scripts").mkdir()
    shutil.copy(ROOT / SCRIPT, td / SCRIPT)
    shutil.copy(ROOT / "matrix.json", td / "matrix.json")
    shutil.copytree(ROOT / "cross-references", td / "cross-references")
    return td


def run_fix(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(root / SCRIPT), "--fix"],
                          capture_output=True, text=True, timeout=60)


def test_the_shipped_index_holds_each_marker_once():
    # The cases below remove one marker; they prove nothing if it was not there.
    text = (ROOT / INDEX).read_text()
    assert text.count(BEGIN) == 1 and text.count(END) == 1


@pytest.mark.parametrize("marker", [BEGIN, END], ids=["no-begin", "no-end"])
def test_fix_says_it_wrote_nothing_when_a_marker_is_missing(marker):
    td = scratch_tree()
    try:
        index = td / INDEX
        index.write_text(index.read_text().replace(marker, ""))
        before = index.read_text()
        r = run_fix(td)
        assert r.returncode == 1, r.stdout + r.stderr
        assert "OK: generated block already current" not in r.stdout, r.stdout
        assert "FIXED: rewrote" not in r.stdout, r.stdout
        assert NOT_FIXED in r.stdout, r.stdout
        assert MISSING in r.stdout, r.stdout
        assert r.stdout.index(NOT_FIXED) < r.stdout.index(MISSING), r.stdout
        assert index.read_text() == before
    finally:
        shutil.rmtree(td)


def test_fix_rewrites_a_stale_block():
    td = scratch_tree()
    try:
        index = td / INDEX
        shipped = index.read_text()
        head, rest = shipped.split(BEGIN, 1)
        _body, tail = rest.split(END, 1)
        index.write_text(f"{head}{BEGIN}\nstale\n{END}{tail}")
        r = run_fix(td)
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.startswith("FIXED: rewrote the generated block\n"), r.stdout
        assert index.read_text() == shipped
    finally:
        shutil.rmtree(td)


def test_fix_reports_a_current_block_as_current():
    td = scratch_tree()
    try:
        index = td / INDEX
        shipped = index.read_text()
        r = run_fix(td)
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.startswith("OK: generated block already current\n"), r.stdout
        assert index.read_text() == shipped
    finally:
        shutil.rmtree(td)
