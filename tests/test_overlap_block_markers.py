"""The overlap-counts block markers in cross-references/technique-overlap-index.md.

scripts/check_cross_references.py stopped with a ValueError traceback, in the check and
in --fix, when the END marker came before the BEGIN marker, and --fix printed "OK:
generated block already current" when it could not find the block. --fix now prints
"NOT FIXED" with the same reason as the C5 failure it is printed ahead of. Each case
runs the script on a scratch copy of the tree it reads.
"""

import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INDEX_REL = Path("cross-references") / "technique-overlap-index.md"


def _load_checker():
    spec = importlib.util.spec_from_file_location(
        "check_cross_references", ROOT / "scripts" / "check_cross_references.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHK = _load_checker()
END_BEFORE_BEGIN = (
    "C5 technique-overlap-index.md: the END marker of the generated block comes before "
    "its BEGIN marker"
)
MISSING = "C5 technique-overlap-index.md: the generated block markers are missing"
NOT_FIXED_MISSING = "NOT FIXED: wrote nothing, as the generated block markers are missing"
NOT_FIXED_END_BEFORE_BEGIN = (
    "NOT FIXED: wrote nothing, as the END marker of the generated block comes before its "
    "BEGIN marker"
)


def scratch_tree() -> Path:
    td = Path(tempfile.mkdtemp(prefix="atm-xref-"))
    shutil.copytree(ROOT / "cross-references", td / "cross-references")
    shutil.copy(ROOT / "matrix.json", td / "matrix.json")
    (td / "scripts").mkdir()
    shutil.copy(ROOT / "scripts" / "check_cross_references.py", td / "scripts")
    return td


def run_checker(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(root / "scripts" / "check_cross_references.py"), *args],
                          capture_output=True, text=True, timeout=120)


def remove_line(root: Path, marker: str) -> list:
    path = root / INDEX_REL
    lines = path.read_text().split("\n")
    assert lines.count(marker) == 1, marker
    lines.remove(marker)
    return lines


def end_marker_on_first_line(root: Path) -> None:
    # The reproduction in the issue: the END line moved to the first line of the page.
    lines = remove_line(root, CHK.END)
    (root / INDEX_REL).write_text("\n".join([CHK.END] + lines))


def drop_begin(root: Path) -> None:
    (root / INDEX_REL).write_text("\n".join(remove_line(root, CHK.BEGIN)))


def drop_end(root: Path) -> None:
    (root / INDEX_REL).write_text("\n".join(remove_line(root, CHK.END)))


def test_extract_block_is_none_when_end_comes_before_begin():
    text = f"{CHK.END}\nintro\n{CHK.BEGIN}\nbody\n"
    assert CHK.extract_block(text) is None


def test_end_before_begin_is_a_c5_failure_not_a_traceback():
    td = scratch_tree()
    try:
        end_marker_on_first_line(td)
        assert CHK.extract_block((td / INDEX_REL).read_text()) is None
        assert any(f.startswith(END_BEFORE_BEGIN) for f in CHK.run_checks(td))

        r = run_checker(td)
        assert r.returncode == 1, r.stdout + r.stderr
        assert "Traceback" not in r.stderr, r.stderr
        assert END_BEFORE_BEGIN in r.stdout, r.stdout
        assert "the generated block markers are missing" not in r.stdout, r.stdout
    finally:
        shutil.rmtree(td)


@pytest.mark.parametrize(
    "break_markers, not_fixed, c5",
    [
        (drop_begin, NOT_FIXED_MISSING, MISSING),
        (drop_end, NOT_FIXED_MISSING, MISSING),
        (end_marker_on_first_line, NOT_FIXED_END_BEFORE_BEGIN, END_BEFORE_BEGIN),
    ],
    ids=["no-begin", "no-end", "end-before-begin"],
)
def test_fix_says_it_wrote_nothing_when_it_cannot_find_the_block(break_markers, not_fixed, c5):
    td = scratch_tree()
    try:
        break_markers(td)
        before = (td / INDEX_REL).read_text()
        r = run_checker(td, "--fix")
        assert r.returncode == 1, r.stdout + r.stderr
        assert "Traceback" not in r.stderr, r.stderr
        assert not_fixed in r.stdout, r.stdout
        assert "OK: generated block already current" not in r.stdout, r.stdout
        assert "FIXED: rewrote" not in r.stdout, r.stdout
        assert f"  - {c5}" in r.stdout, r.stdout
        assert r.stdout.index(not_fixed) < r.stdout.index(c5), r.stdout
        assert r.stdout.count("NOT FIXED") == 1, r.stdout
        assert (td / INDEX_REL).read_text() == before
    finally:
        shutil.rmtree(td)


def test_fix_on_the_shipped_tree_reports_the_block_current():
    td = scratch_tree()
    try:
        before = (td / INDEX_REL).read_text()
        r = run_checker(td, "--fix")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "OK: generated block already current" in r.stdout, r.stdout
        assert (td / INDEX_REL).read_text() == before
    finally:
        shutil.rmtree(td)
