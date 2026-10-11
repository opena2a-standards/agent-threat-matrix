"""Attack class page generator tests.

attack-classes/*.md is a rendering of matrix.json. Ten pages once had their punctuation
edited by hand while matrix.json kept the old text, so regenerating them reintroduced the
dashes and failed scripts/check_docs_prose.py. The committed pages must equal a fresh
rendering, the rendering must pass the prose check, and ``--check`` must report each way
the directory can drift from the data (a page that differs, a missing page, a stale page)
without writing anything. Every run uses a scratch copy so the committed pages are never
rewritten.
"""

import importlib.util
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GENERATOR = Path("scripts") / "generate_class_markdown.py"
PROSE_CHECKER = ROOT / "scripts" / "check_docs_prose.py"


def _load_prose_checker():
    spec = importlib.util.spec_from_file_location("check_docs_prose", PROSE_CHECKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PROSE = _load_prose_checker()


def scratch_tree() -> Path:
    td = Path(tempfile.mkdtemp(prefix="atm-class-pages-"))
    shutil.copy(ROOT / "matrix.json", td / "matrix.json")
    (td / "scripts").mkdir()
    shutil.copy(ROOT / GENERATOR, td / GENERATOR)
    shutil.copytree(ROOT / "attack-classes", td / "attack-classes")
    return td


def run_generator(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(root / GENERATOR), *args],
                          capture_output=True, text=True, timeout=120)


def class_count() -> int:
    return len(json.loads((ROOT / "matrix.json").read_text())["attackClasses"])


def page_texts(directory: Path) -> dict:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(directory.glob("*.md"))}


def test_committed_pages_equal_a_fresh_rendering():
    td = scratch_tree()
    try:
        proc = run_generator(td)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        rendered = page_texts(td / "attack-classes")
        committed = page_texts(ROOT / "attack-classes")
        assert len(rendered) == class_count()
        differing = sorted(fn for fn in rendered if committed.get(fn) != rendered[fn])
        assert differing == [], f"pages differ from the matrix.json rendering: {differing}"
        assert sorted(committed) == sorted(rendered)
    finally:
        shutil.rmtree(td)


def test_rendered_pages_pass_the_docs_prose_check():
    td = scratch_tree()
    try:
        shutil.rmtree(td / "attack-classes")
        proc = run_generator(td)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        failures = []
        for fn, text in page_texts(td / "attack-classes").items():
            failures += PROSE.check_text(f"attack-classes/{fn}", text)
        assert failures == []
    finally:
        shutil.rmtree(td)


def test_check_passes_on_the_shipped_tree():
    td = scratch_tree()
    try:
        proc = run_generator(td, "--check")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert proc.stdout.startswith(f"OK: {class_count()} attack class pages match matrix.json")
    finally:
        shutil.rmtree(td)


def test_check_reports_a_hand_edited_page_and_writes_nothing():
    td = scratch_tree()
    try:
        page = td / "attack-classes" / "TOCTOU-RACE.md"
        edited = page.read_text(encoding="utf-8").replace("execution: swap", "execution, a swap")
        page.write_text(edited, encoding="utf-8")
        proc = run_generator(td, "--check")
        assert proc.returncode == 1
        assert "attack-classes/TOCTOU-RACE.md: differs from the matrix.json rendering" in proc.stdout
        assert page.read_text(encoding="utf-8") == edited
    finally:
        shutil.rmtree(td)


def test_check_reports_a_description_changed_only_in_matrix_json():
    td = scratch_tree()
    try:
        matrix = json.loads((td / "matrix.json").read_text())
        cls = next(c for c in matrix["attackClasses"] if c["id"] == "PHANTOM-SOUL")
        cls["description"] = cls["description"] + "."
        (td / "matrix.json").write_text(json.dumps(matrix, indent=2) + "\n")
        proc = run_generator(td, "--check")
        assert proc.returncode == 1
        assert "attack-classes/PHANTOM-SOUL.md: differs from the matrix.json rendering" in proc.stdout
    finally:
        shutil.rmtree(td)


@pytest.mark.parametrize("argument,status", [("--chek", 2), ("--chec", 2), ("check", 2), ("--help", 0)])
def test_an_argument_other_than_check_writes_nothing(argument, status):
    td = scratch_tree()
    try:
        page = td / "attack-classes" / "LLM-EXPOSE.md"
        edited = page.read_text(encoding="utf-8") + "A line added by hand.\n"
        page.write_text(edited, encoding="utf-8")
        (td / "attack-classes" / "NOT-A-CLASS.md").write_text("# gone\n", encoding="utf-8")
        proc = run_generator(td, argument)
        assert proc.returncode == status, proc.stdout + proc.stderr
        if status:
            assert f"unrecognized arguments: {argument}" in proc.stderr
        assert "Wrote" not in proc.stdout
        assert page.read_text(encoding="utf-8") == edited
        assert (td / "attack-classes" / "NOT-A-CLASS.md").exists()
    finally:
        shutil.rmtree(td)


def test_check_reports_missing_and_stale_pages():
    td = scratch_tree()
    try:
        (td / "attack-classes" / "SOUL-FORK.md").unlink()
        (td / "attack-classes" / "NOT-A-CLASS.md").write_text("# gone\n", encoding="utf-8")
        proc = run_generator(td, "--check")
        assert proc.returncode == 1
        assert "FAIL: 2 attack class page(s)" in proc.stdout
        assert "attack-classes/SOUL-FORK.md: missing" in proc.stdout
        assert "attack-classes/NOT-A-CLASS.md: stale" in proc.stdout
        assert not (td / "attack-classes" / "SOUL-FORK.md").exists()
        assert (td / "attack-classes" / "NOT-A-CLASS.md").exists()
    finally:
        shutil.rmtree(td)
