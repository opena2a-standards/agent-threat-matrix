"""Docs prose checker tests.

scripts/check_docs_prose.py must be green on the shipped tree. Each dash form and each
"Why this exists" heading form is then planted in a fixture string and must be reported at
its own line, while code, comments, front matter, compounds, ranges and table delimiter rows
stay unreported. Scratch trees with no git checkout, or nested inside another repository's
work tree, exercise the file walk the checker falls back to; a file that is not UTF-8 is
reported at its line, not as a traceback.
"""

import importlib.util
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check_docs_prose.py"

EM = "—"
EN = "–"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_docs_prose", CHECKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHK = _load_checker()


def run_checker(script: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(script)], capture_output=True, text=True, timeout=120)


def test_shipped_tree_is_green():
    proc = run_checker(CHECKER)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.startswith("OK: ")


def test_each_dash_form_is_reported_at_its_line():
    text = (
        "# Title\n"
        "The layer -- the part between the model and the user.\n"
        f"The layer {EM} the part between the model and the user.\n"
        f"The layer {EN} the part between the model and the user.\n"
        "A line that wraps on a dash --\n"
        f"Glued{EM}em dash.\n"
    )
    failures = CHK.check_text("doc.md", text)
    assert failures == [
        "doc.md:2: P1 spaced double hyphen used as a dash in prose",
        "doc.md:3: P1 em dash used as a dash in prose",
        "doc.md:4: P1 spaced en dash used as a dash in prose",
        "doc.md:5: P1 spaced double hyphen used as a dash in prose",
        "doc.md:6: P1 em dash used as a dash in prose",
    ]


def test_code_comments_front_matter_and_compounds_are_not_reported():
    text = (
        "---\n"
        f"title: Front matter {EM} not prose\n"
        "---\n"
        "\n"
        "Run `git diff -- matrix.json` and ``a -- b`` before an end-to-end check.\n"
        f"Releases 2024{EN}2025 are a range, not a dash.\n"
        "<!-- generated block -- not prose -->\n"
        "<!--\n"
        f"a multi-line comment {EM} still not prose\n"
        "-->\n"
        "| Col | Col |\n"
        "|-----|-----|\n"
        "| a   | b   |\n"
        "\n"
        "---\n"
        "\n"
        "```bash\n"
        "python3 scripts/validate_matrix.py -- --flag\n"
        f"echo 'output {EM} as printed'\n"
        "```\n"
        "~~~~\n"
        "``` not a closing fence -- inside a tilde fence\n"
        "~~~~\n"
        "Setext heading\n"
        "--\n"
    )
    assert CHK.check_text("doc.md", text) == []


def test_why_this_exists_sections_are_reported():
    text = (
        "## Why this exists\n"
        "### Why This Matters\n"
        "**Why this exists.** A bold section label.\n"
        "Why this matters\n"
        "----------------\n"
        "This paragraph explains why this exists, which is not a heading.\n"
    )
    failures = CHK.check_text("doc.md", text)
    assert [f.split(": P2")[0] for f in failures] == ["doc.md:1", "doc.md:2", "doc.md:3", "doc.md:4"]


def test_excluded_paths():
    for rel in ("CHANGELOG.md", "changelog.d/1.md", "LICENSE.md", "tests/fixtures/a.md",
                "node_modules/x/README.md", "dist/README.md", "corpus/a.md"):
        assert CHK.excluded(rel), rel
    for rel in ("README.md", "docs/cna/application-package.md", ".github/pull_request_template.md",
                "techniques/T-1001.md"):
        assert not CHK.excluded(rel), rel


def test_verbatim_entry_matches_one_exact_line():
    (rel, line), = CHK.VERBATIM
    assert CHK.check_text(rel, f"{line}\n") == []
    assert CHK.check_text(rel, f"{line} (edited)\n") != []
    assert CHK.check_text("README.md", f"{line}\n") != []


def test_table_delimiter_rows_are_not_reported():
    text = (
        "| a | b |\n"
        "| -- | -- |\n"
        "| :-- | --: |\n"
        "a | b\n"
        "-- | --\n"
        "> -- quoted\n"
        "- -- item\n"
        "| a -- b |\n"
    )
    failures = CHK.check_text("t.md", text)
    assert [f.split(": P1")[0] for f in failures] == ["t.md:6", "t.md:7", "t.md:8"]


def test_html_comments_are_stripped_within_and_across_lines():
    text = (
        "Kept <!-- a -- b --> text -- here <!-- open -- \n"
        "still -- inside -->after\n"
        "<!-- one --> word -- <!-- two -->\n"
    )
    failures = CHK.check_text("doc.md", text)
    assert [f.split(": P1")[0] for f in failures] == ["doc.md:1", "doc.md:3"]


def test_unterminated_html_comments_cost_linear_time():
    started = time.perf_counter()
    assert CHK.check_text("x.md", "<!-- " * 40000 + "\n") == []
    assert time.perf_counter() - started < 2.0


def _scratch_tree(parent: Path) -> Path:
    tree = parent / "tree"
    (tree / "scripts").mkdir(parents=True)
    shutil.copy(CHECKER, tree / "scripts" / "check_docs_prose.py")
    return tree


def test_red_on_a_scratch_tree_without_git():
    td = Path(tempfile.mkdtemp(prefix="atm-prose-"))
    try:
        tree = _scratch_tree(td)
        (tree / "README.md").write_text("# Title\n\nPlain prose.\n", encoding="utf-8")
        proc = run_checker(tree / "scripts" / "check_docs_prose.py")
        assert proc.returncode == 0, proc.stdout
        assert proc.stdout.startswith("OK: 1 Markdown files")

        (tree / "README.md").write_text(f"# Title\n\nPlain prose {EM} with a dash.\n", encoding="utf-8")
        (tree / "CHANGELOG.md").write_text(f"History {EM} is not rewritten.\n", encoding="utf-8")
        proc = run_checker(tree / "scripts" / "check_docs_prose.py")
        assert proc.returncode == 1
        assert "README.md:3: P1 em dash used as a dash in prose" in proc.stdout
        assert "CHANGELOG.md" not in proc.stdout
    finally:
        shutil.rmtree(td)


def test_scratch_tree_inside_another_git_work_tree_is_walked():
    td = Path(tempfile.mkdtemp(prefix="atm-prose-"))
    try:
        subprocess.run(["git", "init", "-q", str(td)], check=True, capture_output=True, timeout=60)
        tree = _scratch_tree(td)
        (tree / "README.md").write_text("# Title\n\nPlain prose.\n", encoding="utf-8")
        proc = run_checker(tree / "scripts" / "check_docs_prose.py")
        assert proc.returncode == 0, proc.stdout
        assert proc.stdout.startswith("OK: 1 Markdown files"), proc.stdout
    finally:
        shutil.rmtree(td)


def test_non_utf8_file_is_reported_at_its_line():
    td = Path(tempfile.mkdtemp(prefix="atm-prose-"))
    try:
        tree = _scratch_tree(td)
        (tree / "README.md").write_bytes(b"# T\n\nCaf\xe9\n")
        (tree / "OTHER.md").write_text(f"Plain prose {EM} with a dash.\n", encoding="utf-8")
        proc = run_checker(tree / "scripts" / "check_docs_prose.py")
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "Traceback" not in proc.stderr, proc.stderr
        assert "README.md:3: not valid UTF-8" in proc.stdout, proc.stdout
        assert "OTHER.md:1: P1 em dash used as a dash in prose" in proc.stdout
    finally:
        shutil.rmtree(td)
