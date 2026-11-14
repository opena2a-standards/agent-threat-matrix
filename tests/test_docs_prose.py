"""Docs prose checker tests.

scripts/check_docs_prose.py must be green on the shipped tree. Each dash form and each
"Why this exists" heading form is then planted in a fixture string and must be reported at
its own line, while code, comments, front matter, compounds, ranges and table delimiter rows
stay unreported. So must each form of "attack class" written without "canonical" in front,
the wording the pages used for a family before they called it one, while a canonical attack
class, a path, an anchor, an identifier, code and a comment stay unreported. The technique
template in CONTRIBUTING.md, a fenced block the check skips, passes as the page a new
technique starts from. Scratch trees with no git checkout, or nested inside another repository's
work tree, exercise the file walk the checker falls back to; a scratch git tree shows that a
new file is checked before it is staged, that an ignored file is not, and that a path to the
tree differing only in letter case still reads git. A file that is not UTF-8 is reported at
its line, not as a traceback, and the run goes on to the files after it.
"""

import importlib.util
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

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


# Lines that CommonMark does not treat as an opening fence, so the prose after each is still
# checked: backticks with a backtick in the info string are an inline code span, and a form
# feed or U+2028 does not end a line, so the backticks after it are not at a line start.
NOT_A_FENCE = [
    ("a backtick in the info string", "```x`y\n"),
    ("a line separator before the backticks", "Example\u2028```\n"),
    ("a form feed before the backticks", "Example\x0c```\n"),
]


@pytest.mark.parametrize("opener", [o for _, o in NOT_A_FENCE], ids=[n for n, _ in NOT_A_FENCE])
def test_a_line_that_is_not_a_fence_leaves_the_prose_after_it_checked(opener):
    failures = CHK.check_text("doc.md", opener + f"A dash {EM} in prose.\n")
    assert failures == ["doc.md:2: P1 em dash used as a dash in prose"]


def test_a_backtick_in_a_tilde_fence_info_string_still_opens_the_fence():
    assert CHK.check_text("doc.md", f"~~~x`y\nA dash {EM} in code.\n~~~\n") == []


def test_lines_end_at_commonmark_line_endings():
    failures = CHK.check_text("doc.md", f"a\r\nb\rA dash {EM} here.\n")
    assert failures == ["doc.md:3: P1 em dash used as a dash in prose"]


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


P3_ADVICE = ('without "canonical" in front: write "family" for an entry of attackClasses in '
             'matrix.json, or "canonical attack class" for one of the ten classes of '
             'canonical-classes.json')


def p3(line: int, phrase: str, rel: str = "doc.md") -> str:
    return f'{rel}:{line}: P3 "{phrase}" {P3_ADVICE}'


def test_a_family_called_an_attack_class_is_reported_at_its_line():
    # Lines 1 to 6 are the wording docs/attack-classes.md, README.md and GOVERNANCE.md used
    # for the entries of attackClasses before those pages called them families; the phrase
    # GOVERNANCE.md wrapped onto the next line is reported where it starts.
    text = (
        "# Attack classes\n"
        "\n"
        "## Attack Classes (40)\n"
        "\n"
        "Attack classes group related techniques by the underlying vulnerability pattern.\n"
        "**61 techniques** across 9 tactics. **40 attack classes** grouping related techniques.\n"
        "The attack-class tables on docs/attack-classes.md are rendered from matrix.json.\n"
        "| Attack class | Description |\n"
        "MINOR steps for every other release that changes normative content: a new technique, attack\n"
        "class, tactic or optional field.\n"
    )
    assert CHK.check_text("doc.md", text) == [
        p3(1, "Attack classes"),
        p3(3, "Attack Classes"),
        p3(5, "Attack classes"),
        p3(6, "attack classes"),
        p3(7, "attack-class"),
        p3(8, "Attack class"),
        p3(9, "attack class"),
    ]


def test_a_canonical_attack_class_is_not_reported():
    text = (
        "| `attackClass` | The technique's canonical attack class, such as `injection` |\n"
        "The ten Canonical Attack Classes are listed in canonical-classes.json.\n"
        "## Canonical attack classes\n"
        "Each technique carries one canonical attack-class label.\n"
        "Write canonical\n"
        "attack class for one of the ten, and family for an entry of attackClasses.\n"
        "A canonical\tattack class after a tab.\n"
    )
    assert CHK.check_text("doc.md", text) == []


def test_paths_anchors_identifiers_code_and_comments_are_not_reported():
    text = (
        "- Family: [RAG-POISON](../attack-classes/RAG-POISON.md)\n"
        "- [Families](docs/attack-classes.md#attack-classes-40): every family\n"
        "Each page in attack-classes/ names the family's techniques.\n"
        "<!-- BEGIN GENERATED: attack-class-tables -->\n"
        "The `attackClasses` array and each technique's `attackClass` field.\n"
        "The words `attack class` in a code span.\n"
        "<!-- an attack class in a comment -->\n"
        "```text\n"
        "├── attack-classes/           # One file per attack class\n"
        "```\n"
        "A counterattack class is not the phrase, and neither is attack_class.\n"
    )
    assert CHK.check_text("doc.md", text) == []


def test_no_phrase_is_read_across_a_blank_line_or_across_skipped_lines():
    text = (
        "A canonical\n"
        "\n"
        "attack class after a blank line.\n"
        "A canonical\n"
        "```\n"
        "code\n"
        "```\n"
        "attack class after a fence.\n"
        "An attack\n"
        "\n"
        "class split by a blank line is no phrase.\n"
    )
    assert CHK.check_text("doc.md", text) == [p3(3, "attack class"), p3(8, "attack class")]


def test_a_verbatim_line_keeps_its_wording(monkeypatch):
    line = "> the attack class, as the source records it"
    monkeypatch.setattr(CHK, "VERBATIM", {("doc.md", line)})
    assert CHK.check_text("doc.md", f"{line}\n") == []
    assert CHK.check_text("doc.md", f"{line} (edited)\n") == [p3(1, "attack class")]


def test_failures_of_the_three_rules_are_listed_in_line_order():
    text = f"An attack class {EM} with a dash.\n## Why this exists\nAttack classes.\n"
    assert CHK.check_text("doc.md", text) == [
        "doc.md:1: P1 em dash used as a dash in prose",
        p3(1, "attack class"),
        "doc.md:2: P2 section named \"Why this exists/matters\"",
        p3(3, "Attack classes"),
    ]


def test_many_attack_words_cost_linear_time():
    started = time.perf_counter()
    assert len(CHK.check_text("x.md", "attack " * 20000 + "\n" + "canonical attack class " * 20000 + "\n")) == 0
    assert time.perf_counter() - started < 2.0


def test_the_shipped_pages_that_list_families_call_them_families():
    for rel in ("README.md", "docs/attack-classes.md", "EVIDENCE_AUDIT.md", "GOVERNANCE.md",
                "cross-references/mitre-atlas-mapping.md", "cross-references/owasp-llm-mapping.md",
                "cross-references/technique-overlap-index.md"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert CHK.check_text(rel, text) == [], rel
        assert re.search(r"\bfamil(?:y|ies)\b", text, re.I), rel


def test_a_page_started_from_the_technique_template_passes():
    # CONTRIBUTING.md gives the technique template in a fenced block, which the check skips.
    # A new page in techniques/ starts from it, and there each of its lines is prose the
    # check reads, so the template passes as that page and keeps a section for the family
    # and one for the canonical attack class.
    text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    templates = [block for block in re.findall(r"^```markdown\n(.*?)^```$", text, re.S | re.M)
                 if block.startswith("# T-XXXX: ")]
    assert len(templates) == 1, templates
    assert CHK.check_text("techniques/T-XXXX.md", templates[0]) == []
    assert re.search(r"^## Family$", templates[0], re.M)
    assert re.search(r"^## Canonical attack class$", templates[0], re.M | re.I)


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


def test_text_after_an_unclosed_comment_on_its_line_is_not_reported():
    assert CHK.check_text("doc.md", "Plain <!-- open -- here\n") == []


def test_a_complete_comment_is_replaced_by_a_space():
    failures = CHK.check_text("doc.md", "a<!-- c -->-- b\n")
    assert [f.split(": P1")[0] for f in failures] == ["doc.md:1"]


def test_empty_comment_forms_are_complete():
    for opener in ("<!-->", "<!--->"):
        failures = CHK.check_text("d.md", f"x {opener} y\nlater -- prose\n")
        assert [f.split(": P1")[0] for f in failures] == ["d.md:2"], opener


def test_delimiter_cell_with_one_alignment_colon_is_not_reported():
    assert CHK.check_text("t.md", "| a | b |\n| :-- | -- |\n") == []


def test_table_delimiter_row_inside_a_block_quote_is_not_reported():
    text = (
        "> | a | b |\n"
        "> | -- | -- |\n"
        "> > -- | :-- |\n"
        "> | a -- b |\n"
    )
    failures = CHK.check_text("d.md", text)
    assert [f.split(": P1")[0] for f in failures] == ["d.md:4"]


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


def test_a_family_called_an_attack_class_fails_the_run_and_a_family_passes():
    td = Path(tempfile.mkdtemp(prefix="atm-prose-"))
    try:
        tree = _scratch_tree(td)
        (tree / "README.md").write_text("# Title\n\n**40 attack classes** grouping related techniques.\n",
                                        encoding="utf-8")
        (tree / "CHANGELOG.md").write_text("- The attack class held a family code.\n", encoding="utf-8")
        proc = run_checker(tree / "scripts" / "check_docs_prose.py")
        assert proc.returncode == 1, proc.stdout
        assert f"  - {p3(3, 'attack classes', 'README.md')}" in proc.stdout.splitlines()
        assert "CHANGELOG.md" not in proc.stdout

        (tree / "README.md").write_text("# Title\n\n**40 families** grouping related techniques.\n",
                                        encoding="utf-8")
        proc = run_checker(tree / "scripts" / "check_docs_prose.py")
        assert proc.returncode == 0, proc.stdout
        assert proc.stdout.startswith("OK: 1 Markdown files")
        assert 'no attack class without "canonical" in front' in proc.stdout
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
        (tree / "A.md").write_bytes(b"\xff first\n")
        (tree / "README.md").write_bytes(b"# T\n\nCaf\xe9\n")
        (tree / "OTHER.md").write_text(f"Plain prose {EM} with a dash.\n", encoding="utf-8")
        proc = run_checker(tree / "scripts" / "check_docs_prose.py")
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "Traceback" not in proc.stderr, proc.stderr
        assert "A.md:1: not valid UTF-8" in proc.stdout, proc.stdout
        assert "README.md:3: not valid UTF-8" in proc.stdout, proc.stdout
        assert "OTHER.md:1: P1 em dash used as a dash in prose" in proc.stdout
    finally:
        shutil.rmtree(td)


def _git_tree(parent: Path) -> Path:
    tree = _scratch_tree(parent)
    subprocess.run(["git", "init", "-q", str(tree)], check=True, capture_output=True, timeout=60)
    (tree / ".gitignore").write_text("ignored.md\n", encoding="utf-8")
    (tree / "README.md").write_text("# Title\n\nPlain prose.\n", encoding="utf-8")
    (tree / "ignored.md").write_text(f"Ignored {EM} not checked.\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tree), "add", "README.md"], check=True, capture_output=True,
                   timeout=60)
    return tree


def test_new_markdown_file_is_checked_before_it_is_staged():
    td = Path(tempfile.mkdtemp(prefix="atm-prose-"))
    try:
        tree = _git_tree(td)
        (tree / "NEW.md").write_text(f"New page {EM} with a dash.\n", encoding="utf-8")
        proc = run_checker(tree / "scripts" / "check_docs_prose.py")
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "NEW.md:1: P1 em dash used as a dash in prose" in proc.stdout, proc.stdout
        assert "ignored.md" not in proc.stdout, proc.stdout
    finally:
        shutil.rmtree(td)


def test_case_variant_path_to_the_work_tree_reads_git():
    td = Path(tempfile.mkdtemp(prefix="atm-prose-"))
    try:
        tree = _git_tree(td)
        variant = tree.parent / tree.name.upper()
        if not variant.exists():
            pytest.skip("case-sensitive filesystem: no case-variant path to the tree")
        proc = run_checker(variant / "scripts" / "check_docs_prose.py")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert proc.stdout.startswith("OK: 1 Markdown files"), proc.stdout
    finally:
        shutil.rmtree(td)
