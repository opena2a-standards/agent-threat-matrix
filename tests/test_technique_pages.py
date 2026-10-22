"""Technique and tactic page checker tests.

Every case runs scripts/check_technique_pages.py against a scratch copy of matrix.json,
techniques/ and tactics/ so the committed files are never perturbed. The shipped tree must
be green. Each data line a technique page shares with matrix.json, and each row of a tactic
page's technique table, is then changed in one place: the checker must go red naming the
page and the line, and ``--fix`` must restore the shipped text. The checker used to compare
only the Attack Class and OASB Controls lines, so a class move in the data left the HMA
Checks line, the References class link and the tactic tables on the old values while CI
stayed green. The Mitigation section, rendered from ``oasbControls`` with the OASB-1 control
titles pinned in related-projects.json, the absent Severity line, the Evidence Gap line
every adapted page carries and the Data Sources line of a technique that maps a data source
are checked the same way.
"""

import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = "scripts/check_technique_pages.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_technique_pages", ROOT / SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHK = _load_checker()


def scratch_tree() -> Path:
    td = Path(tempfile.mkdtemp(prefix="atm-pages-"))
    (td / "scripts").mkdir()
    shutil.copy(ROOT / SCRIPT, td / SCRIPT)
    shutil.copy(ROOT / "matrix.json", td / "matrix.json")
    shutil.copy(ROOT / "related-projects.json", td / "related-projects.json")
    shutil.copytree(ROOT / "techniques", td / "techniques")
    shutil.copytree(ROOT / "tactics", td / "tactics")
    return td


def run_checker(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(root / SCRIPT), *args],
                          capture_output=True, text=True, timeout=120)


def mutate(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"mutation target must occur exactly once: {old!r}"
    path.write_text(text.replace(old, new), encoding="utf-8")


@pytest.fixture
def tree():
    td = scratch_tree()
    yield td
    shutil.rmtree(td, ignore_errors=True)


def test_shipped_tree_is_green():
    result = run_checker(ROOT)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.startswith("OK: 61 technique pages and 9 tactic pages agree with matrix.json")


# (page, label, shipped text, stale text). Each shipped text occurs once on its page.
TECHNIQUE_MUTATIONS = [
    ("T-1006", "Title", "# T-1006: Agent Card Discovery", "# T-1006: Agent Card Lookup"),
    ("T-1006", "Tactic", "**Tactic:** reconnaissance", "**Tactic:** collection"),
    ("T-1006", "Attack Class", "**Attack Class:** A2A-EXPOSE", "**Attack Class:** AGENT-IMPERSONATE"),
    ("T-1006", "Description",
     "Discover A2A agent cards to map agent identities, capabilities, and trust relationships",
     "Discover A2A agent cards"),
    ("T-1006", "DVAA Validation", "- **DVAA Validation:** Orchestrator /a2a/agent-card",
     "- **DVAA Validation:** Orchestrator /agent-card"),
    ("T-1006", "HMA Checks", "- **HMA Checks:** A2A-001, A2A-002", "- **HMA Checks:** AIM-001, AIM-002"),
    ("T-1006", "OASB Controls", "- **OASB Controls:** 7.1, 7.2, 7.3, 7.4", "- **OASB Controls:** 7.1"),
    ("T-1006", "Evidence Tier", "- **Evidence Tier:** observed", "- **Evidence Tier:** validated"),
    ("T-1006", "References attack class",
     "- Attack Class: [A2A-EXPOSE](../attack-classes/A2A-EXPOSE.md)",
     "- Attack Class: [AGENT-IMPERSONATE](../attack-classes/AGENT-IMPERSONATE.md)"),
    ("T-9006", "References attack class",
     "- Attack Class: [NEMO-SUPPLY-CHAIN](../attack-classes/NEMO-SUPPLY-CHAIN.md)",
     "- Attack Class: [ORG-SKILL-SPREAD](../attack-classes/ORG-SKILL-SPREAD.md)"),
    ("T-1006", "References tactic", "- Tactic: [reconnaissance](../tactics/reconnaissance.md)",
     "- Tactic: [collection](../tactics/collection.md)"),
]


@pytest.mark.parametrize("tid,label,shipped,stale", TECHNIQUE_MUTATIONS,
                         ids=[f"{m[0]}-{m[1]}" for m in TECHNIQUE_MUTATIONS])
def test_stale_technique_line_is_red_and_fixed(tree, tid, label, shipped, stale):
    page = tree / "techniques" / f"{tid}.md"
    before = page.read_text(encoding="utf-8")
    mutate(page, shipped, stale)

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert f"{tid}: {label} line is '{stale}', matrix.json says '{shipped}'" in result.stdout

    fixed = run_checker(tree, "--fix")
    assert fixed.returncode == 0, fixed.stdout
    assert page.read_text(encoding="utf-8") == before
    assert run_checker(tree).returncode == 0


def test_missing_technique_line_is_red(tree):
    mutate(tree / "techniques" / "T-5002.md", "- **HMA Checks:** A2A-001, A2A-002\n", "")
    result = run_checker(tree)
    assert result.returncode == 1
    assert "T-5002: page has no 'HMA Checks' line" in result.stdout

    fixed = run_checker(tree, "--fix")
    assert fixed.returncode == 1, "--fix cannot invent the line's place, so it stays red"
    assert "FAIL: could not rewrite 1" in fixed.stdout


def test_duplicate_technique_line_is_red(tree):
    mutate(tree / "techniques" / "T-5002.md", "- **HMA Checks:** A2A-001, A2A-002\n",
           "- **HMA Checks:** A2A-001, A2A-002\n- **HMA Checks:** AIM-001, AIM-002\n")
    result = run_checker(tree)
    assert result.returncode == 1
    assert "T-5002: page has 2 'HMA Checks' lines" in result.stdout
    assert run_checker(tree, "--fix").returncode == 1


# Code examples whose lines look like the page's data lines. A shell comment used to be
# counted as a second Title line.
FENCED_EXAMPLES = (
    "```sh\n"
    "# list the agent card a host serves\n"
    "curl -s https://agent.example/.well-known/agent.json\n"
    "```\n"
    "\n"
    "~~~markdown\n"
    "# T-1006: Agent Card Lookup\n"
    "\n"
    "## Description\n"
    "\n"
    "Discover A2A agent cards\n"
    "\n"
    "- **HMA Checks:** AIM-001\n"
    "- Tactic: [collection](../tactics/collection.md)\n"
    "~~~\n"
    "\n"
)


def test_lines_inside_fenced_code_blocks_are_not_data_lines(tree):
    page = tree / "techniques" / "T-1006.md"
    mutate(page, "## Mitigation\n", FENCED_EXAMPLES + "## Mitigation\n")
    before = page.read_text(encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 0, result.stdout
    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


def test_stale_line_beside_a_fenced_code_block_is_red_and_fixed(tree):
    page = tree / "techniques" / "T-1006.md"
    mutate(page, "## Mitigation\n", FENCED_EXAMPLES + "## Mitigation\n")
    before = page.read_text(encoding="utf-8")
    mutate(page, "- **HMA Checks:** A2A-001, A2A-002\n", "- **HMA Checks:** AIM-001, AIM-002\n")

    result = run_checker(tree)
    assert result.returncode == 1
    assert ("T-1006: HMA Checks line is '- **HMA Checks:** AIM-001, AIM-002', "
            "matrix.json says '- **HMA Checks:** A2A-001, A2A-002'") in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


# Blocks whose inner lines look like a closing fence and are not one, as in CommonMark: a
# fence closes on a line of the same character, at least as long as the opening fence, with
# nothing after it. Each block holds a second HMA Checks line that must stay code.
STILL_FENCED = [
    ("a shorter backtick line in a four-backtick block",
     "````markdown\n```\n- **HMA Checks:** AIM-001\n```\n````\n\n"),
    ("a tilde line in a backtick block",
     "```text\n~~~\n- **HMA Checks:** AIM-001\n~~~\n```\n\n"),
    ("a backtick line with an info string",
     "```sh\n```python\n- **HMA Checks:** AIM-001\n```\n\n"),
]


@pytest.mark.parametrize("block", [b for _, b in STILL_FENCED], ids=[n for n, _ in STILL_FENCED])
def test_a_line_that_does_not_close_the_fence_leaves_the_block_open(tree, block):
    page = tree / "techniques" / "T-1006.md"
    mutate(page, "## Mitigation\n", block + "## Mitigation\n")
    before = page.read_text(encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 0, result.stdout
    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


def test_an_unclosed_fence_runs_to_the_end_of_the_page(tree):
    page = tree / "techniques" / "T-1006.md"
    text = page.read_text(encoding="utf-8")
    page.write_text(text + "\n```\n- **HMA Checks:** AIM-001\n", encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 0, result.stdout


def test_an_unclosed_fence_hides_the_data_lines_after_it(tree):
    mutate(tree / "techniques" / "T-1006.md", "## Evidence\n", "```\n\n## Evidence\n")

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert "T-1006: page has no 'Evidence Tier' line" in result.stdout
    assert "T-1006: page has no 'References tactic' line" in result.stdout


# Lines that CommonMark does not treat as an opening fence: backticks followed by a
# backtick in the info string are an inline code span, and U+2028 or a form feed does not
# end a line. The data line after each is still a data line of the page.
NOT_A_FENCE = [
    ("a backtick in the info string", "```x`y\n"),
    ("a line separator before the backticks", "Example\u2028```\n"),
    ("a form feed before the backticks", "Example\x0c```\n"),
]


@pytest.mark.parametrize("opener", [o for _, o in NOT_A_FENCE], ids=[n for n, _ in NOT_A_FENCE])
def test_a_line_that_is_not_a_fence_does_not_hide_the_data_lines_after_it(tree, opener):
    page = tree / "techniques" / "T-1006.md"
    text = page.read_text(encoding="utf-8")
    page.write_text(text + "\n" + opener + "- **HMA Checks:** WRONG-001\n", encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert "T-1006: page has 2 'HMA Checks' lines" in result.stdout


# Blocks that CommonMark ends, or never reads as a fence, before the data line after them,
# so that line is still a data line of the page. A fence inside a list item or a block
# quote ends with it, at the first line that does not continue it, and a fence line inside
# an HTML comment opens nothing. Every case but the block quote used to be read as a fence
# running to the end of the page, which hid the data line.
ENDED_BEFORE_THE_DATA_LINE = [
    ("a fence in a list item", "- step\n  ```sh\n  run\n"),
    ("a fence in a list item after a lazy line", "- step\ncontinued\n  ```sh\n  run\n"),
    ("a fence in a block quote", "> ```sh\n> run\n"),
    ("a fence line in an HTML comment", "<!--\n```\n-->\n"),
    # An item whose first line is blank ends at a second blank line, so the comment is not
    # in the item and does not end at the unindented fence line.
    ("a comment after an item that starts blank", "-\n\n  <!--\n```\n-->\n"),
    # An ordered item that interrupts a paragraph must start at 1, so "2." is paragraph
    # text and the comment is not in an item.
    ("a comment after an ordered line that continues a paragraph",
     "Some text\n2. step\n   <!--\n```\n-->\n"),
    # A comment line starts a block, so it ends the list item instead of continuing its
    # paragraph lazily, and the fence line inside the comment opens nothing.
    ("a fence line in a comment that ends a list item", "- step\n<!--\n```\n-->\n"),
    # A line indented four columns is indented code, not a paragraph, so an ordered item
    # after it may start at 2 and holds the fence. The page ends in a list item, which the
    # indented line would continue, so a paragraph ends that item first.
    ("a fence in an ordered item after indented code",
     "Notes\n\n    code\n2. step\n   ```\n"),
    # Five spaces after a marker start indented code one column after the marker, so the
    # item's content is two columns in and the fence is in the item.
    ("a fence in an item whose text starts with indented code", "-     code\n  ```\n"),
    # A tab reaches column four, so the tab-indented line continues the item.
    ("a fence in an item continued by a tab-indented line", "- step\n\n\tmore\n  ```\n"),
]


@pytest.mark.parametrize("block", [b for _, b in ENDED_BEFORE_THE_DATA_LINE],
                         ids=[n for n, _ in ENDED_BEFORE_THE_DATA_LINE])
def test_a_block_that_ends_before_a_data_line_does_not_hide_it(tree, block):
    page = tree / "techniques" / "T-1006.md"
    text = page.read_text(encoding="utf-8")
    page.write_text(text + "\n" + block + "- **HMA Checks:** WRONG-001\n", encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert "T-1006: page has 2 'HMA Checks' lines" in result.stdout


# Fences that CommonMark keeps open over the data line after them, so that line is code.
STILL_OPEN_AT_THE_DATA_LINE = [
    # A comment in a list item ends with the item, so the unindented fence line opens a fence.
    ("a fence after a comment in a list item", "- <!--\n```\n"),
    # A fence is not paragraph text, so it ends the list item instead of continuing it.
    ("a fence after a lazy line of a list item", "- step\ncontinued\n```\n"),
    # A closing fence has at most three spaces of indentation.
    ("a closing fence line indented four spaces", "```\n    ```\n"),
    # Three list markers with spaces between them are a thematic break, not three list
    # items, so the indented fence after it is not in an item.
    ("a fence after a thematic break made of list markers", "- - -\n  ```\n"),
    # A comment ends at the line that holds "-->", so the fence line after it opens a fence.
    ("a fence after a comment that ends on a later line", "<!--\n-->\n```\n"),
    ("a fence after a comment that ends on its first line", "<!-- note -->\n```\n"),
]


@pytest.mark.parametrize("block", [b for _, b in STILL_OPEN_AT_THE_DATA_LINE],
                         ids=[n for n, _ in STILL_OPEN_AT_THE_DATA_LINE])
def test_a_fence_still_open_at_a_data_line_hides_it(tree, block):
    page = tree / "techniques" / "T-1006.md"
    text = page.read_text(encoding="utf-8")
    page.write_text(text + "\n" + block + "- **HMA Checks:** AIM-001\n", encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 0, result.stdout


def hidden_lines(text: str) -> list[str]:
    """The lines of ``text`` that start inside a fenced code block."""
    spans = CHK.fenced_spans(text)
    hidden, offset = [], 0
    for line in text.split("\n"):
        if any(start <= offset < end for start, end in spans):
            hidden.append(line)
        offset += len(line) + 1
    return hidden


# (text, the lines fenced_spans must hide). A line in a list item or block quote starts with
# indentation or a ">" marker, and a data line is read only at the start of a line, so no
# page-level case can show whether the fence holding such a line was found; these cases
# read the spans directly.
HIDDEN_LINES = [
    ("a fence in a list item",
     "- step\n  ```\n  - **HMA Checks:** WRONG-001\n  ```\nafter\n",
     ["  ```", "  - **HMA Checks:** WRONG-001", "  ```"]),
    ("a fence that ends with its list item",
     "- step\n  ```\n  - **HMA Checks:** WRONG-001\nafter\n",
     ["  ```", "  - **HMA Checks:** WRONG-001"]),
    ("a fence in a block quote",
     "> ```\n> - **HMA Checks:** WRONG-001\n> ```\nafter\n",
     ["> ```", "> - **HMA Checks:** WRONG-001", "> ```"]),
    ("a fence that ends with its block quote",
     "> ```\n> - **HMA Checks:** WRONG-001\nafter\n",
     ["> ```", "> - **HMA Checks:** WRONG-001"]),
    # A marker has at most three spaces before it, so each of these lines is indented code
    # and opens no container for the fence line after it to sit in.
    ("a list marker indented four columns", "    - step\n\n      ```\n      code\n", []),
    ("a block quote marker indented four columns", "    > ```\n    > code\n", []),
]


@pytest.mark.parametrize("text,hidden", [(t, h) for _, t, h in HIDDEN_LINES],
                         ids=[n for n, _, _ in HIDDEN_LINES])
def test_fenced_spans_hide_exactly_the_lines_of_each_fence(text, hidden):
    assert hidden_lines(text) == hidden


def test_a_line_indented_four_spaces_opens_no_fence(tree):
    # Four spaces of indentation make indented code, not a fence, so the data line after it
    # is still a data line of the page.
    mutate(tree / "techniques" / "T-1006.md", "## Mitigation\n",
           "## Mitigation\n\n    ```\n- **HMA Checks:** WRONG-001\n")

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert "T-1006: page has 2 'HMA Checks' lines" in result.stdout


def test_many_fenced_blocks_cost_linear_time():
    blocks = 16000
    text = "# t\n```\n# t\n```\n" * blocks
    title = next(regex for label, regex, _ in CHK.FIELDS if label == "Title")
    started = time.perf_counter()
    found = CHK.find_lines(title, text)
    assert time.perf_counter() - started < 2.0
    assert len(found) == blocks


def test_deeply_nested_list_items_cost_linear_time():
    # A line of many list markers, each read once, and lines that continue every item.
    text = "- " * 20000 + "x\n" + ("1. " * 2000 + "y\n") + (" " * 6000 + "z\n") * 200
    started = time.perf_counter()
    CHK.fenced_spans(text)
    assert time.perf_counter() - started < 2.0


def test_dvaa_line_on_a_technique_without_one_in_the_data_is_red_and_fixed(tree):
    page = tree / "techniques" / "T-8003.md"
    before = page.read_text(encoding="utf-8")
    mutate(page, "No documented procedures yet.", "- **DVAA Validation:** dns tunnel")

    result = run_checker(tree)
    assert result.returncode == 1
    assert "T-8003: page has a 'DVAA Validation' line, matrix.json has none" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


def test_dvaa_added_to_the_data_is_red_and_fixed(tree):
    matrix_path = tree / "matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    technique = next(t for t in matrix["techniques"] if t["id"] == "T-8003")
    technique["dvaaValidation"] = "dns tunnel"
    matrix_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 1
    assert "T-8003: page has no 'DVAA Validation' line" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    page = (tree / "techniques" / "T-8003.md").read_text(encoding="utf-8")
    assert "- **DVAA Validation:** dns tunnel" in page
    assert "No documented procedures yet." not in page
    assert run_checker(tree).returncode == 0


def test_dvaa_added_to_the_data_leaves_a_placeholder_inside_a_fenced_block_alone(tree):
    example = "```markdown\nNo documented procedures yet.\n```\n\n"
    mutate(tree / "techniques" / "T-8003.md", "## Procedure Examples\n",
           example + "## Procedure Examples\n")
    matrix_path = tree / "matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    technique = next(t for t in matrix["techniques"] if t["id"] == "T-8003")
    technique["dvaaValidation"] = "dns tunnel"
    matrix_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")

    assert run_checker(tree, "--fix").returncode == 0
    page = (tree / "techniques" / "T-8003.md").read_text(encoding="utf-8")
    assert example + "## Procedure Examples\n\n- **DVAA Validation:** dns tunnel\n" in page
    assert page.count("No documented procedures yet.") == 1
    assert run_checker(tree).returncode == 0


# (tactic page, shipped row, stale row)
TACTIC_MUTATIONS = [
    ("reconnaissance",
     "| [T-1006](../techniques/T-1006.md) | Agent Card Discovery | observed | A2A-EXPOSE |",
     "| [T-1006](../techniques/T-1006.md) | Agent Card Discovery | observed | AGENT-IMPERSONATE |"),
    ("lateral-movement",
     "| [T-5002](../techniques/T-5002.md) | A2A Agent Pivoting | validated | A2A-EXPOSE |",
     "| [T-5002](../techniques/T-5002.md) | A2A Agent Pivoting | adapted | A2A-EXPOSE |"),
    ("impact",
     "| [T-9006](../techniques/T-9006.md) | Supply Chain Compromise | observed | NEMO-SUPPLY-CHAIN |",
     "| [T-9006](../techniques/T-9006.md) | Supply Chain Compromise | observed | ORG-SKILL-SPREAD |"),
    ("impact", "**Kill Chain Stage:** 9", "**Kill Chain Stage:** 8"),
]


@pytest.mark.parametrize("tactic,shipped,stale", TACTIC_MUTATIONS,
                         ids=[f"{m[0]}-{i}" for i, m in enumerate(TACTIC_MUTATIONS)])
def test_stale_tactic_line_is_red_and_fixed(tree, tactic, shipped, stale):
    page = tree / "tactics" / f"{tactic}.md"
    before = page.read_text(encoding="utf-8")
    mutate(page, shipped, stale)

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert f"tactics/{tactic}.md: " in result.stdout
    assert f"is '{stale}', matrix.json says '{shipped}'" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


def test_missing_tactic_row_is_red_and_fixed(tree):
    page = tree / "tactics" / "impact.md"
    before = page.read_text(encoding="utf-8")
    mutate(page, "| [T-9006](../techniques/T-9006.md) | Supply Chain Compromise | observed | NEMO-SUPPLY-CHAIN |\n", "")

    result = run_checker(tree)
    assert result.returncode == 1
    assert "tactics/impact.md: line 18 is missing, matrix.json says '| [T-9006]" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


def test_tactic_row_follows_a_class_move_in_the_data(tree):
    matrix_path = tree / "matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    technique = next(t for t in matrix["techniques"] if t["id"] == "T-5002")
    technique["attackClass"] = "AGENT-IMPERSONATE"
    matrix_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 1
    assert "tactics/lateral-movement.md: line 14 is" in result.stdout
    assert "T-5002: References attack class line is" in result.stdout


# Every technique maps to one or more OASB controls, yet every page said "No documented
# mitigations yet." under Mitigation and printed an empty Severity line that no matrix.json
# field backs.
NO_MITIGATION = "No documented mitigations yet."
MITIGATION_SECTION_RE = re.compile(r"^## Mitigation\n(.*?)(?=^## |\Z)", re.M | re.S)
TECHNIQUES = json.loads((ROOT / "matrix.json").read_text(encoding="utf-8"))["techniques"]
# The OASB-1 control titles pinned in related-projects.json. Before they were pinned, every
# section listed each control by its bare id, as "- OASB 1.1", and the checker passed it.
RELATED = json.loads((ROOT / "related-projects.json").read_text(encoding="utf-8"))
TITLES = RELATED["oasb"]["controlTitles"]
CONTROL_LINE_RE = re.compile(r"^- OASB (.*)$", re.M)


def titled(*controls: str) -> list[str]:
    """What CONTROL_LINE_RE reads from the lines that list these controls with their titles."""
    return [f"{control}: {TITLES[control]}" for control in controls]


def edit_related(root: Path, change) -> None:
    """Apply change to the parsed related-projects.json under root and write it back."""
    path = root / "related-projects.json"
    related = json.loads(path.read_text(encoding="utf-8"))
    change(related)
    path.write_text(json.dumps(related, indent=2) + "\n", encoding="utf-8")


def test_the_titles_cover_the_pinned_oasb_controls_and_every_mapped_one():
    # The titles were read from the release the controls and domains figures were read from.
    assert len(TITLES) == RELATED["oasb"]["controls"]
    assert len({control.split(".")[0] for control in TITLES}) == RELATED["oasb"]["domains"]
    assert all(isinstance(title, str) and title.strip() for title in TITLES.values())
    assert {c for t in TECHNIQUES for c in t["oasbControls"]} <= set(TITLES)


def test_no_shipped_page_says_no_mitigation_is_documented():
    pages = sorted((ROOT / "techniques").glob("*.md"))
    assert pages
    assert [p.name for p in pages if NO_MITIGATION in p.read_text(encoding="utf-8")] == []


def test_no_shipped_page_prints_a_severity_line():
    pages = sorted((ROOT / "techniques").glob("*.md"))
    assert [p.name for p in pages
            if re.search(r"^\*\*Severity:\*\*", p.read_text(encoding="utf-8"), re.M)] == []


@pytest.mark.parametrize("technique", TECHNIQUES, ids=[t["id"] for t in TECHNIQUES])
def test_mitigation_section_names_every_mapped_control_in_order_with_its_title(technique):
    text = (ROOT / "techniques" / f"{technique['id']}.md").read_text(encoding="utf-8")
    found = MITIGATION_SECTION_RE.search(text)
    assert found, "page has a Mitigation section"
    assert CONTROL_LINE_RE.findall(found.group(1)) == titled(*technique["oasbControls"])


# A line the pages carried before the titles, and two near misses of the titled line.
UNTITLED_LINES = ["- OASB 1.1", "- OASB 1.1: Agent Identity",
                  f"- OASB 1.1 {TITLES['1.1']}"]


@pytest.mark.parametrize("stale", UNTITLED_LINES)
def test_a_control_listed_without_its_title_is_red_and_fixed(tree, stale):
    page = tree / "techniques" / "T-1001.md"
    before = page.read_text(encoding="utf-8")
    mutate(page, f"- OASB 1.1: {TITLES['1.1']}\n", stale + "\n")

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert ("T-1001: Mitigation section does not list the OASB controls matrix.json maps "
            "(1.1, 1.2, 1.3, 1.4, 10.5) with their titles in related-projects.json") in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before
    assert run_checker(tree).returncode == 0


def test_mitigation_follows_a_title_change_in_related_projects_json(tree):
    edit_related(tree, lambda r: r["oasb"]["controlTitles"].update({"7.1": "Agent Authentication"}))
    users = [t["id"] for t in TECHNIQUES if "7.1" in t["oasbControls"]]
    assert users

    result = run_checker(tree)
    assert result.returncode == 1
    assert result.stdout.count("Mitigation section does not list") == len(users), result.stdout
    for tid in users:
        assert f"  - {tid}: Mitigation section does not list the OASB controls" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    for tid in users:
        text = (tree / "techniques" / f"{tid}.md").read_text(encoding="utf-8")
        section = MITIGATION_SECTION_RE.search(text).group(1)
        assert "7.1: Agent Authentication" in CONTROL_LINE_RE.findall(section)
    assert run_checker(tree).returncode == 0


def test_a_mapped_control_with_no_title_is_red_and_left_alone(tree):
    edit_related(tree, lambda r: r["oasb"]["controlTitles"].pop("10.5"))
    page = tree / "techniques" / "T-1001.md"
    before = page.read_text(encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 1
    assert ("T-1001: matrix.json maps OASB control 10.5, which related-projects.json gives no "
            "title under oasb.controlTitles") in result.stdout

    fixed = run_checker(tree, "--fix")
    assert fixed.returncode == 1, "--fix has no title to write, so it stays red"
    assert "FAIL: could not rewrite" in fixed.stdout
    assert page.read_text(encoding="utf-8") == before


def test_controls_with_no_title_are_named_beside_a_missing_section(tree):
    # The OASB 11.1 to 11.4 the pages once cited do not exist in the shipped OASB-1 set.
    matrix_path = tree / "matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    technique = next(t for t in matrix["techniques"] if t["id"] == "T-1006")
    technique["oasbControls"] = ["7.1", "11.1", "11.2"]
    matrix_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")
    page = tree / "techniques" / "T-1006.md"
    page.write_text(MITIGATION_SECTION_RE.sub("", page.read_text(encoding="utf-8"), count=1),
                    encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 1
    assert ("T-1006: matrix.json maps OASB controls 11.1, 11.2, which related-projects.json "
            "gives no title under oasb.controlTitles") in result.stdout
    assert "T-1006: page has no '## Mitigation' section" in result.stdout


def _set_oasb(value):
    return lambda r: r.update({"oasb": value})


def _set_titles(value):
    return lambda r: r["oasb"].update({"controlTitles": value})


def _set_title(control, value):
    return lambda r: r["oasb"]["controlTitles"].update({control: value})


def _write(raw: bytes):
    return lambda path: path.write_bytes(raw)


# (name, what make(path) leaves at related-projects.json, the one line the check prints)
RELATED_CASES = [
    ("missing", lambda path: path.unlink(),
     "FAIL: related-projects.json is missing or does not parse: no such file"),
    ("syntax error", _write(b"{"),
     "FAIL: related-projects.json is missing or does not parse: Expecting property name "
     "enclosed in double quotes: line 1 column 2 (char 1)"),
    ("an array", _write(b"[]\n"),
     "FAIL: related-projects.json parses but has the wrong shape: the top level is an array, "
     "not an object"),
    ("no oasb key", lambda path: edit_related(path.parent, lambda r: r.pop("oasb")),
     "FAIL: related-projects.json parses but has the wrong shape: the top level has no oasb key"),
    ("oasb a string", lambda path: edit_related(path.parent, _set_oasb("OASB-1")),
     "FAIL: related-projects.json parses but has the wrong shape: oasb is a string, not an object"),
    ("no controlTitles",
     lambda path: edit_related(path.parent, lambda r: r["oasb"].pop("controlTitles")),
     "FAIL: related-projects.json parses but has the wrong shape: oasb has no controlTitles"),
    ("controlTitles an array", lambda path: edit_related(path.parent, _set_titles([])),
     "FAIL: related-projects.json parses but has the wrong shape: oasb.controlTitles is an "
     "array, not an object"),
    ("a title that is a number", lambda path: edit_related(path.parent, _set_title("1.1", 1)),
     'FAIL: related-projects.json parses but has the wrong shape: oasb.controlTitles["1.1"] is '
     "a number, not a string"),
    ("a title that is null", lambda path: edit_related(path.parent, _set_title("10.5", None)),
     'FAIL: related-projects.json parses but has the wrong shape: oasb.controlTitles["10.5"] is '
     "null, not a string"),
]


@pytest.mark.parametrize("args", [(), ("--fix",)], ids=["check", "fix"])
@pytest.mark.parametrize("make, line", [case[1:] for case in RELATED_CASES],
                         ids=[case[0] for case in RELATED_CASES])
def test_a_related_projects_json_the_check_cannot_use_is_reported_in_one_line(tree, make, line, args):
    # A stale page that --fix would rewrite, to show that nothing is written.
    mutate(tree / "techniques" / "T-1001.md", f"- OASB 1.1: {TITLES['1.1']}\n", "- OASB 1.1\n")
    pages = {p: p.read_bytes() for p in sorted(tree.rglob("*.md"))}
    make(tree / "related-projects.json")

    result = run_checker(tree, *args)
    assert result.returncode == 1, result.stdout + result.stderr
    assert result.stdout == ""
    assert result.stderr.splitlines() == [line]
    assert {p: p.read_bytes() for p in sorted(tree.rglob("*.md"))} == pages


def test_placeholder_mitigation_is_red_and_fixed(tree):
    page = tree / "techniques" / "T-1001.md"
    before = page.read_text(encoding="utf-8")
    found = MITIGATION_SECTION_RE.search(before)
    page.write_text(before[:found.start(1)] + f"\n{NO_MITIGATION}\n\n" + before[found.end(1):],
                    encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert ("T-1001: Mitigation section does not list the OASB controls matrix.json maps "
            "(1.1, 1.2, 1.3, 1.4, 10.5)") in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before
    assert run_checker(tree).returncode == 0


def test_mitigation_follows_a_control_change_in_the_data(tree):
    matrix_path = tree / "matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    technique = next(t for t in matrix["techniques"] if t["id"] == "T-1006")
    technique["oasbControls"] = ["7.1"]
    matrix_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 1
    assert "T-1006: Mitigation section does not list the OASB controls matrix.json maps (7.1)" \
        in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    section = MITIGATION_SECTION_RE.search((tree / "techniques" / "T-1006.md").read_text(encoding="utf-8"))
    assert CONTROL_LINE_RE.findall(section.group(1)) == titled("7.1")


def test_severity_line_is_red_and_dropped(tree):
    page = tree / "techniques" / "T-1001.md"
    before = page.read_text(encoding="utf-8")
    mutate(page, "**Tactic:** reconnaissance\n", "**Tactic:** reconnaissance\n**Severity:** \n")

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert "T-1001: page has a Severity line, and matrix.json has no severity field" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


def test_severity_line_inside_a_fenced_block_is_not_a_data_line(tree):
    page = tree / "techniques" / "T-1001.md"
    mutate(page, "## Mitigation\n", "```markdown\n**Severity:** high\n```\n\n## Mitigation\n")
    assert run_checker(tree).returncode == 0


def test_missing_mitigation_section_is_red(tree):
    page = tree / "techniques" / "T-1001.md"
    page.write_text(MITIGATION_SECTION_RE.sub("", page.read_text(encoding="utf-8"), count=1),
                    encoding="utf-8")
    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert "T-1001: page has no '## Mitigation' section" in result.stdout

    fixed = run_checker(tree, "--fix")
    assert fixed.returncode == 1, "--fix cannot invent the section's place, so it stays red"
    assert "FAIL: could not rewrite 1" in fixed.stdout


def test_mitigation_section_holding_a_fence_is_red_and_left_alone(tree):
    # An unclosed fence carries the rest of the page into the section; rewriting the section
    # would delete the Evidence and References sections behind it.
    page = tree / "techniques" / "T-1001.md"
    mutate(page, "## Mitigation\n\n", "## Mitigation\n\n```\n")
    before = page.read_text(encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 1
    assert "T-1001: Mitigation section does not list the OASB controls" in result.stdout

    assert run_checker(tree, "--fix").returncode == 1
    assert page.read_text(encoding="utf-8") == before


def test_heading_inside_a_fenced_block_does_not_end_the_mitigation_section(tree):
    page = tree / "techniques" / "T-1001.md"
    line = f"- OASB 10.5: {TITLES['10.5']}\n"
    mutate(page, line, line + "\n```markdown\n## Evidence\n```\n")

    result = run_checker(tree)
    assert result.returncode == 1
    assert "T-1001: Mitigation section does not list the OASB controls" in result.stdout


def test_rendered_section_for_a_technique_without_controls_keeps_the_placeholder():
    assert CHK.expected_mitigation({"oasbControls": []}, TITLES) == NO_MITIGATION
    rendered = CHK.expected_mitigation({"oasbControls": ["1.1", "10.5"]}, TITLES)
    assert CONTROL_LINE_RE.findall(rendered) == ["1.1: Agent Cryptographic Identity",
                                                 "10.5: Recovery and Rollback"]
    assert NO_MITIGATION not in rendered


# The adapted pages showed only "Evidence Tier: adapted" while EVIDENCE_AUDIT.md said each
# page stated the gap.
GAP_LINE_RE = re.compile(r"^- \*\*Evidence Gap:\*\*.*\n", re.M)


@pytest.mark.parametrize("technique", TECHNIQUES, ids=[t["id"] for t in TECHNIQUES])
def test_adapted_page_states_the_gap_and_no_other_page_does(technique):
    text = (ROOT / "techniques" / f"{technique['id']}.md").read_text(encoding="utf-8")
    gap = re.findall(r"^- \*\*Evidence Gap:\*\* (.*)$", text, re.M)
    if technique["evidenceTier"] == "adapted":
        assert len(gap) == 1
        assert "no agent-specific observation and no lab reproduction" in gap[0]
    else:
        assert gap == []


@pytest.mark.parametrize("technique", TECHNIQUES, ids=[t["id"] for t in TECHNIQUES])
def test_procedure_examples_name_the_lab_scenario_matrix_json_carries(technique):
    text = (ROOT / "techniques" / f"{technique['id']}.md").read_text(encoding="utf-8")
    listed = re.findall(r"^- \*\*DVAA Validation:\*\* (.*)$", text, re.M)
    assert listed == ([technique["dvaaValidation"]] if technique["dvaaValidation"] else [])


def test_adapted_page_without_the_gap_is_red_and_fixed(tree):
    page = tree / "techniques" / "T-9004.md"
    before = page.read_text(encoding="utf-8")
    page.write_text(GAP_LINE_RE.sub("", before), encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert "T-9004: adapted page does not state its evidence gap" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


def test_stale_gap_line_is_red_and_fixed(tree):
    page = tree / "techniques" / "T-8003.md"
    before = page.read_text(encoding="utf-8")
    mutate(page, CHK.ADAPTED_GAP, "- **Evidence Gap:** none")

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert "T-8003: Evidence Gap line is '- **Evidence Gap:** none'" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


def test_gap_line_on_a_page_that_is_not_adapted_is_red_and_dropped(tree):
    page = tree / "techniques" / "T-1001.md"
    before = page.read_text(encoding="utf-8")
    mutate(page, "- **Evidence Tier:** observed\n", "- **Evidence Tier:** observed\n" + CHK.ADAPTED_GAP + "\n")

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert ("T-1001: page has an Evidence Gap line, and matrix.json tier is 'observed', "
            "not adapted") in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


def test_two_gap_lines_are_red_and_left_for_a_hand_edit(tree):
    page = tree / "techniques" / "T-8003.md"
    mutate(page, CHK.ADAPTED_GAP + "\n", CHK.ADAPTED_GAP + "\n" + CHK.ADAPTED_GAP + "\n")

    result = run_checker(tree)
    assert result.returncode == 1
    assert "T-8003: page has 2 'Evidence Gap' lines" in result.stdout
    assert run_checker(tree, "--fix").returncode == 1


def test_gap_line_follows_a_tier_change_in_the_data(tree):
    matrix_path = tree / "matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    technique = next(t for t in matrix["techniques"] if t["id"] == "T-1001")
    technique["evidenceTier"] = "adapted"
    matrix_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")

    result = run_checker(tree)
    assert result.returncode == 1
    assert "T-1001: Evidence Tier line is" in result.stdout
    assert "T-1001: adapted page does not state its evidence gap" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    page = (tree / "techniques" / "T-1001.md").read_text(encoding="utf-8")
    assert "- **Evidence Tier:** adapted\n" + CHK.ADAPTED_GAP + "\n" in page


# A vocabulary entry and two uses of it, as matrix.json carries them; the values are
# illustrative, and the page check reads only the source id and name and the four mapping keys.
EXAMPLE_SOURCE = {"id": "example-log", "name": "Example request log", "description": "Example",
                  "readBy": [{"tool": "example-sensor", "repository": "example-org/example-sensor",
                              "commit": "0" * 40, "path": "src/example.ts", "line": 1}]}
EXAMPLE_MAPPINGS = [
    {"source": "example-log", "tool": "example-sensor", "kind": "sensorField", "ref": "path"},
    {"source": "example-log", "tool": "example-sensor", "kind": "check", "ref": "EX-001"},
]
EXAMPLE_LINE = ("- **Data Sources:** Example request log (example-sensor sensor field path, "
                "example-sensor check EX-001)")
T1001_CONTROLS = "- **OASB Controls:** 1.1, 1.2, 1.3, 1.4, 10.5"


def map_data_sources(root: Path, mappings: list, vocabulary: list) -> None:
    matrix_path = root / "matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    matrix["dataSources"] = vocabulary
    next(t for t in matrix["techniques"] if t["id"] == "T-1001")["dataSources"] = mappings
    matrix_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")


def test_a_mapped_data_source_is_red_until_the_page_names_it_and_fix_writes_it(tree):
    map_data_sources(tree, EXAMPLE_MAPPINGS, [EXAMPLE_SOURCE])

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert f"T-1001: page has no 'Data Sources' line; matrix.json says '{EXAMPLE_LINE}'" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    page = (tree / "techniques" / "T-1001.md").read_text(encoding="utf-8")
    assert T1001_CONTROLS + "\n" + EXAMPLE_LINE + "\n" in page
    assert "example-log" not in page
    result = run_checker(tree)
    assert result.returncode == 0, result.stdout
    assert "and 1 of 61 technique pages carry a Data Sources line" in result.stdout


def test_a_data_sources_line_that_shows_the_source_id_is_red_and_fixed(tree):
    map_data_sources(tree, EXAMPLE_MAPPINGS, [EXAMPLE_SOURCE])
    page = tree / "techniques" / "T-1001.md"
    by_id = EXAMPLE_LINE.replace("Example request log", "example-log")
    mutate(page, T1001_CONTROLS + "\n", T1001_CONTROLS + "\n" + by_id + "\n")

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert f"T-1001: Data Sources line is '{by_id}', matrix.json says '{EXAMPLE_LINE}'" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    text = page.read_text(encoding="utf-8")
    assert EXAMPLE_LINE in text and by_id not in text


def test_a_data_sources_line_on_a_technique_that_maps_none_is_red_and_dropped(tree):
    page = tree / "techniques" / "T-1001.md"
    before = page.read_text(encoding="utf-8")
    mutate(page, T1001_CONTROLS + "\n", T1001_CONTROLS + "\n" + EXAMPLE_LINE + "\n")

    result = run_checker(tree)
    assert result.returncode == 1, result.stdout
    assert "T-1001: page has a Data Sources line, and matrix.json maps no data source" in result.stdout

    assert run_checker(tree, "--fix").returncode == 0
    assert page.read_text(encoding="utf-8") == before


def test_a_source_the_vocabulary_does_not_hold_is_red_and_left_alone(tree):
    map_data_sources(tree, EXAMPLE_MAPPINGS, [])
    page = tree / "techniques" / "T-1001.md"
    before = page.read_text(encoding="utf-8")

    result = run_checker(tree, "--fix")
    assert result.returncode == 1, result.stdout
    assert ("T-1001: matrix.json maps data source example-log, which the dataSources vocabulary "
            "does not hold, so the page has no name to show") in result.stdout
    assert page.read_text(encoding="utf-8") == before
