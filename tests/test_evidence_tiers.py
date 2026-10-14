"""Evidence tier definition checker tests.

Every case runs scripts/check_evidence_tiers.py against a scratch copy of the canonical page,
the three quoting pages and the schema, so the committed files are never perturbed. The
shipped tree must be green. Each wording the three pages carried before docs/evidence-tiers.md
became the single definition is then planted back and must be reported at its own line, as
must a dropped definition, a definition wrapped over two lines or continued on the next line
or, after a blank line, by a line indented as far as its item's text, a canonical edit the
quoting pages do not follow, and a schema tier the canonical page does not define. Lines end
where CommonMark ends them, and indentation is counted in columns with tab stops of four. A
list-item definition is read where CommonMark reads a bulleted list item, a code fence
where CommonMark reads one, and the cases where the check is stricter than CommonMark are
named as such. A character that does not print is escaped in the message. A long
line on the canonical page that does not complete a row, a table row
or list item on a quoting page that holds a long run of white space before more text, and a
line of many list markers must be read in linear time.
"""

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = (
    "README.md",
    "CONTRIBUTING.md",
    "EVIDENCE_AUDIT.md",
    "docs/evidence-tiers.md",
    "schema/threat-matrix-v1.2.schema.json",
    "scripts/check_evidence_tiers.py",
)

OBSERVED = "Confirmed in real-world production systems"
VALIDATED = "Reproduced in controlled lab environment (DVAA)"
ADAPTED = ("Well-understood traditional technique applied to agent context, "
           "not yet observed agent-specifically")


@pytest.fixture
def tree():
    td = Path(tempfile.mkdtemp(prefix="atm-tiers-"))
    for rel in FILES:
        dst = td / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    yield td
    shutil.rmtree(td)


def run_checker(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(root / "scripts" / "check_evidence_tiers.py")],
                          capture_output=True, text=True, timeout=120)


def mutate(root: Path, rel: str, old: str, new: str) -> int:
    """Replace the one occurrence of `old` in `rel` and return the line it starts on."""
    path = root / rel
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"mutation target must occur exactly once in {rel}: {old!r}"
    path.write_text(text.replace(old, new), encoding="utf-8")
    return text.count("\n", 0, text.index(old)) + 1


def test_shipped_tree_is_green(tree):
    r = run_checker(tree)
    assert r.returncode == 0, r.stderr
    assert "Evidence tier definitions match docs/evidence-tiers.md: 3 tiers" in r.stdout


@pytest.mark.parametrize("rel, old, new", [
    # The wordings the pages carried before this check existed.
    ("CONTRIBUTING.md", f"| **Observed** | {OBSERVED} |",
     "| **Observed** | Documented in a real-world production system, security incident "
     "report, or internet-wide exposure assessment |"),
    ("CONTRIBUTING.md", f"| **Validated** | {VALIDATED} |",
     "| **Validated** | Reproduced in a controlled lab environment with documented steps, "
     "expected output, and independent verification |"),
    ("EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
     f"- **OBSERVED**: {OBSERVED} (NemoClaw findings, exposure sweeps, npm attacks)\n"),
    ("EVIDENCE_AUDIT.md", f"- **VALIDATED**: {VALIDATED}\n",
     "- **VALIDATED**: Reproducible in controlled lab environment (DVAA challenges, "
     "HMA scan results)\n"),
    # One word changed in the README table.
    ("README.md", f"| **Adapted** | {ADAPTED} |",
     f"| **Adapted** | {ADAPTED.replace('Well-understood', 'Known')} |"),
])
def test_a_quote_that_differs_is_reported_at_its_line(tree, rel, old, new):
    line = mutate(tree, rel, old, new)
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"{rel}:{line}:" in r.stderr, r.stderr
    assert "quote docs/evidence-tiers.md" in r.stderr


def test_a_definition_wrapped_over_two_lines_is_reported(tree):
    line = mutate(tree, "EVIDENCE_AUDIT.md", f"- **ADAPTED**: {ADAPTED}\n",
                  "- **ADAPTED**: Well-understood traditional technique applied to agent "
                  "context,\n  not yet observed agent-specifically\n")
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"EVIDENCE_AUDIT.md:{line}: Adapted reads" in r.stderr, r.stderr


@pytest.mark.parametrize("after", [
    # The examples the audit page added to the Observed definition before this check existed,
    # on an indented line, which Markdown joins to the definition.
    "  (NemoClaw findings, exposure sweeps, npm attacks)\n",
    # The same examples on a line of plain text, which Markdown joins to it too.
    "(NemoClaw findings, exposure sweeps, npm attacks)\n",
    # A list nested under the definition.
    "  - NemoClaw findings\n",
    # A marker followed by a no-break space, or by no space at all: CommonMark separates a
    # bullet from its text with a space or tab only, so this is a line of plain text too.
    "-\N{NO-BREAK SPACE}(NemoClaw findings, exposure sweeps, npm attacks)\n",
    "-(NemoClaw findings, exposure sweeps, npm attacks)\n",
    # A line holding a no-break space or a form feed is not blank: a blank line holds
    # nothing but spaces and tabs.
    "\N{NO-BREAK SPACE}\n",
    "\f\n",
], ids=["indented line", "plain text line", "nested list", "no-break space after the marker",
        "no space after the marker", "no-break space line", "form feed line"])
def test_a_definition_that_continues_onto_the_next_line_is_reported(tree, after):
    # The definition's own line matches the canonical page word for word.
    line = mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
                  f"- **OBSERVED**: {OBSERVED}\n{after}")
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"EVIDENCE_AUDIT.md:{line}: Observed continues on line {line + 1};" in r.stderr, \
        r.stderr
    assert "Observed reads" not in r.stderr, r.stderr


@pytest.mark.parametrize("after", [
    # A marker with no text, which CommonMark reads as an empty item beside the definition.
    "-\n",
    # A numbered item, which starts a numbered list after the definition's list.
    "2. NemoClaw findings\n",
    # A bullet indented one column, which is still outside the definition's text.
    " - NemoClaw findings\n",
    # Three markers and nothing else: a thematic break, not a list item.
    "* * *\n",
], ids=["empty bullet", "numbered item", "bullet indented one column", "thematic break"])
def test_a_line_that_ends_the_item_in_commonmark_but_is_no_bullet_with_text_is_reported(
        tree, after):
    # The check is stricter than CommonMark here. CommonMark ends the definition's list item
    # at each of these lines, so nothing is joined to the definition, and the check reports
    # them all the same: only a bulleted item with text, indented no further than the
    # definition, ends a definition.
    line = mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
                  f"- **OBSERVED**: {OBSERVED}\n{after}")
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"EVIDENCE_AUDIT.md:{line}: Observed continues on line {line + 1};" in r.stderr, \
        r.stderr
    assert "Observed reads" not in r.stderr, r.stderr


@pytest.mark.parametrize("outer, indent", [
    ("-    Tiers:", "\t "),
    ("100. Tiers:", "\t "),
    ("-    Tiers:", "     "),
], ids=["tab-indented under a bulleted item", "tab-indented under a numbered item",
        "space-indented under a bulleted item"])
def test_a_bullet_four_columns_past_the_text_around_it_continues_the_definition(
        tree, outer, indent):
    # The outer item's text starts at column five and the definition is nested under it. The
    # bullet after it is indented four columns: outside the outer item, and too far from the
    # margin to start a list item, so CommonMark joins it to the definition as it joins
    # "    - e" to "d" in "- a / - b / - c / - d / - e".
    line = mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
                  f"{outer}\n{indent}- **OBSERVED**: {OBSERVED}\n"
                  "    - (NemoClaw findings, exposure sweeps, npm attacks)\n")
    r = run_checker(tree)
    assert r.returncode == 1
    assert (f"EVIDENCE_AUDIT.md:{line + 1}: Observed continues on line {line + 2};"
            in r.stderr), r.stderr
    assert "Observed reads" not in r.stderr, r.stderr


def test_a_bullet_three_columns_past_the_text_around_it_ends_the_definition(tree):
    # Indented three columns, the same bullet starts the outer list's next item.
    mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
           f"-    Tiers:\n\t - **OBSERVED**: {OBSERVED}\n"
           "   - (NemoClaw findings, exposure sweeps, npm attacks)\n")
    r = run_checker(tree)
    assert r.returncode == 0, r.stderr


def test_a_no_break_space_before_a_bullet_makes_the_line_plain_text(tree):
    # Indentation is spaces and tabs only, so the line under the nested definition starts
    # with a no-break space and is joined to the definition; read as one column of
    # indentation, it would pass as the outer list's next item.
    line = mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
                  f"- Tiers:\n  - **OBSERVED**: {OBSERVED}\n"
                  "\N{NO-BREAK SPACE}- NemoClaw findings\n")
    r = run_checker(tree)
    assert r.returncode == 1
    assert (f"EVIDENCE_AUDIT.md:{line + 1}: Observed continues on line {line + 2};"
            in r.stderr), r.stderr


@pytest.mark.parametrize("space", ["\N{NO-BREAK SPACE}", "\N{EM SPACE}",
                                   "\N{IDEOGRAPHIC SPACE}"],
                         ids=["no-break space", "em space", "ideographic space"])
def test_white_space_other_than_spaces_and_tabs_after_the_marker_is_the_items_text(
        tree, space):
    # CommonMark counts spaces and tabs only after the marker, so the item's text starts at
    # the other white space character, two columns in, and the paragraph indented two
    # columns after the blank line belongs to the item.
    line = mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
                  f"- {space}**OBSERVED**: {OBSERVED}\n\n"
                  "  (NemoClaw findings, exposure sweeps, npm attacks)\n")
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"EVIDENCE_AUDIT.md:{line}: Observed continues on line {line + 2};" in r.stderr, \
        r.stderr
    assert "Observed reads" not in r.stderr, r.stderr


@pytest.mark.parametrize("old, new", [
    # Under "- see below", a marker followed by a no-break space is more of that item's
    # paragraph: "see below - OBSERVED: ..." in one list item.
    (f"- **OBSERVED**: {OBSERVED}\n",
     f"- see below\n-\N{NO-BREAK SPACE}**OBSERVED**: {OBSERVED}\n"),
    # Indented four columns directly under a paragraph, the two lines are more of it.
    (f"and quoted here:\n\n- **OBSERVED**: {OBSERVED}\n",
     f"and quoted here:\n    - **OBSERVED**: {OBSERVED}\n"
     "    - (NemoClaw findings, exposure sweeps, npm attacks)\n"),
    # Indented four columns after a blank line, the line is indented code.
    (f"- **OBSERVED**: {OBSERVED}\n", f"    - **OBSERVED**: {OBSERVED}\n"),
    # A no-break space is not indentation, so the line is a paragraph that starts with one.
    (f"- **OBSERVED**: {OBSERVED}\n", f"\N{NO-BREAK SPACE}- **OBSERVED**: {OBSERVED}\n"),
    # A blank line ends a list item that holds nothing, so the line is four columns from
    # the margin and is indented code.
    (f"- **OBSERVED**: {OBSERVED}\n", f"-\n\n    - **OBSERVED**: {OBSERVED}\n"),
    # A numbered item that does not start at 1, and a bullet with no text, cannot start on
    # the next line of a paragraph: each is more of "see", and so is the line indented four
    # columns past it.
    (f"- **OBSERVED**: {OBSERVED}\n", f"- see\n  2. below\n      - **OBSERVED**: {OBSERVED}\n"),
    (f"- **OBSERVED**: {OBSERVED}\n", f"- see\n  *\n      - **OBSERVED**: {OBSERVED}\n"),
    # A heading, written with an underline or with "#", is not a paragraph, so the line of
    # plain text after it ends the list item, and the line indented four columns is more of
    # that text.
    (f"- **OBSERVED**: {OBSERVED}\n", f"- see\n  ===\nbelow\n    - **OBSERVED**: {OBSERVED}\n"),
    (f"- **OBSERVED**: {OBSERVED}\n",
     f"- see\n  # below\nand below\n    - **OBSERVED**: {OBSERVED}\n"),
    # A block quote at the margin ends the list item, and the line indented four columns is
    # more of the quoted paragraph.
    (f"- **OBSERVED**: {OBSERVED}\n", f"- see\n> below\n    - **OBSERVED**: {OBSERVED}\n"),
], ids=["no-break space after the marker", "four columns under a paragraph", "indented code",
        "no-break space before the marker", "after an empty item and a blank line",
        "under a numbered item that cannot start", "under an empty bullet that cannot start",
        "after a heading underline and text", "after a heading and text",
        "after a block quote"])
def test_a_line_commonmark_does_not_read_as_a_list_item_is_not_a_definition(tree, old, new):
    mutate(tree, "EVIDENCE_AUDIT.md", old, new)
    r = run_checker(tree)
    assert r.returncode == 1
    assert "EVIDENCE_AUDIT.md does not define Observed" in r.stderr, r.stderr
    assert "Observed reads" not in r.stderr and "Observed continues" not in r.stderr, r.stderr


@pytest.mark.parametrize("new", [
    # A line of plain text continues the paragraph of "examples" and leaves both list items
    # open, so the definition indented four columns is a list item nested under it.
    f"- Tiers:\n  - examples\nand more\n    - **OBSERVED**: {OBSERVED}\n",
    # A numbered item that does not start at 1 does start a list after a block quote or a
    # list item it is outside of, and the definition is nested in it.
    f"> see\n2. below\n     - **OBSERVED**: {OBSERVED}\n",
    f"- intro\n2. see\n      - **OBSERVED**: {OBSERVED}\n",
], ids=["under a paragraph continued at the margin", "under a numbered item after a block quote",
        "under a numbered item after a list item"])
def test_a_definition_nested_in_a_list_item_commonmark_keeps_open_is_read(tree, new):
    mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n", new)
    r = run_checker(tree)
    assert r.returncode == 0, r.stderr


def test_a_wrapped_definition_is_reported_although_its_lines_join_to_the_quote(tree):
    wrapped = ("- **ADAPTED**: Well-understood traditional technique applied to agent "
               "context,\n  not yet observed agent-specifically\n")
    joined = " ".join(part.strip() for part in wrapped.split("\n")[:2])
    assert joined == f"- **ADAPTED**: {ADAPTED}"
    line = mutate(tree, "EVIDENCE_AUDIT.md", f"- **ADAPTED**: {ADAPTED}\n", wrapped)
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"EVIDENCE_AUDIT.md:{line}: Adapted continues on line {line + 1};" in r.stderr, \
        r.stderr


@pytest.mark.parametrize("after, skipped", [
    # A paragraph indented as far as the definition's label, after a blank line, is a second
    # paragraph of the same list item.
    ("\n  (NemoClaw findings, exposure sweeps, npm attacks)\n", 1),
    # Any number of blank lines, holding spaces and tabs, may stand before it.
    ("\n \t\n\n  (NemoClaw findings, exposure sweeps, npm attacks)\n", 3),
    ("\n\t(NemoClaw findings, exposure sweeps, npm attacks)\n", 1),
    # A nested list or a fence indented as far as the label belongs to the item too.
    ("\n  - NemoClaw findings\n", 1),
    ("\n  ```\n  NemoClaw findings\n  ```\n", 1),
], ids=["indented paragraph", "after several blank lines", "tab-indented paragraph",
        "nested list", "fence"])
def test_a_definition_followed_by_a_blank_line_and_more_of_its_item_is_reported(
        tree, after, skipped):
    line = mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
                  f"- **OBSERVED**: {OBSERVED}\n{after}")
    r = run_checker(tree)
    assert r.returncode == 1
    assert (f"EVIDENCE_AUDIT.md:{line}: Observed continues on line {line + skipped + 1};"
            in r.stderr), r.stderr
    assert "Observed reads" not in r.stderr, r.stderr


@pytest.mark.parametrize("item, after", [
    # Indented less than the label, the paragraph after the blank line is outside the item.
    ("- ", "\n(NemoClaw findings, exposure sweeps, npm attacks)\n"),
    ("- ", "\n (NemoClaw findings, exposure sweeps, npm attacks)\n"),
    ("- ", " \t\n(NemoClaw findings, exposure sweeps, npm attacks)\n"),
    # The label starts after the spaces that follow the marker.
    ("-   ", "\n  (NemoClaw findings, exposure sweeps, npm attacks)\n"),
    ("-\t", "\n   (NemoClaw findings, exposure sweeps, npm attacks)\n"),
    # Four spaces after the marker still place the label, at column five.
    ("-    ", "\n  (NemoClaw findings, exposure sweeps, npm attacks)\n"),
    # A space and a tab reach column four, one short of that label.
    ("-    ", "\n \t(NemoClaw findings, exposure sweeps, npm attacks)\n"),
    # Five spaces after the marker put the item's text one column after the marker, not
    # directly after it.
    ("-     ", "\n (NemoClaw findings, exposure sweeps, npm attacks)\n"),
    # A no-break space is not indentation: the paragraph is indented one column.
    ("- ", "\n \N{NO-BREAK SPACE}(NemoClaw findings, exposure sweeps, npm attacks)\n"),
], ids=["unindented paragraph", "paragraph indented one column", "blank line of white space",
        "three spaces after the marker", "tab after the marker",
        "four spaces after the marker", "space and tab before the paragraph",
        "five spaces after the marker", "no-break space in the indentation"])
def test_a_definition_followed_by_a_blank_line_and_text_outside_its_item_ends_on_its_line(
        tree, item, after):
    mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
           f"{item}**OBSERVED**: {OBSERVED}\n{after}")
    r = run_checker(tree)
    assert r.returncode == 0, r.stderr


def test_five_spaces_after_the_marker_put_the_items_text_one_column_after_it(tree):
    # With five or more columns between the marker and the label, CommonMark starts the
    # item's text one column after the marker, so a paragraph indented two columns after a
    # blank line belongs to the item.
    line = mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
                  f"-     **OBSERVED**: {OBSERVED}\n\n  (NemoClaw findings)\n")
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"EVIDENCE_AUDIT.md:{line}: Observed continues on line {line + 2};" in r.stderr, \
        r.stderr


@pytest.mark.parametrize("old, new, continued", [
    # A tab reaches column four, as far as the text of an item indented two columns: the
    # bullet starts a list nested under the definition.
    (f"- **OBSERVED**: {OBSERVED}\n",
     f"  - **OBSERVED**: {OBSERVED}\n\t- NemoClaw findings\n", 1),
    # Under an item indented with a tab, a bullet indented two columns is indented no
    # further, and ends the definition.
    (f"- **OBSERVED**: {OBSERVED}\n- **VALIDATED**: {VALIDATED}\n",
     f"- Tiers:\n\t- **OBSERVED**: {OBSERVED}\n  - **VALIDATED**: {VALIDATED}\n", None),
    # A tab after the marker, which sits in column zero, reaches column four and not five:
    # a paragraph indented four columns after a blank line belongs to the item.
    (f"- **OBSERVED**: {OBSERVED}\n",
     f"-\t**OBSERVED**: {OBSERVED}\n\n    (NemoClaw findings)\n", 2),
], ids=["tab-indented bullet under a space-indented item",
        "space-indented bullet under a tab-indented item",
        "tab after the marker"])
def test_a_tab_counts_to_the_next_stop_of_four_columns(tree, old, new, continued):
    line = mutate(tree, "EVIDENCE_AUDIT.md", old, new)
    r = run_checker(tree)
    if continued:
        assert r.returncode == 1
        assert (f"EVIDENCE_AUDIT.md:{line}: Observed continues on line {line + continued};"
                in r.stderr), r.stderr
    else:
        assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("separator", ["\N{LINE SEPARATOR}", "\x85", "\f"],
                         ids=["line separator", "next line", "form feed"])
def test_a_character_that_does_not_end_a_markdown_line_leaves_the_text_after_it_read(
        tree, separator):
    # CommonMark ends a line at a line feed or carriage return only, so a bullet after one of
    # these characters is part of the definition's line, not the next list item.
    line = mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
                  f"- **OBSERVED**: {OBSERVED}{separator}- NemoClaw findings\n")
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"EVIDENCE_AUDIT.md:{line}: Observed reads" in r.stderr, r.stderr
    # The lines after it keep their numbers.
    validated = mutate(tree, "EVIDENCE_AUDIT.md", f"- **VALIDATED**: {VALIDATED}\n",
                       "- **VALIDATED**: Reproduced\n")
    assert validated == line + 1
    r = run_checker(tree)
    assert f"EVIDENCE_AUDIT.md:{validated}: Validated reads" in r.stderr, r.stderr


@pytest.mark.parametrize("character, escaped", [
    ("\N{LINE SEPARATOR}", "\\u2028"),
    ("\x85", "\\x85"),
    ("\f", "\\x0c"),
    ("\N{NO-BREAK SPACE}", "\\xa0"),
    ("\N{ZERO WIDTH SPACE}", "\\u200b"),
], ids=["line separator", "next line", "form feed", "no-break space", "zero width space"])
def test_a_character_that_does_not_print_is_escaped_in_the_message(tree, character, escaped):
    # Printed as it is, the character between the definition and the text after it does not
    # show in a terminal, and the message would not say what to delete.
    line = mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
                  f"- **OBSERVED**: {OBSERVED}{character}- NemoClaw findings\n")
    r = run_checker(tree)
    assert r.returncode == 1
    assert (f"EVIDENCE_AUDIT.md:{line}: Observed reads \"{OBSERVED}{escaped}- NemoClaw "
            f"findings\";") in r.stderr, r.stderr
    assert character not in r.stderr, r.stderr


@pytest.mark.parametrize("after", [
    # Two markers are a list item that holds an empty one, where three are a thematic break.
    "- -\n",
    # The item's text may be the opening line of a code fence.
    "- ```\n  NemoClaw findings\n  ```\n",
], ids=["two markers", "fence opened on the marker's line"])
def test_a_bulleted_item_that_holds_another_block_ends_the_definition(tree, after):
    mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
           f"- **OBSERVED**: {OBSERVED}\n{after}")
    r = run_checker(tree)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("new", [
    f"- - **OBSERVED**: {OBSERVED}\n",
    f"1. - **OBSERVED**: {OBSERVED}\n",
    f"> - **OBSERVED**: {OBSERVED}\n",
], ids=["after another bullet", "after a numbered marker", "inside a block quote"])
def test_a_definition_after_another_marker_on_its_line_is_not_read(tree, new):
    # Only a line that starts with the bullet of the definition's own list item is read.
    mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n", new)
    r = run_checker(tree)
    assert r.returncode == 1
    assert "EVIDENCE_AUDIT.md does not define Observed" in r.stderr, r.stderr
    assert "Observed reads" not in r.stderr and "Observed continues" not in r.stderr, r.stderr


def test_a_definition_followed_by_a_bulleted_item_indented_no_further_ends_on_its_line(tree):
    # The tier list nested under an outer item, the outer list's next item after it.
    old = (f"- **OBSERVED**: {OBSERVED}\n- **VALIDATED**: {VALIDATED}\n"
           f"- **ADAPTED**: {ADAPTED}\n")
    mutate(tree, "EVIDENCE_AUDIT.md", old,
           f"- Tiers:\n  - **OBSERVED**: {OBSERVED}\n  * **VALIDATED**: {VALIDATED}\n"
           f"  + **ADAPTED**: {ADAPTED}\n- The next item\n")
    r = run_checker(tree)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("rel, row", [
    ("README.md", f"| **Validated** | {VALIDATED} |"),
    ("CONTRIBUTING.md", f"| **Adapted** | {ADAPTED} |"),
    ("EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n"),
])
def test_a_page_that_leaves_a_tier_out_is_reported(tree, rel, row):
    path = tree / rel
    text = path.read_text(encoding="utf-8")
    start = text.index(row)
    end = text.index("\n", start) + 1
    path.write_text(text[:start] + text[end:], encoding="utf-8")
    r = run_checker(tree)
    assert r.returncode == 1
    tier = {"README.md": "Validated", "CONTRIBUTING.md": "Adapted",
            "EVIDENCE_AUDIT.md": "Observed"}[rel]
    assert f"{rel} does not define {tier}" in r.stderr, r.stderr


def test_a_canonical_edit_the_quotes_do_not_follow_is_reported_on_every_page(tree):
    mutate(tree, "docs/evidence-tiers.md", f"| `observed` | {OBSERVED} |",
           f"| `observed` | {OBSERVED} and incident reports |")
    r = run_checker(tree)
    assert r.returncode == 1
    for rel in ("README.md", "CONTRIBUTING.md", "EVIDENCE_AUDIT.md"):
        assert f"{rel}:" in r.stderr and "Observed reads" in r.stderr, r.stderr
    assert r.stderr.count("Observed reads") == 3, r.stderr


def test_a_canonical_edit_every_page_follows_is_green(tree):
    new = f"{OBSERVED} and incident reports"
    mutate(tree, "docs/evidence-tiers.md", f"| `observed` | {OBSERVED} |",
           f"| `observed` | {new} |")
    mutate(tree, "README.md", f"| **Observed** | {OBSERVED} |", f"| **Observed** | {new} |")
    mutate(tree, "CONTRIBUTING.md", f"| **Observed** | {OBSERVED} |",
           f"| **Observed** | {new} |")
    mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
           f"- **OBSERVED**: {new}\n")
    r = run_checker(tree)
    assert r.returncode == 0, r.stderr


def test_a_canonical_tier_defined_twice_is_reported(tree):
    row = f"| Adapted | `adapted` | {ADAPTED} |\n"
    line = mutate(tree, "docs/evidence-tiers.md", row, row + row) + 1
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"docs/evidence-tiers.md:{line}: defines `adapted` a second time" in r.stderr


def test_canonical_lines_that_do_not_complete_a_row_are_read_in_linear_time(tree):
    # Each line starts with "|" and a long run of white space and does not complete a row.
    # Matched with one pattern for the whole row, "|", 2,000 spaces and "x" took about 3 s on
    # Python 3.14, and the same after the Observed name and value about 13 s, eight times as
    # long at each doubling of the run.
    run = " " * 128_000
    path = tree / "docs" / "evidence-tiers.md"
    path.write_text(path.read_text(encoding="utf-8")
                    + f"\n|{run}x\n\n| Observed | `observed` |{run}x\n", encoding="utf-8")
    start = time.perf_counter()
    r = run_checker(tree)
    seconds = time.perf_counter() - start
    assert r.returncode == 0, r.stderr
    assert seconds < 3, f"{seconds:.2f} s"


@pytest.mark.parametrize("rel, form, tier", [
    ("README.md", "| **{}** | x{}y |", "Observed"),
    ("EVIDENCE_AUDIT.md", "- **{}**: x{}y", "OBSERVED"),
], ids=["table row", "list item"])
def test_quoting_page_lines_with_a_long_run_of_white_space_are_read_in_linear_time(
        tree, rel, form, tier):
    # Each line starts a bold-labelled table row or list item and holds a long run of white
    # space before more text; the label need not be a tier. Matched with white space on both
    # sides of a lazy definition, the table row with 40,000 spaces took over 7 s on Python 3.14
    # and the list item over 4 s, about four times as long at each doubling of the run. The
    # tier's line is still read, stripped of the white space around it, and reported at its line.
    run = " " * 128_000
    path = tree / rel
    head = path.read_text(encoding="utf-8") + "\n" + form.format("Note", run) + "\n\n"
    line = head.count("\n") + 1
    path.write_text(head + form.format(tier, run) + "\n", encoding="utf-8")
    start = time.perf_counter()
    r = run_checker(tree)
    seconds = time.perf_counter() - start
    assert r.returncode == 1
    assert r.stderr.count(" reads \"") == 1
    assert f"{rel}:{line}: Observed reads \"x{run}y\";" in r.stderr
    assert seconds < 3, f"{seconds:.2f} s"


def test_a_line_of_many_list_markers_is_read_in_linear_time(tree):
    # Every "- " on the first line opens a list item inside the one before it, and the lines
    # of plain text after it continue the innermost item's paragraph. Reading the rest of the
    # line again at each marker, or every open item again at each line, takes time that
    # grows with the square of the count.
    path = tree / "EVIDENCE_AUDIT.md"
    path.write_text(path.read_text(encoding="utf-8")
                    + "\n" + "- " * 64_000 + "x\n" + "y\n" * 64_000, encoding="utf-8")
    start = time.perf_counter()
    r = run_checker(tree)
    seconds = time.perf_counter() - start
    assert r.returncode == 0, r.stderr
    assert seconds < 3, f"{seconds:.2f} s"


def test_a_schema_tier_the_canonical_page_does_not_define_is_reported(tree):
    path = tree / "schema" / "threat-matrix-v1.2.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    schema["$defs"]["technique"]["properties"]["evidenceTier"]["enum"].append("theoretical")
    path.write_text(json.dumps(schema), encoding="utf-8")
    r = run_checker(tree)
    assert r.returncode == 1
    assert "docs/evidence-tiers.md does not define the `theoretical` tier" in r.stderr


@pytest.mark.parametrize("fenced", [
    "```markdown\n| **Observed** | Anything at all |\n```\n",
    # A line of backticks indented four columns, a run of the other fence character and a
    # shorter run do not close the fence.
    "```\n    ```\n- **OBSERVED**: Anything at all\n```\n",
    "~~~\n```\n- **OBSERVED**: Anything at all\n~~~\n",
    "````\n```\n- **OBSERVED**: Anything at all\n````\n",
], ids=["table row", "after backticks indented four columns", "after backticks in a tilde fence",
        "after a shorter run of backticks"])
def test_a_definition_inside_a_code_fence_is_not_a_quote(tree, fenced):
    path = tree / "CONTRIBUTING.md"
    path.write_text(path.read_text(encoding="utf-8") + "\n" + fenced, encoding="utf-8")
    r = run_checker(tree)
    assert r.returncode == 0, r.stderr


def test_a_definition_inside_a_code_fence_in_a_nested_list_item_is_not_a_quote(tree):
    # The fence is indented four columns from the margin and none from the text of the
    # list item it is in, so it is a fence, not indented code or text.
    path = tree / "CONTRIBUTING.md"
    path.write_text(path.read_text(encoding="utf-8")
                    + "\n- An example:\n  - as a list item:\n\n    ```markdown\n"
                      "    - **OBSERVED**: Anything at all\n    ```\n",
                    encoding="utf-8")
    r = run_checker(tree)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("before", [
    # A fence opened inside a list item is closed by the end of that item: the next bullet
    # at the margin starts the list's next item.
    "- Note:\n  ```\n",
    # A line of backticks followed by text does not close a fence. The line after it does,
    # where a check that took the first for the closing line read a new fence opening.
    "\n```\ncode\n``` text\n```\n",
    # A backtick fence takes no backtick in its info string, so this line is a paragraph.
    "\n``` a`b\n",
], ids=["fence inside a list item that ends", "closing line followed by text",
        "backtick in the info string"])
def test_text_after_a_line_commonmark_does_not_read_as_a_code_fence_is_read(tree, before):
    second = "Documented in a security incident report"
    line = mutate(tree, "EVIDENCE_AUDIT.md", f"- **ADAPTED**: {ADAPTED}\n",
                  f"- **ADAPTED**: {ADAPTED}\n{before}- **OBSERVED**: {second}\n")
    line += 1 + before.count("\n")
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"EVIDENCE_AUDIT.md:{line}: Observed reads \"{second}\";" in r.stderr, r.stderr


def test_the_pages_that_describe_the_check_say_where_an_items_text_starts():
    # The blank-line rule compares a line's indentation with the start of the item's text,
    # which is not the label's column when five or more columns follow the marker.
    script = (ROOT / "scripts" / "check_evidence_tiers.py").read_text(encoding="utf-8")
    described = {
        "README.md": (ROOT / "README.md").read_text(encoding="utf-8"),
        "CONTRIBUTING.md": (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8"),
        "docs/evidence-tiers.md": (ROOT / "docs" / "evidence-tiers.md").read_text(
            encoding="utf-8"),
        "scripts/check_evidence_tiers.py": script.split('"""')[1],
    }
    for rel, text in described.items():
        assert "one column after the marker" in " ".join(text.split()), rel
