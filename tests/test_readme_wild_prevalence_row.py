"""The README's wildPrevalence, wildSampleCount row states the basis its schema gives.

The field table's row for the two fields carries three sentences of their descriptions in
schema/threat-matrix-v1.2.schema.json: the wildPrevalence sentence that contains "callbacks
per page visit", its sentence that contains "not a production attack rate", and the
wildSampleCount sentence that contains "the callbacks plus the page visits".
scripts/check_readme_claims.py reads the three from the schema and fails, naming the README
line, when the row's description cell does not hold each exactly as the schema states it and
as a whole sentence of the cell, so after an edit to one of them in the schema the check
fails until the row holds the edited sentence as one of its own. That includes an edit that
leaves the edited sentence inside the row's copy of the old one.

Each case runs the checker from a scratch copy of the files it reads, so the committed files
are never written, and takes the three sentences from the checker's own read of the schema,
so no case types them. The shipped tree is green. A row that holds none of the three
sentences, one character changed in each copied sentence, the honeypot sentence changed in
the schema alone, words removed in the schema alone from the start of each sentence (its
first word, or every word before the words that pick it out) or from the end of the
wildSampleCount sentence with its period and the rest of its description, words added in the
row before each copied sentence, a row the checker does not read, words that pick out no
sentence of their description or two, a description that is not there, a schema that is
missing or does not parse, and a second row on a README page that leaves a sentence out must
each go red. A "|" in a copied sentence is written "\\|" in the cell, as a table cell needs,
and passes; written bare, it ends the cell and fails.
"""

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "schema/threat-matrix-v1.2.schema.json"


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "check_readme_claims", ROOT / "scripts" / "check_readme_claims.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()
# The files the checker reads, copied into each scratch tree.
FILES = ("matrix.json", "related-projects.json", "CHANGELOG.md",
         "stix/agent-threat-matrix-bundle.json", SCHEMA, "scripts/check_readme_claims.py",
         *CHECKER.PAGES)
# The three sentences as the shipped schema states them, picked by the checker's own read,
# and the words that pick out each, in the order the row states them.
PICKED, REASONS = CHECKER.schema_sentences()
WORDS = [words for _, words in CHECKER.WILD_SENTENCES]
ROW_FAILURE = "the wildPrevalence, wildSampleCount row does not hold"


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    for rel in FILES:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    return tmp_path


def run_checker(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(root / "scripts" / "check_readme_claims.py")],
                          capture_output=True, text=True, timeout=120)


def failures(proc: subprocess.CompletedProcess) -> list:
    """The failure lines the checker printed, without their "  - " lead."""
    return [line[4:] for line in proc.stderr.splitlines() if line.startswith("  - ")]


def row(root: Path):
    """(line number, text) of the one README.md line the checker reads as the row."""
    lines = (root / "README.md").read_text(encoding="utf-8").split("\n")
    found = [(n, line) for n, line in enumerate(lines, 1) if line.startswith(CHECKER.WILD_ROW)]
    assert len(found) == 1, f"README.md holds {len(found)} lines starting {CHECKER.WILD_ROW!r}"
    return found[0]


def edit_row(root: Path, old: str, new: str) -> int:
    """Replace `old`, which the README.md row holds once, with `new` on that row only, and
    return the row's line number."""
    path = root / "README.md"
    lines = path.read_text(encoding="utf-8").split("\n")
    number, line = row(root)
    assert line.count(old) == 1, f"the row holds {old!r} {line.count(old)} times"
    lines[number - 1] = line.replace(old, new)
    path.write_text("\n".join(lines), encoding="utf-8")
    return number


def edit_schema(root: Path, old: str, new: str) -> None:
    """Replace `old`, which the scratch copy of the schema holds once, with `new`."""
    path = root / SCHEMA
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"the schema holds {old!r} {text.count(old)} times"
    path.write_text(text.replace(old, new), encoding="utf-8")


def description(root: Path, field: str) -> str:
    """The `field` description in the scratch copy of the schema."""
    schema = json.loads((root / SCHEMA).read_text(encoding="utf-8"))
    return schema["$defs"]["technique"]["properties"][field]["description"]


def one_character_changed(sentence: str, keep: str) -> str:
    """`sentence` with the letter nearest its middle that is not inside `keep` replaced by
    another letter, so the words `keep` still pick the sentence out."""
    start = sentence.index(keep)
    middle = len(sentence) // 2
    pos = min((i for i, c in enumerate(sentence)
               if c.isalpha() and not start <= i < start + len(keep)),
              key=lambda i: abs(i - middle))
    return sentence[:pos] + ("x" if sentence[pos] != "x" else "y") + sentence[pos + 1:]


def row_failure(number: int, index: int, sentence: str) -> str:
    """The failure line for README.md line `number` whose row does not hold `sentence`, the
    sentence the entry `index` of WILD_SENTENCES picks out of the schema, as a whole sentence."""
    field, words = CHECKER.WILD_SENTENCES[index]
    return (f"README.md:{number}: {ROW_FAILURE}, as a whole sentence and as {SCHEMA} states "
            f"it, the {field} sentence containing \"{words}\": \"{sentence}\"")


# Two ways to remove words from the start of a sentence, each keeping the words that pick it
# out: removing its first word, and removing every word before those words.
START_CUTS = {
    "first word": lambda sentence, words: sentence[sentence.index(" ") + 1:],
    "every word before its words": lambda sentence, words: sentence[sentence.index(words):],
}


def test_the_words_pick_out_one_sentence_of_each_shipped_description():
    assert REASONS == []
    assert len(PICKED) == len(CHECKER.WILD_SENTENCES) == 3
    for words, sentence in zip(WORDS, PICKED):
        assert words in sentence
        assert sentence.endswith(".")


@pytest.mark.parametrize("description, expected", [
    ("One. Two words. Three.", ["One.", "Two words.", "Three."]),
    ("A last piece keeps what it has. Last", ["A last piece keeps what it has.", "Last"]),
    ("A rate of 0.5 per visit. Next.", ["A rate of 0.5 per visit.", "Next."]),
    ("One sentence.", ["One sentence."]),
])
def test_a_description_is_split_on_a_period_and_a_space_keeping_the_period(description,
                                                                            expected):
    assert CHECKER.sentences(description) == expected


def test_the_shipped_row_holds_each_schema_sentence_and_the_tree_is_green(tree):
    _, line = row(tree)
    for sentence in PICKED:
        assert sentence in line
    proc = run_checker(tree)
    assert proc.returncode == 0, proc.stderr
    assert "README claims match matrix.json" in proc.stdout


def test_a_row_without_the_schema_sentences_is_red_on_its_line(tree):
    for sentence in PICKED:
        number = edit_row(tree, sentence, "")
    proc = run_checker(tree)
    assert proc.returncode == 1, proc.stdout
    lines = failures(proc)
    assert len(lines) == 3, proc.stderr
    for words, line in zip(WORDS, lines):
        assert line.startswith(f"README.md:{number}: {ROW_FAILURE}"), line
        assert f'"{words}"' in line


@pytest.mark.parametrize("index", range(3), ids=WORDS)
def test_one_character_changed_in_a_copied_sentence_is_red_on_the_row(tree, index):
    sentence = PICKED[index]
    number = edit_row(tree, sentence, one_character_changed(sentence, WORDS[index]))
    proc = run_checker(tree)
    assert proc.returncode == 1, proc.stdout
    lines = failures(proc)
    assert len(lines) == 1, proc.stderr
    assert lines[0].startswith(f"README.md:{number}: {ROW_FAILURE}"), lines[0]
    assert f'"{WORDS[index]}"' in lines[0]
    assert f'"{sentence}"' in lines[0]


def test_the_honeypot_sentence_changed_in_the_schema_alone_is_red_on_the_row(tree):
    sentence = PICKED[1]
    changed = one_character_changed(sentence, WORDS[1])
    edit_schema(tree, sentence, changed)
    number, _ = row(tree)
    proc = run_checker(tree)
    assert proc.returncode == 1, proc.stdout
    lines = failures(proc)
    assert len(lines) == 1, proc.stderr
    assert lines[0].startswith(f"README.md:{number}: {ROW_FAILURE}"), lines[0]
    assert f'"{WORDS[1]}"' in lines[0]
    assert f'"{changed}"' in lines[0]


@pytest.mark.parametrize("cut", START_CUTS)
@pytest.mark.parametrize("index", range(3), ids=WORDS)
def test_words_removed_from_the_start_of_a_sentence_in_the_schema_alone_are_red_on_the_row(
        tree, index, cut):
    # The shortened sentence stands inside the row's copy of the old one, so the row still
    # contains it, but not as a sentence of its own.
    sentence, words = PICKED[index], WORDS[index]
    shortened = START_CUTS[cut](sentence, words)
    assert words in shortened and shortened != sentence and sentence.endswith(shortened)
    edit_schema(tree, sentence, shortened)
    number, line = row(tree)
    assert shortened in line
    proc = run_checker(tree)
    assert proc.returncode == 1, proc.stdout
    assert failures(proc) == [row_failure(number, index, shortened)]


def test_words_removed_from_the_end_of_the_last_sentence_in_the_schema_alone_are_red(tree):
    # The wildSampleCount sentence cut directly after the words that pick it out, with its
    # period and the rest of its description, so it ends the description with no period and
    # stands inside the row's copy of the old one.
    field, words = CHECKER.WILD_SENTENCES[2]
    sentence = PICKED[2]
    text = description(tree, field)
    rest = text[text.index(sentence):]
    shortened = sentence[:sentence.index(words) + len(words)]
    assert shortened != sentence and sentence.startswith(shortened)
    edit_schema(tree, rest + "\"", shortened + "\"")
    assert CHECKER.sentences(description(tree, field))[-1] == shortened
    number, line = row(tree)
    assert shortened in line
    proc = run_checker(tree)
    assert proc.returncode == 1, proc.stdout
    assert failures(proc) == [row_failure(number, 2, shortened)]


@pytest.mark.parametrize("index", range(3), ids=WORDS)
def test_words_added_before_a_copied_sentence_in_the_row_are_red_on_the_row(tree, index):
    # The row's sentence holds the schema's, but starts with words the schema's does not.
    sentence = PICKED[index]
    number = edit_row(tree, sentence, "Note: " + sentence)
    proc = run_checker(tree)
    assert proc.returncode == 1, proc.stdout
    assert failures(proc) == [row_failure(number, index, sentence)]


def test_a_row_the_checker_does_not_read_is_red(tree):
    edit_row(tree, CHECKER.WILD_ROW, "| `wildPrevalence` and `wildSampleCount` |")
    proc = run_checker(tree)
    assert proc.returncode == 1, proc.stdout
    assert failures(proc) == [
        "README field table has no row for wildPrevalence, wildSampleCount "
        f"(a line starting \"{CHECKER.WILD_ROW}\")"
    ]


@pytest.mark.parametrize("old, new, expected", [
    ("the callbacks plus the page visits", "the callbacks and the page visits",
     f"{SCHEMA}: the wildSampleCount description holds 0 sentences containing "
     "\"the callbacks plus the page visits\", where the README's row copies exactly one"),
    ("It measures engagement with a honeypot",
     "It counts callbacks per page visit. It measures engagement with a honeypot",
     f"{SCHEMA}: the wildPrevalence description holds 2 sentences containing "
     "\"callbacks per page visit\", where the README's row copies exactly one"),
    ("\"description\": \"The wildSampleCount the same endpoint",
     "\"title\": \"The wildSampleCount the same endpoint",
     f"{SCHEMA}: no description string at "
     "$defs.technique.properties.wildSampleCount.description, which the README's "
     "wildSampleCount sentence is copied from"),
], ids=["no sentence", "two sentences", "no description"])
def test_a_schema_the_sentences_cannot_be_picked_from_is_red_naming_why(tree, old, new,
                                                                        expected):
    edit_schema(tree, old, new)
    proc = run_checker(tree)
    assert proc.returncode == 1, proc.stdout
    assert failures(proc) == [expected]


def test_a_missing_schema_is_red_in_one_line(tree):
    (tree / SCHEMA).unlink()
    proc = run_checker(tree)
    assert proc.returncode == 1, proc.stdout
    assert failures(proc) == [f"{SCHEMA} is missing or does not parse: no such file"]
    assert "Traceback" not in proc.stderr


def test_a_schema_that_does_not_parse_is_red_in_one_line(tree):
    (tree / SCHEMA).write_text("{", encoding="utf-8")
    proc = run_checker(tree)
    assert proc.returncode == 1, proc.stdout
    lines = failures(proc)
    assert len(lines) == 1, proc.stderr
    assert lines[0].startswith(f"{SCHEMA} is missing or does not parse: ")
    assert "Traceback" not in proc.stderr


def test_a_second_row_on_a_readme_page_is_checked_too(tree):
    page = tree / "docs" / "schema.md"
    text = page.read_text(encoding="utf-8")
    text = text if text.endswith("\n") else text + "\n"
    page.write_text(text + f"{CHECKER.WILD_ROW} {PICKED[0]} {PICKED[2]} |\n", encoding="utf-8")
    number = text.count("\n") + 1
    proc = run_checker(tree)
    assert proc.returncode == 1, proc.stdout
    lines = failures(proc)
    assert len(lines) == 1, proc.stderr
    assert lines[0].startswith(f"docs/schema.md:{number}: {ROW_FAILURE}"), lines[0]
    assert f'"{WORDS[1]}"' in lines[0]


def test_a_pipe_in_a_copied_sentence_is_written_escaped_in_the_cell(tree):
    sentence = PICKED[1]
    piped = sentence.replace(", not", " | not")
    assert piped != sentence
    edit_schema(tree, sentence, piped)
    edit_row(tree, sentence, piped.replace("|", "\\|"))
    proc = run_checker(tree)
    assert proc.returncode == 0, proc.stderr


def test_a_bare_pipe_in_a_copied_sentence_ends_the_cell_and_is_red(tree):
    sentence = PICKED[1]
    piped = sentence.replace(", not", " | not")
    edit_schema(tree, sentence, piped)
    number = edit_row(tree, sentence, piped)
    proc = run_checker(tree)
    assert proc.returncode == 1, proc.stdout
    lines = [line for line in failures(proc) if f'"{WORDS[1]}"' in line]
    assert len(lines) == 1, proc.stderr
    assert lines[0].startswith(f"README.md:{number}: {ROW_FAILURE}"), lines[0]
