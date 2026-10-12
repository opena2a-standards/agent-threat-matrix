"""A test module docstring that points at a JUnit report names the command that writes one.

Three acceptance test modules said each criterion can be traced to a passing testcase in
"the JUnit output", and nothing in the repository produces or describes such a report: no
workflow runs pytest. The sentence now names the command, `pytest --junitxml`. The last
test here runs that command on the modules that state a criterion id and reads the report,
so the sentence holds as written. The Unreleased section of CHANGELOG.md records the change
in an entry that names this file, the command and each module whose docstring mentions a
JUnit report; it had no such entry.

The report names a testcase after the test function followed by the parametrize id in
brackets, so it is the parametrize id that leads with the criterion id, not the testcase
name. Those modules said "Leaf test names begin with the criterion id" and now say "Every
parametrize id below begins with the criterion id", and the message of the last test spoke
of "testcase names that do not lead with" the id and now speaks of "testcase names whose
parametrize id does not lead with" it. The Unreleased section records that change of
wording in a second entry that names this file, quotes the old and the new wording of the
docstrings and of the message, and names each module whose docstring holds the new
wording; it had no such entry.

A test here fails when such a docstring, or the message of the last test, holds certain
words in a row, in any letter case. A word here is whatever stands between white space,
line breaks included, and a mark is any character of a word other than a letter, a digit
or an underscore. The words are, in this order: one that, a comma at its end aside, is
"name" or "names" or ends in either right after a mark other than the hyphen "-"; at most
eight words, none that ends a sentence and none that holds an id; one that is a form of
"begin", "lead" or "start"; and one that is "with" or begins with it right before a mark.
A word ends a sentence when it holds a full stop, colon, semicolon, question mark or
exclamation mark with nothing but marks between it and the end of the word, as `suffix.`
and `suffix.)` do and `test_atm03.py` does not. A word holds an id when it holds "id" or
"ids" with no letter or digit right before it or right after it, as `id`, `(id)`,
`parametrize-ids` and `test_ids` do and `valid` does not; such a word is taken to make the
parametrize id the subject. A claim worded any other way is not read: "names are prefixed
with" is not, and neither are `"names" begin with`, `*names* begin with`,
`names "begin with"`, `names *begin* with` or `names—each of them—begin with`, where a
mark stands right after "names" or beside the verb, nor is a claim about a compound that
ends in "names", such as `file-names begin with` or `testcase-names begin with`, which is
passed as `filenames begin with` is.
"""

import ast
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parent.parent
TESTS = ROOT / "tests"
CHANGELOG = ROOT / "CHANGELOG.md"
COMMAND = "pytest --junitxml"
CRITERION_RE = re.compile(r"\(([A-Z]+-\d+)\.ACn\)")
# The words the module docstring lists, in a row: the name word with the comma it may end in,
# at most eight words that hold no id and end no sentence, a verb form and the "with" word.
# A word ends no sentence when the marks after its last letter, digit or underscore, or all
# of it when it has none, hold none of the five marks.
NAME_CLAIM_RE = re.compile(
    r"(?<![\w-])names?,?"
    r"(?: (?!\S*(?<![^\W_])ids?(?![^\W_]))(?:\S*\w[^\w\s.:;?!]*|[^\w\s.:;?!]+)){0,8}? "
    r"(?:begin(?:s|ning)?|began|begun|lead(?:s|ing)?|led|start(?:s|ed|ing)?) with\b", re.I)
STRAY = "testcase names whose parametrize id does not lead with {}.ACn"
OLD_STRAY = "testcase names that do not lead with {}.ACn"
WORDING = "Every parametrize id below begins with the criterion id"
OLD_WORDING = "Leaf test names begin with the criterion id"


def docstring(path: Path) -> str:
    return ast.get_docstring(ast.parse(path.read_text(encoding="utf-8"))) or ""


def name_claims(text: str):
    """Return the phrases of a text that say a name, rather than a parametrize id, leads with an id."""
    return NAME_CLAIM_RE.findall(" ".join(text.split()))


def problems(doc: str):
    """Return the lines of a docstring that mention a JUnit report it never names the command for."""
    if COMMAND in " ".join(doc.split()):
        return []
    return [line.strip() for line in doc.splitlines() if "junit" in line.lower()]


def unreleased_entries(changelog: str, needle: str):
    """Return the list items of the Unreleased section, up to the next section, holding needle."""
    if "## Unreleased" not in changelog:
        return []
    section = changelog.split("## Unreleased", 1)[1].split("\n## ", 1)[0]
    items = re.split(r"\n(?=- |#)", section)
    return [" ".join(item.split()) for item in items if needle in item]


def lead(message: str) -> str:
    """Return a failure message up to the criterion id it is formatted with."""
    return message.split(" {}")[0]


def wording_gaps(entries, modules):
    """Return what the first entry quoting the old docstring wording leaves out, or that wording."""
    quoting = [entry for entry in entries if OLD_WORDING in entry]
    if not quoting:
        return [OLD_WORDING]
    return [part for part in (WORDING, lead(OLD_STRAY), lead(STRAY), *modules)
            if part not in quoting[0]]


def test_docstrings_that_mention_a_junit_report_name_the_command():
    found = [f"{path.relative_to(ROOT)}: {line}"
             for path in sorted(TESTS.glob("test_*.py")) for line in problems(docstring(path))]
    assert not found, "\n".join(found)


def test_problems_name_the_old_wording():
    old = ("Leaf test names begin with the criterion id (ATM-03.ACn) so each criterion can be\n"
           "traced to a passing testcase in the JUnit output: the id is the first token.\n")
    assert problems(old) == [
        "traced to a passing testcase in the JUnit output: the id is the first token."]


def test_problems_accept_a_docstring_that_names_the_command():
    assert problems("Traced to a passing testcase in a JUnit report written by `pytest\n"
                    "--junitxml`: the id is the first token.\n") == []
    assert problems("Leaf test names begin with the criterion id.\n") == []


def test_docstrings_that_state_a_criterion_id_say_the_parametrize_id_leads_with_it():
    found = [f"{path.relative_to(ROOT)}: {claim}"
             for path in sorted(TESTS.glob("test_*.py")) if CRITERION_RE.search(docstring(path))
             for claim in name_claims(docstring(path))]
    assert not found, "\n".join(found)


def test_name_claims_find_the_old_wording_and_pass_the_new():
    assert name_claims("Leaf test names begin with the criterion id (ATM-03.ACn) so each\n"
                       "criterion can be traced") == ["names begin with"]
    assert name_claims(OLD_STRAY.format("ATM-06")) == ["names that do not lead with"]
    assert name_claims("Every parametrize id below begins with the criterion id (ATM-03.ACn)\n"
                       "so each criterion can be traced") == []
    assert name_claims(STRAY.format("ATM-06")) == []


def test_name_claims_find_a_claim_with_words_between_the_name_and_the_verb():
    # Each sentence says a name leads with the id, and none of them was found.
    assert name_claims("Testcase names all begin with the criterion id") == [
        "names all begin with"]
    assert name_claims("Leaf test names, which begin with the criterion id") == [
        "names, which begin with"]
    # The comma at the end of the name word is passed right before the verb as well.
    assert name_claims("Testcase names, begin with the criterion id") == ["names, begin with"]
    assert name_claims("Test names now start with the criterion id") == [
        "names now start with"]
    assert name_claims("Every testcase name in the report leads with the criterion id") == [
        "name in the report leads with"]
    assert name_claims("requiring the name of every testcase in the report to lead with\n"
                       "that id") == ["name of every testcase in the report to lead with"]
    assert name_claims("Names of leaf tests Begin With the criterion id") == [
        "Names of leaf tests Begin With"]
    for verb in ("begin", "begins", "beginning", "began", "begun", "lead", "leads", "leading",
                 "led", "start", "starts", "started", "starting"):
        assert name_claims(f"Test names {verb} with the criterion id") == [
            f"names {verb} with"], verb


def test_name_claims_stop_at_an_id_at_the_end_of_a_sentence_and_after_eight_words():
    # "id" or "ids" between the name and the verb makes the parametrize id the subject.
    assert name_claims("Each testcase name carries a parametrize id that leads with\n"
                       "ATM-06.ACn") == []
    assert name_claims("Testcase names, whose parametrize ids all begin with ATM-06.ACn") == []
    assert name_claims("Each testcase name ends in a bracketed (id) that starts with\n"
                       "ATM-06.ACn") == []
    assert name_claims("Fixture filenames begin with the criterion id") == []
    # The mark ends the sentence right after the name or after a later word.
    for mark in ".:;?!":
        assert name_claims(f"The report gives each testcase a name{mark} Every bracketed\n"
                           "part begins with the criterion id") == [], mark
        assert name_claims(f"The report gives each testcase name a suffix{mark} Every\n"
                           "bracketed part begins with the criterion id") == [], mark
    eight = "name of each and every testcase in the report starts with"
    assert name_claims(f"The {eight} the criterion id") == [eight]
    assert name_claims("The name of each and every testcase in the whole report starts with\n"
                       "the criterion id") == []
    # A wording outside the three verbs is not read, as the module docstring says.
    assert name_claims("Testcase names are prefixed with the criterion id") == []
    assert name_claims("Testcase names begin within the report") == []


def test_name_claims_stop_at_id_or_ids_with_no_letter_or_digit_beside_it():
    # Such a word names an id wherever in it "id" or "ids" stands; only a word that began
    # with either stopped the check, so the first sentence was read as a name claim.
    assert name_claims("Testcase names whose parametrize-ids begin with ATM-06.ACn") == []
    for word in ("test_ids", "id_values", "id-values", "ids=", "(node-id),"):
        assert name_claims(f"Testcase names whose {word} begin with ATM-06.ACn") == [], word
    # A letter or a digit beside it makes another word of it, and the name stays the subject.
    for word in ("valid", "identical", "provided", "kids", "id3", "3ids"):
        assert name_claims(f"Testcase names in {word} reports begin with ATM-06.ACn") == [
            f"names in {word} reports begin with"], word


def test_name_claims_pass_a_compound_that_ends_in_name_or_names():
    # A letter, a digit, an underscore or a hyphen right before "name" or "names" makes a
    # compound of it. The first was read as a claim about testcase names.
    assert name_claims("Fixture file-names begin with the criterion id") == []
    assert name_claims("Each fixture file-name begins with the criterion id") == []
    for word in ("testcase-names", "testnames", "file_names", "file2names", "-names"):
        assert name_claims(f"Fixture {word} begin with the criterion id") == [], word
    # Any other mark right before it leaves it the name word.
    for word in ('"names', "(names", "tests\N{EM DASH}names"):
        assert name_claims(f"Leaf {word} begin with the criterion id") == [
            "names begin with"], word


def test_name_claims_read_past_a_mark_inside_a_word_and_stop_where_only_marks_follow_it():
    # The full stop of a file name ends no sentence. Any word holding one of the five marks
    # stopped the check, so a docstring that made the claim while naming a file passed.
    assert name_claims("Leaf test names in test_atm03.py begin with the criterion id") == [
        "names in test_atm03.py begin with"]
    for mark in ".:;?!":
        inside = f"test_atm03{mark}py"
        assert name_claims(f"Leaf test names in {inside} begin with the criterion id") == [
            f"names in {inside} begin with"], mark
        # With nothing but marks after it, also in a word of marks alone, it ends a sentence.
        for end in (f"suffix{mark})", f'"suffix{mark}"', f"suffix{mark}{mark}", f"({mark})",
                    mark):
            assert name_claims(f"The report gives each testcase name a {end} Every\n"
                               "bracketed part begins with the criterion id") == [], end


def test_name_claims_pass_a_mark_right_after_the_name_beside_the_verb_or_before_with():
    # The name word ends in "name" or "names", a comma aside, the verb is a word of its own
    # and the word after it begins with "with", so none of these is read. The module
    # docstring gives the first five.
    for claim in ('Leaf test "names" begin with the criterion id',
                  "Leaf test *names* begin with the criterion id",
                  'Leaf test names "begin with" the criterion id',
                  "Leaf test names *begin* with the criterion id",
                  "Leaf test names\N{EM DASH}each of them\N{EM DASH}begin with the criterion id",
                  "Leaf test names begin, with the criterion id",
                  "Leaf test names begin *with* the criterion id"):
        assert name_claims(claim) == [], claim
    # These are read: a quotation mark at the start of the name word and at the end of the
    # "with" word, brackets around a word in between, and a hyphen that is a word of its own.
    assert name_claims('Leaf test "names begin with" the criterion id') == ["names begin with"]
    assert name_claims("Leaf test names (each) begin with the criterion id") == [
        "names (each) begin with"]
    assert name_claims("Leaf test names - each of them - begin with the criterion id") == [
        "names - each of them - begin with"]


def test_the_unreleased_changelog_records_the_wording_and_this_test():
    me = f"tests/{HERE.name}"
    entries = unreleased_entries(CHANGELOG.read_text(encoding="utf-8"), me)
    assert entries, f"CHANGELOG.md: no Unreleased entry names {me}"
    modules = [f"tests/{path.name}" for path in sorted(TESTS.glob("test_*.py"))
               if path.resolve() != HERE and "junit" in docstring(path).lower()]
    assert modules, "no test module docstring mentions a JUnit report"
    entry = entries[0]
    missing = [name for name in (COMMAND, *modules) if name not in entry]
    assert not missing, f"CHANGELOG.md: the Unreleased entry for {me} does not name {missing}"


def test_unreleased_entries_stop_at_the_next_section():
    # An entry that stands only under a released version is not read as Unreleased.
    changelog = ("# Changelog\n\n## Unreleased\n\n### Fixed\n\n- An unrelated fix.\n\n"
                 "## v1.2.0 (2026-09-08)\n\n### Fixed\n\n"
                 "- `tests/test_junit_report_claim.py` runs `pytest --junitxml`.\n")
    assert unreleased_entries(changelog, "tests/test_junit_report_claim.py") == []
    assert unreleased_entries(changelog, "unrelated") == ["- An unrelated fix."]
    wrapped = ("## Unreleased\n\n### Fixed\n\n- One entry naming\n"
               "  `tests/test_junit_report_claim.py` across a line break.\n- Another.\n")
    assert unreleased_entries(wrapped, "test_junit_report_claim") == [
        "- One entry naming `tests/test_junit_report_claim.py` across a line break."]


def test_the_unreleased_changelog_records_the_parametrize_id_wording():
    me = f"tests/{HERE.name}"
    modules = [f"tests/{path.name}" for path in sorted(TESTS.glob("test_*.py"))
               if path.resolve() != HERE and WORDING in " ".join(docstring(path).split())]
    assert modules, f"no test module docstring says {WORDING!r}"
    entries = unreleased_entries(CHANGELOG.read_text(encoding="utf-8"), me)
    missing = wording_gaps(entries, modules)
    assert not missing, f"CHANGELOG.md: the Unreleased entries naming {me} do not record {missing}"


def test_wording_gaps_find_an_entry_that_records_only_the_command():
    modules = ["tests/test_atm03.py", "tests/test_atm04.py"]
    command = ("- The module docstrings of `tests/test_atm03.py` and `tests/test_atm04.py` say "
               "each criterion can be traced to a passing testcase in a JUnit report written by "
               "`pytest --junitxml`. `tests/test_junit_report_claim.py` runs the command.")
    wording = (f'- The module docstrings of `{modules[0]}` and `{modules[1]}` say "{WORDING}"; '
               f'they said "{OLD_WORDING}". The message of the report check speaks of '
               f'"{lead(STRAY)}" the id; it spoke of "{lead(OLD_STRAY)}" it.')
    assert wording_gaps([], modules) == [OLD_WORDING]
    assert wording_gaps([command], modules) == [OLD_WORDING]
    assert wording_gaps([command, wording], modules) == []
    assert wording_gaps([wording.replace(WORDING, "the parametrize id")], modules) == [WORDING]
    assert wording_gaps([wording.replace(lead(OLD_STRAY), "names")], modules) == [lead(OLD_STRAY)]
    assert wording_gaps([wording.replace(lead(STRAY), "ids")], modules) == [lead(STRAY)]
    assert wording_gaps([wording], [*modules, "tests/test_atm06.py"]) == ["tests/test_atm06.py"]


def test_the_named_command_writes_a_report_whose_parametrize_ids_lead_with_the_criterion_id():
    prefixes = {}
    for path in sorted(TESTS.glob("test_*.py")):
        m = CRITERION_RE.search(docstring(path))
        if m:
            prefixes[path.stem] = m.group(1)
    assert prefixes, "no test module docstring states a criterion id"
    with tempfile.TemporaryDirectory() as td:
        report = Path(td) / "report.xml"
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             f"--junitxml={report}", *(str(TESTS / f"{stem}.py") for stem in prefixes)],
            cwd=ROOT, capture_output=True, text=True, timeout=300)
        assert report.is_file(), proc.stdout + proc.stderr
        cases = [(c.get("classname").rsplit(".", 1)[-1], c.get("name"))
                 for c in ET.parse(report).iter("testcase")]
    for stem, prefix in prefixes.items():
        names = [name for module, name in cases if module == stem]
        assert names, f"{stem}: no testcase in the report\n{proc.stdout}{proc.stderr}"
        stray = [n for n in names if not re.match(rf"\w+\[{re.escape(prefix)}\.AC\d+ ", n)]
        assert not stray, f"{stem}: {STRAY.format(prefix)}: {stray}"
