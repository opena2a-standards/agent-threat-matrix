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
name. Those modules said "Leaf test names begin with the criterion id"; a test here fails
when such a docstring, or the message of the last test, says a name leads with it.
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
NAME_CLAIM_RE = re.compile(
    r"\bnames? (?:that |which )?(?:do(?:es)? not |don't )?(?:begins?|leads?|starts?) with", re.I)
STRAY = "testcase names whose parametrize id does not lead with {}.ACn"


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
    assert name_claims("testcase names that do not lead with ATM-06.ACn") == [
        "names that do not lead with"]
    assert name_claims("Every parametrize id below begins with the criterion id (ATM-03.ACn)\n"
                       "so each criterion can be traced") == []
    assert name_claims(STRAY.format("ATM-06")) == []


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
