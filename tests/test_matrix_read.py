"""The claim checks report a matrix.json they cannot read, parse or use in one line, not a traceback.

scripts/check_readme_claims.py, scripts/check_technique_pages.py,
scripts/check_cross_references.py and scripts/check_attribution.py read matrix.json with no
error handling, so a directory at that path or a file holding only "{" stopped each of them
with a traceback ending in an IsADirectoryError or a json.JSONDecodeError, and arrays or
objects nested deeper than the JSON parser reads stopped each with one ending in a
RecursionError, which is not a ValueError. Each must print one line on standard error naming
the file and the cause, with the reason scripts/validate_matrix.py gives for the same file,
print nothing on standard output, write nothing and exit 1, with ``--fix`` as without it.
scripts/check_readme_claims.py prints the line scripts/check_canonical_classes.py prints;
the other three put "FAIL: " before it, as their other failure lines start.

A matrix.json that parses but does not hold what a check reads from it, as "[]", "{}" and
'{"techniques": [{}]}', stopped each of them with a traceback too, ending in a TypeError, an
AttributeError or a KeyError. Each must report it the same way, in the line
scripts/check_canonical_classes.py prints for the same file,
"matrix.json parses but has the wrong shape: <reason>", naming the first place that fails.
Reduced to the keys a check reads, the shipped matrix.json still passes it, so the check asks
for no key it does not read, and a value it reads as optional may be absent or null without
that line.

Each case runs the script from a scratch copy of the script and the files it reads, with
matrix.json replaced, so the shipped tree is never written. With the shipped matrix.json the
scratch copy is green, so the line is caused by matrix.json alone.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
READ_LINE = "matrix.json is missing or does not parse: "

NOT_AS_ROOT = pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0,
                                 reason="root reads a file whatever its mode")
INT_LIMIT = pytest.mark.skipif(
    getattr(sys, "get_int_max_str_digits", lambda: 0)() != 4300,
    reason="needs Python's default int string conversion limit of 4300 digits")


def readme_pages() -> tuple:
    """README.md and the pages that took its reference text, as the checker lists them."""
    spec = importlib.util.spec_from_file_location("check_readme_claims",
                                                  ROOT / "scripts" / "check_readme_claims.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.PAGES


# (script, the files and directories it reads besides matrix.json, the text its read line
# starts with before READ_LINE, whether it takes --fix)
SCRIPTS = [
    ("check_readme_claims.py",
     ("related-projects.json", "CHANGELOG.md", "stix/agent-threat-matrix-bundle.json",
      *readme_pages()),
     "", True),
    ("check_technique_pages.py", ("techniques", "tactics"), "FAIL: ", True),
    ("check_cross_references.py", ("cross-references",), "FAIL: ", True),
    ("check_attribution.py", ("ATTRIBUTION.md",), "FAIL: ", False),
]


def scratch_tree(script: str, reads) -> Path:
    """A scratch copy of the script, the shipped matrix.json and the other files it reads."""
    td = Path(tempfile.mkdtemp(prefix="atm-matrix-read-"))
    for rel in (f"scripts/{script}", "matrix.json", *reads):
        src, dst = ROOT / rel, td / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            shutil.copy(src, dst)
    return td


def files(root: Path) -> dict:
    """Each file under root other than matrix.json, by path, with its bytes."""
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.relative_to(root).parts[0] != "matrix.json" and p.is_file()}


def run(root: Path, script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(root / "scripts" / script), *args],
                          capture_output=True, text=True, timeout=120)


def line_matches(got: str, want: str) -> bool:
    """want in full, or, when it holds "...", a got that starts with the text before the
    "..." and ends with the text after it."""
    head, dots, tail = want.partition("...")
    if not dots:
        return got == want
    return len(got) >= len(head) + len(tail) and got.startswith(head) and got.endswith(tail)


def missing(path: Path):
    path.unlink()


def directory(path: Path):
    path.unlink()
    path.mkdir()


def mode_zero(path: Path):
    path.chmod(0)


def not_utf8(path: Path):
    path.write_bytes(b"\xff\xfe" + path.read_bytes())


def syntax_error(path: Path):
    path.write_bytes(b"{")


def long_integer(path: Path):
    path.write_bytes(b'{"huge": ' + b"1" * 4301 + b"}")


NESTING = 200000


def nested_arrays(path: Path):
    """Arrays nested NESTING levels deep: json.loads raises a RecursionError on them, which
    is not a ValueError (tried on Python 3.12, 3.13 and 3.14)."""
    path.write_bytes(b"[" * NESTING + b"]" * NESTING)


def nested_objects(path: Path):
    """Objects nested NESTING levels deep, each the value of "a" in the object around it."""
    path.write_bytes(b'{"a": ' * NESTING + b"1" + b"}" * NESTING)


# (name, what make(path) leaves at matrix.json, the reason the read line gives, marks)
CASES = [
    ("missing", missing, "no such file", ()),
    ("directory", directory, "a directory, not a file", ()),
    ("mode 0", mode_zero, "Permission denied", NOT_AS_ROOT),
    ("not UTF-8", not_utf8,
     "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte", ()),
    ("syntax error", syntax_error,
     "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)", ()),
    ("4301-digit integer", long_integer,
     "Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits...",
     INT_LIMIT),
    # The start of the reason differs between Python versions: "maximum recursion depth
    # exceeded" on 3.12 and 3.13, "Stack overflow (used ... kB)" on 3.14.
    ("arrays nested 200000 levels deep", nested_arrays,
     "... while decoding a JSON array from a unicode string", ()),
    ("objects nested 200000 levels deep", nested_objects,
     "... while decoding a JSON object from a unicode string", ()),
]


def read_cases():
    for script, reads, prefix, takes_fix in SCRIPTS:
        for args in (((), ("--fix",)) if takes_fix else ((),)):
            for name, make, reason, marks in CASES:
                yield pytest.param(script, reads, args, make, prefix + READ_LINE + reason,
                                   id=" ".join((script, *args, name)), marks=marks)


def assert_reported_in_one_line(script: str, reads, args, make, line: str):
    """Run the script on a scratch tree holding at matrix.json what make(path) leaves, and
    assert that it prints line alone on standard error and nothing on standard output, writes
    nothing and exits 1."""
    td = scratch_tree(script, reads)
    try:
        make(td / "matrix.json")
        before = files(td)
        proc = run(td, script, *args)
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "Traceback" not in proc.stderr, proc.stderr
        assert proc.stdout == "", proc.stdout
        err = proc.stderr.splitlines()
        assert len(err) == 1 and line_matches(err[0], line), proc.stderr
        assert files(td) == before, "the run wrote to the scratch tree"
    finally:
        shutil.rmtree(td)


@pytest.mark.parametrize("script, reads, args, make, line", read_cases())
def test_a_matrix_json_that_cannot_be_read_is_reported_in_one_line(script, reads, args, make, line):
    assert_reported_in_one_line(script, reads, args, make, line)


SHAPE_LINE = "matrix.json parses but has the wrong shape: "
REMOVE = object()


def holding(raw: bytes):
    """A make that writes raw at matrix.json."""
    def make(path: Path):
        path.write_bytes(raw)
    return make


def shipped_with(*changes):
    """A make that writes the shipped matrix.json with each change made. A change is the keys
    that lead to a value, then what replaces it, or REMOVE to remove it, as in
    ("techniques", 3, "id", REMOVE)."""
    def make(path: Path):
        matrix = json.loads((ROOT / "matrix.json").read_text(encoding="utf-8"))
        for *keys, last, value in changes:
            target = matrix
            for key in keys:
                target = target[key]
            if value is REMOVE:
                del target[last]
            else:
                target[last] = value
        path.write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")
    return make


# (name, what make(path) leaves at matrix.json, the reason the shape line gives): the shapes
# tests/test_atm04.py gives scripts/check_canonical_classes.py. Each check reads the
# technique ids, so each gives the same reason for each.
SHAPE_CASES = [
    ("an array", holding(b"[]"), "the top level is an array, not an object"),
    ("null", holding(b"null"), "the top level is null, not an object"),
    ("no techniques key", holding(b"{}"), "the top level has no techniques key"),
    ("a techniques number", holding(b'{"techniques": 5}'), "techniques is a number, not an array"),
    ("a technique with no id", holding(b'{"techniques": [{}]}'), "techniques[0] has no id"),
    ("a technique that is a number", holding(b'{"techniques": [5]}'),
     "techniques[0] is a number, not an object"),
    ("a technique id that is an array", holding(b'{"techniques": [{"id": ["T-1001"]}]}'),
     "techniques[0].id is an array, not a string"),
    ("a number id beside a string id", holding(b'{"techniques": [{"id": 5}, {"id": "T-0000"}]}'),
     "techniques[0].id is a number, not a string"),
    ("the shipped matrix.json with no id on techniques[3]",
     shipped_with(("techniques", 3, "id", REMOVE)), "techniques[3] has no id"),
]

# (script, name, make, reason): what else a check reads, each case a value of the shipped
# matrix.json removed or replaced, which stopped that check with a traceback
SCRIPT_SHAPE_CASES = [
    ("check_readme_claims.py", "no tactics key", shipped_with(("tactics", REMOVE)),
     "the top level has no tactics key"),
    ("check_readme_claims.py", "a technique with no name",
     shipped_with(("techniques", 0, "name", REMOVE)), "techniques[0] has no name"),
    ("check_readme_claims.py", "an evidence tier that is an array",
     shipped_with(("techniques", 0, "evidenceTier", [])),
     "techniques[0].evidenceTier is an array, not a string or null"),
    ("check_readme_claims.py", "a tactic name that is null",
     shipped_with(("tactics", 0, "name", None)), "tactics[0].name is null, not a string"),
    ("check_readme_claims.py", "a tactic with no order", shipped_with(("tactics", 0, "order", REMOVE)),
     "tactics[0] has no order"),
    ("check_readme_claims.py", "attackClasses null", shipped_with(("attackClasses", None)),
     "attackClasses is null, not an array"),
    ("check_readme_claims.py", "a class category that is a number",
     shipped_with(("attackClasses", 0, "category", 5)),
     "attackClasses[0].category is a number, not a string"),
    ("check_readme_claims.py", "a class technique that is a number",
     shipped_with(("attackClasses", 0, "techniques", [5])),
     "attackClasses[0].techniques[0] is a number, not a string"),
    ("check_technique_pages.py", "no tactics key", shipped_with(("tactics", REMOVE)),
     "the top level has no tactics key"),
    ("check_technique_pages.py", "a technique with no attackClass",
     shipped_with(("techniques", 0, "attackClass", REMOVE)), "techniques[0] has no attackClass"),
    ("check_technique_pages.py", "a description that is a number",
     shipped_with(("techniques", 0, "description", 5)),
     "techniques[0].description is a number, not a string or null"),
    ("check_technique_pages.py", "hmaChecks that is a number",
     shipped_with(("techniques", 0, "hmaChecks", 5)),
     "techniques[0].hmaChecks is a number, not an array of strings or null"),
    ("check_technique_pages.py", "an OASB control that is a number",
     shipped_with(("techniques", 0, "oasbControls", [5])),
     "techniques[0].oasbControls[0] is a number, not a string"),
    ("check_technique_pages.py", "a tactic description that is null",
     shipped_with(("tactics", 0, "description", None)),
     "tactics[0].description is null, not a string"),
    ("check_technique_pages.py", "a tactic with no order",
     shipped_with(("tactics", 0, "order", REMOVE)), "tactics[0] has no order"),
    ("check_cross_references.py", "no attackClasses key", shipped_with(("attackClasses", REMOVE)),
     "the top level has no attackClasses key"),
    ("check_cross_references.py", "a class that is a number",
     shipped_with(("attackClasses", 0, 5)), "attackClasses[0] is a number, not an object"),
    ("check_cross_references.py", "a class id that is an array",
     shipped_with(("attackClasses", 0, "id", [])), "attackClasses[0].id is an array, not a string"),
]


def shape_cases():
    for script, reads, prefix, takes_fix in SCRIPTS:
        cases = SHAPE_CASES + [case[1:] for case in SCRIPT_SHAPE_CASES if case[0] == script]
        for args in (((), ("--fix",)) if takes_fix else ((),)):
            for name, make, reason in cases:
                yield pytest.param(script, reads, args, make, prefix + SHAPE_LINE + reason,
                                   id=" ".join((script, *args, name)))


@pytest.mark.parametrize("script, reads, args, make, line", shape_cases())
def test_a_matrix_json_with_the_wrong_shape_is_reported_in_one_line(script, reads, args, make, line):
    assert_reported_in_one_line(script, reads, args, make, line)


# The keys each check reads: at the top level of matrix.json (under None) and in the objects
# of each array it reads.
READS = {
    "check_readme_claims.py": {
        None: ("techniques", "tactics", "attackClasses", "version"),
        "techniques": ("id", "name", "tactic", "attackClass", "evidenceTier", "hmaChecks",
                       "oasbControls", "dvaaValidation"),
        "tactics": ("id", "name", "order"),
        "attackClasses": ("id", "category", "description", "techniques"),
    },
    "check_technique_pages.py": {
        None: ("techniques", "tactics"),
        "techniques": ("id", "name", "tactic", "attackClass", "description", "dvaaValidation",
                       "hmaChecks", "oasbControls", "evidenceTier"),
        "tactics": ("id", "name", "order", "description"),
    },
    "check_cross_references.py": {
        None: ("techniques", "attackClasses", "version"),
        "techniques": ("id",),
        "attackClasses": ("id",),
    },
    "check_attribution.py": {
        None: ("techniques",),
        "techniques": ("id",),
    },
}


@pytest.mark.parametrize("script, reads", [(s, r) for s, r, _p, _f in SCRIPTS],
                         ids=[s for s, *_ in SCRIPTS])
def test_each_check_passes_on_the_shipped_matrix_json_reduced_to_the_keys_it_reads(script, reads):
    td = scratch_tree(script, reads)
    try:
        keys = READS[script]
        matrix = json.loads((td / "matrix.json").read_text(encoding="utf-8"))
        cut = {key: matrix[key] for key in keys[None]}
        for array, fields in keys.items():
            if array is not None:
                cut[array] = [{field: item[field] for field in fields} for item in matrix[array]]
        (td / "matrix.json").write_text(json.dumps(cut, indent=2) + "\n", encoding="utf-8")
        proc = run(td, script)
        assert proc.returncode == 0, proc.stdout + proc.stderr
    finally:
        shutil.rmtree(td)


# (script, name, make): values a check reads as optional, absent or null, which it must take
# without the shape line
OPTIONAL_CASES = [
    ("check_readme_claims.py", "no attackClasses key", shipped_with(("attackClasses", REMOVE))),
    ("check_readme_claims.py", "a technique with a null tactic, attackClass and evidenceTier",
     shipped_with(("techniques", 0, "tactic", None), ("techniques", 0, "attackClass", None),
                  ("techniques", 0, "evidenceTier", None))),
    ("check_readme_claims.py", "a technique with no tactic, attackClass or evidenceTier",
     shipped_with(("techniques", 0, "tactic", REMOVE), ("techniques", 0, "attackClass", REMOVE),
                  ("techniques", 0, "evidenceTier", REMOVE))),
    ("check_readme_claims.py", "a class with null techniques",
     shipped_with(("attackClasses", 0, "techniques", None))),
    ("check_readme_claims.py", "a class with no techniques",
     shipped_with(("attackClasses", 0, "techniques", REMOVE))),
    ("check_technique_pages.py", "a technique with a null description, hmaChecks and oasbControls",
     shipped_with(("techniques", 0, "description", None), ("techniques", 0, "hmaChecks", None),
                  ("techniques", 0, "oasbControls", None))),
    ("check_technique_pages.py", "a technique with no description, hmaChecks or oasbControls",
     shipped_with(("techniques", 0, "description", REMOVE), ("techniques", 0, "hmaChecks", REMOVE),
                  ("techniques", 0, "oasbControls", REMOVE))),
    ("check_cross_references.py", "no version key", shipped_with(("version", REMOVE))),
]


@pytest.mark.parametrize("script, make", [(s, m) for s, _n, m in OPTIONAL_CASES],
                         ids=[" ".join((s, n)) for s, n, _m in OPTIONAL_CASES])
def test_a_value_read_as_optional_may_be_absent_or_null(script, make):
    reads = next(r for s, r, _p, _f in SCRIPTS if s == script)
    td = scratch_tree(script, reads)
    try:
        make(td / "matrix.json")
        proc = run(td, script)
        assert proc.returncode in (0, 1), proc.stdout + proc.stderr
        assert "Traceback" not in proc.stderr, proc.stderr
        assert SHAPE_LINE not in proc.stdout + proc.stderr, proc.stdout + proc.stderr
    finally:
        shutil.rmtree(td)


@pytest.mark.parametrize("script, reads", [(s, r) for s, r, _p, _f in SCRIPTS],
                         ids=[s for s, *_ in SCRIPTS])
def test_the_scratch_tree_is_green_with_the_shipped_matrix_json(script, reads):
    # The cases above prove nothing about matrix.json if the scratch tree lacks a file the
    # script reads.
    td = scratch_tree(script, reads)
    try:
        proc = run(td, script)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Traceback" not in proc.stderr, proc.stderr
    finally:
        shutil.rmtree(td)
