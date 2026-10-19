"""The claim checks report a matrix.json they cannot read or parse in one line, not a traceback.

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

Each case runs the script from a scratch copy of the script and the files it reads, with
matrix.json replaced, so the shipped tree is never written. With the shipped matrix.json the
scratch copy is green, so the line is caused by matrix.json alone.
"""

import importlib.util
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


@pytest.mark.parametrize("script, reads, args, make, line", read_cases())
def test_a_matrix_json_that_cannot_be_read_is_reported_in_one_line(script, reads, args, make, line):
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
