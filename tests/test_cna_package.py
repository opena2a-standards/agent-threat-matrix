"""CNA application package reference-claim tests.

docs/cna/application-package.md says which files in this repository name a CVE id it cites.
It used to say "This repository does not reference" that id while naming it three times
itself. Every such statement on the page is read and checked against the tracked tree:
"this repository does not reference `X`" and a "(not present in this repo)" table cell hold
only when no tracked file names X; "no other file in this repository references `X`" and a
"(named in no other file in this repo)" table cell hold only when the page is the one
tracked file that names X. Every CVE id the page names must carry one of these statements.
This file never spells out the page's id, so it does not become a second file naming it.
"""

import re
import subprocess
from functools import lru_cache
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PAGE = "docs/cna/application-package.md"
# A placeholder id for the fixture cases; it matches CVE_RE and is not a real CVE.
CVE = "CVE-0000-00000"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")


def _phrase(words: str) -> str:
    return r"\s+".join(re.escape(w) for w in words.split())


SENTENCES = (
    (re.compile(_phrase("this repository does not reference") + r"\s+`([^`]+)`", re.I), "none"),
    (re.compile(_phrase("no other file in this repository references") + r"\s+`([^`]+)`", re.I),
     "only-page"),
)
ROWS = (
    (re.compile(r"\(\s*not present in this repo(?:sitory)?\s*\)", re.I), "none"),
    (re.compile(r"\(\s*named in no other file in this repo(?:sitory)?\s*\)", re.I), "only-page"),
)
CODE_RE = re.compile(r"`([^`]+)`")


def claims(text: str) -> list:
    """(line, identifier, scope) per reference claim; scope is "none" or "only-page"."""
    out = []
    for regex, scope in SENTENCES:
        for m in regex.finditer(text):
            out.append((text.count("\n", 0, m.start(1)) + 1, m.group(1), scope))
    for no, line in enumerate(text.splitlines(), 1):
        for regex, scope in ROWS:
            if regex.search(line):
                out.extend((no, ident, scope) for ident in CODE_RE.findall(line))
    return sorted(out)


def violations(page: str, text: str, files_naming) -> list:
    out = []
    for no, ident, scope in claims(text):
        allowed = {page} if scope == "only-page" else set()
        extra = sorted(set(files_naming(ident)) - allowed)
        if extra:
            said = "no other file names" if scope == "only-page" else "the repository does not name"
            out.append(f"{page}:{no}: says {said} `{ident}`, but {', '.join(extra)} does")
    return out


@lru_cache(maxsize=1)
def tracked_files() -> tuple:
    try:
        top = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=60)
        if top.returncode != 0 or Path(top.stdout.strip()).resolve() != ROOT:
            pytest.skip("not a git checkout of this repository")
        proc = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"],
                              capture_output=True, timeout=60, check=True)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("git not available")
    return tuple(rel for rel in proc.stdout.decode().split("\0") if rel)


def tracked_files_naming(ident: str) -> list:
    needle = ident.encode()
    return [rel for rel in tracked_files()
            if (ROOT / rel).is_file() and needle in (ROOT / rel).read_bytes()]


def test_page_reference_claims_hold_on_tracked_tree():
    text = (ROOT / PAGE).read_text(encoding="utf-8")
    assert violations(PAGE, text, tracked_files_naming) == []


def test_every_cve_id_on_the_page_carries_a_reference_claim():
    text = (ROOT / PAGE).read_text(encoding="utf-8")
    named = set(CVE_RE.findall(text))
    assert named, f"{PAGE} names no CVE id; this test has nothing to check"
    assert named - {ident for _, ident, _ in claims(text)} == set()


def test_absence_claim_on_a_page_that_names_the_id_is_reported():
    text = (f"| Claim | Source |\n|---|---|\n| `{CVE}` is detected | unit (not present in this repo) |\n"
            f"presented as one. This repository does not reference\n`{CVE}`; the unit is its only\n")
    assert violations(PAGE, text, lambda ident: [PAGE]) == [
        f"{PAGE}:3: says the repository does not name `{CVE}`, but {PAGE} does",
        f"{PAGE}:5: says the repository does not name `{CVE}`, but {PAGE} does",
    ]


def test_only_page_claim_reports_another_file():
    text = (f"No other file in this repository references `{CVE}`.\n"
            f"| `{CVE}` | unit (named in no other file in this repo) |\n")
    assert violations(PAGE, text, lambda ident: [PAGE]) == []
    assert violations(PAGE, text, lambda ident: ["README.md", PAGE]) == [
        f"{PAGE}:1: says no other file names `{CVE}`, but README.md does",
        f"{PAGE}:2: says no other file names `{CVE}`, but README.md does",
    ]
