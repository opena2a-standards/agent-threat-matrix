"""README claim checker tests.

Every case runs scripts/check_readme_claims.py against a scratch copy of README.md and
matrix.json so the committed files are never perturbed. The shipped tree must be green.
Each count the README states is then changed by one in a single place and the checker
must go red, including the counts repeated in the "Use cases" section: the checker used
to accept a claim when the right number appeared anywhere, so a stale repeat passed
while the overview copy still matched.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = ("README.md", "matrix.json", "scripts/check_readme_claims.py")


def scratch_tree() -> Path:
    td = Path(tempfile.mkdtemp(prefix="atm-readme-"))
    for rel in FILES:
        dst = td / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    return td


def run_checker(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(root / "scripts" / "check_readme_claims.py")],
                          capture_output=True, text=True, timeout=120)


def mutate_readme(root: Path, old: str, new: str) -> None:
    readme = root / "README.md"
    text = readme.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"mutation target must occur exactly once: {old!r}"
    readme.write_text(text.replace(old, new), encoding="utf-8")


def test_shipped_readme_is_green():
    td = scratch_tree()
    try:
        r = run_checker(td)
        assert r.returncode == 0, r.stderr
        assert "README claims match matrix.json" in r.stdout
    finally:
        shutil.rmtree(td)


# (old, new): one stated number moved off the measured value in one place.
MUTATIONS = [
    # Use cases: the threat-list paragraph.
    ("into 9 tactics and 61 techniques along a kill chain",
     "into 8 tactics and 61 techniques along a kill chain"),
    ("into 9 tactics and 61 techniques along a kill chain",
     "into 9 tactics and 62 techniques along a kill chain"),
    ("and 60 of the 61 carry a reproducible lab scenario",
     "and 59 of the 61 carry a reproducible lab scenario"),
    # Use cases: the evidence-tier sentence.
    ("16 of the 61 techniques carry real-world evidence",
     "15 of the 61 techniques carry real-world evidence"),
    ("16 of the 61 techniques carry real-world evidence",
     "16 of the 60 techniques carry real-world evidence"),
    ("42 are validated in controlled lab environments",
     "41 are validated in controlled lab environments"),
    ("3 are adapted from traditional environments",
     "4 are adapted from traditional environments"),
    # Purpose.
    ("into 9 tactics and 61 techniques, organized by kill chain stage",
     "into 9 tactics and 60 techniques, organized by kill chain stage"),
    ("60 of the 61 also carry a reproducible lab scenario",
     "61 of the 61 also carry a reproducible lab scenario"),
    # Matrix overview.
    ("**61 techniques** across 9 tactics", "**61 techniques** across 10 tactics"),
    ("**40 attack classes**", "**41 attack classes**"),
    ("**16 techniques with real-world evidence**", "**17 techniques with real-world evidence**"),
    ("**42 techniques validated in controlled lab environments**",
     "**43 techniques validated in controlled lab environments**"),
    ("**3 techniques adapted from traditional environments**",
     "**2 techniques adapted from traditional environments**"),
]


@pytest.mark.parametrize("old,new", MUTATIONS, ids=[n for _, n in MUTATIONS])
def test_a_wrong_count_in_one_place_is_red(old, new):
    td = scratch_tree()
    try:
        mutate_readme(td, old, new)
        text = (td / "README.md").read_text(encoding="utf-8")
        line = text[:text.index(new)].count("\n") + 1
        r = run_checker(td)
        assert r.returncode == 1, f"checker passed with {new!r}:\n{r.stdout}"
        assert f"README.md:{line}:" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)


def test_a_claim_reworded_out_of_the_readme_is_red():
    td = scratch_tree()
    try:
        mutate_readme(td, "16 of the 61 techniques carry real-world evidence",
                      "some techniques carry real-world evidence")
        r = run_checker(td)
        assert r.returncode == 1, r.stdout
        assert "README does not state observed of total" in r.stderr, r.stderr
    finally:
        shutil.rmtree(td)
