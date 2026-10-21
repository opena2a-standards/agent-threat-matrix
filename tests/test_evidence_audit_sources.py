"""Exposure counts in EVIDENCE_AUDIT.md rows held to the rule link the source that states them.

T-6003 justified its Observed tier with "~75K exposed" OpenClaw gateways and named no source
for the figure. SOURCED lists the rows held to this rule: every count in the row's
justification (a number with a thousands separator, or one ending in K) must sit in a
sentence that carries an https link.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
AUDIT = ROOT / "EVIDENCE_AUDIT.md"
SOURCED = ("T-6003",)
COUNT_RE = re.compile(r"~?\d+(?:\.\d+)?K\b|\b\d{1,3}(?:,\d{3})+\b")
LINK_RE = re.compile(r"\]\(https://[^)\s]+\)")
SENTENCE_RE = re.compile(r"(?<=\.)\s+")


def unsourced_counts(text: str) -> list:
    """Return each count in text that sits in a sentence with no https link."""
    return [count for sentence in SENTENCE_RE.split(text) if not LINK_RE.search(sentence)
            for count in COUNT_RE.findall(sentence)]


def justification(tid: str) -> str:
    rows = [line for line in AUDIT.read_text(encoding="utf-8").splitlines()
            if line.startswith(f"| {tid} |")]
    assert len(rows) == 1, f"{tid}: {len(rows)} rows in EVIDENCE_AUDIT.md"
    cells = [cell.strip() for cell in rows[0].strip().strip("|").split("|")]
    assert len(cells) == 4, f"{tid}: {len(cells)} cells, expected 4"
    return cells[3]


def test_unlinked_count_is_reported():
    text = ("OpenClaw gateway configs modifiable without auth (~75K exposed). "
            "NemoClaw config files world-readable.")
    assert unsourced_counts(text) == ["~75K"]


def test_linked_count_passes():
    text = ("A sweep counted 40,214 instances, 23,505 with panels "
            "([report](https://example.org/report)). Config files world-readable.")
    assert unsourced_counts(text) == []


@pytest.mark.parametrize("tid", SOURCED)
def test_sourced_rows_link_every_count(tid):
    assert unsourced_counts(justification(tid)) == [], justification(tid)
