#!/usr/bin/env python3
"""Fail when a technique page disagrees with matrix.json on the fields both carry.

matrix.json is canonical. The per-technique pages under techniques/ are hand-written
prose, but two of their lines are data that also lives in matrix.json:

- ``**Attack Class:**`` (a class swap in the data left the pages on the old class)
- ``- **OASB Controls:**`` (data and pages cited OASB 11.1-11.4 from v1.0 on
  2026-03-24 until 2026-08-25; the shipped OASB-1 set had no domain 11 at any
  point in that window, and correcting the data did not reach the pages)

Run with ``--fix`` to rewrite those lines from the data. Every other line is left alone.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLASS_RE = re.compile(r"^\*\*Attack Class:\*\* .*$", re.M)
OASB_RE = re.compile(r"^- \*\*OASB Controls:\*\* .*$", re.M)


def expected_lines(technique: dict) -> tuple[str, str]:
    cls = technique.get("attackClass") or ""
    controls = ", ".join(technique.get("oasbControls") or [])
    return f"**Attack Class:** {cls}", f"- **OASB Controls:** {controls}"


def main(argv: list[str]) -> int:
    fix = "--fix" in argv
    with open(ROOT / "matrix.json") as f:
        matrix = json.load(f)

    failures = []
    for technique in matrix["techniques"]:
        page = ROOT / "techniques" / f"{technique['id']}.md"
        if not page.exists():
            failures.append(f"{technique['id']}: no page at techniques/{technique['id']}.md")
            continue
        text = page.read_text()
        want_class, want_oasb = expected_lines(technique)
        updated = text
        for regex, want, label in ((CLASS_RE, want_class, "Attack Class"), (OASB_RE, want_oasb, "OASB Controls")):
            found = regex.search(text)
            if not found:
                failures.append(f"{technique['id']}: page has no '{label}' line")
                continue
            if found.group(0) != want:
                failures.append(f"{technique['id']}: {label} line is '{found.group(0)}', matrix.json says '{want}'")
                updated = regex.sub(lambda _m, w=want: w, updated, count=1)
        if fix and updated != text:
            page.write_text(updated)

    if failures:
        verb = "rewrote" if fix else "found"
        print(f"{'FIXED' if fix else 'FAIL'}: {verb} {len(failures)} technique-page line(s) that disagree with matrix.json:")
        for failure in failures:
            print(f"  - {failure}")
        return 0 if fix else 1

    print(f"OK: {len(matrix['techniques'])} technique pages agree with matrix.json on attack class and OASB controls")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
