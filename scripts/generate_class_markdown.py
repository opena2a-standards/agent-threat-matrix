#!/usr/bin/env python3
"""Regenerate attack-classes/*.md from matrix.json.

matrix.json is canonical; the markdown pages are a rendering of it. The
original one-time generation (v1.0) was never re-run: 4 later classes had no
page at all, 17 pages carried empty technique tables while matrix.json
declared members, and every page stamped a uniform "Severity: Medium" that
existed nowhere in the data. Regenerating from the data is the fix for the
class, not the instances. Run this whenever matrix.json changes:

    python3 scripts/generate_class_markdown.py

A wording change to a class page belongs in that class's matrix.json
description. Ten pages once had their punctuation edited by hand while
matrix.json kept the old text, so the next regeneration reverted them and
failed scripts/check_docs_prose.py. ``--check`` writes nothing and exits 1
when attack-classes/ differs from a fresh rendering (a page that differs, a
class with no page, or a page for a class that is gone):

    python3 scripts/generate_class_markdown.py --check

``--help`` (or ``-h``) prints the usage and exits 0. Any other argument, such as a
mistyped ``--chek``, exits 2. Neither writes anything.

The severity line is gone deliberately: matrix.json carries no per-class
severity, and a generator default dressed as a measurement is exactly what
this repo's evidence standard prohibits.

A class page lists BOTH membership views where they differ: the techniques
whose primary attackClass is this class, plus any the class additionally
declares in its techniques[] array (overlapping secondary membership is
allowed by the schema).
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The first line of the docstring, which ``python3 -OO`` strips.
DESCRIPTION = "Regenerate attack-classes/*.md from matrix.json."


def render_pages(matrix: dict) -> dict:
    """Map each class page file name to the text this matrix renders for it."""
    techniques = {t["id"]: t for t in matrix["techniques"]}
    tactics = {t["id"]: t["name"] for t in matrix["tactics"]}

    pages = {}
    for cls in matrix["attackClasses"]:
        # Union of declared members and primary-class members, declared order
        # first — a technique's primary class must always list it.
        member_ids = list(cls.get("techniques") or [])
        for tid, t in techniques.items():
            if t.get("attackClass") == cls["id"] and tid not in member_ids:
                member_ids.append(tid)

        rows = []
        for tid in member_ids:
            t = techniques.get(tid)
            if t is None:
                print(f"WARNING: {cls['id']} declares unknown technique {tid}", file=sys.stderr)
                continue
            tactic = tactics.get(t["tactic"], t["tactic"])
            rows.append(f"| [{tid}](../techniques/{tid}.md) | {t['name']} | {tactic} |")

        lines = [
            f"# {cls['name']} ({cls['id']})",
            "",
            f"**Category:** {cls['category']}",
            "",
            "## Description",
            "",
            cls["description"],
            "",
            "## Techniques",
            "",
        ]
        if rows:
            lines += ["| ID | Name | Tactic |", "|----|------|--------|", *rows]
        else:
            lines.append("No techniques currently map to this class.")
        lines += [
            "",
            "## Detection",
            "",
            f"- **HMA Checks:** {', '.join(cls.get('hmaChecks') or []) or 'none mapped'}",
            "",
        ]
        pages[f"{cls['id']}.md"] = "\n".join(lines)
    return pages


def check(pages: dict, out_dir: str) -> int:
    """Report every page that differs from the rendering; write nothing."""
    on_disk = set()
    if os.path.isdir(out_dir):
        on_disk = {fn for fn in os.listdir(out_dir) if fn.endswith(".md")}

    problems = []
    for fn in sorted(pages):
        if fn not in on_disk:
            problems.append(f"attack-classes/{fn}: missing (matrix.json declares the class)")
            continue
        with open(os.path.join(out_dir, fn), encoding="utf-8") as f:
            if f.read() != pages[fn]:
                problems.append(f"attack-classes/{fn}: differs from the matrix.json rendering")
    for fn in sorted(on_disk - set(pages)):
        problems.append(f"attack-classes/{fn}: stale (no such class in matrix.json)")

    if problems:
        print(f"FAIL: {len(problems)} attack class page(s) do not match matrix.json:")
        for p in problems:
            print(f"  - {p}")
        print("Edit the class in matrix.json, then run: python3 scripts/generate_class_markdown.py")
        return 1
    print(f"OK: {len(pages)} attack class pages match matrix.json.")
    return 0


def main(argv: list) -> int:
    # An argument this script does not know ends the run with exit 2 before anything is
    # written: a mistyped --check must not regenerate the pages.
    parser = argparse.ArgumentParser(description=DESCRIPTION, allow_abbrev=False)
    parser.add_argument("--check", action="store_true",
                        help="write nothing; exit 1 when attack-classes/ differs from a fresh rendering")
    args = parser.parse_args(argv)

    with open(os.path.join(ROOT, "matrix.json")) as f:
        matrix = json.load(f)

    pages = render_pages(matrix)
    out_dir = os.path.join(ROOT, "attack-classes")
    if args.check:
        return check(pages, out_dir)

    os.makedirs(out_dir, exist_ok=True)
    for fn, text in pages.items():
        with open(os.path.join(out_dir, fn), "w", encoding="utf-8") as f:
            f.write(text)

    # Remove pages for classes no longer in the data.
    removed = 0
    for fn in os.listdir(out_dir):
        if fn.endswith(".md") and fn not in pages:
            os.remove(os.path.join(out_dir, fn))
            removed += 1

    print(f"Wrote {len(pages)} class pages, removed {removed} stale ones.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
