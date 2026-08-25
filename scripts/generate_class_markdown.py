#!/usr/bin/env python3
"""Regenerate attack-classes/*.md from matrix.json.

matrix.json is canonical; the markdown pages are a rendering of it. The
original one-time generation (v1.0) was never re-run: 4 later classes had no
page at all, 17 pages carried empty technique tables while matrix.json
declared members, and every page stamped a uniform "Severity: Medium" that
existed nowhere in the data. Regenerating from the data is the fix for the
class, not the instances — run this whenever matrix.json changes:

    python3 scripts/generate_class_markdown.py

The severity line is gone deliberately: matrix.json carries no per-class
severity, and a generator default dressed as a measurement is exactly what
this repo's evidence standard prohibits.

A class page lists BOTH membership views where they differ: the techniques
whose primary attackClass is this class, plus any the class additionally
declares in its techniques[] array (overlapping secondary membership is
allowed by the schema).
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    with open(os.path.join(ROOT, "matrix.json")) as f:
        matrix = json.load(f)

    techniques = {t["id"]: t for t in matrix["techniques"]}
    tactics = {t["id"]: t["name"] for t in matrix["tactics"]}
    out_dir = os.path.join(ROOT, "attack-classes")
    os.makedirs(out_dir, exist_ok=True)

    written = 0
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

        path = os.path.join(out_dir, f"{cls['id']}.md")
        with open(path, "w") as f:
            f.write("\n".join(lines))
        written += 1

    # Remove pages for classes no longer in the data.
    valid = {f"{c['id']}.md" for c in matrix["attackClasses"]}
    removed = 0
    for fn in os.listdir(out_dir):
        if fn.endswith(".md") and fn not in valid:
            os.remove(os.path.join(out_dir, fn))
            removed += 1

    print(f"Wrote {written} class pages, removed {removed} stale ones.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
