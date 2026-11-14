#!/usr/bin/env python3
"""Derive the hmaChecks of each family in matrix.json from HackMyAgent's TAXONOMY_MAP.

A family is an entry of the top-level attackClasses in matrix.json, not a canonical
attack class (docs/attack-classes.md). TAXONOMY_MAP in HackMyAgent's
src/hardening/taxonomy.ts pairs each check ID with a code, and this script takes it as
the ground truth for check membership: a check belongs to the family whose id is its
code. The hand-curated check lists of the families in matrix.json drifted into three
simultaneous wrong states (spec subset vs registry rows vs HMA truth) before this
existed; the hmaChecks of each family are DERIVED now (ruled 2026-08-25; see CHANGELOG)
and must not be edited by hand. Technique-level hmaChecks remain authored. The script
keeps the file name it had when a family was called a class.

    python3 scripts/derive_class_checks.py [path-to-hackmyagent-checkout]

Rules:
- SOUL-HV shim: taxonomy.ts (hackmyagent#626) maps SOUL-HV-001..004 to
  themselves instead of family SOUL-HV; normalize them so the family derives its
  checks. Remove the shim when #626 is fixed.
- Quarantine-and-report: a check whose code is not the id of a family in matrix.json
  is reported and left out, never silently minted into a new family (a new family
  follows "Proposing a New Family" in CONTRIBUTING.md).
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOUL_HV_SHIM = {"SOUL-HV-001", "SOUL-HV-002", "SOUL-HV-003", "SOUL-HV-004"}


def parse_taxonomy_map(hma_root: str) -> dict:
    path = os.path.join(hma_root, "src", "hardening", "taxonomy.ts")
    src = open(path).read()
    m = re.search(r"const TAXONOMY_MAP: Record<string, string> = \{(.*?)\n\};", src, re.S)
    if not m:
        raise SystemExit(f"could not locate TAXONOMY_MAP in {path}")
    pairs = re.findall(r"'([A-Z][A-Z0-9_-]+)':\s*'([A-Z][A-Z0-9_-]+)'", m.group(1))
    out = {}
    for check, code in pairs:
        if check in SOUL_HV_SHIM and code == check:
            code = "SOUL-HV"  # shim for hackmyagent#626
        out[check] = code
    return out


def main() -> int:
    hma_root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "..", "hackmyagent")
    taxonomy = parse_taxonomy_map(hma_root)

    matrix_path = os.path.join(ROOT, "matrix.json")
    with open(matrix_path) as f:
        matrix = json.load(f)

    families = {family["id"] for family in matrix["attackClasses"]}
    by_family: dict = {}
    quarantined: dict = {}
    for check, code in taxonomy.items():
        if code in families:
            by_family.setdefault(code, []).append(check)
        else:
            quarantined.setdefault(code, []).append(check)

    changed = 0
    for family in matrix["attackClasses"]:
        derived = sorted(by_family.get(family["id"], []))
        if (family.get("hmaChecks") or []) != derived:
            family["hmaChecks"] = derived
            changed += 1

    with open(matrix_path, "w") as f:
        json.dump(matrix, f, indent=2)
        f.write("\n")

    print(f"Derived hmaChecks for {len(matrix['attackClasses'])} families ({changed} changed) "
          f"from {len(taxonomy)} mapped checks.")
    for code, checks in sorted(quarantined.items()):
        print(f"QUARANTINED (not one of the {len(families)} families in matrix.json): "
              f"{code} -> {', '.join(sorted(checks))}")
    empty = [family["id"] for family in matrix["attackClasses"] if not family["hmaChecks"]]
    if empty:
        print(f"Families with no HMA checks mapped: {', '.join(empty)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
