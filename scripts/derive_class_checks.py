#!/usr/bin/env python3
"""Derive class-level hmaChecks in matrix.json from HackMyAgent's TAXONOMY_MAP.

HackMyAgent's src/hardening/taxonomy.ts maps every shipped check ID to an
attack-class ID and is the ground truth for check membership. The hand-curated
class check lists in matrix.json drifted into three simultaneous wrong states
(spec subset vs registry rows vs HMA truth) before this existed; class-level
hmaChecks are DERIVED now (ruled 2026-08-25; see CHANGELOG) and must not be edited by
hand. Technique-level hmaChecks remain authored.

    python3 scripts/derive_class_checks.py [path-to-hackmyagent-checkout]

Rules:
- SOUL-HV shim: taxonomy.ts (hackmyagent#626) maps SOUL-HV-001..004 to
  themselves instead of class SOUL-HV; normalize them so the class derives its
  checks. Remove the shim when #626 is fixed.
- Quarantine-and-report: a check whose HMA class is not one of the matrix's
  canonical classes is reported and left out, never silently minted into a new
  class (new classes follow the taxonomy proposal path).
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
    for check, cls in pairs:
        if check in SOUL_HV_SHIM and cls == check:
            cls = "SOUL-HV"  # shim for hackmyagent#626
        out[check] = cls
    return out


def main() -> int:
    hma_root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "..", "hackmyagent")
    taxonomy = parse_taxonomy_map(hma_root)

    matrix_path = os.path.join(ROOT, "matrix.json")
    with open(matrix_path) as f:
        matrix = json.load(f)

    canonical = {c["id"] for c in matrix["attackClasses"]}
    by_class: dict = {}
    quarantined: dict = {}
    for check, cls in taxonomy.items():
        if cls in canonical:
            by_class.setdefault(cls, []).append(check)
        else:
            quarantined.setdefault(cls, []).append(check)

    changed = 0
    for c in matrix["attackClasses"]:
        derived = sorted(by_class.get(c["id"], []))
        if (c.get("hmaChecks") or []) != derived:
            c["hmaChecks"] = derived
            changed += 1

    with open(matrix_path, "w") as f:
        json.dump(matrix, f, indent=2)
        f.write("\n")

    print(f"Derived hmaChecks for {len(matrix['attackClasses'])} classes ({changed} changed) "
          f"from {len(taxonomy)} mapped checks.")
    for cls, checks in sorted(quarantined.items()):
        print(f"QUARANTINED (HMA class not in the canonical {len(canonical)}): "
              f"{cls} -> {', '.join(sorted(checks))}")
    empty = [c["id"] for c in matrix["attackClasses"] if not c["hmaChecks"]]
    if empty:
        print(f"Classes with no HMA checks mapped: {', '.join(empty)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
