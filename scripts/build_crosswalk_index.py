#!/usr/bin/env python3
"""Build the release-id indexes the crosswalk test resolves against.

The technique-level crosswalks in matrix.json (``attackMapping`` and ``atlasMapping``)
name external technique ids. Each id must exist in the release the note names. This
script distils a local git clone of each published data repository into a committed
id -> name snapshot of that release, which tests/test_crosswalks.py resolves every
mapping id against. It is a provenance tool run by hand with the clones present, not a
CI step: the published data repositories are not vendored into this repository.

The two releases, their sources and the read date are recorded in the output so the
snapshot states where and when it was read. To refresh against a newer release, re-clone,
re-run this, and update the release ids in cross-references and the notes in matrix.json.

usage::

    git clone --filter=blob:none https://github.com/mitre-attack/attack-stix-data
    git clone --filter=blob:none https://github.com/mitre-atlas/atlas-data
    python3 scripts/build_crosswalk_index.py \\
        attack-stix-data/enterprise-attack/enterprise-attack-20.0.json \\
        atlas-data/dist/v6/ATLAS-2026.09.yaml

Writes crosswalks/attack-release.json and crosswalks/atlas-release.json. Needs PyYAML to
read the ATLAS YAML. Exit 0 on success.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "crosswalks"

ATTACK = {"framework": "MITRE ATT&CK Enterprise", "release": "20.0",
          "source": "https://github.com/mitre-attack/attack-stix-data", "read": "2026-10-21"}
ATLAS = {"framework": "MITRE ATLAS", "release": "2026.09",
         "source": "https://github.com/mitre-atlas/atlas-data", "read": "2026-10-21"}


def attack_index(bundle_path: str) -> dict:
    """id -> name for every current (non-revoked, non-deprecated) ATT&CK technique."""
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
    name_by_ext = {}
    for obj in patterns:
        ext = next(r["external_id"] for r in obj["external_references"]
                   if r.get("source_name") == "mitre-attack")
        name_by_ext[ext] = obj["name"]
    out = {}
    for obj in patterns:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next(r["external_id"] for r in obj["external_references"]
                   if r.get("source_name") == "mitre-attack")
        name = obj["name"]
        if obj.get("x_mitre_is_subtechnique"):
            name = f"{name_by_ext[ext.split('.')[0]]}: {name}"
        out[ext] = name
    return dict(sorted(out.items()))


def atlas_index(yaml_path: str) -> dict:
    """id -> name for every ATLAS technique and sub-technique in the release."""
    import yaml
    tech = yaml.safe_load(Path(yaml_path).read_text(encoding="utf-8"))["techniques"]
    out = {}
    for tid, entry in tech.items():
        name = entry["name"]
        if "." in tid[5:]:
            name = f"{tech[tid.rsplit('.', 1)[0]]['name']}: {name}"
        out[tid] = name
    return dict(sorted(out.items()))


def main(argv: list) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    attack = {**ATTACK, "techniques": attack_index(argv[0])}
    atlas = {**ATLAS, "techniques": atlas_index(argv[1])}
    (OUT / "attack-release.json").write_text(json.dumps(attack, indent=2) + "\n", encoding="utf-8")
    (OUT / "atlas-release.json").write_text(json.dumps(atlas, indent=2) + "\n", encoding="utf-8")
    print(f"attack {ATTACK['release']}: {len(attack['techniques'])} techniques")
    print(f"atlas {ATLAS['release']}: {len(atlas['techniques'])} techniques")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
