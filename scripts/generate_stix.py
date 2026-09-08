#!/usr/bin/env python3
"""Render matrix.json as a STIX 2.1 bundle at stix/agent-threat-matrix-bundle.json.

The bundle is derived, never edited: every object id is uuid5 over the matrix's
pinned ``stixNamespace`` and a canonical name, so the same matrix.json always
produces the same bytes, and scripts/validate_matrix.py fails when the committed
bundle no longer matches what this script renders.

Object types and their canonical names:

- ``identity``            ``identity:agent-threat-matrix``   the publishing organization
- ``x-opena2a-tactic``    ``tactic:<tactic id>``            one per tactic
- ``attack-pattern``      ``<technique id>``                one per technique
- ``grouping``            ``class:<attack class id>``       one per attack class
- ``course-of-action``    ``oasb:<control id>``             one per distinct OASB control
- ``relationship``        ``rel:<source>:<type>:<target>``  subtechnique-of, mitigates

``created`` is the matrix ``created`` date and ``modified`` the matrix ``updated``
date, both at midnight UTC. ``created_by_ref`` on every object points at the identity.

Usage::

    python3 scripts/generate_stix.py             # writes stix/agent-threat-matrix-bundle.json
    python3 scripts/generate_stix.py --output P  # writes P instead

Exit 0 on success. Exit 1 when matrix.json references something the bundle cannot
resolve or when the rendered bundle fails its own structural self-check.
"""

import argparse
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "matrix.json"
DEFAULT_OUTPUT = ROOT / "stix" / "agent-threat-matrix-bundle.json"

SPEC_VERSION = "2.1"
KILL_CHAIN = "agent-threat-matrix"
SOURCE_NAME = "agent-threat-matrix"
TECHNIQUE_URL = "https://threats.opena2a.org/techniques/{id}"
OASB_URL = "https://oasb.ai"
ATTACK_URL = "https://attack.mitre.org/techniques/{path}/"
ATLAS_URL = "https://atlas.mitre.org/techniques/{id}"

IDENTITY_NAME = "AI Agent Threat Matrix"
IDENTITY_CANONICAL = "identity:agent-threat-matrix"
BUNDLE_CANONICAL = "bundle:agent-threat-matrix"

# STIX 2.1 common properties every SDO and SRO in the bundle must carry.
COMMON_REQUIRED = ("type", "spec_version", "id", "created", "modified", "created_by_ref")


class GenerationError(Exception):
    pass


def stix_id(namespace: uuid.UUID, stix_type: str, canonical: str) -> str:
    return f"{stix_type}--{uuid.uuid5(namespace, canonical)}"


def timestamp(date: str) -> str:
    return f"{date}T00:00:00.000Z"


def attack_reference(entry: dict) -> dict:
    ext_id = entry["id"]
    path = ext_id.replace(".", "/")
    ref = {"source_name": "mitre-attack", "external_id": ext_id, "url": ATTACK_URL.format(path=path)}
    ref["description"] = mapping_description(entry)
    return ref


def atlas_reference(entry: dict) -> dict:
    ext_id = entry["id"]
    ref = {"source_name": "mitre-atlas", "external_id": ext_id, "url": ATLAS_URL.format(id=ext_id)}
    ref["description"] = mapping_description(entry)
    return ref


def mapping_description(entry: dict) -> str:
    text = entry["relationship"]
    note = entry.get("note")
    return f"{text}: {note}" if note else text


def build_bundle(matrix: dict) -> dict:
    namespace = uuid.UUID(matrix["stixNamespace"])
    created = timestamp(matrix["created"])
    modified = timestamp(matrix["updated"])
    identity_id = stix_id(namespace, "identity", IDENTITY_CANONICAL)

    def common(stix_type: str, canonical: str) -> dict:
        return {
            "type": stix_type,
            "spec_version": SPEC_VERSION,
            "id": stix_id(namespace, stix_type, canonical),
            "created": created,
            "modified": modified,
            "created_by_ref": identity_id,
        }

    objects = []

    identity = common("identity", IDENTITY_CANONICAL)
    identity.update({"name": IDENTITY_NAME, "identity_class": "organization"})
    objects.append(identity)

    tactic_ids = {t["id"] for t in matrix["tactics"]}
    for tactic in matrix["tactics"]:
        obj = common("x-opena2a-tactic", f"tactic:{tactic['id']}")
        obj.update({
            "name": tactic["name"],
            "description": tactic["description"],
            "x_shortname": tactic["id"],
            "x_order": tactic["order"],
        })
        objects.append(obj)

    technique_ids = {t["id"] for t in matrix["techniques"]}
    pattern_id_by_technique = {}
    for technique in matrix["techniques"]:
        tid = technique["id"]
        if technique["tactic"] not in tactic_ids:
            raise GenerationError(f"{tid}: tactic {technique['tactic']!r} is not in tactics[]")
        obj = common("attack-pattern", tid)
        refs = [{"source_name": SOURCE_NAME, "external_id": tid, "url": TECHNIQUE_URL.format(id=tid)}]
        refs.extend(attack_reference(e) for e in technique.get("attackMapping", []))
        refs.extend(atlas_reference(e) for e in technique.get("atlasMapping", []))
        obj.update({
            "name": technique["name"],
            "description": technique["description"],
            "external_references": refs,
            "kill_chain_phases": [{"kill_chain_name": KILL_CHAIN, "phase_name": technique["tactic"]}],
            "x_evidence_tier": technique["evidenceTier"],
        })
        objects.append(obj)
        pattern_id_by_technique[tid] = obj["id"]

    for attack_class in matrix["attackClasses"]:
        cid = attack_class["id"]
        members = attack_class.get("techniques", [])
        for tid in members:
            if tid not in technique_ids:
                raise GenerationError(f"class {cid}: member {tid} is not in techniques[]")
        obj = common("grouping", f"class:{cid}")
        obj.update({
            "name": attack_class["name"],
            "description": attack_class["description"],
            "context": "unspecified",
            "object_refs": [pattern_id_by_technique[tid] for tid in members],
            "x_attack_class_id": cid,
            "x_category": attack_class["category"],
        })
        objects.append(obj)

    controls = sorted({c for t in matrix["techniques"] for c in t["oasbControls"]},
                      key=lambda c: tuple(int(p) for p in c.split(".")))
    coa_id_by_control = {}
    for control in controls:
        obj = common("course-of-action", f"oasb:{control}")
        obj.update({
            "name": f"OASB {control}",
            "external_references": [{"source_name": "oasb", "external_id": control, "url": OASB_URL}],
        })
        objects.append(obj)
        coa_id_by_control[control] = obj["id"]

    for technique in matrix["techniques"]:
        tid = technique["id"]
        parent = technique.get("parentId")
        if "." in tid:
            if parent is None:
                raise GenerationError(f"{tid}: dotted id without parentId")
            if parent not in technique_ids:
                raise GenerationError(f"{tid}: parentId {parent} is not in techniques[]")
            rel = common("relationship", f"rel:{tid}:subtechnique-of:{parent}")
            rel.update({
                "relationship_type": "subtechnique-of",
                "source_ref": pattern_id_by_technique[tid],
                "target_ref": pattern_id_by_technique[parent],
            })
            objects.append(rel)

    for technique in matrix["techniques"]:
        tid = technique["id"]
        for control in technique["oasbControls"]:
            rel = common("relationship", f"rel:oasb:{control}:mitigates:{tid}")
            rel.update({
                "relationship_type": "mitigates",
                "source_ref": coa_id_by_control[control],
                "target_ref": pattern_id_by_technique[tid],
            })
            objects.append(rel)

    return {
        "type": "bundle",
        "id": stix_id(namespace, "bundle", BUNDLE_CANONICAL),
        "objects": objects,
    }


def self_check(bundle: dict) -> list:
    """Structural STIX checks that need no external library: unique ids, resolving
    references, and the common properties every object must carry."""
    problems = []
    if bundle.get("type") != "bundle" or not str(bundle.get("id", "")).startswith("bundle--"):
        problems.append("bundle: type or id is not a STIX bundle")
    objects = bundle.get("objects", [])
    ids = {}
    for obj in objects:
        oid = obj.get("id")
        if oid in ids:
            problems.append(f"duplicate id: {oid}")
        ids[oid] = obj
    for obj in objects:
        oid = obj.get("id", "<no id>")
        for prop in COMMON_REQUIRED:
            if prop not in obj:
                problems.append(f"{oid}: missing {prop}")
        if obj.get("spec_version") != SPEC_VERSION:
            problems.append(f"{oid}: spec_version is not {SPEC_VERSION}")
        if oid != "<no id>" and not oid.startswith(f"{obj.get('type')}--"):
            problems.append(f"{oid}: id prefix does not match type {obj.get('type')!r}")
        for key, value in obj.items():
            if key == "created_by_ref" or key.endswith("_ref"):
                if value not in ids:
                    problems.append(f"{oid}: {key} {value} does not resolve inside the bundle")
            elif key.endswith("_refs"):
                for ref in value:
                    if ref not in ids:
                        problems.append(f"{oid}: {key} entry {ref} does not resolve inside the bundle")
        if obj.get("type") == "relationship":
            for prop in ("relationship_type", "source_ref", "target_ref"):
                if prop not in obj:
                    problems.append(f"{oid}: relationship missing {prop}")
        if obj.get("type") == "grouping":
            if "context" not in obj:
                problems.append(f"{oid}: grouping missing context")
            if not obj.get("object_refs"):
                problems.append(f"{oid}: grouping has no object_refs")
        if obj.get("type") == "identity" and "identity_class" not in obj:
            problems.append(f"{oid}: identity missing identity_class")
        if obj.get("type") in ("attack-pattern", "course-of-action", "x-opena2a-tactic", "identity", "grouping"):
            if not obj.get("name"):
                problems.append(f"{oid}: missing name")
    created_by = {obj.get("created_by_ref") for obj in objects}
    if len(created_by) != 1:
        problems.append(f"created_by_ref is not the same identity on every object: {sorted(map(str, created_by))}")
    return problems


def render(matrix: dict) -> str:
    bundle = build_bundle(matrix)
    problems = self_check(bundle)
    if problems:
        raise GenerationError("bundle self-check failed:\n  " + "\n  ".join(problems))
    return json.dumps(bundle, indent=2) + "\n"


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="where to write the bundle")
    args = parser.parse_args(argv)

    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    try:
        text = render(matrix)
    except GenerationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    count = text.count('"type": "')
    print(f"wrote {args.output}: {count - 1} STIX objects")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
