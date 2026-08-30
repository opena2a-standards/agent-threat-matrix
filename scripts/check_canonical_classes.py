#!/usr/bin/env python3
"""Assert canonical-classes.json resolves the ten canonical classes to matrix.json ids.

canonical-classes.json is authored content: it maps a behavior axis (the ten
canonical attack classes) onto the technique ids in matrix.json, which carry a
separate attack-vector axis in ``attackClass``. The two axes are not derivable
from one another, so this script validates the mapping's shape and never
computes it. There is no ``--fix`` mode for the same reason: a violation here is
a question for the taxonomy, not a rewrite.

Checks:

- V1 the file parses; top-level keys and class names are exactly the expected sets
- V2 every id matches ``T-NNNN`` and exists in matrix.json
- V3 the primary arrays partition the matrix technique ids -- each id exactly once
- V4 ``benign`` carries no ids at all
- V5 per class, primary and secondary are disjoint, strictly ascending, duplicate-free

``matrixVersion`` and ``matrixCommit`` are informational and deliberately unchecked.

Exit 0 when the mapping holds, 1 otherwise, printing one line per violation.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MATRIX = ROOT / "matrix.json"
CANONICAL = ROOT / "canonical-classes.json"

TOP_LEVEL_KEYS = {"description", "matrixVersion", "matrixCommit", "classes"}

# the classifier's label set
CLASS_NAMES = [
    "injection",
    "exfiltration",
    "credential_abuse",
    "privilege_escalation",
    "persistence",
    "lateral_movement",
    "social_engineering",
    "policy_violation",
    "steganography",
    "benign",
]

ID_RE = re.compile(r"^T-[0-9]{4}$")

ARRAYS = ("primary", "secondary")


def check_shape(data, errors):
    """V1: top-level keys and the ten class names, with each class well-formed.

    Returns the class mapping when it is safe to walk, else None.
    """
    if not isinstance(data, dict):
        errors.append("canonical-classes.json: top level is not a JSON object")
        return None

    keys = set(data)
    for key in sorted(TOP_LEVEL_KEYS - keys):
        errors.append(f"V1 missing top-level key: {key}")
    for key in sorted(keys - TOP_LEVEL_KEYS):
        errors.append(f"V1 unexpected top-level key: {key}")

    classes = data.get("classes")
    if not isinstance(classes, dict):
        errors.append("V1 classes: not a JSON object")
        return None

    names = set(classes)
    for name in sorted(set(CLASS_NAMES) - names):
        errors.append(f"V1 missing class: {name}")
    for name in sorted(names - set(CLASS_NAMES)):
        errors.append(f"V1 unexpected class: {name}")

    well_formed = {}
    for name in CLASS_NAMES:
        entry = classes.get(name)
        if entry is None:
            continue
        if not isinstance(entry, dict):
            errors.append(f"V1 {name}: not a JSON object")
            continue
        for key in sorted(set(entry) - set(ARRAYS)):
            errors.append(f"V1 {name}: unexpected key: {key}")
        arrays = {}
        for key in ARRAYS:
            value = entry.get(key)
            if not isinstance(value, list) or not all(isinstance(i, str) for i in value):
                errors.append(f"V1 {name}.{key}: not an array of strings")
                continue
            arrays[key] = value
        if len(arrays) == len(ARRAYS):
            well_formed[name] = arrays
    return well_formed


def check_ids(mapping, matrix_ids, errors):
    """V2: every id is well-formed and present in matrix.json."""
    for name in CLASS_NAMES:
        for key in ARRAYS:
            for tid in mapping.get(name, {}).get(key, []):
                if not ID_RE.match(tid):
                    errors.append(f"V2 {name}.{key}: malformed id: {tid}")
                elif tid not in matrix_ids:
                    errors.append(f"V2 {name}.{key}: id not in matrix.json: {tid}")


def check_partition(mapping, matrix_ids, errors):
    """V3: the primary arrays cover every matrix id exactly once."""
    owners = {}
    for name in CLASS_NAMES:
        for tid in mapping.get(name, {}).get("primary", []):
            owners.setdefault(tid, []).append(name)

    for tid in sorted(matrix_ids - set(owners)):
        errors.append(f"V3 id missing from every primary array: {tid}")
    for tid, names in sorted(owners.items()):
        if len(names) > 1:
            errors.append(f"V3 id in more than one primary array: {tid} ({', '.join(names)})")


def check_benign(mapping, errors):
    """V4: benign is a label, not a set of techniques."""
    for key in ARRAYS:
        ids = mapping.get("benign", {}).get(key, [])
        if ids:
            errors.append(f"V4 benign.{key} must be empty, holds: {', '.join(ids)}")


def check_ordering(mapping, errors):
    """V5: per class, arrays are strictly ascending and the two do not overlap."""
    for name in CLASS_NAMES:
        arrays = mapping.get(name)
        if arrays is None:
            continue
        for key in ARRAYS:
            ids = arrays[key]
            for earlier, later in zip(ids, ids[1:]):
                if earlier == later:
                    errors.append(f"V5 {name}.{key}: duplicate id: {earlier}")
                elif earlier > later:
                    errors.append(f"V5 {name}.{key}: ids out of order: {earlier} before {later}")
        for tid in sorted(set(arrays["primary"]) & set(arrays["secondary"])):
            errors.append(f"V5 {name}: id in both primary and secondary: {tid}")


def main():
    try:
        data = json.loads(CANONICAL.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"canonical-classes.json not found at {CANONICAL}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"canonical-classes.json does not parse: {exc}", file=sys.stderr)
        return 1

    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    matrix_ids = {t["id"] for t in matrix["techniques"]}

    errors = []
    mapping = check_shape(data, errors)
    if mapping is not None:
        check_ids(mapping, matrix_ids, errors)
        check_partition(mapping, matrix_ids, errors)
        check_benign(mapping, errors)
        check_ordering(mapping, errors)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f"canonical-classes.json: {len(errors)} violation(s)", file=sys.stderr)
        return 1

    print(f"canonical-classes.json OK: {len(matrix_ids)} technique ids across {len(CLASS_NAMES)} classes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
