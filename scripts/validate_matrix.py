#!/usr/bin/env python3
"""Validate matrix.json against the 1.2 schema and the rules the schema cannot state.

Standard library only, no network. Two passes:

1. Shape. matrix.json is checked against schema/threat-matrix-v1.2.schema.json by
   the subset JSON Schema checker below. The subset is what that schema uses:
   ``type``, ``required``, ``properties``, ``additionalProperties``, ``items``,
   ``enum``, ``const``, ``pattern`` and local ``$ref`` into ``$defs``. Any other
   keyword in the schema is a fault in this checker's coverage and fails loudly
   rather than being silently ignored.

2. Semantics, one line per failure:

   - S1 technique ids are unique
   - S2 ``tactic`` names an entry in tactics[]
   - S3 ``attackClass`` names an entry in attackClasses[]
   - S4 ``dataSources`` values name entries in the top-level dataSources[] registry,
        whose ids are themselves unique
   - S5 ``replacedBy`` is present if and only if ``status`` is ``deprecated``, and
        names another technique
   - S6 ``parentId`` is present if and only if the id is dotted, names a technique,
        and equals the part of the id before the dot
   - S7 consumer readiness: while schema/consumer-readiness.json says
        ``subTechniques: false``, no dotted id may appear
   - S8 technique-ids.json carries the matrix version and exactly the sorted
        technique ids of matrix.json
   - S9 attack class and attack path membership lists name techniques
   - S10 stix/agent-threat-matrix-bundle.json is byte-identical to what
        scripts/generate_stix.py renders from this matrix.json
   - S11 technique-ids.json ``matrixCommit`` is the 40-hex sha of the commit
        whose matrix.json the id list indexes; a placeholder, an abbreviated
        sha or a missing key is refused. Where the repository root is the top
        of a git work tree that holds the commit, matrix.json is read at that
        commit, and a sha that names no commit, names another kind of object,
        names a commit where matrix.json is a directory or a submodule, or
        indexes a matrix.json whose ids differ from the list is refused. A
        copy without git, a shallow checkout that lacks the commit, or a
        partial clone that lacks the commit's tree or matrix.json cannot read
        the file at that commit, so there only the shape is checked; the
        summary line says which check ran

Exit 0 when everything holds, 1 otherwise.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "matrix.json"
SCHEMA = ROOT / "schema" / "threat-matrix-v1.2.schema.json"
READINESS = ROOT / "schema" / "consumer-readiness.json"
TECHNIQUE_IDS = ROOT / "technique-ids.json"
STIX_BUNDLE = ROOT / "stix" / "agent-threat-matrix-bundle.json"
STIX_GENERATOR = ROOT / "scripts" / "generate_stix.py"

DOTTED_RE = re.compile(r"^(T-[0-9]{4})\.[0-9]{3}$")
COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Variables that would point git at a repository other than the one ROOT sits in.
GIT_LOCATION_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                     "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")

# --------------------------------------------------------------------------- schema subset

SUPPORTED = {
    "type", "required", "properties", "additionalProperties", "items", "enum", "const",
    "pattern", "$ref",
    # annotation-only keywords: carried in the schema for readers, no validation effect
    "$schema", "$id", "title", "description", "$defs", "x-semantic",
}

TYPE_CHECKS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


class SchemaChecker:
    def __init__(self, schema: dict):
        self.root = schema
        self.errors = []

    def resolve(self, ref: str) -> dict:
        if not ref.startswith("#/"):
            raise ValueError(f"only local $ref is supported, got {ref!r}")
        node = self.root
        for part in ref[2:].split("/"):
            node = node[part]
        return node

    def check(self, value, schema: dict, path: str):
        for keyword in schema:
            if keyword not in SUPPORTED:
                raise ValueError(f"schema keyword {keyword!r} at {path} is outside the supported subset")

        if "$ref" in schema:
            self.check(value, self.resolve(schema["$ref"]), path)

        if "const" in schema and value != schema["const"]:
            self.errors.append(f"{path}: expected {schema['const']!r}, got {value!r}")
            return

        if "enum" in schema and value not in schema["enum"]:
            self.errors.append(f"{path}: {value!r} is not one of {schema['enum']}")
            return

        if "type" in schema:
            types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(TYPE_CHECKS[t](value) for t in types):
                self.errors.append(f"{path}: expected type {schema['type']}, got {type(value).__name__}")
                return

        if "pattern" in schema and isinstance(value, str):
            if not re.search(schema["pattern"], value):
                self.errors.append(f"{path}: {value!r} does not match {schema['pattern']}")

        if isinstance(value, dict):
            for key in schema.get("required", []):
                if key not in value:
                    self.errors.append(f"{path}: missing required property {key!r}")
            properties = schema.get("properties", {})
            for key, sub in properties.items():
                if key in value:
                    self.check(value[key], sub, f"{path}.{key}")
            additional = schema.get("additionalProperties", True)
            if additional is False:
                for key in value:
                    if key not in properties:
                        self.errors.append(f"{path}: unexpected property {key!r}")
            elif isinstance(additional, dict):
                for key in value:
                    if key not in properties:
                        self.check(value[key], additional, f"{path}.{key}")

        if isinstance(value, list) and "items" in schema:
            for index, item in enumerate(value):
                self.check(item, schema["items"], f"{path}[{index}]")


# --------------------------------------------------------------------------- semantics

def technique_label(technique: dict, index: int) -> str:
    return technique.get("id") if isinstance(technique.get("id"), str) else f"techniques[{index}]"


def id_difference(expected: list, listed) -> str:
    """The ids one list misses and adds against the other, or "" when they hold the same ids."""
    missing = sorted(set(expected) - set(listed or []))
    extra = sorted(set(listed or []) - set(expected))
    detail = []
    if missing:
        detail.append(f"missing {missing}")
    if extra:
        detail.append(f"extra {extra}")
    return "; ".join(detail)


def git(*args):
    """Run git in ROOT; stdout as text, or None when git is absent or the command fails."""
    env = {key: value for key, value in os.environ.items() if key not in GIT_LOCATION_VARS}
    env["GIT_NO_LAZY_FETCH"] = "1"  # a partial clone must not fetch a missing object
    try:
        proc = subprocess.run(["git", "-C", str(ROOT), *args],
                              capture_output=True, timeout=60, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", errors="replace")


def same_directory(path: str, other: Path) -> bool:
    """Whether two paths name one directory, compared by file identity.

    On a case-insensitive filesystem a path that differs from the on-disk path only in
    letter case is the same directory, which a comparison of the path text misses.
    """
    try:
        return os.path.samefile(path, other)
    except OSError:
        return False


def resolve_matrix_commit(commit: str, listed, errors: list) -> str:
    """S11 beyond the shape: compare the ids of matrix.json at matrixCommit with the list.

    Returns the note the summary line prints after the sha.
    """
    top = git("rev-parse", "--show-toplevel")
    if top is None or not same_directory(top.strip(), ROOT):
        return "shape only: no git history at the repository root"
    kind = (git("cat-file", "-t", commit) or "").strip()
    if not kind:
        if (git("rev-parse", "--is-shallow-repository") or "").strip() == "true":
            return "shape only: shallow checkout without that commit"
        errors.append(f"S11 technique-ids.json matrixCommit {commit} does not name a commit in this repository")
        return ""
    if kind != "commit":
        errors.append(f"S11 technique-ids.json matrixCommit {commit} names a {kind} object, not a commit")
        return ""
    # A partial clone holds the commit but may lack its tree (--filter=tree:0) or the
    # matrix.json blob (--filter=blob:none), and lazy fetching is off, so a missing object
    # is told apart from a commit that has no matrix.json.
    blob_id = (git("rev-parse", "--verify", "--quiet", f"{commit}:matrix.json") or "").strip()
    if not blob_id:
        if git("cat-file", "-e", f"{commit}^{{tree}}") is None:
            return "shape only: partial clone without that commit's tree"
        errors.append(f"S11 technique-ids.json matrixCommit {commit} has no matrix.json")
        return ""
    blob = git("cat-file", "blob", blob_id)
    if blob is None:
        # The commit's tree records what kind of entry matrix.json is, so this reads no
        # object a filter may have left out: a directory or a submodule there is not a
        # missing blob.
        entry = (git("ls-tree", commit, "--", "matrix.json") or "").split()
        if len(entry) > 1 and entry[1] != "blob":
            errors.append(f"S11 technique-ids.json matrixCommit {commit} has no matrix.json file: "
                          f"the entry at that commit is a {entry[1]}, not a blob")
            return ""
        return "shape only: partial clone without matrix.json at that commit"
    try:
        indexed = sorted(t["id"] for t in json.loads(blob)["techniques"])
    except (json.JSONDecodeError, KeyError, TypeError):
        errors.append(f"S11 technique-ids.json matrixCommit {commit}: matrix.json at that commit does not parse")
        return ""
    detail = id_difference(indexed, listed)
    if detail:
        errors.append(
            f"S11 technique-ids.json matrixCommit {commit} indexes a matrix.json whose ids "
            f"differ from the list: {detail}"
        )
        return ""
    return "ids match matrix.json at that commit"


def semantic_checks(matrix: dict, readiness: dict, technique_ids_file, errors: list) -> str:
    """Append one line per semantic failure; return the matrixCommit note for the summary."""
    commit_note = ""
    techniques = matrix["techniques"]
    tactic_ids = {t["id"] for t in matrix["tactics"]}
    class_ids = {c["id"] for c in matrix["attackClasses"]}

    seen = set()
    for index, t in enumerate(techniques):
        tid = technique_label(t, index)
        if tid in seen:
            errors.append(f"S1 {tid}: duplicate technique id")
        seen.add(tid)
    ids = {t["id"] for t in techniques}

    source_ids = [d["id"] for d in matrix.get("dataSources", [])]
    for dup in sorted({s for s in source_ids if source_ids.count(s) > 1}):
        errors.append(f"S4 dataSources registry: duplicate id {dup!r}")
    source_ids = set(source_ids)

    for index, t in enumerate(techniques):
        tid = technique_label(t, index)
        if t["tactic"] not in tactic_ids:
            errors.append(f"S2 {tid}: tactic {t['tactic']!r} is not in tactics[]")
        if t["attackClass"] not in class_ids:
            errors.append(f"S3 {tid}: attackClass {t['attackClass']!r} is not in attackClasses[]")
        for source in t.get("dataSources", []):
            if source not in source_ids:
                errors.append(f"S4 {tid}: dataSources value {source!r} is not in the dataSources registry")

        status = t.get("status", "active")
        replaced_by = t.get("replacedBy")
        if status == "deprecated" and replaced_by is None:
            errors.append(f"S5 {tid}: status is deprecated but replacedBy is absent")
        if status != "deprecated" and replaced_by is not None:
            errors.append(f"S5 {tid}: replacedBy is present but status is {status!r}, not deprecated")
        if replaced_by is not None:
            if replaced_by not in ids:
                errors.append(f"S5 {tid}: replacedBy {replaced_by!r} is not a technique id")
            elif replaced_by == tid:
                errors.append(f"S5 {tid}: replacedBy points at itself")

        dotted = DOTTED_RE.match(tid) if isinstance(tid, str) else None
        parent = t.get("parentId")
        if dotted and parent is None:
            errors.append(f"S6 {tid}: dotted id requires parentId")
        if not dotted and parent is not None:
            errors.append(f"S6 {tid}: parentId is only allowed on a dotted id")
        if dotted and parent is not None:
            if parent not in ids:
                errors.append(f"S6 {tid}: parentId {parent!r} is not a technique id")
            if parent != dotted.group(1):
                errors.append(f"S6 {tid}: parentId {parent!r} does not match the id prefix {dotted.group(1)!r}")
        if dotted and not readiness.get("subTechniques", False):
            errors.append(
                f"S7 {tid}: dotted ids are not accepted while schema/consumer-readiness.json "
                f"has subTechniques false ({readiness.get('note', '')})"
            )

    expected = sorted(ids)
    if technique_ids_file is None:
        errors.append("S8 technique-ids.json is missing or does not parse")
    else:
        if technique_ids_file.get("version") != matrix["version"]:
            errors.append(
                f"S8 technique-ids.json version {technique_ids_file.get('version')!r} "
                f"differs from matrix.json version {matrix['version']!r}"
            )
        listed = technique_ids_file.get("ids")
        if listed != expected:
            detail = id_difference(expected, listed) or "same ids, different order (the list must be sorted)"
            errors.append("S8 technique-ids.json ids differ from matrix.json: " + detail)
        commit = technique_ids_file.get("matrixCommit")
        if not (isinstance(commit, str) and COMMIT_SHA_RE.match(commit)):
            errors.append(f"S11 technique-ids.json matrixCommit {commit!r} is not a 40-hex commit sha")
        else:
            commit_note = resolve_matrix_commit(commit, listed, errors)

    for attack_class in matrix["attackClasses"]:
        for tid in attack_class.get("techniques", []):
            if tid not in ids:
                errors.append(f"S9 attackClasses {attack_class['id']}: member {tid} is not a technique id")
    for path in matrix["attackPaths"]:
        for tid in path.get("techniques", []):
            if tid not in ids:
                errors.append(f"S9 attackPaths {path['id']}: step {tid} is not a technique id")
    return commit_note


def stix_check(errors: list):
    if not STIX_BUNDLE.exists():
        errors.append(f"S10 {STIX_BUNDLE.relative_to(ROOT)} is missing; run scripts/generate_stix.py")
        return
    with tempfile.TemporaryDirectory(prefix="atm-stix-") as tmp:
        out = Path(tmp) / "bundle.json"
        proc = subprocess.run(
            [sys.executable, str(STIX_GENERATOR), "--output", str(out)],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            errors.append(f"S10 scripts/generate_stix.py failed: {proc.stderr.strip() or proc.stdout.strip()}")
            return
        if out.read_bytes() != STIX_BUNDLE.read_bytes():
            errors.append(
                f"S10 {STIX_BUNDLE.relative_to(ROOT)} is not what scripts/generate_stix.py renders "
                f"from matrix.json; regenerate it with: python3 scripts/generate_stix.py"
            )


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def main() -> int:
    matrix = load_json(MATRIX)
    schema = load_json(SCHEMA)
    readiness = load_json(READINESS)
    if matrix is None or schema is None or readiness is None:
        for path, data in ((MATRIX, matrix), (SCHEMA, schema), (READINESS, readiness)):
            if data is None:
                print(f"FAIL: {path.relative_to(ROOT)} is missing or does not parse", file=sys.stderr)
        return 1

    checker = SchemaChecker(schema)
    try:
        checker.check(matrix, schema, "matrix")
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    errors = list(checker.errors)

    technique_ids_file = load_json(TECHNIQUE_IDS)
    commit_note = ""
    if not errors:
        commit_note = semantic_checks(matrix, readiness, technique_ids_file, errors)
        stix_check(errors)
    else:
        errors.append("semantic checks skipped until the schema violations above are fixed")

    if errors:
        print(f"FAIL: matrix.json does not validate ({len(errors)} finding(s)):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    sub = sum(1 for t in matrix["techniques"] if "." in t["id"])
    print(
        f"matrix.json validates against schema 1.2: {len(matrix['techniques'])} techniques "
        f"({sub} sub-techniques), {len(matrix['dataSources'])} data sources, "
        f"technique-ids.json and STIX bundle in sync "
        f"(matrixCommit {technique_ids_file['matrixCommit']}, {commit_note})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
