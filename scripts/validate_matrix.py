#!/usr/bin/env python3
"""Validate matrix.json against the 1.2 schema and the rules the schema cannot state.

Standard library only, no network. Two passes:

1. Shape. matrix.json is checked against schema/threat-matrix-v1.2.schema.json by
   the subset JSON Schema checker below. The subset is what that schema uses:
   ``type``, ``required``, ``properties``, ``additionalProperties``, ``items``,
   ``enum``, ``const``, ``pattern``, ``minimum``, ``maximum``, ``minItems`` and local
   ``$ref`` into ``$defs``. Any other keyword in the schema is a fault in this checker's
   coverage and fails loudly rather than being silently ignored. A ``pattern`` is an
   ECMA-262 regular expression, the dialect JSON Schema names for it, and is applied after
   ``ecma_pattern`` rewrites the constructs it names, which Python's re reads another way.
   A ``number`` is finite: the NaN and Infinity that Python's json module reads are not
   JSON numbers.
   An ``integer`` or ``number`` too large to convert to a 64-bit float, which JSON
   allows, is reported as not a finite number. An integer longer than Python's int
   string conversion limit (4300 digits by default) does not parse, and the FAIL line
   says so with the parser's reason. The same holds for arrays or objects nested deeper
   than the parser allows.

2. Semantics, one line per failure:

   - S1 technique ids are unique
   - S2 ``tactic`` names an entry in tactics[]
   - S3 ``attackClass`` names an entry in attackClasses[]
   - S4 each ``dataSources`` mapping of a technique names an entry in the top-level
        dataSources[] registry, whose ids are themselves unique, and names a tool
        that the entry's ``readBy`` cites
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
   - S12 an ``adapted`` technique carries no ``dvaaValidation``: the tier means
        no lab reproduction, so naming a lab scenario counts it both ways
   - S13 when matrix.json content (anything but ``updated``) differs from the
        copy committed at ``HEAD``, ``updated`` is no earlier than today: every
        STIX object takes its ``modified`` date from it, so a stale ``updated``
        dates new content before it existed. Skipped where ROOT is not the top of
        a git work tree or ``HEAD`` carries no matrix.json
   - S14 a technique whose ``wildPrevalence`` is above 0 has a ``wildSampleCount``
        above 0: a prevalence with no samples behind it was not measured
   - S15 every ``evidence`` entry resolves to a source this validator reads, and a
        technique lists no entry twice (the same type, reference and date). A
        ``honeypot-telemetry`` entry resolves when its reference is the
        ``wildPrevalenceSource`` url, its date is the ``wildPrevalenceSource`` read
        date, and the technique's ``wildSampleCount`` is above 0, so the endpoint
        served telemetry for the technique on that date. A ``lab-reproduction``
        entry resolves when its reference is the permalink of a page that
        evidence-sources.json pins, ``<repository>/blob/<commit>/<path>``, its date
        is the page's ``committed`` date, and the page names the technique's id with
        the technique's name as the label, so the page at that commit names the
        technique. No other reference resolves: the validator records no other
        source, so a citation it cannot read is refused rather than taken on trust
   - S16 evidence-gaps.json is byte-identical to what scripts/generate_stix.py
        renders from this matrix.json: the sorted ids of the techniques whose
        ``evidence`` is empty or absent
   - S17 evidence-sources.json has the shape schema/evidence-sources.schema.json
        gives; its ``read`` date and each page's ``committed`` date are calendar
        dates, ``read`` is no later than today and no ``committed`` is later than
        ``read``; no page is pinned twice; and every page names a technique. The
        validator does not read the clone the pins were taken from:
        ``python3 scripts/pin_evidence_sources.py --dvaa <clone> --check`` compares
        them with it
   - S18 a ``dataSources`` mapping of a technique whose ``tool`` is ``hackmyagent``
        and whose ``kind`` is ``check`` names one of the technique's ``hmaChecks``,
        so the technique page's Data Sources line shows no check its HMA Checks
        line leaves out

Exit 0 when everything holds, 1 otherwise.
"""

import functools
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "matrix.json"
SCHEMA = ROOT / "schema" / "threat-matrix-v1.2.schema.json"
READINESS = ROOT / "schema" / "consumer-readiness.json"
TECHNIQUE_IDS = ROOT / "technique-ids.json"
STIX_BUNDLE = ROOT / "stix" / "agent-threat-matrix-bundle.json"
STIX_GENERATOR = ROOT / "scripts" / "generate_stix.py"
EVIDENCE_GAPS = ROOT / "evidence-gaps.json"
EVIDENCE_SOURCES = ROOT / "evidence-sources.json"
SOURCES_SCHEMA = ROOT / "schema" / "evidence-sources.schema.json"
TELEMETRY = "honeypot-telemetry"
LAB = "lab-reproduction"

DOTTED_RE = re.compile(r"^(T-[0-9]{4})\.[0-9]{3}$")
# Applied with fullmatch: ``$`` also matches before a trailing newline.
COMMIT_SHA_RE = re.compile(r"[0-9a-f]{40}")

# Variables that would point git at a repository other than the one ROOT sits in.
GIT_LOCATION_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                     "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")

# --------------------------------------------------------------------------- schema subset

SUPPORTED = {
    "type", "required", "properties", "additionalProperties", "items", "enum", "const",
    "pattern", "minimum", "maximum", "minItems", "$ref",
    # annotation-only keywords: carried in the schema for readers, no validation effect
    "$schema", "$id", "title", "description", "$defs", "x-semantic",
}


def too_large_for_float(value) -> bool:
    """Whether value is an int too large to convert to a 64-bit float.

    JSON allows an integer of any length, but math.isfinite converts an int to a float
    first and raises OverflowError on such an int. TYPE_CHECKS asks this first, so the
    int fails the ``integer`` and ``number`` checks instead of ending the run.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        return False
    try:
        float(value)
    except OverflowError:
        return True
    return False


TYPE_CHECKS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool) and not too_large_for_float(v),
    "number": lambda v: (isinstance(v, (int, float)) and not isinstance(v, bool)
                         and not too_large_for_float(v) and math.isfinite(v)),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}

# The code points ECMA-262 reads as white space or a line terminator, which its \s matches,
# as the contents of a Python class. Python's \s also matches U+001C to U+001F and U+0085,
# and does not match U+FEFF.
ECMA_SPACE = (r"\t\n\v\f\r \xa0\U00001680\U00002000-\U0000200a\U00002028\U00002029"
              r"\U0000202f\U0000205f\U00003000\U0000feff")
# Every other code point, which ECMA-262's \S matches, for a \S inside a class.
ECMA_NOT_SPACE = (r"\x00-\x08\x0e-\x1f\x21-\x9f\xa1-\U0000167f\U00001681-\U00001fff"
                  r"\U0000200b-\U00002027\U0000202a-\U0000202e\U00002030-\U0000205e"
                  r"\U00002060-\U00002fff\U00003001-\U0000fefe\U0000ff00-\U0010ffff")
# The line terminators, which ECMA-262's . does not match. Python's . matches all but \n.
ECMA_LINE_TERMINATORS = r"\n\r\U00002028\U00002029"


@functools.lru_cache(maxsize=None)
def ecma_pattern(pattern: str) -> re.Pattern:
    """A schema ``pattern``, an ECMA-262 regular expression as JSON Schema has it, compiled
    for Python's re.

    These constructs, which Python reads another way, are rewritten to the ECMA-262
    reading: ``$`` outside a class matches only at the end of the string, where Python's
    also matches before a final newline; ``.`` does not match the ECMA_LINE_TERMINATORS;
    ``\\s`` matches ECMA_SPACE and ``\\S`` every other code point, inside a class and
    outside one; ``[]`` matches no character and ``[^]`` any character, where Python reads
    that ``]`` as a member of the class. ``re.ASCII`` reads ``\\d``, ``\\w`` and ``\\b`` and
    their capitals as ASCII, as ECMA-262 does.
    """
    out, in_class, i = [], False, 0
    while i < len(pattern):
        token, width = pattern[i], 1
        if token == "\\" and i + 1 < len(pattern):
            token, width = pattern[i:i + 2], 2
            if token == r"\s":
                token = ECMA_SPACE if in_class else f"[{ECMA_SPACE}]"
            elif token == r"\S":
                token = ECMA_NOT_SPACE if in_class else f"[^{ECMA_SPACE}]"
        elif in_class:
            in_class = token != "]"
        elif pattern.startswith("[]", i):
            token, width = "(?!)", 2
        elif pattern.startswith("[^]", i):
            token, width = "(?s:.)", 3
        elif token == "[":
            in_class = True
        elif token == "$":
            token = r"\Z"
        elif token == ".":
            token = f"[^{ECMA_LINE_TERMINATORS}]"
        out.append(token)
        i += width
    return re.compile("".join(out), re.ASCII)


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
                if too_large_for_float(value) and {"integer", "number"} & set(types):
                    self.errors.append(f"{path}: an integer of {len(str(abs(value)))} digits is too large "
                                       f"for a 64-bit float, so it is not a finite number")
                else:
                    self.errors.append(f"{path}: expected type {schema['type']}, got {type(value).__name__}")
                return

        if "pattern" in schema and isinstance(value, str):
            if not ecma_pattern(schema["pattern"]).search(value):
                self.errors.append(f"{path}: {value!r} does not match {schema['pattern']}")

        if TYPE_CHECKS["number"](value):
            if "minimum" in schema and value < schema["minimum"]:
                self.errors.append(f"{path}: {value!r} is below the minimum {schema['minimum']}")
            if "maximum" in schema and value > schema["maximum"]:
                self.errors.append(f"{path}: {value!r} is above the maximum {schema['maximum']}")

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

        if isinstance(value, list) and "minItems" in schema and len(value) < schema["minItems"]:
            self.errors.append(f"{path}: {len(value)} item(s), fewer than the minimum {schema['minItems']}")

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
    except (ValueError, RecursionError, KeyError, TypeError):
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


def unpinned_reason(entry: dict, technique: dict, pages: dict):
    """Why a lab-reproduction entry does not resolve to a pinned page (S15), or None."""
    page = pages.get(entry["reference"])
    if page is None:
        return (f"evidence-sources.json pins no page with this reference, so the validator cannot show "
                f"it was read; a {LAB} reference resolves only to the permalink of a pinned page, "
                f"<repository>/blob/<commit>/<path>")
    if entry["date"] != page["committed"]:
        return (f"its date {entry['date']} is not {page['committed']}, the date evidence-sources.json "
                f"gives the commit that wrote the page")
    tid, name = technique["id"], technique["name"]
    labels = [n["label"] for n in page["names"] if n["technique"] == tid]
    if not labels:
        return f"the page evidence-sources.json pins at this reference names no {tid}"
    if name not in labels:
        named = " and ".join(repr(label) for label in labels)
        return f"the page names {tid} as {named}, not as {name!r}, its name in matrix.json"
    return None


def unresolved_reason(entry: dict, technique: dict, source: dict, pages: dict):
    """Why an evidence entry does not resolve (S15), or None when it does."""
    if entry["type"] == LAB:
        return unpinned_reason(entry, technique, pages)
    if entry["type"] != TELEMETRY:
        return (f"the validator reads no {entry['type']} source, so it cannot show the reference "
                f"was read; it resolves a {TELEMETRY} entry against wildPrevalenceSource and a {LAB} "
                f"entry against evidence-sources.json")
    if entry["reference"] != source["url"]:
        return (f"a {TELEMETRY} reference resolves only to the endpoint wildPrevalenceSource "
                f"names, {source['url']}")
    if entry["date"] != source["read"]:
        return (f"its date {entry['date']} is not {source['read']}, the date wildPrevalenceSource "
                f"says the endpoint was read")
    if technique["wildSampleCount"] == 0:
        return (f"the endpoint served no samples for the technique on {source['read']}: its "
                f"wildSampleCount is 0")
    return None


def evidence_findings(technique: dict, tid: str, source: dict, pages: dict) -> list:
    """S15 lines for the evidence entries of one technique."""
    findings = []
    first = {}
    for index, entry in enumerate(technique.get("evidence", [])):
        reason = unresolved_reason(entry, technique, source, pages)
        if reason:
            findings.append(f"S15 {tid}: evidence[{index}] reference {entry['reference']!r} "
                            f"does not resolve: {reason}")
        key = (entry["type"], entry["reference"], entry["date"])
        if key in first:
            findings.append(f"S15 {tid}: evidence[{index}] repeats evidence[{first[key]}] "
                            f"(the same type, reference and date)")
        else:
            first[key] = index
    return findings


def semantic_checks(matrix: dict, readiness: dict, technique_ids_file, pages: dict, errors: list) -> str:
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
    readers = {}
    for d in matrix.get("dataSources", []):
        readers.setdefault(d["id"], set()).update(r["tool"] for r in d["readBy"])

    for index, t in enumerate(techniques):
        tid = technique_label(t, index)
        if t["tactic"] not in tactic_ids:
            errors.append(f"S2 {tid}: tactic {t['tactic']!r} is not in tactics[]")
        if t["attackClass"] not in class_ids:
            errors.append(f"S3 {tid}: attackClass {t['attackClass']!r} is not in attackClasses[]")
        for mapping in t.get("dataSources", []):
            source, tool = mapping["source"], mapping["tool"]
            if source not in readers:
                errors.append(f"S4 {tid}: dataSources source {source!r} is not in the dataSources registry")
            elif tool not in readers[source]:
                errors.append(
                    f"S4 {tid}: dataSources source {source!r} names tool {tool!r}, which its readBy "
                    f"does not cite ({', '.join(sorted(readers[source]))}); cite where {tool!r} reads "
                    f"the data, or name a tool that does"
                )
            if tool == "hackmyagent" and mapping["kind"] == "check" and mapping["ref"] not in t["hmaChecks"]:
                errors.append(
                    f"S18 {tid}: dataSources source {source!r} names hackmyagent check "
                    f"{mapping['ref']!r}, which hmaChecks does not list; add the check to hmaChecks, "
                    f"or name a check that hmaChecks lists"
                )

        scenario = t.get("dvaaValidation")
        if t["evidenceTier"] == "adapted" and isinstance(scenario, str) and scenario.strip():
            errors.append(
                f"S12 {tid}: evidenceTier is adapted (no lab reproduction) but dvaaValidation names "
                f"{scenario!r}; set it to null, or reproduce the technique and re-tier it validated"
            )

        if t["wildPrevalence"] > 0 and t["wildSampleCount"] == 0:
            errors.append(
                f"S14 {tid}: wildPrevalence is {t['wildPrevalence']!r} but wildSampleCount is 0; a "
                f"prevalence with no samples behind it was not measured, so read both from the "
                f"registry with scripts/sync_wild_prevalence.py rather than editing them"
            )

        errors.extend(evidence_findings(t, tid, matrix["wildPrevalenceSource"], pages))

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
        if not (isinstance(commit, str) and COMMIT_SHA_RE.fullmatch(commit)):
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


def calendar_date(value: str) -> bool:
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def pinned_pages(schema: dict, today: str, errors: list) -> dict:
    """S17: append one line per fault in evidence-sources.json; return its pages by permalink.

    A file that does not parse, or does not have the shape its schema gives, has fields that
    cannot be read, so it pins no page that S15 resolves an entry against.
    """
    sources, cause = read_json(EVIDENCE_SOURCES)
    if sources is None:
        errors.append(f"S17 evidence-sources.json is missing or does not parse: {cause}")
        return {}
    checker = SchemaChecker(schema)
    try:
        checker.check(sources, schema, "evidence-sources")
    except ValueError as exc:
        errors.append(f"S17 schema/evidence-sources.schema.json: {exc}")
        return {}
    if checker.errors:
        errors.extend(f"S17 {error}" for error in checker.errors)
        return {}
    dvaa = sources["dvaa"]
    read = dvaa["read"]
    if not calendar_date(read):
        errors.append(f"S17 evidence-sources.dvaa.read: {read!r} is not a calendar date")
    elif read > today:
        errors.append(f"S17 evidence-sources.dvaa.read: {read} is later than today, {today}")
    pages, first = {}, {}
    for index, page in enumerate(dvaa["pages"]):
        where = f"evidence-sources.dvaa.pages[{index}] ({page['path']})"
        committed = page["committed"]
        if not calendar_date(committed):
            errors.append(f"S17 {where}: committed {committed!r} is not a calendar date")
        elif calendar_date(read) and committed > read:
            errors.append(f"S17 {where}: committed {committed} is later than read {read}, the date the "
                          f"clone was read")
        if not page["names"]:
            errors.append(f"S17 {where}: names no technique; a page is pinned for the techniques it names")
        if page["path"] in first:
            errors.append(f"S17 {where}: evidence-sources.dvaa.pages[{first[page['path']]}] pins this "
                          f"page already")
        else:
            first[page["path"]] = index
        pages[f"{dvaa['repository']}/blob/{page['commit']}/{page['path']}"] = page
    return pages


def stix_check(errors: list):
    """S10 and S16: the committed bundle and gap list are what the generator renders."""
    missing = [(rule, path) for rule, path in (("S10", STIX_BUNDLE), ("S16", EVIDENCE_GAPS))
               if not path.is_file()]
    for rule, path in missing:
        errors.append(f"{rule} {path.relative_to(ROOT)} is missing; run scripts/generate_stix.py")
    if missing:
        return
    with tempfile.TemporaryDirectory(prefix="atm-stix-") as tmp:
        out = Path(tmp) / "bundle.json"
        gaps = Path(tmp) / "evidence-gaps.json"
        proc = subprocess.run(
            [sys.executable, str(STIX_GENERATOR), "--output", str(out), "--gaps-output", str(gaps)],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            errors.append(f"S10 scripts/generate_stix.py failed: {proc.stderr.strip() or proc.stdout.strip()}")
            return
        for rule, rendered, committed in (("S10", out, STIX_BUNDLE), ("S16", gaps, EVIDENCE_GAPS)):
            if rendered.read_bytes() != committed.read_bytes():
                errors.append(
                    f"{rule} {committed.relative_to(ROOT)} is not what scripts/generate_stix.py "
                    f"renders from matrix.json; regenerate it with: python3 scripts/generate_stix.py"
                )


def committed_matrix():
    """matrix.json as committed at HEAD, or None when there is no such copy to compare
    against (ROOT is not the top of a git work tree, or HEAD has no matrix.json file)."""
    top = git("rev-parse", "--show-toplevel")
    if top is None or not same_directory(top.strip(), ROOT):
        return None
    shown = git("show", "HEAD:matrix.json")
    if shown is None:
        return None
    try:
        committed = json.loads(shown)
    except (ValueError, RecursionError):
        return None
    return committed if isinstance(committed, dict) else None


def changed_sections(before: dict, after: dict) -> list:
    """Top-level keys other than ``updated`` whose value differs, each with the ids of
    the entries that were added, removed or edited when the value is a list of ids."""
    changed = []
    for key in sorted((set(before) | set(after)) - {"updated"}):
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        ids = []
        if isinstance(old, list) and isinstance(new, list) and all(
                isinstance(e, dict) and isinstance(e.get("id"), str) for e in old + new):
            old_by_id = {e["id"]: e for e in old}
            new_by_id = {e["id"]: e for e in new}
            ids = sorted(i for i in set(old_by_id) | set(new_by_id) if old_by_id.get(i) != new_by_id.get(i))
        if len(ids) > 10:
            ids = ids[:10] + [f"and {len(ids) - 10} more"]
        changed.append(f"{key} {', '.join(ids)}" if ids else key)
    return changed


def freshness_check(matrix: dict, committed, today: str, errors: list):
    if committed is None:
        return
    changed = changed_sections(committed, matrix)
    if changed and matrix["updated"] < today:
        errors.append(
            f"S13 matrix.json content differs from HEAD ({'; '.join(changed)}) but updated is "
            f"{matrix['updated']}, older than today {today}; set updated to {today} and "
            f"regenerate the STIX bundle, whose modified dates take it"
        )


def read_json(path: Path):
    """(data, None), or (None, the reason the file could not be read).

    ValueError covers more than json.JSONDecodeError: json.loads raises a plain
    ValueError for an integer literal longer than Python's int string conversion limit.
    For arrays or objects nested deeper than it parses, json.loads raises a RecursionError,
    which is not a ValueError, and its message is the reason.
    A directory at the path is reported as "a directory, not a file". Another OSError,
    such as a file where a directory on the path should be or a file the user may not
    read, is reported with the system's reason, its strerror, as in "Not a directory".
    """
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except FileNotFoundError:
        return None, "no such file"
    except IsADirectoryError:
        return None, "a directory, not a file"
    except OSError as exc:
        return None, exc.strerror or str(exc)
    except (ValueError, RecursionError) as exc:
        return None, str(exc)


def load_json(path: Path):
    return read_json(path)[0]


def main() -> int:
    inputs = (MATRIX, SCHEMA, READINESS, SOURCES_SCHEMA)
    loaded = {path: read_json(path) for path in inputs}
    if any(data is None for data, _ in loaded.values()):
        for path, (data, cause) in loaded.items():
            if data is None:
                print(f"FAIL: {path.relative_to(ROOT)} is missing or does not parse: {cause}",
                      file=sys.stderr)
        return 1
    matrix, schema, readiness, sources_schema = (loaded[path][0] for path in inputs)

    checker = SchemaChecker(schema)
    try:
        checker.check(matrix, schema, "matrix")
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    errors = list(checker.errors)

    technique_ids_file = load_json(TECHNIQUE_IDS)
    commit_note = ""
    pages = {}
    if not errors:
        today = date.today().isoformat()
        source_errors = []
        pages = pinned_pages(sources_schema, today, source_errors)
        commit_note = semantic_checks(matrix, readiness, technique_ids_file, pages, errors)
        errors.extend(source_errors)
        freshness_check(matrix, committed_matrix(), today, errors)
        stix_check(errors)
    else:
        errors.append("semantic checks skipped until the schema violations above are fixed")

    if errors:
        print(f"FAIL: matrix.json does not validate ({len(errors)} finding(s)):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    sub = sum(1 for t in matrix["techniques"] if "." in t["id"])
    entries = sum(len(t.get("evidence", [])) for t in matrix["techniques"])
    bare = sum(1 for t in matrix["techniques"] if not t.get("evidence"))
    print(
        f"matrix.json validates against schema 1.2: {len(matrix['techniques'])} techniques "
        f"({sub} sub-techniques), {len(matrix['dataSources'])} data sources, "
        f"{entries} evidence entries resolved ({bare} techniques with none) against "
        f"wildPrevalenceSource and the {len(pages)} pages evidence-sources.json pins, "
        f"technique-ids.json, STIX bundle and evidence-gaps.json in sync "
        f"(matrixCommit {technique_ids_file['matrixCommit']}, {commit_note})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
