#!/usr/bin/env python3
"""Enforce the technique overlap partition in cross-references/ against matrix.json, and
hold the technique-level crosswalk entries in matrix.json to their entry-review record.

matrix.json is canonical for what the Agent Threat Matrix contains. The three files
under cross-references/ are an analyst reading of two external frameworks against it.
This checker keeps that reading honest and keeps every count on the published pages
derived rather than typed. It reads cross-references/ and matrix.json, and for C9 the
entry-review record crosswalks/review.json and the two release snapshots beside it. Its
one statement about what an external framework contains is the C8 pin of the ATLAS
tactic list, which names the ATLAS release it was read from.

Nine properties:

- C1 every ``T-####`` in cross-references/ exists in matrix.json.
- C2 every family id in cross-references/ exists in matrix.json.attackClasses, whose
     entries are the families.
- C3 the OWASP-named set (owasp-llm-mapping.md mapping table) and the no-counterpart set
     (technique-overlap-index.md) are DISJOINT.
- C4 those two sets union to exactly the technique ids in matrix.json.
- C5 the generated block between the BEGIN/END markers in technique-overlap-index.md
     re-renders byte-identically to the committed text.
- C6 no ``~`` immediately precedes a digit anywhere in cross-references/.
- C7 none of ``coverage``, ``covered``, ``covers`` or ``gap analysis`` appears in a
     heading line or a table header row in cross-references/.
- C8 mitre-atlas-mapping.md states the ATLAS release it is read against, and its tactic
     table (the rows whose first cell is bold) holds exactly one row per tactic of that
     release, as ``**Name** (AML.TA####)`` under the release's current name and in its
     matrix order, and names no technique id.
- C9 every ``attackMapping`` and ``atlasMapping`` entry in matrix.json appears once and has
     exactly one row in crosswalks/review.json, matched by technique, field and id; it
     carries the row's relationship and a note whose sha256 is the row's ``noteSha256``;
     every row matches an entry; no entry matches a ``withdrawn`` row; the record's
     ``unmapped`` list is the techniques carrying no mapping; and its ``releases`` are
     the ones crosswalks/attack-release.json and crosswalks/atlas-release.json record.
     The record is written from the review of each entry against the named release,
     never generated from matrix.json, so an entry no review admitted fails here. A
     record or snapshot that is missing, does not parse or has the wrong shape (see
     ``record_shape``) is reported in one C9 line, and C9 checks nothing else. In the
     record (see ``record_shape``) and in a snapshot's release, a string that is not valid
     Unicode text, as the JSON escape ``\\ud800`` alone decodes to (see ``text_problem``),
     is the wrong shape. In an entry, a relationship or note that is not valid Unicode
     text is reported as such where C9 compares the entry with its row, and an entry whose
     id is not valid Unicode text is named by its place in the array and matched against
     no row.

Run with ``--fix`` to rewrite only the generated block from matrix.json and the mapping
table. Every other line is left alone; there is no other rewrite, because C3 and C4 are
editorial placements, not text a script may invent. With the BEGIN or END marker
missing, or END before BEGIN, ``--fix`` writes nothing and prints "NOT FIXED" ahead of
the C5 failure. Exit 0 when all nine hold, 1 otherwise, printing one line per violation.
A read of matrix.json that raises an OSError, a ValueError or a RecursionError (see
``read_matrix``) is reported in one line on standard error,
``FAIL: matrix.json is missing or does not parse: <reason>``, and the run exits 1 without
checking anything or, under ``--fix``, writing anything. So is a matrix.json that parses but
is not an object whose ``techniques`` and ``attackClasses`` arrays hold objects with a string
``id`` (see ``wrong_shape``), in the line
``FAIL: matrix.json parses but has the wrong shape: <reason>``.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CROSSREF = ROOT / "cross-references"
INDEX_NAME = "technique-overlap-index.md"
OWASP_NAME = "owasp-llm-mapping.md"
ATLAS_NAME = "mitre-atlas-mapping.md"

# C9: the entry-review record, the technique fields it reviews, and the snapshot each of its
# releases is read against, by the key the record gives it, with the framework's name.
REVIEW_PATH = "crosswalks/review.json"
MAPPING_FIELDS = ("attackMapping", "atlasMapping")
RELEASE_SNAPSHOTS = (
    ("attack", "ATT&CK", "crosswalks/attack-release.json"),
    ("atlas", "ATLAS", "crosswalks/atlas-release.json"),
)
REVIEW_ROW_KEYS = ("technique", "field", "id", "relationship", "noteSha256", "reviewed")
WITHDRAWN_ROW_KEYS = ("technique", "field", "id", "reviewed")

# The ATLAS release the tactic mapping is read against, and that release's tactics in
# ATLAS matrix order: the tactics map and the matrix sequence positions of
# dist/v6/ATLAS-2026.09.yaml in the mitre-atlas/atlas-data repository. When ATLAS adds,
# renames or retires a tactic, update this pin and the page in the same change.
ATLAS_RELEASE = "2026.09"
ATLAS_TACTICS = (
    ("AML.TA0002", "Reconnaissance"),
    ("AML.TA0003", "Resource Development"),
    ("AML.TA0001", "AI Attack Adaptation"),
    ("AML.TA0004", "Initial Access"),
    ("AML.TA0000", "AI Model Access"),
    ("AML.TA0005", "Execution"),
    ("AML.TA0006", "Persistence"),
    ("AML.TA0012", "Privilege Escalation"),
    ("AML.TA0007", "Defense Evasion"),
    ("AML.TA0013", "Credential Access"),
    ("AML.TA0008", "Discovery"),
    ("AML.TA0015", "Lateral Movement"),
    ("AML.TA0009", "Collection"),
    ("AML.TA0014", "Command and Control"),
    ("AML.TA0010", "Exfiltration"),
    ("AML.TA0011", "Impact"),
)

BEGIN = "<!-- BEGIN GENERATED: overlap-counts -->"
END = "<!-- END GENERATED: overlap-counts -->"

BANNED_HEADING_WORDS = ("coverage", "covered", "covers", "gap analysis")

TECH_ID_RE = re.compile(r"T-\d{4}")
OWASP_ROW_RE = re.compile(r"^\|\s*\*\*(LLM\d\d)\*\*[^|]*\|([^|]*)\|")
NO_COUNTERPART_ROW_RE = re.compile(r"^\|\s*(T-\d{4})\s*\|")
CLASS_ID_RE = re.compile(r"\b([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)\b")
TILDE_DIGIT_RE = re.compile(r"~\d")
HEADING_RE = re.compile(r"^#{1,6}\s")
# A markdown table separator row: after optional leading whitespace a pipe, then only
# separator characters, and at least one dash. Kept as a single-quantifier match plus a
# membership test so it is linear -- an `X*-X*` form over a class that contains the dash
# backtracks quadratically on a long crafted run of dashes.
TABLE_SEP_RE = re.compile(r"^\s*\|[\s:|-]*$")
# A row of the ATLAS tactic table: its first cell is bold. The tactic cell must then read
# exactly "**Name** (AML.TA####)".
ATLAS_ROW_RE = re.compile(r"^\|\s*\*\*")
ATLAS_TACTIC_CELL_RE = re.compile(r"^\|\s*\*\*([^*|]+)\*\*\s*\((AML\.TA\d{4})\)\s*\|")
ATLAS_TECH_ID_RE = re.compile(r"\bAML\.T\d{4}")

# The section of CONTRIBUTING.md the C3/C4 failure text points a contributor at.
PLACEMENT_SECTION = 'CONTRIBUTING.md, "Placing a new technique"'


def read_matrix(root: Path):
    """(matrix.json parsed, None), or (None, the reason it could not be read or parsed).

    The reasons are the ones scripts/validate_matrix.py gives for the same file: "no such
    file", "a directory, not a file", the system's reason for another OSError, its strerror,
    as in "Permission denied", the message of a ValueError, raised for a syntax error, an
    integer longer than Python's int string conversion limit and bytes that are not UTF-8,
    among others, and the message of the RecursionError, which is not a ValueError, that
    json.loads raises for arrays or objects nested deeper than it parses.
    """
    return read_json(root / "matrix.json")


def read_json(path: Path):
    """(the file at path parsed, None), or (None, the reason it could not be read or parsed),
    with the reasons ``read_matrix`` gives."""
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


def json_type(value) -> str:
    """The JSON type of a parsed value, with its article, as in "an array" or "null"."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "an array"
    return "an object"


def text_problem(value: str):
    """None when the string ``value`` is valid Unicode text, which UTF-8 encodes; otherwise the
    reason it is not, naming the first character UTF-8 cannot encode by its place in ``value``,
    counted from 1, as in "character 88 is U+D800, a surrogate code point, which UTF-8 cannot
    encode".

    The surrogate code points, U+D800 to U+DFFF, are the only characters UTF-8 cannot encode.
    json.loads decodes the JSON escape of one that is not half of a pair, such as ``\\ud800``
    alone, to that code point, so the file parses while the string has no UTF-8 encoding: it
    has no bytes to hash, and a line holding it cannot be written out as UTF-8.
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        return (f"character {exc.start + 1} is U+{ord(value[exc.start]):04X}, a surrogate code "
                f"point, which UTF-8 cannot encode")
    return None


def wrong_shape(matrix):
    """None when the parsed matrix.json is an object whose ``techniques`` and
    ``attackClasses`` arrays hold objects with a string ``id``, the values this check reads
    from it besides ``version``, which may be absent or hold any value; otherwise the reason
    it is not, naming the first place that fails, as scripts/check_canonical_classes.py
    words it.

    The checks hold these ids in sets beside the ids cross-references/ names, and sort and
    print the technique ids, so an id that is not a string can end the run with a traceback:
    an array is not hashable, and a number does not sort beside a string.
    """
    if not isinstance(matrix, dict):
        return f"the top level is {json_type(matrix)}, not an object"
    for key in ("techniques", "attackClasses"):
        if key not in matrix:
            return f"the top level has no {key} key"
        items = matrix[key]
        if not isinstance(items, list):
            return f"{key} is {json_type(items)}, not an array"
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                return f"{key}[{index}] is {json_type(item)}, not an object"
            if "id" not in item:
                return f"{key}[{index}] has no id"
            if not isinstance(item["id"], str):
                return f"{key}[{index}].id is {json_type(item['id'])}, not a string"
    return None


def load_matrix(root: Path):
    matrix = json.loads((root / "matrix.json").read_text())
    version = matrix.get("version")
    ids = {t["id"] for t in matrix["techniques"]}
    classes = {c["id"] for c in matrix["attackClasses"]}
    return version, ids, classes


def crossref_files(root: Path):
    return sorted((root / "cross-references").glob("*.md"))


def parse_owasp_named(text: str) -> set:
    """Distinct technique ids named in the OWASP mapping-table rows (set A)."""
    named = set()
    for line in text.splitlines():
        m = OWASP_ROW_RE.match(line)
        if m:
            named.update(TECH_ID_RE.findall(m.group(2)))
    return named


def parse_no_counterpart(text: str) -> set:
    """Technique ids whose row leads a table in the overlap index (set B)."""
    return {m.group(1) for line in text.splitlines() if (m := NO_COUNTERPART_ROW_RE.match(line))}


def parse_atlas_rows(text: str) -> list:
    """(line number, tactic id or None, tactic name or None, line) per ATLAS tactic-table row."""
    rows = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not ATLAS_ROW_RE.match(line):
            continue
        m = ATLAS_TACTIC_CELL_RE.match(line)
        rows.append((lineno, m.group(2) if m else None, m.group(1).strip() if m else None, line))
    return rows


def check_atlas_mapping(text: str) -> list:
    """C8 failures for the text of mitre-atlas-mapping.md."""
    failures = []
    if f"ATLAS release {ATLAS_RELEASE}" not in text:
        failures.append(
            f"C8 {ATLAS_NAME}: the page does not state the ATLAS release it is read against "
            f"(expected the words 'ATLAS release {ATLAS_RELEASE}')"
        )
    pinned = dict(ATLAS_TACTICS)
    rows = parse_atlas_rows(text)
    seen = []
    for lineno, tid, name, line in rows:
        if tid is None:
            failures.append(
                f"C8 {ATLAS_NAME}:{lineno}: the tactic cell does not read '**Name** (AML.TA####)'"
            )
            continue
        if tid not in pinned:
            failures.append(
                f"C8 {ATLAS_NAME}:{lineno}: {tid} is not a tactic of ATLAS release {ATLAS_RELEASE}"
            )
        elif name != pinned[tid]:
            failures.append(
                f"C8 {ATLAS_NAME}:{lineno}: {tid} is named '{name}'; ATLAS release "
                f"{ATLAS_RELEASE} names it '{pinned[tid]}'"
            )
        if tid in seen:
            failures.append(f"C8 {ATLAS_NAME}:{lineno}: {tid} has more than one row")
        seen.append(tid)
        ids = sorted(set(TECH_ID_RE.findall(line)) | set(ATLAS_TECH_ID_RE.findall(line)))
        if ids:
            failures.append(
                f"C8 {ATLAS_NAME}:{lineno}: the tactic table names technique ids "
                f"({', '.join(ids)}); it relates tactics only"
            )
    for tid, name in ATLAS_TACTICS:
        if tid not in seen:
            failures.append(
                f"C8 {ATLAS_NAME}: ATLAS tactic {tid} {name} has no row; the tactic table holds "
                f"one row per tactic of ATLAS release {ATLAS_RELEASE}"
            )
    order = [tid for tid, _name in ATLAS_TACTICS]
    present = [tid for tid in dict.fromkeys(seen) if tid in pinned]
    if present != [tid for tid in order if tid in present]:
        failures.append(
            f"C8 {ATLAS_NAME}: the tactic rows are not in ATLAS matrix order "
            f"({', '.join(order)})"
        )
    return failures


def class_ids_in(text: str) -> set:
    out = set()
    for token in CLASS_ID_RE.findall(text):
        if token.startswith("T-") and token[2:].isdigit():
            continue
        out.add(token)
    return out


def render_block(version, total: int, named: int) -> str:
    not_named = total - named
    return (
        f"`matrix.json` version {version} holds {total} techniques. The mapping table in\n"
        f"`owasp-llm-mapping.md` names {named} of them and does not name {not_named}. `mitre-atlas-mapping.md`\n"
        f"maps ATLAS tactics to ATM tactics and names no technique in its mapping table."
    )


def extract_block(text: str):
    """Return (before, body, after) around the generated block, or None when no END
    marker follows the BEGIN marker: either marker is missing, or END comes only before
    BEGIN."""
    if BEGIN not in text:
        return None
    before, rest = text.split(BEGIN, 1)
    if END not in rest:
        return None
    body, after = rest.split(END, 1)
    # body is everything between the markers; the committed form is
    # "\n<content>\n". Compare the content without those framing newlines.
    return before, body, after


def end_before_begin(text: str) -> bool:
    """True when both markers are present and no END marker follows the BEGIN marker."""
    return BEGIN in text and END in text and extract_block(text) is None


def is_table_header_rows(lines):
    """Yield indices of lines that are markdown table header rows."""
    for i in range(len(lines) - 1):
        nxt = lines[i + 1]
        if lines[i].lstrip().startswith("|") and "-" in nxt and TABLE_SEP_RE.match(nxt):
            yield i


def record_shape(record):
    """None when the parsed crosswalks/review.json has the shape C9 reads; otherwise the
    reason it does not, naming the first place that fails, as ``wrong_shape`` words it.

    The shape is an object with four keys: ``releases``, an object holding a string release
    under each key of RELEASE_SNAPSHOTS and no other key; ``entries`` and ``withdrawn``,
    arrays of objects whose REVIEW_ROW_KEYS and WITHDRAWN_ROW_KEYS are strings; and
    ``unmapped``, an array of strings. Each of those strings, and each key of ``releases``,
    is valid Unicode text (see ``text_problem``), so a failure line that holds one can be
    written out.
    """
    if not isinstance(record, dict):
        return f"the top level is {json_type(record)}, not an object"
    for key in ("releases", "entries", "withdrawn", "unmapped"):
        if key not in record:
            return f"the top level has no {key} key"
    releases = record["releases"]
    if not isinstance(releases, dict):
        return f"releases is {json_type(releases)}, not an object"
    for name in releases:
        cause = text_problem(name)
        if cause is not None:
            return f"releases has a key that is not valid Unicode text ({cause})"
    keys = [key for key, _framework, _path in RELEASE_SNAPSHOTS]
    if sorted(releases) != sorted(keys):
        return f"releases has the keys {', '.join(sorted(releases)) or 'none'}, not {' and '.join(keys)}"
    for key in keys:
        if not isinstance(releases[key], str):
            return f"releases.{key} is {json_type(releases[key])}, not a string"
        cause = text_problem(releases[key])
        if cause is not None:
            return f"releases.{key} is not valid Unicode text ({cause})"
    for key, fields in (("entries", REVIEW_ROW_KEYS), ("withdrawn", WITHDRAWN_ROW_KEYS)):
        rows = record[key]
        if not isinstance(rows, list):
            return f"{key} is {json_type(rows)}, not an array"
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                return f"{key}[{index}] is {json_type(row)}, not an object"
            for field in fields:
                if field not in row:
                    return f"{key}[{index}] has no {field}"
                if not isinstance(row[field], str):
                    return f"{key}[{index}].{field} is {json_type(row[field])}, not a string"
                cause = text_problem(row[field])
                if cause is not None:
                    return f"{key}[{index}].{field} is not valid Unicode text ({cause})"
    unmapped = record["unmapped"]
    if not isinstance(unmapped, list):
        return f"unmapped is {json_type(unmapped)}, not an array"
    for index, tid in enumerate(unmapped):
        if not isinstance(tid, str):
            return f"unmapped[{index}] is {json_type(tid)}, not a string"
        cause = text_problem(tid)
        if cause is not None:
            return f"unmapped[{index}] is not valid Unicode text ({cause})"
    return None


def mapping_entries(techniques: list):
    """([(technique id, field, entry)], failures): the entries of each technique's
    MAPPING_FIELDS in matrix order, and a C9 failure for each such field that is not an
    array and each entry that is not an object with a string id, a string relationship and
    a note that is a string or absent, which C9 cannot match against a row. So is an entry
    whose id is not valid Unicode text (see ``text_problem``): a line holding that id cannot
    be written out as UTF-8, so its failure names the entry by its place in the array."""
    entries, failures = [], []
    for technique in techniques:
        tid = technique["id"]
        for field in MAPPING_FIELDS:
            if field not in technique:
                continue
            value = technique[field]
            if not isinstance(value, list):
                failures.append(f"C9 {tid} {field} is {json_type(value)}, not an array")
                continue
            for index, entry in enumerate(value):
                if not (isinstance(entry, dict) and isinstance(entry.get("id"), str)
                        and isinstance(entry.get("relationship"), str)
                        and isinstance(entry.get("note", ""), str)):
                    failures.append(f"C9 {tid} {field}[{index}] is not an object with a string id, "
                                    f"a string relationship and a string note or none")
                    continue
                cause = text_problem(entry["id"])
                if cause is not None:
                    failures.append(f"C9 {tid} {field}[{index}].id is not valid Unicode text ({cause})")
                    continue
                entries.append((tid, field, entry))
    return entries, failures


def review_problems(techniques: list, record: dict, releases: dict) -> list:
    """C9 failures for the mapping entries of ``techniques`` against ``record``, the parsed
    entry-review record in the shape ``record_shape`` accepts, and ``releases``, the release
    each snapshot records under the record's key for it ("attack", "atlas").

    An entry is matched to a row by technique, field and id, and each failure names it so.
    The note is compared by the sha256 of its UTF-8 bytes. A relationship or note that is
    not valid Unicode text (see ``text_problem``) is reported as such in place of the
    comparison; such a note has no UTF-8 bytes to hash. Repeated copies of one entry are
    each compared with the row, and a line two copies would share is reported once.
    """
    entries, failures = mapping_entries(techniques)
    rows = {}
    for row in record["entries"]:
        rows.setdefault((row["technique"], row["field"], row["id"]), []).append(row)
    withdrawn = {(row["technique"], row["field"], row["id"]) for row in record["withdrawn"]}
    found = {}
    for tid, field, entry in entries:
        found.setdefault((tid, field, entry["id"]), []).append(entry)
    for key, copies in found.items():
        name = " ".join(key)
        matched = rows.get(key, [])
        lines = []
        if not matched:
            lines.append(f"C9 {name} has no review row in {REVIEW_PATH}")
        elif len(matched) > 1:
            lines.append(f"C9 {name} has {len(matched)} review rows in {REVIEW_PATH}, not one")
        else:
            row = matched[0]
            for entry in copies:
                cause = text_problem(entry["relationship"])
                if cause is not None:
                    lines.append(f"C9 {name}: relationship is not valid Unicode text ({cause})")
                elif entry["relationship"] != row["relationship"]:
                    lines.append(f"C9 {name}: relationship {entry['relationship']} differs from "
                                 f"the reviewed {row['relationship']}")
                note = entry.get("note")
                cause = None if note is None else text_problem(note)
                if cause is not None:
                    lines.append(f"C9 {name}: note is not valid Unicode text ({cause})")
                    continue
                digest = None if note is None else hashlib.sha256(note.encode("utf-8")).hexdigest()
                if digest != row["noteSha256"]:
                    have = "the entry has no note" if digest is None else f"sha256 {digest}"
                    lines.append(f"C9 {name}: note differs from its review row ({have}; the row "
                                 f"records {row['noteSha256']})")
        if key in withdrawn:
            lines.append(f"C9 {name} was withdrawn on review and is present in matrix.json")
        if len(copies) > 1:
            lines.append(f"C9 {name} appears {len(copies)} times in matrix.json; its review row "
                         f"admits one entry")
        failures.extend(dict.fromkeys(lines))
    for key in rows:
        if key not in found:
            failures.append(f"C9 {' '.join(key)} is reviewed but absent from matrix.json")
    carrying = {tid for tid, _field, _entry in entries}
    unmapped = sorted({technique["id"] for technique in techniques} - carrying)
    if sorted(record["unmapped"]) != unmapped:
        failures.append(f"C9 {REVIEW_PATH} lists as unmapped {', '.join(record['unmapped']) or 'none'}; "
                        f"the techniques carrying no mapping are {', '.join(unmapped) or 'none'}")
    for key, framework, path in RELEASE_SNAPSHOTS:
        if record["releases"][key] != releases.get(key):
            failures.append(f"C9 {REVIEW_PATH} records {framework} {record['releases'][key]}; "
                            f"{path} records {releases.get(key)}")
    return failures


def check_crosswalk_review(root: Path, techniques: list) -> list:
    """C9 failures for ``techniques``, the techniques of matrix.json, against the
    entry-review record and the two release snapshots under ``root``. A record or snapshot
    that is missing, does not parse or has the wrong shape is reported in one line naming
    the file, and nothing else is checked."""
    record, cause = read_json(root / REVIEW_PATH)
    if cause is not None:
        return [f"C9 {REVIEW_PATH} is missing or does not parse: {cause}"]
    cause = record_shape(record)
    if cause is not None:
        return [f"C9 {REVIEW_PATH} parses but has the wrong shape: {cause}"]
    releases = {}
    for key, _framework, path in RELEASE_SNAPSHOTS:
        snapshot, cause = read_json(root / path)
        if cause is not None:
            return [f"C9 {path} is missing or does not parse: {cause}"]
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("release"), str):
            return [f"C9 {path} parses but has the wrong shape: it records no release as a string"]
        cause = text_problem(snapshot["release"])
        if cause is not None:
            return [f"C9 {path} parses but has the wrong shape: its release is not valid Unicode "
                    f"text ({cause})"]
        releases[key] = snapshot["release"]
    return review_problems(techniques, record, releases)


def run_checks(root: Path) -> list:
    failures = []
    version, ids, classes = load_matrix(root)
    files = crossref_files(root)

    index_path = root / "cross-references" / INDEX_NAME
    owasp_path = root / "cross-references" / OWASP_NAME
    index_text = index_path.read_text() if index_path.exists() else ""
    owasp_text = owasp_path.read_text() if owasp_path.exists() else ""

    # C1 -- every technique id referenced exists in matrix.json.
    for path in files:
        text = path.read_text()
        for tid in sorted(set(TECH_ID_RE.findall(text))):
            if tid not in ids:
                failures.append(f"C1 {path.name}: {tid} is not a technique id in matrix.json")

    # C2 -- every family id referenced exists in matrix.json.attackClasses.
    for path in files:
        text = path.read_text()
        for cid in sorted(class_ids_in(text)):
            if cid not in classes:
                failures.append(f"C2 {path.name}: {cid} is not a family id in matrix.json")

    named = parse_owasp_named(owasp_text)          # set A
    no_counterpart = parse_no_counterpart(index_text)  # set B

    # C3 -- the two lists are disjoint.
    for tid in sorted(named & no_counterpart):
        failures.append(
            f"C3 {tid} is in both published lists at once. It is named against an OWASP item in "
            f"cross-references/{OWASP_NAME} AND listed with no counterpart in "
            f"cross-references/{INDEX_NAME}. A technique sits in exactly one list. Resolve it "
            f"against the OWASP item's PUBLISHED TEXT. See {PLACEMENT_SECTION}. A title is not evidence."
        )

    # C4 -- the two lists union to exactly the matrix technique ids.
    for tid in sorted(ids - named - no_counterpart):
        failures.append(
            f"C4: {tid} is in matrix.json but appears in neither published list. Every technique "
            f"sits in exactly one of: (A) cross-references/{OWASP_NAME} -- add the id to one OWASP "
            f"item's row; (B) cross-references/{INDEX_NAME} -- add a row with the agent-layer "
            f"property it depends on. Choose (A) only if all three tests pass against that OWASP "
            f"item's PUBLISHED TEXT. See {PLACEMENT_SECTION}. A title is not evidence."
        )
    for tid in sorted((named | no_counterpart) - ids):
        failures.append(
            f"C4: {tid} appears in a published list but is not a technique id in matrix.json"
        )

    # C5 -- the generated block re-renders byte-identically.
    parts = extract_block(index_text)
    if end_before_begin(index_text):
        failures.append(
            f"C5 {INDEX_NAME}: the END marker of the generated block comes before its BEGIN "
            f"marker; move it after the BEGIN marker"
        )
    elif parts is None:
        failures.append(f"C5 {INDEX_NAME}: the generated block markers are missing")
    else:
        _before, body, _after = parts
        want = render_block(version, len(ids), len(named))
        if body != f"\n{want}\n":
            failures.append(
                f"C5 {INDEX_NAME}: the generated block differs from the rendering of matrix.json "
                f"and the mapping table; run scripts/check_cross_references.py --fix"
            )

    # C6 -- no tilde immediately precedes a digit.
    for path in files:
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if TILDE_DIGIT_RE.search(line):
                failures.append(f"C6 {path.name}:{lineno}: a tilde immediately precedes a digit")

    # C7 -- no banned verdict word in a heading or a table header row.
    for path in files:
        lines = path.read_text().splitlines()
        flagged = set()
        for lineno, line in enumerate(lines, 1):
            if HEADING_RE.match(line):
                flagged.add(lineno)
        for i in is_table_header_rows(lines):
            flagged.add(i + 1)
        for lineno in sorted(flagged):
            low = lines[lineno - 1].lower()
            for word in BANNED_HEADING_WORDS:
                if word in low:
                    failures.append(
                        f"C7 {path.name}:{lineno}: heading or table header contains '{word}'"
                    )

    # C8 -- the ATLAS tactic table matches the pinned ATLAS release.
    atlas_path = root / "cross-references" / ATLAS_NAME
    if atlas_path.exists():
        failures.extend(check_atlas_mapping(atlas_path.read_text()))
    else:
        failures.append(f"C8 {ATLAS_NAME}: the page is missing")

    # C9 -- every crosswalk entry in matrix.json matches its row in the entry-review record.
    techniques = json.loads((root / "matrix.json").read_text(encoding="utf-8"))["techniques"]
    failures.extend(check_crosswalk_review(root, techniques))

    return failures


def fix_block(root: Path):
    """Rewrite the generated block from the data. Returns True if the file changed, False
    if the block was already current, and None, writing nothing, if a marker is missing or
    END comes before BEGIN."""
    version, ids, _classes = load_matrix(root)
    owasp_path = root / "cross-references" / OWASP_NAME
    index_path = root / "cross-references" / INDEX_NAME
    named = parse_owasp_named(owasp_path.read_text())
    text = index_path.read_text()
    parts = extract_block(text)
    if parts is None:
        return None
    before, _body, after = parts
    want = render_block(version, len(ids), len(named))
    rebuilt = f"{before}{BEGIN}\n{want}\n{END}{after}"
    if rebuilt != text:
        index_path.write_text(rebuilt)
        return True
    return False


def main(argv: list) -> int:
    fix = "--fix" in argv
    matrix, cause = read_matrix(ROOT)
    if cause is not None:
        print(f"FAIL: matrix.json is missing or does not parse: {cause}", file=sys.stderr)
        return 1
    cause = wrong_shape(matrix)
    if cause is not None:
        print(f"FAIL: matrix.json parses but has the wrong shape: {cause}", file=sys.stderr)
        return 1
    if fix and end_before_begin((ROOT / "cross-references" / INDEX_NAME).read_text()):
        # An END marker before the BEGIN marker leaves no block to rewrite, so nothing is
        # written and the block is not reported current; the C5 failure below ends the run
        # with 1.
        print("NOT FIXED: wrote nothing, as the END marker of the generated block comes "
              "before its BEGIN marker; see the C5 failure below")
    elif fix:
        changed = fix_block(ROOT)
        # Without both markers there is no block to rewrite, so nothing is written and the
        # block is not reported current; the C5 failure below ends the run with 1.
        if changed is None:
            print("NOT FIXED: wrote nothing, as the generated block markers are missing; "
                  "see the C5 failure below")
        else:
            print("FIXED: rewrote the generated block" if changed else "OK: generated block already current")

    failures = run_checks(ROOT)
    if failures:
        print(f"FAIL: {len(failures)} cross-reference check(s) failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    version, ids, _classes = load_matrix(ROOT)
    named = parse_owasp_named((ROOT / "cross-references" / OWASP_NAME).read_text())
    no_counterpart = parse_no_counterpart((ROOT / "cross-references" / INDEX_NAME).read_text())
    print(
        f"OK: {len(named)} techniques named in the OWASP mapping table, "
        f"{len(no_counterpart)} with no counterpart named, disjoint, "
        f"union equals the {len(ids)} techniques in matrix.json"
    )
    entries, _failures = mapping_entries(matrix["techniques"])
    record, _cause = read_json(ROOT / REVIEW_PATH)
    per_field = {field: sum(1 for _tid, f, _entry in entries if f == field) for field in MAPPING_FIELDS}
    print(
        f"OK: crosswalk review clean: the {len(entries)} entries in matrix.json "
        f"({per_field['attackMapping']} attackMapping, {per_field['atlasMapping']} atlasMapping) "
        f"each match their one row of {REVIEW_PATH} in relationship and note, none of the "
        f"{len(record['withdrawn'])} withdrawn entries is present, and the unmapped list "
        f"({', '.join(record['unmapped']) or 'none'}) and the releases (ATT&CK "
        f"{record['releases']['attack']}, ATLAS {record['releases']['atlas']}) hold"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
