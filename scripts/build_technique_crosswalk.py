#!/usr/bin/env python3
"""Render crosswalks/technique-crosswalk.json from matrix.json, technique-ids.json and vendor/.

The crosswalk joins every technique in matrix.json to the HackMyAgent checks and OASB-1
controls the technique lists, the AIIS signatures that name it, and the DVAA scenarios that
expect one of its checks. It is derived content: this script renders it, it is never edited
by hand, and ``python3 scripts/check_technique_crosswalk.py`` fails when the committed file
differs from a fresh rendering or names an id that does not resolve.

Inputs, all read from the repository tree:

- ``matrix.json``: each technique's ``hmaChecks`` and ``oasbControls``, and ``updated``;
- ``technique-ids.json``: hashed into the ``matrix`` block with ``matrix.json``;
- ``vendor/<source>/``: pinned copies of external inputs, each described by its
  ``VENDOR.json`` (a 40-hex ``commit`` for a git source, an exact ``version`` for a
  package), refreshed by the ``refresh`` or ``generate`` command that file states:
  - ``vendor/hackmyagent/check-ids.json``, ``oasb-1-controls.json`` and
    ``payload-ids.json``, generated from the published package;
  - ``vendor/aiis-signatures/crosswalks/technique-signatures.json`` and
    ``retired-ids.yaml``, byte-exact copies;
  - ``vendor/damn-vulnerable-ai-agent/expected-checks.json``, generated from the
    scenarios' own ``expected-checks.json`` files.
- the existence of ``mappings/<producer>-payloads.json``, the producer mapping files that
  fill the payload columns. None exists yet.

The document, keys in this order:

- ``schemaVersion``: 1.
- ``generated``: the latest of matrix.json ``updated`` and every VENDOR.json ``read``. The
  rendering reads no clock, so a rendering on a later day from the same inputs is the same.
- ``matrix``: matrix.json ``version``, and the sha256 of matrix.json and of
  technique-ids.json. A committed file cannot name the commit that holds it, so the matrix
  is identified by content.
- ``inputs``: per vendored source, its pin and the sha256 of each vendored file.
- ``byTechnique``: per technique, ``hmaChecks``, ``oasbControls``, ``aiisSignatures``
  (``{id, basis}``, where ``basis`` is ``aiis-technique-id`` for the signature's
  ``techniqueId`` and ``aiis-related-technique-id`` for an entry of its
  ``relatedTechniqueIds``), ``dvaaScenarios`` (``{scenario, basis: "expected-check",
  checks}``: the scenario expects each of ``checks`` and the technique lists each of them)
  and ``attackPayloads`` per producer.
- ``byHmaCheck``, ``byOasbControl``, ``byAiisSignature``, ``byDvaaScenario``: the reverse
  views, holding each id that joins at least one technique. Each entry names a
  ``techniqueId`` and carries ``relation``. No producer mapping file exists, so every
  ``relation`` is null: the entry is a coverage edge that may be counted, never the
  technique of a finding.
- ``byPayload``: per producer, null while its mapping file does not exist.
- ``unjoined``: the ids an input names that join no technique: OASB-1 controls, check ids a
  DVAA scenario expects, HackMyAgent check ids, and payloads per producer (null while the
  producer has no mapping file).
- ``notAssessed``: one ``{column, reason}`` per column that has no source. A null column is
  not assessed; an empty list is assessed and holds none.

Every by-view and ``byTechnique`` is an object keyed by id in sorted order, and every id list
is sorted. The file is ``json.dumps(doc, indent=2, ensure_ascii=False)`` and a newline,
UTF-8 with LF line endings, so two renderings from the same inputs are byte-identical. The
rendering reads no clock, no environment variable, no git command and no network.

Usage: ``python3 scripts/build_technique_crosswalk.py [root]`` writes the file under the
repository root (default: the parent of this script's directory). Exit 0 when written, 1
when an input is absent or not of the shape read here (one line naming it), 2 on a usage
error. ``--help`` prints the usage.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

# The docstring's first line, held apart so --help still works under python3 -OO.
DESCRIPTION = ("Render crosswalks/technique-crosswalk.json from matrix.json, "
               "technique-ids.json and vendor/.")

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = "crosswalks/technique-crosswalk.json"
SCHEMA_VERSION = 1

MATRIX = "matrix.json"
TECHNIQUE_IDS = "technique-ids.json"
VENDOR = "vendor"
MANIFEST = "VENDOR.json"

HMA = "hackmyagent"
AIIS = "aiis-signatures"
DVAA = "damn-vulnerable-ai-agent"
CHECK_IDS = f"{VENDOR}/{HMA}/check-ids.json"
OASB_CONTROLS = f"{VENDOR}/{HMA}/oasb-1-controls.json"
PAYLOAD_IDS = f"{VENDOR}/{HMA}/payload-ids.json"
AIIS_CROSSWALK = f"{VENDOR}/{AIIS}/crosswalks/technique-signatures.json"
AIIS_RETIRED = f"{VENDOR}/{AIIS}/retired-ids.yaml"
DVAA_EXPECTED = f"{VENDOR}/{DVAA}/expected-checks.json"

# Payload producers: the mapping file that fills the producer's column, and the vendored id
# list its payload ids resolve against (None: no list is vendored for that producer).
PAYLOAD_PRODUCERS = {
    "agentpwn": {"mapping": "mappings/agentpwn-payloads.json", "ids": None},
    "hackmyagent": {"mapping": "mappings/hackmyagent-payloads.json", "ids": PAYLOAD_IDS},
}

BASIS_EXPECTED_CHECK = "expected-check"
BASIS_AIIS_PRIMARY = "aiis-technique-id"
BASIS_AIIS_RELATED = "aiis-related-technique-id"

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class InputError(Exception):
    """An input is absent, not valid JSON, or not of the shape the rendering reads."""

    def __init__(self, path: str, message: str):
        super().__init__(f"{path}: {message}")
        self.path = path


def read_bytes(root: Path, rel: str) -> bytes:
    path = root / rel
    if not path.is_file():
        raise InputError(rel, "absent")
    return path.read_bytes()


def read_json(root: Path, rel: str):
    try:
        return json.loads(read_bytes(root, rel).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InputError(rel, f"not valid UTF-8 ({exc.reason} at byte {exc.start})") from None
    except ValueError as exc:
        raise InputError(rel, f"not valid JSON ({exc})") from None


def read_object(root: Path, rel: str) -> dict:
    value = read_json(root, rel)
    if not isinstance(value, dict):
        raise InputError(rel, "is not a JSON object")
    return value


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def string_list(value, rel: str, where: str) -> list:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise InputError(rel, f"{where} is not a list of strings")
    return value


def relative_path(value) -> bool:
    """A clean relative POSIX path that stays inside the directory it is read from."""
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and str(path) == value


def vendor_sources(root: Path) -> list:
    """The directories under vendor/ that hold a VENDOR.json, sorted."""
    vendor = root / VENDOR
    if not vendor.is_dir():
        raise InputError(f"{VENDOR}/", "absent")
    return sorted(p.name for p in vendor.iterdir() if p.is_dir() and (p / MANIFEST).is_file())


def load_manifest(root: Path, source: str) -> dict:
    rel = f"{VENDOR}/{source}/{MANIFEST}"
    return read_object(root, rel)


def input_entry(root: Path, source: str, manifest: dict) -> dict:
    rel = f"{VENDOR}/{source}/{MANIFEST}"
    files = string_list(manifest.get("files"), rel, "files")
    for name in files:
        if not relative_path(name):
            raise InputError(rel, f"files names {name!r}, which is not a relative path")
    if "package" in manifest:
        entry = {"package": manifest["package"], "version": manifest.get("version")}
    else:
        entry = {"repository": manifest.get("repo"), "commit": manifest.get("commit"),
                 "version": manifest.get("version")}
    entry["read"] = manifest.get("read")
    entry["files"] = [{"path": f"{VENDOR}/{source}/{name}",
                       "sha256": sha256(read_bytes(root, f"{VENDOR}/{source}/{name}"))}
                      for name in sorted(files)]
    return entry


def matrix_techniques(matrix: dict) -> dict:
    """{technique id: (hmaChecks, oasbControls)} from matrix.json."""
    techniques = matrix.get("techniques")
    if not isinstance(techniques, list):
        raise InputError(MATRIX, "techniques is not a list")
    out = {}
    for index, technique in enumerate(techniques):
        tid = technique.get("id") if isinstance(technique, dict) else None
        if not isinstance(tid, str):
            raise InputError(MATRIX, f"techniques[{index}] has no string id")
        if tid in out:
            raise InputError(MATRIX, f"technique {tid} appears twice")
        checks = string_list(technique.get("hmaChecks", []), MATRIX, f"{tid} hmaChecks")
        controls = string_list(technique.get("oasbControls", []), MATRIX, f"{tid} oasbControls")
        out[tid] = (sorted(set(checks)), sorted(set(controls)))
    return out


def vendored_check_ids(root: Path) -> list:
    return string_list(read_object(root, CHECK_IDS).get("checkIds"), CHECK_IDS, "checkIds")


def vendored_oasb_controls(root: Path) -> list:
    controls = read_object(root, OASB_CONTROLS).get("controls")
    if not isinstance(controls, list) or not all(
            isinstance(c, dict) and isinstance(c.get("id"), str) for c in controls):
        raise InputError(OASB_CONTROLS, "controls is not a list of objects with a string id")
    return [c["id"] for c in controls]


def vendored_signatures(root: Path) -> dict:
    """{signature id: [(technique id, basis)]} from the vendored aiis crosswalk."""
    by_signature = read_object(root, AIIS_CROSSWALK).get("bySignature")
    if not isinstance(by_signature, dict):
        raise InputError(AIIS_CROSSWALK, "bySignature is not an object")
    out = {}
    for sid, entry in by_signature.items():
        primary = entry.get("techniqueId") if isinstance(entry, dict) else None
        if not isinstance(primary, str):
            raise InputError(AIIS_CROSSWALK, f"{sid} has no string techniqueId")
        related = string_list(entry.get("relatedTechniqueIds", []), AIIS_CROSSWALK,
                              f"{sid} relatedTechniqueIds")
        edges = {(primary, BASIS_AIIS_PRIMARY)} | {(t, BASIS_AIIS_RELATED) for t in related}
        out[sid] = sorted(edges)
    return out


def vendored_scenarios(root: Path) -> dict:
    """{scenario: [expected check ids]} from the vendored DVAA file."""
    doc = read_object(root, DVAA_EXPECTED)
    return {name: sorted(set(string_list(value, DVAA_EXPECTED, name)))
            for name, value in doc.items()}


def not_assessed_reason(producer: str) -> str:
    mapping = PAYLOAD_PRODUCERS[producer]["mapping"]
    return (f"{mapping} does not exist; this column, byPayload.{producer} and "
            f"unjoined.payloadsInNoTechnique.{producer} are null until it does")


def build(root: Path) -> dict:
    """The crosswalk document for the tree at root."""
    matrix_bytes = read_bytes(root, MATRIX)
    ids_bytes = read_bytes(root, TECHNIQUE_IDS)
    matrix = read_object(root, MATRIX)
    techniques = matrix_techniques(matrix)

    sources = vendor_sources(root)
    manifests = {source: load_manifest(root, source) for source in sources}
    dates = [(MATRIX, matrix.get("updated"))] + [
        (f"{VENDOR}/{s}/{MANIFEST}", m.get("read")) for s, m in manifests.items()]
    for rel, value in dates:
        if not isinstance(value, str) or not DATE_RE.match(value):
            raise InputError(rel, f"date {value!r} is not YYYY-MM-DD")

    check_ids = vendored_check_ids(root)
    oasb_ids = vendored_oasb_controls(root)
    signatures = vendored_signatures(root)
    scenarios = vendored_scenarios(root)

    # A producer whose mapping file does not exist has no payload column: null, never [].
    payloads = {producer: None for producer in sorted(PAYLOAD_PRODUCERS)}

    by_technique = {}
    by_check, by_control, by_signature, by_scenario = {}, {}, {}, {}
    for tid in sorted(techniques):
        checks, controls = techniques[tid]
        aiis = sorted({(sid, basis) for sid, edges in signatures.items()
                       for technique, basis in edges if technique == tid})
        dvaa = []
        for scenario in sorted(scenarios):
            joined = sorted(set(checks) & set(scenarios[scenario]))
            if joined:
                dvaa.append({"scenario": scenario, "basis": BASIS_EXPECTED_CHECK,
                             "checks": joined})
                by_scenario.setdefault(scenario, []).append(
                    {"techniqueId": tid, "basis": BASIS_EXPECTED_CHECK, "checks": joined,
                     "relation": None})
        by_technique[tid] = {
            "hmaChecks": checks,
            "oasbControls": controls,
            "aiisSignatures": [{"id": sid, "basis": basis} for sid, basis in aiis],
            "dvaaScenarios": dvaa,
            "attackPayloads": dict(payloads),
        }
        for check in checks:
            by_check.setdefault(check, []).append({"techniqueId": tid, "relation": None})
        for control in controls:
            by_control.setdefault(control, []).append({"techniqueId": tid, "relation": None})

    for sid in sorted(signatures):
        by_signature[sid] = [{"techniqueId": tid, "basis": basis, "relation": None}
                             for tid, basis in signatures[sid]]

    listed_checks = {check for checks, _ in techniques.values() for check in checks}
    listed_controls = {control for _, controls in techniques.values() for control in controls}
    expected = {check for checks in scenarios.values() for check in checks}

    return {
        "schemaVersion": SCHEMA_VERSION,
        "generated": max(value for _, value in dates),
        "matrix": {
            "version": matrix.get("version"),
            "files": [{"path": MATRIX, "sha256": sha256(matrix_bytes)},
                      {"path": TECHNIQUE_IDS, "sha256": sha256(ids_bytes)}],
        },
        "inputs": {source: input_entry(root, source, manifests[source]) for source in sources},
        "byTechnique": by_technique,
        "byHmaCheck": {key: by_check[key] for key in sorted(by_check)},
        "byOasbControl": {key: by_control[key] for key in sorted(by_control)},
        "byAiisSignature": by_signature,
        "byDvaaScenario": {key: by_scenario[key] for key in sorted(by_scenario)},
        "byPayload": dict(payloads),
        "unjoined": {
            "oasbControlsInNoTechnique": sorted(set(oasb_ids) - listed_controls),
            "dvaaExpectedChecksInNoTechnique": sorted(expected - listed_checks),
            "hmaChecksInNoTechnique": sorted(set(check_ids) - listed_checks),
            "payloadsInNoTechnique": dict(payloads),
        },
        "notAssessed": [{"column": f"attackPayloads.{producer}",
                         "reason": not_assessed_reason(producer)}
                        for producer in sorted(PAYLOAD_PRODUCERS)],
    }


def render(root: Path) -> str:
    """The file text for the tree at root."""
    return json.dumps(build(root), indent=2, ensure_ascii=False) + "\n"


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description=DESCRIPTION, allow_abbrev=False)
    parser.add_argument("root", nargs="?", default=str(ROOT),
                        help="repository root (default: the parent of scripts/)")
    args = parser.parse_args(argv)
    root = Path(args.root)
    if not args.root or not root.is_dir():
        print(f"{args.root!r} is not a directory", file=sys.stderr)
        return 1
    try:
        text = render(root)
    except InputError as exc:
        print(f"cannot render {OUTPUT}: {exc}", file=sys.stderr)
        return 1
    (root / OUTPUT).write_bytes(text.encode("utf-8"))
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
