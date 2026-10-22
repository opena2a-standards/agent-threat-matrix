"""The technique-level crosswalks in matrix.json resolve against the named releases.

Each technique may carry ``attackMapping`` and ``atlasMapping``, each entry naming an
external technique id, a SKOS relation and a note that names the release. The ids were read
from a git clone of the published data repositories; crosswalks/attack-release.json and
crosswalks/atlas-release.json hold the resolvable id -> name snapshot of each release.

These tests resolve every mapping id against the snapshot for its framework (a fixture whose
id is absent from the release fails), check the SKOS relation and the release name in each
note, and assert crosswalks/unmapped.md equals the techniques carrying no mapping. Before the
crosswalks were authored the matrix held no mapping and these files did not exist, so the run
was red; it is green once every entry resolves.
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CROSSWALKS = ROOT / "crosswalks"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "crosswalks"

RELATIONS = {"exactMatch", "closeMatch", "broadMatch", "narrowMatch", "relatedMatch"}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def matrix() -> dict:
    return _load(ROOT / "matrix.json")


def attack_release() -> dict:
    return _load(CROSSWALKS / "attack-release.json")


def atlas_release() -> dict:
    return _load(CROSSWALKS / "atlas-release.json")


def _schema_pattern(defs: str) -> re.Pattern:
    schema = _load(ROOT / "schema" / "threat-matrix-v1.2.schema.json")
    return re.compile(schema["$defs"][defs]["properties"]["id"]["pattern"])


def unresolved(techniques: list, attack: dict, atlas: dict) -> list:
    """Return one problem string per mapping entry that does not resolve.

    ``attack`` and ``atlas`` are the release index objects. An entry fails when its id is not
    a technique of the named release, its relation is not a SKOS relation, or its note does
    not name that release. The id grammar is the schema's, so a malformed id is reported too.
    """
    attack_re = _schema_pattern("attackMappingEntry")
    atlas_re = _schema_pattern("atlasMappingEntry")
    problems = []
    frameworks = {
        "attackMapping": (attack, attack_re, "ATT&CK " + attack["release"]),
        "atlasMapping": (atlas, atlas_re, "ATLAS " + atlas["release"]),
    }
    for technique in techniques:
        tid = technique.get("id")
        for field, (index, pattern, release) in frameworks.items():
            for entry in technique.get(field, []):
                eid = entry.get("id", "")
                if not pattern.fullmatch(eid):
                    problems.append(f"{tid}: {field} id {eid!r} does not match the schema grammar")
                elif eid not in index["techniques"]:
                    problems.append(f"{tid}: {field} id {eid} is not a technique of {release}")
                if entry.get("relationship") not in RELATIONS:
                    problems.append(f"{tid}: {field} relationship {entry.get('relationship')!r} is not a SKOS relation")
                note = entry.get("note", "")
                if release not in note:
                    problems.append(f"{tid}: {field} note does not name {release}")
    return problems


def test_every_mapping_id_resolves_against_the_named_release():
    problems = unresolved(matrix()["techniques"], attack_release(), atlas_release())
    assert problems == [], problems


def test_mappings_are_populated_and_match_the_unmapped_list():
    techniques = matrix()["techniques"]
    mapped = [t["id"] for t in techniques if t.get("attackMapping") or t.get("atlasMapping")]
    unmapped = sorted(t["id"] for t in techniques if not (t.get("attackMapping") or t.get("atlasMapping")))
    # Populated: the before-state was zero, so this is the regression that was red.
    assert mapped, "no technique carries a crosswalk"
    listed = sorted(set(re.findall(r"\bT-\d{4}\b", (CROSSWALKS / "unmapped.md").read_text(encoding="utf-8"))))
    assert listed == unmapped, {"listed": listed, "carry no mapping": unmapped}


def test_an_unknown_id_fails_to_resolve():
    fixture = _load(FIXTURES / "unknown_id.json")
    problems = unresolved(fixture["techniques"], attack_release(), atlas_release())
    joined = "\n".join(problems)
    assert "AML.T9999 is not a technique of ATLAS 2026.09" in joined, problems
    assert "T9999 is not a technique of ATT&CK 20.0" in joined, problems
    # The real id in the same fixture resolves, so only the unknown ids are reported.
    assert not any("AML.T0051.000" in p for p in problems), problems


def test_release_snapshots_name_their_release_and_source():
    for release, expected, source in (
        (attack_release(), "20.0", "attack-stix-data"),
        (atlas_release(), "2026.09", "atlas-data"),
    ):
        assert release["release"] == expected
        assert source in release["source"]
        assert release["read"] and isinstance(release["techniques"], dict) and release["techniques"]
