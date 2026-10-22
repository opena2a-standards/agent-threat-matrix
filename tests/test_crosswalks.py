"""The technique-level crosswalks in matrix.json resolve against the named releases.

Each technique may carry ``attackMapping`` and ``atlasMapping``, each entry naming an
external technique id, a SKOS relation and a note that names the release. The ids were read
from a git clone of the published data repositories; crosswalks/attack-release.json and
crosswalks/atlas-release.json hold the resolvable id -> name snapshot of each release.

These tests resolve every mapping id against the snapshot for its framework (a fixture whose
id is absent from the release fails), check the SKOS relation and the release name in each
note, assert that the ids in the table rows of crosswalks/unmapped.md equal the techniques
carrying no mapping, and assert that the notes name the release each snapshot records. They
read that release from the snapshots rather than naming it, so refreshing the snapshots
against a newer release does not edit them. Before the crosswalks were authored the matrix
held no mapping and these files did not exist, so the run was red; it is green once every
entry resolves.
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CROSSWALKS = ROOT / "crosswalks"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "crosswalks"

RELATIONS = {"exactMatch", "closeMatch", "broadMatch", "narrowMatch", "relatedMatch"}

# A row of the table in crosswalks/unmapped.md, whose first cell is the technique id it lists.
ROW_RE = re.compile(r"^\|\s*(T-\d{4})\s*\|", re.M)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def matrix() -> dict:
    return _load(ROOT / "matrix.json")


def attack_release() -> dict:
    return _load(CROSSWALKS / "attack-release.json")


def atlas_release() -> dict:
    return _load(CROSSWALKS / "atlas-release.json")


def listed_ids(text: str) -> list:
    """The technique ids unmapped.md lists: the first cell of each table row, in page order.

    The prose under the table names some of the listed ids to explain them, so an id read
    from the whole page would stay listed after its row was removed.
    """
    return ROW_RE.findall(text)


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
    listed = sorted(listed_ids((CROSSWALKS / "unmapped.md").read_text(encoding="utf-8")))
    assert listed == unmapped, {"listed": listed, "carry no mapping": unmapped}


def test_removing_any_row_of_the_unmapped_list_fails_the_membership_check():
    # The prose under the table names some of the listed ids to explain them. While the ids
    # were read from the whole page, deleting the row of such an id left it listed, and the
    # membership check above still passed.
    text = (CROSSWALKS / "unmapped.md").read_text(encoding="utf-8")
    rows = [line for line in text.splitlines(keepends=True) if ROW_RE.match(line)]
    assert rows, "unmapped.md has no table row"
    for row in rows:
        tid = ROW_RE.match(row).group(1)
        assert tid not in listed_ids(text.replace(row, "", 1)), f"{tid} is still listed with its row removed"


def test_the_unmapped_list_names_the_command_that_checks_it():
    # The page said its membership was "checked in CI-shaped tests" while no workflow ran
    # pytest. It names the command that runs this test, and says CI only once a workflow does.
    text = (CROSSWALKS / "unmapped.md").read_text(encoding="utf-8")
    workflow_dir = ROOT / ".github" / "workflows"
    workflows = "".join(p.read_text(encoding="utf-8")
                        for p in sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")]))
    assert "python3 -m pytest -q tests/test_crosswalks.py" in text
    if "pytest" not in workflows:
        assert not re.search(r"\bCI\b", text), "unmapped.md says CI, and no workflow runs pytest"


def test_an_unknown_id_fails_to_resolve():
    attack, atlas = attack_release(), atlas_release()
    fixture = _load(FIXTURES / "unknown_id.json")
    problems = unresolved(fixture["techniques"], attack, atlas)
    joined = "\n".join(problems)
    assert f"AML.T9999 is not a technique of ATLAS {atlas['release']}" in joined, problems
    assert f"T9999 is not a technique of ATT&CK {attack['release']}" in joined, problems
    # The real id in the same fixture resolves, so no problem names it.
    assert not any("AML.T0051.000" in p for p in problems), problems


def stale_releases(techniques: list, field: str, framework: str, release: str) -> list:
    """The releases other than `release` that the notes of `field` name, sorted.

    A note opens with the framework and the release it was read against ("ATT&CK 20.0 ..."),
    so the word after `framework` is read as that release. A refresh that moved the notes and
    not the snapshot, or the snapshot and not the notes, leaves the notes' release here.
    """
    opener = re.compile(re.escape(framework) + r" (\S+)")
    named = set()
    for technique in techniques:
        for entry in technique.get(field, []):
            m = opener.match(entry.get("note", ""))
            if m:
                named.add(m.group(1))
    return sorted(named - {release})


def test_release_snapshots_name_their_release_and_source():
    techniques = matrix()["techniques"]
    for field, framework, release, source in (
        ("attackMapping", "ATT&CK", attack_release(), "attack-stix-data"),
        ("atlasMapping", "ATLAS", atlas_release(), "atlas-data"),
    ):
        # The release is the snapshot's own, so refreshing a snapshot does not edit this test;
        # a snapshot the notes have moved past, or notes a snapshot has moved past, fail here.
        stale = stale_releases(techniques, field, framework, release["release"])
        assert not stale, (f"the {field} notes in matrix.json name {framework} {', '.join(stale)}, "
                           f"and the snapshot records {release['release']}")
        assert source in release["source"]
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", release["read"]), release["read"]
        assert isinstance(release["techniques"], dict) and release["techniques"]


def test_notes_that_name_another_release_than_the_snapshot_are_reported():
    techniques = [{"id": "T-0001", "attackMapping": [
        {"id": "T1595", "relationship": "broadMatch", "note": "ATT&CK 21.0 Active Scanning"}]}]
    assert stale_releases(techniques, "attackMapping", "ATT&CK", "20.0") == ["21.0"]
    assert stale_releases(techniques, "attackMapping", "ATT&CK", "21.0") == []
