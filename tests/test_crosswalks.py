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

crosswalks/review.json is the entry-review record: one row per admitted entry, giving its
relation and the sha256 of its note, the entries withdrawn on review, and the techniques left
unmapped. scripts/check_cross_references.py (C9), which CI runs, holds matrix.json to it. The
tests below run that check on the shipped files, and on copies that each break one clause: an
entry with no row, a row twice, an entry twice, a changed relation, an edited note, a stale
row, a withdrawn entry restored, an unmapped list and a release that differ. Until the
reviewed corrections were applied to matrix.json the check reported 29 problems on it, so the
first of them was red.

The last tests give an entry, the record and a snapshot a string that is not valid Unicode
text, as the JSON escape \\ud800 alone decodes to, and one gives a note an escaped surrogate
pair, which is text. Until C9 reported a string that is not text in a line naming where it
stands, the run ended with a UnicodeEncodeError traceback when the note or the id of an
entry held one.
"""

import copy
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CROSSWALKS = ROOT / "crosswalks"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "crosswalks"
CHECKER = ROOT / "scripts" / "check_cross_references.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_cross_references", CHECKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHK = _load_checker()

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


# The entry-review record and the check that holds matrix.json to it.

REVIEW = CROSSWALKS / "review.json"
ROW_KEYS = ["technique", "field", "id", "relationship", "noteSha256", "reviewed"]
WITHDRAWN_KEYS = ["technique", "field", "id", "reviewed"]


def review_record() -> dict:
    return _load(REVIEW)


def snapshot_releases() -> dict:
    return {"attack": attack_release()["release"], "atlas": atlas_release()["release"]}


def review(techniques: list, record: dict = None, releases: dict = None) -> list:
    """The C9 problems of `techniques` against the shipped record and snapshots, or against
    the `record` and `releases` given in their place."""
    return CHK.review_problems(techniques,
                               review_record() if record is None else record,
                               snapshot_releases() if releases is None else releases)


def technique(techniques: list, tid: str) -> dict:
    return next(t for t in techniques if t["id"] == tid)


def first_with(techniques: list, *fields: str) -> dict:
    """The first technique that carries an entry in each of `fields`."""
    return next(t for t in techniques if all(t.get(field) for field in fields))


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_the_review_record_covers_every_crosswalk_entry():
    # Red until the reviewed corrections reached matrix.json: 16 relations and 3 notes that
    # differed, 2 withdrawn entries present with no row, 5 admitted entries absent, and an
    # unmapped list of 7 techniques where the review leaves 2.
    assert review(matrix()["techniques"]) == []


def test_an_entry_with_no_review_row_is_reported():
    techniques = copy.deepcopy(matrix()["techniques"])
    t = first_with(techniques, "attackMapping", "atlasMapping")
    taken = {e["id"] for e in t["attackMapping"]}
    eid = next(i for i in ("T1059", "T1078", "T1595") if i not in taken)
    t["attackMapping"].append({"id": eid, "relationship": "relatedMatch",
                               "note": f"ATT&CK {attack_release()['release']} an entry no review read"})
    assert review(techniques) == [
        f"C9 {t['id']} attackMapping {eid} has no review row in crosswalks/review.json"]


def test_a_changed_relation_is_reported():
    techniques = copy.deepcopy(matrix()["techniques"])
    t = first_with(techniques, "atlasMapping")
    entry = t["atlasMapping"][0]
    was = entry["relationship"]
    entry["relationship"] = "exactMatch" if was != "exactMatch" else "relatedMatch"
    assert review(techniques) == [
        f"C9 {t['id']} atlasMapping {entry['id']}: relationship {entry['relationship']} "
        f"differs from the reviewed {was}"]


def test_a_withdrawn_entry_restored_is_reported():
    techniques = copy.deepcopy(matrix()["techniques"])
    # The entry as it stood before the review withdrew it, and the field with it.
    technique(techniques, "T-5005").setdefault("attackMapping", []).append(
        {"id": "T1210", "relationship": "relatedMatch",
         "note": "ATT&CK 20.0 Exploitation of Remote Services: reaching database-level access "
                 "from the agent's SQL tool"})
    assert review(techniques) == [
        "C9 T-5005 attackMapping T1210 has no review row in crosswalks/review.json",
        "C9 T-5005 attackMapping T1210 was withdrawn on review and is present in matrix.json",
    ]


def test_an_edited_note_is_reported():
    techniques = copy.deepcopy(matrix()["techniques"])
    t = first_with(techniques, "atlasMapping")
    entry = t["atlasMapping"][0]
    reviewed = sha256(entry["note"])
    entry["note"] += " and one more claim"
    assert review(techniques) == [
        f"C9 {t['id']} atlasMapping {entry['id']}: note differs from its review row "
        f"(sha256 {sha256(entry['note'])}; the row records {reviewed})"]


def test_an_entry_whose_note_is_removed_is_reported():
    # The schema requires only id and relationship, so a note can go; its row still records
    # the note the review read.
    techniques = copy.deepcopy(matrix()["techniques"])
    t = first_with(techniques, "attackMapping")
    entry = t["attackMapping"][0]
    reviewed = sha256(entry.pop("note"))
    assert review(techniques) == [
        f"C9 {t['id']} attackMapping {entry['id']}: note differs from its review row "
        f"(the entry has no note; the row records {reviewed})"]


def test_a_review_row_with_no_entry_is_reported():
    techniques = copy.deepcopy(matrix()["techniques"])
    t = first_with(techniques, "attackMapping", "atlasMapping")
    gone = t.pop("attackMapping")
    assert review(techniques) == [
        f"C9 {t['id']} attackMapping {e['id']} is reviewed but absent from matrix.json"
        for e in sorted(gone, key=lambda e: e["id"])]


def test_an_entry_with_two_review_rows_is_reported():
    record = review_record()
    row = record["entries"][0]
    record["entries"].insert(1, dict(row))
    assert review(matrix()["techniques"], record) == [
        f"C9 {row['technique']} {row['field']} {row['id']} has 2 review rows in "
        f"crosswalks/review.json, not one"]


def test_an_entry_present_twice_is_reported():
    techniques = copy.deepcopy(matrix()["techniques"])
    t = first_with(techniques, "atlasMapping")
    t["atlasMapping"].append(dict(t["atlasMapping"][0]))
    assert review(techniques) == [
        f"C9 {t['id']} atlasMapping {t['atlasMapping'][0]['id']} appears 2 times in "
        f"matrix.json; its review row admits one entry"]


def test_an_unmapped_list_that_differs_is_reported():
    record = review_record()
    listed = record["unmapped"]
    record["unmapped"] = listed[1:]
    assert review(matrix()["techniques"], record) == [
        f"C9 crosswalks/review.json lists as unmapped {', '.join(listed[1:]) or 'none'}; the "
        f"techniques carrying no mapping are {', '.join(listed) or 'none'}"]


def test_a_release_other_than_the_snapshot_records_is_reported():
    record = review_record()
    newer = dict(snapshot_releases(), attack="99.0")
    assert review(matrix()["techniques"], record, newer) == [
        f"C9 crosswalks/review.json records ATT&CK {record['releases']['attack']}; "
        f"crosswalks/attack-release.json records 99.0"]


def test_the_review_record_keeps_its_published_form():
    # Sorted rows of fixed keys, written as json.dumps(indent=2, ensure_ascii=False) and a
    # newline, so the file's sha256 is a stable reference to the review it records.
    text = REVIEW.read_text(encoding="utf-8")
    record = json.loads(text)
    assert text == json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    assert list(record) == ["releases", "entries", "withdrawn", "unmapped"]
    assert list(record["releases"]) == ["attack", "atlas"]
    for key, keys in (("entries", ROW_KEYS), ("withdrawn", WITHDRAWN_KEYS)):
        rows = record[key]
        assert all(list(row) == keys for row in rows), f"a {key} row has keys other than {keys}"
        order = [(row["technique"], row["field"], row["id"]) for row in rows]
        assert order == sorted(order), f"the {key} rows are not sorted by technique, field and id"
    assert record["unmapped"] == sorted(record["unmapped"])


@pytest.mark.parametrize("content, line", [
    (None, "C9 crosswalks/review.json is missing or does not parse: no such file"),
    ("{", "C9 crosswalks/review.json is missing or does not parse: Expecting"),
    ("[]", "C9 crosswalks/review.json parses but has the wrong shape: the top level is an "
           "array, not an object"),
    ('{"releases": {"attack": "20.0", "atlas": "2026.09"}, "entries": [{"technique": "T-1001"}], '
     '"withdrawn": [], "unmapped": []}',
     "C9 crosswalks/review.json parses but has the wrong shape: entries[0] has no field"),
], ids=["missing", "not JSON", "an array", "a row with one key"])
def test_a_review_record_that_cannot_be_read_is_reported_in_one_line(content, line):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "crosswalks").mkdir()
        for name in ("attack-release.json", "atlas-release.json"):
            (root / "crosswalks" / name).write_bytes((CROSSWALKS / name).read_bytes())
        if content is not None:
            (root / "crosswalks" / "review.json").write_text(content, encoding="utf-8")
        failures = CHK.check_crosswalk_review(root, matrix()["techniques"])
    assert len(failures) == 1 and failures[0].startswith(line), failures


def test_the_checker_reports_the_crosswalk_review_clean():
    proc = subprocess.run([sys.executable, str(CHECKER)], capture_output=True, text=True,
                          timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK: crosswalk review clean" in proc.stdout, proc.stdout


# A string that is not valid Unicode text: what the six characters \ud800 in a JSON string
# decode to, a surrogate code point that is not half of a pair. The JSON is valid, and UTF-8
# cannot encode the string.

LONE_SURROGATE = json.loads('"\\ud800"')
NOT_TEXT = "a surrogate code point, which UTF-8 cannot encode"


def not_text(where: str, was: str) -> str:
    """The reason C9 gives for `where`, a string that read `was` before LONE_SURROGATE was
    appended to it."""
    return f"{where} is not valid Unicode text (character {len(was) + 1} is U+D800, {NOT_TEXT})"


def test_the_escape_the_cases_below_append_is_not_text():
    # The cases below prove nothing if the escape decoded to a character UTF-8 encodes.
    assert [f"U+{ord(c):04X}" for c in LONE_SURROGATE] == ["U+D800"]
    with pytest.raises(UnicodeEncodeError):
        LONE_SURROGATE.encode("utf-8")


def test_a_note_that_is_not_text_is_reported_in_one_line():
    # The note was hashed as UTF-8, so the check ended with a UnicodeEncodeError.
    techniques = copy.deepcopy(matrix()["techniques"])
    t = first_with(techniques, "atlasMapping")
    entry = t["atlasMapping"][0]
    was = entry["note"]
    entry["note"] += LONE_SURROGATE
    assert review(techniques) == [f"C9 {t['id']} atlasMapping {entry['id']}: "
                                  f"{not_text('note', was)}"]


def test_a_note_holding_an_escaped_surrogate_pair_is_text():
    # Both halves of a pair decode to one character, which UTF-8 encodes: the note is text,
    # and it differs from the one the review read.
    techniques = copy.deepcopy(matrix()["techniques"])
    t = first_with(techniques, "atlasMapping")
    entry = t["atlasMapping"][0]
    reviewed = sha256(entry["note"])
    entry["note"] += json.loads('"\\ud83d\\ude00"')
    assert review(techniques) == [
        f"C9 {t['id']} atlasMapping {entry['id']}: note differs from its review row "
        f"(sha256 {sha256(entry['note'])}; the row records {reviewed})"]


def test_a_relationship_that_is_not_text_is_reported_in_one_line():
    techniques = copy.deepcopy(matrix()["techniques"])
    t = first_with(techniques, "attackMapping")
    entry = t["attackMapping"][0]
    was = entry["relationship"]
    entry["relationship"] += LONE_SURROGATE
    assert review(techniques) == [f"C9 {t['id']} attackMapping {entry['id']}: "
                                  f"{not_text('relationship', was)}"]


def test_an_entry_whose_id_is_not_text_is_named_by_its_place_in_the_array():
    # A line holding the id cannot be written out as UTF-8, so the entry is named by
    # technique, field and index, as an entry of the wrong type is; the reviewed id it no
    # longer holds is absent.
    techniques = copy.deepcopy(matrix()["techniques"])
    t = first_with(techniques, "atlasMapping")
    entry = t["atlasMapping"][0]
    was = entry["id"]
    entry["id"] += LONE_SURROGATE
    assert review(techniques) == [
        f"C9 {t['id']} {not_text('atlasMapping[0].id', was)}",
        f"C9 {t['id']} atlasMapping {was} is reviewed but absent from matrix.json",
    ]


def crosswalk_review_of(record: dict = None, snapshots: dict = None) -> list:
    """The C9 failures of the shipped matrix.json against `record` and `snapshots`, a file
    name -> parsed snapshot map, with the shipped file for any not given. Each is written by
    json.dumps, which writes a string that is not text as the escape a contributor types."""
    given = dict(snapshots or {}, **({} if record is None else {"review.json": record}))
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "crosswalks").mkdir()
        for name in ("review.json", "attack-release.json", "atlas-release.json"):
            target = root / "crosswalks" / name
            if name in given:
                target.write_text(json.dumps(given[name], indent=2) + "\n", encoding="utf-8")
            else:
                target.write_bytes((CROSSWALKS / name).read_bytes())
        return CHK.check_crosswalk_review(root, matrix()["techniques"])


def test_the_shipped_files_written_by_json_dumps_are_clean():
    # The cases below prove nothing if writing the files this way failed them.
    assert crosswalk_review_of(review_record(), {"attack-release.json": attack_release(),
                                                 "atlas-release.json": atlas_release()}) == []


@pytest.mark.parametrize("path, where", [
    (("releases", "attack"), "releases.attack"),
    (("entries", 0, "id"), "entries[0].id"),
    (("entries", 0, "noteSha256"), "entries[0].noteSha256"),
    (("withdrawn", 0, "technique"), "withdrawn[0].technique"),
    (("unmapped", 0), "unmapped[0]"),
], ids=["release", "entry id", "entry noteSha256", "withdrawn technique", "unmapped"])
def test_a_string_of_the_review_record_that_is_not_text_is_its_wrong_shape(path, where):
    record = review_record()
    holder = record
    for step in path[:-1]:
        holder = holder[step]
    was = holder[path[-1]]
    holder[path[-1]] = was + LONE_SURROGATE
    assert crosswalk_review_of(record) == [
        f"C9 crosswalks/review.json parses but has the wrong shape: {not_text(where, was)}"]


def test_a_releases_key_of_the_review_record_that_is_not_text_is_its_wrong_shape():
    # The line for keys other than attack and atlas prints the keys.
    record = review_record()
    record["releases"]["atlas" + LONE_SURROGATE] = record["releases"].pop("atlas")
    assert crosswalk_review_of(record) == [
        f"C9 crosswalks/review.json parses but has the wrong shape: releases has a key that is "
        f"not valid Unicode text (character 6 is U+D800, {NOT_TEXT})"]


@pytest.mark.parametrize("name", ["attack-release.json", "atlas-release.json"])
def test_a_snapshot_release_that_is_not_text_is_its_wrong_shape(name):
    snapshot = _load(CROSSWALKS / name)
    was = snapshot["release"]
    snapshot["release"] = was + LONE_SURROGATE
    assert crosswalk_review_of(snapshots={name: snapshot}) == [
        f"C9 crosswalks/{name} parses but has the wrong shape: "
        f"{not_text('its release', was)}"]


def checker_run(data: dict) -> subprocess.CompletedProcess:
    """The checker run from a scratch copy of the files it reads, with `data` as its
    matrix.json, written by json.dumps, which writes a string that is not text as the escape
    a contributor types."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "scripts").mkdir()
        shutil.copy(CHECKER, root / "scripts" / CHECKER.name)
        shutil.copytree(ROOT / "cross-references", root / "cross-references")
        shutil.copytree(CROSSWALKS, root / "crosswalks")
        (root / "matrix.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return subprocess.run([sys.executable, str(root / "scripts" / CHECKER.name)],
                              capture_output=True, text=True, timeout=120)


def test_the_checker_run_from_a_scratch_copy_is_clean():
    # The cases below prove nothing if the scratch copy failed the check unchanged.
    proc = checker_run(matrix())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK: crosswalk review clean" in proc.stdout, proc.stdout


@pytest.mark.parametrize("key", ["note", "id"])
def test_the_checker_reports_an_entry_that_is_not_text_in_c9_lines(key):
    # Hashing the note and printing the line that named the id each ended the run with a
    # UnicodeEncodeError traceback.
    data = matrix()
    t = first_with(data["techniques"], "atlasMapping")
    entry = t["atlasMapping"][0]
    reviewed = f"{t['id']} atlasMapping {entry['id']}"
    was = entry[key]
    entry[key] += LONE_SURROGATE
    proc = checker_run(data)
    if key == "note":
        lines = [f"C9 {reviewed}: {not_text('note', was)}"]
    else:
        lines = [f"C9 {t['id']} {not_text('atlasMapping[0].id', was)}",
                 f"C9 {reviewed} is reviewed but absent from matrix.json"]
    assert (proc.returncode, proc.stderr) == (1, ""), proc.stdout + proc.stderr
    assert proc.stdout == (f"FAIL: {len(lines)} cross-reference check(s) failed:\n"
                           + "".join(f"  - {line}\n" for line in lines)), proc.stdout
