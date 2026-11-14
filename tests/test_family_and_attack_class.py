"""A technique's family and its canonical attack class are two fields, and each reader reads one.

matrix.json gave each technique one field, ``attackClass``, that held a family code such as
RAG-POISON: the id of an entry in the top-level ``attackClasses``, which is the attack vector.
None of its 23 values was one of the ten canonical attack classes that canonical-classes.json
maps to technique ids. The field holding the family is now ``family``, and ``attackClass``
holds the technique's canonical class, the one whose ``primary`` array lists it.

These cases hold the data to that, and hold each script that read the old field to the field
it means: the class pages and the README class tables group techniques by ``family``,
scripts/check_canonical_classes.py (V7) holds ``attackClass`` to canonical-classes.json, and
scripts/check_live_api_drift.py finds a hollow class from the family a served technique
names. No case uses the network, and every case that writes runs on a scratch copy.
"""

import copy
import importlib.util
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MATRIX = json.loads((ROOT / "matrix.json").read_text(encoding="utf-8"))
CANONICAL_FILE = json.loads((ROOT / "canonical-classes.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((ROOT / "schema" / "threat-matrix-v1.2.schema.json").read_text(encoding="utf-8"))
CHECKER = Path("scripts") / "check_canonical_classes.py"

# The classifier's label set, in the order canonical-classes.json lists it.
CANONICAL_CLASSES = ("injection", "exfiltration", "credential_abuse", "privilege_escalation",
                     "persistence", "lateral_movement", "social_engineering", "policy_violation",
                     "steganography", "benign")


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _primary_class(tid: str) -> str:
    return next(name for name, entry in CANONICAL_FILE["classes"].items() if tid in entry["primary"])


# --------------------------------------------------------------------------- the data

def test_every_attack_class_in_matrix_json_is_one_of_the_ten_canonical_classes():
    outside = {t["id"]: t.get("attackClass") for t in MATRIX["techniques"]
               if t.get("attackClass") not in CANONICAL_CLASSES}
    assert not outside, f"attackClass is not a canonical class on {len(outside)} techniques: {outside}"


def test_every_attack_class_is_the_class_whose_primary_array_lists_the_technique():
    differ = {t["id"]: (t.get("attackClass"), _primary_class(t["id"]))
              for t in MATRIX["techniques"] if t.get("attackClass") != _primary_class(t["id"])}
    assert not differ, differ


def test_every_family_names_an_entry_of_attack_classes():
    families = {c["id"] for c in MATRIX["attackClasses"]}
    outside = {t["id"]: t.get("family") for t in MATRIX["techniques"] if t.get("family") not in families}
    assert not outside, outside


def test_the_ten_classes_are_the_same_in_the_schema_and_canonical_classes_json():
    technique = SCHEMA["$defs"]["technique"]
    assert technique["properties"]["attackClass"] == {
        "$ref": "#/$defs/canonicalClass",
        "x-semantic": technique["properties"]["attackClass"]["x-semantic"],
    }
    assert SCHEMA["$defs"]["canonicalClass"]["enum"] == list(CANONICAL_CLASSES)
    assert list(CANONICAL_FILE["classes"]) == list(CANONICAL_CLASSES)
    assert {"family", "attackClass"} <= set(technique["required"])


# --------------------------------------------------------------------------- V7

def _scratch(edit_matrix=None, edit_canonical=None) -> Path:
    td = Path(tempfile.mkdtemp(prefix="atm-attack-class-"))
    (td / "scripts").mkdir()
    shutil.copy(ROOT / CHECKER, td / CHECKER)
    matrix = copy.deepcopy(MATRIX)
    canonical = copy.deepcopy(CANONICAL_FILE)
    if edit_matrix:
        edit_matrix(next(t for t in matrix["techniques"] if t["id"] == "T-2002"))
    if edit_canonical:
        edit_canonical(canonical["classes"])
    (td / "matrix.json").write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")
    (td / "canonical-classes.json").write_text(json.dumps(canonical, indent=1) + "\n",
                                               encoding="utf-8")
    return td


def _run(td: Path) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["python3", str(td / CHECKER)], capture_output=True, text=True,
                              timeout=60)
    finally:
        shutil.rmtree(td)


def _set(value):
    def edit(technique):
        technique["attackClass"] = value
    return edit


def _drop(technique):
    del technique["attackClass"]


def _move_t2002_to_exfiltration(classes):
    classes["injection"]["primary"].remove("T-2002")
    classes["exfiltration"]["primary"] = sorted(classes["exfiltration"]["primary"] + ["T-2002"])


V7_CASES = [
    ("a family code", _set("RAG-POISON"), None,
     'V7 T-2002: attackClass "RAG-POISON" is not one of the 10 canonical classes'),
    ("another canonical class", _set("exfiltration"), None,
     'V7 T-2002: attackClass "exfiltration" is not "injection", the class whose primary array '
     'lists it'),
    ("benign", _set("benign"), None,
     'V7 T-2002: attackClass "benign" is not "injection", the class whose primary array lists it'),
    ("no attackClass", _drop, None, "V7 T-2002: matrix.json gives it no attackClass"),
    ("a number", _set(5), None, "V7 T-2002: attackClass is a number, not a string"),
    ("null", _set(None), None, "V7 T-2002: attackClass is null, not a string"),
    ("a mapping that moved the technique", None, _move_t2002_to_exfiltration,
     'V7 T-2002: attackClass "injection" is not "exfiltration", the class whose primary array '
     'lists it'),
]


def test_v7_is_green_on_the_shipped_tree():
    proc = _run(_scratch())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip() == "canonical-classes.json OK: 61 technique ids across 10 classes"


@pytest.mark.parametrize("edit_matrix,edit_canonical,line",
                         [case[1:] for case in V7_CASES], ids=[case[0] for case in V7_CASES])
def test_v7_refuses_an_attack_class_the_mapping_does_not_give(edit_matrix, edit_canonical, line):
    proc = _run(_scratch(edit_matrix, edit_canonical))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stderr.splitlines() == [line, "canonical-classes.json: 1 violation(s)"]


def test_v7_leaves_a_technique_no_primary_array_lists_to_v3():
    def drop_from_primary(classes):
        classes["injection"]["primary"].remove("T-2002")
    proc = _run(_scratch(None, drop_from_primary))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stderr.splitlines() == ["V3 id missing from every primary array: T-2002",
                                        "canonical-classes.json: 1 violation(s)"]


# --------------------------------------------------------------------------- class pages

def _without_declared_member(cid: str, tid: str) -> dict:
    """matrix.json with ``tid`` dropped from the techniques the class ``cid`` declares."""
    matrix = copy.deepcopy(MATRIX)
    cls = next(c for c in matrix["attackClasses"] if c["id"] == cid)
    cls["techniques"].remove(tid)
    return matrix


def test_a_class_page_lists_a_technique_of_its_family_that_the_class_does_not_declare():
    generator = _load("generate_class_markdown", "scripts/generate_class_markdown.py")
    pages = generator.render_pages(_without_declared_member("RAG-POISON", "T-2002"))
    assert "| [T-2002](../techniques/T-2002.md) |" in pages["RAG-POISON.md"]


def test_the_readme_class_table_lists_a_technique_of_its_family_that_the_class_does_not_declare():
    checker = _load("check_readme_claims", "scripts/check_readme_claims.py")
    tables = checker.render_class_tables(_without_declared_member("RAG-POISON", "T-2002"))
    row = next(line for line in tables.splitlines() if line.startswith("| [RAG-POISON]"))
    assert row.endswith("| T-2002, T-7006 |"), row


def test_a_canonical_class_adds_no_member_to_a_class_page_or_table():
    generator = _load("generate_class_markdown", "scripts/generate_class_markdown.py")
    checker = _load("check_readme_claims", "scripts/check_readme_claims.py")
    assert generator.render_pages(MATRIX) == generator.render_pages(
        {**MATRIX, "techniques": [{**t, "attackClass": "persistence"} for t in MATRIX["techniques"]]})
    assert checker.render_class_tables(MATRIX) == checker.render_class_tables(
        {**MATRIX, "techniques": [{**t, "attackClass": "persistence"} for t in MATRIX["techniques"]]})


# --------------------------------------------------------------------------- live drift

DRIFT = _load("check_live_api_drift", "scripts/check_live_api_drift.py")


def _emptied(live: dict, cid: str) -> dict:
    next(c for c in live["attackClasses"] if c["id"] == cid)["techniques"] = []
    return live


def _served_before_the_rename() -> dict:
    """A payload as the registry imported matrix.json while the family was named attackClass."""
    live = copy.deepcopy(MATRIX)
    for technique in live["techniques"]:
        technique["attackClass"] = technique.pop("family")
    return live


def test_a_payload_with_family_and_canonical_classes_has_no_hollow_class():
    assert DRIFT.hollow_classes(copy.deepcopy(MATRIX)) == ([], None)


def test_a_hollow_class_is_found_from_the_family():
    assert DRIFT.hollow_classes(_emptied(copy.deepcopy(MATRIX), "RAG-POISON")) == (["RAG-POISON"], None)


def test_a_payload_served_before_the_rename_is_read_with_a_note():
    hollow, note = DRIFT.hollow_classes(_emptied(_served_before_the_rename(), "RAG-POISON"))
    assert hollow == ["RAG-POISON"]
    assert note.startswith("the live API serves no technique family field")


def test_a_payload_with_no_techniques_carries_no_note():
    assert DRIFT.hollow_classes({"techniques": [], "attackClasses": []}) == ([], None)
