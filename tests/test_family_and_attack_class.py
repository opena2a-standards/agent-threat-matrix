"""A technique's family and its canonical attack class are two fields, and each reader reads one.

matrix.json gave each technique one field, ``attackClass``, that held a family code such as
RAG-POISON: the id of an entry in the top-level ``attackClasses``, which is the attack vector.
None of its 23 values was one of the ten canonical attack classes that canonical-classes.json
maps to technique ids. The field holding the family is now ``family``, and ``attackClass``
holds the technique's canonical class, the one whose ``primary`` array lists it.

These cases hold the data to that, and hold each script that read the old field to the field
it means: the class pages and the README class tables group techniques by ``family``,
scripts/check_canonical_classes.py (V7) holds ``attackClass`` to canonical-classes.json, and
scripts/check_live_api_drift.py finds a hollow family from the family a served technique
names, and the lines it prints about the entries of the top-level ``attackClasses`` call
each entry a family. No case uses the network, and every case that writes runs on a
scratch copy.

The names around the data are held to the same split. In the schema, a name that says
attack class holds one of the ten classes, apart from the top-level ``attackClasses``,
which keeps its name, and an entry of that array is defined as ``family``, its id as
``familyId``. In the STIX bundle, the committed copy and a fresh rendering, no property
named for attack class holds a family, and each family grouping names its family in
``x_family_id`` under the grouping id it had before the property was renamed.
scripts/derive_class_checks.py calls the entries it derives checks for families.
"""

import copy
import importlib.util
import io
import json
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MATRIX = json.loads((ROOT / "matrix.json").read_text(encoding="utf-8"))
CANONICAL_FILE = json.loads((ROOT / "canonical-classes.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((ROOT / "schema" / "threat-matrix-v1.2.schema.json").read_text(encoding="utf-8"))
STIX = json.loads((ROOT / "stix" / "agent-threat-matrix-bundle.json").read_text(encoding="utf-8"))
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


HOLLOW_FAMILY_LINE = ("  - families that a served technique names and whose live attackClasses "
                      "entry is missing or lists no technique: RAG-POISON")


def _run_drift(monkeypatch, live: dict) -> int:
    """Run the drift check's main() in a scratch directory holding matrix.json and a README
    without the sentence about the live API's version, with ``live`` served by a stub of
    urlopen, so the lines it prints are about the families alone."""
    td = Path(tempfile.mkdtemp(prefix="atm-drift-family-"))
    try:
        shutil.copy(ROOT / "matrix.json", td / "matrix.json")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        (td / "README.md").write_text(
            "\n".join(line for line in readme.splitlines() if "labels the matrix" not in line),
            encoding="utf-8")
        body = json.dumps(live).encode()
        monkeypatch.setattr(DRIFT.urllib.request, "urlopen",
                            lambda url, timeout=None: io.BytesIO(body))
        monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
        monkeypatch.chdir(td)
        return DRIFT.main()
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_the_drift_check_prints_a_hollow_family_as_a_family(monkeypatch, capsys):
    rc = _run_drift(monkeypatch, _emptied(copy.deepcopy(MATRIX), "RAG-POISON"))
    out = capsys.readouterr().out
    assert rc == 1, out
    assert out.splitlines() == [
        "FAIL: live registry drifts from matrix.json (1 finding(s)):",
        HOLLOW_FAMILY_LINE,
    ]


def test_the_drift_check_prints_a_family_the_live_api_lacks_as_a_family(monkeypatch, capsys):
    live = copy.deepcopy(MATRIX)
    live["attackClasses"] = [c for c in live["attackClasses"] if c["id"] != "RAG-POISON"]
    rc = _run_drift(monkeypatch, live)
    out = capsys.readouterr().out
    n = len(MATRIX["attackClasses"])
    assert rc == 1, out
    assert out.splitlines() == [
        "FAIL: live registry drifts from matrix.json (2 finding(s)):",
        f"  - families (attackClasses): live API has {n - 1}, matrix.json has {n}",
        HOLLOW_FAMILY_LINE,
    ]


def test_the_drift_check_prints_a_hollow_family_served_before_the_rename_as_a_family(
        monkeypatch, capsys):
    rc = _run_drift(monkeypatch, _emptied(_served_before_the_rename(), "RAG-POISON"))
    out = capsys.readouterr().out
    assert rc == 1, out
    assert out.splitlines() == [
        "NOTE: the live API serves no technique family field, so each technique's attackClass "
        "is read as its family, as matrix.json named the field before it was renamed family "
        "(pending registry re-import)",
        "FAIL: live registry drifts from matrix.json (1 finding(s)):",
        HOLLOW_FAMILY_LINE,
    ]


# --------------------------------------------------------------------------- names

# The top-level array keeps its name, as docs/attack-classes.md states; its entries are
# families, and the schema defines one as family.
KEPT_NAMES = {"#/properties/attackClasses"}


def _says_attack_class(name: str) -> bool:
    """True for a name that says attack class in any spelling: attackClass, attackClassId,
    x_attack_class_id."""
    return "attackclass" in re.sub(r"[^a-z]", "", name.lower())


def _named_schemas(node, path="#"):
    """(path, name, subschema) for each name that a $defs or a properties object of the
    schema defines, at any depth."""
    if isinstance(node, list):
        for i, item in enumerate(node):
            yield from _named_schemas(item, f"{path}/{i}")
        return
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if key in ("$defs", "properties") and isinstance(value, dict):
            for name, sub in value.items():
                yield f"{path}/{key}/{name}", name, sub
                yield from _named_schemas(sub, f"{path}/{key}/{name}")
        else:
            yield from _named_schemas(value, f"{path}/{key}")


def test_every_schema_name_that_says_attack_class_holds_a_canonical_class():
    named = [path for path, name, _ in _named_schemas(SCHEMA) if _says_attack_class(name)]
    assert "#/$defs/technique/properties/attackClass" in named
    wrong = sorted(path for path, name, sub in _named_schemas(SCHEMA)
                   if _says_attack_class(name) and path not in KEPT_NAMES
                   and sub.get("$ref") != "#/$defs/canonicalClass")
    assert not wrong, f"named for attack class, defined as something else: {wrong}"


def test_an_entry_of_attack_classes_and_a_technique_family_take_the_family_definitions():
    defs = SCHEMA["$defs"]
    assert SCHEMA["properties"]["attackClasses"]["items"] == {"$ref": "#/$defs/family"}
    assert defs["family"]["properties"]["id"] == {"$ref": "#/$defs/familyId"}
    assert defs["technique"]["properties"]["family"]["$ref"] == "#/$defs/familyId"


def _properties(node):
    """(name, value) for each property of a STIX object, nested ones included."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield key, value
            yield from _properties(value)
    elif isinstance(node, list):
        for item in node:
            yield from _properties(item)


def _rendered_bundle() -> dict:
    generator = _load("generate_stix", "scripts/generate_stix.py")
    return json.loads(generator.render(copy.deepcopy(MATRIX)))


@pytest.mark.parametrize("which", ["committed", "rendered"])
def test_no_stix_property_named_for_attack_class_holds_anything_but_a_canonical_class(which):
    bundle = STIX if which == "committed" else _rendered_bundle()
    wrong = [(key, value) for key, value in _properties(bundle["objects"])
             if _says_attack_class(key) and value not in CANONICAL_CLASSES]
    assert not wrong, f"{len(wrong)} properties named for attack class hold another value: {wrong[:3]}"


def test_each_family_grouping_names_its_family_in_x_family_id():
    families = {family["id"]: family for family in MATRIX["attackClasses"]}
    groupings = [obj for obj in STIX["objects"] if obj["type"] == "grouping"]
    assert sorted(obj.get("x_family_id", "") for obj in groupings) == sorted(families)
    for obj in groupings:
        family = families[obj["x_family_id"]]
        assert (obj["name"], obj["x_category"]) == (family["name"], family["category"])


def test_a_family_grouping_keeps_the_id_it_had_before_the_property_was_renamed():
    # The canonical name of a grouping is class:<family id>, as it was while the property
    # was x_attack_class_id, so its uuid5 id is the one published then.
    generator = _load("generate_stix", "scripts/generate_stix.py")
    namespace = uuid.UUID(MATRIX["stixNamespace"])
    for obj in (obj for obj in STIX["objects"] if obj["type"] == "grouping"):
        assert obj["id"] == generator.stix_id(namespace, "grouping", f"class:{obj['x_family_id']}")


# --------------------------------------------------------------------------- derived checks

TAXONOMY = ("const TAXONOMY_MAP: Record<string, string> = {\n"
            "  'MEM-001': 'MEM-POISON',\n"
            "  'ZZZ-001': 'NOT-A-FAMILY',\n"
            "};\n")


def test_derive_class_checks_calls_the_entries_it_derives_checks_for_families():
    td = Path(tempfile.mkdtemp(prefix="atm-derive-"))
    try:
        (td / "tree" / "scripts").mkdir(parents=True)
        shutil.copy(ROOT / "scripts" / "derive_class_checks.py", td / "tree" / "scripts")
        shutil.copy(ROOT / "matrix.json", td / "tree" / "matrix.json")
        (td / "hma" / "src" / "hardening").mkdir(parents=True)
        (td / "hma" / "src" / "hardening" / "taxonomy.ts").write_text(TAXONOMY, encoding="utf-8")
        proc = subprocess.run(["python3", str(td / "tree" / "scripts" / "derive_class_checks.py"),
                               str(td / "hma")], capture_output=True, text=True, timeout=60)
        derived = json.loads((td / "tree" / "matrix.json").read_text(encoding="utf-8"))
    finally:
        shutil.rmtree(td)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    families = [family["id"] for family in MATRIX["attackClasses"]]
    expected = {fid: (["MEM-001"] if fid == "MEM-POISON" else []) for fid in families}
    changed = sum(1 for family in MATRIX["attackClasses"]
                  if (family.get("hmaChecks") or []) != expected[family["id"]])
    assert proc.stdout.splitlines() == [
        f"Derived hmaChecks for {len(families)} families ({changed} changed) from 2 mapped checks.",
        f"QUARANTINED (not one of the {len(families)} families in matrix.json): "
        "NOT-A-FAMILY -> ZZZ-001",
        "Families with no HMA checks mapped: " + ", ".join(f for f in families if f != "MEM-POISON"),
    ]
    assert {family["id"]: family["hmaChecks"] for family in derived["attackClasses"]} == expected
