"""The ATLAS tactic mapping is read against a stated ATLAS release, one row per tactic.

The checker under test is C8 of scripts/check_cross_references.py. It is GREEN on the
shipped page and RED on the pre-change page (tests/fixtures/pre_change/), which held 11
rows under older tactic names against the 16 tactics ATLAS publishes and stated no
release.
"""

import importlib.util
import re
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CROSSREF = ROOT / "cross-references"
ATLAS_PAGE = CROSSREF / "mitre-atlas-mapping.md"
PRE_CHANGE_PAGE = Path(__file__).resolve().parent / "fixtures" / "pre_change" / "mitre-atlas-mapping.md"
README = ROOT / "README.md"
# The README's scope lists moved to the overview page, and its sentence on the catalogs that
# already exist to the use-cases page.
OVERVIEW = ROOT / "docs" / "overview.md"
USE_CASES = ROOT / "docs" / "use-cases.md"


def _load_checker():
    spec = importlib.util.spec_from_file_location(
        "check_cross_references", ROOT / "scripts" / "check_cross_references.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHK = _load_checker()

# A sample table: one well-formed row per pinned tactic, in order.
GOOD_ROWS = [f"| **{name}** ({tid}) | None | None | Note. |" for tid, name in CHK.ATLAS_TACTICS]


def _page(rows, release=True):
    head = f"Read against ATLAS release {CHK.ATLAS_RELEASE}.\n\n" if release else "No release.\n\n"
    table = "| ATLAS Tactic | ATM Tactic(s) | Overlap | Notes |\n|---|---|---|---|\n"
    return head + table + "\n".join(rows) + "\n"


def test_pin_holds_sixteen_distinct_tactics():
    ids = [tid for tid, _name in CHK.ATLAS_TACTICS]
    names = [name for _tid, name in CHK.ATLAS_TACTICS]
    assert len(ids) == 16 and len(set(ids)) == 16 and len(set(names)) == 16


def test_shipped_page_has_one_row_per_pinned_tactic():
    text = ATLAS_PAGE.read_text()
    assert len(re.findall(r"^\| \*\*", text, re.M)) == len(CHK.ATLAS_TACTICS)
    rows = [(tid, name) for _n, tid, name, _line in CHK.parse_atlas_rows(text)]
    assert rows == list(CHK.ATLAS_TACTICS)


def test_shipped_page_is_green():
    assert CHK.check_atlas_mapping(ATLAS_PAGE.read_text()) == []
    assert [f for f in CHK.run_checks(ROOT) if f.startswith("C8 ")] == []


def test_pre_change_page_is_red():
    failures = CHK.check_atlas_mapping(PRE_CHANGE_PAGE.read_text())
    text = "\n".join(failures)
    assert f"ATLAS release {CHK.ATLAS_RELEASE}" in text, "the missing release must be reported"
    for tid, name in (
        ("AML.TA0012", "Privilege Escalation"),
        ("AML.TA0013", "Credential Access"),
        ("AML.TA0015", "Lateral Movement"),
        ("AML.TA0001", "AI Attack Adaptation"),
        ("AML.TA0014", "Command and Control"),
    ):
        assert f"ATLAS tactic {tid} {name} has no row" in text, f"{name} must be reported missing"
    # Rows that carry no tactic id ("**ML Model Access**", "**Evasion**") are refused.
    assert sum("does not read '**Name** (AML.TA####)'" in f for f in failures) == 11


def test_pre_change_page_fails_the_whole_checker():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        shutil.copytree(CROSSREF, tmp / "cross-references")
        shutil.copy(ROOT / "matrix.json", tmp / "matrix.json")
        shutil.copy(PRE_CHANGE_PAGE, tmp / "cross-references" / CHK.ATLAS_NAME)
        assert any(f.startswith("C8 ") for f in CHK.run_checks(tmp))


def test_well_formed_sample_is_green():
    assert CHK.check_atlas_mapping(_page(GOOD_ROWS)) == []


def test_missing_release_is_red():
    failures = CHK.check_atlas_mapping(_page(GOOD_ROWS, release=False))
    assert len(failures) == 1 and "does not state the ATLAS release" in failures[0]


def test_retired_tactic_name_is_red():
    rows = [r.replace("**AI Attack Adaptation**", "**AI Attack Staging**") for r in GOOD_ROWS]
    failures = CHK.check_atlas_mapping(_page(rows))
    assert len(failures) == 1
    assert "AML.TA0001 is named 'AI Attack Staging'" in failures[0]
    assert "'AI Attack Adaptation'" in failures[0]


def test_unknown_tactic_id_is_red():
    rows = GOOD_ROWS + ["| **Invented** (AML.TA0099) | None | None | Note. |"]
    failures = CHK.check_atlas_mapping(_page(rows))
    assert failures == [
        f"C8 {CHK.ATLAS_NAME}:{4 + len(rows)}: AML.TA0099 is not a tactic of ATLAS release "
        f"{CHK.ATLAS_RELEASE}"
    ]


def test_duplicate_row_is_red():
    rows = GOOD_ROWS + [GOOD_ROWS[-1]]
    failures = CHK.check_atlas_mapping(_page(rows))
    assert len(failures) == 1 and "AML.TA0011 has more than one row" in failures[0]


def test_missing_row_is_red():
    rows = [r for r in GOOD_ROWS if "(AML.TA0014)" not in r]
    failures = CHK.check_atlas_mapping(_page(rows))
    assert len(failures) == 1
    assert "ATLAS tactic AML.TA0014 Command and Control has no row" in failures[0]


def test_out_of_order_rows_are_red():
    rows = [GOOD_ROWS[1], GOOD_ROWS[0]] + GOOD_ROWS[2:]
    failures = CHK.check_atlas_mapping(_page(rows))
    assert len(failures) == 1 and "not in ATLAS matrix order" in failures[0]


def test_technique_ids_in_the_table_are_red():
    for token in ("T-2006", "AML.T0081", "AML.T0080.000"):
        rows = list(GOOD_ROWS)
        rows[6] = rows[6].replace("Note.", f"Note {token}.")
        failures = CHK.check_atlas_mapping(_page(rows))
        assert len(failures) == 1 and "names technique ids" in failures[0], (token, failures)


def test_readme_scope_lines_do_not_limit_atlas_to_models():
    for page in (README, OVERVIEW, USE_CASES):
        assert "and models (MITRE ATLAS)" not in page.read_text(), page
    text = OVERVIEW.read_text()
    scope = [line for line in text.splitlines() if line.startswith("- Model-level attacks")]
    assert scope and "agent" in scope[0], scope


# The quoted description of ATLAS is in the notes of atlas-data release v2026.08
# (published 2026-09-01), not in those of v2026.09, the release the page is read against.
ATLAS_QUOTE = "harmful autonomous behavior materially enabled by AI"


def test_quoted_atlas_description_names_the_release_it_comes_from():
    para = next((p for p in ATLAS_PAGE.read_text().split("\n\n") if ATLAS_QUOTE in p), None)
    assert para, "the page no longer quotes the ATLAS description"
    sentence = para.split(ATLAS_QUOTE)[0].rsplit(". ", 1)[-1]
    assert "2026.08" in sentence and CHK.ATLAS_RELEASE not in sentence, sentence
