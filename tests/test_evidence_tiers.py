"""Evidence tier definition checker tests.

Every case runs scripts/check_evidence_tiers.py against a scratch copy of the canonical page,
the three quoting pages and the schema, so the committed files are never perturbed. The
shipped tree must be green. Each wording the three pages carried before docs/evidence-tiers.md
became the single definition is then planted back and must be reported at its own line, as
must a dropped definition, a definition wrapped over two lines, a canonical edit the quoting
pages do not follow, and a schema tier the canonical page does not define.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = (
    "README.md",
    "CONTRIBUTING.md",
    "EVIDENCE_AUDIT.md",
    "docs/evidence-tiers.md",
    "schema/threat-matrix-v1.2.schema.json",
    "scripts/check_evidence_tiers.py",
)

OBSERVED = "Confirmed in real-world production systems"
VALIDATED = "Reproduced in controlled lab environment (DVAA)"
ADAPTED = ("Well-understood traditional technique applied to agent context, "
           "not yet observed agent-specifically")


@pytest.fixture
def tree():
    td = Path(tempfile.mkdtemp(prefix="atm-tiers-"))
    for rel in FILES:
        dst = td / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    yield td
    shutil.rmtree(td)


def run_checker(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(root / "scripts" / "check_evidence_tiers.py")],
                          capture_output=True, text=True, timeout=120)


def mutate(root: Path, rel: str, old: str, new: str) -> int:
    """Replace the one occurrence of `old` in `rel` and return the line it starts on."""
    path = root / rel
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"mutation target must occur exactly once in {rel}: {old!r}"
    path.write_text(text.replace(old, new), encoding="utf-8")
    return text.count("\n", 0, text.index(old)) + 1


def test_shipped_tree_is_green(tree):
    r = run_checker(tree)
    assert r.returncode == 0, r.stderr
    assert "Evidence tier definitions match docs/evidence-tiers.md: 3 tiers" in r.stdout


@pytest.mark.parametrize("rel, old, new", [
    # The wordings the pages carried before this check existed.
    ("CONTRIBUTING.md", f"| **Observed** | {OBSERVED} |",
     "| **Observed** | Documented in a real-world production system, security incident "
     "report, or internet-wide exposure assessment |"),
    ("CONTRIBUTING.md", f"| **Validated** | {VALIDATED} |",
     "| **Validated** | Reproduced in a controlled lab environment with documented steps, "
     "expected output, and independent verification |"),
    ("EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
     f"- **OBSERVED**: {OBSERVED} (NemoClaw findings, exposure sweeps, npm attacks)\n"),
    ("EVIDENCE_AUDIT.md", f"- **VALIDATED**: {VALIDATED}\n",
     "- **VALIDATED**: Reproducible in controlled lab environment (DVAA challenges, "
     "HMA scan results)\n"),
    # One word changed in the README table.
    ("README.md", f"| **Adapted** | {ADAPTED} |",
     f"| **Adapted** | {ADAPTED.replace('Well-understood', 'Known')} |"),
])
def test_a_quote_that_differs_is_reported_at_its_line(tree, rel, old, new):
    line = mutate(tree, rel, old, new)
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"{rel}:{line}:" in r.stderr, r.stderr
    assert "quote docs/evidence-tiers.md" in r.stderr


def test_a_definition_wrapped_over_two_lines_is_reported(tree):
    line = mutate(tree, "EVIDENCE_AUDIT.md", f"- **ADAPTED**: {ADAPTED}\n",
                  "- **ADAPTED**: Well-understood traditional technique applied to agent "
                  "context,\n  not yet observed agent-specifically\n")
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"EVIDENCE_AUDIT.md:{line}: Adapted reads" in r.stderr, r.stderr


@pytest.mark.parametrize("rel, row", [
    ("README.md", f"| **Validated** | {VALIDATED} |"),
    ("CONTRIBUTING.md", f"| **Adapted** | {ADAPTED} |"),
    ("EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n"),
])
def test_a_page_that_leaves_a_tier_out_is_reported(tree, rel, row):
    path = tree / rel
    text = path.read_text(encoding="utf-8")
    start = text.index(row)
    end = text.index("\n", start) + 1
    path.write_text(text[:start] + text[end:], encoding="utf-8")
    r = run_checker(tree)
    assert r.returncode == 1
    tier = {"README.md": "Validated", "CONTRIBUTING.md": "Adapted",
            "EVIDENCE_AUDIT.md": "Observed"}[rel]
    assert f"{rel} does not define {tier}" in r.stderr, r.stderr


def test_a_canonical_edit_the_quotes_do_not_follow_is_reported_on_every_page(tree):
    mutate(tree, "docs/evidence-tiers.md", f"| `observed` | {OBSERVED} |",
           f"| `observed` | {OBSERVED} and incident reports |")
    r = run_checker(tree)
    assert r.returncode == 1
    for rel in ("README.md", "CONTRIBUTING.md", "EVIDENCE_AUDIT.md"):
        assert f"{rel}:" in r.stderr and "Observed reads" in r.stderr, r.stderr
    assert r.stderr.count("Observed reads") == 3, r.stderr


def test_a_canonical_edit_every_page_follows_is_green(tree):
    new = f"{OBSERVED} and incident reports"
    mutate(tree, "docs/evidence-tiers.md", f"| `observed` | {OBSERVED} |",
           f"| `observed` | {new} |")
    mutate(tree, "README.md", f"| **Observed** | {OBSERVED} |", f"| **Observed** | {new} |")
    mutate(tree, "CONTRIBUTING.md", f"| **Observed** | {OBSERVED} |",
           f"| **Observed** | {new} |")
    mutate(tree, "EVIDENCE_AUDIT.md", f"- **OBSERVED**: {OBSERVED}\n",
           f"- **OBSERVED**: {new}\n")
    r = run_checker(tree)
    assert r.returncode == 0, r.stderr


def test_a_canonical_tier_defined_twice_is_reported(tree):
    row = f"| Adapted | `adapted` | {ADAPTED} |\n"
    line = mutate(tree, "docs/evidence-tiers.md", row, row + row) + 1
    r = run_checker(tree)
    assert r.returncode == 1
    assert f"docs/evidence-tiers.md:{line}: defines `adapted` a second time" in r.stderr


def test_a_schema_tier_the_canonical_page_does_not_define_is_reported(tree):
    path = tree / "schema" / "threat-matrix-v1.2.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    schema["$defs"]["technique"]["properties"]["evidenceTier"]["enum"].append("theoretical")
    path.write_text(json.dumps(schema), encoding="utf-8")
    r = run_checker(tree)
    assert r.returncode == 1
    assert "docs/evidence-tiers.md does not define the `theoretical` tier" in r.stderr


def test_a_definition_inside_a_code_fence_is_not_a_quote(tree):
    path = tree / "CONTRIBUTING.md"
    path.write_text(path.read_text(encoding="utf-8")
                    + "\n```markdown\n| **Observed** | Anything at all |\n```\n",
                    encoding="utf-8")
    r = run_checker(tree)
    assert r.returncode == 0, r.stderr
