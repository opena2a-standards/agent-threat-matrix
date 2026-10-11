"""A document that says a script runs in CI names a script that a workflow runs.

README.md said scripts/validate_matrix.py "runs in CI" and the v1.2.0 CHANGELOG entry said
it was wired into the readme-claims CI job, while no workflow under .github/workflows ran
it. Each paragraph or list item that mentions CI is read with the scripts it names.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ("README.md", "CHANGELOG.md", "CONTRIBUTING.md")
SCRIPT_RE = re.compile(r"scripts/[\w.-]+\.py")
CI_RE = re.compile(r"\bCI\b")
ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")


def blocks(text: str):
    """Yield (first line number, text) for each paragraph or list item outside code fences."""
    block, start, fence = [], 0, None
    for lineno, line in enumerate(text.splitlines(), 1):
        m = FENCE_RE.match(line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = None
            continue
        if m or not line.strip() or ITEM_RE.match(line):
            if block:
                yield start, " ".join(block)
            block = []
            if m:
                fence = m.group(1)
                continue
        if line.strip():
            if not block:
                start = lineno
            block.append(line.strip())
    if block:
        yield start, " ".join(block)


def test_scripts_said_to_run_in_ci_are_run_by_a_workflow():
    workflow_dir = ROOT / ".github" / "workflows"
    workflows = "".join(p.read_text(encoding="utf-8")
                        for p in sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")]))
    paths = [ROOT / rel for rel in DOCS] + sorted((ROOT / "docs").rglob("*.md"))
    unrun = []
    for path in paths:
        for lineno, block in blocks(path.read_text(encoding="utf-8")):
            if not CI_RE.search(block):
                continue
            for script in sorted(set(SCRIPT_RE.findall(block))):
                if script not in workflows:
                    unrun.append(f"{path.relative_to(ROOT)}:{lineno}: {script}")
    assert not unrun, "said to run in CI, but no workflow runs it: " + ", ".join(unrun)


def test_blocks_split_list_items_and_skip_fences():
    text = ("Intro line\nwraps here.\n\n- one\n  continued\n- two\n\n```sh\n# CI scripts/x.py\n```\nlast\n")
    assert list(blocks(text)) == [(1, "Intro line wraps here."), (4, "- one continued"),
                                  (6, "- two"), (11, "last")]
