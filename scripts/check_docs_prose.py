#!/usr/bin/env python3
"""Keep dashes and "Why this exists" sections out of the Markdown prose in this repository.

Two writing rules apply to every Markdown page a reader sees here:

- P1 no spaced double hyphen (``--``), em dash (U+2014) or spaced en dash (U+2013) is used
     as a dash in prose. Rewrite it as the sentence needs: a period, a comma, a colon or
     parentheses. A single hyphen, a hyphenated compound and an unspaced en dash in a range
     are not dashes and are left alone.
- P2 no heading or bold section label is named "Why this exists" or "Why this matters".

The checked set is every tracked ``*.md`` and ``*.mdx`` file (every such file on disk when
there is no git checkout) except CHANGELOG.md and changelog.d/, whose history is not
rewritten, LICENSE files, dependency and build output, and test, fixture, corpus, golden,
snapshot and example directories, whose text is data a test compares against. Front matter,
fenced code blocks, inline code spans and HTML comments are skipped: a ``--`` there is a
command-line separator or program text, not punctuation. VERBATIM lists the lines that quote
a recorded source word for word, where rewriting the punctuation would misquote it; an entry
matches one exact line, so an edited line is checked again.

Exit 0 when both rules hold, 1 otherwise, printing ``file:line`` for each violation.
"""

import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent

EXCLUDED_DIRS = {
    "node_modules", "vendor", "dist", "build", "changelog.d",
    "test", "tests", "fixture", "fixtures", "corpus", "golden", "goldens",
    "snapshot", "snapshots", "__snapshots__", "example", "examples",
}

VERBATIM = {
    # The CNA scope statement, quoted exactly as the source it cites records it.
    ("docs/cna/application-package.md", "> npm/PyPI — advisories from originated research"),
}

FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
INLINE_CODE_RE = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->")
RULE_RE = re.compile(r"^\s*-+\s*$")
DASHES = (
    ("spaced double hyphen", re.compile(r"(?:^|\s)--(?:\s|$)")),
    ("em dash", re.compile("—")),
    ("spaced en dash", re.compile(r"(?:^|\s)–(?:\s|$)")),
)
WHY_HEADING_RE = re.compile(r"^ {0,3}(?:#{1,6}\s*|\*\*|__)\s*why this (?:exists|matters)\b", re.I)
WHY_SETEXT_RE = re.compile(r"^ {0,3}why this (?:exists|matters)\b", re.I)
SETEXT_UNDERLINE_RE = re.compile(r"^ {0,3}(?:=+|-+)\s*$")


def excluded(rel: str) -> bool:
    parts = PurePosixPath(rel).parts
    name = parts[-1]
    if name == "CHANGELOG.md" or name.startswith("LICENSE"):
        return True
    return any(part in EXCLUDED_DIRS for part in parts[:-1])


def markdown_files(root: Path) -> list:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--", "*.md", "*.mdx"],
            capture_output=True, check=True, timeout=60,
        ).stdout.decode("utf-8")
        paths = [p for p in out.split("\0") if p]
    except (OSError, subprocess.SubprocessError):
        paths = [
            p.relative_to(root).as_posix() for p in root.rglob("*")
            if p.suffix in (".md", ".mdx") and ".git" not in p.relative_to(root).parts
        ]
    return sorted(p for p in paths if not excluded(p) and (root / p).is_file())


def prose_lines(text: str):
    """Yield (line number, line) for each line outside front matter, fences and comments,
    with inline code spans and HTML comments removed."""
    lines = text.splitlines()
    start = 0
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() in ("---", "..."):
                start = i + 1
                break
    fence = None
    in_comment = False
    for i in range(start, len(lines)):
        line = lines[i]
        if fence:
            m = FENCE_RE.match(line)
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) \
                    and not line.strip().strip(fence[0]):
                fence = None
            continue
        if in_comment:
            if "-->" not in line:
                continue
            line = line.split("-->", 1)[1]
            in_comment = False
        m = FENCE_RE.match(line)
        if m:
            fence = m.group(1)
            continue
        line = HTML_COMMENT_RE.sub(" ", line)
        if "<!--" in line:
            line = line.split("<!--", 1)[0]
            in_comment = True
        yield i + 1, INLINE_CODE_RE.sub(" ", line)


def check_text(rel: str, text: str) -> list:
    """Return one ``file:line: rule`` string per violation in one Markdown file."""
    raw = text.splitlines()
    failures = []
    for lineno, line in prose_lines(text):
        if (rel, raw[lineno - 1].rstrip()) in VERBATIM:
            continue
        if not RULE_RE.match(line):
            for name, pattern in DASHES:
                if pattern.search(line):
                    failures.append(f"{rel}:{lineno}: P1 {name} used as a dash in prose")
        nxt = raw[lineno] if lineno < len(raw) else ""
        if WHY_HEADING_RE.match(line) or (WHY_SETEXT_RE.match(line) and SETEXT_UNDERLINE_RE.match(nxt)):
            failures.append(f"{rel}:{lineno}: P2 section named \"Why this exists/matters\"")
    return failures


def run_checks(root: Path):
    files = markdown_files(root)
    failures = []
    for rel in files:
        failures.extend(check_text(rel, (root / rel).read_text(encoding="utf-8")))
    return files, failures


def main() -> int:
    files, failures = run_checks(ROOT)
    if failures:
        print(f"FAIL: {len(failures)} docs prose violation(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"OK: {len(files)} Markdown files, no dash used in prose and no \"Why this exists\" section")
    return 0


if __name__ == "__main__":
    sys.exit(main())
