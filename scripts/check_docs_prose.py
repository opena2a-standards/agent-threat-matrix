#!/usr/bin/env python3
"""Keep dashes and "Why this exists" sections out of the Markdown prose in this repository.

Two writing rules apply to every Markdown page a reader sees here:

- P1 no spaced double hyphen (``--``), em dash (U+2014) or spaced en dash (U+2013) is used
     as a dash in prose. Rewrite it as the sentence needs: a period, a comma, a colon or
     parentheses. A single hyphen, a hyphenated compound and an unspaced en dash in a range
     are not dashes and are left alone.
- P2 no heading or bold section label is named "Why this exists" or "Why this matters".

The checked set is every ``*.md`` and ``*.mdx`` file that git tracks or that is untracked and
not ignored, so a new file is checked before it is staged (every such file on disk when the
repository root is not the top of a git work tree), except CHANGELOG.md and changelog.d/,
whose history is not rewritten, LICENSE files, dependency and build output, and test,
fixture, corpus, golden, snapshot and example directories, whose text is data a test
compares against. Front matter, fenced code blocks, inline code spans, HTML comments and
table delimiter rows are skipped: a ``--`` there is a command-line separator, program text or
table syntax, not punctuation. VERBATIM lists the lines that quote a recorded source word for
word, where rewriting the punctuation would misquote it; an entry matches one exact line, so
an edited line is checked again.

Exit 0 when both rules hold, 1 otherwise, printing ``file:line`` for each violation and for
each file that is not valid UTF-8.
"""

import os
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
RULE_RE = re.compile(r"^\s*-+\s*$")
DELIMITER_CELL_RE = re.compile(r":?-+:?")
BLOCKQUOTE_RE = re.compile(r"^\s*(?:>\s*)+")
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


def git_markdown_files(root: Path):
    """Return the tracked and the untracked, not ignored, Markdown paths when root is the top
    of a git work tree, else None. A root nested inside some other repository's work tree is
    walked instead: there, ``git ls-files`` lists that repository's index, not this tree. The
    top is compared by file identity, so a path that differs only in letter case on a
    case-insensitive filesystem still counts as the same directory."""
    def git(*args) -> str:
        return subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, check=True, timeout=60,
        ).stdout.decode("utf-8")

    try:
        if not os.path.samefile(git("rev-parse", "--show-toplevel").strip(), root):
            return None
        out = git("ls-files", "-z", "--cached", "--others", "--exclude-standard",
                  "--", "*.md", "*.mdx")
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError):
        return None
    return [p for p in out.split("\0") if p]


def markdown_files(root: Path) -> list:
    paths = git_markdown_files(root)
    if paths is None:
        paths = [
            p.relative_to(root).as_posix() for p in root.rglob("*")
            if p.suffix in (".md", ".mdx") and ".git" not in p.relative_to(root).parts
        ]
    return sorted(p for p in paths if not excluded(p) and (root / p).is_file())


def strip_html_comments(line: str):
    """Replace each complete ``<!-- ... -->`` in one line with a space and cut the line at an
    unclosed ``<!--``. Return the stripped line and whether a comment is left open. As in
    CommonMark, ``<!-->`` and ``<!--->`` are complete empty comments, so the search for the
    closing ``-->`` starts at the opener's own hyphens. Each character is scanned once, so a
    line of many unclosed openers costs linear time."""
    kept = []
    pos = 0
    while True:
        start = line.find("<!--", pos)
        if start < 0:
            kept.append(line[pos:])
            return "".join(kept), False
        kept.append(line[pos:start])
        end = line.find("-->", start + 2)
        if end < 0:
            return "".join(kept), True
        kept.append(" ")
        pos = end + 3


def table_delimiter_row(line: str) -> bool:
    """True for a GFM table delimiter row such as ``| -- | :-: |`` or ``-- | --``: at least
    one pipe, and every cell between the pipes is hyphens with optional alignment colons.
    Block quote markers in front of the row, as in ``> | -- | -- |``, are removed first."""
    row = BLOCKQUOTE_RE.sub("", line).strip()
    if "|" not in row:
        return False
    if row.startswith("|"):
        row = row[1:]
    if row.endswith("|"):
        row = row[:-1]
    return all(DELIMITER_CELL_RE.fullmatch(cell.strip()) for cell in row.split("|"))


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
        line, in_comment = strip_html_comments(line)
        yield i + 1, INLINE_CODE_RE.sub(" ", line)


def check_text(rel: str, text: str) -> list:
    """Return one ``file:line: rule`` string per violation in one Markdown file."""
    raw = text.splitlines()
    failures = []
    for lineno, line in prose_lines(text):
        if (rel, raw[lineno - 1].rstrip()) in VERBATIM:
            continue
        if not RULE_RE.match(line) and not table_delimiter_row(line):
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
        data = (root / rel).read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            lineno = data.count(b"\n", 0, exc.start) + 1
            failures.append(f"{rel}:{lineno}: not valid UTF-8 (byte 0x{data[exc.start]:02x}); "
                            "save the file as UTF-8 so its prose can be checked")
            continue
        failures.extend(check_text(rel, text))
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
