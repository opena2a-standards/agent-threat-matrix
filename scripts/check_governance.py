#!/usr/bin/env python3
"""Check that GOVERNANCE.md exists, links its homes, and names only paths that exist.

GOVERNANCE.md is the change control of this repository for a reader outside the
organization: who decides, what is normative, how a change is proposed, how the version
moves, how a tier moves, how the scope is amended, and when a release is complete. It
states the organization's authority model and change route by link, so that a change to
the organization's documents needs no change here, and it names the repository paths that
are normative and derived. A page that links a document that moved, or names a path that
was renamed, sends an outside reader to nothing, so each of those is checked.

Six properties:

- G1 GOVERNANCE.md exists at the repository root.
- G2 it links the organization's GOVERNANCE.md and CONTRIBUTING.md, the homes of the
     authority model and of the change route, which it does not restate.
- G3 every path named in a code span of its section "What is normative, derived and
     editorial" exists in the tree. A path ending in "/" must be a directory.
- G4 CONTRIBUTING.md and README.md link GOVERNANCE.md, so a reader who starts at either
     reaches it.
- G5 every pattern in .github/CODEOWNERS, when that file is present, resolves to at least
     one path in the tree. A file that is absent is reported as absent and fails nothing.
- G6 every relative link in GOVERNANCE.md resolves to a path in the tree, and a fragment on
     a link to a Markdown page names a heading on that page.

A file a property reads that is not valid UTF-8 fails that property, in one line naming the
file, the first byte that does not decode and the line it is on. GOVERNANCE.md is reported
under G1 and then ends the run, as an absent page does; CONTRIBUTING.md and README.md under
G4; .github/CODEOWNERS under G5; and a Markdown page that GOVERNANCE.md links with a
fragment under G6, once however many such links it has.

There is no ``--fix`` mode: the page is prose that people decide, not text a script may
write. Exit 0 when all six hold, 1 otherwise, printing one line per violation. An optional
argument names the repository root to check; the default is the parent of this script's
directory.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = "GOVERNANCE.md"
CODEOWNERS = ".github/CODEOWNERS"
LINKING_PAGES = ("CONTRIBUTING.md", "README.md")

ORG_LINKS = (
    "https://github.com/opena2a-standards/.github/blob/main/GOVERNANCE.md",
    "https://github.com/opena2a-standards/.github/blob/main/CONTRIBUTING.md",
)

PATHS_SECTION = "## What is normative, derived and editorial"
PATH_SUFFIXES = (".json", ".md", ".py", ".yml", ".yaml")

CODE_SPAN_RE = re.compile(r"`([^`\n]+)`")
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
HEADING_RE = re.compile(r"^ {0,3}#{1,6}\s+(.*?)\s*#*\s*$")
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
EXTERNAL_RE = re.compile(r"^[a-z][a-z0-9+.-]*:", re.I)
PAGE_LINK_RE = re.compile(r"\]\(GOVERNANCE\.md(?:#[^)]*)?\)")


def read_utf8(path: Path):
    """(text, None) when the bytes of `path` are valid UTF-8, else (None, reason), where
    reason names the first byte that does not decode and the line it is on."""
    data = path.read_bytes()
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError as exc:
        lineno = data.count(b"\n", 0, exc.start) + 1
        return None, f"is not valid UTF-8 (byte 0x{data[exc.start]:02x} on line {lineno})"


def prose_lines(text: str):
    """Yield the lines of a Markdown text that are outside fenced code blocks."""
    fence = None
    for line in text.splitlines():
        m = FENCE_RE.match(line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = None
            continue
        if m:
            fence = m.group(1)
            continue
        yield line


def section(text: str, heading: str) -> str:
    """The text under `heading` up to the next heading of the same or a higher level."""
    level = len(heading) - len(heading.lstrip("#"))
    lines = []
    inside = False
    for line in text.splitlines():
        if line.rstrip() == heading:
            inside = True
            continue
        if inside and re.match(r"^#{1,%d}\s" % level, line):
            break
        if inside:
            lines.append(line)
    return "\n".join(lines)


def path_tokens(span: str):
    """The tokens of one code span that name a repository path: a token holding "/" or
    ending in one of PATH_SUFFIXES, with trailing punctuation removed. Flags and words are
    not paths."""
    for token in span.split():
        token = token.rstrip(",.;:)")
        if token.startswith("-") or not token:
            continue
        if "/" in token or token.endswith(PATH_SUFFIXES):
            yield token


def named_paths(text: str) -> list:
    """The paths named in code spans of the normative/derived/editorial section, in order
    of first appearance."""
    seen = []
    for line in prose_lines(section(text, PATHS_SECTION)):
        for span in CODE_SPAN_RE.findall(line):
            for token in path_tokens(span):
                if token not in seen:
                    seen.append(token)
    return seen


def heading_slug(heading: str) -> str:
    """The fragment GitHub gives a heading: lower case, with every character other than a
    letter, a digit, a space or a hyphen removed, and spaces written as hyphens."""
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.strip().lower()
    text = "".join(ch for ch in text if ch.isalnum() or ch in " -")
    return text.replace(" ", "-")


def heading_slugs(text: str) -> set:
    slugs = set()
    for line in prose_lines(text):
        m = HEADING_RE.match(line)
        if m:
            slugs.add(heading_slug(m.group(1)))
    return slugs


def relative_links(text: str) -> list:
    """(target, fragment) for each link in `text` whose destination is not a URL."""
    links = []
    for line in prose_lines(text):
        for target in LINK_RE.findall(line):
            if EXTERNAL_RE.match(target):
                continue
            path, _, fragment = target.partition("#")
            links.append((path, fragment))
    return links


def codeowners_patterns(text: str) -> list:
    """(line number, pattern) for each rule line of a CODEOWNERS file."""
    patterns = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        patterns.append((lineno, stripped.split()[0]))
    return patterns


def pattern_resolves(root: Path, pattern: str) -> bool:
    """True when a CODEOWNERS pattern names at least one path in the tree. A pattern that
    starts with "/" or holds a "/" before its end is read from the root; one with no other
    "/" than a trailing one matches a name at any depth, as `*.js` matches every .js file
    in GitHub's CODEOWNERS syntax; a pattern ending in "/" must be a directory; "*", "?"
    and "[" are globbed."""
    anchored = pattern.startswith("/")
    body = pattern.lstrip("/")
    want_dir = body.endswith("/")
    body = body.rstrip("/")
    if not body:
        return True
    if anchored or "/" in body:
        if any(ch in body for ch in "*?["):
            matches = list(root.glob(body))
        else:
            matches = [root / body] if (root / body).exists() else []
    else:
        matches = list(root.rglob(body))
    matches = [m for m in matches if ".git" not in m.relative_to(root).parts]
    if want_dir:
        matches = [m for m in matches if m.is_dir()]
    return bool(matches)


def run_checks(root: Path):
    """Return (failures, summary) for the tree at `root`."""
    failures = []
    page = root / PAGE

    # G1 -- the page exists and is valid UTF-8.
    if not page.is_file():
        return [f"G1 {PAGE} does not exist at the repository root"], None
    text, problem = read_utf8(page)
    if problem:
        return [f"G1 {PAGE} {problem}; save it as UTF-8 so it can be checked"], None

    # G2 -- the page links both organization documents.
    for url in ORG_LINKS:
        if url not in text:
            failures.append(f"G2 {PAGE} does not link {url}")

    # G3 -- every path named in the normative/derived/editorial section exists.
    if PATHS_SECTION not in text.splitlines():
        failures.append(f"G3 {PAGE} has no section headed {PATHS_SECTION!r}")
    paths = named_paths(text)
    for rel in paths:
        target = root / rel
        if not target.exists():
            failures.append(f"G3 {PAGE} names {rel}, which does not exist in the tree")
        elif rel.endswith("/") and not target.is_dir():
            failures.append(f"G3 {PAGE} names {rel} as a directory, and it is a file")

    # G4 -- CONTRIBUTING.md and README.md link the page.
    for rel in LINKING_PAGES:
        linking = root / rel
        linking_text, problem = read_utf8(linking) if linking.is_file() else ("", None)
        if problem:
            failures.append(f"G4 {rel} {problem}; save it as UTF-8 so its link to {PAGE} can be checked")
        elif not PAGE_LINK_RE.search(linking_text):
            failures.append(f"G4 {rel} does not link {PAGE}")

    # G5 -- every CODEOWNERS pattern resolves, when the file is present.
    owners = root / CODEOWNERS
    owner_patterns = []
    if owners.is_file():
        owners_text, problem = read_utf8(owners)
        if problem:
            failures.append(f"G5 {CODEOWNERS} {problem}; save it as UTF-8 so its patterns can be checked")
        else:
            owner_patterns = codeowners_patterns(owners_text)
        for lineno, pattern in owner_patterns:
            if not pattern_resolves(root, pattern):
                failures.append(
                    f"G5 {CODEOWNERS}:{lineno}: pattern {pattern!r} resolves to no path in the tree"
                )

    # G6 -- every relative link in the page resolves, fragment included.
    links = relative_links(text)
    undecodable = set()
    for path, fragment in links:
        target = root / path if path else page
        if not target.exists():
            failures.append(f"G6 {PAGE} links {path}, which does not exist in the tree")
            continue
        if fragment and target.is_file() and target.suffix == ".md":
            target_text, problem = read_utf8(target)
            if problem:
                if target not in undecodable:
                    undecodable.add(target)
                    failures.append(
                        f"G6 {path or PAGE} {problem}; save it as UTF-8 so the fragments "
                        f"{PAGE} links on it can be checked"
                    )
                continue
            slugs = heading_slugs(target_text)
            base = re.sub(r"-\d+$", "", fragment)
            if fragment not in slugs and base not in slugs:
                failures.append(
                    f"G6 {PAGE} links {path or PAGE}#{fragment}, and no heading on that page has that fragment"
                )

    summary = (
        f"OK: {PAGE} links both organization documents, the {len(paths)} paths it names exist, "
        f"{' and '.join(LINKING_PAGES)} link it, its {len(links)} relative links resolve, "
        + (f"and the {len(owner_patterns)} patterns in {CODEOWNERS} each resolve to a path"
           if owners.is_file() else f"and {CODEOWNERS} is absent")
    )
    return failures, summary


def main(argv: list) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    failures, summary = run_checks(root)
    if failures:
        print(f"FAIL: {len(failures)} governance check(s) failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
