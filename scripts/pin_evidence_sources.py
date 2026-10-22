#!/usr/bin/env python3
"""Pin the DVAA pages that back lab-reproduction evidence into evidence-sources.json, and cite them in matrix.json.

DVAA documents a scenario in ``scenarios/<name>/README.md``, and some of those pages name a
technique in bold as ``**T-2001 (Prompt Injection):**`` (the id, a label in parentheses,
then a colon), the form they give the steps of an attack chain. This script reads a git
clone of DVAA at one commit, the head (the clone's ``HEAD`` unless ``--head`` names another
commit), and pins each scenario page there that names a technique in that form. A pin
records the page's ``path``; the last commit at or before the head that changed the page,
``commit``, and that commit's date as its committer recorded it, ``committed`` (what
``git log --format=%cs`` prints); the git blob id of the page, ``blob``; and in ``names``
each name on the page as it is written: its line, the technique id and the label. The pins
go into evidence-sources.json under ``dvaa``, with the repository, the head and the date the
clone was read, ``read``. The clone is read with git's plumbing commands, with replace
objects off, so a replace ref in the clone does not stand in for the commit that is pinned.

In matrix.json the script writes the ``lab-reproduction`` evidence entries the pins back: on
a technique, one for each pinned page that names the technique's id with the technique's
name in matrix.json as the label. Its reference is the page's permalink at its commit,
``<repository>/blob/<commit>/<path>``, and its date is the page's ``committed``. Those
entries come first in the technique's ``evidence``, in path order. A ``lab-reproduction``
entry whose reference is a page of the DVAA repository is this script's to write, so it
gives way to the entries the pins back; every other entry stays as it was, and an
``evidence`` array left empty is dropped. A name whose label is not the technique's name is
pinned, backs no entry and is printed: a page that labels T-2001 "Threshold Exhaustion"
does not name Direct Prompt Injection. So is a name whose id is not a technique in
matrix.json.

A technique's ``dvaaValidation`` in matrix.json names the DVAA lab work that reproduces it:
free text, or the id of a challenge or the name of a scenario, several separated by commas.
The script reads each value between the commas. A value that is the id of a challenge
defined in ``src/challenges/index.js`` at the head, as a key ``'L1-03': {`` with
``id: 'L1-03',`` and ``name: '<name>',`` among its properties, names that challenge; any
other value that is the name of a directory under ``scenarios/`` holding a ``README.md``
names that scenario. Under ``challenges`` the script pins the file as it pins a page
(``path``, ``commit``, ``committed`` and ``blob``), with ``named``, each challenge a
dvaaValidation names: the line of its key, its id and its name. Under ``scenarios`` it pins
the page of each scenario a dvaaValidation names, as it pins a page but with no names. Each
key is written only when it pins something. A pinned challenge or scenario page backs one
``lab-reproduction`` entry on each technique whose dvaaValidation names it, after the
entries the pages back and before every other entry, in the order the dvaaValidation names
them. The reference of a challenge's entry is
``<repository>/blob/<commit>/src/challenges/index.js#L<line>`` and of a scenario's the
permalink of its page, and the date is the ``committed`` date of the file. A value that
names no challenge or scenario at the head backs no entry, and the script prints it with its
technique.

When evidence-sources.json and matrix.json already hold what the clone holds at the head,
nothing is written and ``read`` keeps the date the file records. Otherwise ``read`` is
today; when matrix.json changes, ``updated`` moves to today if it is older, as
scripts/validate_matrix.py requires of a change, and the STIX bundle and evidence-gaps.json
are rendered again with scripts/generate_stix.py, whose report of the techniques left with
no evidence entry is printed.

Usage::

    python3 scripts/pin_evidence_sources.py --dvaa PATH             # pin the clone at its HEAD
    python3 scripts/pin_evidence_sources.py --dvaa PATH --head SHA  # pin it at another commit
    python3 scripts/pin_evidence_sources.py --dvaa PATH --check     # compare, and write nothing

``--check`` reads the clone at the head evidence-sources.json records and fails when that
file, apart from ``read``, or the DVAA entries in matrix.json differ from what the clone
holds at that head.

Exit 0 when the files hold what the clone holds, written or already there; 1 when the clone
or a file cannot be read, a page is not valid UTF-8, the clone holds no scenario page that
names a technique (so it is not read as a DVAA clone, and no entry is dropped on its word),
``src/challenges/index.js`` is there but is not valid UTF-8, holds no ``CHALLENGES`` object
(an ``export const CHALLENGES = {`` line, closed by a ``};`` line), or defines in it no
challenge, a challenge whose id is not its key, a challenge with no name or a challenge
twice, the STIX bundle cannot be rendered, or under ``--check`` the files differ; 2 on a
usage error.
"""

import argparse
import copy
import json
import os
import re
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "matrix.json"
SOURCES = ROOT / "evidence-sources.json"
STIX_GENERATOR = ROOT / "scripts" / "generate_stix.py"
REPOSITORY = "https://github.com/opena2a-org/damn-vulnerable-ai-agent"
LAB = "lab-reproduction"
# The first line of the docstring, which ``python3 -OO`` strips.
DESCRIPTION = ("Pin the DVAA pages that back lab-reproduction evidence into evidence-sources.json, "
               "and cite them in matrix.json.")
SOURCES_DESCRIPTION = (
    "The DVAA pages that lab-reproduction evidence entries in matrix.json cite, pinned by "
    "scripts/pin_evidence_sources.py from a git clone of the repository, read at the commit head "
    "on the date read. pages are the scenario pages, scenarios/<name>/README.md, that name a "
    "technique in bold as **T-NNNN (Label):**, the form DVAA gives the steps of an attack chain. "
    "commit is the last commit at or before head that changed the page, committed is that "
    "commit's date as its committer recorded it, blob is the git blob id of the page there, and "
    "names lists each such name as the page writes it: its line, the technique id and the label. "
    "challenges pins src/challenges/index.js the same way and lists in named each challenge a "
    "technique's dvaaValidation names: the line of its key, its id and its name. scenarios pins, "
    "the same way, the page of each scenario a technique's dvaaValidation names. "
    "scripts/validate_matrix.py resolves a lab-reproduction evidence entry against this file. "
    "Its reference is the permalink of a page, <repository>/blob/<commit>/<path>, its date is the "
    "page's committed date, and the page names the technique's id with the technique's name in "
    "matrix.json as the label. Or its reference is the permalink of a challenge, "
    "<repository>/blob/<commit>/<path>#L<line>, or of a scenario page, its date is the committed "
    "date of the file, and the technique's dvaaValidation names the challenge or the scenario. "
    "Written by the script, not by hand: python3 scripts/pin_evidence_sources.py --dvaa <clone> "
    "--check fails when this file, apart from read, differs from what the clone holds at head for "
    "matrix.json.")
PAGE_RE = re.compile(r"scenarios/[A-Za-z0-9_-]+/README\.md")
SCENARIO_NAME_RE = re.compile(r"[A-Za-z0-9_-]+")
# The code points ECMA-262 reads as white space or a line terminator, which its \s matches,
# as ECMA_SPACE in scripts/validate_matrix.py has them. The label pattern in
# schema/evidence-sources.schema.json is read with that \s, so a label is read here with the
# same set: Python's \s also matches U+001C to U+001F and U+0085, and does not match U+FEFF.
ECMA_SPACE = (r"\t\n\v\f\r \xa0\U00001680\U00002000-\U0000200a\U00002028\U00002029"
              r"\U0000202f\U0000205f\U00003000\U0000feff")
NAME_RE = re.compile(rf"\*\*(T-[0-9]{{4}}(?:\.[0-9]{{3}})?) "
                     rf"\(([^(){ECMA_SPACE}](?:[^()\r\n]*[^(){ECMA_SPACE}])?)\):\*\*")
OFFSET_RE = re.compile(r"([+-])([0-9]{2})([0-9]{2})")
CHALLENGE_FILE = "src/challenges/index.js"
CHALLENGES_OPEN = "export const CHALLENGES = {"
CHALLENGES_CLOSE = "};"
# A challenge's key and its own properties, each on its line and applied with fullmatch: the
# key two spaces in, its properties four. A nested object's properties sit deeper. The id
# pattern in schema/evidence-sources.schema.json is read with ECMA-262's \s, so a key is read
# with ECMA_SPACE, as a label is.
CHALLENGE_KEY_RE = re.compile(rf"  '([^'\\{ECMA_SPACE}]+)': \{{")
CHALLENGE_FIELD_RE = re.compile(r"    (id|name): '([^'\\\r\n]+)',")

# Variables that would point git at a repository other than the clone.
GIT_LOCATION_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                     "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")


class Refused(Exception):
    """The clone or a file cannot be read as this script needs; the message says why."""


def git(clone: Path, *args: str) -> bytes:
    """Run git in the clone and return its output, or refuse with git's reason."""
    env = {key: value for key, value in os.environ.items() if key not in GIT_LOCATION_VARS}
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        proc = subprocess.run(["git", "-C", str(clone), *args], capture_output=True, timeout=300, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused(f"git {args[0]} could not run in {clone}: {exc}")
    if proc.returncode != 0:
        reason = proc.stderr.decode("utf-8", errors="replace").strip() or f"exit status {proc.returncode}"
        raise Refused(f"git {' '.join(args)} failed in {clone}: {reason}")
    return proc.stdout


def resolve_head(clone: Path, head: str) -> str:
    """The full sha of the commit head names in the clone."""
    if not clone.is_dir():
        raise Refused(f"--dvaa {clone} is not a directory")
    try:
        git(clone, "rev-parse", "--git-dir")
    except Refused:
        raise Refused(f"--dvaa {clone} is not a git clone") from None
    try:
        return git(clone, "rev-parse", "--verify", "--quiet", f"{head}^{{commit}}").decode().strip()
    except Refused:
        raise Refused(f"the clone at {clone} holds no commit {head}; fetch it first") from None


def commit_date(clone: Path, commit: str) -> str:
    """The date of a commit as its committer recorded it, as ``git log --format=%cs`` prints it."""
    text = git(clone, "cat-file", "commit", commit).decode("utf-8", errors="replace")
    for line in text.split("\n"):
        if not line:
            break  # the headers end at the first blank line
        if line.startswith("committer "):
            parts = line.rsplit(" ", 2)
            offset = OFFSET_RE.fullmatch(parts[-1]) if len(parts) == 3 else None
            if offset and parts[1].isdigit():
                sign = -1 if offset.group(1) == "-" else 1
                zone = timezone(sign * timedelta(hours=int(offset.group(2)), minutes=int(offset.group(3))))
                return datetime.fromtimestamp(int(parts[1]), zone).date().isoformat()
    raise Refused(f"commit {commit} in the clone carries no committer date git can read")


def scenario_readmes(clone: Path, head: str) -> dict:
    """The git blob id of each scenarios/<name>/README.md at head, by path."""
    readmes = {}
    for record in git(clone, "ls-tree", "-r", "-z", "--full-tree", head, "--", "scenarios").split(b"\0"):
        meta, _, raw_path = record.partition(b"\t")
        fields = meta.decode("ascii", errors="replace").split()
        path = raw_path.decode("utf-8", errors="replace")
        if len(fields) == 3 and fields[1] == "blob" and PAGE_RE.fullmatch(path):
            readmes[path] = fields[2]
    return readmes


def pin_file(clone: Path, head: str, path: str, blob: str) -> dict:
    """The pin of a file at head: its path, the last commit at or before head that changed it,
    that commit's date, and the git blob id of the file."""
    commit = git(clone, "rev-list", "-1", head, "--", path).decode().strip()
    if git(clone, "rev-parse", "--verify", f"{commit}:{path}").decode().strip() != blob:
        raise Refused(f"{path}: the last commit that changed it before {head}, {commit}, holds "
                      f"another version of it than {head} does")
    return {"path": path, "commit": commit, "committed": commit_date(clone, commit), "blob": blob}


def read_pages(clone: Path, head: str, readmes: dict) -> list:
    """The pins of the scenario pages at head that name a technique, sorted by path."""
    pages = []
    for path, blob in readmes.items():
        try:
            text = git(clone, "cat-file", "blob", blob).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Refused(f"{path} at {head} is not valid UTF-8: {exc}")
        names = [{"line": text.count("\n", 0, match.start()) + 1, "technique": match.group(1),
                  "label": match.group(2)} for match in NAME_RE.finditer(text)]
        if names:
            pages.append(dict(pin_file(clone, head, path, blob), names=names))
    if not pages:
        raise Refused(f"the clone at {clone} holds no scenarios/<name>/README.md at {head} that names a "
                      f"technique in bold as **T-NNNN (Label):**, so it is not read as a DVAA clone")
    return sorted(pages, key=lambda page: page["path"])


def read_challenges(clone: Path, head: str):
    """The pin of src/challenges/index.js at head and the challenges it defines in its
    CHALLENGES object, in file order, or None when head holds no such file."""
    listed = git(clone, "ls-tree", "-z", "--full-tree", head, "--", CHALLENGE_FILE).split(b"\0")[0]
    fields = listed.partition(b"\t")[0].decode("ascii", errors="replace").split()
    if len(fields) != 3 or fields[1] != "blob":
        return None
    blob = fields[2]
    try:
        lines = git(clone, "cat-file", "blob", blob).decode("utf-8").split("\n")
    except UnicodeDecodeError as exc:
        raise Refused(f"{CHALLENGE_FILE} at {head} is not valid UTF-8: {exc}")
    lines = [line[:-1] if line.endswith("\r") else line for line in lines]
    start = next((index for index, line in enumerate(lines) if line == CHALLENGES_OPEN), None)
    end = None if start is None else next(
        (index for index in range(start + 1, len(lines)) if lines[index] == CHALLENGES_CLOSE), None)
    if end is None:
        raise Refused(f"{CHALLENGE_FILE} at {head} holds no CHALLENGES object, an '{CHALLENGES_OPEN}' "
                      f"line closed by a '{CHALLENGES_CLOSE}' line, so its challenges are not read")
    defined = []
    for index in range(start + 1, end):
        key = CHALLENGE_KEY_RE.fullmatch(lines[index])
        if key:
            defined.append({"line": index + 1, "key": key.group(1), "id": None, "name": None})
            continue
        field = CHALLENGE_FIELD_RE.fullmatch(lines[index])
        if field and defined and defined[-1][field.group(1)] is None:
            defined[-1][field.group(1)] = field.group(2)
    if not defined:
        raise Refused(f"{CHALLENGE_FILE} at {head} defines no challenge in its CHALLENGES object as a "
                      f"key '<id>': {{ two spaces in, so its challenges are not read")
    first = {}
    for challenge in defined:
        where = f"{CHALLENGE_FILE}:{challenge['line']} at {head} defines {challenge['key']!r}"
        if challenge["id"] != challenge["key"]:
            given = f"id {challenge['id']!r}" if challenge["id"] else "no id: '<id>', line"
            raise Refused(f"{where} with {given}, so which challenge it is cannot be read")
        if challenge["name"] is None:
            raise Refused(f"{where} with no name: '<name>', line holding a name with no quote or "
                          f"backslash in it")
        if challenge["key"] in first:
            raise Refused(f"{where} again: line {first[challenge['key']]} defines it already")
        first[challenge["key"]] = challenge["line"]
    return (pin_file(clone, head, CHALLENGE_FILE, blob),
            [{"line": c["line"], "id": c["id"], "name": c["name"]} for c in defined])


def validation_values(technique: dict) -> list:
    """The values a technique's dvaaValidation lists: the text between its commas, trimmed."""
    value = technique.get("dvaaValidation")
    if not isinstance(value, str):
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def read_named(clone: Path, head: str, matrix: dict, readmes: dict):
    """The pins of the challenges and scenario pages at head a dvaaValidation names, keyed as
    evidence-sources.json keeps them, and the values that name neither, by technique."""
    challenges = read_challenges(clone, head)
    defined = {challenge["id"] for challenge in challenges[1]} if challenges else set()
    named, scenarios, unnamed = set(), set(), []
    for technique in matrix["techniques"]:
        missing = []
        for value in validation_values(technique):
            page = f"scenarios/{value}/README.md"
            if value in defined:
                named.add(value)
            elif SCENARIO_NAME_RE.fullmatch(value) and page in readmes:
                scenarios.add(page)
            else:
                missing.append(value)
        if missing:
            unnamed.append((technique["id"], missing))
    block = {}
    if named:
        block["challenges"] = dict(challenges[0], named=[c for c in challenges[1] if c["id"] in named])
    if scenarios:
        block["scenarios"] = [pin_file(clone, head, page, readmes[page]) for page in sorted(scenarios)]
    return block, unnamed


def permalink(page: dict) -> str:
    return f"{REPOSITORY}/blob/{page['commit']}/{page['path']}"


def backed_entries(matrix: dict, pages: list):
    """The entries the pins back by technique id, and the names that back none."""
    names = {t["id"]: t["name"] for t in matrix["techniques"]}
    entries, mislabelled, unknown = {}, [], []
    for page in pages:
        for name in page["names"]:
            tid = name["technique"]
            if tid not in names:
                unknown.append((page, name))
            elif name["label"] != names[tid]:
                mislabelled.append((page, name, names[tid]))
            else:
                entry = {"type": LAB, "reference": permalink(page), "date": page["committed"]}
                cited = entries.setdefault(tid, [])
                if entry not in cited:
                    cited.append(entry)
    return entries, mislabelled, unknown


def named_entries(matrix: dict, block: dict) -> dict:
    """The entries the challenges and scenario pages a dvaaValidation names back, by technique
    id, in the order each dvaaValidation names them."""
    cites = {}
    for page in block.get("scenarios", []):
        cites[page["path"].split("/")[1]] = {"type": LAB, "reference": permalink(page),
                                             "date": page["committed"]}
    challenges = block.get("challenges")
    for challenge in challenges["named"] if challenges else []:
        cites[challenge["id"]] = {"type": LAB, "reference": f"{permalink(challenges)}#L{challenge['line']}",
                                  "date": challenges["committed"]}
    entries = {}
    for technique in matrix["techniques"]:
        for value in validation_values(technique):
            entry = cites.get(value)
            if entry is None:
                continue
            cited = entries.setdefault(technique["id"], [])
            if entry not in cited:
                cited.append(dict(entry))
    return entries


def add_named(entries: dict, named: dict) -> int:
    """Append to each technique's entries the ones its dvaaValidation backs that it does not
    carry yet, after the ones the pages back; return how many were appended."""
    added = 0
    for tid, cites in named.items():
        cited = entries.setdefault(tid, [])
        for entry in cites:
            if entry not in cited:
                cited.append(entry)
                added += 1
    return added


def written_here(entry) -> bool:
    """Whether an evidence entry is one this script writes: a DVAA page as lab-reproduction."""
    return (isinstance(entry, dict) and entry.get("type") == LAB
            and isinstance(entry.get("reference"), str)
            and entry["reference"].startswith(f"{REPOSITORY}/blob/"))


def write_entries(matrix: dict, entries: dict) -> None:
    for technique in matrix["techniques"]:
        evidence = technique.get("evidence", [])
        if not isinstance(evidence, list):
            raise Refused(f"{technique['id']}: evidence in matrix.json is not an array")
        written = entries.get(technique["id"], []) + [e for e in evidence if not written_here(e)]
        if written:
            technique["evidence"] = written
        else:
            technique.pop("evidence", None)


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise Refused(f"{path.name} is missing")
    except (OSError, ValueError, RecursionError) as exc:
        raise Refused(f"could not read {path.name}: {exc}")


def without(data, key: str):
    return {k: v for k, v in data.items() if k != key} if isinstance(data, dict) else data


def render_sources(block: dict) -> str:
    return json.dumps({"description": SOURCES_DESCRIPTION, "dvaa": block}, indent=2) + "\n"


def recorded_head(recorded) -> str:
    dvaa = recorded.get("dvaa") if isinstance(recorded, dict) else None
    head = dvaa.get("head") if isinstance(dvaa, dict) else None
    if not isinstance(head, str) or not head:
        raise Refused("evidence-sources.json records no dvaa head to check the clone at")
    return head


def pin_difference(old, new: dict) -> str:
    """How the pins a file records differ from the pins the clone gives."""
    if not isinstance(old, dict):
        return "it records no dvaa pins"
    details = [f"{key} is {old.get(key)!r}, the clone gives {new[key]!r}"
               for key in ("repository", "head") if old.get(key) != new[key]]
    listed = old.get("pages") if isinstance(old.get("pages"), list) else []
    have = {page.get("path"): page for page in listed if isinstance(page, dict)}
    want = {page["path"]: page for page in new["pages"]}
    for path in sorted(set(have) | set(want), key=str):
        if path not in want:
            details.append(f"{path} is pinned, and the clone holds no such page naming a technique")
        elif path not in have:
            details.append(f"{path} names a technique and is not pinned")
        elif have[path] != want[path]:
            changed = [key for key in want[path] if have[path].get(key) != want[path][key]]
            details.append(f"{path} is pinned with {', '.join(changed) or 'keys'} other than the clone gives")
    old_challenges, new_challenges = old.get("challenges"), new.get("challenges")
    if old_challenges != new_challenges:
        if new_challenges is None:
            details.append(f"{CHALLENGE_FILE} is pinned, and no dvaaValidation names a challenge it "
                           f"defines in the clone")
        elif not isinstance(old_challenges, dict):
            details.append(f"{CHALLENGE_FILE} defines a challenge a dvaaValidation names and is not pinned")
        else:
            changed = [key for key in new_challenges if old_challenges.get(key) != new_challenges[key]]
            details.append(f"{CHALLENGE_FILE} is pinned with {', '.join(changed) or 'keys'} other than "
                           f"the clone gives")
    listed = old.get("scenarios") if isinstance(old.get("scenarios"), list) else []
    have = {page.get("path"): page for page in listed if isinstance(page, dict)}
    want = {page["path"]: page for page in new.get("scenarios", [])}
    for path in sorted(set(have) | set(want), key=str):
        if path not in want:
            details.append(f"{path} is pinned as the page of a scenario a dvaaValidation names, and no "
                           f"dvaaValidation names a scenario the clone holds there")
        elif path not in have:
            details.append(f"{path} is the page of a scenario a dvaaValidation names and is not pinned")
        elif have[path] != want[path]:
            changed = [key for key in want[path] if have[path].get(key) != want[path][key]]
            details.append(f"{path} is pinned as a scenario page with {', '.join(changed) or 'keys'} "
                           f"other than the clone gives")
    return "; ".join(details) or "the text of the file differs from what the script writes"


def changed_techniques(before: dict, after: dict) -> list:
    return [t["id"] for t, u in zip(before["techniques"], after["techniques"]) if t != u]


def report_names(mislabelled: list, unknown: list) -> None:
    if mislabelled:
        print("Named with a label that is not the technique's name in matrix.json, so backing no entry:")
        for page, name, real in mislabelled:
            print(f"  {page['path']}:{name['line']} {name['technique']} {name['label']!r}; "
                  f"matrix.json names it {real!r}")
    if unknown:
        print("Named with an id that is not a technique in matrix.json, so backing no entry:")
        for page, name in unknown:
            print(f"  {page['path']}:{name['line']} {name['technique']} {name['label']!r}")


def named_line(block: dict, vcount: int) -> str:
    """The line that states what the dvaaValidation pins hold and back."""
    challenges = len(block["challenges"]["named"]) if "challenges" in block else 0
    scenarios = len(block.get("scenarios", []))
    return (f"evidence-sources.json pins the {challenges} DVAA challenges and {scenarios} scenario pages "
            f"a technique's dvaaValidation names at {block['head']}, and matrix.json carries the "
            f"{vcount} {LAB} entries they back")


def report_unnamed(unnamed: list) -> None:
    if unnamed:
        print("A dvaaValidation value that names no DVAA challenge or scenario page at the head, so "
              "backing no entry:")
        for tid, values in unnamed:
            print(f"  {tid} {', '.join(repr(value) for value in values)}")


def parse_args(argv):
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("--dvaa", type=Path, required=True, help="a git clone of DVAA to read")
    parser.add_argument("--head", help="the commit to read the clone at; the default is its HEAD")
    parser.add_argument("--check", action="store_true",
                        help="read the clone at the head evidence-sources.json records, compare, "
                             "and write nothing")
    args = parser.parse_args(argv)
    if args.check and args.head is not None:
        parser.error("--check reads the clone at the head evidence-sources.json records; it takes no --head")
    if args.head is not None and (not args.head or args.head.startswith("-")):
        parser.error(f"--head {args.head!r} does not name a commit")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    today = date.today().isoformat()
    try:
        matrix = read_json(MATRIX)
        recorded = read_json(SOURCES) if args.check or SOURCES.exists() else None
        head = resolve_head(args.dvaa, recorded_head(recorded) if args.check else args.head or "HEAD")
        readmes = scenario_readmes(args.dvaa, head)
        block = {"repository": REPOSITORY, "head": head, "read": today,
                 "pages": read_pages(args.dvaa, head, readmes)}
        named_block, unnamed = read_named(args.dvaa, head, matrix, readmes)
        block.update(named_block)
        old = recorded.get("dvaa") if isinstance(recorded, dict) else None
        if isinstance(old, dict) and isinstance(old.get("read"), str) and without(old, "read") == without(block, "read"):
            block["read"] = old["read"]
        entries, mislabelled, unknown = backed_entries(matrix, block["pages"])
        count = sum(len(cites) for cites in entries.values())
        vcount = add_named(entries, named_entries(matrix, block))
        cited = copy.deepcopy(matrix)
        write_entries(cited, entries)
        current = SOURCES.read_text(encoding="utf-8") if recorded is not None else None
    except (Refused, OSError) as exc:
        print(f"FAIL: {exc}; nothing is written", file=sys.stderr)
        return 1

    pages = len(block["pages"])
    matrix_changed = without(cited, "updated") != without(matrix, "updated")
    sources_text = render_sources(block)

    if args.check:
        problems = []
        if current != sources_text:
            problems.append(f"evidence-sources.json is not what {args.dvaa} holds at {head}: "
                            f"{pin_difference(old, block)}")
        if matrix_changed:
            problems.append(f"the {LAB} entries citing DVAA pages in matrix.json are not the ones the "
                            f"pins back, on {', '.join(changed_techniques(matrix, cited))}")
        if problems:
            print("FAIL: " + "\n  ".join(["the pins are not what the clone holds:"] + problems), file=sys.stderr)
            return 1
        print(f"OK: evidence-sources.json pins the {pages} DVAA scenario pages that name a technique at "
              f"{head}, and matrix.json carries the {count} {LAB} entries they back")
        print(named_line(block, vcount))
        report_names(mislabelled, unknown)
        report_unnamed(unnamed)
        return 0

    if current == sources_text and not matrix_changed:
        print(f"evidence-sources.json already pins the {pages} DVAA scenario pages that name a technique "
              f"at {head}, read {block['read']}, and matrix.json carries the {count} {LAB} entries they "
              f"back; nothing written")
        print(named_line(block, vcount))
        report_names(mislabelled, unknown)
        report_unnamed(unnamed)
        return 0

    if current != sources_text:
        SOURCES.write_text(sources_text, encoding="utf-8")
    print(f"Pinned the {pages} DVAA scenario pages that name a technique at {head}, read {block['read']}, "
          f"in evidence-sources.json.")
    print(named_line(block, vcount))
    if matrix_changed:
        if cited["updated"] < today:
            cited["updated"] = today
        MATRIX.write_text(json.dumps(cited, indent=2) + "\n", encoding="utf-8")
        proc = subprocess.run([sys.executable, str(STIX_GENERATOR)], capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            print(f"FAIL: matrix.json is written, but scripts/generate_stix.py failed: "
                  f"{proc.stderr.strip() or proc.stdout.strip()}", file=sys.stderr)
            return 1
        print(f"matrix.json carries the {count + vcount} {LAB} entries the pins back, written on "
              f"{', '.join(changed_techniques(matrix, cited))}; updated is {cited['updated']}, and the "
              f"STIX bundle and evidence-gaps.json are rendered again:")
        print(proc.stdout.strip())
    else:
        print(f"matrix.json already carries the {count + vcount} {LAB} entries the pins back.")
    report_names(mislabelled, unknown)
    report_unnamed(unnamed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
