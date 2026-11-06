#!/usr/bin/env python3
"""Check crosswalks/technique-crosswalk.json against a fresh rendering and the vendored inputs.

The crosswalk is derived content: ``scripts/build_technique_crosswalk.py`` renders it from
``matrix.json``, ``technique-ids.json`` and the pinned inputs under ``vendor/``. This check
reads no network and asks git only which files X9 leaves out;
``scripts/check_vendor_integrity.py`` is the half that compares each vendored input with its
source at the pin. It fails when any of these holds:

- X1 the committed file differs in bytes from a fresh rendering, is absent or is not valid
     JSON, or an input cannot be rendered or an id list cannot be read, as when a string read
     from it is not valid Unicode text (the JSON escape ``\\ud800`` with no pair, which UTF-8
     cannot encode): the line names the file, the string's place and the string, escaped;
- X2 a technique id is not in ``technique-ids.json`` ``ids``;
- X3 an OASB-1 control id is not in ``vendor/hackmyagent/oasb-1-controls.json``;
- X4 a check id is not in ``vendor/hackmyagent/check-ids.json``;
- X5 a signature id is not in the vendored aiis ``bySignature``, or is a retired id: the
     ``retired-ids.yaml`` reader takes only column-0 lines of the form ``- id: <id>``, so a
     ``superseded_by`` value is never read as retired, and any other column-0 list item fails;
- X6 a scenario is not a key of ``vendor/damn-vulnerable-ai-agent/expected-checks.json``;
- X7 a payload id is not in its own producer's vendored list, or a payload column is null
     while the producer's ``mappings/<producer>-payloads.json`` exists, or is not null while
     that file does not exist;
- X8 a ``VENDOR.json`` pin is not of its source's form: a git source carries ``repo``,
     ``commit`` (40 lower-case hex), ``version`` (null or a non-empty string, whitespace
     alone counting as empty; a string that names no tag passes here, and
     ``scripts/check_vendor_integrity.py`` is the check that verifies the tag names the
     commit), ``read`` (a date), ``files`` and one of ``refresh`` or ``generate``; a package
     carries ``package``, ``version`` (exact, no range), ``registry``, ``integrity``
     (sha512), ``read``, ``files`` and ``generate``;
- X9 a file under ``vendor/<source>/`` is not ``VENDOR.json``, the source's generator
     (``generate.mjs`` or ``generate.py``, kept only by a source with ``generate``) or a
     file listed in ``files``, or a listed file is absent.

X9 judges what the repository can track. When the root is the top of a git work tree, it
leaves out what ``git ls-files --others --ignored --exclude-standard`` lists, such as
``__pycache__/`` output and ``.DS_Store``, and a directory directly under ``vendor/`` with no
file left. A tracked file is judged where an ignore rule matches it, and so is an untracked
file git does not ignore. A tree with no git, a root nested inside another repository's work
tree and a machine without git have no such listing, so each file on disk is judged there.

Every id resolves against its own family's list, never a union and never by the id's shape:
a payload id that equals no check id fails in a check column even though the payload list
holds it. X2 to X7 are read from the committed file and, when it differs, from the fresh
rendering too, so an id that does not resolve is named before the file is rendered again.

Exit 0 when every rule holds, 1 otherwise, printing one line per violation, in which a
surrogate code point is written as its escape. An optional argument names the repository
root to check; the default is the parent of this script's directory, and the rendering is
the one of the build script beside this one. A root argument that names no directory prints
one line and exits 1 without checking. ``--help`` prints the usage and exits 0; an option the
script does not know, or a second argument, prints the usage and exits 2.
"""

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

# The docstring's first line, held apart so --help still works under python3 -OO.
DESCRIPTION = ("Check crosswalks/technique-crosswalk.json against a fresh rendering and the "
               "vendored inputs.")

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "build_technique_crosswalk", SCRIPTS / "build_technique_crosswalk.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


B = load_builder()

GIT_KEYS = ("repo", "commit", "version", "read", "files", "refresh", "generate")
NPM_KEYS = ("package", "version", "registry", "integrity", "read", "files", "generate")
GENERATORS = ("generate.mjs", "generate.py")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
EXACT_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
INTEGRITY_RE = re.compile(r"^sha512-[A-Za-z0-9+/]{86}==$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REGISTRY_RE = re.compile(r"^https://[^\s/]+(/\S*)?$")
LIST_ITEM_RE = re.compile(r"^-(\s|$)")
RETIRED_ID_RE = re.compile(r"^- id: ([A-Za-z0-9][A-Za-z0-9._-]*)$")
# Variables that would point git at a repository other than the root's. Per githooks(5), git
# exports such variables to a hook, and a hook may run this check on another root.
GIT_LOCATION_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                     "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")

COMMITTED = f"{B.OUTPUT}"
FRESH = "the fresh rendering"


class Report:
    """Violation lines, kept per rule and printed in rule order."""

    def __init__(self):
        self.lines = {}

    def add(self, rule: int, line: str):
        bucket = self.lines.setdefault(rule, [])
        # A committed file, a pin or a file name can hold a surrogate code point, which has no
        # UTF-8 encoding, so a line holding one could not be printed.
        text = f"X{rule} {line}".encode("utf-8", "backslashreplace").decode("utf-8")
        if text not in bucket:
            bucket.append(text)

    def ordered(self) -> list:
        return [line for rule in sorted(self.lines) for line in self.lines[rule]]


def is_date(value) -> bool:
    if not isinstance(value, str) or not B.DATE_RE.match(value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def check_manifest(source: str, manifest: dict, report: Report):
    """X8: the pin of one VENDOR.json is of its source's form."""
    rel = f"{B.VENDOR}/{source}/{B.MANIFEST}"
    if "package" in manifest:
        kind, keys = "package", NPM_KEYS
    elif "repo" in manifest or "commit" in manifest:
        kind, keys = "git", GIT_KEYS
    else:
        report.add(8, f"{rel} is neither a git pin (repo, commit) nor a package pin (package)")
        return
    unknown = sorted(set(manifest) - set(keys))
    if unknown:
        report.add(8, f"{rel} carries keys a {kind} pin does not: {', '.join(unknown)}")
    if kind == "git":
        if not isinstance(manifest.get("repo"), str) or not REPO_RE.match(manifest["repo"]):
            report.add(8, f"{rel} repo {manifest.get('repo')!r} is not <owner>/<name>")
        commit = manifest.get("commit")
        if not isinstance(commit, str) or not COMMIT_RE.match(commit):
            report.add(8, f"{rel} commit {commit!r} is not 40 lower-case hex")
        if "version" not in manifest:
            report.add(8, f"{rel} has no version (null or a non-empty string)")
        elif manifest["version"] is not None and (
                not isinstance(manifest["version"], str) or not manifest["version"].strip()):
            report.add(8, f"{rel} version {manifest['version']!r} is neither null nor a "
                          f"non-empty string")
        commands = [key for key in ("refresh", "generate") if key in manifest]
        if len(commands) != 1:
            report.add(8, f"{rel} carries {len(commands)} of refresh and generate; a git pin "
                          f"carries exactly one")
    else:
        if not isinstance(manifest.get("package"), str) or not manifest["package"]:
            report.add(8, f"{rel} package {manifest.get('package')!r} is not a package name")
        version = manifest.get("version")
        if not isinstance(version, str) or not EXACT_VERSION_RE.match(version):
            report.add(8, f"{rel} version {version!r} is not an exact version "
                          f"(MAJOR.MINOR.PATCH, no range)")
        if not isinstance(manifest.get("registry"), str) or \
                not REGISTRY_RE.match(manifest["registry"]):
            report.add(8, f"{rel} registry {manifest.get('registry')!r} is not an https URL")
        if not isinstance(manifest.get("integrity"), str) or \
                not INTEGRITY_RE.match(manifest["integrity"]):
            report.add(8, f"{rel} integrity {manifest.get('integrity')!r} is not a sha512 "
                          f"integrity value")
        commands = ["generate"] if "generate" in manifest else []
        if not commands:
            report.add(8, f"{rel} has no generate command")
    for key in commands:
        if not isinstance(manifest[key], str) or not manifest[key].strip():
            report.add(8, f"{rel} {key} is not a command")
    if not is_date(manifest.get("read")):
        report.add(8, f"{rel} read {manifest.get('read')!r} is not a date (YYYY-MM-DD)")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        report.add(8, f"{rel} files is not a non-empty list")
    else:
        for name in files:
            if not B.relative_path(name) or name == B.MANIFEST or name in GENERATORS:
                report.add(8, f"{rel} files names {name!r}, which is not a relative path to "
                              f"a vendored file")
        if len(set(map(str, files))) != len(files):
            report.add(8, f"{rel} files names a path twice")


def git_ignored_paths(root: Path):
    """What git lists as untracked and ignored under vendor/ when root is the top of a git work
    tree, else None: a file by its path, and a nested repository inside an ignored directory
    by its directory, with a trailing slash. A root nested inside another repository's work
    tree gets None, since that repository's rules do not describe this tree, and so does a
    machine without git. The top is compared by file identity, so a path that differs only in
    letter case on a case-insensitive filesystem still counts as the same directory."""
    env = {key: value for key, value in os.environ.items() if key not in GIT_LOCATION_VARS}

    def git(*args) -> str:
        return os.fsdecode(subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, check=True, timeout=60,
            env=env).stdout)

    try:
        if not os.path.samefile(git("rev-parse", "--show-toplevel").rstrip("\n"), root):
            return None
        out = git("ls-files", "-z", "--others", "--ignored", "--exclude-standard",
                  "--", B.VENDOR)
    except (OSError, subprocess.SubprocessError):
        return None
    return [rel for rel in out.split("\0") if rel]


def judged_entries(root: Path) -> list:
    """[(entry, files)] for each path directly under vendor/, with the files X9 judges in it: the
    entry itself when it is not a directory. Where git gives a listing, the files it names are
    left out, and an entry with no file left is dropped, whether git names all its files or it
    holds none. A path git does not name stays judged. Where git gives no listing, each path
    on disk is kept."""
    listed = git_ignored_paths(root)
    ignored = set(listed or ())
    ignored_directories = tuple(rel for rel in ignored if rel.endswith("/"))

    def is_ignored(path: Path) -> bool:
        rel = path.relative_to(root).as_posix()
        return rel in ignored or rel.startswith(ignored_directories)

    entries = []
    for entry in sorted((root / B.VENDOR).iterdir(), key=lambda p: p.name):
        paths = sorted(entry.rglob("*")) if entry.is_dir() else [entry]
        files = [path for path in paths if not path.is_dir() and not is_ignored(path)]
        if files or listed is None:
            entries.append((entry, files))
    return entries


def check_vendor_tree(root: Path, report: Report) -> dict:
    """X8 and X9 over vendor/. Returns {source: manifest} for the sources that have one."""
    vendor = root / B.VENDOR
    manifests = {}
    if not vendor.is_dir():
        report.add(9, f"{B.VENDOR}/ is absent")
        return manifests
    for entry, judged in judged_entries(root):
        rel = f"{B.VENDOR}/{entry.name}"
        if not entry.is_dir():
            report.add(9, f"{rel} is a file directly under {B.VENDOR}/; every input is a "
                          f"directory with a {B.MANIFEST}")
            continue
        manifest_path = entry / B.MANIFEST
        manifest = None
        if not manifest_path.is_file():
            report.add(9, f"{rel}/ has no {B.MANIFEST}")
        else:
            try:
                manifest = json.loads(manifest_path.read_bytes().decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                report.add(8, f"{rel}/{B.MANIFEST} is not valid JSON ({exc})")
            if manifest is not None and not isinstance(manifest, dict):
                report.add(8, f"{rel}/{B.MANIFEST} is not a JSON object")
                manifest = None
        allowed = {B.MANIFEST}
        if manifest is not None:
            manifests[entry.name] = manifest
            check_manifest(entry.name, manifest, report)
            files = manifest.get("files")
            listed = [f for f in files if isinstance(f, str)] if isinstance(files, list) else []
            allowed.update(listed)
            for name in listed:
                if B.relative_path(name) and not (entry / name).is_file():
                    report.add(9, f"{rel}/{name} is listed in files but absent")
            if "generate" in manifest:
                present = [g for g in GENERATORS if (entry / g).is_file()]
                if len(present) != 1:
                    report.add(9, f"{rel}/ has a generate command and {len(present)} "
                                  f"generators; it keeps exactly one of "
                                  f"{' or '.join(GENERATORS)}")
                for generator in present:
                    allowed.add(generator)
                    named = f"{rel}/{generator}"
                    if isinstance(manifest["generate"], str) and named not in manifest["generate"]:
                        report.add(9, f"{rel}/{B.MANIFEST} generate does not name {named}")
        for path in judged:
            name = path.relative_to(entry).as_posix()
            if name not in allowed:
                report.add(9, f"{rel}/{name} is not {B.MANIFEST}, the generator or a file "
                              f"listed in files")
    return manifests


def retired_ids(root: Path, report: Report) -> set:
    """The ids of the vendored retired-ids.yaml, read by its column-0 '- id:' lines only."""
    path = root / B.AIIS_RETIRED
    if not path.is_file():
        return set()
    ids = set()
    for lineno, line in enumerate(path.read_bytes().decode("utf-8", "replace").split("\n"), 1):
        if not LIST_ITEM_RE.match(line):
            continue
        m = RETIRED_ID_RE.match(line.rstrip("\r"))
        if m:
            ids.add(m.group(1))
        else:
            report.add(5, f"{B.AIIS_RETIRED}:{lineno} is a list item that is not "
                          f"'- id: <id>'; the reader takes no other form")
    return ids


def as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def as_list(value) -> list:
    return value if isinstance(value, list) else []


def ids_in(doc: dict) -> dict:
    """{family: [(location, id)]} for every id the document names, in document order."""
    out = {"technique": [], "oasb": [], "check": [], "signature": [], "scenario": []}
    for tid, entry in as_dict(doc.get("byTechnique")).items():
        here = f"byTechnique.{tid}"
        out["technique"].append((here, tid))
        entry = as_dict(entry)
        out["check"] += [(f"{here}.hmaChecks", c) for c in as_list(entry.get("hmaChecks"))]
        out["oasb"] += [(f"{here}.oasbControls", c) for c in as_list(entry.get("oasbControls"))]
        out["signature"] += [(f"{here}.aiisSignatures", as_dict(s).get("id"))
                             for s in as_list(entry.get("aiisSignatures"))]
        for item in as_list(entry.get("dvaaScenarios")):
            item = as_dict(item)
            out["scenario"].append((f"{here}.dvaaScenarios", item.get("scenario")))
            out["check"] += [(f"{here}.dvaaScenarios.checks", c)
                             for c in as_list(item.get("checks"))]
    for view, family in (("byHmaCheck", "check"), ("byOasbControl", "oasb"),
                         ("byAiisSignature", "signature"), ("byDvaaScenario", "scenario")):
        for key, entries in as_dict(doc.get(view)).items():
            out[family].append((view, key))
            for item in as_list(entries):
                item = as_dict(item)
                out["technique"].append((f"{view}.{key}", item.get("techniqueId")))
                out["check"] += [(f"{view}.{key}.checks", c) for c in as_list(item.get("checks"))]
    unjoined = as_dict(doc.get("unjoined"))
    out["oasb"] += [("unjoined.oasbControlsInNoTechnique", c)
                    for c in as_list(unjoined.get("oasbControlsInNoTechnique"))]
    out["check"] += [("unjoined.dvaaExpectedChecksInNoTechnique", c)
                     for c in as_list(unjoined.get("dvaaExpectedChecksInNoTechnique"))]
    out["check"] += [("unjoined.hmaChecksInNoTechnique", c)
                     for c in as_list(unjoined.get("hmaChecksInNoTechnique"))]
    return out


def payload_columns(doc: dict, producer: str) -> list:
    """[(location, value)] for each payload column of one producer."""
    columns = [(f"byTechnique.{tid}.attackPayloads.{producer}",
                as_dict(as_dict(entry).get("attackPayloads")).get(producer))
               for tid, entry in as_dict(doc.get("byTechnique")).items()]
    columns.append((f"byPayload.{producer}", as_dict(doc.get("byPayload")).get(producer)))
    columns.append((f"unjoined.payloadsInNoTechnique.{producer}",
                    as_dict(as_dict(doc.get("unjoined")).get("payloadsInNoTechnique")).get(producer)))
    return columns


def payload_ids_in(location: str, value) -> list:
    if location.startswith("byPayload."):
        return list(as_dict(value))
    if location.startswith("unjoined."):
        return as_list(value)
    return [as_dict(item).get("id") for item in as_list(value)]


def check_document(root: Path, label: str, doc: dict, known: dict, report: Report):
    """X2 to X7 over one rendering of the crosswalk."""
    families = (
        (2, "technique", "technique", known["techniques"], B.TECHNIQUE_IDS),
        (3, "oasb", "OASB-1 control", known["oasb"], B.OASB_CONTROLS),
        (4, "check", "check", known["checks"], B.CHECK_IDS),
        (5, "signature", "signature", known["signatures"], f"{B.AIIS_CROSSWALK} bySignature"),
        (6, "scenario", "scenario", known["scenarios"], B.DVAA_EXPECTED),
    )
    found = ids_in(doc)
    for rule, family, noun, members, home in families:
        for location, ident in found[family]:
            if not isinstance(ident, str):
                report.add(rule, f"{label} {location}: {noun} id {ident!r} is not a string")
            elif ident not in members:
                hint = ""
                if family == "check" and ident in known["payloads"].get("hackmyagent", set()):
                    hint = "; it is a hackmyagent payload id, which resolves only in a payload column"
                report.add(rule, f"{label} {location}: {noun} {ident} is not in {home}{hint}")
            elif family == "signature" and ident in known["retired"]:
                report.add(rule, f"{label} {location}: signature {ident} is retired in "
                                 f"{B.AIIS_RETIRED}")
    for producer, spec in sorted(B.PAYLOAD_PRODUCERS.items()):
        mapping_exists = (root / spec["mapping"]).is_file()
        members = known["payloads"].get(producer)
        for location, value in payload_columns(doc, producer):
            if value is None:
                if mapping_exists:
                    report.add(7, f"{label} {location} is null while {spec['mapping']} exists")
                continue
            if not mapping_exists:
                report.add(7, f"{label} {location} is not null, but {spec['mapping']} does not "
                              f"exist; a column with no source is null")
            for ident in payload_ids_in(location, value):
                if members is None:
                    report.add(7, f"{label} {location}: payload {ident!r} has no vendored "
                                  f"{producer} payload list to resolve against")
                elif ident not in members:
                    report.add(7, f"{label} {location}: payload {ident!r} is not in "
                                  f"{spec['ids']}")


def known_ids(root: Path, report: Report, render_failure: str = None):
    """The id list of each family, or None when an input cannot be read. The rendering reads
    the lists of four families through the same readers, so a failure equal to
    ``render_failure`` is already on the rendering's line and is not reported again."""
    try:
        technique_ids = B.read_object(root, B.TECHNIQUE_IDS).get("ids")
        known = {
            "techniques": set(B.string_list(technique_ids, B.TECHNIQUE_IDS, "ids")),
            "oasb": set(B.vendored_oasb_controls(root)),
            "checks": set(B.vendored_check_ids(root)),
            "signatures": set(B.vendored_signatures(root)),
            "scenarios": set(B.vendored_scenarios(root)),
            "payloads": {},
        }
        for producer, spec in B.PAYLOAD_PRODUCERS.items():
            if spec["ids"] is not None:
                ids = B.read_object(root, spec["ids"]).get("payloadIds")
                known["payloads"][producer] = set(B.string_list(ids, spec["ids"], "payloadIds"))
    except B.InputError as exc:
        if str(exc) != render_failure:
            report.add(1, f"cannot read the id lists: {exc}")
        return None
    known["retired"] = retired_ids(root, report)
    return known


def first_difference(a: bytes, b: bytes) -> int:
    left, right = a.split(b"\n"), b.split(b"\n")
    for lineno, (x, y) in enumerate(zip(left, right), 1):
        if x != y:
            return lineno
    return min(len(left), len(right)) + 1


def run(root: Path) -> list:
    report = Report()
    check_vendor_tree(root, report)

    fresh_text, render_failure = None, None
    try:
        fresh_text = B.render(root)
    except B.InputError as exc:
        render_failure = str(exc)
        report.add(1, f"cannot render {COMMITTED}: {exc}")
    committed_path = root / COMMITTED
    committed = committed_path.read_bytes() if committed_path.is_file() else None
    fresh = fresh_text.encode("utf-8") if fresh_text is not None else None

    if committed is None:
        report.add(1, f"{COMMITTED} is absent; run python3 scripts/build_technique_crosswalk.py")
    elif fresh is not None and committed != fresh:
        report.add(1, f"{COMMITTED} differs from a fresh rendering of {B.MATRIX}, "
                      f"{B.TECHNIQUE_IDS} and {B.VENDOR}/ (first difference at line "
                      f"{first_difference(committed, fresh)}); run "
                      f"python3 scripts/build_technique_crosswalk.py")

    documents = []
    if committed is not None:
        try:
            doc = json.loads(committed.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            report.add(1, f"{COMMITTED} is not valid JSON ({exc})")
        else:
            if isinstance(doc, dict):
                documents.append((COMMITTED, doc))
            else:
                report.add(1, f"{COMMITTED} is not a JSON object")
    if fresh is not None and fresh != committed:
        documents.append((FRESH, json.loads(fresh_text)))

    known = known_ids(root, report, render_failure)
    if known is not None:
        for label, doc in documents:
            check_document(root, label, doc, known, report)
    return report.ordered()


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description=DESCRIPTION, allow_abbrev=False)
    parser.add_argument("root", nargs="?",
                        help="the repository root to check; the default is the parent of "
                             "this script's directory")
    args = parser.parse_args(argv)
    if args.root is None:
        root = ROOT
    elif os.path.isdir(args.root):
        root = Path(args.root).resolve()
    else:
        print(f"FAIL: the root argument {args.root!r} names no directory, so no check was run")
        return 1
    violations = run(root)
    for line in violations:
        print(line)
    if violations:
        return 1
    print(f"OK: {COMMITTED} matches a fresh rendering, every id resolves in its own family, "
          f"and every vendored input is pinned and listed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
