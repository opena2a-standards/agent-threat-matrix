#!/usr/bin/env python3
"""Compare every vendored input under vendor/ with its source, fetched at its pin.

``scripts/check_technique_crosswalk.py`` is offline: it checks the crosswalk against the
vendored files and the pins' form. This is the network half. For each ``vendor/<source>/``
it reads ``VENDOR.json`` and fetches the source at the pin:

- a git source (``repo``, ``commit``): ``git -c credential.helper= clone --filter=blob:none
  --no-checkout https://github.com/<repo>.git``. The commit must be in the clone, and a
  ``version`` must be a tag that names it. A source with ``refresh`` holds byte-exact copies,
  each compared with ``git show <commit>:<path>``; a source with ``generate`` is regenerated
  with ``python3 -I vendor/<source>/generate.py <clone> <commit> <file>``.
- a package (``package``, ``version``): ``npm pack <package>@<version>`` from ``registry``,
  with an empty npm cache of the run's own, so the tarball is read from the registry each
  time. The tarball's sha512 must equal ``integrity``; each listed file is regenerated with
  ``node vendor/<source>/generate.mjs <extracted package> <file>``, run with an environment
  that holds PATH only, so no credential reaches the package's module code.

Every vendored file is then compared byte for byte with what was fetched or regenerated.
Each fetch is tried three times. The compare runs only after a successful fetch, so a
source that cannot be fetched is reported as not measured, never as matching.

Child processes run without GITHUB_TOKEN (and GH_TOKEN, NPM_TOKEN, NODE_AUTH_TOKEN), with
GIT_TERMINAL_PROMPT=0. No request goes to the GitHub REST API: git over HTTPS and the npm
registry only.

Output, one line per finding:

- ``DRIFT <source> <file>``: the vendored file differs from its source at the pin, or the
  file is ``VENDOR.json`` when the pin itself does not hold (the commit is not upstream, the
  tag names another commit, or the tarball's sha512 is not ``integrity``);
- ``UNREACHABLE <source>: upstream unreachable, drift not measured``, after three attempts.

Exit 0 when every file matches, 1 when any DRIFT line was printed, 3 when none was but a
source was unreachable, and 2 on a usage error: an unknown option, a root that is not a
directory, a ``VENDOR.json`` that is not a readable pin, an override naming no source, a
missing ``git``, ``npm`` or ``node``, or, when a package source is pinned, a Python whose
``tarfile`` module has no extraction filters (before 3.12, other than 3.8.17, 3.9.17,
3.10.12, 3.11.4 and later releases of those lines). Neither 1 nor 3 is a pass.

``--override <source>=<location>`` replaces where a source is fetched from: a git URL or a
local repository path for a git source, a local tarball for a package. The tests use it with
a local bare repository and a local tarball, so they open no network connection.
``--retry-delay`` sets the seconds between attempts (default 5, growing with each attempt).
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

# The docstring's first line, held apart so --help still works under python3 -OO.
DESCRIPTION = "Compare every vendored input under vendor/ with its source, fetched at its pin."

ROOT = Path(__file__).resolve().parent.parent
VENDOR = "vendor"
MANIFEST = "VENDOR.json"
ATTEMPTS = 3
REMOVED_VARIABLES = ("GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN", "NODE_AUTH_TOKEN")
TIMEOUT = 900


class UsageError(Exception):
    """The run cannot start: a bad argument, an unreadable pin or a missing tool."""


class Unreachable(Exception):
    """The source could not be fetched after every attempt."""


def child_env() -> dict:
    env = {k: v for k, v in os.environ.items() if k not in REMOVED_VARIABLES}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"
    return env


def node_env() -> dict:
    return {"PATH": os.environ.get("PATH", os.defpath)}


def run(argv: list, cwd=None, env=None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, cwd=cwd, env=env if env is not None else child_env(),
                              capture_output=True, timeout=TIMEOUT)
    except FileNotFoundError:
        raise UsageError(f"{argv[0]} is not installed") from None
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, b"", f"timed out after {TIMEOUT}s".encode())


def last_line(proc: subprocess.CompletedProcess) -> str:
    lines = proc.stderr.decode("utf-8", "replace").strip().splitlines()
    return lines[-1] if lines else f"exit {proc.returncode}"


def git(clone: Path, *args: str) -> subprocess.CompletedProcess:
    return run(["git", "-c", "credential.helper=", "-C", str(clone), *args])


def with_attempts(source: str, what: str, action, delay: float):
    """Run action() until it returns a CompletedProcess that exited 0, at most ATTEMPTS
    times. Raises Unreachable when every attempt fails."""
    for attempt in range(1, ATTEMPTS + 1):
        proc = action()
        if proc.returncode == 0:
            return proc
        print(f"{source}: {what}: attempt {attempt} of {ATTEMPTS} failed: {last_line(proc)}",
              file=sys.stderr)
        if attempt < ATTEMPTS and delay > 0:
            time.sleep(delay * attempt)
    raise Unreachable(what)


def load_manifests(root: Path) -> dict:
    vendor = root / VENDOR
    sources = sorted(p.name for p in vendor.iterdir()
                     if p.is_dir() and (p / MANIFEST).is_file()) if vendor.is_dir() else []
    if not sources:
        raise UsageError(f"no {VENDOR}/<source>/{MANIFEST} under {root}")
    manifests = {}
    for source in sources:
        rel = f"{VENDOR}/{source}/{MANIFEST}"
        try:
            manifest = json.loads((vendor / source / MANIFEST).read_bytes().decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise UsageError(f"{rel} is not valid JSON ({exc})") from None
        files = manifest.get("files") if isinstance(manifest, dict) else None
        if not isinstance(files, list) or not files or \
                not all(isinstance(f, str) and f for f in files):
            raise UsageError(f"{rel} is not a pin with a files list; "
                             f"run python3 scripts/check_technique_crosswalk.py")
        if "package" in manifest:
            needed = ("package", "version", "registry", "integrity", "generate")
        else:
            needed = ("repo", "commit")
        missing = [key for key in needed if not isinstance(manifest.get(key), str)]
        if missing:
            raise UsageError(f"{rel} has no {', '.join(missing)}; "
                             f"run python3 scripts/check_technique_crosswalk.py")
        manifests[source] = manifest
    return manifests


def generator(root: Path, source: str, extension: str) -> Path:
    path = root / VENDOR / source / f"generate.{extension}"
    if not path.is_file():
        raise UsageError(f"{VENDOR}/{source}/{MANIFEST} has generate but "
                         f"{VENDOR}/{source}/generate.{extension} is absent")
    return path


def fetch_git(root: Path, source: str, manifest: dict, location: str, work: Path,
              delay: float, drift: list) -> dict:
    """{file: upstream bytes} for a git source, or {} when the pin itself does not hold."""
    commit = manifest["commit"]
    clone = work / "clone"

    def clone_once():
        shutil.rmtree(clone, ignore_errors=True)
        return run(["git", "-c", "credential.helper=", "clone", "-q", "--filter=blob:none",
                    "--no-checkout", location, str(clone)])

    with_attempts(source, f"clone {location}", clone_once, delay)
    if git(clone, "cat-file", "-e", f"{commit}^{{commit}}").returncode != 0:
        print(f"{source}: commit {commit} is not in {location}", file=sys.stderr)
        drift.append(MANIFEST)
        return {}
    tag = manifest.get("version")
    if isinstance(tag, str):
        named = git(clone, "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}")
        if named.returncode != 0 or named.stdout.decode().strip() != commit:
            print(f"{source}: tag {tag} does not name {commit} in {location}", file=sys.stderr)
            drift.append(MANIFEST)

    fetched = {}
    if "generate" in manifest:
        script = generator(root, source, "py")
        for name in manifest["files"]:
            # The generator exits 3 when git fails, as a blob fetch from the remote does;
            # only that is tried again. 1 is content it cannot read, which is drift.
            proc = None
            for attempt in range(1, ATTEMPTS + 1):
                proc = run([sys.executable, "-I", str(script), str(clone), commit, name],
                           cwd=work)
                if proc.returncode != 3:
                    break
                print(f"{source}: generate {name}: attempt {attempt} of {ATTEMPTS} failed: "
                      f"{last_line(proc)}", file=sys.stderr)
                if attempt < ATTEMPTS and delay > 0:
                    time.sleep(delay * attempt)
            if proc.returncode == 3:
                raise Unreachable(f"generate {name}")
            if proc.returncode == 2:
                raise UsageError(f"{script.relative_to(root)} refused its arguments: "
                                 f"{last_line(proc)}")
            if proc.returncode != 0:
                print(f"{source}: generate {name}: {last_line(proc)}", file=sys.stderr)
                fetched[name] = None
            else:
                fetched[name] = proc.stdout
    else:
        for name in manifest["files"]:
            listed = git(clone, "ls-tree", "--name-only", commit, "--", name)
            if listed.returncode != 0 or listed.stdout.decode("utf-8").strip() != name:
                print(f"{source}: {name} is not in {commit}", file=sys.stderr)
                fetched[name] = None
                continue
            proc = with_attempts(source, f"git show {commit}:{name}",
                                 lambda name=name: git(clone, "show", f"{commit}:{name}"), delay)
            fetched[name] = proc.stdout
    return fetched


def require_extraction_filters():
    """Raise UsageError when this interpreter's tarfile has no extraction filters, which
    safe_extract needs. They are in Python 3.12 and later, and in 3.8.17, 3.9.17, 3.10.12
    and 3.11.4 and later releases of those lines."""
    if not hasattr(tarfile, "data_filter"):
        raise UsageError(
            f"{sys.executable} is Python {sys.version.split()[0]}, whose tarfile module has "
            f"no extraction filters; a package source needs Python 3.12 or later, or "
            f"3.8.17, 3.9.17, 3.10.12 or 3.11.4 or later in those lines")


def safe_extract(tarball: Path, into: Path):
    # The "data" filter refuses absolute paths, paths that leave the directory, links that
    # point outside it, and device files.
    require_extraction_filters()
    with tarfile.open(tarball, "r:gz") as archive:
        archive.extractall(into, filter="data")


def fetch_package(root: Path, source: str, manifest: dict, location, work: Path,
                  delay: float, drift: list) -> dict:
    """{file: regenerated bytes} for a package, or {} when the tarball is not the pinned one."""
    package, version = manifest["package"], manifest["version"]
    destination = work / "pack"

    def pack_once():
        shutil.rmtree(destination, ignore_errors=True)
        destination.mkdir(parents=True)
        if location is None:
            # An empty cache of its own, so the tarball is read from the registry each run.
            return run(["npm", "pack", f"{package}@{version}", "--pack-destination",
                        str(destination), "--registry", manifest["registry"],
                        "--cache", str(work / "npm-cache"), "--ignore-scripts"], cwd=work)
        argv = ["copy", location]
        if not Path(location).is_file():
            return subprocess.CompletedProcess(argv, 1, b"", f"{location} is not a file".encode())
        shutil.copyfile(location, destination / Path(location).name)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    what = f"npm pack {package}@{version}" if location is None else f"read {location}"
    with_attempts(source, what, pack_once, delay)
    packed = sorted(destination.glob("*.tgz"))
    if len(packed) != 1:
        print(f"{source}: {what} left {len(packed)} tarballs", file=sys.stderr)
        raise Unreachable(what)
    tarball = packed[0]
    digest = "sha512-" + base64.b64encode(hashlib.sha512(tarball.read_bytes()).digest()).decode()
    if digest != manifest["integrity"]:
        print(f"{source}: the tarball's sha512 is {digest}, not the pinned integrity",
              file=sys.stderr)
        drift.append(MANIFEST)
        return {}
    extracted = work / "extracted"
    extracted.mkdir()
    try:
        safe_extract(tarball, extracted)
    except (tarfile.TarError, OSError) as exc:
        print(f"{source}: cannot extract {tarball.name}: {exc}", file=sys.stderr)
        drift.append(MANIFEST)
        return {}
    package_dir = extracted / "package"
    script = generator(root, source, "mjs")
    fetched = {}
    for name in manifest["files"]:
        proc = run(["node", str(script), str(package_dir), name], cwd=work, env=node_env())
        if proc.returncode != 0:
            print(f"{source}: generate {name}: {last_line(proc)}", file=sys.stderr)
            fetched[name] = None
        else:
            fetched[name] = proc.stdout
    return fetched


def check_source(root: Path, source: str, manifest: dict, override, work: Path,
                 delay: float) -> tuple:
    """(drift file names, unreachable) for one source."""
    drift = []
    try:
        if "package" in manifest:
            fetched = fetch_package(root, source, manifest, override, work, delay, drift)
        else:
            location = override if override is not None else \
                f"https://github.com/{manifest['repo']}.git"
            fetched = fetch_git(root, source, manifest, location, work, delay, drift)
    except Unreachable:
        return [], True
    for name in manifest["files"]:
        if name not in fetched:
            continue
        vendored = root / VENDOR / source / name
        if fetched[name] is None or not vendored.is_file() or \
                vendored.read_bytes() != fetched[name]:
            drift.append(name)
    return drift, False


def parse_overrides(values: list, manifests: dict) -> dict:
    overrides = {}
    for value in values:
        source, sep, location = value.partition("=")
        if not sep or not location:
            raise UsageError(f"--override {value!r} is not <source>=<location>")
        if source not in manifests:
            raise UsageError(f"--override names {source!r}, which is not a source under "
                             f"{VENDOR}/ ({', '.join(sorted(manifests))})")
        overrides[source] = location
    return overrides


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description=DESCRIPTION, allow_abbrev=False)
    parser.add_argument("root", nargs="?",
                        help="the repository root; the default is the parent of this "
                             "script's directory")
    parser.add_argument("--override", action="append", default=[], metavar="SOURCE=LOCATION",
                        help="fetch SOURCE from LOCATION: a git URL or repository path, or a "
                             "package tarball")
    parser.add_argument("--retry-delay", type=float, default=5.0, metavar="SECONDS",
                        help="seconds before the second attempt, doubled before the third "
                             "(default 5)")
    args = parser.parse_args(argv)
    try:
        if args.root is None:
            root = ROOT
        elif os.path.isdir(args.root):
            root = Path(args.root).resolve()
        else:
            raise UsageError(f"the root argument {args.root!r} names no directory")
        if args.retry_delay < 0:
            raise UsageError("--retry-delay is negative")
        manifests = load_manifests(root)
        overrides = parse_overrides(args.override, manifests)
        if any("package" in manifest for manifest in manifests.values()):
            # Checked before any fetch, so the run stops before it reads the network.
            require_extraction_filters()
        drifted, unreachable, files = [], [], 0
        with tempfile.TemporaryDirectory(prefix="vendor-integrity-") as tmp:
            for source in sorted(manifests):
                work = Path(tmp) / source
                work.mkdir()
                drift, lost = check_source(root, source, manifests[source],
                                           overrides.get(source), work, args.retry_delay)
                if lost:
                    unreachable.append(source)
                    print(f"UNREACHABLE {source}: upstream unreachable, drift not measured")
                    continue
                files += len(manifests[source]["files"])
                for name in drift:
                    drifted.append((source, name))
                    print(f"DRIFT {source} {name}")
    except UsageError as exc:
        print(f"usage error: {exc}", file=sys.stderr)
        return 2
    if drifted:
        return 1
    if unreachable:
        return 3
    print(f"OK: {files} vendored files in {len(manifests)} sources match their sources at "
          f"the pin")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
