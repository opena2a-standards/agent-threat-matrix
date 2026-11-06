#!/usr/bin/env python3
"""Print vendor/damn-vulnerable-ai-agent/expected-checks.json from a clone of DVAA.

The file is one JSON object keyed by scenario directory name. Each value is that
scenario's ``scenarios/<name>/expected-checks.json`` array, read at a commit and copied
in its own order: the HackMyAgent check ids the scenario expects a scan to report. A
scenario directory that holds no expected-checks.json has no key.

Usage:

    git -c credential.helper= clone --filter=blob:none --no-checkout \\
        https://github.com/opena2a-org/damn-vulnerable-ai-agent.git <dir>
    python3 -I vendor/damn-vulnerable-ai-agent/generate.py <dir> <commit> expected-checks.json \\
        > vendor/damn-vulnerable-ai-agent/expected-checks.json

The commit is the 40-hex ``commit`` of VENDOR.json. Each file is read with
``git show <commit>:<path>``, which fetches the blob from the clone's remote when the clone
holds none. git runs without credential helpers, without terminal prompts and without
GITHUB_TOKEN. Standard library only. Output is stable: keys sorted, two space indent,
trailing newline. Exit 0 when printed, 1 when a scenario file is not a JSON array of strings
or the commit holds none, 2 on a usage error, and 3 when git fails, as it does when a blob
cannot be fetched from the remote.
"""

import json
import os
import re
import subprocess
import sys

OUTPUT = "expected-checks.json"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SCENARIO_FILE_RE = re.compile(r"^scenarios/([^/]+)/expected-checks\.json$")
USAGE = "usage: generate.py <git dir> <40-hex commit> expected-checks.json"


class GenerateError(Exception):
    """A scenario file is not a JSON array of strings, or the commit holds none."""


class GitError(Exception):
    """git failed: a blob fetch from the remote, or a commit the clone does not hold."""


def git_env() -> dict:
    env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_TOKEN", "GH_TOKEN")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def git(git_dir: str, *args: str) -> bytes:
    proc = subprocess.run(["git", "-c", "credential.helper=", "-C", git_dir, *args],
                          capture_output=True, env=git_env(), timeout=600)
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GitError(f"git {' '.join(args)} failed: {detail[-1] if detail else proc.returncode}")
    return proc.stdout


def scenario_files(git_dir: str, commit: str) -> dict:
    """{scenario name: path} for every scenarios/<name>/expected-checks.json at commit."""
    listing = git(git_dir, "ls-tree", "-r", "-z", "--name-only", commit, "--", "scenarios")
    out = {}
    for path in listing.decode("utf-8").split("\0"):
        m = SCENARIO_FILE_RE.match(path)
        if m:
            out[m.group(1)] = path
    return out


def parse(path: str, data: bytes) -> list:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise GenerateError(f"{path} is not valid JSON: {exc}") from None
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise GenerateError(f"{path} is not a JSON array of strings")
    return value


def render(files: dict) -> str:
    """The output text for {scenario name: (path, raw bytes)}."""
    doc = {name: parse(path, data) for name, (path, data) in sorted(files.items())}
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def generate(git_dir: str, commit: str) -> str:
    files = {name: (path, git(git_dir, "show", f"{commit}:{path}"))
             for name, path in scenario_files(git_dir, commit).items()}
    if not files:
        raise GenerateError(f"no scenarios/<name>/expected-checks.json at {commit}")
    return render(files)


def main(argv: list) -> int:
    if len(argv) != 3 or not COMMIT_RE.match(argv[1]) or argv[2] != OUTPUT:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        text = generate(argv[0], argv[1])
    except GenerateError as exc:
        print(f"generate.py: {exc}", file=sys.stderr)
        return 1
    except (GitError, OSError, subprocess.SubprocessError) as exc:
        print(f"generate.py: {exc}", file=sys.stderr)
        return 3
    sys.stdout.buffer.write(text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
