#!/usr/bin/env python3
"""Fail when the live registry's threat matrix drifts from this repo's matrix.json.

The registry (api.oa2a.org) serves the matrix that threats.opena2a.org renders.
This repo is the canonical source; the registry is import-derived. The check
compares the metadata and counts that have actually drifted before:

- version: the API hardcoded "1.0" for two months after the spec shipped 1.1
  (rendered in the site header on every page).
- created: the API served the request date as the creation date.
- counts: registry-side migrations once added classes without memberships.
- README.md: the sentence stating which version the live API labels the matrix
  with, which version this repository is at, and that the counts agree. It is a
  measurement of this same payload, so it is held to it, and it fails once the
  registry catches up until the sentence is removed.

Read-only over the public endpoint, so it carries no secret. It compares
spec-owned metadata and counts only — content fields the registry legitimately
enriches at runtime (threat status, prevalence, evidence) are out of scope.
"""

import json
import os
import re
import sys
import urllib.request

API_URL = "https://api.oa2a.org/api/v1/threat-matrix"

LIVE_CLAIM = "labels the matrix"
LIVE_VERSION = re.compile(r"labels the matrix (\d+(?:\.\d+)*)")
REPO_VERSION = re.compile(r"this repository is at (\d+(?:\.\d+)*)")
COUNTS_CLAIM = "the technique and tactic counts agree"


def _version_tuple(value) -> tuple:
    """Parse "1.2" or "1.2.0" into a comparable tuple; anything unparseable sorts lowest."""
    try:
        return tuple(int(part) for part in str(value).split("."))
    except (TypeError, ValueError):
        return ()


def readme_findings(readme: str, live: dict, spec: dict) -> list:
    """Findings for each README line that states the live API's matrix version."""
    findings = []
    live_version, spec_version = live.get("version"), spec.get("version")
    for n, line in enumerate(readme.splitlines(), 1):
        if LIVE_CLAIM not in line:
            continue
        where = f"README.md:{n}"
        stated = LIVE_VERSION.search(line)
        if not stated:
            findings.append(
                f"{where} states the live API's matrix version, but no version "
                f"number follows {LIVE_CLAIM!r}"
            )
        elif stated.group(1) != str(live_version):
            finding = f"{where} says the live API labels the matrix {stated.group(1)}; it serves {live_version!r}"
            if live_version == spec_version:
                finding += ", the same version as matrix.json, so remove the sentence"
            findings.append(finding)
        elif live_version == spec_version:
            findings.append(
                f"{where} states a version gap, but the live API and matrix.json "
                f"both say {spec_version!r}, so remove the sentence"
            )

        repo = REPO_VERSION.search(line)
        if repo and repo.group(1) != str(spec_version):
            findings.append(f"{where} says this repository is at {repo.group(1)}; matrix.json says {spec_version!r}")

        if COUNTS_CLAIM in line:
            for coll in ("techniques", "tactics"):
                n_live, n_spec = len(live.get(coll) or []), len(spec.get(coll) or [])
                if n_live != n_spec:
                    findings.append(
                        f"{where} says {COUNTS_CLAIM}; {coll}: live API has {n_live}, matrix.json has {n_spec}"
                    )
    return findings


def main() -> int:
    with open("matrix.json") as f:
        spec = json.load(f)
    with open("README.md") as f:
        readme = f.read()

    try:
        with urllib.request.urlopen(API_URL, timeout=30) as resp:
            live = json.load(resp)
    except Exception as e:  # unreachable API is its own (infra) problem — fail loud
        print(f"FAIL: could not fetch {API_URL}: {e}")
        return 1

    failures = []
    notes = []

    for field in ("version", "created"):
        if live.get(field) != spec.get(field):
            finding = f"{field}: live API serves {live.get(field)!r}, matrix.json says {spec.get(field)!r}"
            # A pull request that releases a NEWER matrix version is ahead of the
            # live registry by construction until the registry re-imports after
            # the merge; on pull_request runs that one condition is reported, not
            # failed. Every other drift (an older version, a changed created
            # date, a count, a hollow class) still fails, and push and scheduled
            # runs fail on the version too, because after a merge the registry
            # is the thing that must catch up.
            if (
                field == "version"
                and os.environ.get("GITHUB_EVENT_NAME") == "pull_request"
                and _version_tuple(spec.get(field)) > _version_tuple(live.get(field))
            ):
                notes.append(finding + " (pending registry re-import after merge)")
                continue
            failures.append(finding)

    for coll in ("tactics", "techniques", "attackClasses", "attackPaths"):
        n_live, n_spec = len(live.get(coll) or []), len(spec.get(coll) or [])
        if n_live != n_spec:
            failures.append(f"{coll}: live API has {n_live}, matrix.json has {n_spec}")

    # A class served with an empty membership while techniques declare it is the
    # exact defect that rendered "0 techniques" on the live /classes page.
    declared = {c["id"] for c in (live.get("attackClasses") or []) if c.get("techniques")}
    derived = {t.get("attackClass") for t in (live.get("techniques") or [])}
    hollow = sorted(derived - declared - {None})
    if hollow:
        failures.append(
            f"classes with empty techniques[] while techniques declare membership: {', '.join(hollow)}"
        )

    failures.extend(readme_findings(readme, live, spec))

    for n_ in notes:
        print(f"NOTE: {n_}")

    if failures:
        print(f"FAIL: live registry drifts from matrix.json ({len(failures)} finding(s)):")
        for f_ in failures:
            print(f"  - {f_}")
        return 1

    qualifier = f" apart from {len(notes)} noted item(s)" if notes else ""
    print(
        f"Live registry matches matrix.json{qualifier}: version {spec['version']}, "
        f"{len(spec['tactics'])} tactics, {len(spec['techniques'])} techniques, "
        f"{len(spec['attackClasses'])} attack classes, {len(spec['attackPaths'])} attack paths."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
