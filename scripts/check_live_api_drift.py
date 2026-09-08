#!/usr/bin/env python3
"""Fail when the live registry's threat matrix drifts from this repo's matrix.json.

The registry (api.oa2a.org) serves the matrix that threats.opena2a.org renders.
This repo is the canonical source; the registry is import-derived. The check
compares the metadata and counts that have actually drifted before:

- version: the API hardcoded "1.0" for two months after the spec shipped 1.1
  (rendered in the site header on every page).
- created: the API served the request date as the creation date.
- counts: registry-side migrations once added classes without memberships.

Read-only over the public endpoint, so it carries no secret. It compares
spec-owned metadata and counts only — content fields the registry legitimately
enriches at runtime (threat status, prevalence, evidence) are out of scope.
"""

import json
import os
import sys
import urllib.request

API_URL = "https://api.oa2a.org/api/v1/threat-matrix"


def _version_tuple(value) -> tuple:
    """Parse "1.2" or "1.2.0" into a comparable tuple; anything unparseable sorts lowest."""
    try:
        return tuple(int(part) for part in str(value).split("."))
    except (TypeError, ValueError):
        return ()


def main() -> int:
    with open("matrix.json") as f:
        spec = json.load(f)

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
