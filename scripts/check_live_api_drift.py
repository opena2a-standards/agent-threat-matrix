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
import sys
import urllib.request

API_URL = "https://api.oa2a.org/api/v1/threat-matrix"


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

    for field in ("version", "created"):
        if live.get(field) != spec.get(field):
            failures.append(
                f"{field}: live API serves {live.get(field)!r}, matrix.json says {spec.get(field)!r}"
            )

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

    if failures:
        print(f"FAIL: live registry drifts from matrix.json ({len(failures)} finding(s)):")
        for f_ in failures:
            print(f"  - {f_}")
        return 1

    print(
        f"Live registry matches matrix.json: version {spec['version']}, "
        f"{len(spec['tactics'])} tactics, {len(spec['techniques'])} techniques, "
        f"{len(spec['attackClasses'])} attack classes, {len(spec['attackPaths'])} attack paths."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
