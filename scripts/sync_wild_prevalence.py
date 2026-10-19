#!/usr/bin/env python3
"""Read each technique's wild prevalence and wild sample count from the registry into matrix.json.

The registry endpoint ``API_URL`` serves ``wildPrevalence`` and ``wildSampleCount`` on the
techniques it lists. This script reads the endpoint once and, on each technique of
matrix.json, writes the two values the endpoint serves for the technique with the same
id, or 0 for both where the endpoint serves no value for it or does not list it. It
records the endpoint and the read date in the top-level ``wildPrevalenceSource`` and
writes no other technique field. When that changes matrix.json it also moves ``updated``
to today if it is older, as scripts/validate_matrix.py requires of any change, and renders
the STIX bundle again with scripts/generate_stix.py, whose objects take their
``modified`` date from ``updated``.

Usage::

    python3 scripts/sync_wild_prevalence.py
    python3 scripts/sync_wild_prevalence.py --payload saved.json --read-date 2026-10-19

``--payload`` reads a response saved from the endpoint instead of fetching it, and then
``--read-date`` gives the date it was read.

Refused, with matrix.json left as it was: a response that cannot be fetched or does not
parse, holds no technique list, lists an entry without a string id or one id twice, or
lists none of the technique ids in matrix.json; a ``wildPrevalence`` that is not a number
from 0 to 100; a ``wildSampleCount`` that is not a whole number of 0 or more; and a
``wildPrevalence`` above 0 served with a ``wildSampleCount`` of 0.

Exit 0 when matrix.json was written or already held the values, 1 when the response is
refused or the STIX bundle cannot be rendered, 2 on a usage error (a ``--read-date`` that
is not a YYYY-MM-DD date, or is later than today, included).
"""

import argparse
import copy
import json
import math
import re
import subprocess
import sys
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "matrix.json"
STIX_GENERATOR = ROOT / "scripts" / "generate_stix.py"
API_URL = "https://api.oa2a.org/api/v1/threat-matrix"
# The first line of the docstring, which ``python3 -OO`` strips.
DESCRIPTION = ("Read each technique's wild prevalence and wild sample count from the registry "
               "into matrix.json.")
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


class Refused(Exception):
    """The response cannot be written into matrix.json; the message says why."""


def is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def served_values(payload) -> dict:
    """Map each technique id the response lists to its (wildPrevalence, wildSampleCount)."""
    techniques = payload.get("techniques") if isinstance(payload, dict) else None
    if not isinstance(techniques, list) or not techniques:
        raise Refused("the response holds no techniques list")
    values = {}
    for index, entry in enumerate(techniques):
        tid = entry.get("id") if isinstance(entry, dict) else None
        if not isinstance(tid, str):
            raise Refused(f"techniques[{index}] in the response has no string id")
        if tid in values:
            raise Refused(f"{tid} is listed twice in the response")
        prevalence = entry.get("wildPrevalence")
        samples = entry.get("wildSampleCount")
        prevalence = 0 if prevalence is None else prevalence
        samples = 0 if samples is None else samples
        if not (is_number(prevalence) and 0 <= prevalence <= 100):
            raise Refused(f"{tid}: wildPrevalence {prevalence!r} is not a number from 0 to 100")
        if not (isinstance(samples, int) and not isinstance(samples, bool) and samples >= 0):
            raise Refused(f"{tid}: wildSampleCount {samples!r} is not a whole number of 0 or more")
        if prevalence > 0 and samples == 0:
            raise Refused(f"{tid}: wildPrevalence {prevalence!r} is served with a wildSampleCount of 0")
        values[tid] = (prevalence, samples)
    return values


def apply(matrix: dict, values: dict, read_date: str) -> dict:
    """Write the served values onto the techniques of matrix; return what was written."""
    ids = [t["id"] for t in matrix["techniques"]]
    if not set(ids) & set(values):
        raise Refused("the response lists none of the technique ids in matrix.json")
    absent = []
    for technique in matrix["techniques"]:
        if technique["id"] in values:
            prevalence, samples = values[technique["id"]]
        else:
            prevalence, samples = 0, 0
            absent.append(technique["id"])
        technique["wildPrevalence"] = prevalence
        technique["wildSampleCount"] = samples
    matrix["wildPrevalenceSource"] = {"url": API_URL, "read": read_date}
    return {
        "absent": absent,
        "unlisted": sorted(set(values) - set(ids)),
        "aboveZero": sum(1 for t in matrix["techniques"] if t["wildPrevalence"] > 0),
    }


def parse_args(argv, today: str):
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("--payload", type=Path,
                        help="read a response saved from the endpoint instead of fetching it")
    parser.add_argument("--read-date", help="the date the --payload response was read, as YYYY-MM-DD")
    args = parser.parse_args(argv)
    if args.payload is None:
        if args.read_date is not None:
            parser.error("--read-date is the date of a --payload response; a fetch is read today")
        return args
    if args.read_date is None:
        parser.error("--payload needs --read-date, the date the response was read")
    try:
        valid = bool(DATE_RE.fullmatch(args.read_date)) and bool(date.fromisoformat(args.read_date))
    except ValueError:
        valid = False
    if not valid:
        parser.error(f"--read-date {args.read_date!r} is not a YYYY-MM-DD date")
    if args.read_date > today:
        parser.error(f"--read-date {args.read_date} is later than today, {today}")
    return args


def read_response(args, today: str):
    """The response and the date it was read."""
    if args.payload is None:
        try:
            with urllib.request.urlopen(API_URL, timeout=30) as resp:
                return json.load(resp), today
        except (OSError, ValueError) as exc:
            raise Refused(f"could not fetch {API_URL}: {exc}")
    try:
        return json.loads(args.payload.read_text(encoding="utf-8")), args.read_date
    except (OSError, ValueError) as exc:
        raise Refused(f"could not read {args.payload}: {exc}")


def without_updated(matrix: dict) -> dict:
    return {key: value for key, value in matrix.items() if key != "updated"}


def main(argv=None) -> int:
    today = date.today().isoformat()
    args = parse_args(argv, today)
    try:
        payload, read_date = read_response(args, today)
        values = served_values(payload)
        try:
            matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise Refused(f"could not read matrix.json: {exc}")
        before = copy.deepcopy(matrix)
        report = apply(matrix, values, read_date)
    except Refused as exc:
        print(f"FAIL: {exc}; matrix.json is unchanged", file=sys.stderr)
        return 1

    if without_updated(matrix) == without_updated(before):
        print(f"matrix.json already holds the values {API_URL} served, read {read_date}; nothing written")
        return 0

    if matrix["updated"] < today:
        matrix["updated"] = today
    MATRIX.write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, str(STIX_GENERATOR)],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        print(f"FAIL: matrix.json is written, but scripts/generate_stix.py failed: "
              f"{proc.stderr.strip() or proc.stdout.strip()}", file=sys.stderr)
        return 1

    print(f"Wrote wildPrevalence and wildSampleCount on {len(matrix['techniques'])} techniques from "
          f"{API_URL}, read {read_date}: {report['aboveZero']} above 0. updated is "
          f"{matrix['updated']} and the STIX bundle is rendered again.")
    if report["absent"]:
        print(f"Not listed by the endpoint, written as 0: {', '.join(report['absent'])}")
    if report["unlisted"]:
        print(f"Listed by the endpoint but not in matrix.json, left out: {', '.join(report['unlisted'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
