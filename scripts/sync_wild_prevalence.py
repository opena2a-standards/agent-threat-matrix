#!/usr/bin/env python3
"""Read each technique's wild prevalence and wild sample count from the registry into matrix.json.

The registry endpoint ``API_URL`` serves ``wildPrevalence`` and ``wildSampleCount`` on the
techniques it lists. This script copies them only for a closed period: the response must
name, in its top-level ``wildPeriod``, the ``start`` and the ``end`` of the period its values
cover, as YYYY-MM-DD dates, the first and the last day included, and the period must have
ended before the read date. A response that names no closed period is refused, so the
script writes nothing until the registry serves one.

This script reads the endpoint once and, on each technique of matrix.json, writes the two
values the endpoint serves for the technique with the same id, or 0 for both where the
endpoint serves no value for it or does not list it. It records the endpoint, the read
date and the period bounds in the top-level ``wildPrevalenceSource``. In ``evidence`` it
writes the ``honeypot-telemetry`` entry that cites the same read: one on each technique the
endpoint served a ``wildSampleCount`` above 0 for, with the endpoint as its reference, the
read date as its date and the period bounds in its note, after the technique's other
entries, and none on the others. It leaves every other evidence entry as it was, drops an
``evidence`` array it leaves empty, and writes no other technique field. When it writes
matrix.json it also moves ``updated`` to today if it is older, as scripts/validate_matrix.py
requires of any change, renders the STIX bundle and evidence-gaps.json again with
scripts/generate_stix.py, whose objects take their ``modified`` date from ``updated``,
renders crosswalks/technique-crosswalk.json again with scripts/build_technique_crosswalk.py,
which records the sha256 of matrix.json and dates the file with the latest of ``updated``
and the read dates of its vendored inputs, and then runs
scripts/check_technique_pages.py --fix. The References section of a technique page lists
the technique's evidence entries, one Evidence line each, and that check fails on a page
whose lines differ from them, so the run writes the Evidence lines of the entries this
script wrote and drops those of the entries it dropped.

A run that leaves matrix.json as it is renders those files and runs that check in the same
way when one of them disagrees with matrix.json: when the STIX bundle or evidence-gaps.json
differs from what scripts/generate_stix.py renders from it, crosswalks/technique-crosswalk.json
differs from what scripts/build_technique_crosswalk.py renders or cannot be rendered, or
scripts/check_technique_pages.py exits 1. A run that writes matrix.json and then cannot
render one of them, as when a vendored input of the crosswalk is absent, leaves the tree so,
and once the cause is fixed the next run with the same response renders them.

It never rewrites a value matrix.json holds for a period. A response for the period
``wildPrevalenceSource`` already gives, with the values matrix.json holds for it, leaves
matrix.json as it is; one that serves another ``wildPrevalence`` or ``wildSampleCount`` for a technique
in that period is refused, and so is a period that starts on or before the day the held
period ends. A ``wildPrevalenceSource`` that gives no period, such as the one written from
a read taken before the endpoint named periods, takes the first closed period served.

Usage::

    python3 scripts/sync_wild_prevalence.py
    python3 scripts/sync_wild_prevalence.py --payload saved.json --read-date 2026-10-19

``--payload`` reads a response saved from the endpoint instead of fetching it, and then
``--read-date`` gives the date it was read.

Refused, with matrix.json left as it was: a response that cannot be fetched or does not
parse, holds no technique list, lists an entry without a string id or one id twice, or
lists none of the technique ids in matrix.json; a ``wildPrevalence`` or ``wildSampleCount``
that is an integer too large to convert to a 64-bit float, which JSON allows and
scripts/validate_matrix.py reports as not a finite number; a ``wildPrevalence`` that is not
a number from 0 to 100; a ``wildSampleCount`` that is not a whole number of 0 or more; a
``wildPrevalence`` above 0 served with a ``wildSampleCount`` of 0; a response with no
``wildPeriod``, or one whose ``start`` or ``end`` is not a YYYY-MM-DD date, whose ``start``
is later than its ``end``, or whose ``end`` is not earlier than the read date; a period that
matrix.json already holds other values for, or that starts on or before the day the held
period ends; a ``wildPrevalenceSource`` period in matrix.json without a YYYY-MM-DD
``start`` and ``end``; and a technique in matrix.json whose ``evidence`` is not an array.

Exit 0 when matrix.json was written or already held the values, 1 when the response is
refused, the STIX bundle or the crosswalk cannot be rendered, or
scripts/check_technique_pages.py --fix exits 1, as it does when a page line still disagrees
with matrix.json after it writes what it can, such as on a technique page with no Tactic
link to write the Evidence lines under, and 2 on a usage error (a ``--read-date`` that is
not a YYYY-MM-DD date, or is later than today, included).
"""

import argparse
import importlib.util
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
CROSSWALK_BUILDER = ROOT / "scripts" / "build_technique_crosswalk.py"
PAGE_CHECKER = ROOT / "scripts" / "check_technique_pages.py"
API_URL = "https://api.oa2a.org/api/v1/threat-matrix"
TELEMETRY = "honeypot-telemetry"
TELEMETRY_NOTE = ("The wildPrevalence and wildSampleCount this endpoint served for the technique over the "
                  "closed period {start} to {end}, read on this date; they measure engagement with a "
                  "honeypot, not a production attack rate.")
# The top-level field of the response that names the closed period its values cover.
PERIOD = "wildPeriod"
# The first line of the docstring, which ``python3 -OO`` strips.
DESCRIPTION = ("Read each technique's wild prevalence and wild sample count from the registry "
               "into matrix.json.")
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


class Refused(Exception):
    """The response cannot be written into matrix.json; the message says why."""


def too_large_for_float(value) -> bool:
    """Whether value is an int too large to convert to a 64-bit float.

    JSON allows an integer of any length, but math.isfinite converts an int to a float
    first and raises OverflowError on such an int, so is_number asks this first.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        return False
    try:
        float(value)
    except OverflowError:
        return True
    return False


def is_number(value) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and not too_large_for_float(value) and math.isfinite(value))


def is_date(value) -> bool:
    """Whether value is a YYYY-MM-DD string that names a calendar date."""
    if not (isinstance(value, str) and DATE_RE.fullmatch(value)):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def served_period(payload, read_date: str) -> dict:
    """The closed period the response serves its values for, as {"start": ..., "end": ...}."""
    period = payload.get(PERIOD)
    if period is None:
        raise Refused(f"the response names no closed period in {PERIOD}, so its values are not "
                      f"copied until the registry serves one")
    if not isinstance(period, dict):
        raise Refused(f"{PERIOD} in the response is not an object with a start and an end")
    for key in ("start", "end"):
        if not is_date(period.get(key)):
            raise Refused(f"{PERIOD}.{key} {period.get(key)!r} in the response is not a YYYY-MM-DD date")
    start, end = period["start"], period["end"]
    if start > end:
        raise Refused(f"{PERIOD} starts on {start}, after it ends on {end}")
    if end >= read_date:
        raise Refused(f"{PERIOD} {start} to {end} is not closed: it ends on or after the read date, "
                      f"{read_date}")
    return {"start": start, "end": end}


def held_period(matrix: dict):
    """The period matrix.json holds values for, or None where wildPrevalenceSource gives none."""
    source = matrix.get("wildPrevalenceSource")
    if not isinstance(source, dict) or "period" not in source:
        return None
    period = source["period"]
    if not (isinstance(period, dict) and is_date(period.get("start")) and is_date(period.get("end"))):
        raise Refused("wildPrevalenceSource.period in matrix.json is not a YYYY-MM-DD start and end")
    return {"start": period["start"], "end": period["end"]}


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
        for name, value in (("wildPrevalence", prevalence), ("wildSampleCount", samples)):
            if too_large_for_float(value):
                raise Refused(f"{tid}: {name} is an integer of {len(str(abs(value)))} digits, too large "
                              f"for a 64-bit float, so it is not a finite number")
        if not (is_number(prevalence) and 0 <= prevalence <= 100):
            raise Refused(f"{tid}: wildPrevalence {prevalence!r} is not a number from 0 to 100")
        if not (isinstance(samples, int) and not isinstance(samples, bool) and samples >= 0):
            raise Refused(f"{tid}: wildSampleCount {samples!r} is not a whole number of 0 or more")
        if prevalence > 0 and samples == 0:
            raise Refused(f"{tid}: wildPrevalence {prevalence!r} is served with a wildSampleCount of 0")
        values[tid] = (prevalence, samples)
    return values


def cites_the_endpoint(entry) -> bool:
    """Whether an evidence entry is the honeypot-telemetry entry this script writes."""
    return isinstance(entry, dict) and entry.get("type") == TELEMETRY and entry.get("reference") == API_URL


def write_telemetry_entry(technique: dict, samples: int, read_date: str, period: dict) -> None:
    """Leave the technique one entry citing this read if the endpoint served samples for it,
    after its other entries, and none otherwise."""
    evidence = technique.get("evidence", [])
    if not isinstance(evidence, list):
        raise Refused(f"{technique['id']}: evidence in matrix.json is not an array")
    kept = [entry for entry in evidence if not cites_the_endpoint(entry)]
    if samples > 0:
        kept.append({"type": TELEMETRY, "reference": API_URL, "date": read_date,
                     "note": TELEMETRY_NOTE.format(**period)})
    if kept:
        technique["evidence"] = kept
    else:
        technique.pop("evidence", None)


def apply(matrix: dict, values: dict, read_date: str, period: dict):
    """Write the served values for period onto the techniques of matrix; return what was
    written, or None where matrix already holds these values for this period."""
    ids = [t["id"] for t in matrix["techniques"]]
    if not set(ids) & set(values):
        raise Refused("the response lists none of the technique ids in matrix.json")
    held = held_period(matrix)
    bounds = f"{period['start']} to {period['end']}"
    if held == period:
        other = [t["id"] for t in matrix["techniques"]
                 if values.get(t["id"], (0, 0)) != (t.get("wildPrevalence"), t.get("wildSampleCount"))]
        if other:
            raise Refused(f"matrix.json holds the values for the period {bounds}, and the response "
                          f"serves other values for it on {', '.join(other)}; a value held for a "
                          f"period is never rewritten")
        return None
    if held is not None and period["start"] <= held["end"]:
        raise Refused(f"the period {bounds} does not start after {held['start']} to {held['end']}, "
                      f"the period matrix.json holds values for; a value held for a period is never "
                      f"rewritten")
    absent = []
    for technique in matrix["techniques"]:
        if technique["id"] in values:
            prevalence, samples = values[technique["id"]]
        else:
            prevalence, samples = 0, 0
            absent.append(technique["id"])
        technique["wildPrevalence"] = prevalence
        technique["wildSampleCount"] = samples
        write_telemetry_entry(technique, samples, read_date, period)
    matrix["wildPrevalenceSource"] = {"url": API_URL, "read": read_date, "period": period}
    return {
        "absent": absent,
        "unlisted": sorted(set(values) - set(ids)),
        "aboveZero": sum(1 for t in matrix["techniques"] if t["wildPrevalence"] > 0),
        "withSamples": sum(1 for t in matrix["techniques"] if t["wildSampleCount"] > 0),
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


def listed(items: list) -> str:
    """The items as a list in a sentence: a, b and c."""
    return items[0] if len(items) == 1 else f"{', '.join(items[:-1])} and {items[-1]}"


def load_script(path: Path):
    """The module of the script at path, loaded without running its main."""
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_or_none(path: Path, binary: bool = False):
    """The text of the file at path, or its bytes with binary, or None when it cannot be read."""
    try:
        return path.read_bytes() if binary else path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None


def stale_renderings() -> list:
    """The files rendered from matrix.json that disagree with it: the STIX bundle and
    evidence-gaps.json where they differ from what scripts/generate_stix.py renders,
    crosswalks/technique-crosswalk.json where it differs from what
    scripts/build_technique_crosswalk.py renders or cannot be rendered, and the pages
    scripts/check_technique_pages.py checks where it exits 1."""
    stale = []
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    stix = load_script(STIX_GENERATOR)
    try:
        bundle = stix.render(matrix)
    except stix.GenerationError:
        bundle = None
    if bundle is None or read_or_none(stix.DEFAULT_OUTPUT) != bundle:
        stale.append("the STIX bundle")
    if read_or_none(stix.DEFAULT_GAPS_OUTPUT) != stix.render_gaps(matrix):
        stale.append("evidence-gaps.json")
    builder = load_script(CROSSWALK_BUILDER)
    try:
        crosswalk = builder.render(ROOT).encode("utf-8")
    except builder.InputError:
        crosswalk = None
    if crosswalk is None or read_or_none(ROOT / builder.OUTPUT, binary=True) != crosswalk:
        stale.append(builder.OUTPUT)
    pages = subprocess.run([sys.executable, str(PAGE_CHECKER)], capture_output=True, text=True, timeout=120)
    if pages.returncode != 0:
        stale.append("the pages scripts/check_technique_pages.py checks")
    return stale


def failed_after(written: list, step: str) -> str:
    """The FAIL line of a render step that failed once the files in written were written."""
    if not written:
        return f"FAIL: {step} failed"
    return f"FAIL: {listed(written)} {'is' if len(written) == 1 else 'are'} written, but {step} failed"


def render_from_matrix(written: list) -> bool:
    """Render the STIX bundle and evidence-gaps.json, then crosswalks/technique-crosswalk.json,
    from matrix.json, and then run scripts/check_technique_pages.py --fix.

    Return True when every step exits 0. When a step fails, print its FAIL line, which names
    the files in written, those written before this ran, and the files the steps before it
    wrote, and return False.
    """
    written = list(written)
    proc = subprocess.run([sys.executable, str(STIX_GENERATOR)],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        print(f"{failed_after(written, 'scripts/generate_stix.py')}: "
              f"{proc.stderr.strip() or proc.stdout.strip()}", file=sys.stderr)
        return False
    written += ["the STIX bundle", "evidence-gaps.json"]
    # The crosswalk records the sha256 of matrix.json, and scripts/check_technique_crosswalk.py
    # fails when it differs from a fresh rendering, so it is rendered from the file as it is now.
    crosswalk = subprocess.run([sys.executable, str(CROSSWALK_BUILDER)],
                               capture_output=True, text=True, timeout=120)
    if crosswalk.returncode != 0:
        print(f"{failed_after(written, 'scripts/build_technique_crosswalk.py')}: "
              f"{crosswalk.stderr.strip() or crosswalk.stdout.strip()}", file=sys.stderr)
        return False
    written.append("crosswalks/technique-crosswalk.json")
    # The technique pages list the evidence entries; --fix exits 0 only when no page line
    # disagrees with matrix.json once it has written what it can.
    pages = subprocess.run([sys.executable, str(PAGE_CHECKER), "--fix"],
                           capture_output=True, text=True, timeout=120)
    if pages.returncode != 0:
        print(f"{failed_after(written, 'scripts/check_technique_pages.py --fix')}:\n"
              f"{(pages.stdout + pages.stderr).strip()}", file=sys.stderr)
        return False
    return True


def main(argv=None) -> int:
    today = date.today().isoformat()
    args = parse_args(argv, today)
    try:
        payload, read_date = read_response(args, today)
        values = served_values(payload)
        period = served_period(payload, read_date)
        try:
            matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise Refused(f"could not read matrix.json: {exc}")
        report = apply(matrix, values, read_date, period)
    except Refused as exc:
        print(f"FAIL: {exc}; matrix.json is unchanged", file=sys.stderr)
        return 1

    bounds = f"{period['start']} to {period['end']}"
    if report is None:
        held = (f"matrix.json already holds the values {API_URL} served for the closed period {bounds}, "
                f"read {matrix['wildPrevalenceSource']['read']}")
        # A run that wrote matrix.json and then failed to render a file from it leaves that
        # file behind, and the next run with the same response finds the values held, so a run
        # that leaves matrix.json as it is renders them when one of them disagrees with it.
        stale = stale_renderings()
        if not stale:
            print(f"{held}; nothing written")
            return 0
        print(f"{held}.")
        if not render_from_matrix([]):
            return 1
        print(f"{listed(stale)} disagreed with matrix.json, so the STIX bundle, evidence-gaps.json and "
              f"crosswalks/technique-crosswalk.json are rendered again, and the technique pages list "
              f"the evidence entries matrix.json carries.")
        return 0

    if matrix["updated"] < today:
        matrix["updated"] = today
    MATRIX.write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")
    if not render_from_matrix(["matrix.json"]):
        return 1

    print(f"Wrote wildPrevalence and wildSampleCount for the closed period {bounds} on "
          f"{len(matrix['techniques'])} techniques from "
          f"{API_URL}, read {read_date}: {report['aboveZero']} above 0, and a {TELEMETRY} evidence "
          f"entry dated {read_date} on the {report['withSamples']} with a wildSampleCount above 0. "
          f"updated is {matrix['updated']}, the STIX bundle, evidence-gaps.json and "
          f"crosswalks/technique-crosswalk.json are rendered again, and the technique pages list "
          f"the evidence entries matrix.json now carries.")
    if report["absent"]:
        print(f"Not listed by the endpoint, written as 0: {', '.join(report['absent'])}")
    if report["unlisted"]:
        print(f"Listed by the endpoint but not in matrix.json, left out: {', '.join(report['unlisted'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
