#!/usr/bin/env python3
"""Assert every counted claim in README.md matches matrix.json.

The README states counts (tactics, techniques, attack classes, evidence tiers)
and coverage claims (detection, defensive control, lab scenario). Those are
measurements, not prose, so they are checked here and in CI rather than
maintained by hand.

Exit 0 when every claim matches the data, 1 otherwise.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MATRIX = ROOT / "matrix.json"
README = ROOT / "README.md"


def empty(value):
    """A mapping field counts as absent when null, empty, or all-empty strings."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple)):
        return all(empty(v) for v in value) if value else True
    return False


def main():
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    readme = README.read_text(encoding="utf-8")

    tactics = matrix["tactics"]
    techniques = matrix["techniques"]
    classes = matrix.get("attackClasses", [])

    tiers = {}
    for t in techniques:
        tiers[t.get("evidenceTier")] = tiers.get(t.get("evidenceTier"), 0) + 1

    with_detection = sum(1 for t in techniques if not empty(t.get("hmaChecks")))
    with_control = sum(1 for t in techniques if not empty(t.get("oasbControls")))
    with_lab = sum(1 for t in techniques if not empty(t.get("dvaaValidation")))

    total = len(techniques)
    failures = []

    def require(pattern, expected, label):
        """The README states this wording at least once, and every occurrence carries
        the measured number(s).

        `pattern` captures each stated number as a group, in the order of `expected`.
        Checking every occurrence, rather than that the right number appears
        somewhere, is what catches a count repeated in a second section (Use cases,
        Purpose) going stale while the first copy still matches.
        """
        want = tuple(str(v) for v in expected)
        found = list(re.finditer(pattern, readme))
        if not found:
            failures.append(f"README does not state {label} ({', '.join(want)})")
        for m in found:
            if m.groups() != want:
                line = readme.count("\n", 0, m.start()) + 1
                failures.append(
                    f"README.md:{line}: \"{m.group(0)}\" does not match matrix.json "
                    f"({label}: {', '.join(want)})"
                )

    observed = tiers.get("observed", 0)
    validated = tiers.get("validated", 0)
    adapted = tiers.get("adapted", 0)

    require(r"\b(\d+) tactics\b", [len(tactics)], "tactics")
    require(r"\*\*(\d+) techniques\*\*", [total], "techniques")
    require(r"\b(\d+) tactics and (\d+) techniques\b", [len(tactics), total],
            "tactics and techniques")
    require(r"\b(\d+) attack classes\b", [len(classes)], "attack classes")
    require(r"\*\*(\d+) attack classes\*\*", [len(classes)], "attack classes")

    # Evidence tiers, in the overview wording and in the Use cases wording.
    require(r"\*\*(\d+) techniques with real-world evidence\*\*", [observed], "observed")
    require(r"\b(\d+) of the (\d+) techniques carry real-world evidence\b",
            [observed, total], "observed of total")
    require(r"\*\*(\d+) techniques validated in controlled lab environments\*\*",
            [validated], "validated")
    require(r"\b(\d+) are validated in controlled lab environments\b", [validated],
            "validated")
    require(r"\*\*(\d+) techniques adapted from traditional environments\*\*",
            [adapted], "adapted")
    require(r"\b(\d+) are adapted from traditional environments\b", [adapted], "adapted")

    # Coverage claims. Detection and defensive control are stated as universal,
    # so they must actually hold for every technique. The lab-scenario claim is
    # stated as a ratio because it does not.
    if with_detection != total:
        gaps = [t["id"] for t in techniques if empty(t.get("hmaChecks"))]
        failures.append(
            f"README claims every technique maps to automated detection, "
            f"but {total - with_detection} do not: {gaps}"
        )
    if with_control != total:
        gaps = [t["id"] for t in techniques if empty(t.get("oasbControls"))]
        failures.append(
            f"README claims every technique maps to a defensive control, "
            f"but {total - with_control} do not: {gaps}"
        )
    require(
        r"\b(\d+) of the (\d+) (?:also )?carry a reproducible lab scenario\b",
        [with_lab, total],
        "lab scenario of total",
    )

    tier_total = sum(tiers.values())
    if tier_total != total:
        failures.append(
            f"evidence tiers sum to {tier_total}, expected {total} "
            f"(every technique needs exactly one tier; got {tiers})"
        )

    if failures:
        print("README claims do not match matrix.json:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print(
            f"\nmeasured: {len(tactics)} tactics, {total} techniques, "
            f"{len(classes)} attack classes, tiers={tiers}, "
            f"detection={with_detection}/{total}, control={with_control}/{total}, "
            f"lab={with_lab}/{total}",
            file=sys.stderr,
        )
        return 1

    print(
        f"README claims match matrix.json: {len(tactics)} tactics, {total} techniques, "
        f"{len(classes)} attack classes, tiers={tiers}, "
        f"detection={with_detection}/{total}, control={with_control}/{total}, "
        f"lab={with_lab}/{total}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
