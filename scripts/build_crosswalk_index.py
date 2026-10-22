#!/usr/bin/env python3
"""Build the release-id indexes the crosswalk test resolves against.

The technique-level crosswalks in matrix.json (``attackMapping`` and ``atlasMapping``)
name external technique ids. Each id must exist in the release the note names. This
script distils a local git clone of each published data repository into a committed
id -> name snapshot of that release, which tests/test_crosswalks.py resolves every
mapping id against. It is a provenance tool run by hand with the clones present, not a
CI step: the published data repositories are not vendored into this repository.

Each snapshot records its framework, its release, its source repository and the date it was
read, so it states what was read, where and when. The release is the one the input file's
name carries, as in the usage below (``enterprise-attack-20.0.json``, ``ATLAS-2026.09.yaml``);
``--attack-release`` and ``--atlas-release`` give it for a file whose name carries none, and a
value that differs from the release the name carries is refused. The read date is the day the
script runs, or the date ``--read`` gives. The script holds no release or date of its own, so
a refresh against a newer release does not edit it. The steps of a refresh, and the files it
changes, are in crosswalks/README.md under "Refreshing against a newer release".

usage::

    git clone --filter=blob:none https://github.com/mitre-attack/attack-stix-data
    git clone --filter=blob:none https://github.com/mitre-atlas/atlas-data
    python3 scripts/build_crosswalk_index.py \\
        attack-stix-data/enterprise-attack/enterprise-attack-20.0.json \\
        atlas-data/dist/v6/ATLAS-2026.09.yaml

Writes attack-release.json and atlas-release.json into crosswalks/, or into the directory
``--out`` names. Needs PyYAML to read the ATLAS YAML. Exit 0 on success. Exit 2, writing
nothing, when neither a file's name nor its option gives its release, when an option differs
from the release the file's name carries or is not written as dotted numbers (20.0, 2026.09),
when ``--read`` is not a date written YYYY-MM-DD, or when ``--out`` names no directory.
"""
import argparse
import datetime
import json
import re
import sys
from pathlib import Path

# The docstring's first line, held apart so --help still works under python3 -OO.
DESCRIPTION = "Build the release-id indexes the crosswalk test resolves against."

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "crosswalks"

ATTACK = {"framework": "MITRE ATT&CK Enterprise",
          "source": "https://github.com/mitre-attack/attack-stix-data"}
ATLAS = {"framework": "MITRE ATLAS",
         "source": "https://github.com/mitre-atlas/atlas-data"}

# A release written as dotted numbers (20.0, 2026.09), and the names of the release files
# that carry one: enterprise-attack-<release>.json and ATLAS-<release>.yaml.
RELEASE = r"\d+(?:\.\d+)+"
ATTACK_NAME_RE = re.compile(rf"enterprise-attack-({RELEASE})\.json")
ATLAS_NAME_RE = re.compile(rf"ATLAS-({RELEASE})\.ya?ml")


def attack_index(bundle_path: str) -> dict:
    """id -> name for every current (non-revoked, non-deprecated) ATT&CK technique."""
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
    name_by_ext = {}
    for obj in patterns:
        ext = next(r["external_id"] for r in obj["external_references"]
                   if r.get("source_name") == "mitre-attack")
        name_by_ext[ext] = obj["name"]
    out = {}
    for obj in patterns:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next(r["external_id"] for r in obj["external_references"]
                   if r.get("source_name") == "mitre-attack")
        name = obj["name"]
        if obj.get("x_mitre_is_subtechnique"):
            name = f"{name_by_ext[ext.split('.')[0]]}: {name}"
        out[ext] = name
    return dict(sorted(out.items()))


def atlas_index(yaml_path: str) -> dict:
    """id -> name for every ATLAS technique and sub-technique in the release."""
    import yaml
    tech = yaml.safe_load(Path(yaml_path).read_text(encoding="utf-8"))["techniques"]
    out = {}
    for tid, entry in tech.items():
        name = entry["name"]
        if "." in tid[5:]:
            name = f"{tech[tid.rsplit('.', 1)[0]]['name']}: {name}"
        out[tid] = name
    return dict(sorted(out.items()))


def release_arg(value: str) -> str:
    """The type of --attack-release and --atlas-release: a release written as dotted numbers."""
    if not re.fullmatch(RELEASE, value):
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a release written as dotted numbers, such as 20.0 or 2026.09")
    return value


def date_arg(value: str) -> str:
    """The type of --read: a calendar date written YYYY-MM-DD."""
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            return datetime.date.fromisoformat(value).isoformat()
    except ValueError:
        pass
    raise argparse.ArgumentTypeError(f"{value!r} is not a date written YYYY-MM-DD")


def release_of(path: str, name_re: re.Pattern, given, option: str) -> str:
    """The release the file at `path` is read as: the one its name carries, else `given`.

    Raises ValueError when neither gives a release, or when both do and they differ, so a
    snapshot is never labelled with a release other than the one its file was published as.
    """
    name = Path(path).name
    match = name_re.fullmatch(name)
    named = match.group(1) if match else None
    if given is not None and named is not None and given != named:
        raise ValueError(f"{option} {given} differs from release {named}, which the name {name} carries")
    if given is None and named is None:
        raise ValueError(f"the name {name} carries no release; give it with {option}")
    return named if named is not None else given


def snapshot(meta: dict, release: str, read: str, techniques: dict) -> dict:
    """One release snapshot, its fields in the order the committed snapshots hold them."""
    return {"framework": meta["framework"], "release": release, "source": meta["source"],
            "read": read, "techniques": techniques}


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description=DESCRIPTION, allow_abbrev=False)
    parser.add_argument("attack_bundle",
                        help="the ATT&CK Enterprise STIX bundle, such as enterprise-attack-20.0.json")
    parser.add_argument("atlas_yaml", help="the ATLAS release file, such as ATLAS-2026.09.yaml")
    parser.add_argument("--attack-release", type=release_arg,
                        help="the ATT&CK release, for a bundle whose file name carries none")
    parser.add_argument("--atlas-release", type=release_arg,
                        help="the ATLAS release, for a file whose name carries none")
    parser.add_argument("--read", type=date_arg,
                        help="the read date, YYYY-MM-DD; the default is the day the script runs")
    parser.add_argument("--out", type=Path, default=OUT,
                        help="the directory to write the snapshots into; the default is crosswalks/")
    args = parser.parse_args(argv)
    try:
        attack_release = release_of(args.attack_bundle, ATTACK_NAME_RE, args.attack_release,
                                    "--attack-release")
        atlas_release = release_of(args.atlas_yaml, ATLAS_NAME_RE, args.atlas_release,
                                   "--atlas-release")
    except ValueError as exc:
        parser.error(str(exc))
    if not args.out.is_dir():
        parser.error(f"--out {args.out} names no directory")
    read = args.read or datetime.date.today().isoformat()
    attack = snapshot(ATTACK, attack_release, read, attack_index(args.attack_bundle))
    atlas = snapshot(ATLAS, atlas_release, read, atlas_index(args.atlas_yaml))
    (args.out / "attack-release.json").write_text(json.dumps(attack, indent=2) + "\n", encoding="utf-8")
    (args.out / "atlas-release.json").write_text(json.dumps(atlas, indent=2) + "\n", encoding="utf-8")
    print(f"attack {attack_release}: {len(attack['techniques'])} techniques, read {read}")
    print(f"atlas {atlas_release}: {len(atlas['techniques'])} techniques, read {read}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
