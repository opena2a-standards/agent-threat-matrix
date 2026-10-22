# Technique-level crosswalks

Each technique in [`matrix.json`](../matrix.json) carries two optional cross-reference arrays,
`attackMapping` and `atlasMapping`. Each entry names an external technique id, the SKOS
relation between the matrix technique and it (`exactMatch`, `closeMatch`, `broadMatch`,
`narrowMatch` or `relatedMatch`), and a note that names the release the id was read against.
This directory holds the resolvable snapshot of those releases and the residue the crosswalk
leaves.

The mappings were read from the release data itself, a git clone of each published data
repository, not a REST walk:

- `attack-release.json`: the current techniques of MITRE ATT&CK Enterprise 20.0, from
  [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data).
- `atlas-release.json`: the techniques of MITRE ATLAS release 2026.09, from
  [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data).

Each file records the framework, the release, the source repository and the read date, and an
`id -> name` map of that release's techniques. `scripts/build_crosswalk_index.py` distils them
from a local clone; it is a provenance tool, not a CI step, because the external repositories
are not vendored here.

[`unmapped.md`](unmapped.md) lists the techniques with no counterpart in either release. It is
derived from `matrix.json` and checked against it.

`tests/test_crosswalks.py` resolves every `attackMapping` and `atlasMapping` id against the
snapshot for its framework, so a mapping that names an id absent from the named release fails;
asserts the unmapped list equals the techniques carrying no mapping; and asserts the notes name
the release each snapshot records. It is a local test that no workflow runs; run it with
`python3 -m pytest -q tests/test_crosswalks.py`. The relation on the cross-reference pages
under `cross-references/` is separate: those pages are a tactic-grain analyst reading, while
these arrays are the technique-grain crosswalk in the data.

## Refreshing against a newer release

`scripts/build_crosswalk_index.py` takes each release from the name of the file it reads
(`enterprise-attack-<release>.json`, `ATLAS-<release>.yaml`), or from `--attack-release` and
`--atlas-release` when the name carries none, and records the day it runs as the read date
(`--read` gives another). It holds no release or date of its own, so a refresh does not edit
it. A refresh changes these files, in one change:

1. `crosswalks/attack-release.json` and `crosswalks/atlas-release.json`: clone the two data
   repositories and run the script on the new release files, as its docstring shows.
2. `matrix.json`: the note of every `attackMapping` and `atlasMapping` entry names the new
   release, and every mapping, and every technique on the unmapped list, is read again against
   it. `updated` moves too: `scripts/validate_matrix.py` requires it to be no earlier than the
   day it runs whenever `matrix.json` differs from the committed copy.
3. `stix/agent-threat-matrix-bundle.json`, which carries the notes and takes its `modified`
   dates from `updated`: regenerate it with `python3 scripts/generate_stix.py`.
4. `crosswalks/README.md` and `crosswalks/unmapped.md`, which name both releases. The table in
   `unmapped.md` also changes when a technique gains its first mapping or loses its last.
5. `CHANGELOG.md`: an entry under "Unreleased", as `GOVERNANCE.md` requires of a normative
   change.

The tactic-grain page `cross-references/mitre-atlas-mapping.md` is read against an ATLAS release
of its own, pinned as `ATLAS_RELEASE` in `scripts/check_cross_references.py`. When the page moves
to the new ATLAS release too, the page and the pin change together, and `ATLAS_TACTICS` beside
the pin changes when that release adds, renames or retires a tactic;
`python3 scripts/check_cross_references.py` checks the page against both.

`python3 -m pytest -q tests/test_crosswalks.py` fails while a note names a release other than
the one its snapshot records, while a mapping id is absent from its snapshot, and while the
unmapped list differs from the techniques carrying no mapping. `python3 scripts/validate_matrix.py`
fails while the STIX bundle differs from what `scripts/generate_stix.py` renders.
