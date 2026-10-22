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
snapshot for its framework, so a mapping that names an id absent from the named release fails,
and asserts the unmapped list equals the techniques carrying no mapping. The relation on the
cross-reference pages under `cross-references/` is separate: those pages are a tactic-grain
analyst reading, while these arrays are the technique-grain crosswalk in the data.
