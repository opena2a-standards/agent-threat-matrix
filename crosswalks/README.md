# Technique-level crosswalks

Each technique in [`matrix.json`](../matrix.json) carries two optional cross-reference arrays,
`attackMapping` and `atlasMapping`. Each entry names an external technique id, the SKOS
relation between the matrix technique and it (`exactMatch`, `closeMatch`, `broadMatch`,
`narrowMatch` or `relatedMatch`), and a note that names the release the id was read against.
This directory holds the resolvable snapshot of those releases, the residue the crosswalk
leaves and the record of the review each entry passed.

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

[`review.json`](review.json) is the entry-review record: a row for each admitted entry with its
relation and the sha256 of its note, the entries withdrawn on review, and the techniques left
unmapped, against the releases it names. It is written from the review of each entry against
the named release, never generated from `matrix.json`. `python3 scripts/check_cross_references.py`,
which CI runs, fails when an entry has no row or differs from its row in relation or note, when
a row matches no entry, when a withdrawn entry is present, and when the unmapped list or the
releases differ, so an entry no review admitted does not pass it.

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
   repositories and run the script on the new release files, as its docstring shows. The ATLAS
   release file is `dist/v6/ATLAS-<release>.yaml`; `dist/ATLAS.yaml` is frozen at 5.6.0 and is
   not the current release.
2. `matrix.json`: the note of every `attackMapping` and `atlasMapping` entry names the new
   release, and every mapping, and every technique on the unmapped list, is read again against
   it. `updated` moves too: `scripts/validate_matrix.py` requires it to be no earlier than the
   day it runs whenever `matrix.json` differs from the committed copy. Every entry and the
   unmapped list are reviewed again, and `crosswalks/review.json` is rewritten from that
   review, never from `matrix.json`.
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
`python3 scripts/check_cross_references.py` fails while an entry, the unmapped list or the
releases differ from `crosswalks/review.json`.

## Checks, controls, signatures and scenarios per technique

[`technique-crosswalk.json`](technique-crosswalk.json) joins every technique in `matrix.json`
to the HackMyAgent checks and OASB-1 controls it lists, the AIIS signatures that name it, and
the DVAA scenarios that expect one of its checks. `scripts/build_technique_crosswalk.py`
renders it from `matrix.json`, `technique-ids.json` and pinned copies of the external inputs
under `vendor/`; it is never edited by hand.

Which checks cover a technique:

```sh
jq -c '.byTechnique["T-1001"].hmaChecks' crosswalks/technique-crosswalk.json
# ["MCP-011","WEBEXPOSE-001","WEBEXPOSE-002"]
```

Which techniques list a check:

```sh
jq -c '[.byHmaCheck["CRED-001"][].techniqueId]' crosswalks/technique-crosswalk.json
# ["T-3001","T-3003","T-3005","T-3006","T-5004"]
```

How to read it:

- `byTechnique` holds, per technique, `hmaChecks`, `oasbControls`, `aiisSignatures`,
  `dvaaScenarios` and `attackPayloads`. An AIIS entry's `basis` is `aiis-technique-id` when
  the technique is the signature's own and `aiis-related-technique-id` when the signature
  lists it as related. A DVAA entry, `basis: "expected-check"`, names the scenario and the
  `checks` it expects that the technique lists: a listed check can fire on the scenario, which
  is not a claim that the scenario validates the technique.
- `byHmaCheck`, `byOasbControl`, `byAiisSignature` and `byDvaaScenario` are the reverse views.
  Each entry names a `techniqueId` and carries `relation`. `relation: null` marks a coverage
  edge: it may be counted, but it is never the technique of a finding. A check can sit under
  several techniques, as `CRED-001` does under five, so it covers each of them and identifies
  none. Every `relation` is `null` until a per-producer mapping file states one.
- A column that is `null` was not assessed, because no source for it exists yet. `[]` was
  assessed and holds none. `notAssessed` names each `null` column and the reason; today these
  are the payload columns `attackPayloads.hackmyagent` and `attackPayloads.agentpwn`, which
  stay `null`, with `byPayload` and `unjoined.payloadsInNoTechnique`, until
  `mappings/hackmyagent-payloads.json` and `mappings/agentpwn-payloads.json` exist.
- `unjoined` lists the ids an input names that join no technique: HackMyAgent checks and
  OASB-1 controls no technique lists, and check ids a DVAA scenario expects that no technique
  lists.
- `matrix` identifies `matrix.json` and `technique-ids.json` by sha256, `inputs` names each
  pinned source with the sha256 of each vendored file, and `generated` is the latest of
  `matrix.json` `updated` and the inputs' read dates.

To verify the file, run `python3 scripts/check_technique_crosswalk.py`. It renders the file
again and fails when the committed copy differs, when an id does not resolve against its own
family's vendored list (a payload id is never read as a check id), when a signature is
retired, when a pin is not an exact version or a 40-hex commit, or when a file under `vendor/`
is not listed in its `VENDOR.json`. It reads no network. `python3 scripts/check_vendor_integrity.py`
is the network half: it fetches each input at its pin and exits 1 when a vendored file differs
from its source, and 3 when a source cannot be reached, which is not a pass.

To refresh a pin, open `vendor/<source>/VENDOR.json`. It states the pin (`commit` for a git
source; `version` and `integrity` for the package), the date it was read, the files, and the
command that writes them: `refresh` for byte-exact copies, `generate` for files a generator
writes. Run that command at the new pin, set the pin and `read`, run
`python3 scripts/build_technique_crosswalk.py`, and commit the vendored files, `VENDOR.json`
and the crosswalk in one change.
