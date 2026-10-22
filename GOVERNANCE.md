# Governance

This page is the change control of the AI Agent Threat Matrix: who decides what enters it,
what counts as a change to it, how a change is proposed, how its version moves, how an
evidence tier moves, how its scope is amended, and when a release is complete. It covers
this repository alone. How the `opena2a-standards` organization is governed, and how
contribution rights evolve, is in the organization's
[GOVERNANCE.md](https://github.com/opena2a-standards/.github/blob/main/GOVERNANCE.md).
This page links that document and does not restate it, so a change there needs no change
here.

## Who decides

OpenA2A decides what enters the matrix, as the "Change control" section of
[CONTRIBUTING.md](CONTRIBUTING.md#change-control) states: a submission, however well
evidenced, creates no entitlement to inclusion, and each decision is recorded on the issue
or pull request the content arrived in.

The maintainers of record are the members of the `opena2a-standards` GitHub organization.
GitHub lists them on the organization's
[people page](https://github.com/orgs/opena2a-standards/people), where a membership set to
private is not shown; the command below prints the members whose membership is public.

```sh
gh api orgs/opena2a-standards/public_members --jq '.[].login'
```

A question this page and the organization's GOVERNANCE.md do not answer goes to an issue in
this repository, or to the contact that document names.

## What is normative, derived and editorial

The organization's
[CONTRIBUTING.md](https://github.com/opena2a-standards/.github/blob/main/CONTRIBUTING.md#two-kinds-of-change)
separates a normative change from an editorial one. In this repository the normative
content is:

- `matrix.json`, the matrix itself: every tactic, technique, attack class and attack path,
  with each technique's evidence tier and its technique-level crosswalk to MITRE ATT&CK and
  MITRE ATLAS, the `attackMapping` and `atlasMapping` arrays;
- `technique-ids.json`, the technique id list, kept in step with `matrix.json`;
- `canonical-classes.json`, the canonical attack classes resolved to technique ids;
- `schema/`, the JSON Schema for `matrix.json`, the JSON Schema for `evidence-sources.json`
  and the consumer-readiness gate on dotted ids;
- `docs/evidence-tiers.md`, the definition of each evidence tier and the evidence standard;
- `EVIDENCE_AUDIT.md`, the justification of every technique's tier;
- `cross-references/`, the published mapping pages that relate the matrix to external
  frameworks, and the index of the techniques they name, beside the technique-level
  crosswalk that `matrix.json` carries;
- the scope statement in `docs/overview.md`, under "What This Covers (and What It
  Doesn't)".

Derived content is rendered from the normative content and is never edited by hand. A
check fails when it differs from a fresh rendering:

- the pages in `attack-classes/`: `python3 scripts/generate_class_markdown.py --check`;
- the bundle in `stix/`, and `evidence-gaps.json`, the techniques that carry no evidence
  entry: `python3 scripts/validate_matrix.py`;
- the data lines of the pages in `techniques/`, and the whole of each page in `tactics/`:
  `python3 scripts/check_technique_pages.py`;
- the counts on `README.md` and on the pages the README check reads with it, and the
  attack-class tables on `docs/attack-classes.md`: `python3 scripts/check_readme_claims.py`;
- the overlap counts in `cross-references/technique-overlap-index.md`:
  `python3 scripts/check_cross_references.py`.

Three files under `crosswalks/` hold derived content that no check renders afresh.
`tests/test_crosswalks.py` guards them; it is a local test that no workflow runs, run with
`python3 -m pytest -q tests/test_crosswalks.py`:

- the technique list of `crosswalks/unmapped.md`, the ids in the first column of its table,
  which is typed by hand: the test fails when it differs from the techniques whose
  `attackMapping` and `atlasMapping` are both empty in `matrix.json`;
- the release snapshots `crosswalks/attack-release.json` and `crosswalks/atlas-release.json`,
  derived from the external releases rather than from the normative content:
  `scripts/build_crosswalk_index.py` writes them from a clone of each published data
  repository, which is not vendored here, and they are never edited by hand. The test
  resolves every `attackMapping` and `atlasMapping` id against them, and fails when the notes
  in `matrix.json` name a release other than the one a snapshot records.

Everything else is editorial: the prose of `README.md`, the pages under `docs/` other than
the two named above, the prose of the technique pages, `crosswalks/README.md` and the rest
of `crosswalks/unmapped.md`, `CONTRIBUTING.md`, `CHANGELOG.md`,
`ATTRIBUTION.md`, whose own rule is the "Contributor credit" section of CONTRIBUTING.md,
`related-projects.json`, the figures about related projects that the README check
reads and the OASB-1 control titles that `scripts/check_technique_pages.py` writes into
the Mitigation section of each technique page, and `evidence-sources.json`, the DVAA
scenario pages and challenges that `lab-reproduction` evidence entries cite, pinned from a
git clone by `scripts/pin_evidence_sources.py`.

A change to normative content is a normative change in the organization's sense and takes
the route below. An editorial change is a pull request directly.

## How a change is proposed

The route is the organization's, in its CONTRIBUTING.md under
["Two kinds of change"](https://github.com/opena2a-standards/.github/blob/main/CONTRIBUTING.md#two-kinds-of-change)
and
["What a normative change needs"](https://github.com/opena2a-standards/.github/blob/main/CONTRIBUTING.md#what-a-normative-change-needs):
an editorial change is a pull request directly, and a normative change opens an issue in
this repository first. This page adds what is specific to the matrix.

- A new technique or attack class is proposed with the
  [technique submission form](.github/ISSUE_TEMPLATE/technique-submission.yml), whose
  required fields are the inputs of the evidence standard. [CONTRIBUTING.md](CONTRIBUTING.md)
  gives the evidence each tier requires, the technique template, the id ranges, and the two
  placements a technique pull request carries in the same commit.
- A move of a technique's evidence tier is proposed with the same form, with "re-tier" in
  the title (see "How an evidence tier moves").
- A change to the scope statement is proposed as an issue, never as a pull request directly
  (see "How the scope is amended").
- Every normative change carries an entry under "Unreleased" in `CHANGELOG.md` that names
  the technique ids it touches, and the version step of the next section.

The maintainers of record decide on the issue or pull request thread, and the decision is
recorded there.

## The version rule

`version` in `matrix.json` is MAJOR.MINOR. Read the current value with:

```sh
python3 -c 'import json; print(json.load(open("matrix.json"))["version"])'
```

MAJOR steps when a consumer that reads `matrix.json` must change its code or its reading of
an id:

- a change to the technique id grammar the schema states;
- the removal or renaming of a required technique field;
- a change to the set of `evidenceTier` values the schema fixes;
- a change to the scope statement.

MINOR steps for every other release that changes normative content: a new technique, attack
class, tactic or optional field, a re-tier, a re-placement, a deprecation.

`updated` in `matrix.json` moves on every normative change; `scripts/validate_matrix.py`
requires it to be no earlier than the current date whenever the file differs from the
committed copy in anything but that field. A release heading in `CHANGELOG.md` starts with
`## v` and the version as `matrix.json` writes it, followed by the release date.

A technique may carry its own `version`, a semantic version the schema defines, read as
1.0.0 when absent. It steps when that technique's own content changes. It is optional until
a technique first carries it and required for that technique from then on.

## Technique ids are permanent

A technique id, once published, is never deleted, reused or renumbered. Consumers pin ids,
and `schema/consumer-readiness.json` lists the ones that read them. A technique that no
longer belongs in the matrix is deprecated, not deleted: its record stays in `matrix.json`
with `status` set to `deprecated` and `replacedBy` naming the technique that supersedes it,
its id stays in `technique-ids.json`, and its page under `techniques/` stays and says so.
`scripts/validate_matrix.py` requires `replacedBy` exactly when `status` is `deprecated`,
and requires it to name another technique. A deprecation is a MINOR step.

## How an evidence tier moves

A technique's tier is an adjudication by the maintainers of record, written with its
justification in `EVIDENCE_AUDIT.md`. The tiers and the evidence each requires are defined
once, in [docs/evidence-tiers.md](docs/evidence-tiers.md#the-three-tiers) and its
[Evidence Standard](docs/evidence-tiers.md#evidence-standard) table; this page does not
repeat them. Nothing derives a tier: an `evidence` entry in `matrix.json` does not set or
change it, and a recomputation proposed from outside this repository is an input to an
issue, never a write.

To propose a move, open an issue with the technique submission form, put "re-tier" in the
title, name the technique id, and give the evidence the target tier requires; the "Evidence
to include" column of the tier table in CONTRIBUTING.md says what that is for each tier.
Several reports of one incident are one observation. The maintainers of record decide on
the thread. The move lands as one pull request that changes `evidenceTier` in
`matrix.json`, the technique's entry in `EVIDENCE_AUDIT.md` and `CHANGELOG.md`; it is a
MINOR step. A move down, when evidence is withdrawn or re-read, takes the same path.

## How the scope is amended

The scope statement is in
[docs/overview.md](docs/overview.md#what-this-covers-and-what-it-doesnt), under "What This
Covers (and What It Doesn't)": what the matrix covers and what it leaves to other
frameworks. A change to it is a MAJOR step. It is proposed as an issue, never as a pull
request directly, and decided by the maintainers of record with OpenA2A's approval. The
issue states what the matrix would newly cover or stop covering, what every existing
technique needs so that the old and the new content can be told apart, and which consumers
must change. This page records the process and decides no scope.

## Review routing

Branch protection on `main` requires one status check, "Gate file approval", and sets no
required review count and no code-owner review. That check passes for a pull request that
changes nothing under `.github/`; a pull request that changes a file there needs an
approving review on its current head commit from one of the accounts named in the
`approvers` line of `.github/workflows/gate-file-approval.yml`: the GitHub user
`thebenignhacker`, or `benign-gate-reviewer[bot]`, the bot account of the gate-reviewer
GitHub App. The check counts an approval from either account the same way. Read the
current branch protection with:

```sh
gh api repos/opena2a-standards/agent-threat-matrix/branches/main/protection
```

A `.github/CODEOWNERS` file, when this repository carries one, lists the maintainers of
record against the normative paths above, so that GitHub requests their review on a pull
request that touches them. That is routing, not an approval requirement: it changes whose
review is requested, not what is required to merge. Merge rights are held by the
maintainers of record.

## Publication and the drift check

The registry at `https://api.oa2a.org/api/v1/threat-matrix` serves the matrix, and
[threats.opena2a.org](https://threats.opena2a.org) renders what the registry serves. A
release is complete only when the registry serves the `matrix.json` of this repository's
`main` branch and `python3 scripts/check_live_api_drift.py` passes. The workflow in
`.github/workflows/claims.yml` runs that check on each push to `main`, on each pull request
and once a day. On a pull request, a repository version newer than the live one is
reported, not failed; after the merge, the push and the daily runs fail until the registry
serves the new version. That red run is the gap between a version step here and the
registry's import of it, and the maintainers of record own closing it. The import is an
operation on the registry, not a change to this repository.

## Checking this page

`python3 scripts/check_governance.py` checks that this page exists and links the
organization's GOVERNANCE.md and CONTRIBUTING.md, that every path named in a code span of
"What is normative, derived and editorial" exists in the tree, that `CONTRIBUTING.md` and
`README.md` link this page, that every relative link on it resolves and every heading
fragment names a heading, and that every pattern in `.github/CODEOWNERS`, when the file is
present, resolves to a path. `python3 scripts/check_docs_prose.py` checks its prose with
the other pages.
