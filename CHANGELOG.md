# Changelog

## v1.2.0 (2026-09-08)

Schema release. No technique, tier, or classification content changed.
- Test note: the two acceptance checks that compared `matrix.json` and `canonical-classes.json` against `origin/main` now compare the working tree against the committed tree (`HEAD`); the old form failed by construction for any change to `matrix.json` until it merged, which made a schema release unmergeable under its own tests.
- Drift check: on pull request runs, `scripts/check_live_api_drift.py` reports (and no longer fails on) a matrix version that is newer than the version the live registry serves, because a release is ahead of the registry by construction until the registry re-imports after the merge; every other drift still fails, and push and scheduled runs still fail on the version.
- Scan scope: `stix/` is excluded from static security scans in `.hmaignore`; the bundle is generated threat-intelligence data whose attack-pattern descriptions read as findings when scanned as configuration.

### Added

- `schema/threat-matrix-v1.2.schema.json`: JSON Schema (2020-12) for `matrix.json`. The nine technique fields of 1.1 are unchanged and still required; `evidenceTier` stays `observed`, `validated`, `adapted`. New optional technique fields: `attackMapping` and `atlasMapping` (external technique id plus a `relationship` of `exactMatch`, `closeMatch`, `broadMatch`, `narrowMatch` or `relatedMatch`), `dataSources` (ids from the new top-level `dataSources` registry), `evidence` (typed, dated references), `status` (`draft`, `active`, `deprecated`; absent means active), `replacedBy` (required exactly when deprecated), `version` (semver; absent means 1.0.0), and `parentId` (required exactly when the id is dotted). Technique ids may take the form `T-NNNN.NNN` for a sub-technique, listed flat in `techniques`.
- `matrix.json`: `version` is `1.2`; new top-level `dataSources` registry (empty) and `stixNamespace`, the pinned UUID namespace for STIX ids.
- `scripts/validate_matrix.py`: validates `matrix.json` against the schema with a standard library subset checker, then the rules the schema cannot state (tactic, attack class, data source, `replacedBy` and `parentId` resolve; `replacedBy` and `parentId` present exactly when required; `technique-ids.json` in sync; the STIX bundle byte-identical to a fresh rendering).
- `schema/consumer-readiness.json`: the consumer-readiness gate. While `subTechniques` is false the validator rejects any dotted technique id, because the listed consumers (the aiis-signatures `technique_ids` pattern, the aim-sdk Python and TypeScript technique validators with their pinned 1.1 id set, and the registry telemetry handler id pattern) do not accept them yet.
- `technique-ids.json`: the sorted technique id list with the matrix version, checked for equality against `matrix.json`.
- `stix/agent-threat-matrix-bundle.json` and `scripts/generate_stix.py`: a STIX 2.1 bundle rendered from `matrix.json` with deterministic ids (uuid5 over `stixNamespace` and a canonical name): one tactic object per tactic, one attack pattern per technique with external references, one grouping per attack class, one course of action per OASB control, and `mitigates` and `subtechnique-of` relationships. The generator runs a structural self-check (unique ids, references resolve, common properties present).
- `docs/evidence-tiers.md`: the three tiers as the README defines them, the `evidence` entry types, and the pending mapping table to the ARIA behavioral-sweep classes.

### Changed

- `scripts/check_canonical_classes.py` accepts `T-NNNN.NNN` ids alongside `T-NNNN`.
- README states version 1.2 and gains a Schema subsection; the derived overlap-counts block in `cross-references/technique-overlap-index.md` now renders version 1.2.

## Unreleased

### Changed

- `technique-ids.json`: `matrixCommit` is the 40-character sha of the commit whose `matrix.json` the id list indexes (it carried the placeholder `PENDING-AT-MERGE`). `scripts/validate_matrix.py` gains S11, which refuses any value that is not a 40-hex commit sha, and its summary line names the commit.
- `scripts/check_readme_claims.py` checks every occurrence of each counted claim, not only that the right number appears somewhere, and covers the counts repeated in the README "Use cases" section (tactics and techniques, the lab-scenario ratio, and the observed, validated and adapted tier counts). A stale repeat used to pass while the overview copy still matched; a failure now names the README line.
- `scripts/check_live_api_drift.py` checks the README sentence that states which version the live API labels the matrix with, which version this repository is at, and that the technique and tactic counts agree, against the live payload and `matrix.json`. A wrong number in that sentence fails the check, and so does the sentence itself once the live API serves the same version as `matrix.json`, until it is removed. Before, neither this check nor `scripts/check_readme_claims.py` read the sentence.
- `cross-references/mitre-atlas-mapping.md` is read against ATLAS release 2026.09 and says so. Its tactic table has one row per ATLAS tactic (16, it had 11), each named as ATLAS names it with its `AML.TA` id and in ATLAS matrix order: Privilege Escalation, Credential Access, Lateral Movement, AI Attack Adaptation ("AI Attack Staging" in ATLAS 5.6.0) and Command and Control are added, and "ML Model Access" and "Evasion" are now "AI Model Access" and "Defense Evasion". The table no longer names technique ids, as the overlap index states. The sections after the table name the ATLAS agent techniques nearest to each agent-layer area (agent context poisoning, agent tool poisoning, exfiltration via agent tool invocation and others) instead of stating that ATLAS has no counterpart. README and the overlap index no longer describe ATLAS as covering models only. `scripts/check_cross_references.py` gains C8, which pins the ATLAS release and its tactic list and fails when the page does not state that release, misses, repeats, renames or reorders a tactic row, or names a technique id in the table.

### Fixed

- `scripts/check_docs_prose.py`: HTML comments are stripped in one pass, so a line holding many unclosed `<!--` no longer costs quadratic time (a 40 KB line took about 0.8 s); a GFM table delimiter row such as `| -- | -- |` is no longer reported as a dash; a Markdown file that is not valid UTF-8 is reported as `file:line: not valid UTF-8` with exit 1 instead of ending the run with a traceback; and a copy of the repository nested inside another repository's work tree is walked on disk instead of reading the outer repository's index, which lists none of the copy's files when the outer repository does not track it. CONTRIBUTING.md now tells contributors to run the check before opening a pull request.
- `docs/cna/application-package.md` defines "the owner", "the unit" and OWNER-RETAINED at the top of the document.
- Technique and tactic pages show the attack classes and HMA checks in `matrix.json`. T-1006 and T-5002 listed `AIM-001, AIM-002` where the data lists `A2A-001, A2A-002`; the References class link on T-1006, T-5002, T-9002 and T-9006 named the class the data replaced on 2026-08-25, contradicting the same page's `Attack Class` line; and the technique tables on the Reconnaissance, Lateral Movement and Impact tactic pages showed the same four old classes. `scripts/check_technique_pages.py` compared only the `Attack Class` and `OASB Controls` lines. It now also checks the title, description, `Tactic`, `DVAA Validation`, `HMA Checks` and `Evidence Tier` lines and both References links of each technique page, failing when a line is missing, repeated or different, and checks each tactic page against its full rendering from `matrix.json`. `--fix` rewrites all of them from the data, and exits 1 instead of 0 when a missing or repeated line remains that it has no place to write.
- README attack-class tables are rendered from `matrix.json` inside a generated block. The hand-typed tables reworded 34 of the 40 class descriptions, and GATEWAY-EXPLOIT, SOUL-INJECT, AGENT-IMPERSONATE and RETROACTIVE-PRIV described a different attack than the class definition. Every table now lists each class with its `matrix.json` description and member techniques and links its class page; the class-level evidence column, which `matrix.json` does not hold, is dropped in favor of the per-technique record in EVIDENCE_AUDIT.md. `scripts/check_readme_claims.py` fails when the block differs from `matrix.json` and `--fix` re-renders it.
- `docs/cna/application-package.md` says no other file in this repository references the detected-not-owned CVE id, in the evidence framing and in the sources table; it said the repository did not reference that id while the page itself named it three times. `tests/test_cna_package.py` checks every such statement on the page against the tracked files and requires one for every CVE id the page names.
- `scripts/validate_matrix.py` S11: `matrixCommit` is resolved when the checkout has the commit's history. A sha that names no commit, names an object other than a commit, or names a commit that has no `matrix.json` or whose `matrix.json` carries ids other than those in `technique-ids.json` is refused; any 40-hex value used to pass. A shallow checkout without that commit, or a copy without git, still gets the shape check only, and the summary line after the sha says which check ran.
- README described DVAA as "21 vulnerable agents"; DVAA's own agent table labels one of the 21 a hardened reference and four control-protected variants. The Cross-Framework Mapping row now reads "21 agents: 16 deliberately vulnerable, 1 hardened reference, 4 control-protected variants". The DVAA figures are pinned in `related-projects.json` with the DVAA release and commit they were read from (0.9.3, `5791826`), and `scripts/check_readme_claims.py` fails when a README line naming DVAA states a different agent, agent-kind or vulnerability-category count in one of the wordings it reads ("N agents", "N deliberately vulnerable", "N hardened reference", "N control-protected variants", "N vulnerable agents" and "N categories", with up to two words between the number and "categories"); a figure worded any other way is not checked.
- Attack class pages: ten pages (BEHAVIORAL-IMPERSONATE, INTEGRITY-BYPASS, LLM-EXPOSE, NEMO-NETWORK-EXPOSE, NEMO-OPENCLAW-INHERIT, PHANTOM-SOUL, SKILL-MEM-AMP, SOUL-FORK, SUPPLY-CHAIN-INSTALL, TOCTOU-RACE) had their dashes replaced by hand while the class descriptions in `matrix.json` kept them, so running `scripts/generate_class_markdown.py` as documented brought the dashes back and failed `scripts/check_docs_prose.py`. The ten descriptions in `matrix.json` now carry the same punctuation as the pages, the STIX bundle is regenerated (the ten grouping descriptions change, nothing else), and a fresh rendering equals all 40 committed pages. `scripts/generate_class_markdown.py --check` writes nothing and exits 1 when a page differs from the rendering, a class has no page, or a page has no class. CONTRIBUTING.md now says to add or change a class in `matrix.json` and regenerate its page, instead of writing the page by hand.
- `scripts/check_docs_prose.py`: a new Markdown file is checked before it is staged (untracked files that are not ignored are listed alongside tracked ones; it used to print `OK` without reading the file); a path to the repository that differs from the on-disk path only in letter case, on a case-insensitive filesystem, still reads the git file list instead of walking the directory and checking ignored files; `<!-->` and `<!--->` are complete empty comments, as in CommonMark, instead of hiding every following line up to the next `-->`; and a table delimiter row inside a block quote, such as `> | -- | -- |`, is no longer reported as a dash.
- `docs/cna/application-package.md` describes the unpublished planning records it cites without giving their file paths, which a reader of this repository cannot open.
- README and the v1.2.0 entry for `scripts/validate_matrix.py` no longer say that a workflow runs the validator; none does. Run it locally with `python3 scripts/validate_matrix.py`.
- `scripts/check_technique_pages.py` skips fenced code blocks, so a `# comment` line in a shell example is no longer counted as a second title line, and a code example that shows a data line is no longer counted as that line.
- `scripts/validate_matrix.py` S11: a partial clone that lacks the tree or the `matrix.json` blob of the `matrixCommit` commit gets the shape check only, as a shallow checkout does. It used to report that the commit has no `matrix.json` and exit 1 for a correct value.
- `cross-references/mitre-atlas-mapping.md` attributes its quoted description of ATLAS to the notes for ATLAS release 2026.08, where the sentence appears, instead of to unnamed release notes.
- `scripts/validate_matrix.py` S11: a path to the repository that differs from the on-disk path only in letter case, on a case-insensitive filesystem, still reads `matrix.json` at `matrixCommit`; that run used to report "shape only: no git history at the repository root". A `matrixCommit` whose `matrix.json` entry is a directory or a submodule is refused with "has no matrix.json file"; it used to pass as a partial clone without the blob.
- `scripts/check_technique_pages.py` follows the CommonMark fence rules more closely. A backtick run followed by another backtick on the same line, such as a line that starts with three backticks and holds a fourth later, no longer opens a fenced block, and a form feed or U+2028 no longer starts a line, so the data lines after either are checked again. The time to find the data lines is linear in the number of fenced blocks (a 128 KB page with 16,000 fence lines took about 3.3 s). The tests now pin each closing-fence rule: a shorter run, the other fence character and a run with an info string do not close a block, an unclosed fence runs to the end of the page, and `--fix` leaves a "No documented procedures yet." line inside a fenced block alone.
- `scripts/generate_class_markdown.py` exits 2 and writes nothing for an argument it does not know. Any argument other than `--check`, such as `--help` or a mistyped `--chek`, used to regenerate all 40 pages and overwrite hand edits without notice. `--help` now prints the usage.
- `scripts/check_readme_claims.py` reads the DVAA category count under any name ("N categories", with up to two words between the number and "categories"); "13 attack categories" on a line naming DVAA used to pass. README, `related-projects.json` and the entry above name the wordings the check reads instead of saying it fails on any different number.

### Added

- `canonical-classes.json`: the canonical attack classes resolved to `matrix.json` technique ids (authored mapping, ruled 2026-08-30). The class axis is behavior; `attackClass` in `matrix.json` is attack vector, and neither is derivable from the other. Each technique carries exactly one `primary` class, with `secondary` recording other classes its definition also satisfies; resolution uses `primary` only. `scripts/check_canonical_classes.py` enforces the shape: known class names, ids that exist in `matrix.json`, `primary` a partition of the technique ids, and per-class arrays sorted and disjoint.

- `ATTRIBUTION.md` and `scripts/check_attribution.py`: a published attribution record placing every `matrix.json` technique id in exactly one of two lists — externally contributed (the contributor's credit as they gave it, plus the issue or pull request the submission arrived in) or authored in-house — with the partition enforced in CI alongside the existing claim checks. All 61 current techniques are listed as authored in-house: the repository's history establishes no external contributor, and credit is recorded, never guessed.

- `.github/ISSUE_TEMPLATE/technique-submission.yml` and `.github/pull_request_template.md`: the public submission entry point. The issue form's required fields are the inputs the published evidence bar already demands (tactic, name, description, attack class, evidence tier and its tier-specific source, procedure example, detection logic, DVAA validation, defensive controls, references, credit preference); the PR template states the two same-commit placement obligations (`canonical-classes.json` `primary` and the (A)/(B) `cross-references/` placement).

- `docs/cna/application-package.md`: prep-only package for the CVE Numbering Authority application under CSNP — scope statement, Root recommendation (Red Hat, MITRE TL-Root as fallback), the five prereqs, and the five filing steps with their refs. Every fact traces to the roadmap unit or to this repository; unknown values are explicit `PLACEHOLDER` markers. Nothing has been submitted: the filing, the Root contact and counsel sign-off are owner-retained.

### Changed

- CONTRIBUTING.md gains "Contributor credit" (what is credited, that the credit is published in `ATTRIBUTION.md` as the name or handle the contributor gives, and how to decline) and "Change control" (OpenA2A decides what enters the matrix, a submission creates no entitlement to inclusion, accepted content may be edited, re-tiered, re-placed or removed, with the decision recorded on the submission thread). The evidence-tier table and the technique template are unchanged.
- `cross-references/gap-analysis.md` is now `cross-references/technique-overlap-index.md`. The page listed techniques by whether an external framework addressed them, which is a judgement about frameworks this project does not maintain; it now indexes which techniques this repository's own mapping documents name, and the counts are derived from `matrix.json` and checked in CI.
- OASB control mappings for T-9001, T-9003, T-9004 and T-9005 re-derived from the full control text of the shipped 46-control OASB-1 set (mapping review, 2026-08-25). Three name-match mappings were wrong (6.2 and 8.1 on T-9001 are component and conversation integrity, not data integrity; 7.4 on T-9005 is agent-to-agent logging, not output attribution) and two text-verified controls were missing (6.3 on T-9003, whose audit names the technique's own HEARTBEAT checks; 7.2 on T-9004). T-9001 is now 2.2, 2.3, 4.1, 4.2, 10.5; T-9003 adds 6.3; T-9004 adds 7.2; T-9005 is now 4.1, 4.4, 10.1, 10.2.
- Class-level `hmaChecks` in `matrix.json` are derived from HackMyAgent's `TAXONOMY_MAP` (`src/hardening/taxonomy.ts`) by `scripts/derive_class_checks.py` and are not edited by hand (ruled 2026-08-25). The hand-curated lists had drifted into three simultaneous wrong states — spec subset, registry rows and HMA truth all disagreed. Technique-level `hmaChecks` remain authored.
- Technique pages: the `Attack Class` and `OASB Controls` lines are now derived from matrix.json (`scripts/check_technique_pages.py`, enforced in CI). Six pages still cited OASB 11.1-11.4, which do not exist in the shipped set; four pages carried a superseded attack class.

## v1.1 — 2026-06-04

### Added

- 4 lab-validated techniques, each backed by a DVAA scenario and an HMA check family: T-2009 (Parser Differential Exploitation), T-4007 (Tool Impersonation and Squatting), T-6007 (Persistent Agent State Manipulation), T-7007 (Context Assembly Pipeline).
- 4 corresponding attack classes (40 total).

### Changed

- Technique count reconciled to 61 across 9 tactics; evidence tiers 16 observed / 42 validated / 3 adapted. Observed count unchanged: exposure-sweep signals are not wild-observed attacks.
- README attack-class tables reconciled (previously undercounted by 2).

### Fixed (2026-07-02)

- README Matrix Overview per-tactic technique counts summed to 57; corrected to match the 61 techniques in `matrix.json` (initial-access 9, privilege-escalation 7, persistence 7, collection 7).
- All 9 `tactics/*.md` pages shipped empty technique tables; now populated from `matrix.json` (ID, name, evidence tier, attack class) with links to each technique page.
- EVIDENCE_AUDIT.md anticipated-pushback item still cited 57 techniques; updated to 61.

## v1.0 — 2026-03-24

### Initial Release

- 9 tactics (kill chain stages)
- 57 techniques with evidence classification
- 36 attack classes
- 4 documented attack paths
- Cross-reference mappings to MITRE ATT&CK, MITRE ATLAS, and OWASP Top 10 for LLM
- Gap analysis showing agent-layer coverage not addressed by existing frameworks
- Machine-readable matrix (matrix.json)
- Evidence audit documenting justification for every technique's evidence tier

### Evidence Distribution

- 16 techniques with real-world evidence (Observed)
- 38 techniques validated in controlled lab environment (Validated)
- 3 techniques adapted from traditional security frameworks (Adapted)

### Sources

- NVIDIA NemoClaw security assessment (10 confirmed vulnerabilities)
- Internet-wide AI exposure sweeps (January and March 2026)
- OpenClaw security analysis (8 merged security PRs)
- os-info-checker npm supply chain attack (May 2025)
- DVAA (Damn Vulnerable AI Agent) lab validation
- HackMyAgent automated detection (199 checks)
- OASB defensive benchmark (72 controls)
