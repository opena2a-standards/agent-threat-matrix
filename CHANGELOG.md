# Changelog

## Unreleased

### Added

- `canonical-classes.json`: the canonical attack classes resolved to `matrix.json` technique ids (authored mapping, ruled 2026-08-30). The class axis is behavior; `attackClass` in `matrix.json` is attack vector, and neither is derivable from the other. Each technique carries exactly one `primary` class, with `secondary` recording other classes its definition also satisfies; resolution uses `primary` only. `scripts/check_canonical_classes.py` enforces the shape: known class names, ids that exist in `matrix.json`, `primary` a partition of the technique ids, and per-class arrays sorted and disjoint.

- `docs/cna/application-package.md`: prep-only package for the CVE Numbering Authority application under CSNP — scope statement, Root recommendation (Red Hat, MITRE TL-Root as fallback), the five prereqs, and the five filing steps with their refs. Every fact traces to the roadmap unit or to this repository; unknown values are explicit `PLACEHOLDER` markers. Nothing has been submitted: the filing, the Root contact and counsel sign-off are owner-retained.

### Changed

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
