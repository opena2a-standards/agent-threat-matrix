# Changelog

## Unreleased

### Changed

- OASB control mappings for T-9001, T-9003, T-9004 and T-9005 re-derived from the full control text of the shipped 46-control OASB-1 set (Chief Architect review, 2026-08-25). Three name-match mappings were wrong (6.2 and 8.1 on T-9001 are component and conversation integrity, not data integrity; 7.4 on T-9005 is agent-to-agent logging, not output attribution) and two text-verified controls were missing (6.3 on T-9003, whose audit names the technique's own HEARTBEAT checks; 7.2 on T-9004). T-9001 is now 2.2, 2.3, 4.1, 4.2, 10.5; T-9003 adds 6.3; T-9004 adds 7.2; T-9005 is now 4.1, 4.4, 10.1, 10.2.
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
