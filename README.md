# AI Agent Threat Matrix

A structured framework for classifying, detecting, and defending against attacks on AI agent systems.

**Version 1.2** | September 2026 | [Threats Matrix](https://threats.opena2a.org) | [OpenA2A](https://opena2a.org)

## Matrix Overview

Open [`matrix.json`](matrix.json) first. It holds every tactic, technique, attack class and attack path, and [`scripts/validate_matrix.py`](scripts/validate_matrix.py) checks it against its schema in [`schema/`](schema/). Each technique carries these fields:

| Field | Holds |
|-------|-------|
| `id`, `name`, `description` | The technique id (such as `T-2002`), its name and what the attacker does |
| `tactic` | The tactic id, one of the rows of the table below |
| `evidenceTier` | `observed`, `validated` or `adapted`, as defined under [Evidence Standard](docs/evidence-tiers.md#evidence-standard) |
| `attackClass` | The technique's primary attack class, such as `RAG-POISON` |
| `hmaChecks`, `oasbControls` | The HackMyAgent checks that detect it and the OASB controls that defend against it |
| `dvaaValidation` | The DVAA challenge, scenario or agent that reproduces it in the lab, or `null` |
| `wildPrevalence`, `wildSampleCount` | The wild prevalence the registry serves for the technique, a percentage from 0 to 100, and its sample count, both 0 where it serves none; the top-level `wildPrevalenceSource` gives the endpoint and the date they were read |

The tactics, in kill chain order:

| Tactic | Kill Chain Stage | Techniques | Description |
|--------|-----------------|------------|-------------|
| [Reconnaissance](tactics/reconnaissance.md) | 1 | 7 | Map the target agent's attack surface, capabilities, and behavioral boundaries |
| [Initial Access](tactics/initial-access.md) | 2 | 9 | Gain control over agent behavior through prompt manipulation or input exploitation |
| [Credential Harvest](tactics/credential-harvest.md) | 3 | 6 | Extract API keys, tokens, and credentials from agent context and connected services |
| [Privilege Escalation](tactics/privilege-escalation.md) | 4 | 7 | Escalate capabilities beyond declared scope or bypass authorization |
| [Lateral Movement](tactics/lateral-movement.md) | 5 | 6 | Pivot from compromised agent to connected services or other agents |
| [Persistence](tactics/persistence.md) | 6 | 7 | Establish persistent access surviving restarts and session changes |
| [Collection](tactics/collection.md) | 7 | 7 | Gather and stage data from databases, file systems, and APIs |
| [Exfiltration](tactics/exfiltration.md) | 8 | 6 | Transfer collected data out of target environment |
| [Impact](tactics/impact.md) | 9 | 6 | Modify data, deploy malicious code, or disrupt services |

**61 techniques** across 9 tactics. **40 attack classes** grouping related techniques. **16 techniques with real-world evidence**. **42 techniques validated in controlled lab environments**. **3 techniques adapted from traditional environments** (marked as such).

The live API at `https://api.oa2a.org/api/v1/threat-matrix` still labels the matrix 1.1 while this repository is at 1.2; the technique and tactic counts agree.

## Who this is for

- **Security leaders and CISOs**: what can go wrong with an agent you ship, and how to compare one vendor's detection claim with another's.
- **IAM professionals and identity architects**: the attacks on agent credentials and on trust between agents, and the controls that answer them.
- **Platform and security engineers, and implementers**: what to collect to see each technique, and which ids and fields stay stable.
- **GRC, audit and compliance readers, and standards reviewers**: the control and evidence tier behind each technique, and how the matrix relates to existing catalogs.

[Use cases](docs/use-cases.md) gives each reader's question and where the matrix answers it.

## How to Use This Framework

### For Red Teams
Follow the kill chain stages sequentially. Use technique IDs to plan attack paths. Reference DVAA challenges for practice. The [Attack Paths](docs/attack-paths.md) page provides complete worked examples.

### For Blue Teams
Map your defenses against each tactic. Use OASB controls as a checklist. Any tactic without detection or prevention represents a gap. Focus on breaking the chain at the earliest stage.

### For Researchers
Cite techniques using their IDs (e.g., "ATM T-2001"). The catalog is extensible: contribute new techniques via pull request with evidence requirements.

### For Vendors
Map your tool's detection capabilities to ATM technique IDs. This enables customers to understand which agent-specific threats your tool covers.

## How to Cite

When referencing individual techniques:
> AI Agent Threat Matrix T-2001 (Direct Prompt Injection). OpenA2A, 2026. https://threats.opena2a.org/techniques/T-2001

When referencing the framework:
> OpenA2A. "AI Agent Threat Matrix v1.2." September 2026. https://threats.opena2a.org

## Documentation

- [Overview](docs/overview.md): the matrix's purpose, and what it covers and leaves to MITRE ATLAS, the OWASP Top 10 for LLM and MITRE ATT&CK
- [Attack classes](docs/attack-classes.md): every attack class with its description and techniques, rendered from `matrix.json`
- [Cross-framework mapping](docs/cross-framework-mapping.md): what HackMyAgent, DVAA, OASB and the MITRE and OWASP mapping documents provide, and how `python3 scripts/check_readme_claims.py` checks their figures
- [Attack paths](docs/attack-paths.md): complete kill chain traversals demonstrated in DVAA
- [Evidence tiers](docs/evidence-tiers.md) and [EVIDENCE_AUDIT.md](EVIDENCE_AUDIT.md): the tier definitions, the evidence standard with each tier's technique count, and every technique's tier justification
- [Schema](docs/schema.md): what `python3 scripts/validate_matrix.py` checks in `matrix.json`, `technique-ids.json` and the STIX bundle
- [Data sources](docs/data-sources.md): the data a defender collects to see each technique, the code that reads each source, and the techniques that map none
- [Use cases](docs/use-cases.md): the situations the matrix answers, the commands for each, and the catalogs that already cover networks and AI systems
- [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md): the repository structure, proposing techniques and attack classes, and changes to the matrix and its checks
- Related projects: [HackMyAgent](https://github.com/opena2a-org/hackmyagent) (automated detection), [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) (lab validation), [OASB](https://oasb.ai) (defensive controls) and [AI Agent Kill Chain](https://github.com/opena2a-org/ai-agent-kill-chain) (the kill chain stages)

## License

Apache-2.0. The framework is free to use, cite, and build upon.

*Maintained by OpenA2A. [GOVERNANCE.md](GOVERNANCE.md) says who decides what enters the matrix and how it changes. Contributions welcome via pull request.*
