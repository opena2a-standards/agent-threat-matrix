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

## Use cases

### Your team ships an agent and security asks what can go wrong

A team is about to ship an agent that reads documents, calls tools and keeps memory. Security asks for the threat list. The layer between the model and the user, where governance files, skills, MCP connections, memory and credentials in context live, is where agents differ, and a team without a list for that layer defends by guesswork.

The matrix classifies attacks on that layer into 9 tactics and 61 techniques along a kill chain. Each technique carries an evidence tier, maps to a detection check and a defensive control, and 58 of the 61 carry a reproducible lab scenario.

What you can do today: browse [threats.opena2a.org](https://threats.opena2a.org), or read `matrix.json` and validate it against its schema.

```bash
git clone https://github.com/opena2a-standards/agent-threat-matrix
cd agent-threat-matrix
python3 scripts/validate_matrix.py
```

Where it stops today: the live API at `https://api.oa2a.org/api/v1/threat-matrix` still labels the matrix 1.1 while this repository is at 1.2; the technique and tactic counts agree.

### A web page tells your agent what to do

An agent reads a page or a tool result. The page contains an instruction. The agent follows it, and an API key sitting in its context leaves with the next request. The person who delegated the task never sees the page.

Both halves are catalogued: Indirect Prompt Injection (T-2002, initial access, observed in the wild) and Context Window Credential Leak (T-3006, credential harvest, validated in the lab). The ids are stable, so detection signatures (AIIS) and telemetry attributes can cite the same technique.

What you can do today:

```bash
jq '.techniques[] | select(.id == "T-2002" or .id == "T-3006")' matrix.json
```

Where it stops today: 16 of the 61 techniques carry real-world evidence; 42 are validated in controlled lab environments and 3 are adapted from traditional environments, and each is marked as such.

### A vendor says its scanner catches agent attacks

A buyer hears that a tool "covers agent threats" and has no way to compare that claim with another vendor's, or to load it into the systems they already run.

Vendors map their detections to technique ids, and the matrix ships as a STIX 2.1 bundle rendered from `matrix.json`, so the same ids load into a SIEM or threat-intelligence platform alongside ATT&CK and ATLAS.

What you can do today: import `stix/agent-threat-matrix-bundle.json`, or regenerate it with `python3 scripts/generate_stix.py`.

Why you can check this yourself: [`matrix.json`](matrix.json) and its schema in [`schema/`](schema/); [`scripts/validate_matrix.py`](scripts/validate_matrix.py); the per-technique justification in [`EVIDENCE_AUDIT.md`](EVIDENCE_AUDIT.md); the STIX bundle in [`stix/`](stix/); the rendered site at [threats.opena2a.org](https://threats.opena2a.org); and the live API at `https://api.oa2a.org/api/v1/threat-matrix`.

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

- [Overview](docs/overview.md): the purpose of the matrix, and what it covers and leaves to MITRE ATLAS, the OWASP Top 10 for LLM and MITRE ATT&CK
- [Attack classes](docs/attack-classes.md): every attack class with its description and techniques, rendered from `matrix.json`
- [Cross-framework mapping](docs/cross-framework-mapping.md): what HackMyAgent, DVAA, OASB and the MITRE and OWASP mapping documents provide, and how `python3 scripts/check_readme_claims.py` checks their figures
- [Attack paths](docs/attack-paths.md): complete kill chain traversals demonstrated in DVAA
- [Evidence tiers](docs/evidence-tiers.md) and [EVIDENCE_AUDIT.md](EVIDENCE_AUDIT.md): the tier definitions, the evidence standard with the number of techniques in each tier, and the justification of every technique's tier
- [Schema](docs/schema.md): what `python3 scripts/validate_matrix.py` checks in `matrix.json`, `technique-ids.json` and the STIX bundle
- [Use cases: background](docs/use-cases.md): the catalogs that already cover networks and AI systems
- [CONTRIBUTING.md](CONTRIBUTING.md): the repository structure, and how to propose a technique or an attack class
- [CHANGELOG.md](CHANGELOG.md): changes to the matrix and its checks
- Related projects: [HackMyAgent](https://github.com/opena2a-org/hackmyagent) (automated detection), [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) (lab validation), [OASB](https://oasb.ai) (defensive controls) and [AI Agent Kill Chain](https://github.com/opena2a-org/ai-agent-kill-chain) (the kill chain stages)

## License

Apache-2.0. The framework is free to use, cite, and build upon.

*Maintained by OpenA2A. Contributions welcome via pull request.*
