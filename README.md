# AI Agent Threat Matrix

A structured framework for classifying, detecting, and defending against attacks on AI agent systems.

**Version 1.2** | September 2026 | [Threats Matrix](https://threats.opena2a.org) | [OpenA2A](https://opena2a.org)

## Use cases

### Your team ships an agent and security asks what can go wrong

A team is about to ship an agent that reads documents, calls tools and keeps memory. Security asks for the threat list. Existing catalogs cover networks (MITRE ATT&CK) and AI systems (MITRE ATLAS, which names attacks on models and, in recent releases, some on agents, such as agent tool invocation and agent configuration changes). The layer between the model and the user, where governance files, skills, MCP connections, memory and credentials in context live, is where agents differ, and a team without a list for that layer defends by guesswork.

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

Why you can check this yourself: [`matrix.json`](matrix.json) and its schema [`schema/threat-matrix-v1.2.schema.json`](schema/threat-matrix-v1.2.schema.json); [`scripts/validate_matrix.py`](scripts/validate_matrix.py); the per-technique justification in [`EVIDENCE_AUDIT.md`](EVIDENCE_AUDIT.md); the STIX bundle in [`stix/`](stix/); the rendered site at [threats.opena2a.org](https://threats.opena2a.org); and the live API at `https://api.oa2a.org/api/v1/threat-matrix`.

---

## Purpose

AI agents operate differently from traditional software. They make decisions based on natural language, delegate actions to tools with varying trust levels, communicate with other agents via open protocols, and maintain persistent memory that can be poisoned. These properties create attack surfaces that existing frameworks do not adequately model.

The **AI Agent Threat Matrix** classifies attacks against AI agent systems into 9 tactics and 61 techniques, organized by kill chain stage. Every technique carries an explicit evidence tier: observed in the wild, validated in a controlled lab environment, or adapted from a traditional environment and marked as such. Every technique maps to automated detection and a defensive control; 58 of the 61 also carry a reproducible lab scenario.

### What This Covers (and What It Doesn't)

This matrix covers the **agent layer**, the infrastructure between the model and the user:

- Governance file manipulation (SOUL.md, system prompts, behavioral constraints)
- Skill and plugin supply chain attacks
- MCP and A2A protocol exploitation
- Agent memory poisoning and persistence
- Credential exposure through agent infrastructure
- Sandbox escape via framework defaults
- Cross-agent lateral movement and identity attacks

This matrix does **not** cover:

- Model-level attacks (adversarial examples, training data poisoning): see [MITRE ATLAS](https://atlas.mitre.org/), which also names some agent techniques; [the ATLAS mapping](cross-references/mitre-atlas-mapping.md) relates its tactics to this matrix's
- Prompt injection as a standalone topic: see [OWASP Top 10 for LLM](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- Traditional enterprise network attacks: see [MITRE ATT&CK](https://attack.mitre.org/)

The Agent Threat Matrix is designed to work **alongside** these frameworks, not replace them.

---

## Matrix Overview

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

---

## Evidence Standard

Every technique in this matrix is assigned an evidence tier. The definitions are quoted from [docs/evidence-tiers.md](docs/evidence-tiers.md):

| Tier | Meaning | Count |
|------|---------|-------|
| **Observed** | Confirmed in real-world production systems | 16 (26%) |
| **Validated** | Reproduced in controlled lab environment (DVAA) | 42 (69%) |
| **Adapted** | Well-understood traditional technique applied to agent context, not yet observed agent-specifically | 3 (5%) |

We do not publish purely theoretical techniques. Every entry has either a real-world observation, a reproducible lab scenario, or an established traditional precedent.

See [EVIDENCE_AUDIT.md](EVIDENCE_AUDIT.md) for the full justification of every technique's evidence tier.

---

## Cross-Framework Mapping

This matrix maps every technique to four external references:

| Framework | What It Provides |
|-----------|-----------------|
| [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | Automated detection (318 static checks, 164 attack payloads) |
| [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Lab validation (21 agents: 16 deliberately vulnerable, 1 hardened reference, 4 control-protected variants; 12 vulnerability categories) |
| [OASB](https://oasb.ai) | Defensive controls (46 controls across 10 domains) |
| MITRE ATT&CK / ATLAS / OWASP LLM | An index of which techniques this repository's mapping documents name against each framework, and which they do not |

See [cross-references/](cross-references/) for detailed mapping documents. The DVAA figures are pinned in [`related-projects.json`](related-projects.json) with the DVAA release they were read from. On each README line naming DVAA, `python3 scripts/check_readme_claims.py` reads the wordings "N agents", "N deliberately vulnerable", "N hardened reference", "N control-protected variant(s)", "N vulnerable agent(s)" and "N categories" (up to two words, each a run of ASCII letters and hyphens, may stand between the number and "categories"), in any letter case with one space between words, and fails when one states a different number. A DVAA figure worded any other way is not checked. A line naming DVAA fails the check when it carries a format character (Unicode category Cf, such as a soft hyphen or a zero width space), a control character other than a tab, a Hangul filler, a combining mark that Unicode lists as default ignorable, such as a variation selector, or a code point that Unicode lists as default ignorable without assigning it, because such a character can keep a figure from being read while the line still shows it. A line names DVAA when it contains "DVAA" once such characters are removed, either as it then stands or after three more steps, with no combining mark (Unicode category M) directly after it that NFKC joins to the last A. So "DVAA" followed by U+0301 COMBINING ACUTE ACCENT, which NFKC joins to the A as U+00C1 LATIN CAPITAL LETTER A WITH ACUTE, does not name DVAA, nor does "DVAA" followed by U+0332 COMBINING LOW LINE and U+0301, while "DVAA" followed by U+0332, U+0335 COMBINING SHORT STROKE OVERLAY, U+0338 COMBINING LONG SOLIDUS OVERLAY or U+20DD COMBINING ENCLOSING CIRCLE, which NFKC leaves apart from the A, names DVAA. A mark counts as directly after "DVAA" only where it is written as itself, not as a character reference, directly after a letter or another mark, and a mark that does not is kept apart from the name, so that NFKC in the third step below does not join it to the last A: `DV**AA**` followed by U+0301, `DVAA&#x301;`, `DV**AA**&#x301;` and `DV**AA&#x301;**` name DVAA, while NFKC alone gives "DVA" followed by U+00C1. First, going along the line, its HTML is removed wherever it stands, also where it starts inside a link destination or title and ends after the `)` that closes them: each comment, processing instruction, CDATA section and declaration from its opening `<!--`, `<?`, `<![CDATA[` or `<!` and an ASCII letter to the first `-->`, `?>`, `]]>` or `>` after it, respectively, or to the end of the line when none follows, and each tag from `<` or `</` and a name, which is an ASCII letter followed by any ASCII letters, digits and hyphens, to a `>` right after the name or, after `/` or a character Unicode lists as white space (such as U+00A0 NO-BREAK SPACE), to the first `>` after that if no `<` comes first. Where white space other than a space or tab follows a tag name, the line is also read with only a space, a tab or `/` ending a tag name, and names DVAA when either reading does. Second, going along what remains, each `]` followed by `(` is removed with the text after it to the first `)` if no further `(` comes first, and each `]` followed by `[` with the text after it to the first `]` if no further `[` comes first, whether or not they make a link, then each `!` directly before a `[`, and then the Markdown characters `*`, `_`, `~`, `` ` ``, `\`, `[` and `]`. Third, its character references are decoded, each to the characters it stands for less any such character, so `&#8203;` (U+200B) leaves nothing, and it is brought to Unicode NFKC with each character that Unicode lists as confusable with A, D or V, such as U+0410 CYRILLIC CAPITAL LETTER A, read as that letter. So the name written as `DV&#8203;AA`, `**DV**AA`, `DV<!-- -->AA`, `<b>DV</b>AA`, `[DV](url)AA`, `DV![](x.png)AA`, `[DV](url "<b` U+00A0 `x=")AA>` or in fullwidth letters does not take the line out of the check, while `DV!AA` does not name DVAA. On a line that carries one of the characters above, a combining mark after "DVAA" does not keep the line from naming DVAA, so "DVAA" followed by U+200B and U+0301 names DVAA and the line fails on U+200B. A line that states one of the `matrix.json` counts in this README once such characters are removed fails the same way, and each failure gives the line and column of the character.

The HackMyAgent and OASB figures are pinned in [`related-projects.json`](related-projects.json) too, with the HackMyAgent release they were read from. The check reads "N static checks", "N payloads" and "N attack payloads" against the pinned HackMyAgent figures and "N controls" and "N domains" against the pinned OASB figures, on every README line in that letter case, and fails when one states a different number.

---

## Attack Classes (40)

Attack classes group related techniques by the underlying vulnerability pattern. The tables below are rendered from [`matrix.json`](matrix.json): `python3 scripts/check_readme_claims.py` fails when they differ, and `--fix` re-renders them. Each page in [attack-classes/](attack-classes/) names the class's techniques and the HMA checks mapped to it. Real-world evidence is recorded per technique in [EVIDENCE_AUDIT.md](EVIDENCE_AUDIT.md).

<!-- BEGIN GENERATED: attack-class-tables -->

### Governance (11 classes)
| Class | Description | Techniques |
|-------|-------------|------------|
| [ASSEMBLY-INJECT](attack-classes/ASSEMBLY-INJECT.md) | Attacks targeting the system prompt assembly process where components combine into exploitable injections | T-7007 |
| [PHANTOM-SOUL](attack-classes/PHANTOM-SOUL.md) | Agent deployed with zero behavioral constraints: no SOUL.md, no system prompt, no governance | T-1006 |
| [SOUL-BOUNDARY](attack-classes/SOUL-BOUNDARY.md) | Exploiting ambiguous or incomplete constraint definitions to find unguarded actions | T-2008 |
| [SOUL-DELEGATE](attack-classes/SOUL-DELEGATE.md) | Exploiting delegation and capability transfer mechanisms to exceed authorized scope | T-4001 |
| [SOUL-DRIFT](attack-classes/SOUL-DRIFT.md) | Gradually displacing safety instructions from the active context through conversation manipulation | T-2004, T-4006 |
| [SOUL-FORK](attack-classes/SOUL-FORK.md) | Different behavior under evaluation vs production: agent passes safety tests but behaves differently in deployment | T-5002 |
| [SOUL-HIJACK](attack-classes/SOUL-HIJACK.md) | External content achieving full override of agent behavioral constitution | T-4002, T-5002 |
| [SOUL-HV](attack-classes/SOUL-HV.md) | Techniques to bypass agent harm avoidance constraints (4 sub-types) | T-2001, T-2003 |
| [SOUL-IMPERSONATE](attack-classes/SOUL-IMPERSONATE.md) | False capability claims exceeding actual authorization level | T-4002 |
| [SOUL-INJECT](attack-classes/SOUL-INJECT.md) | Directly manipulating or overriding the agent's system-level instructions and behavioral boundaries | T-1003, T-2001, T-2003, T-2007, T-2008 |
| [SOUL-POISON](attack-classes/SOUL-POISON.md) | Malicious instructions injected into governance files at write-time | T-2001, T-2003, T-2007, T-2008 |

### Supply Chain (11 classes)
| Class | Description | Techniques |
|-------|-------------|------------|
| [FAKETOOL-INJECT](attack-classes/FAKETOOL-INJECT.md) | MCP tool impersonation, squatting, and schema poisoning attacks | T-4007 |
| [HEARTBEAT-RCE](attack-classes/HEARTBEAT-RCE.md) | Exploiting scheduled task or heartbeat mechanisms to achieve persistent code execution | T-6005, T-9003 |
| [MEM-POISON](attack-classes/MEM-POISON.md) | Injecting malicious entries into agent persistent memory to maintain control across sessions | T-2002, T-3004, T-6001, T-6002, T-7004 |
| [ORG-SKILL-SPREAD](attack-classes/ORG-SKILL-SPREAD.md) | Propagating malicious capabilities across an organization's agent fleet through shared skills and registries | T-9002, T-9004, T-9005, T-9006 |
| [PERSIST-STATE](attack-classes/PERSIST-STATE.md) | Cross-session persistence via memory poisoning, state tampering, and cached context injection | T-6007 |
| [RAG-POISON](attack-classes/RAG-POISON.md) | Injecting malicious content into retrieval-augmented generation data sources | T-2002, T-7006 |
| [SKILL-EXFIL](attack-classes/SKILL-EXFIL.md) | Using legitimate tool capabilities for unauthorized data transfer | T-5001, T-7003, T-8001, T-8002, T-8003, T-8004, T-8006 |
| [SKILL-FRONTMATTER](attack-classes/SKILL-FRONTMATTER.md) | Embedding malicious instructions in skill or plugin metadata and description fields | T-2005, T-6004, T-6006 |
| [SKILL-MEM-AMP](attack-classes/SKILL-MEM-AMP.md) | Skill plants payload in agent memory that survives skill uninstall: cross-session persistence | T-3004 |
| [SUPPLY-CHAIN-INSTALL](attack-classes/SUPPLY-CHAIN-INSTALL.md) | Unsigned installation scripts executed without integrity verification: curl\|sh without checksum | T-9003 |
| [UNICODE-STEGO](attack-classes/UNICODE-STEGO.md) | Using invisible Unicode characters, homoglyphs, and encoding tricks to bypass filters | T-2006, T-4005 |

### Infrastructure (10 classes)
| Class | Description | Techniques |
|-------|-------------|------------|
| [A2A-EXPOSE](attack-classes/A2A-EXPOSE.md) | Agent-to-Agent protocol endpoints publicly discoverable without access control | T-1006, T-5002 |
| [AITOOL-EXPOSE](attack-classes/AITOOL-EXPOSE.md) | AI development tools (Jupyter, MLflow, Gradio, Streamlit) exposed without authentication | T-1001, T-1004, T-1005 |
| [CODE-INJECTION](attack-classes/CODE-INJECTION.md) | Injecting and executing arbitrary code through SQL injection, command injection, or code generation | T-7002, T-9001 |
| [GATEWAY-EXPLOIT](attack-classes/GATEWAY-EXPLOIT.md) | Modifying gateway or proxy configurations to intercept, redirect, or manipulate agent traffic | T-6003 |
| [INTEGRITY-BYPASS](attack-classes/INTEGRITY-BYPASS.md) | Digest or hash verification bypass on empty or missing values: tampered artifacts pass silently | T-9001 |
| [LLM-EXPOSE](attack-classes/LLM-EXPOSE.md) | LLM inference endpoints exposed without authentication, allowing arbitrary prompt execution | T-1001, T-1004 |
| [MCP-EXPLOIT](attack-classes/MCP-EXPLOIT.md) | Attacking Model Context Protocol server configurations, tool registrations, and inter-server trust | T-1002, T-1005, T-4003, T-5003, T-5005, T-5006 |
| [PARSER-DIFFERENTIAL](attack-classes/PARSER-DIFFERENTIAL.md) | Exploits differences between parser implementations to bypass security controls | T-2009 |
| [RETROACTIVE-PRIV](attack-classes/RETROACTIVE-PRIV.md) | Exploiting previously granted access or cached credentials to gain unauthorized capabilities | T-1001, T-1004, T-1007, T-3001, T-3003, T-3005, T-3006, T-5004, T-8005 |
| [TOCTOU-RACE](attack-classes/TOCTOU-RACE.md) | Time-of-check-time-of-use race between verification and execution: swap window for attackers | T-9001 |

### NemoClaw-Specific (5 classes)
| Class | Description | Techniques |
|-------|-------------|------------|
| [NEMO-CRED-LEAK](attack-classes/NEMO-CRED-LEAK.md) | Unintended exposure of credentials through environment variables, logs, or error messages | T-3002, T-7005 |
| [NEMO-NETWORK-EXPOSE](attack-classes/NEMO-NETWORK-EXPOSE.md) | NemoClaw network services bound to public interfaces: gateway, k3s API, mDNS beacons | T-1001, T-1004, T-5001 |
| [NEMO-OPENCLAW-INHERIT](attack-classes/NEMO-OPENCLAW-INHERIT.md) | Inherited OpenClaw flaws that survive NemoClaw sandboxing: heartbeat persistence, pre-allowed APIs | T-1001 |
| [NEMO-SANDBOX-ESCAPE](attack-classes/NEMO-SANDBOX-ESCAPE.md) | Breaking out of agent sandbox restrictions to access the underlying file system or OS | T-7001 |
| [NEMO-SUPPLY-CHAIN](attack-classes/NEMO-SUPPLY-CHAIN.md) | Compromising upstream dependencies or infrastructure to affect downstream agent deployments | T-9006 |

### Identity (2 classes)
| Class | Description | Techniques |
|-------|-------------|------------|
| [AGENT-IMPERSONATE](attack-classes/AGENT-IMPERSONATE.md) | Impersonating trusted agents or administrative roles to gain unauthorized access | T-4002, T-4004 |
| [BEHAVIORAL-IMPERSONATE](attack-classes/BEHAVIORAL-IMPERSONATE.md) | Using stolen credentials detected via behavioral baseline mismatch: agent DNA forgery | T-4002 |

### Sandbox (1 class)
| Class | Description | Techniques |
|-------|-------------|------------|
| [SANDBOX-ESCAPE](attack-classes/SANDBOX-ESCAPE.md) | General sandbox escape via privileged containers, LSM degradation, or process environment leakage | T-7001 |

<!-- END GENERATED: attack-class-tables -->

---

## How to Use This Framework

### For Red Teams
Follow the kill chain stages sequentially. Use technique IDs to plan attack paths. Reference DVAA challenges for practice. The [Attack Paths](#attack-paths) section provides complete worked examples.

### For Blue Teams
Map your defenses against each tactic. Use OASB controls as a checklist. Any tactic without detection or prevention represents a gap. Focus on breaking the chain at the earliest stage.

### For Researchers
Cite techniques using their IDs (e.g., "ATM T-2001"). The catalog is extensible: contribute new techniques via pull request with evidence requirements.

### For Vendors
Map your product's detection capabilities to ATM technique IDs. This enables customers to understand which agent-specific threats your product covers.

---

## Attack Paths

Complete kill chain traversals demonstrated in DVAA:

**Path A (API Agent Full Compromise):**
T-1001 → T-2001 → T-3001 → T-5004 → T-7001 → T-8002
(LegacyBot → ToolBot: recon, inject, harvest creds, pivot, enumerate files, exfiltrate)

**Path B (Memory Persistence Chain):**
T-1001 → T-2001 → T-6001 → T-7004 → T-8005
(MemoryBot: recon, inject, persist in memory, dump memory, exfiltrate via conversation)

**Path C (Multi-Agent A2A Chain):**
T-1006 → T-2001 → T-4002 → T-5002 → T-9001
(Orchestrator → Worker → ToolBot: discover agent card, inject, impersonate admin, pivot via A2A, modify data)

**Path D (Supply Chain to Full Compromise):**
T-1002 → T-2005 → T-6004 → T-5003 → T-9006
(PluginBot → ProxyBot: discover tools, inject via tool description, backdoor skill, hop MCP servers, compromise downstream)

---

## Repository Structure

```
agent-threat-matrix/
├── README.md                 # This document
├── EVIDENCE_AUDIT.md         # Evidence tier justification for every technique
├── matrix.json               # Machine-readable matrix (full data)
├── technique-ids.json        # The technique id list, checked against matrix.json
├── schema/                   # JSON Schema for matrix.json and the consumer-readiness gate
├── stix/                     # STIX 2.1 bundle rendered from matrix.json
├── tactics/                  # One file per tactic (kill chain stage)
├── techniques/               # One file per technique (T-XXXX)
├── attack-classes/           # One file per attack class
├── cross-references/         # MITRE ATT&CK, ATLAS, OWASP LLM mappings
├── CONTRIBUTING.md           # How to propose new techniques
├── CHANGELOG.md
└── LICENSE                   # Apache-2.0
```

`canonical-classes.json` maps the canonical attack classes to the technique ids in `matrix.json`, and is validated by `scripts/check_canonical_classes.py`. Its `matrixVersion` and `matrixCommit` name the matrix version and the full 40-character sha of the commit whose `matrix.json` it maps; the check refuses a version other than the one in `matrix.json` and an abbreviated sha.

### Schema

`matrix.json` follows `schema/threat-matrix-v1.2.schema.json` (JSON Schema 2020-12). `scripts/validate_matrix.py` checks the file against that schema and the rules the schema cannot state (ids resolve, `replacedBy` and `parentId` present exactly when required, `technique-ids.json` in sync). `matrixCommit` in `technique-ids.json` is the 40-character sha of the commit whose `matrix.json` the id list indexes; the validator refuses a value of any other shape, and in a checkout that has the commit's history it also refuses a sha that names no commit or whose `matrix.json` carries different ids (a shallow checkout without that commit, a partial clone without that commit's tree or `matrix.json`, or a copy without git, gets the shape check only, and the validator's summary line says which check ran). Technique ids may take the form `T-NNNN.NNN` for a sub-technique, listed flat in `techniques` with a `parentId`; `schema/consumer-readiness.json` keeps dotted ids out of the file until the listed consumers accept them. `stix/agent-threat-matrix-bundle.json` is a STIX 2.1 rendering of the matrix produced by `scripts/generate_stix.py`, with deterministic object ids; the validator fails when the committed bundle differs from a fresh rendering. Every STIX object takes its `modified` date from `updated` in `matrix.json`, so when the file's content other than `updated` differs from the committed copy the validator also requires `updated` to be no earlier than the current date. Evidence tiers are defined in `docs/evidence-tiers.md`, and `scripts/check_evidence_tiers.py` checks that every page quoting a tier definition quotes it word for word.

---

## How to Cite

When referencing individual techniques:
> AI Agent Threat Matrix T-2001 (Direct Prompt Injection). OpenA2A, 2026. https://threats.opena2a.org/techniques/T-2001

When referencing the framework:
> OpenA2A. "AI Agent Threat Matrix v1.2." September 2026. https://threats.opena2a.org

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process. In summary:

1. Every new technique must meet one evidence tier: a real-world observation (Observed), a reproducible lab scenario (Validated), or an established traditional precedent (Adapted)
2. Assign the next available technique ID in the appropriate stage range
3. Include HMA detection check ID, DVAA validation (if applicable), and OASB control mapping
4. Submit as a pull request with evidence documentation

---

## License

Apache-2.0. The framework is free to use, cite, and build upon.

---

## Related Projects

| Project | Role |
|---------|------|
| [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | Automated detection for ATM techniques (318 static checks, 164 payloads) |
| [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Lab validation environment (21 agents, 12 vulnerability categories) |
| [OASB](https://oasb.ai) | Defensive benchmark (46 controls) |
| [AI Agent Kill Chain](https://github.com/opena2a-org/ai-agent-kill-chain) | Tactical framework (the 9-stage progression model) |

---

*Maintained by OpenA2A. Contributions welcome via pull request.*
