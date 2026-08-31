# AI Agent Threat Matrix

A structured framework for classifying, detecting, and defending against attacks on AI agent systems.

**Version 1.1** | June 2026 | [Threats Matrix](https://threats.opena2a.org) | [OpenA2A](https://opena2a.org)

---

## Purpose

AI agents operate differently from traditional software. They make decisions based on natural language, delegate actions to tools with varying trust levels, communicate with other agents via open protocols, and maintain persistent memory that can be poisoned. These properties create attack surfaces that existing frameworks do not adequately model.

The **AI Agent Threat Matrix** classifies attacks against AI agent systems into 9 tactics and 61 techniques, organized by kill chain stage. Every technique carries an explicit evidence tier: observed in the wild, validated in a controlled lab environment, or adapted from a traditional environment and marked as such. Every technique maps to automated detection and a defensive control; 60 of the 61 also carry a reproducible lab scenario.

### What This Covers (and What It Doesn't)

This matrix covers the **agent layer** — the infrastructure between the model and the user:

- Governance file manipulation (SOUL.md, system prompts, behavioral constraints)
- Skill and plugin supply chain attacks
- MCP and A2A protocol exploitation
- Agent memory poisoning and persistence
- Credential exposure through agent infrastructure
- Sandbox escape via framework defaults
- Cross-agent lateral movement and identity attacks

This matrix does **not** cover:

- Model-level attacks (adversarial examples, training data poisoning) — see [MITRE ATLAS](https://atlas.mitre.org/)
- Prompt injection as a standalone topic — see [OWASP Top 10 for LLM](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- Traditional enterprise network attacks — see [MITRE ATT&CK](https://attack.mitre.org/)

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

Every technique in this matrix is assigned an evidence tier:

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
| [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | Automated detection (310 static checks, 164 attack payloads) |
| [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Lab validation (21 vulnerable agents, 12 vulnerability categories) |
| [OASB](https://oasb.ai) | Defensive controls (46 controls across 10 domains) |
| MITRE ATT&CK / ATLAS / OWASP LLM | An index of which techniques this repository's mapping documents name against each framework, and which they do not |

See [cross-references/](cross-references/) for detailed mapping documents.

---

## Attack Classes (40)

Attack classes group related techniques by the underlying vulnerability pattern:

### Governance (11 classes)
| Class | Description | Techniques |
|-------|-------------|------------|
| SOUL-POISON | Malicious instructions injected into governance files at write-time | T-2001, T-2003, T-2007, T-2008 |
| SOUL-DRIFT | Multi-turn sequences gradually eroding behavioral boundaries | T-2004, T-4006 |
| SOUL-INJECT | Conflicting instructions via tool outputs or indirect channels | T-1003, T-2001, T-2003, T-2007, T-2008 |
| PHANTOM-SOUL | Agent deployed with zero behavioral constraints | T-1006 |
| SOUL-FORK | Different behavior under evaluation vs production | T-5002 |
| SOUL-HIJACK | External content achieving constitution override | T-4002, T-5002 |
| SOUL-BOUNDARY | Exploiting ambiguous constraint definitions | T-2008 |
| SOUL-DELEGATE | Delegation without authorization chain verification | T-4001 |
| SOUL-IMPERSONATE | False capability claims beyond authorization | T-4002 |
| SOUL-HV | Harm avoidance override variants (4 sub-types) | T-2001, T-2003 |
| ASSEMBLY-INJECT | Targeting the system-prompt assembly pipeline where components combine into exploitable injections | T-7007 |

### Supply Chain (11 classes)
| Class | Description | Real-World Evidence |
|-------|-------------|-------------------|
| UNICODE-STEGO | Invisible Unicode encoding instructions in source code | os-info-checker npm attack (May 2025) |
| MEM-POISON | Persistent instructions in agent memory surviving restarts | DVAA L2-04, L3-03 |
| SKILL-MEM-AMP | Skill plants payload in memory, survives uninstall | DVAA validated |
| RAG-POISON | Malicious content in vector databases retrieved by RAG pipeline | Academic research, DVAA RAGBot |
| HEARTBEAT-RCE | Periodic instruction fetch via heartbeat URL persistence | OpenClaw heartbeat mechanism, NemoClaw H-007 |
| SKILL-FRONTMATTER | YAML metadata injection bypassing content filters | DVAA PluginBot |
| SKILL-EXFIL | Skill exfiltrates data outside declared tool boundaries | DVAA tool chain scenarios |
| ORG-SKILL-SPREAD | Compromised admin skill propagates organization-wide | ClawHavoc campaign patterns |
| SUPPLY-CHAIN-INSTALL | Unsigned installation scripts executed without integrity verification — curl\|sh without checksum | — |
| FAKETOOL-INJECT | MCP tool impersonation, squatting, and schema poisoning attacks | — |
| PERSIST-STATE | Cross-session persistence via memory poisoning, state tampering, and cached context injection | — |

### Infrastructure (10 classes)
| Class | Description | Real-World Evidence |
|-------|-------------|-------------------|
| GATEWAY-EXPLOIT | Misconfigured API gateways exposing agent infrastructure | ~75K OpenClaw gateways unauthenticated |
| MCP-EXPLOIT | MCP server config, tool permissions, transport security | DVAA MCP agents, MCP protocol analysis |
| RETROACTIVE-PRIV | Existing credentials silently gaining AI permissions | 32 API keys in HTTP responses (Jan 2026) |
| LLM-EXPOSE | LLM inference endpoints exposed without authentication | ~56K Ollama instances (Mar 2026) |
| AITOOL-EXPOSE | AI development tools exposed (Jupyter, MLflow, Gradio) | ~8.3K Jupyter, ~740 MLflow (Mar 2026) |
| CODE-INJECTION | Command injection via unsanitized inputs | NemoClaw C-001, C-002 |
| INTEGRITY-BYPASS | Digest/hash bypass on empty or missing values | NemoClaw C-005 |
| TOCTOU-RACE | Time-of-check-time-of-use race in verification pipelines | NemoClaw C-006 |
| A2A-EXPOSE | Agent-to-Agent protocol endpoints publicly discoverable without access control | — |
| PARSER-DIFFERENTIAL | Exploits differences between parser implementations to bypass security controls | — |

### NemoClaw-Specific (5 classes)
| Class | Description | Evidence |
|-------|-------------|----------|
| NEMO-CRED-LEAK | Credential exposure in NemoClaw configuration | C-004 (CLI args), H-004 (env passthrough) |
| NEMO-NETWORK-EXPOSE | Network services bound to public interfaces | C-004 (gateway), C-005 (k3s) |
| NEMO-SUPPLY-CHAIN | Supply chain integrity bypass | C-003 (curl\|sh), C-005 (digest bypass) |
| NEMO-SANDBOX-ESCAPE | Sandbox isolation failure | H-001 (Docker privileged), H-004 (Landlock) |
| NEMO-OPENCLAW-INHERIT | Inherited OpenClaw flaws surviving sandboxing | H-007 (Telegram pre-allowed) |

### Identity (2 classes)
| Class | Description |
|-------|-------------|
| AGENT-IMPERSONATE | False capability claims in A2A communications |
| BEHAVIORAL-IMPERSONATE | Stolen credentials detected via behavioral baseline mismatch |

### Sandbox (1 class)
| Class | Description |
|-------|-------------|
| SANDBOX-ESCAPE | General sandbox escape via privileged containers or LSM degradation |

---

## How to Use This Framework

### For Red Teams
Follow the kill chain stages sequentially. Use technique IDs to plan attack paths. Reference DVAA challenges for practice. The [Attack Paths](#attack-paths) section provides complete worked examples.

### For Blue Teams
Map your defenses against each tactic. Use OASB controls as a checklist. Any tactic without detection or prevention represents a gap. Focus on breaking the chain at the earliest stage.

### For Researchers
Cite techniques using their IDs (e.g., "ATM T-2001"). The catalog is extensible — contribute new techniques via pull request with evidence requirements.

### For Vendors
Map your product's detection capabilities to ATM technique IDs. This enables customers to understand which agent-specific threats your product covers.

---

## Attack Paths

Complete kill chain traversals demonstrated in DVAA:

**Path A — API Agent Full Compromise:**
T-1001 → T-2001 → T-3001 → T-5004 → T-7001 → T-8002
(LegacyBot → ToolBot: recon, inject, harvest creds, pivot, enumerate files, exfiltrate)

**Path B — Memory Persistence Chain:**
T-1001 → T-2001 → T-6001 → T-7004 → T-8005
(MemoryBot: recon, inject, persist in memory, dump memory, exfiltrate via conversation)

**Path C — Multi-Agent A2A Chain:**
T-1006 → T-2001 → T-4002 → T-5002 → T-9001
(Orchestrator → Worker → ToolBot: discover agent card, inject, impersonate admin, pivot via A2A, modify data)

**Path D — Supply Chain to Full Compromise:**
T-1002 → T-2005 → T-6004 → T-5003 → T-9006
(PluginBot → ProxyBot: discover tools, inject via tool description, backdoor skill, hop MCP servers, compromise downstream)

---

## Repository Structure

```
agent-threat-matrix/
├── README.md                 # This document
├── EVIDENCE_AUDIT.md         # Evidence tier justification for every technique
├── matrix.json               # Machine-readable matrix (full data)
├── tactics/                  # One file per tactic (kill chain stage)
├── techniques/               # One file per technique (T-XXXX)
├── attack-classes/           # One file per attack class
├── cross-references/         # MITRE ATT&CK, ATLAS, OWASP LLM mappings
├── CONTRIBUTING.md           # How to propose new techniques
├── CHANGELOG.md
└── LICENSE                   # Apache-2.0
```

`canonical-classes.json` maps the canonical attack classes to the technique ids in `matrix.json`, and is validated by `scripts/check_canonical_classes.py`.

---

## How to Cite

When referencing individual techniques:
> AI Agent Threat Matrix T-2001 (Direct Prompt Injection). OpenA2A, 2026. https://threats.opena2a.org/techniques/T-2001

When referencing the framework:
> OpenA2A. "AI Agent Threat Matrix v1.1." June 2026. https://threats.opena2a.org

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process. In summary:

1. Every new technique must have either a real-world observation or a reproducible lab scenario
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
| [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | Automated detection for ATM techniques (310 static checks, 164 payloads) |
| [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Lab validation environment (21 agents, 12 vulnerability categories) |
| [OASB](https://oasb.ai) | Defensive benchmark (46 controls) |
| [AI Agent Kill Chain](https://github.com/opena2a-org/ai-agent-kill-chain) | Tactical framework (the 9-stage progression model) |

---

*Maintained by OpenA2A. Contributions welcome via pull request.*
