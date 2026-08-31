# MITRE ATLAS -- Agent Threat Matrix Mapping

This document maps [MITRE ATLAS](https://atlas.mitre.org/) (Adversarial Threat Landscape for AI Systems) tactics to AI Agent Threat Matrix (ATM) tactics. ATLAS covers the **ML system lifecycle** -- from data collection through model deployment. ATM covers the **agent infrastructure layer** -- from governance files through multi-agent communication. The two frameworks address different layers of the same stack.

---

## Tactic-Level Mapping

| ATLAS Tactic | ATM Tactic(s) | Overlap | Notes |
|-------------|---------------|---------|-------|
| **Reconnaissance** | Reconnaissance (Stage 1) | High | Both cover target enumeration. ATLAS focuses on ML model and data recon. ATM focuses on agent endpoint enumeration, tool discovery, governance file extraction, agent card discovery, and context window probing. |
| **Resource Development** | -- | None | ATLAS covers adversary infrastructure (acquiring compute, training shadow models). ATM does not model attacker-side resource acquisition. |
| **Initial Access** | Initial Access (Stage 2) | Medium | ATLAS covers ML supply chain compromise and data poisoning as access vectors. ATM covers prompt injection variants (7 techniques), tool description injection, and Unicode encoding bypass -- all agent-input-specific. |
| **ML Model Access** | -- | None | ATLAS covers white-box/black-box model access. ATM does not address model-level access -- it begins at the agent layer above the model. |
| **Execution** | Privilege Escalation (Stage 4) | Low | ATLAS covers adversarial ML execution (trigger activation, backdoor inference). ATM covers capability override, admin impersonation, tool parameter injection, and delegation abuse -- all agent-runtime escalation. |
| **Persistence** | Persistence (Stage 6) | Medium | ATLAS covers ML model poisoning persistence (backdoors in model weights). ATM covers agent-layer persistence: memory injection, self-replicating memory, config modification, skill backdoors, scheduled task injection, and tool registration persistence. |
| **Evasion** | Initial Access (Stage 2), Privilege Escalation (Stage 4) | Low | ATLAS covers adversarial example evasion and model interpretability attacks. ATM covers evasion via Unicode steganography (T-2006, T-4005), context window exploitation (T-2004, T-4006), and multi-turn gradual manipulation (T-2007). |
| **Discovery** | Reconnaissance (Stage 1), Collection (Stage 7) | Medium | Both cover target environment mapping. ATLAS focuses on ML pipeline discovery. ATM focuses on agent tool catalogs, capability mapping, and API/database/file system enumeration. |
| **Collection** | Credential Harvest (Stage 3), Collection (Stage 7) | Medium | Both cover data gathering. ATLAS focuses on training data and model artifacts. ATM focuses on credentials in system prompts, environment variables, tool responses, memory stores, configuration files, and PII in agent context. |
| **Exfiltration** | Exfiltration (Stage 8) | Medium | Both cover data transfer. ATLAS focuses on model exfiltration (model extraction attacks). ATM focuses on agent-specific exfiltration channels: email tools, HTTP callbacks, tool chains, conversation responses, and pre-allowed webhook APIs. |
| **Impact** | Impact (Stage 9) | Medium | Both cover adversary objectives. ATLAS covers model degradation and denial of ML service. ATM covers data manipulation, service disruption, malicious code deployment, multi-agent consensus manipulation, reputation poisoning, and supply chain compromise. |

---

## What ATLAS Covers That ATM Does Not

These are model-layer and ML-pipeline concerns outside the agent infrastructure scope.

| ATLAS Area | Description | Why ATM Excludes It |
|-----------|-------------|---------------------|
| Adversarial Examples | Crafted inputs that cause misclassification | Model inference layer, not agent infrastructure |
| Model Extraction | Querying a model to reconstruct its weights/architecture | Model IP theft, not agent behavior |
| Training Data Poisoning | Corrupting training datasets to insert backdoors | Model training pipeline, not agent runtime |
| Model Backdoors | Trojans embedded in model weights | Model layer -- agents use models but don't control their weights |
| Data Poisoning | Manipulating datasets used for training or fine-tuning | Training pipeline, not agent operational layer |
| Model Inversion | Extracting training data from model outputs | Model privacy, not agent infrastructure |
| Resource Development | Adversary acquiring ML compute, shadow models, infrastructure | Attacker-side preparation, outside agent defensive scope |
| ML Supply Chain | Compromised model registries, poisoned pre-trained models | Model distribution -- ATM covers agent-level supply chain (skills, plugins, MCP servers) instead |

---

## What ATM Covers That ATLAS Does Not

These are agent-infrastructure attack surfaces that emerge when an ML model is embedded in an autonomous agent system.

### Governance Attacks (10 attack classes, no ATLAS equivalent)

| ATM Coverage | Description |
|-------------|-------------|
| SOUL-POISON | Malicious instructions injected into governance files (SOUL.md, CLAUDE.md) at write-time |
| SOUL-DRIFT | Multi-turn sequences gradually eroding behavioral boundaries |
| SOUL-INJECT | Conflicting instructions via tool outputs or indirect channels |
| PHANTOM-SOUL | Agent deployed with zero behavioral constraints |
| SOUL-FORK | Different behavior under evaluation vs production |
| SOUL-HIJACK | External content achieving governance override |
| SOUL-BOUNDARY | Exploiting ambiguous constraint definitions |
| SOUL-DELEGATE | Delegation without authorization chain verification |
| SOUL-IMPERSONATE | False capability claims beyond authorization |
| SOUL-HV | Harm avoidance override variants |

ATLAS has no concept of "governance files" because traditional ML systems do not use natural language behavioral constraints. This entire attack class is unique to LLM-based agents.

### Agent Memory Attacks (no ATLAS equivalent)

| ATM Technique | Description |
|--------------|-------------|
| T-6001 Memory Injection | Persistent instructions planted in agent memory surviving session restarts |
| T-6002 Self-Replicating Memory Entry | Memory entries that re-inject themselves when recalled |
| T-3004 Memory Credential Mining | Extracting credentials from agent memory stores |
| T-7004 Memory Dump | Enumerating all entries in agent memory |

ATLAS covers training data poisoning but not runtime memory manipulation. Agent memory is a distinct persistence and collection surface.

### Multi-Agent Protocol Attacks (no ATLAS equivalent)

| ATM Technique | Description |
|--------------|-------------|
| T-1006 Agent Card Discovery | Discovering agent capabilities via A2A protocol (/.well-known/agent.json) |
| T-5002 A2A Agent Pivoting | Lateral movement from compromised agent to peer agents via A2A protocol |
| T-9004 Multi-Agent Consensus Manipulation | Poisoning voting/consensus mechanisms in multi-agent decision systems |
| T-4004 Delegation Abuse | Exploiting agent-to-agent delegation without authorization chain verification |

ATLAS does not model multi-agent systems. A2A protocol exploitation, agent identity attacks, and cross-agent lateral movement are outside its scope.

### Skill/Plugin Supply Chain (agent-specific)

| ATM Technique | Description |
|--------------|-------------|
| T-2005 Tool Description Injection | Malicious instructions in MCP tool descriptions |
| T-6004 Skill/Plugin Backdoor | Backdoor installed via compromised skill package |
| T-6006 Tool Registration Persistence | Malicious tool registered in agent's tool catalog |
| T-5003 MCP Server Hopping | Pivoting between MCP servers in a tool chain |

ATLAS covers ML model supply chain. ATM covers agent skill/plugin supply chain -- a different layer with different attack vectors (YAML frontmatter injection, MCP tool registration, skill marketplace poisoning).

### Sandbox and Runtime Exploitation (agent-specific)

| ATM Coverage | Description |
|-------------|-------------|
| NEMO-SANDBOX-ESCAPE | Docker privileged mode, Landlock LSM degradation |
| NEMO-OPENCLAW-INHERIT | Inherited platform flaws surviving sandboxing |
| NEMO-NETWORK-EXPOSE | Network services bound to public interfaces |
| NEMO-CRED-LEAK | Credential exposure in agent runtime configuration |

ATLAS does not cover agent sandbox boundaries or runtime configuration security. These are infrastructure concerns specific to deployed agent systems.

### Agent-Specific Exfiltration Channels

| ATM Technique | Description |
|--------------|-------------|
| T-8004 Tool Chain Exfiltration | Chaining read_file + fetch_url to bypass single-tool restrictions |
| T-8005 Conversation Exfiltration | Data extracted through conversation responses to the requesting user |
| T-8006 Webhook Exfiltration | Pre-allowed messaging APIs (Telegram, Slack) used from within sandboxed agents |

ATLAS models data exfiltration at the ML pipeline level (stealing training data, extracting model weights). ATM models exfiltration through agent-specific channels that exist because agents have tool access and conversation interfaces.

### Unicode Steganography (agent-specific application)

| ATM Technique | Description |
|--------------|-------------|
| T-2006 Unicode/Encoding Bypass | Invisible Unicode characters encoding instructions in source code or tool outputs |
| T-4005 Policy Bypass via Encoding | Unicode steganography bypassing regex-based governance policy filters |

Confirmed in the wild (os-info-checker npm attack, May 2025). ATLAS does not cover encoding-based attacks against natural language policy enforcement.

---

## Summary

| Metric | Count |
|--------|-------|
| ATM techniques with partial ATLAS overlap | ~20 |
| ATM techniques with no ATLAS equivalent | ~37 |
| ATLAS areas with no ATM equivalent | 8 (all model-layer) |

The two frameworks are complementary. ATLAS covers model security from training through inference. ATM covers agent security from governance through multi-agent communication. An organization deploying AI agents needs both: ATLAS for the model layer and ATM for the agent layer built on top of it.
