# Gap Analysis: What Existing Frameworks Do Not Cover

This document identifies the techniques in the AI Agent Threat Matrix (ATM) that are not adequately covered by either the [OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/) or [MITRE ATLAS](https://atlas.mitre.org/). This is not a criticism of those frameworks -- they were designed for different layers. This analysis shows why a dedicated agent-layer threat model is necessary.

---

## Coverage Summary

This page compares against the OWASP Top 10 for LLM Applications (2023 edition);
a re-map to the 2025 edition is tracked separately.

| Metric | Value |
|--------|-------|
| Total ATM techniques | 61 |
| Partially covered by OWASP LLM Top 10 | ~25 |
| Partially covered by MITRE ATLAS | ~20 |
| Partially covered by at least one framework | ~30 |
| **Not covered by either OWASP or ATLAS** | **~31** |

"Partially covered" means the existing framework addresses the general vulnerability class but not the agent-specific attack vector, detection method, or kill chain context that ATM provides.

---

## Techniques Not Covered by Either Framework

These techniques exist at the agent infrastructure layer -- between the model (ATLAS) and the application input/output (OWASP). They arise from properties unique to AI agent systems: governance files, persistent memory, tool ecosystems, multi-agent protocols, and sandbox boundaries.

### Reconnaissance

| ID | Technique | Description | Why It Falls in the Gap |
|----|-----------|-------------|------------------------|
| T-1004 | Security Level Probing | Probe an agent's behavioral constraint strength through calibrated test inputs | Governance-layer recon. Traditional frameworks do not model natural language policy enforcement. |
| T-1005 | Capability Mapping | Enumerate an agent's full tool catalog via MCP tools/list or equivalent | Agent tool ecosystem recon. No equivalent in OWASP (no plugin enumeration) or ATLAS (no tool protocol). |
| T-1006 | Agent Card Discovery | Discover agent capabilities via A2A protocol (/.well-known/agent.json) | Multi-agent protocol recon. A2A is a new protocol surface neither framework addresses. |
| T-1007 | Context Window Probing | Measure an agent's token budget to plan context overflow attacks | Agent memory architecture recon. Context windows are an agent-specific constraint. |

### Initial Access

| ID | Technique | Description | Why It Falls in the Gap |
|----|-----------|-------------|------------------------|
| T-2009 | Parser Differential Exploitation | Exploit differences in how parsers (JSON, YAML, markdown) interpret the same input | Adjacent to OWASP LLM01 (prompt injection) but distinct: the attack targets parser disagreement, not the prompt. Flagged for review in a 2025 OWASP re-map. |

### Privilege Escalation

| ID | Technique | Description | Why It Falls in the Gap |
|----|-----------|-------------|------------------------|
| T-4005 | Policy Bypass via Encoding | Use Unicode steganography to bypass regex-based governance filters | Governance enforcement bypass. Neither framework models natural language policy filters. |
| T-4006 | Safety Instruction Displacement | Push safety instructions out of active context window via token flooding | Agent memory architecture attack. Context window management is agent-specific. |
| T-4007 | Tool Impersonation and Squatting | Impersonate, shadow, or squat on legitimate MCP tools to intercept agent actions | Adjacent to OWASP LLM07 (insecure plugin design) but distinct: MCP tool identity and squatting are an agent tool-ecosystem surface. Flagged for review in a 2025 OWASP re-map. |

### Lateral Movement

| ID | Technique | Description | Why It Falls in the Gap |
|----|-----------|-------------|------------------------|
| T-5001 | SSRF via Tool | Agent-initiated SSRF through tool invocation (fetch_url to internal endpoints) | Agent tool abuse. OWASP LLM02 covers output handling but not agent-initiated network requests via tools. |
| T-5002 | A2A Agent Pivoting | Compromised agent sends malicious task requests to peer agents via A2A protocol | Multi-agent lateral movement. No equivalent in any existing framework. |
| T-5004 | Credential Reuse | Apply harvested agent credentials against adjacent services | Agent credential scope. Traditional credential reuse exists in ATT&CK but not in the agent context with tool-granted credentials. |
| T-5005 | Database Pivoting | SQL injection from agent context reaching database-level access | Agent-to-database pivot. The agent's SQL tool creates an access path that doesn't exist in standard LLM applications. |
| T-5006 | Internal API Discovery | Network scanning from agent process position | Agent process as pivot point. The agent's runtime environment provides a network position. |

### Persistence

| ID | Technique | Description | Why It Falls in the Gap |
|----|-----------|-------------|------------------------|
| T-6001 | Memory Injection | Plant persistent instructions in agent memory surviving session restarts | Agent memory as persistence surface. ATLAS covers model backdoors, not runtime memory poisoning. |
| T-6002 | Self-Replicating Memory Entry | Memory entry that re-injects itself when recalled by the agent | Self-propagating agent memory persistence. No equivalent anywhere. |
| T-6003 | Configuration Modification | Modify agent gateway or runtime configuration for persistent access | Agent infrastructure persistence. Traditional config modification exists in ATT&CK but not for agent gateways. |
| T-6005 | Scheduled Task Injection | Inject instructions into heartbeat or periodic callback mechanisms | Agent heartbeat persistence. OpenClaw/NemoClaw heartbeat mechanism is agent-specific. |
| T-6006 | Tool Registration Persistence | Register malicious tool in agent's tool catalog that persists across sessions | Agent tool ecosystem persistence. No equivalent in OWASP or ATLAS. |
| T-6007 | Persistent Agent State Manipulation | Persist across sessions via memory poisoning, state tampering, and cached-context injection | Cross-session agent state persistence. Neither framework has a persistence concept for agent memory or cached context. |

### Collection

| ID | Technique | Description | Why It Falls in the Gap |
|----|-----------|-------------|------------------------|
| T-7002 | Database Extraction | Agent-initiated SQL injection for data collection | Agent SQL tool abuse. The agent's authorized database access creates a unique collection vector. |
| T-7003 | API Data Harvesting | Use agent's authenticated API access to harvest data from connected services | Agent API scope abuse. Agents hold credentials for multiple services simultaneously. |
| T-7004 | Memory Dump | Enumerate all entries in agent memory store | Agent memory as collection target. No equivalent in OWASP or ATLAS. |
| T-7007 | Context Assembly Pipeline Attack | Target the system-prompt assembly pipeline where components combine into an exploitable prompt | Agent prompt-assembly surface. Neither framework models the component pipeline that builds an agent's context. |

### Exfiltration

| ID | Technique | Description | Why It Falls in the Gap |
|----|-----------|-------------|------------------------|
| T-8001 | Email Exfiltration | Agent's email tool used for outbound data transfer | Agent tool as exfiltration channel. The agent's authorized email capability becomes an exfil vector. |
| T-8002 | HTTP Callback | Agent's fetch tool used for outbound data transfer to attacker endpoint | Agent tool as exfiltration channel. No egress filtering on agent tool invocations. |
| T-8003 | DNS Exfiltration | DNS-based exfiltration from agent process | Adapted from traditional environments. Included for completeness. |
| T-8004 | Tool Chain Exfiltration | Chain read_file + fetch_url to bypass single-tool restrictions | Multi-tool abuse. The combination of tools creates exfil paths that individual tool reviews miss. |
| T-8006 | Webhook Exfiltration | Pre-allowed messaging APIs (Telegram, Slack, Discord) used from sandboxed agents | Sandbox policy bypass. Pre-allowed API lists create exfiltration channels from within containment. |

### Impact

| ID | Technique | Description | Why It Falls in the Gap |
|----|-----------|-------------|------------------------|
| T-9002 | Service Disruption | Agent-level resource exhaustion and denial of service | Agent-specific DoS (context flooding, tool abuse). OWASP LLM04 covers model DoS, not agent DoS. |
| T-9004 | Multi-Agent Consensus Manipulation | Poison voting or consensus mechanisms in multi-agent decision systems | Multi-agent coordination attack. No existing framework models multi-agent governance. |
| T-9005 | Reputation Poisoning | Manipulate agent output history to damage trust scores or reliability metrics | Agent identity and trust attack. No equivalent in OWASP or ATLAS. |

---

## Attack Classes with No External Framework Equivalent

Beyond individual techniques, entire attack classes in the ATM have no mapping to OWASP or ATLAS.

### Governance Attack Classes (10)

| Class | Description |
|-------|-------------|
| SOUL-POISON | Injecting malicious instructions into governance files at write-time |
| SOUL-DRIFT | Gradual erosion of behavioral boundaries over conversation turns |
| SOUL-INJECT | Conflicting instructions delivered via tool outputs or indirect channels |
| PHANTOM-SOUL | Agent deployed with no governance file -- zero behavioral constraints |
| SOUL-FORK | Different behavior under evaluation vs production conditions |
| SOUL-HIJACK | External content achieving full governance override |
| SOUL-BOUNDARY | Exploiting ambiguous constraint definitions in natural language policies |
| SOUL-DELEGATE | Delegation chains without authorization verification |
| SOUL-IMPERSONATE | False capability claims beyond declared authorization |
| SOUL-HV | Harm avoidance override variants |

None of these have equivalents in OWASP or ATLAS because neither framework models natural language behavioral constraints.

### NemoClaw Attack Classes (5)

| Class | Description |
|-------|-------------|
| NEMO-CRED-LEAK | Credential exposure in agent runtime configuration |
| NEMO-NETWORK-EXPOSE | Network services bound to public interfaces |
| NEMO-SUPPLY-CHAIN | Supply chain integrity bypass in agent deployment |
| NEMO-SANDBOX-ESCAPE | Sandbox isolation failure in agent runtime |
| NEMO-OPENCLAW-INHERIT | Inherited platform flaws surviving sandboxing |

These are specific to observed agent deployment infrastructure. ATLAS covers ML pipeline security but not agent runtime infrastructure.

### Memory and Identity Attack Classes

| Class | Description |
|-------|-------------|
| MEM-POISON | Persistent instructions in agent memory surviving restarts |
| SKILL-MEM-AMP | Skill plants payload in memory that persists after skill uninstall |
| HEARTBEAT-RCE | Periodic instruction fetch via heartbeat URL persistence |
| AGENT-IMPERSONATE | False capability claims in A2A communications |
| BEHAVIORAL-IMPERSONATE | Stolen credentials detected via behavioral baseline mismatch |

Agent memory, skill lifecycle attacks, and agent identity are surfaces that do not exist in traditional ML systems.

---

## Why This Framework Exists

The gap is structural, not an oversight. OWASP and MITRE ATLAS were designed for their respective layers:

| Layer | Framework | What It Models |
|-------|-----------|---------------|
| Model | MITRE ATLAS | Training data, model weights, inference attacks, ML supply chain |
| Application | OWASP LLM Top 10 | Prompt injection, output handling, plugin trust, information disclosure |
| **Agent** | **Agent Threat Matrix** | **Governance files, tool ecosystems, multi-agent protocols, agent memory, sandbox boundaries, agent identity** |
| Infrastructure | MITRE ATT&CK | Network, endpoint, cloud, enterprise IT |

AI agents sit between the application layer and the infrastructure layer. They inherit model-level vulnerabilities from below and expose new attack surfaces above: governance manipulation, memory persistence, multi-agent lateral movement, skill supply chain attacks, and sandbox escapes. These surfaces exist because agents make autonomous decisions, hold persistent state, communicate with other agents, and invoke tools with real-world effects.

No existing framework was designed to model this layer. The 27 uncovered techniques and 20 uncovered attack classes represent the security gap that the AI Agent Threat Matrix addresses.

---

## Detailed Mapping References

- [owasp-llm-mapping.md](owasp-llm-mapping.md) -- Full OWASP LLM Top 10 technique-by-technique mapping
- [mitre-atlas-mapping.md](mitre-atlas-mapping.md) -- Full MITRE ATLAS tactic-by-tactic mapping
