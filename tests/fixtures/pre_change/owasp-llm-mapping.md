# OWASP Top 10 for LLM Applications (2023) -- Agent Threat Matrix Mapping

This document maps the [OWASP Top 10 for LLM Applications (2023 edition)](https://owasp.org/www-project-top-10-for-large-language-model-applications/) to techniques in the AI Agent Threat Matrix (ATM). The purpose is not to suggest OWASP is incomplete -- it covers what it was designed to cover. The purpose is to show where OWASP's scope ends and the agent layer begins. A re-map to the 2025 edition, which reorganized the categories, is tracked as separate work.

OWASP LLM Top 10 focuses on **LLM application security** -- the model, its inputs, its outputs, and its immediate integration surface. The Agent Threat Matrix focuses on **agent infrastructure** -- governance files, multi-agent protocols, skill supply chains, memory systems, and sandbox boundaries. The two frameworks are complementary.

---

## Mapping Table

Each row shows an OWASP item, which ATM techniques it partially covers, and the nature of the overlap.

| OWASP LLM Item | ATM Techniques (Partial Overlap) | Overlap Notes |
|-----------------|----------------------------------|---------------|
| **LLM01** Prompt Injection | T-2001, T-2002, T-2003, T-2004, T-2006, T-2007, T-2008 | OWASP treats prompt injection as a single vulnerability class. ATM decomposes it into 7 distinct techniques with different attack vectors (direct, indirect, role-play, context window, Unicode encoding, multi-turn, boundary bypass). ATM also extends into agent-specific injection surfaces (governance files, tool descriptions, memory) that OWASP does not address. |
| **LLM02** Insecure Output Handling | T-7001, T-8005 | OWASP focuses on output sanitization failures (XSS, SSRF via generated content). ATM covers file system enumeration (T-7001) and conversation exfiltration (T-8005) as agent-specific output abuse vectors. |
| **LLM03** Training Data Poisoning | -- | Not in ATM scope. ATM covers the agent layer, not the model training pipeline. OWASP and MITRE ATLAS cover this. |
| **LLM04** Model Denial of Service | -- | Not in ATM scope. T-9002 (Service Disruption) addresses agent-level resource exhaustion but not model-level DoS. |
| **LLM05** Supply Chain Vulnerabilities | T-9006, T-6004, T-5003 | OWASP covers general LLM supply chain (model provenance, training data). ATM covers agent-specific supply chain: compromised skills/plugins (T-6004), MCP server hopping (T-5003), and upstream supply chain compromise (T-9006) including skill registries and npm packages. |
| **LLM06** Sensitive Information Disclosure | T-3001, T-3002, T-3003, T-3004, T-3005, T-3006, T-7004, T-7005, T-7006 | Strongest overlap. OWASP addresses information leakage generally. ATM decomposes agent-specific credential and data exposure across 9 techniques covering system prompts, environment variables, tool responses, memory stores, config files, context windows, memory dumps, configuration harvesting, and PII discovery. |
| **LLM07** Insecure Plugin Design | T-2005, T-4003, T-6004, T-6006 | OWASP covers plugin trust and input validation. ATM extends to tool description injection (T-2005), tool parameter injection (T-4003), skill backdoors (T-6004), and persistent malicious tool registration (T-6006) -- all specific to MCP/A2A tool ecosystems. |
| **LLM08** Excessive Agency | T-4001, T-4002, T-4004, T-9001, T-9003 | OWASP addresses over-permissioned agents. ATM covers specific escalation paths: capability override (T-4001), admin impersonation (T-4002), delegation abuse (T-4004), data manipulation (T-9001), and malicious code deployment (T-9003). |
| **LLM09** Overreliance | T-6001, T-6002 | Weak overlap. OWASP addresses user trust in LLM outputs. ATM covers memory injection (T-6001) and self-replicating memory entries (T-6002) -- poisoned memory that the agent itself over-relies on across sessions. |
| **LLM10** Model Theft | -- | Not in ATM scope. ATM covers the agent layer, not model weights or architecture. |

---

## ATM Techniques NOT Covered by Any OWASP LLM Item

These techniques address attack surfaces that exist only at the agent infrastructure layer. OWASP LLM Top 10 was not designed to cover them.

### Reconnaissance (Agent-Specific)

| ID | Technique | Why OWASP Doesn't Cover It |
|----|-----------|---------------------------|
| T-1004 | Security Level Probing | Agent-specific: probing behavioral constraint strength is unique to systems governed by natural language policies |
| T-1005 | Capability Mapping | Agent-specific: enumerating MCP tools/list and skill catalogs has no LLM-application equivalent |
| T-1006 | Agent Card Discovery | A2A protocol recon: discovering agent capabilities via /.well-known/agent.json is specific to multi-agent systems |
| T-1007 | Context Window Probing | Agent-specific: measuring token budget to plan context overflow attacks |

### Privilege Escalation (Agent-Specific)

| ID | Technique | Why OWASP Doesn't Cover It |
|----|-----------|---------------------------|
| T-4005 | Policy Bypass via Encoding | Unicode steganography used to bypass regex-based governance filters -- agent policy enforcement layer |
| T-4006 | Safety Instruction Displacement | Context overflow pushing safety instructions out of the active window -- agent memory architecture |

### Lateral Movement (Multi-Agent)

| ID | Technique | Why OWASP Doesn't Cover It |
|----|-----------|---------------------------|
| T-5001 | SSRF via Tool | Agent-initiated SSRF through tool invocation (fetch_url reaching internal endpoints) |
| T-5002 | A2A Agent Pivoting | Multi-agent lateral movement: compromised agent sends malicious tasks to peer agents via A2A protocol |
| T-5004 | Credential Reuse | Harvested agent credentials applied against adjacent services |
| T-5005 | Database Pivoting | SQL injection from agent context reaching database-level access |
| T-5006 | Internal API Discovery | Network scanning from agent process position |

### Persistence (Agent-Specific)

| ID | Technique | Why OWASP Doesn't Cover It |
|----|-----------|---------------------------|
| T-6001 | Memory Injection | Persistent instructions planted in agent memory surviving session restarts |
| T-6002 | Self-Replicating Memory Entry | Memory entries that re-inject themselves when recalled -- self-propagating persistence |
| T-6003 | Configuration Modification | Modifying agent gateway or runtime configuration for persistent access |
| T-6005 | Scheduled Task Injection | Heartbeat/cron persistence: injecting instructions into periodic callback mechanisms |

### Collection (Agent-Specific)

| ID | Technique | Why OWASP Doesn't Cover It |
|----|-----------|---------------------------|
| T-7002 | Database Extraction | Agent-initiated SQL injection for data collection |
| T-7003 | API Data Harvesting | Using agent's authenticated API access to harvest data from connected services |

### Exfiltration (Agent-Specific)

| ID | Technique | Why OWASP Doesn't Cover It |
|----|-----------|---------------------------|
| T-8001 | Email Exfiltration | Agent's email tool used for data exfiltration |
| T-8002 | HTTP Callback | Agent's fetch tool used for outbound data transfer |
| T-8003 | DNS Exfiltration | DNS-based exfiltration from agent process |
| T-8004 | Tool Chain Exfiltration | Chaining multiple tools (read_file + fetch_url) to bypass single-tool restrictions |
| T-8006 | Webhook Exfiltration | Pre-allowed messaging APIs (Telegram, Slack, Discord) used for exfiltration from sandboxed agents |

### Impact (Agent-Specific)

| ID | Technique | Why OWASP Doesn't Cover It |
|----|-----------|---------------------------|
| T-9002 | Service Disruption | Agent-level resource exhaustion and denial of service |
| T-9004 | Multi-Agent Consensus Manipulation | Poisoning voting/consensus mechanisms in multi-agent decision systems |
| T-9005 | Reputation Poisoning | Manipulating agent output history to damage trust scores |

### Attack Classes with No OWASP Equivalent

The following attack classes are entirely outside OWASP LLM scope:

| Attack Class | Description |
|-------------|-------------|
| SOUL-POISON | Malicious instructions injected into governance files (SOUL.md, CLAUDE.md) at write-time |
| SOUL-DRIFT | Multi-turn sequences gradually eroding behavioral boundaries over conversation turns |
| PHANTOM-SOUL | Agent deployed with zero behavioral constraints -- no governance file present |
| SOUL-FORK | Different agent behavior under evaluation vs production (split personality) |
| SOUL-HIJACK | External content achieving full governance override |
| SOUL-BOUNDARY | Exploiting ambiguous constraint definitions in natural language policies |
| SOUL-DELEGATE | Delegation without authorization chain verification |
| SOUL-IMPERSONATE | False capability claims beyond declared authorization |
| SOUL-HV | Harm avoidance override variants |
| MEM-POISON | Persistent instructions in agent memory surviving restarts |
| SKILL-MEM-AMP | Skill plants payload in memory, persists after skill uninstall |
| HEARTBEAT-RCE | Periodic instruction fetch via heartbeat URL persistence |
| NEMO-CRED-LEAK | Credential exposure in NemoClaw configuration |
| NEMO-NETWORK-EXPOSE | Network services bound to public interfaces |
| NEMO-SUPPLY-CHAIN | Supply chain integrity bypass in NemoClaw |
| NEMO-SANDBOX-ESCAPE | Sandbox isolation failure in NemoClaw |
| NEMO-OPENCLAW-INHERIT | Inherited OpenClaw flaws surviving sandboxing |
| AGENT-IMPERSONATE | False capability claims in A2A communications |
| BEHAVIORAL-IMPERSONATE | Stolen credentials detected via behavioral baseline mismatch |

---

## Summary

| Metric | Count |
|--------|-------|
| Total ATM techniques | 61 |
| Partially overlapping with OWASP LLM | ~25 |
| Not covered by any OWASP LLM item | ~36 |
| OWASP items with no ATM overlap (model-layer) | 3 (LLM03, LLM04, LLM10) |

The techniques outside OWASP scope represent the agent infrastructure layer: governance manipulation, multi-agent protocol exploitation, memory persistence, skill supply chain attacks, sandbox escapes, and agent identity abuse. These are the attack surfaces that emerge when an LLM is embedded in an autonomous agent system with tools, memory, and inter-agent communication.
