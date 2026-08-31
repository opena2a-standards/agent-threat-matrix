# OWASP Top 10 for LLM Applications (2023) -- Agent Threat Matrix Mapping

This document maps the [OWASP Top 10 for LLM Applications (2023 edition)](https://owasp.org/www-project-top-10-for-large-language-model-applications/) to techniques in the AI Agent Threat Matrix (ATM). Each row is an analyst reading that names, for one OWASP item, the ATM techniques this repository draws a correspondence to. It is a statement about this repository's mapping, not about OWASP's scope; OWASP publishes its own scope. A re-map to the 2025 edition is tracked as separate work.

OWASP LLM Top 10 describes itself as addressing **LLM application security** -- the model, its inputs, its outputs, and its immediate integration surface. The Agent Threat Matrix addresses **agent infrastructure** -- governance files, multi-agent protocols, skill supply chains, memory systems, and sandbox boundaries. The two readings are complementary.

---

## Mapping Table

Each row shows an OWASP item, the ATM techniques this reading names against it, and the nature of the overlap.

| OWASP LLM Item | ATM Techniques (Partial Overlap) | Overlap Notes |
|-----------------|----------------------------------|---------------|
| **LLM01** Prompt Injection | T-1003, T-2001, T-2002, T-2003, T-2004, T-2006, T-2007, T-2008 | OWASP treats prompt injection as a single vulnerability class. ATM separates it by vector and by objective -- direct, indirect, role-play, context window, Unicode encoding, multi-turn and boundary bypass as vectors, and system prompt extraction as the reconnaissance objective LLM01's fifth scenario describes -- and it also names agent-specific injection surfaces: governance files, tool descriptions, and memory. T-1003 System Prompt Extraction is named here because LLM01's own description defines direct prompt injection as a user who "overwrites or reveals the underlying system prompt", and its fifth example scenario is an attacker asking a model to repeat its system prompt in order to construct further attacks -- ATM places that act in the reconnaissance stage, where the recovered prompt is the map of the tool set, delegation rules and governance boundaries the later stages target. |
| **LLM02** Insecure Output Handling | T-7001, T-8005 | LLM02 addresses output sanitization failures (XSS, SSRF via generated content). ATM names file system enumeration (T-7001) and conversation exfiltration (T-8005) as agent-specific output abuse vectors. |
| **LLM03** Training Data Poisoning | -- | Not named in this mapping. ATM addresses the agent layer, not the model training pipeline. |
| **LLM04** Model Denial of Service | -- | Not named in this mapping. T-9002 (Service Disruption) addresses agent-level resource exhaustion, distinct from model-level denial of service. |
| **LLM05** Supply Chain Vulnerabilities | T-9006, T-6004, T-6006, T-5003 | LLM05 addresses the general LLM supply chain (model provenance, training data). ATM names agent-specific supply chain: compromised skills/plugins (T-6004), MCP server hopping (T-5003), and upstream supply chain compromise (T-9006) including skill registries and npm packages. T-6006 Tool Registration Persistence is named here rather than against LLM07, because LLM07 states that it "focuses on creating LLM plugins rather than third-party plugins, which LLM-Supply-Chain-Vulnerabilities cover", and LLM05's eighth mitigation names monitoring for "use of unauthorized plugins" -- the overlap is an attacker-supplied tool entering the agent's tool set, and what LLM05 does not reach is that tool surviving in the registry across sessions, which is the property T-6006 is named for. |
| **LLM06** Sensitive Information Disclosure | T-3001, T-3002, T-3003, T-3004, T-3005, T-3006, T-7004, T-7005, T-7006 | Strongest overlap. ATM names agent-specific credential and data exposure techniques for system prompts, environment variables, tool responses, memory stores, config files, context windows, memory dumps, configuration harvesting, and PII discovery. |
| **LLM07** Insecure Plugin Design | T-2005, T-4003, T-6004 | LLM07 addresses plugin trust and input validation. ATM names tool description injection (T-2005), tool parameter injection (T-4003), and skill backdoors (T-6004) -- all specific to MCP/A2A tool ecosystems. |
| **LLM08** Excessive Agency | T-4001, T-4002, T-4004, T-9001, T-9003 | LLM08 addresses over-permissioned agents. ATM names specific escalation paths: capability override (T-4001), admin impersonation (T-4002), delegation abuse (T-4004), data manipulation (T-9001), and malicious code deployment (T-9003). |
| **LLM09** Overreliance | -- | No technique named. LLM09's published description is about erroneous or hallucinated model output that people or downstream systems trust. This reading names no ATM technique against it: T-6001 and T-6002 turn on attacker-planted entries persisting in a runtime memory store, which is a different object, and they are listed in the technique overlap index instead. |
| **LLM10** Model Theft | -- | Not named in this mapping. ATM addresses the agent layer, not model weights or architecture. |

---

## ATM techniques not named in the mapping table above

These techniques address attack surfaces at the agent infrastructure layer. Each row records the agent-layer property it depends on.

### Reconnaissance (Agent-Specific)

| ID | Technique | Agent-layer property it depends on |
|----|-----------|------------------------------------|
| T-1004 | Security Level Probing | Probing behavioral constraint strength is unique to systems governed by natural language policies |
| T-1005 | Capability Mapping | Enumerating MCP tools/list and skill catalogs depends on a tool protocol an agent has |
| T-1006 | Agent Card Discovery | Discovering agent capabilities via /.well-known/agent.json is specific to multi-agent systems |
| T-1007 | Context Window Probing | Measuring token budget to plan context overflow attacks is an agent memory-architecture property |

### Privilege Escalation (Agent-Specific)

| ID | Technique | Agent-layer property it depends on |
|----|-----------|------------------------------------|
| T-4005 | Policy Bypass via Encoding | Unicode steganography used to bypass regex-based governance filters -- agent policy enforcement layer |
| T-4006 | Safety Instruction Displacement | Context overflow pushing safety instructions out of the active window -- agent memory architecture |

### Lateral Movement (Multi-Agent)

| ID | Technique | Agent-layer property it depends on |
|----|-----------|------------------------------------|
| T-5001 | SSRF via Tool | Agent-initiated SSRF through tool invocation (fetch_url reaching internal endpoints) |
| T-5002 | A2A Agent Pivoting | Multi-agent lateral movement: compromised agent sends malicious tasks to peer agents via A2A protocol |
| T-5004 | Credential Reuse | Harvested agent credentials applied against adjacent services |
| T-5005 | Database Pivoting | SQL injection from agent context reaching database-level access |
| T-5006 | Internal API Discovery | Network scanning from agent process position |

### Persistence (Agent-Specific)

| ID | Technique | Agent-layer property it depends on |
|----|-----------|------------------------------------|
| T-6001 | Memory Injection | Persistent instructions planted in agent memory surviving session restarts |
| T-6002 | Self-Replicating Memory Entry | Memory entries that re-inject themselves when recalled -- self-propagating persistence |
| T-6003 | Configuration Modification | Modifying agent gateway or runtime configuration for persistent access |
| T-6005 | Scheduled Task Injection | Heartbeat/cron persistence: injecting instructions into periodic callback mechanisms |

### Collection (Agent-Specific)

| ID | Technique | Agent-layer property it depends on |
|----|-----------|------------------------------------|
| T-7002 | Database Extraction | Agent-initiated SQL injection for data collection |
| T-7003 | API Data Harvesting | Using agent's authenticated API access to harvest data from connected services |

### Exfiltration (Agent-Specific)

| ID | Technique | Agent-layer property it depends on |
|----|-----------|------------------------------------|
| T-8001 | Email Exfiltration | Agent's email tool used for data exfiltration |
| T-8002 | HTTP Callback | Agent's fetch tool used for outbound data transfer |
| T-8003 | DNS Exfiltration | DNS-based exfiltration from agent process |
| T-8004 | Tool Chain Exfiltration | Chaining multiple tools (read_file + fetch_url) to bypass single-tool restrictions |
| T-8006 | Webhook Exfiltration | Pre-allowed messaging APIs (Telegram, Slack, Discord) used for exfiltration from sandboxed agents |

### Impact (Agent-Specific)

| ID | Technique | Agent-layer property it depends on |
|----|-----------|------------------------------------|
| T-9002 | Service Disruption | Agent-level resource exhaustion and denial of service |
| T-9004 | Multi-Agent Consensus Manipulation | Poisoning voting/consensus mechanisms in multi-agent decision systems |
| T-9005 | Reputation Poisoning | Manipulating agent output history to damage trust scores |

### Attack classes not named against any OWASP item

The following attack classes are not named against any OWASP LLM item in this reading:

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

Each OWASP item's row above lists the ATM techniques this reading names against it. The counts -- how many techniques the mapping table names, and how many it does not -- are rendered from `matrix.json` in the [technique overlap index](technique-overlap-index.md) and are not restated here. The OWASP items with no technique named against them in this reading are LLM03, LLM04, LLM09 and LLM10.

The techniques not named above sit at the agent-infrastructure layer: governance manipulation, multi-agent protocol exploitation, memory persistence, skill supply chain attacks, sandbox escapes, and agent identity abuse. These are the attack surfaces that emerge when an LLM is embedded in an autonomous agent system with tools, memory, and inter-agent communication.
