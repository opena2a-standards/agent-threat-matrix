# Technique overlap index

This index records which Agent Threat Matrix techniques the mapping documents in this
directory name against an external framework, and which they do not.

The mappings are an analyst reading of two published frameworks -- the OWASP Top 10 for
LLM Applications and MITRE ATLAS -- against `matrix.json`. They describe where the
documents in this directory draw a correspondence. No entry states what OWASP or MITRE
ATLAS does or does not address; each publishes its own scope.

Direction is one way, from an ATM technique to an external framework item. Nothing here
is a reading of an external framework against ATM.

---

## Method and limits

`matrix.json` is canonical for what the Agent Threat Matrix contains. Nothing in this
repository is canonical for what an external framework contains, so every correspondence
below is an analyst reading, not a measurement.

Two consequences, stated so they are not inferred:

- A technique listed below as having no counterpart named means only that no mapping
  document in this directory names one. It does not mean that no counterpart exists.
- No combined figure across the two mapping documents is published.
  `owasp-llm-mapping.md` names technique ids; `mitre-atlas-mapping.md` maps ATLAS tactics
  to ATM tactics and names no technique ids in its mapping table. A combined figure would
  add a reading taken at technique level to one taken at tactic level, and would not mean
  anything.

Rendered by `scripts/check_cross_references.py` from `matrix.json` and the mapping
documents. Do not edit the block below by hand.

<!-- BEGIN GENERATED: overlap-counts -->
`matrix.json` version 1.1 holds 61 techniques. The mapping table in
`owasp-llm-mapping.md` names 30 of them and does not name 31. `mitre-atlas-mapping.md`
maps ATLAS tactics to ATM tactics and names no technique in its mapping table.
<!-- END GENERATED: overlap-counts -->

Read against `matrix.json` version 1.1 (updated 2026-06-03) and the OWASP Top 10 for LLM
Applications (2023 edition) on 2026-08-31. A re-map to the 2025 edition is tracked
separately.

---

## Techniques with no counterpart named in either mapping

These techniques sit at the agent infrastructure layer, between the model layer ATLAS addresses and the application layer OWASP addresses. They arise from properties unique to AI agent systems: governance files, persistent memory, tool ecosystems, multi-agent protocols, and sandbox boundaries. Each row records the agent-layer property the technique depends on -- the thing an agent has that a bare LLM application does not.

### Reconnaissance

| ID | Technique | Description | Agent-layer property it depends on |
|----|-----------|-------------|------------------------------------|
| T-1001 | Endpoint Enumeration | Discover exposed API endpoints, health checks, and information disclosure routes on target agents | The agent's deployed control surface. Agent runtimes ship default health, info and discovery routes -- the DVAA validation for this technique is that all of its agents expose /health and /info -- so the route set is readable before any prompt is sent, and it is the input every other reconnaissance technique starts from. The enumeration itself is a traditional web technique applied to that surface, in the same sense as T-8003. |
| T-1002 | Tool Discovery | Enumerate available tools and their schemas via MCP tools/list or equivalent discovery endpoints | The agent's tool registry. MCP answers a tools/list call with every registered tool and its schema, so an agent's capability set is self-describing and readable without invoking a tool -- a request that only exists where a tool protocol does. Same surface as T-1005 at a finer grain: T-1002 is the protocol call, T-1005 is the capability picture built from it. |
| T-1004 | Security Level Probing | Probe an agent's behavioral constraint strength through calibrated test inputs | The agent's governance layer. Calibrated probes measure the strength of an agent's natural-language behavioral constraints, a property only a governed agent has. |
| T-1005 | Capability Mapping | Enumerate an agent's full tool catalog via MCP tools/list or equivalent | The agent's tool catalog. An agent exposes its full tool set through MCP tools/list or a skill catalog, so the capability picture is enumerable at once -- the coarse-grained view T-1002 feeds. |
| T-1006 | Agent Card Discovery | Discover agent capabilities via A2A protocol (/.well-known/agent.json) | The agent's A2A identity surface. An agent advertises its declared role and skills at /.well-known/agent.json, readable over the A2A protocol before any interaction. |
| T-1007 | Context Window Probing | Measure an agent's token budget to plan context overflow attacks | The agent's memory architecture. The token budget is an agent-specific constraint, and measuring it plans a context-overflow attack. |

### Initial Access

| ID | Technique | Description | Agent-layer property it depends on |
|----|-----------|-------------|------------------------------------|
| T-2009 | Parser Differential Exploitation | Exploit differences in how parsers (JSON, YAML, markdown) interpret the same input | The agent's multi-parser input path. The attack targets disagreement between parsers over the same bytes, not the prompt text. Flagged for review in a 2025 OWASP re-map. |

### Privilege Escalation

| ID | Technique | Description | Agent-layer property it depends on |
|----|-----------|-------------|------------------------------------|
| T-4005 | Policy Bypass via Encoding | Use Unicode steganography to bypass regex-based governance filters | The agent's governance filter. Unicode steganography slips instructions past a regex-based natural-language policy filter, a control that exists only in a governed agent. |
| T-4006 | Safety Instruction Displacement | Push safety instructions out of active context window via token flooding | The agent's memory architecture. Token flooding pushes safety instructions out of the active context window; context-window management is agent-specific. |
| T-4007 | Tool Impersonation and Squatting | Impersonate, shadow, or squat on legitimate MCP tools to intercept agent actions | The agent's tool registry. Impersonating, shadowing or squatting on a tool's identity depends on a registry an agent has. Flagged for review in a 2025 OWASP re-map. |

### Lateral Movement

| ID | Technique | Description | Agent-layer property it depends on |
|----|-----------|-------------|------------------------------------|
| T-5001 | SSRF via Tool | Agent-initiated SSRF through tool invocation (fetch_url to internal endpoints) | The agent's tool-issued network requests. The agent itself issues the outbound request through a fetch-style tool, reaching internal endpoints from its runtime network position. |
| T-5002 | A2A Agent Pivoting | Compromised agent sends malicious task requests to peer agents via A2A protocol | The agent's A2A peer connections. A compromised agent sends malicious task requests to peer agents over the A2A protocol, a path that exists only between agents. |
| T-5004 | Credential Reuse | Apply harvested agent credentials against adjacent services | The agent's credential scope. An agent holds tool-granted credentials for several services at once, so harvested credentials reuse across the adjacent services it can already reach. |
| T-5005 | Database Pivoting | SQL injection from agent context reaching database-level access | The agent's SQL tool. The tool is itself the access path from agent context to database-level access. |
| T-5006 | Internal API Discovery | Network scanning from agent process position | The agent's runtime network position. The agent process provides a pivot point from which internal APIs are scanned. |

### Persistence

| ID | Technique | Description | Agent-layer property it depends on |
|----|-----------|-------------|------------------------------------|
| T-6001 | Memory Injection | Plant persistent instructions in agent memory surviving session restarts | The agent's persistent memory store. An attacker-planted entry survives session restarts and re-enters context when the agent recalls it. |
| T-6002 | Self-Replicating Memory Entry | Memory entry that re-injects itself when recalled by the agent | The agent's persistent memory store. The entry instructs the agent to re-inject it when recalled, so removal alone does not clear it. |
| T-6003 | Configuration Modification | Modify agent gateway or runtime configuration for persistent access | The agent's gateway and runtime configuration. Modifying it holds access across restarts. |
| T-6005 | Scheduled Task Injection | Inject instructions into heartbeat or periodic callback mechanisms | The agent's heartbeat. Instructions injected into the periodic callback mechanism run on each beat; the OpenClaw/NemoClaw heartbeat is agent-specific. |
| T-6007 | Persistent Agent State Manipulation | Persist across sessions via memory poisoning, state tampering, and cached-context injection | The agent's cross-session state. Memory poisoning, state tampering and cached-context injection combine to persist across sessions. |

### Collection

| ID | Technique | Description | Agent-layer property it depends on |
|----|-----------|-------------|------------------------------------|
| T-7002 | Database Extraction | Agent-initiated SQL injection for data collection | The agent's authorized database access. Agent-initiated SQL injection turns that access into a collection vector. |
| T-7003 | API Data Harvesting | Use agent's authenticated API access to harvest data from connected services | The agent's authenticated API access. An agent holds credentials for multiple connected services simultaneously and harvests from each. |
| T-7007 | Context Assembly Pipeline Attack | Target the system-prompt assembly pipeline where components combine into an exploitable prompt | The agent's prompt-assembly pipeline. Components combine into the final context, and tampering with a component poisons the assembled prompt. |

### Exfiltration

| ID | Technique | Description | Agent-layer property it depends on |
|----|-----------|-------------|------------------------------------|
| T-8001 | Email Exfiltration | Agent's email tool used for outbound data transfer | The agent's email tool. Its authorized send capability becomes an outbound channel. |
| T-8002 | HTTP Callback | Agent's fetch tool used for outbound data transfer to attacker endpoint | The agent's fetch tool. Tool invocations carry no egress filtering, so the fetch becomes an outbound channel. |
| T-8003 | DNS Exfiltration | DNS-based exfiltration from agent process | Adapted from traditional environments. Included for completeness. |
| T-8004 | Tool Chain Exfiltration | Chain read_file + fetch_url to bypass single-tool restrictions | The agent's tool chain. Combining read_file and fetch_url creates an exfil path that single-tool reviews miss. |
| T-8006 | Webhook Exfiltration | Pre-allowed messaging APIs (Telegram, Slack, Discord) used from sandboxed agents | The agent's sandbox allow-list. Pre-allowed messaging APIs open exfiltration channels from within containment. |

### Impact

| ID | Technique | Description | Agent-layer property it depends on |
|----|-----------|-------------|------------------------------------|
| T-9002 | Service Disruption | Agent-level resource exhaustion and denial of service | The agent's own resources. Context flooding and tool abuse exhaust them, distinct from model-level denial of service. |
| T-9004 | Multi-Agent Consensus Manipulation | Poison voting or consensus mechanisms in multi-agent decision systems | The agent's consensus mechanism. Poisoning the voting mechanism in a multi-agent decision system steers the outcome. |
| T-9005 | Reputation Poisoning | Manipulate agent output history to damage trust scores or reliability metrics | The agent's identity and trust record. Manipulating its output history damages the trust scores and reliability metrics attached to it. |

---

## Attack classes

Attack classes are listed in [matrix.json](../matrix.json) and in the repository README.
The mapping documents in this directory name the classes each framework's items relate
to. This index does not repeat those lists.

---

## Where the layers meet

Each framework states the layer it addresses. This table restates those published scopes and where the Agent Threat Matrix sits relative to them:

| Layer | Framework | What It Models |
|-------|-----------|---------------|
| Model | MITRE ATLAS | Training data, model weights, inference attacks, ML supply chain |
| Application | OWASP LLM Top 10 | Prompt injection, output handling, plugin trust, information disclosure |
| **Agent** | **Agent Threat Matrix** | **Governance files, tool ecosystems, multi-agent protocols, agent memory, sandbox boundaries, agent identity** |
| Infrastructure | MITRE ATT&CK | Network, endpoint, cloud, enterprise IT |

AI agents sit between the application layer and the infrastructure layer. They inherit model-level vulnerabilities from below and expose new attack surfaces above: governance manipulation, memory persistence, multi-agent lateral movement, skill supply chain attacks, and sandbox escapes. These surfaces exist because agents make autonomous decisions, hold persistent state, communicate with other agents, and invoke tools with real-world effects.

The Agent Threat Matrix addresses the agent layer: governance files, tool ecosystems,
multi-agent protocols, agent memory, sandbox boundaries, and agent identity. Which
techniques the mapping documents in this directory name against an external framework is
listed above.

---

## Detailed Mapping References

- [owasp-llm-mapping.md](owasp-llm-mapping.md) -- Full OWASP LLM Top 10 technique-by-technique mapping
- [mitre-atlas-mapping.md](mitre-atlas-mapping.md) -- Full MITRE ATLAS tactic-by-tactic mapping
