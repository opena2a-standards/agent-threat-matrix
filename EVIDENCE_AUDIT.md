# Evidence Audit: Every Technique Against MITRE's Standard

MITRE ATT&CK requires every technique to be grounded in observed adversary behavior.
We apply three evidence tiers:

- **OBSERVED**: Confirmed in real-world production systems (NemoClaw findings, exposure sweeps, npm attacks)
- **VALIDATED**: Reproducible in controlled lab environment (DVAA challenges, HMA scan results)
- **THEORETICAL**: Plausible but no real-world observation or lab reproduction yet

MITRE publishes THEORETICAL techniques only when the attack vector is well-understood
and the technique fills a gap in the matrix. We should be more conservative: publish
OBSERVED and VALIDATED only. Flag THEORETICAL for future research.

---

## Stage 1: Reconnaissance (7 Techniques)

| ID | Technique | Evidence Tier | Justification |
|----|-----------|--------------|---------------|
| T-1001 | Endpoint Enumeration | OBSERVED | Exposure sweeps confirmed ~140K services responding to standard probes. Google/Amazon/UChicago confirmed. |
| T-1002 | Tool Discovery | VALIDATED | DVAA ToolBot (3010) responds to tools/list. MCP protocol spec defines this endpoint. |
| T-1003 | System Prompt Extraction | VALIDATED | DVAA Challenge L1-01. Also: 1,190 CLAUDE.md files found exposed in January 2026 sweep. Borderline OBSERVED. |
| T-1004 | Security Level Probing | VALIDATED | Standard security testing technique. DVAA agents respond with varying security levels. |
| T-1005 | Capability Mapping | VALIDATED | DVAA ToolBot exposes full tool catalog. MCP tools/list is a protocol feature. |
| T-1006 | Agent Card Discovery | OBSERVED | First A2A agent cards found in the wild during March 2026 sweep. ClawGrid marketplace. |
| T-1007 | Context Window Probing | VALIDATED | DVAA LongwindBot (3008) demonstrates context overflow. |

**Verdict: 2 OBSERVED, 5 VALIDATED, 0 THEORETICAL. All publishable.**

---

## Stage 2: Initial Access (8 Techniques)

| ID | Technique | Evidence Tier | Justification |
|----|-----------|--------------|---------------|
| T-2001 | Direct Prompt Injection | OBSERVED | Extensively documented across all LLM deployments. DVAA L1-03. Academic papers (Greshake et al. 2023). |
| T-2002 | Indirect Prompt Injection | OBSERVED | Greshake et al. 2023. RAG poisoning demonstrated in multiple production systems. |
| T-2003 | Role-Play Jailbreak | OBSERVED | "DAN" jailbreaks widely documented. DVAA L2-01. |
| T-2004 | Context Window Exploitation | VALIDATED | DVAA L2-06. Academic research on attention dilution. |
| T-2005 | Tool Description Injection | VALIDATED | DVAA PluginBot (3012). Skill frontmatter injection demonstrated in DVAA. |
| T-2006 | Unicode/Encoding Bypass | OBSERVED | os-info-checker npm attack (May 2025) — real supply chain attack using Unicode steganography. |
| T-2007 | Multi-Turn Manipulation | VALIDATED | DVAA multi-turn challenges. Academic research on gradual jailbreaking. |
| T-2008 | System Prompt Boundary Bypass | VALIDATED | DVAA L3-04. Boundary confusion between system and user messages. |
| T-2009 | Parser Differential Exploitation | VALIDATED | DVAA parser-differential-json scenario; PARSE-001..010 HMA checks exist. VALIDATED. |

**Verdict: 4 OBSERVED, 5 VALIDATED, 0 THEORETICAL. All publishable.**

---

## Stage 3: Credential Harvest (6 Techniques)

| ID | Technique | Evidence Tier | Justification |
|----|-----------|--------------|---------------|
| T-3001 | System Prompt Credential Extraction | OBSERVED | 32 API keys found in HTTP responses (Jan 2026 sweep). DVAA L1-02. NemoClaw C-004. |
| T-3002 | Environment Variable Leakage | OBSERVED | NemoClaw H-004 (process.env passthrough). DVAA agents leak env vars. |
| T-3003 | Tool Response Credential Capture | VALIDATED | DVAA ToolBot returns credentials in tool responses. |
| T-3004 | Memory Credential Mining | VALIDATED | DVAA L2-05 (MemoryBot recalls credentials from prior sessions). |
| T-3005 | Configuration File Access | OBSERVED | OpenClaw config.get returns Discord/Slack/Telegram tokens. 199 .env directory listings (Mar 2026). |
| T-3006 | Context Window Credential Leak | VALIDATED | DVAA LegacyBot has credentials in system prompt with no isolation. |

**Verdict: 3 OBSERVED, 3 VALIDATED, 0 THEORETICAL. All publishable.**

---

## Stage 4: Privilege Escalation (6 Techniques)

| ID | Technique | Evidence Tier | Justification |
|----|-----------|--------------|---------------|
| T-4001 | Capability Override | VALIDATED | DVAA CodeBot executes shell commands when prompted with authority language. |
| T-4002 | Admin Impersonation | VALIDATED | DVAA L4-01 (SecureBot admin bypass). |
| T-4003 | Tool Parameter Injection | VALIDATED | MCP tool calls with injected parameters. Standard MCP protocol behavior. |
| T-4004 | Delegation Abuse | VALIDATED | DVAA delegation-privilege-escalation scenario. |
| T-4005 | Policy Bypass via Encoding | VALIDATED | Extension of T-2006 (Unicode bypass). Demonstrated against regex-based filters. |
| T-4006 | Safety Instruction Displacement | VALIDATED | Extension of T-2004 (context overflow). DVAA L2-07. |
| T-4007 | Tool Impersonation and Squatting | VALIDATED | DVAA fake-tool-squatting scenario; FAKETOOL-001..010 HMA checks exist. VALIDATED. |

**Verdict: 0 OBSERVED, 7 VALIDATED, 0 THEORETICAL. All publishable (lab-proven).**

---

## Stage 5: Lateral Movement (6 Techniques)

| ID | Technique | Evidence Tier | Justification |
|----|-----------|--------------|---------------|
| T-5001 | SSRF via Tool | VALIDATED | DVAA L3-02 (ToolBot fetch_url reaches 169.254.169.254). Classic SSRF adapted to agent context. |
| T-5002 | A2A Agent Pivoting | VALIDATED | DVAA L4-02 (Orchestrator → Worker chain). |
| T-5003 | MCP Server Hopping | VALIDATED | DVAA tool-chain-exfiltration scenario. MCP server enumeration. |
| T-5004 | Credential Reuse | OBSERVED | Standard technique. Harvested credentials from T-3001/T-3005 used against adjacent services. |
| T-5005 | Database Pivoting | VALIDATED | DVAA DataBot SQL injection enables database-level pivoting. |
| T-5006 | Internal API Discovery | VALIDATED | Network scanning from agent position. Standard lateral movement technique. |

**Verdict: 1 OBSERVED, 5 VALIDATED, 0 THEORETICAL. All publishable.**

---

## Stage 6: Persistence (6 Techniques)

| ID | Technique | Evidence Tier | Justification |
|----|-----------|--------------|---------------|
| T-6001 | Memory Injection | VALIDATED | DVAA L2-04 (MemoryBot persistent injection). |
| T-6002 | Self-Replicating Memory Entry | VALIDATED | DVAA L3-03. Memory entry that re-injects itself when recalled. |
| T-6003 | Configuration Modification | OBSERVED | OpenClaw gateway configs modifiable without auth (~75K exposed). NemoClaw config files world-readable. |
| T-6004 | Skill/Plugin Backdoor | VALIDATED | DVAA skill-backdoor-install scenario. |
| T-6005 | Scheduled Task Injection | OBSERVED | OpenClaw heartbeat mechanism confirmed (RQ-OC-001 investigation — local fs only, not remote, but persistence mechanism exists). NemoClaw H-007. |
| T-6006 | Tool Registration Persistence | VALIDATED | DVAA L2-08 (PluginBot malicious tool registration). |
| T-6007 | Persistent Agent State Manipulation | VALIDATED | DVAA persistent-agent-memory-poison scenario; PERSIST-001..010 HMA checks exist. VALIDATED. |

**Verdict: 2 OBSERVED, 5 VALIDATED, 0 THEORETICAL. All publishable.**

---

## Stage 7: Collection (6 Techniques)

| ID | Technique | Evidence Tier | Justification |
|----|-----------|--------------|---------------|
| T-7001 | File System Enumeration | VALIDATED | DVAA ToolBot path traversal (../../etc/passwd). |
| T-7002 | Database Extraction | VALIDATED | DVAA DataBot SQL injection. |
| T-7003 | API Data Harvesting | VALIDATED | DVAA agents use authenticated API access for data collection. |
| T-7004 | Memory Dump | VALIDATED | DVAA MemoryBot memory enumeration. |
| T-7005 | Configuration Harvesting | OBSERVED | OpenClaw config.get returns full config including tokens. NemoClaw world-readable config files. |
| T-7006 | PII Discovery | VALIDATED | DVAA LegacyBot leaks PII (SSN data). |
| T-7007 | Context Assembly Pipeline Attack | VALIDATED | DVAA context-lifecycle-split-injection / displacement / priority-hijack scenarios; LIFECYCLE-001..010 HMA checks exist. VALIDATED. |

**Verdict: 1 OBSERVED, 6 VALIDATED, 0 THEORETICAL. All publishable.**

---

## Stage 8: Exfiltration (6 Techniques)

| ID | Technique | Evidence Tier | Justification |
|----|-----------|--------------|---------------|
| T-8001 | Email Exfiltration | VALIDATED | DVAA ToolBot send_email tool with no recipient validation. |
| T-8002 | HTTP Callback | VALIDATED | DVAA ToolBot fetch_url to external endpoint with no egress filtering. |
| T-8003 | DNS Exfiltration | THEORETICAL | Plausible but not demonstrated in DVAA or observed in the wild for AI agents specifically. Standard technique from traditional environments. |
| T-8004 | Tool Chain Exfiltration | VALIDATED | DVAA L3-06 (read_file + fetch_url chain). |
| T-8005 | Conversation Exfiltration | VALIDATED | All DVAA agents — data extracted via conversation responses. |
| T-8006 | Webhook Exfiltration | OBSERVED | NemoClaw H-007 (Telegram Bot API pre-allowed in sandbox policy). OpenClaw pre-allows messaging APIs. |

**Verdict: 1 OBSERVED, 4 VALIDATED, 1 THEORETICAL.**

**T-8003 (DNS Exfiltration) is the only THEORETICAL technique.** It's a well-understood traditional technique adapted to agent context. Decision: include but mark as "adapted from traditional environments — not yet observed in AI agent-specific deployments." MITRE includes adapted techniques when the attack vector is clear.

---

## Stage 9: Impact (6 Techniques)

| ID | Technique | Evidence Tier | Justification |
|----|-----------|--------------|---------------|
| T-9001 | Data Manipulation | VALIDATED | DVAA ToolBot write_file and DataBot SQL injection. NemoClaw C-005 (digest bypass enables blueprint tampering). |
| T-9002 | Service Disruption | VALIDATED | Resource exhaustion via context flooding. Standard DoS techniques applied to agents. |
| T-9003 | Malicious Code Deployment | OBSERVED | NemoClaw C-003 (curl|sh without checksum). Supply chain attacks deploying backdoors. |
| T-9004 | Multi-Agent Consensus Manipulation | THEORETICAL | Plausible in multi-agent voting systems but not observed. DVAA consensus-manipulation scenario exists but is synthetic. |
| T-9005 | Reputation Poisoning | THEORETICAL | Plausible output manipulation but not observed in production AI agent context specifically. |
| T-9006 | Supply Chain Compromise | OBSERVED | os-info-checker npm attack (May 2025). ClawHavoc campaign. NemoClaw C-003, C-005, C-006. |

**Verdict: 2 OBSERVED, 2 VALIDATED, 2 THEORETICAL.**

**T-9004 (Multi-Agent Consensus Manipulation) and T-9005 (Reputation Poisoning) are THEORETICAL.** Both are plausible but lack specific evidence in AI agent deployments. Decision: include with "adapted/projected" label, or hold for a future version when evidence exists.

---

## Summary

| Evidence Tier | Count | Percentage |
|--------------|-------|------------|
| OBSERVED (real-world) | 16 | 26% |
| VALIDATED (lab-proven) | 42 | 69% |
| THEORETICAL | 3 | 5% |
| **Total** | **61** | **100%** |

### Decisions

**Publish all 61 techniques.** 95% are OBSERVED or VALIDATED. The 3 THEORETICAL techniques (T-8003, T-9004, T-9005) are well-understood traditional techniques adapted to agent context. MITRE ATT&CK includes adapted techniques when the attack vector is clear.

**Mark evidence tier on each technique page.** This is transparency that MITRE doesn't even do (they mix observed and theoretical without explicit labeling). Our evidence labeling is a differentiator.

### Attack Classes Audit

All 40 attack classes contain at least one OBSERVED or VALIDATED technique. No attack class is purely theoretical. The NemoClaw-specific classes (5 classes) are all backed by the 10 confirmed code-level vulnerabilities.

### Gaps Identified

1. **No real-world observation of multi-agent consensus attacks.** T-9004 should be marked as projected.
2. **DNS exfiltration for AI agents** (T-8003) is inherited from traditional environments. No agent-specific twist documented.
3. **Reputation poisoning** (T-9005) is generic — could be more specific to agent-generated content.

### What MITRE Would Push Back On

1. "Are your VALIDATED findings just penetration test results against your own deliberately vulnerable system?" Response: Yes, but DVAA is purpose-built with documented vulnerability patterns. Each DVAA agent targets a specific attack class. The validation proves the technique works, not that it's been used by real adversaries.

2. "Your technique IDs don't follow MITRE's format." Response: Intentional. T-XYYY (where X = stage) vs MITRE's TXXXX (sequential). Our format encodes the kill chain stage in the ID, which is more useful for practitioners.

3. "61 techniques across 9 stages is dense for an early release." Response: MITRE ATT&CK v1 (2015) had ~100 techniques. Our 61 is reasonable for a domain-specific matrix. The agent attack surface is genuinely this broad.

4. "Some techniques overlap across stages." Response: Acknowledged. T-2004 (Context Window Exploitation) and T-4006 (Safety Instruction Displacement) are related but occur at different kill chain stages with different attacker goals. MITRE has similar overlaps (T1059 Command and Scripting Interpreter appears in Execution but enables techniques in many other tactics).

---

## Honeypot-Derived Evidence: What It Proves and What It Does Not

The AgentPwn honeypot fleet contributes live evidence to the published Attack Prevalence
Index at [threats.opena2a.org](https://threats.opena2a.org). These are real events from the
open internet, not lab reproductions. They are also not per-technique incident counts, and
the gap between those two statements is what this section exists to state.

**What the telemetry is.** A trap page publishes an injection carrying a canary URL. When a
client fetches that URL, the honeypot records the fetch and resolves the canary token back to
the payload it was embedded in. Figures below come from
`GET /api/v1/intelligence/attack-prevalence`. That endpoint reports a **rolling 30-day
window**, so every absolute count here is a snapshot that moves daily as fires age out —
quote the endpoint, not this page, for a current number. Snapshot of 2026-07-28: roughly
7,300 evidence records across roughly 7,100 distinct fires.

**How it is attributed.** Attribution is payload-level. A canary token is a deterministic
hash of `(salt, category, tier, date)`, so it resolves to exactly one `(category, tier)`,
which resolves to exactly one payload and one technique. One fire produces one evidence row.
The 1:1 property is enforced by a unique index on the `(category, tier)` join key, not merely
observed to hold — a duplicate mapping would fan a single fire across several techniques,
which is the failure mode the constraint exists to prevent.

This replaced an earlier site-level scheme in which `agentpwn.com` was mapped to five
technique classes and every qualifying interaction wrote one row per mapped technique. Under
that scheme 7,125 interactions became 35,625 rows and all five techniques reported an
identical 7,125 — one population counted five ways. Two things distinguish the current
scheme, and both are stable properties rather than snapshot figures: the row-to-fire ratio is
about **1.03**, not 5.00, and the per-technique counts are **differentiated** rather than
identical. On the 2026-07-28 snapshot the leaders were T-2007 805, T-2001 762, T-2003 615,
T-2006 501, T-4007 422, T-6004 407, T-2004 328, T-8002 315, across 26 techniques.

**What a fire does not prove.** A canary fetch records that a client followed an embedded
link. It is not, by itself, proof that an *agent* obeyed an *injection*:

- **Client type is not currently gated.** The evidence rows are written without filtering on
  the client classification, even though that classification is captured and stored
  (`llm_agent`, `llm_crawler`, `browser`, `scanner`, `http_client`, `sdk_client`, `unknown`,
  each at `verified` or `claimed` confidence). A crawler indexing a trap page and an agent
  obeying its injection both land in the count. The current mix is unmeasured and should not
  be assumed.
- **Confidence is asymmetric.** `verified` means the source IP fell inside an LLM provider's
  published egress range, which the caller cannot forge. `claimed` means the User-Agent said
  so, which it can. Only the former should carry weight.
- **Tokens can be replayed.** A canary URL is public once fetched, so a count is a
  directional prevalence signal, not a tamper-proof tally.
- **Recovered history has a hard ceiling.** Fires predating the client-classification columns
  can be retro-classified only from the stored User-Agent, at `claimed` confidence. The raw
  IP is deliberately never retained, so `verified` classification is permanently unavailable
  for those rows.

**Why no evidence tier was upgraded on this basis.** T-2004 (Context Window Exploitation) and
T-8002 (HTTP Callback) remain VALIDATED rather than OBSERVED. Payload-level attribution
removed the original objection — a count is no longer one population counted five ways — but
OBSERVED means the specific behaviour was confirmed in a real-world system, and an ungated
fetch count cannot separate an agent that obeyed an injection from a crawler that followed a
link. Promoting a tier on volume alone would reproduce the old error in a subtler form.

What each technique still needs is different:

- **T-8002 (HTTP Callback)** is the nearer case. A fetch by a client verifiably inside a
  provider's egress range *is* an outbound callback to an attacker-designated URL. Once the
  evidence is gated on a verified agent classification, the surviving count supports OBSERVED
  on its merits rather than on its size.
- **T-2004 (Context Window Exploitation)** needs more than a gated fetch. A fire shows an
  agent followed a link embedded in a context-dilution payload; it does not isolate dilution
  as the cause, because there is no control arm. A tier-stratified comparison within the same
  category — do higher-dilution tiers convert at a materially different rate than tier 1? —
  would establish that the mechanism does measurable work.

**Reading the index correctly.** Each per-technique number is a count of distinct canary
fires attributed to one payload of that technique class, over the trailing 30 days, before
client-type gating. Read it as prevalence of engagement with that technique's traps. Do not
read it as a count of confirmed compromises, and do not sum evidence rows to get a population
size — use the distinct-fire count.
