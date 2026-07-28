# Evidence Audit: Every Technique Against MITRE's Standard

MITRE ATT&CK requires every technique to be grounded in observed adversary behavior.
We apply three evidence tiers:

- **OBSERVED**: Confirmed in real-world production systems (NemoClaw findings, exposure sweeps, npm attacks)
- **VALIDATED**: Reproducible in controlled lab environment (DVAA challenges, HMA scan results)
- **ADAPTED**: A well-understood traditional technique applied to the agent context, with a
  clear attack vector but no agent-specific observation or lab reproduction yet

We do not publish purely theoretical techniques. Where this audit assessed a technique as
theoretical, the outcome was either to establish an agent-specific basis for it or to label
it ADAPTED and say so on the technique page — never to publish it unmarked. MITRE includes
adapted techniques when the attack vector is clear; the difference is that we label them.

These three tier names are the ones that ship: `evidenceTier` in `matrix.json` takes exactly
`observed`, `validated` or `adapted`, and every technique page carries the same value.

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

**Verdict: 2 OBSERVED, 5 VALIDATED, 0 ADAPTED. All publishable.**

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

**Verdict: 4 OBSERVED, 5 VALIDATED, 0 ADAPTED. All publishable.**

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

**Verdict: 3 OBSERVED, 3 VALIDATED, 0 ADAPTED. All publishable.**

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

**Verdict: 0 OBSERVED, 7 VALIDATED, 0 ADAPTED. All publishable (lab-proven).**

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

**Verdict: 1 OBSERVED, 5 VALIDATED, 0 ADAPTED. All publishable.**

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

**Verdict: 2 OBSERVED, 5 VALIDATED, 0 ADAPTED. All publishable.**

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

**Verdict: 1 OBSERVED, 6 VALIDATED, 0 ADAPTED. All publishable.**

---

## Stage 8: Exfiltration (6 Techniques)

| ID | Technique | Evidence Tier | Justification |
|----|-----------|--------------|---------------|
| T-8001 | Email Exfiltration | VALIDATED | DVAA ToolBot send_email tool with no recipient validation. |
| T-8002 | HTTP Callback | VALIDATED | DVAA ToolBot fetch_url to external endpoint with no egress filtering. |
| T-8003 | DNS Exfiltration | ADAPTED | Plausible but not demonstrated in DVAA or observed in the wild for AI agents specifically. Standard technique from traditional environments. |
| T-8004 | Tool Chain Exfiltration | VALIDATED | DVAA L3-06 (read_file + fetch_url chain). |
| T-8005 | Conversation Exfiltration | VALIDATED | All DVAA agents — data extracted via conversation responses. |
| T-8006 | Webhook Exfiltration | OBSERVED | NemoClaw H-007 (Telegram Bot API pre-allowed in sandbox policy). OpenClaw pre-allows messaging APIs. |

**Verdict: 1 OBSERVED, 4 VALIDATED, 1 ADAPTED.**

**T-8003 (DNS Exfiltration) is the only technique in this stage without an agent-specific basis.** It's a well-understood traditional technique applied to the agent context. Decision taken and applied: publish it as **ADAPTED**, marked on the technique page as "adapted from traditional environments — not yet observed in AI agent-specific deployments." MITRE includes adapted techniques when the attack vector is clear.

---

## Stage 9: Impact (6 Techniques)

| ID | Technique | Evidence Tier | Justification |
|----|-----------|--------------|---------------|
| T-9001 | Data Manipulation | VALIDATED | DVAA ToolBot write_file and DataBot SQL injection. NemoClaw C-005 (digest bypass enables blueprint tampering). |
| T-9002 | Service Disruption | VALIDATED | Resource exhaustion via context flooding. Standard DoS techniques applied to agents. |
| T-9003 | Malicious Code Deployment | OBSERVED | NemoClaw C-003 (curl|sh without checksum). Supply chain attacks deploying backdoors. |
| T-9004 | Multi-Agent Consensus Manipulation | ADAPTED | Plausible in multi-agent voting systems but not observed. DVAA consensus-manipulation scenario exists but is synthetic. |
| T-9005 | Reputation Poisoning | ADAPTED | Plausible output manipulation but not observed in production AI agent context specifically. |
| T-9006 | Supply Chain Compromise | OBSERVED | os-info-checker npm attack (May 2025). ClawHavoc campaign. NemoClaw C-003, C-005, C-006. |

**Verdict: 2 OBSERVED, 2 VALIDATED, 2 ADAPTED.**

**T-9004 (Multi-Agent Consensus Manipulation) and T-9005 (Reputation Poisoning) lack agent-specific evidence.** Both are plausible but have no observation in AI agent deployments. Decision taken and applied: publish both as **ADAPTED** rather than holding them, so the gap is stated on the page instead of the technique being absent.

---

## Summary

| Evidence Tier | Count | Percentage |
|--------------|-------|------------|
| OBSERVED (real-world) | 16 | 26% |
| VALIDATED (lab-proven) | 42 | 69% |
| ADAPTED (traditional, labelled) | 3 | 5% |
| **Total** | **61** | **100%** |

### Decisions

**Publish all 61 techniques.** 95% are OBSERVED or VALIDATED. The 3 ADAPTED techniques (T-8003, T-9004, T-9005) are well-understood traditional techniques applied to the agent context. MITRE ATT&CK includes adapted techniques when the attack vector is clear; the difference is that ours carry the label.

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
the payload it was embedded in.

Two different figures appear below and they are not interchangeable. Published counts come
from `GET /api/v1/intelligence/attack-prevalence`, which reports a **rolling 30-day window**
— those move daily as fires age out, so quote the endpoint, not this page, for a current
number (a 2026-07-28 pull gave roughly 7,300 evidence records over roughly 7,100 distinct
fires). Structural figures — ratios, mix percentages, per-classifier totals — are measured
directly against the full evidence corpus on the stated date and are cited because the
*proportions* are stable, not because the absolutes are.

**How it is attributed.** Attribution is payload-level *when the token carries a tier*. A
canary token is a deterministic hash of `(salt, category, tier, date)`, so it resolves to one
`(category, tier)`, which resolves to one payload and one technique. That path is genuinely
1:1 and the property is enforced, not merely observed: a partial unique index on
`(category, tier) WHERE tier IS NOT NULL` makes a duplicate mapping unrepresentable.
Measured 2026-07-28, it holds exactly — 10,970 rows across 10,970 distinct fires, ratio
1.000, spanning 26 techniques.

This replaced an earlier site-level scheme in which `agentpwn.com` was mapped to five
technique classes and every qualifying interaction wrote one row per mapped technique. Under
that scheme 7,125 interactions became 35,625 rows and all five techniques reported an
identical 7,125 — one population counted five ways.

**That fan-out is not fully gone, and the residue should be read as a known defect.** Some
lures are hand-slugged rather than hashed (`browser-verify`, `tool-*`, `trap-ci`,
`cred-verify`, `badge`, `loop-test`). These resolve to a category but to no tier, so they
fall outside the partial index and the writer falls back to a category-only lookup — which
matches *every* technique that category maps to. Measured 2026-07-28: 121 such fires produced
382 rows, a ratio of **3.157**, across 9 techniques.

| Category | Fires | Rows | Ratio | Techniques |
|---|---|---|---|---|
| mcp-exploitation | 99 | 297 | 3.00 | T-1002, T-2005, T-4007 |
| data-exfiltration | 19 | 76 | 4.00 | T-1003, T-3001, T-7004, T-8002 |
| tool-shadow | 3 | 9 | 3.00 | T-4007, T-8004, T-9002 |

So the blended row-to-fire ratio is about **1.02**, not 5.00 and not 1.00: 96.6% of rows are
1:1, and the remaining 3.4% reproduce the original error at small scale. Do not read a
per-technique count as a fire count without subtracting this class. The per-technique counts
are otherwise **differentiated** rather than identical — one 2026-07-28 pull gave T-2007 800,
T-2001 754, T-2003 615, T-2006 498, T-4007 418, T-6004 405, T-2004 330, T-8002 314 across 26
techniques (these drift between pulls; the differentiation is the durable claim, not the
digits).

**What a fire does not prove.** A canary fetch records that a client followed an embedded
link. It is not, by itself, proof that an *agent* obeyed an *injection*:

- **No client-type filter is applied at write time, and that is a deliberate decision rather
  than an omission.** Five successive filters were built on this path and all five were
  withdrawn as evasion primitives: User-Agent substring; `agent_type` (derived from the UA,
  so the same defect one layer up); reverse DNS (resolved without forward confirmation, so a
  VPS PTR record defeats it); source ASN (AS8075 is Azure and AS15169 is Google Cloud, so a
  free-tier VM buys entry to "Bingbot's" ASN — and OpenAI publishes GPTBot egress inside
  Azure space, so genuine GPTBot would have been excluded *as* Bingbot); and a canary-token
  validity check believed to be a server-side HMAC, which on inspection tests only
  `startsWith("apwn_") && length === 21` — a pure function of the URL the client requested.
  Every one of these keys on something the client chooses, so each would have let an agent
  delete its own evidence rather than remove noise. Crawlers are therefore **counted and
  disclosed**, not filtered: over-counting a crawler is visible in the published client mix,
  whereas suppressing an agent is invisible by construction.
- **The classification that exists is almost entirely absent or spoofable.** The schema
  admits `llm_agent`, `llm_crawler`, `browser`, `scanner`, `http_client`, `sdk_client` and
  `unknown`, each at `verified` or `claimed` confidence. What is actually recorded is far
  narrower. Measured 2026-07-28 over the 11,093 distinct fires behind the evidence corpus:
  **80.5% unclassified**, 19.0% `browser/claimed`, 0.5% `llm_crawler/claimed`. Across every
  interaction the honeypot has ever recorded — over 420,000 by that date, and still climbing —
  `agent_type` has taken only three values: null, `browser` and `llm_crawler`. **`llm_agent`
  has never been written once, and no interaction has ever reached `verified` confidence.**
  Those two counts are exactly zero, not merely small. So the rule "only
  `verified` should carry weight" currently resolves to "nothing carries weight", and the
  index contains no fire that the honeypot itself classified as an agent.
- **`browser` is a fallback, not a positive identification.** The classifier returns it
  whenever the fingerprint looks human, so declared search and SEO crawlers land inside it.
- **Tokens can be replayed.** A canary URL is public once fetched, so a count is a
  directional prevalence signal, not a tamper-proof tally.
- **Recovered history has a hard ceiling.** Fires predating the client-classification columns
  can be retro-classified only from the stored User-Agent, at `claimed` confidence. The raw
  IP is deliberately never retained, so `verified` classification is permanently unavailable
  for those rows — which is most of the corpus.

**Why no evidence tier was upgraded on this basis.** T-2004 (Context Window Exploitation) and
T-8002 (HTTP Callback) remain VALIDATED rather than OBSERVED. Payload-level attribution
removed the original objection — a count is no longer one population counted five ways — but
OBSERVED means the specific behaviour was confirmed in a real-world system, and an ungated
fetch count cannot separate an agent that obeyed an injection from a crawler that followed a
link. Promoting a tier on volume alone would reproduce the old error in a subtler form.

Both techniques were then reassessed individually, against measurement rather than argument.
Neither reassessment supports a promotion, and each fails for a different reason.

**T-8002 (HTTP Callback): the channel that would justify OBSERVED is empty.** A callback is
structurally the strongest signal the honeypot can collect — an outbound request to a URL
that only the injected payload named, which is the technique's definition rather than a proxy
for it. It is also not what T-8002's evidence is made of. Measured 2026-07-28, all 488
T-8002 rows are canary fetches (469 payload-attributed, 19 from the category fan-out
described above); **none is a callback.** The `payload_callback` event has fired **four times
in the honeypot's lifetime**, against roughly 389,000 page visits and 11,296 canary fires:

| Date | Category | Attack ID | User-Agent |
|---|---|---|---|
| 2026-03-27 | verification | VERIFY-001 | (none) |
| 2026-03-27 | prompt-injection | APWN-PI-001 | (none) |
| 2026-03-27 | prompt-injection | APWN-PI-003 | (none) |
| 2026-07-07 | file-fetch | APWN-SMOKE-VERIFY | curl/8.7.1 |

Three are first-day bring-up events and the fourth is our own smoke test. None is attributable
to a third-party agent, and none produced a T-8002 row. T-8002 is therefore *further* from
OBSERVED than its 488-row count suggests, not nearer: the count rests entirely on the
ambiguous channel while the unambiguous one has no real-world observation at all.

**T-2004 (Context Window Exploitation): the comparison cannot be computed, and that is the
finding.** The objection to promoting T-2004 was that a fire shows an agent followed a link
embedded in a context-dilution payload without isolating dilution as the cause. Settling that
needs a conversion rate — fires over exposures — and **the honeypot records fires but never
records exposures.** No serve or impression counter is kept per `(category, tier)`. The
`page_visit` stream cannot substitute: it registers 114 `context-window` visits against 993
`context-window` fires, so it is not the population the fires came from. Every other quantity
derivable from the fire log — distinct tokens, active days, token-days — is itself a function
of firing, so any rate built on one is circular.

Two things can still be stated, and neither supports a promotion:

- **Raw per-tier fire counts show no monotonic relationship with dilution.** `context-window`
  tiers 1 through 5 recorded 253, 191, 221, 143 and 185 fires. The least-diluted arm fires
  most, which is the wrong direction for the mechanism.
- **Firing intensity is flat.** Measured as fires per token-day — the one normalisation not
  confounded by how long a token stays in circulation — `context-window` runs 1.10, 1.09,
  1.12, 1.07, 1.09 across tiers 1 to 5. Site-wide the quantity is very nearly a constant:
  across all 48 `(category, tier)` cells it spans 1.07 to 1.18, median 1.13, standard
  deviation 0.023. The `context-window` tiers sit inside that band and are unordered with
  respect to tier. A dilution effect would have to appear as a tier-dependent departure from
  the constant. None does.

An earlier draft of this analysis normalised fires by distinct *token* rather than token-day
and reported a tier gradient with a negative rank correlation. That metric was confounded and
the conclusion drawn from it was wrong: a token's fire count is largely a function of how many
days it remained in circulation (3.1 to 4.2 days on average, varying by tier), so the metric
measured token longevity and not conversion. The gradient vanishes under the corrected
normalisation. It is recorded here because the same mistake is easy to repeat against this
dataset — any denominator taken from the fire log encodes the firing it is meant to normalise.

What would still move each tier: for T-8002, real third-party callbacks, which need the
channel to be exercised rather than analysed; for T-2004, a serve-side counter incrementing
per `(category, tier)` whenever a payload is rendered, which is the missing denominator and a
change to the honeypot rather than to this matrix. For both, a client signal the caller cannot
choose. Two such signals are within reach in the honeypot and neither has yet reached the
registry, so both would qualify zero rows today, which is the honest state:
`attribution_confidence == "verified"` set by matching the source address against providers'
*published* egress ranges, and forward-confirmed reverse DNS, which exists in the honeypot but
is not threaded into telemetry.

**Reading the index correctly.** Each per-technique number counts canary fires attributed to a
payload of that technique class over the trailing 30 days, with no client-type filtering at
any stage. Read it as prevalence of engagement with that technique's traps. Do not read it as
a count of confirmed compromises; do not read it as a count of agents, since no row in it has
ever been classified as one; and do not sum evidence rows to get a population size, because
the 3.4% category-fan-out class counts one fire three or four times — use the distinct-fire
count. The live response carries its own `clientMix` block and caveat stating these limits;
that block, not this page, is the current figure.
