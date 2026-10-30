# Use cases

Situations the matrix is used in, what you can do today in each, and where it stops.

## Who reads this

| Reader | The question they bring | Where it is answered |
|---|---|---|
| Security leader or CISO | What can go wrong with an agent we ship, and how do I compare one vendor's detection claim with another's? | The use cases [Your team ships an agent and security asks what can go wrong](#your-team-ships-an-agent-and-security-asks-what-can-go-wrong) and [A vendor says its scanner catches agent attacks](#a-vendor-says-its-scanner-catches-agent-attacks) |
| IAM professional or identity architect | Which attacks go after an agent's credentials and the trust between agents, and which controls answer them? | The [Credential Harvest](../tactics/credential-harvest.md) tactic and the use case [An identity team asks which attacks go after agent credentials](#an-identity-team-asks-which-attacks-go-after-agent-credentials) |
| Platform or security engineer | What do I collect to see a technique, and how does one attack chain run? | [Data sources](data-sources.md), [attack paths](attack-paths.md), and the use case [A web page tells your agent what to do](#a-web-page-tells-your-agent-what-to-do) |
| Agent developer or implementer | Which fields do I read, and what stays stable from one release to the next? | The field table under [Matrix Overview](../README.md#matrix-overview), [schema](schema.md), and the use case [A tool cites technique ids and a new release lands](#a-tool-cites-technique-ids-and-a-new-release-lands) |
| GRC, audit or compliance reader | Which control answers an attack, and how strong is the evidence that it happens? | [Evidence tiers](evidence-tiers.md), [`EVIDENCE_AUDIT.md`](../EVIDENCE_AUDIT.md), and the use case [An auditor asks which control answers an attack](#an-auditor-asks-which-control-answers-an-attack) |
| Standards reviewer (IETF or AIW participant) | What does this cover that MITRE ATT&CK, MITRE ATLAS and the OWASP Top 10 for LLM do not, who decides what enters it, and which release is current? | The scope in [overview](overview.md#what-this-covers-and-what-it-doesnt), [`GOVERNANCE.md`](../GOVERNANCE.md), the technique-level [crosswalks](../crosswalks/README.md), and the version line at the top of the [README](../README.md) |

## Your team ships an agent and security asks what can go wrong

A team is about to ship an agent that reads documents, calls tools and keeps memory. Security asks for the threat list. The layer between the model and the user, where governance files, skills, MCP connections, memory and credentials in context live, is where agents differ, and a team without a list for that layer defends by guesswork.

Existing catalogs cover networks (MITRE ATT&CK) and AI systems (MITRE ATLAS, which names attacks on models and, in recent releases, some on agents, such as agent tool invocation and agent configuration changes).

The matrix classifies attacks on that layer into 9 tactics and 61 techniques along a kill chain. Each technique carries an evidence tier, maps to a detection check and a defensive control, and 58 of the 61 carry a reproducible lab scenario.

What you can do today: browse [threats.opena2a.org](https://threats.opena2a.org), or read `matrix.json` and validate it against its schema.

```bash
git clone https://github.com/opena2a-standards/agent-threat-matrix
cd agent-threat-matrix
python3 scripts/validate_matrix.py
```

Where it stops today: the README's [Matrix Overview](../README.md#matrix-overview) states which version the live API serves.

## A web page tells your agent what to do

An agent reads a page or a tool result. The page contains an instruction. The agent follows it, and an API key sitting in its context leaves with the next request. The person who delegated the task never sees the page.

Both halves are catalogued: Indirect Prompt Injection (T-2002, initial access, observed in the wild) and Context Window Credential Leak (T-3006, credential harvest, validated in the lab). The ids are stable, so detection signatures (AIIS) and telemetry attributes can cite the same technique.

What you can do today:

```bash
jq '.techniques[] | select(.id == "T-2002" or .id == "T-3006")' matrix.json
```

Where it stops today: 16 of the 61 techniques carry real-world evidence; 42 are validated in controlled lab environments and 3 are adapted from traditional environments, and each is marked as such.

## A vendor says its scanner catches agent attacks

A buyer hears that a tool "covers agent threats" and has no way to compare that claim with another vendor's, or to load it into the systems they already run.

Vendors map their detections to technique ids, and the matrix ships as a STIX 2.1 bundle rendered from `matrix.json`, so the same ids load into a SIEM or threat-intelligence platform alongside ATT&CK and ATLAS.

What you can do today: import `stix/agent-threat-matrix-bundle.json`, or regenerate it with `python3 scripts/generate_stix.py`.

## An identity team asks which attacks go after agent credentials

Agents hold API keys and tokens, and some act for other agents. The identity team is asked which attacks aim at those credentials and at the trust between agents, and which of its controls each attack runs into. The lists it works from describe stolen passwords and compromised servers; they say nothing about a key pasted into an agent's instructions, or an agent that passes on a request it should have refused.

Reader: IAM professional or identity architect.

Without the matrix: the ways a credential leaks out of an agent, and the ways one agent borrows another's authority, have no names to plan or test against.

What the matrix does: the Credential Harvest tactic covers extracting API keys, tokens and credentials from agent context and connected services ([`matrix.json:21-24`](../matrix.json)). Its techniques, from [`matrix.json:884`](../matrix.json) on, name where a credential leaks from: T-3001 (System Prompt Credential Extraction), T-3002 (Environment Variable Leakage), T-3003 (Tool Response Credential Capture), T-3004 (Memory Credential Mining), T-3005 (Configuration File Access) and T-3006 (Context Window Credential Leak). The AGENT-IMPERSONATE attack class ([`matrix.json:4868`](../matrix.json)) holds Admin Impersonation (T-4002, [`matrix.json:1432`](../matrix.json)) and Delegation Abuse (T-4004, [`matrix.json:1545`](../matrix.json)), which escalates privileges through trusted agent chains. Each technique lists the OASB controls that defend against it in `oasbControls` ([field table](../README.md#matrix-overview)).

How it maps onto what the team runs: the controls are stated as outcomes, such as Credential Scope Limitation, Credential Rotation and No Implicit Trust Escalation, and the team maps each onto the mechanism it already runs. The matrix does not name OAuth 2.0, OpenID Connect, SPIFFE, X.509 certificates or DIDs.

What you can do today: list those techniques with their evidence tier and controls, then the control titles.

```bash
jq -r '.techniques[] | select(.attackClass == "AGENT-IMPERSONATE" or .tactic == "credential-harvest") | [.id, .name, .evidenceTier, (.oasbControls | join(","))] | @tsv' matrix.json
jq -r '.oasb.controlTitles | to_entries[] | select(.key | test("^(2|5)\\.")) | "\(.key)\t\(.value)"' related-projects.json
```

```
T-3001	System Prompt Credential Extraction	observed	5.1,5.2,5.3,5.4,5.5
T-3002	Environment Variable Leakage	observed	5.1,5.2,5.3,5.4,5.5
T-3003	Tool Response Credential Capture	validated	5.1,5.2,5.3,5.4,5.5
T-3004	Memory Credential Mining	validated	5.1,5.2,5.3,5.4,5.5
T-3005	Configuration File Access	observed	5.1,5.2,5.3,5.4,5.5
T-3006	Context Window Credential Leak	validated	5.1,5.2,5.3,5.4,5.5
T-4002	Admin Impersonation	validated	2.1,2.2,2.3,2.4,2.5
T-4004	Delegation Abuse	validated	2.1,2.2,2.3,2.4,2.5
2.1	Explicit Capability Grants
2.2	Least Privilege Principle
2.3	Capability Boundaries
2.4	No Implicit Trust Escalation
2.5	Human-in-the-Loop for Sensitive Actions
5.1	No Hardcoded Credentials
5.2	Context Window Isolation
5.3	Credential Scope Limitation
5.4	Credential Rotation
5.5	Secrets Not Logged
```

Where it stops today: three of these are observed in the wild; the others are validated in a lab.

Out of scope: the matrix names attacks and the controls that answer them. It does not authenticate, issue or rotate anything, and detection is the work of the checks listed in `hmaChecks`.

## A tool cites technique ids and a new release lands

A detection tool, a telemetry pipeline and a signature pack all cite T-2002 for indirect prompt injection. A new release of the matrix comes out. If that id had been renamed, given to another attack or deleted, every one of those references would point at the wrong attack, and nothing would say so.

Reader: agent developer or implementer.

Without the matrix's rules: a reference into a catalog breaks silently when the catalog changes.

What the matrix does: a technique id, once published, is never deleted, reused or renumbered; a technique that no longer belongs is deprecated, keeps its record, and names its successor in `replacedBy` ([`GOVERNANCE.md:147-153`](../GOVERNANCE.md#technique-ids-are-permanent)). The schema fixes the id grammar ([`schema/threat-matrix-v1.2.schema.json:31`](../schema/threat-matrix-v1.2.schema.json)) and requires `replacedBy` if and only if the status is `deprecated` ([`schema/threat-matrix-v1.2.schema.json:104-111`](../schema/threat-matrix-v1.2.schema.json)). The version is MAJOR.MINOR, and MAJOR steps only when a consumer must change its code or its reading of an id ([`GOVERNANCE.md:119-134`](../GOVERNANCE.md#the-version-rule)). What to implement first follows from that: read `version`, follow `replacedBy` when `status` is `deprecated`, and review the change when MAJOR steps.

What you can do today: read the version, then run the validator.

```bash
python3 -c 'import json; print(json.load(open("matrix.json"))["version"])'
python3 scripts/validate_matrix.py
```

```
1.2
matrix.json validates against schema 1.2: 61 techniques (0 sub-techniques), 19 data sources, 58 evidence entries resolved (24 techniques with none) against wildPrevalenceSource and the 6 pages, 15 challenges and 12 scenario pages evidence-sources.json pins, technique-ids.json, STIX bundle and evidence-gaps.json in sync (matrixCommit b554a22db7fce6826b776e730b8955aed3583cf8, ids match matrix.json at that commit)
```

Where it stops today: no technique in this release has the status `deprecated`, so no consumer has had to follow a `replacedBy` yet. The README's [Matrix Overview](../README.md#matrix-overview) states which version the live API serves.

Out of scope: how a consumer stores, caches or displays the ids.

## An auditor asks which control answers an attack

A compliance lead is writing the agent section of a risk register. For each attack listed, the auditor will ask two things: which control is meant to stop it, and has the attack been seen in practice or only shown in a lab?

Reader: GRC, audit or compliance reader.

Without the matrix: a register names agent attacks in its own words, with no control beside them and no statement of how strong the evidence is.

What the matrix does: each technique lists the OASB controls that defend against it and carries an evidence tier: observed in the wild, validated in a controlled lab, or adapted from a traditional environment ([field table](../README.md#matrix-overview)). The tier definitions in [`docs/evidence-tiers.md`](evidence-tiers.md) and the justification of every technique's tier in [`EVIDENCE_AUDIT.md`](../EVIDENCE_AUDIT.md) are both normative content ([`GOVERNANCE.md:45-46`](../GOVERNANCE.md#what-is-normative-derived-and-editorial)). A tier moves only by a recorded decision of the maintainers, landed as one pull request that changes `matrix.json`, `EVIDENCE_AUDIT.md` and `CHANGELOG.md` ([`GOVERNANCE.md:157-171`](../GOVERNANCE.md#how-an-evidence-tier-moves)). Each technique also carries its crosswalk to MITRE ATT&CK and MITRE ATLAS ([`GOVERNANCE.md:38-40`](../GOVERNANCE.md#what-is-normative-derived-and-editorial)). Those, with the OWASP Top 10 for LLM mapping page under [`cross-references/`](../cross-references/), are the mappings the repository makes; it maps no regulation. The artifacts an auditor reads are the technique's entry in `matrix.json`, its page under [`techniques/`](../techniques/), and its row in `EVIDENCE_AUDIT.md`.

What you can do today: read one technique's controls, tier and crosswalks, then its row in the evidence audit.

```bash
jq -c --slurpfile r related-projects.json '.techniques[] | select(.id == "T-2002") | {id, name, evidenceTier, controls: [.oasbControls[] as $c | "\($c) \($r[0].oasb.controlTitles[$c])"], attackMapping: [.attackMapping[].id], atlasMapping: [.atlasMapping[].id]}' matrix.json
grep -n "T-2002" EVIDENCE_AUDIT.md
```

```
{"id":"T-2002","name":"Indirect Prompt Injection","evidenceTier":"observed","controls":["3.1 Prompt Injection Protection","3.2 Instruction Boundary Enforcement","3.3 Input Validation","3.4 URL and Resource Validation","3.5 Multi-Modal Input Security"],"attackMapping":["T1698"],"atlasMapping":["AML.T0051.001"]}
42:| T-2002 | Indirect Prompt Injection | OBSERVED | Greshake et al. 2023. RAG poisoning demonstrated in multiple production systems. |
```

Where it stops today: the control titles are pinned from one OASB-1 release in [`related-projects.json`](../related-projects.json), which is editorial content.

Out of scope: whether a deployment meets a control. The matrix says which control answers an attack; testing a deployment against the control is the work of the OASB benchmark.

Why you can check this yourself: [`matrix.json`](../matrix.json) and its schema in [`schema/`](../schema/); [`scripts/validate_matrix.py`](../scripts/validate_matrix.py); the per-technique justification in [`EVIDENCE_AUDIT.md`](../EVIDENCE_AUDIT.md); the STIX bundle in [`stix/`](../stix/); the rendered site at [threats.opena2a.org](https://threats.opena2a.org); and the live API at `https://api.oa2a.org/api/v1/threat-matrix`.
