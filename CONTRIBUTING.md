# Contributing to the AI Agent Threat Matrix

We welcome contributions of new techniques, attack classes, evidence reports, and detection methods.

## Evidence Requirements

Every technique in this matrix must meet one of these evidence bars:

| Tier | Requirement |
|------|------------|
| **Observed** | Documented in a real-world production system, security incident report, or internet-wide exposure assessment |
| **Validated** | Reproduced in a controlled lab environment with documented steps, expected output, and independent verification |
| **Adapted** | Well-understood technique from traditional security (MITRE ATT&CK) applied to the AI agent context with a clear explanation of how the agent-specific variant differs |

We do not accept purely theoretical techniques. If you have a plausible attack vector but no evidence, file an issue describing the hypothesis and we will evaluate it for future research.

## Proposing a New Technique

1. **Check for duplicates.** Search existing techniques in `techniques/` and `matrix.json` to ensure the technique is not already covered.

2. **Assign an ID.** Use the next available ID in the appropriate stage range:
   - T-1XXX: Reconnaissance
   - T-2XXX: Initial Access
   - T-3XXX: Credential Harvest
   - T-4XXX: Privilege Escalation
   - T-5XXX: Lateral Movement
   - T-6XXX: Persistence
   - T-7XXX: Collection
   - T-8XXX: Exfiltration
   - T-9XXX: Impact

3. **Create a technique file** in `techniques/` following the template:

```markdown
# T-XXXX: Technique Name

## Tactic
[Kill chain stage]

## Description
[What the technique does and why it works]

## Attack Class
[Which attack class this belongs to]

## Evidence
- **Tier:** Observed / Validated / Adapted
- **Source:** [Where this was observed or validated]

## Procedure Example
[Step-by-step description of how an attacker executes this]

## Detection
- **HMA Checks:** [Check IDs]
- **Detection Logic:** [What to look for]

## Validation
- **DVAA Challenge:** [Challenge ID or scenario name]
- **Reproduction Steps:** [How to reproduce in DVAA]

## Defense
- **OASB Controls:** [Control IDs]
- **Mitigation:** [How to prevent this]

## References
[Links to evidence, academic papers, incident reports]
```

4. **Update matrix.json** to include the new technique.

5. **Submit a pull request** with:
   - The technique file
   - Updated matrix.json
   - Evidence documentation (if new evidence)
   - A brief description of why this technique should be included

## Placing a new technique

Every technique in `matrix.json` sits in exactly one published list in `cross-references/`:

- **(A)** named against an OWASP item in `cross-references/owasp-llm-mapping.md`, or
- **(B)** listed with no counterpart in `cross-references/technique-overlap-index.md`.

**(B) is the default. (A) is the exception, and it must be sourced.** `scripts/check_cross_references.py` enforces the partition: its C3 check fails if a technique is in both lists, and its C4 check fails if a technique is in neither. When either fails, the fix is to place the technique here, not to move it into whichever list makes CI green.

A technique enters **list (A)** only if you can complete this sentence with a quotation from the OWASP item's own published text:

> *"OWASP item LLMnn names this technique's object or effect at: `<verbatim sentence>`."*

Three tests. All three must pass, against the **item's own text** -- its Description, Common Examples of Vulnerability, or Example Attack Scenarios. **The item's title is not evidence.** Reading a title is how "memory injection" reached "Overreliance".

1. **Object test.** Either the thing the technique acts on, or the asset it yields, is named in that text.
2. **Effect test.** What the attacker gets is the same kind of outcome the item describes. Discovery is not disclosure. Persistence is not a bad recommendation. A badly designed component is not an attacker-planted one.
3. **Mitigation test.** At least one of the item's own numbered Prevention and Mitigation Strategies would reduce this technique. Name the number. If none of them touch it, the item is not about it.

**Any test fails -> list (B).** Two tests passing is not a partial pass; the table's "Partial Overlap" header describes the *degree* of a real correspondence, never a substitute for one.

**If (A):** the row records the OWASP item id and one sentence naming what overlaps **and** what the item does not reach. The pull request body -- not the published file -- carries the `matrix.json` line range of the technique record, the verbatim OWASP sentence relied on, and the numbered mitigation from test 3.

**If (B):** the row records the agent-layer property it depends on -- *the thing an agent has that a bare LLM application does not*: persistent memory across sessions, a tool registry, a governance file, an A2A identity, a deployed control surface, a sandbox boundary. **If the honest answer is that the technique is a traditional one adapted to an agent, the cell says that**, as T-8003's row does. Inventing uniqueness to fill the column is the defect this rule exists to stop.

Two ties broken in advance, so nobody re-derives them:

- **A technique's delivery vector never places it.** Almost everything is delivered by prompt injection. If delivery placed techniques, every row would be LLM01 and the table would carry no information. Place on the technique's own distinguishing property -- the reason it has its own `T-` id instead of being a footnote on another one.
- **C3/C4 red is never resolved by moving the technique into whichever list makes CI green.** Red means the placement has not been made, not that a list is short.

The pull request that adds a technique to `matrix.json` carries, in the same commit, its `canonical-classes.json` `primary` class **and** its placement in (A) or (B). A PR that adds a technique without both is incomplete, and both validators failing is the gate working as designed.

If a technique-grain MITRE ATLAS mapping is ever authored, this two-list partition becomes insufficient: (A) becomes "named in at least one mapping table", (B) "named in none", and C3/C4 are recomputed.

## Proposing a New Attack Class

Attack classes group related techniques. To propose a new class:

1. Identify 2+ techniques that share a common vulnerability pattern
2. Create a class file in `attack-classes/` with the class name, description, member techniques, and member HMA checks
3. Explain why this grouping is useful for practitioners

## Reporting Errors

If you find an error in a technique description, evidence citation, or cross-reference mapping, please file an issue with:

- The technique or class ID
- What is incorrect
- What the correct information should be
- A source for the correction

## Code of Conduct

Contributions must be:
- Factual and evidence-based
- Vendor-neutral (no product promotion)
- Responsible (no active exploit code against production systems)
- Respectful of coordinated disclosure timelines
