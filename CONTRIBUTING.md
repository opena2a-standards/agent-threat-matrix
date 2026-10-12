# Contributing to the AI Agent Threat Matrix

We welcome contributions of new techniques, attack classes, evidence reports, and detection methods.

## Evidence Requirements

Every technique in this matrix must meet one of these evidence bars. The definitions are
quoted from [docs/evidence-tiers.md](docs/evidence-tiers.md); the last column is the
evidence a submission includes to show its tier.

| Tier | Definition | Evidence to include |
|------|------------|---------------------|
| **Observed** | Confirmed in real-world production systems | The real-world production system, security incident report, or internet-wide exposure assessment where it was documented |
| **Validated** | Reproduced in controlled lab environment (DVAA) | The documented reproduction steps and the expected output |
| **Adapted** | Well-understood traditional technique applied to agent context, not yet observed agent-specifically | The named traditional technique (the MITRE ATT&CK id where one exists) and a clear explanation of how the agent-specific variant differs |

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

Three tests. All three must pass, against the **item's own text**: its Description, Common Examples of Vulnerability, or Example Attack Scenarios. **The item's title is not evidence.** Reading a title is how "memory injection" reached "Overreliance".

1. **Object test.** Either the thing the technique acts on, or the asset it yields, is named in that text.
2. **Effect test.** What the attacker gets is the same kind of outcome the item describes. Discovery is not disclosure. Persistence is not a bad recommendation. A badly designed component is not an attacker-planted one.
3. **Mitigation test.** At least one of the item's own numbered Prevention and Mitigation Strategies would reduce this technique. Name the number. If none of them touch it, the item is not about it.

**Any test fails -> list (B).** Two tests passing is not a partial pass; the table's "Partial Overlap" header describes the *degree* of a real correspondence, never a substitute for one.

**If (A):** the row records the OWASP item id and one sentence naming what overlaps **and** what the item does not reach. The pull request body (not the published file) carries the `matrix.json` line range of the technique record, the verbatim OWASP sentence relied on, and the numbered mitigation from test 3.

**If (B):** the row records the agent-layer property it depends on, *the thing an agent has that a bare LLM application does not*: persistent memory across sessions, a tool registry, a governance file, an A2A identity, a deployed control surface, a sandbox boundary. **If the honest answer is that the technique is a traditional one adapted to an agent, the cell says that**, as T-8003's row does. Inventing uniqueness to fill the column is the defect this rule exists to stop.

Two ties broken in advance, so nobody re-derives them:

- **A technique's delivery vector never places it.** Almost everything is delivered by prompt injection. If delivery placed techniques, every row would be LLM01 and the table would carry no information. Place on the technique's own distinguishing property: the reason it has its own `T-` id instead of being a footnote on another one.
- **C3/C4 red is never resolved by moving the technique into whichever list makes CI green.** Red means the placement has not been made, not that a list is short.

The pull request that adds a technique to `matrix.json` carries, in the same commit, its `canonical-classes.json` `primary` class **and** its placement in (A) or (B). A PR that adds a technique without both is incomplete, and both validators failing is the gate working as designed.

If a technique-grain MITRE ATLAS mapping is ever authored, this two-list partition becomes insufficient: (A) becomes "named in at least one mapping table", (B) "named in none", and C3/C4 are recomputed.

## Proposing a New Attack Class

Attack classes group related techniques. To propose a new class:

1. Identify 2+ techniques that share a common vulnerability pattern
2. Add the class to `attackClasses` in `matrix.json` with its name, description, member techniques, and member HMA checks
3. Write its page by running `python3 scripts/generate_class_markdown.py`
4. Explain why this grouping is useful for practitioners

The pages in `attack-classes/` are rendered from `matrix.json`. To change a page, change the
class in `matrix.json` and run the generator again; a page edited by hand is overwritten by the
next run. `python3 scripts/generate_class_markdown.py --check` writes nothing and exits 1 when
a page differs from what `matrix.json` renders.

## Reporting Errors

If you find an error in a technique description, evidence citation, or cross-reference mapping, please file an issue with:

- The technique or class ID
- What is incorrect
- What the correct information should be
- A source for the correction

## Contributor credit

An accepted contribution is credited to its contributor: a new technique or attack class, new
evidence that changes a technique's tier, or a correction that changes published content. The
credit is published in `ATTRIBUTION.md` in this repository. The externally-contributed list
carries, per technique, the contributor's name or handle **exactly as the contributor gives
it** (in the issue form's credit preference field or the pull request body), together with the
issue or pull request the submission arrived in.

To decline credit, say so in the submission's credit preference field. A declined credit is
recorded in `ATTRIBUTION.md` as *(credit declined)*: the entry stays in the
externally-contributed list with its submission reference, and is never reclassified as
in-house work.

Credit is recorded, never guessed. `ATTRIBUTION.md` places every technique id in `matrix.json`
in exactly one of two published lists (externally contributed or authored in-house), and
`scripts/check_attribution.py` enforces the partition in CI, on the same terms as the
cross-reference placement above. An external entry must name the issue or pull request it
arrived in; where the repository's history does not establish an external contributor for a
technique, that technique is listed as authored in-house.

## Change control

OpenA2A retains final change control over the matrix. OpenA2A decides what enters the matrix,
and a submission, however well evidenced, creates no entitlement to inclusion. Content that
has been accepted may afterwards be edited, re-tiered (its evidence tier changed), re-placed
(its canonical class or its (A)/(B) cross-reference placement changed), or removed entirely,
as the evidence and the taxonomy evolve. Each such decision is recorded on the submission
thread (the issue or pull request the content arrived in), so the contributor and any later
reader can see what was decided and why.

## Checking documentation prose

If your pull request adds or edits any Markdown file, run the docs prose check from the
repository root before you open it:

```bash
python3 scripts/check_docs_prose.py
```

It prints `file:line` for each spaced double hyphen, em dash or spaced en dash used as a dash
in prose, and for each heading or bold label named "Why this exists" or "Why this matters",
and exits 1 if it finds any. Rewrite the sentence with a period, a comma, a colon or
parentheses. Code spans, fenced code blocks, HTML comments and table delimiter rows are not
checked, and neither are `CHANGELOG.md` and test fixture directories. A new file is checked
before you stage it; a file that git ignores is not checked. For a finding in
`attack-classes/`, make the fix in the class description in `matrix.json` and regenerate the
page.

If your pull request touches an evidence tier definition, also run:

```bash
python3 scripts/check_evidence_tiers.py
```

`docs/evidence-tiers.md` is the single definition of each tier, and `README.md`, this file
and `EVIDENCE_AUDIT.md` quote it. The check reads those three pages for definitions written
as a table row whose first cell is the tier in bold, as in the table at the top of this file,
or as a list item labelled with the tier in bold, as in `EVIDENCE_AUDIT.md`. It prints
`file:line` for each such definition that differs from that page, and for each list-item
definition followed by a line that is neither blank nor a bulleted list item indented no
further than it, names each page that leaves a tier out, and exits 1 if it finds any. Keep
each definition on one line.

## Code of Conduct

Contributions must be:
- Factual and evidence-based
- Vendor-neutral (no product promotion)
- Responsible (no active exploit code against production systems)
- Respectful of coordinated disclosure timelines
