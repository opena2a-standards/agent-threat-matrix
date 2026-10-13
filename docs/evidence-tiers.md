# Evidence tiers

Every technique in `matrix.json` carries exactly one `evidenceTier`. The schema
(`schema/threat-matrix-v1.2.schema.json`) fixes the enum to the three values below and
`scripts/validate_matrix.py` rejects any other value. The matrix carries exactly these
three tiers; there is no fourth tier, no sub-tier, and no theoretical tier.

## The three tiers

This table is the single definition of each tier. README.md, CONTRIBUTING.md and
EVIDENCE_AUDIT.md quote the Definition column word for word.
`scripts/check_evidence_tiers.py` reads those three pages, where it takes a line written as
`| **Observed** | <definition> |` (a table row whose first cell is the tier in bold) or as
`- **OBSERVED**: <definition>` (a list item labelled with the tier in bold) as a definition.
It fails when such a definition differs from this table, when the line after a list-item
definition is neither blank nor a bulleted list item with text indented no further than it
(Markdown may join such a line to the definition), when blank lines after a list-item
definition are followed by a line indented as far as its label (Markdown reads that line as
more of the same list item), or when one of the pages leaves a tier out. A blank line holds
nothing but spaces and tabs, a bullet is followed by a space or tab, a tab indents to the
next stop of four columns, and lines end only at a line feed or carriage return, as in
CommonMark. A definition written in any other form, such as inside a block quote, or on
another page is not read.
To change a definition, change it here and in every page that quotes it.

| Tier | `evidenceTier` value | Definition |
|------|----------------------|---------------------|
| Observed | `observed` | Confirmed in real-world production systems |
| Validated | `validated` | Reproduced in controlled lab environment (DVAA) |
| Adapted | `adapted` | Well-understood traditional technique applied to agent context, not yet observed agent-specifically |

The README states the bar behind the tiers: "We do not publish purely theoretical
techniques. Every entry has either a real-world observation, a reproducible lab scenario,
or an established traditional precedent." `EVIDENCE_AUDIT.md` records the justification
for every technique's tier.

## Evidence entries

Schema 1.2 adds an optional `evidence` array to each technique. Each entry names the
kind of source, the reference, and the date, so a tier can be traced to the material it
rests on. The `type` values are:

| `type` | Kind of source |
|--------|----------------|
| `observation` | A documented occurrence in a production system or an incident report |
| `lab-reproduction` | A reproduction in a controlled environment with documented steps |
| `publication` | A paper, article, or conference talk |
| `advisory` | A vendor or coordinating body security advisory |
| `honeypot-telemetry` | Telemetry from a published honeypot or sensor network |

Every value names a publicly resolvable kind of source. An `evidence` entry does not set
or change the technique's tier; the tier is assigned by the maintainers and audited in
`EVIDENCE_AUDIT.md`.

## Mapping to other registers

Other registers classify evidence on their own axes. The ARIA behavioral sweep classifies a
finding by where it was observed. The table below is the schema's home for the mapping
between that register and the matrix tiers. The mapping content is authored by the
maintainers; this table is the schema's home for it.

| ARIA behavioral-sweep class | Matrix tier |
|-----------------------------|-------------|
| laboratory-validated | PENDING |
| observed-single-fleet | PENDING |
| observed-cross-fleet | PENDING |

A row reads PENDING until the maintainers author the mapping. No tier is inferred from a
sweep class, and no sweep class is inferred from a tier.
