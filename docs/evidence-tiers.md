# Evidence tiers

Every technique in `matrix.json` carries exactly one `evidenceTier`. The schema
(`schema/threat-matrix-v1.2.schema.json`) fixes the enum to the three values below and
`scripts/validate_matrix.py` rejects any other value. The matrix carries exactly these
three tiers; there is no fourth tier, no sub-tier, and no theoretical tier.

## The three tiers

This table is the single definition of each tier. The [Evidence Standard](#evidence-standard)
table on this page, CONTRIBUTING.md and EVIDENCE_AUDIT.md quote the Definition column word
for word. `scripts/check_evidence_tiers.py` reads those three pages, and README.md, which
links here and defines no tier, where it takes a line written as
`| **Observed** | <definition> |` (a table row whose first cell is the tier in bold) or as
`- **OBSERVED**: <definition>` (a list item labelled with the tier in bold) as a definition.
It fails when such a definition differs from this table, when the line after a list-item
definition is neither blank nor a bulleted list item with text indented no further than it
(Markdown may join such a line to the definition), when blank lines after a list-item
definition are followed by a line indented as far as the item's text (Markdown reads that
line as more of the same list item), or when this page, CONTRIBUTING.md or EVIDENCE_AUDIT.md
leaves a tier out. README.md need not define a tier, and a definition written there is
checked as on the other pages. A blank line holds nothing but spaces and tabs, a bullet is
followed by a space or tab, a tab indents to the next stop of four columns, and lines end
only at a line feed or carriage return, as in CommonMark. A list item's text starts after the spaces and tabs that follow
its marker, or one column after the marker when those cover five or more columns. A bullet
indented four or more columns past the text of the list item it is inside, or past the
margin when it is inside none, starts no list item, so such a line is not a definition and
does not end one. Code blocks are skipped as CommonMark delimits them: a fence closes on a
line that holds only a run of its own character at least as long as the opening one, does
not open on a run of backticks with a backtick later on the line, and ends with the list
item it is in. The check is stricter than CommonMark in one respect: only a bulleted list
item with text ends a definition, so a bullet with no text, a numbered item or a thematic
break directly after a definition is reported although CommonMark ends the list item
there. A definition written in any other form, such as inside a block quote, or on another
page is not read.
To change a definition, change it here and in every page that quotes it.

| Tier | `evidenceTier` value | Definition |
|------|----------------------|---------------------|
| Observed | `observed` | Confirmed in real-world production systems |
| Validated | `validated` | Reproduced in controlled lab environment (DVAA) |
| Adapted | `adapted` | Well-understood traditional technique applied to agent context, not yet observed agent-specifically |

The [Evidence Standard](#evidence-standard) below states the bar behind the tiers, and
`EVIDENCE_AUDIT.md` records the justification for every technique's tier.

## Evidence Standard

Every technique in this matrix is assigned an evidence tier. The definitions are quoted from [The three tiers](#the-three-tiers):

| Tier | Meaning | Count |
|------|---------|-------|
| **Observed** | Confirmed in real-world production systems | 16 (26%) |
| **Validated** | Reproduced in controlled lab environment (DVAA) | 42 (69%) |
| **Adapted** | Well-understood traditional technique applied to agent context, not yet observed agent-specifically | 3 (5%) |

We do not publish purely theoretical techniques. Every entry has either a real-world observation, a reproducible lab scenario, or an established traditional precedent.

See [EVIDENCE_AUDIT.md](../EVIDENCE_AUDIT.md) for the full justification of every technique's evidence tier.

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

An entry is accepted only where `scripts/validate_matrix.py` resolves its reference to a
source it reads, so no entry rests on a citation nobody read. The validator resolves three
kinds of entry:

- A `honeypot-telemetry` entry whose reference is the registry endpoint in
  `wildPrevalenceSource` and whose date is the read date there, on a technique whose
  `wildSampleCount` is above 0. `scripts/sync_wild_prevalence.py` writes that entry when it
  records the read.
- A `lab-reproduction` entry whose reference is the permalink of a DVAA scenario page that
  `evidence-sources.json` pins, `<repository>/blob/<commit>/<path>`, whose date is the date
  of the commit in that permalink, and whose technique the page names by its id with the
  technique's name in `matrix.json` as the label, in bold as `**T-NNNN (Label):**`, the form
  DVAA gives the steps of an attack chain. `scripts/pin_evidence_sources.py` reads a git
  clone of DVAA and writes the pins and these entries. A pin records the page's path, the
  last commit that changed the page as of the commit the clone was read at, that commit's
  date, the page's git blob id, and each technique the page names, with its line and its
  label. A page that names an id under a label that is not that technique's name backs no
  entry, and the script prints each such name.
- A `lab-reproduction` entry whose reference is the permalink of a DVAA challenge or
  scenario page that `evidence-sources.json` pins for a technique's `dvaaValidation`, whose
  date is the date of the commit in that permalink, and whose technique's `dvaaValidation`
  names that challenge or scenario. `dvaaValidation` names the DVAA lab work that
  reproduces the technique: free text, or the id of a challenge or the name of a scenario,
  several separated by commas. `scripts/pin_evidence_sources.py` reads each value. A value
  that is the id of a challenge defined in DVAA's `src/challenges/index.js` names that
  challenge, and its entry cites the file at the line of the challenge's key,
  `<repository>/blob/<commit>/src/challenges/index.js#L<line>`. Any other value that is the
  name of a directory under `scenarios/` holding a `README.md` names that scenario, and its
  entry cites the permalink of that page. A pin records the file's path, the last commit
  that changed the file as of the commit the clone was read at, that commit's date and the
  file's git blob id, and for a challenge the line of its key, its id and its name. A value
  that names neither backs no entry, and the script prints each such value with its
  technique.

The validator does not read the clone;
`python3 scripts/pin_evidence_sources.py --dvaa <clone> --check` fails when the pins, or the
entries they back, differ from what the clone holds at the commit the pins record.

An entry of any other kind is refused until the validator reads its source.
`evidence-gaps.json` lists the techniques with no entry; `scripts/generate_stix.py` writes
it and the validator fails when it differs from that rendering, so a gap is closed by an
entry that resolves, never by text.

The References section of a technique's page lists each of its entries in one line,
directly under the Tactic link and in `matrix.json` order: the entry's type and date, its
reference as a link, then its note. `scripts/check_technique_pages.py` fails when a page's
Evidence lines differ from the entries in `matrix.json`, and its `--fix` writes them, so the
page cites the entries the STIX bundle carries. A technique with no entry has no Evidence
line.

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
