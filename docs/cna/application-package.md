# CNA Application Prep Package

**Status: PREP ONLY — NOT SUBMITTED.** Nothing in this package has been filed, sent, or
submitted to the CVE Program, MITRE, Red Hat, or any Root. No request has been opened and no
ticket, confirmation, or correspondence exists. This document exists so that when the owner
files, the material is already assembled.

**Owner-retained actions** (explicitly NOT performed here): submitting the CVE Request Form,
contacting MITRE or any Root, and obtaining counsel sign-off. The roadmap unit records a
queued-for-owner card at `decisions/2026-08-31-queued-cna-filing-csnp.md` for the filing itself.

## How to read this document

Every fact below comes from exactly one of two places: the roadmap unit
`roadmap/standards-cna-csnp.md` (referred to as **the unit**), or this repository. The
[Provenance](#provenance) table maps each claim to its source. Anything not recorded in either
place is written as the literal token `PLACEHOLDER` and is the owner's to fill. An empty field
is intentional; nothing here is a plausible-looking guess.

**Decision of record (from the unit):** file for CNA status scoped under CSNP (the 501c3), so
the CVE authority reads as neutral rather than attached to the commercial brand. Counsel must
confirm that operating a CNA fits CSNP's charitable purpose *before* applying.

---

## Block A — Scope statement

The scope statement exactly as the unit records it:

> AI-agent frameworks, MCP/A2A implementations, agent security tooling, agent supply-chain
> npm/PyPI — advisories from originated research

This is prereq item (1) in the unit and is one of the documents step 3 refers to.

---

## Block B — Root recommendation

**Recommended Root: Red Hat** — contact `RootCNA-Coordination@redhat.com`.

**Rationale, as cited by the unit:** Red Hat is the recommended root for open-source /
nonprofit orgs. The unit records no rationale beyond that; no additional justification has been
supplied here.

**Fallback: MITRE TL-Root**, which the unit records as fine if undecided.

`RootCNA-Coordination@redhat.com` is the only external email address in this package, and it is
recorded because the unit records it. It has not been contacted.

| Field | Value |
| --- | --- |
| Recommended Root | Red Hat |
| Red Hat Root contact | `RootCNA-Coordination@redhat.com` (unit-recorded; not contacted) |
| Fallback Root | MITRE TL-Root |
| Root selected by owner | `PLACEHOLDER` |
| Date Root selected | `PLACEHOLDER` |

---

## Block C — Prereq checklist

The five prereqs the unit records as needing to be ready before/at onboarding.

- [ ] **(1) Scope statement.** Recorded in [Block A](#block-a--scope-statement). Ready — no
      owner input required.
- [ ] **(2) Published disclosure/embargo policy URL.** `opena2a.org/security/disclosure-policy`
      — the URL the unit records. Owner to confirm the policy is published and reachable at that
      URL at filing time: `PLACEHOLDER` (confirmed / not confirmed).
- [ ] **(3) Advisory publishing location URL.** `api.oa2a.org/api/v1/registry/advisories` — the
      URL the unit records. Owner to confirm the location is live at filing time: `PLACEHOLDER`
      (confirmed / not confirmed).
- [ ] **(4) At least 2 points of contact.** The unit requires name + email for each, and a phone
      number for the primary, for KEV/emergency use. Listed by role below; every value is an
      owner placeholder.
- [ ] **(5) Counsel sign-off — OWNER-RETAINED.** Written confirmation that operating a CNA fits
      CSNP's 501c3 charitable purpose. The unit records this as a precondition of applying, and
      obtaining it is the owner's action, not this package's.

### (4) Points of contact — by role, values owner-supplied

Roles are the two contact functions the unit describes (a primary, who carries the
KEV/emergency phone, and at least one further contact). No person is named anywhere in this
package; the organizational title attached to each role is also the owner's to assign.

| Field | Primary point of contact | Second point of contact |
| --- | --- | --- |
| Role function | Primary CNA point of contact (KEV/emergency reachable) | Second CNA point of contact (alternate) |
| Organizational title | `PLACEHOLDER` | `PLACEHOLDER` |
| Name | `PLACEHOLDER` | `PLACEHOLDER` |
| Email | `PLACEHOLDER` | `PLACEHOLDER` |
| Phone | `PLACEHOLDER` (required by the unit for the primary) | `PLACEHOLDER` (the unit requires a phone only for the primary) |

The unit says "at least 2"; if the owner adds further contacts, copy a column and keep every
unsupplied value as `PLACEHOLDER`.

### (5) Counsel sign-off line — OWNER-RETAINED

> Counsel confirms that operating a CVE Numbering Authority fits CSNP's 501c3 charitable
> purpose.

| Field | Value |
| --- | --- |
| Counsel | `PLACEHOLDER` |
| Signed on | `PLACEHOLDER` |
| Status | **OWNER-RETAINED — not obtained.** The unit records this as required before applying. |

---

## Block D — Steps and refs

The unit's five steps, in the unit's order.

1. **Submit the initial request at `cveform.mitre.org`.** The unit records the first action as
   the CVE Request Form at `https://cveform.mitre.org/` → "Request Information on the CVE
   Numbering Program (CNA)". **Not submitted** — owner-retained. Date submitted:
   `PLACEHOLDER`.
2. **Pick the Root.** See [Block B](#block-b--root-recommendation). Recommendation staged;
   the selection is the owner's. Root selected: `PLACEHOLDER`.
3. **Finalize the 3 required documents.** The unit does not enumerate which three; the
   document-shaped prereqs are items (1), (2) and (3) in [Block C](#block-c--prereq-checklist)
   — scope statement, disclosure/embargo policy URL, advisory publishing location URL. That
   mapping is a reading of the unit, not something the unit records; owner to confirm against
   the onboarding guide.
4. **Line up the POCs.** See [Block C item (4)](#4-points-of-contact--by-role-values-owner-supplied).
   Roles are staged; names, emails and phone numbers are the owner's to supply.
5. **Lead the evidence with originated coordinated disclosures.** See
   [Evidence framing](#evidence-framing) below.

### Refs

The unit records these URLs for the owner to use. They have not been fetched or resolved by
this package.

| Ref | URL |
| --- | --- |
| CVE Request Form (first action) | `https://cveform.mitre.org/` |
| CNA program page | `https://www.cve.org/programorganization/cnas` |
| CNA onboarding guide | `https://cveproject.github.io/docs/cna/onboarding/` |
| CNA rules | `https://www.cve.org/resourcessupport/allresources/cnarules` |

### Evidence framing

**Lead with originated coordinated disclosures.** The unit records: NemoClaw — 10 vulnerabilities
disclosed to NVIDIA PSIRT. This repository corroborates the count: `CHANGELOG.md` lists "NVIDIA
NemoClaw security assessment (10 confirmed vulnerabilities)" among the v1.0 sources, and
`EVIDENCE_AUDIT.md` records that the five NemoClaw-specific attack classes "are all backed by the
10 confirmed code-level vulnerabilities."

**Do NOT claim CVE-2026-25253.** The unit is explicit: cite `CVE-2026-25253` only as a CVE our
tooling detects, **NOT** as ours. It is not an originated or owned CVE and must never be
presented as one. This repository does not reference `CVE-2026-25253`; the unit is its only
source here, and the unit does not name which tool detects it — so no tool is named.

**Supporting corpus, from this repository** (measured by `scripts/check_readme_claims.py`,
which is enforced in CI): 9 tactics, 61 techniques and 40 attack classes in `matrix.json`, with
evidence tiers 16 observed / 42 validated / 3 adapted.

---

## Timeline reality

Stated as the unit records it (the unit's correction of 2026-07-05):

> this is NOT "two days of form work". Minimum ~4 weeks: first contact → onboarding form → a
> 1-hour onboarding call scheduled >=3 weeks out → exercises → approval. This week you START the
> request and finalize prereq docs; a CNA cannot be assigned this week.

The onboarding call is scheduled **>=3 weeks out**, and the overall process is a **~4-week
minimum**. No CNA assignment date can be projected from this package; the unit's "done when" is
CNA assigned and listed, which it records as weeks out.

---

## Placeholder register

Everything the owner must supply. Each is `PLACEHOLDER` above because neither the unit nor this
repository records a value.

| # | Placeholder | Where |
| --- | --- | --- |
| 1 | Root selected, and the date selected | Block B |
| 2 | Confirmation that the disclosure/embargo policy URL is published | Block C (2) |
| 3 | Confirmation that the advisory publishing location URL is live | Block C (3) |
| 4 | Primary POC: organizational title, name, email, phone | Block C (4) |
| 5 | Second POC: organizational title, name, email, phone | Block C (4) |
| 6 | Counsel identity and sign-off date | Block C (5) |
| 7 | Date the CVE Request Form is submitted | Block D step 1 |
| 8 | Which three documents step 3 means, confirmed against the onboarding guide | Block D step 3 |

---

## Provenance

`unit` = `roadmap/standards-cna-csnp.md`. Repo paths are relative to this repository.

| Claim | Source |
| --- | --- |
| File for CNA under CSNP so the authority reads as neutral | unit |
| Counsel must confirm charitable-purpose fit before applying | unit |
| Queued-for-owner card at `decisions/2026-08-31-queued-cna-filing-csnp.md` | unit (Links) |
| Scope statement wording (Block A) | unit, prereq (1) |
| Red Hat recommended root for open-source / nonprofit orgs | unit |
| `RootCNA-Coordination@redhat.com` | unit |
| MITRE TL-Root is fine if undecided | unit |
| `opena2a.org/security/disclosure-policy` | unit, prereq (2) |
| `api.oa2a.org/api/v1/registry/advisories` | unit, prereq (3) |
| >=2 POCs; name+email each; phone for the primary, for KEV/emergency | unit, prereq (4) |
| Counsel sign-off on 501c3 charitable purpose | unit, prereq (5) |
| The five steps | unit, Steps |
| First action is the CVE Request Form at `cveform.mitre.org` | unit, Filing |
| The four ref URLs | unit, Filing + Refs |
| NemoClaw: 10 vulnerabilities to NVIDIA PSIRT | unit, step 5 |
| 10 confirmed NemoClaw vulnerabilities | `CHANGELOG.md`, `EVIDENCE_AUDIT.md` |
| `CVE-2026-25253` is detected, not owned | unit, step 5 (not present in this repo) |
| 9 tactics / 61 techniques / 40 attack classes; tiers 16/42/3 | `matrix.json`, verified by `scripts/check_readme_claims.py` |
| ~4-week minimum; onboarding call >=3 weeks out | unit, REALITY (corrected 2026-07-05) |
| Done when: CNA assigned and listed, weeks out | unit |

No date, contact name, email address, or phone number appears in this package other than those
listed above as unit- or repo-sourced.
