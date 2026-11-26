# CNA Application Prep Package

**Status: PREP ONLY, NOT SUBMITTED.** Nothing in this package has been filed, sent, or
submitted to the CVE Program, MITRE, Red Hat, or any Root. No request has been opened and no
ticket, confirmation, or correspondence exists. This document exists so that when CSNP, the
applicant, files, the material is already assembled.

**Actions kept by the applicant** (marked "kept by the applicant" below; explicitly NOT
performed here): submitting the CVE Request Form, contacting MITRE or any Root, and obtaining
counsel sign-off. A separate unpublished record queues the filing itself for the lead
maintainer.

## How to read this document

Three terms recur throughout:

- **The applicant** is CSNP, which applies for CNA status. The lead maintainer files the CNA
  application on CSNP's behalf.
- **The planning record** is OpenA2A's record for this filing. It is kept in a private planning
  tracker and is not published in this repository, so a claim taken from it cannot be checked
  from here. The [Provenance](#provenance) table marks every such claim `planning record`.
- **Kept by the applicant** labels an action that only the applicant may take: submitting the
  CVE Request Form, contacting MITRE or any Root, or obtaining counsel sign-off. Nothing so
  labeled has been done, and nothing in this repository does it.

Every fact below comes from exactly one of two places: the planning record or this repository.
The [Provenance](#provenance) table maps each claim to its source. Anything not recorded in
either place is written as the literal token `PLACEHOLDER` and is the applicant's to fill. An
empty field is intentional; nothing here is a plausible-looking guess.

**Decision of record:** file for CNA status scoped under CSNP (the 501c3), so the CVE authority
reads as neutral rather than attached to the commercial brand. Counsel must confirm that
operating a CNA fits CSNP's charitable purpose *before* applying.

---

## Block A: Scope statement

The scope statement, word for word:

> AI-agent frameworks, MCP/A2A implementations, agent security tooling, agent supply-chain
> npm/PyPI — advisories from originated research

This is prereq item (1) in [Block C](#block-c-prereq-checklist) and is one of the documents
step 3 refers to.

---

## Block B: Root recommendation

**Recommended Root: Red Hat** (contact `RootCNA-Coordination@redhat.com`).

**Rationale:** Red Hat is the recommended root for open-source / nonprofit orgs. No rationale
beyond that is recorded, and no additional justification has been supplied here.

**Fallback: MITRE TL-Root**, which is fine if undecided.

`RootCNA-Coordination@redhat.com` is the only external email address in this package, and it is
listed only as the Red Hat Root contact. It has not been contacted.

| Field | Value |
| --- | --- |
| Recommended Root | Red Hat |
| Red Hat Root contact | `RootCNA-Coordination@redhat.com` (from the planning record; not contacted) |
| Fallback Root | MITRE TL-Root |
| Root selected by the applicant | `PLACEHOLDER` |
| Date Root selected | `PLACEHOLDER` |

---

## Block C: Prereq checklist

The five prereqs that need to be ready before/at onboarding.

- [ ] **(1) Scope statement.** Recorded in [Block A](#block-a-scope-statement). Ready: no
      input required from the applicant.
- [ ] **(2) Published disclosure/embargo policy URL.** `opena2a.org/security/disclosure-policy`.
      Applicant to confirm the policy is published and reachable at that URL at filing time:
      `PLACEHOLDER` (confirmed / not confirmed).
- [ ] **(3) Advisory publishing location URL.** `api.oa2a.org/api/v1/registry/advisories`.
      Applicant to confirm the location is live at filing time: `PLACEHOLDER`
      (confirmed / not confirmed).
- [ ] **(4) At least 2 points of contact.** Each needs a name and an email, and the primary
      also needs a phone number, for KEV/emergency use. Listed by role below; every value is a
      placeholder for the applicant to fill.
- [ ] **(5) Counsel sign-off (kept by the applicant).** Written confirmation that operating a
      CNA fits CSNP's 501c3 charitable purpose. It is a precondition of applying, and
      obtaining it is the applicant's action, not this package's.

### (4) Points of contact: by role, values supplied by the applicant

Roles are the two contact functions required (a primary, who carries the KEV/emergency phone,
and at least one further contact). No person is named anywhere in this package; the
organizational title attached to each role is also the applicant's to assign.

| Field | Primary point of contact | Second point of contact |
| --- | --- | --- |
| Role function | Primary CNA point of contact (KEV/emergency reachable) | Second CNA point of contact (alternate) |
| Organizational title | `PLACEHOLDER` | `PLACEHOLDER` |
| Name | `PLACEHOLDER` | `PLACEHOLDER` |
| Email | `PLACEHOLDER` | `PLACEHOLDER` |
| Phone | `PLACEHOLDER` (required for the primary) | `PLACEHOLDER` (a phone is required only for the primary) |

At least 2 are required; if the applicant adds further contacts, copy a column and keep every
unsupplied value as `PLACEHOLDER`.

### (5) Counsel sign-off line (kept by the applicant)

> Counsel confirms that operating a CVE Numbering Authority fits CSNP's 501c3 charitable
> purpose.

| Field | Value |
| --- | --- |
| Counsel | `PLACEHOLDER` |
| Signed on | `PLACEHOLDER` |
| Status | **Kept by the applicant, not obtained.** Required before applying. |

---

## Block D: Steps and refs

The five steps, in order.

1. **Submit the initial request at `cveform.mitre.org`.** The first action is the CVE Request
   Form at `https://cveform.mitre.org/` → "Request Information on the CVE Numbering Program
   (CNA)". **Not submitted** (kept by the applicant). Date submitted: `PLACEHOLDER`.
2. **Pick the Root.** See [Block B](#block-b-root-recommendation). Recommendation staged;
   the selection is the applicant's. Root selected: `PLACEHOLDER`.
3. **Finalize the 3 required documents.** Which three is not enumerated; the document-shaped
   prereqs are items (1), (2) and (3) in [Block C](#block-c-prereq-checklist): scope
   statement, disclosure/embargo policy URL, advisory publishing location URL. That mapping is
   this package's reading, not a recorded list; applicant to confirm against the onboarding
   guide.
4. **Line up the POCs.** See [Block C item (4)](#4-points-of-contact-by-role-values-supplied-by-the-applicant).
   Roles are staged; names, emails and phone numbers are the applicant's to supply.
5. **Lead the evidence with originated coordinated disclosures.** See
   [Evidence framing](#evidence-framing) below.

### Refs

These URLs are for the applicant to use. They have not been fetched or resolved by this
package.

| Ref | URL |
| --- | --- |
| CVE Request Form (first action) | `https://cveform.mitre.org/` |
| CNA program page | `https://www.cve.org/programorganization/cnas` |
| CNA onboarding guide | `https://cveproject.github.io/docs/cna/onboarding/` |
| CNA rules | `https://www.cve.org/resourcessupport/allresources/cnarules` |

### Evidence framing

**Lead with originated coordinated disclosures.** NemoClaw: 10 vulnerabilities disclosed to
NVIDIA PSIRT. This repository corroborates the count: `CHANGELOG.md` lists "NVIDIA NemoClaw
security assessment (10 confirmed vulnerabilities)" among the v1.0 sources, and
`EVIDENCE_AUDIT.md` records that the five NemoClaw-specific families "are all backed by the
10 confirmed code-level vulnerabilities."

**Do NOT claim CVE-2026-25253.** Cite `CVE-2026-25253` only as a CVE our tooling detects,
**NOT** as ours. It is not an originated or owned CVE and must never be presented as one. No
other file in this repository references `CVE-2026-25253`; the planning record is its only
source here, and that record does not name which tool detects it, so no tool is named.

**Supporting corpus, from this repository** (measured by `scripts/check_readme_claims.py`,
which is enforced in CI): 9 tactics, 61 techniques and 40 families in `matrix.json`, with
evidence tiers 16 observed / 42 validated / 3 adapted.

---

## Timeline reality

Stated as recorded in the correction of 2026-07-05:

> this is NOT "two days of form work". Minimum ~4 weeks: first contact → onboarding form → a
> 1-hour onboarding call scheduled >=3 weeks out → exercises → approval. This week you START the
> request and finalize prereq docs; a CNA cannot be assigned this week.

The onboarding call is scheduled **>=3 weeks out**, and the overall process is a **~4-week
minimum**. No CNA assignment date can be projected from this package; the filing is done when
the CNA is assigned and listed, which is weeks out.

---

## Placeholder register

Everything the applicant must supply. Each is `PLACEHOLDER` above because neither the planning
record nor this repository records a value.

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

`planning record` = the unpublished record for this filing (see
[How to read this document](#how-to-read-this-document)). Repo paths are relative to this
repository.

| Claim | Source |
| --- | --- |
| File for CNA under CSNP so the authority reads as neutral | planning record |
| Counsel must confirm charitable-purpose fit before applying | planning record |
| The filing is queued for the lead maintainer in a separate unpublished record | planning record (Links) |
| Scope statement wording (Block A) | planning record, prereq (1) |
| Red Hat recommended root for open-source / nonprofit orgs | planning record |
| `RootCNA-Coordination@redhat.com` | planning record |
| MITRE TL-Root is fine if undecided | planning record |
| `opena2a.org/security/disclosure-policy` | planning record, prereq (2) |
| `api.oa2a.org/api/v1/registry/advisories` | planning record, prereq (3) |
| >=2 POCs; name+email each; phone for the primary, for KEV/emergency | planning record, prereq (4) |
| Counsel sign-off on 501c3 charitable purpose | planning record, prereq (5) |
| The five steps | planning record, Steps |
| First action is the CVE Request Form at `cveform.mitre.org` | planning record, Filing |
| The four ref URLs | planning record, Filing + Refs |
| NemoClaw: 10 vulnerabilities to NVIDIA PSIRT | planning record, step 5 |
| 10 confirmed NemoClaw vulnerabilities | `CHANGELOG.md`, `EVIDENCE_AUDIT.md` |
| `CVE-2026-25253` is detected, not owned | planning record, step 5 (named in no other file in this repo) |
| 9 tactics / 61 techniques / 40 families; tiers 16/42/3 | `matrix.json`, verified by `scripts/check_readme_claims.py` |
| ~4-week minimum; onboarding call >=3 weeks out | planning record, REALITY (corrected 2026-07-05) |
| Done when: CNA assigned and listed, weeks out | planning record |

No date, contact name, email address, or phone number appears in this package other than those
listed above as sourced from the planning record or this repository.
