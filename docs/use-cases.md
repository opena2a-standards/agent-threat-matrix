# Use cases

Situations the matrix is used in, what you can do today in each, and where it stops.

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

Why you can check this yourself: [`matrix.json`](../matrix.json) and its schema in [`schema/`](../schema/); [`scripts/validate_matrix.py`](../scripts/validate_matrix.py); the per-technique justification in [`EVIDENCE_AUDIT.md`](../EVIDENCE_AUDIT.md); the STIX bundle in [`stix/`](../stix/); the rendered site at [threats.opena2a.org](https://threats.opena2a.org); and the live API at `https://api.oa2a.org/api/v1/threat-matrix`.
