# Agent-layer residue: techniques neither framework models at technique level

This list is derived from `matrix.json`: it is exactly the techniques whose `attackMapping`
and `atlasMapping` are both empty, read against MITRE ATT&CK Enterprise 20.0 and MITRE ATLAS
release 2026.09 (the releases named in `attack-release.json` and `atlas-release.json`).

A technique is listed here when no technique or sub-technique of either release denotes the
same object and effect. These sit at the agent infrastructure layer that neither the model
layer (ATLAS) nor the enterprise layer (ATT&CK) names at the technique grain. The gap is the
finding: it is where the agent layer carries attack surface the two external catalogs do not
yet reach.

| ID | Technique | The agent-layer property neither release names |
|----|-----------|------------------------------------------------|
| T-1006 | Agent Card Discovery | The A2A identity surface. No ATT&CK or ATLAS technique names agent cards or `/.well-known/agent.json`. |
| T-1007 | Context Window Probing | The agent's token budget. Neither release names measuring context-window size to plan an overflow. |
| T-2009 | Parser Differential Exploitation | The agent's multi-parser input path. Neither release names a disagreement between parsers over the same bytes. |
| T-4004 | Delegation Abuse | The agent-to-agent authorization chain. Neither release names delegation across a trusted agent chain. |
| T-5002 | A2A Agent Pivoting | The A2A peer connection. No ATT&CK or ATLAS technique names pivoting between agents over A2A. |
| T-7007 | Context Assembly Pipeline Attack | The system-prompt assembly pipeline. Neither release names tampering with a component that the agent combines into its final context. |
| T-9004 | Multi-Agent Consensus Manipulation | The multi-agent consensus mechanism. No ATT&CK or ATLAS technique names poisoning a voting or consensus process across agents. |

ATLAS release 2026.09 does name autonomous agent-to-agent communication (AML.T0118), but as the
adversary's coordination of their own agents carrying out an attack, not an attack on a
victim's multi-agent system, so T-4004, T-5002 and T-9004 remain unmapped. ATLAS AML.T0119
names exploiting an automated artifact-processing pipeline at ingest, which is a different
surface from the in-agent prompt-assembly pipeline T-7007 targets.

Membership is checked in CI-shaped tests: `tests/test_crosswalks.py` asserts this list equals
the set of techniques in `matrix.json` carrying no mapping, so an entry cannot drift from the
data.
