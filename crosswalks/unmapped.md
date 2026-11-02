# Agent-layer residue: techniques neither framework models at technique level

This list is derived from `matrix.json`: it is exactly the techniques whose `attackMapping`
and `atlasMapping` are both empty, read against MITRE ATT&CK Enterprise 20.0 and MITRE ATLAS
release 2026.09 (the releases named in `attack-release.json` and `atlas-release.json`).

A technique is listed here when no technique or sub-technique of either release relates to it
at all, an associative relation included; a technique whose nearest external technique is only
associated with it carries a `relatedMatch` entry instead. These sit at the agent
infrastructure layer that neither the model layer (ATLAS) nor the enterprise layer (ATT&CK)
names at the technique grain. The gap is the finding: it is where the agent layer carries
attack surface the two external catalogs do not yet reach.

| ID | Technique | The agent-layer property neither release names |
|----|-----------|------------------------------------------------|
| T-1007 | Context Window Probing | The agent's token budget. Neither release names measuring context-window size to plan an overflow. |
| T-9004 | Multi-Agent Consensus Manipulation | The multi-agent consensus mechanism. No ATT&CK or ATLAS technique names poisoning a voting or consensus process across agents. |

ATLAS release 2026.09 does name autonomous agent-to-agent communication (AML.T0118), but as the
adversary's coordination of their own agents carrying out an attack, not an attack on a
victim's multi-agent system, so T-9004 remains unmapped.

Membership is checked by a local test that no workflow runs. Run it with
`python3 -m pytest -q tests/test_crosswalks.py`: it asserts that the ids in the first column of
the table above equal the techniques in `matrix.json` carrying no mapping, so removing a row,
or adding one for a technique that carries a mapping, fails it.
