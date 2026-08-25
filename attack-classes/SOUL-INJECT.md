# SOUL/System Prompt Injection (SOUL-INJECT)

**Category:** governance

## Description

Directly manipulating or overriding the agent's system-level instructions and behavioral boundaries

## Techniques

| ID | Name | Tactic |
|----|------|--------|
| [T-1003](../techniques/T-1003.md) | System Prompt Extraction | Reconnaissance |
| [T-2001](../techniques/T-2001.md) | Direct Prompt Injection | Initial Access |
| [T-2003](../techniques/T-2003.md) | Role-Play Jailbreak | Initial Access |
| [T-2007](../techniques/T-2007.md) | Multi-Turn Manipulation | Initial Access |
| [T-2008](../techniques/T-2008.md) | System Prompt Boundary Bypass | Initial Access |

## Detection

- **HMA Checks:** CLAUDE-002, CLAUDE-003, CLAUDE-004, CLAUDE-006, CLAUDE-007, CONFIG-002, CONFIG-007, PROMPT-001, PROMPT-002, PROMPT-003, PROMPT-004, SEM-INST-001, SEM-INST-002, SEM-INST-003, SEM-INST-004, SEM-PERM-001, SEM-PERM-002, SOUL-IH-001, SOUL-IH-002, SOUL-OVERRIDE-001, TOOL-001, TOOL-002, TOOL-003, TOOL-004
