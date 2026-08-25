# Retroactive Privilege Exploitation (RETROACTIVE-PRIV)

**Category:** infrastructure

## Description

Exploiting previously granted access or cached credentials to gain unauthorized capabilities

## Techniques

| ID | Name | Tactic |
|----|------|--------|
| [T-1001](../techniques/T-1001.md) | Endpoint Enumeration | Reconnaissance |
| [T-1004](../techniques/T-1004.md) | Security Level Probing | Reconnaissance |
| [T-1007](../techniques/T-1007.md) | Context Window Probing | Reconnaissance |
| [T-3001](../techniques/T-3001.md) | System Prompt Credential Extraction | Credential Harvest |
| [T-3003](../techniques/T-3003.md) | Tool Response Credential Capture | Credential Harvest |
| [T-3005](../techniques/T-3005.md) | Configuration File Access | Credential Harvest |
| [T-3006](../techniques/T-3006.md) | Context Window Credential Leak | Credential Harvest |
| [T-5004](../techniques/T-5004.md) | Credential Reuse | Lateral Movement |
| [T-8005](../techniques/T-8005.md) | Conversation Exfiltration | Exfiltration |

## Detection

- **HMA Checks:** AGENT-CRED-001, API-003, API-KEY-EXPOSED, AUTH-001, AUTH-002, AUTH-003, AUTH-004, CLAUDE-001, CLAUDE-MD-EXPOSED, CLIPASS-001, CONFIG-001, CONFIG-004, CONFIG-009, CONFIG-EXPOSED, CRED-001, CRED-002, CRED-003, CRED-004, CURSOR-001, ENCRYPT-001, ENCRYPT-002, ENCRYPT-003, ENCRYPT-004, ENV-001, ENV-002, ENV-003, ENV-004, ENVLEAK-001, GIT-001, GIT-002, GIT-003, SEC-001, SEC-002, SEC-003, SEC-004, SEM-CRED-001, SEM-CRED-002, SEM-CRED-003, SEM-CRED-004, SESSION-001, SESSION-002, SESSION-003, SESSION-004, VSCODE-001, VSCODE-002, WEBCRED-001, WEBEXPOSE-001, WEBEXPOSE-002, WEBEXPOSE-003
