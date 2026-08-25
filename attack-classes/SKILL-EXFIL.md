# Skill-Based Exfiltration (SKILL-EXFIL)

**Category:** supply-chain

## Description

Using legitimate tool capabilities for unauthorized data transfer

## Techniques

| ID | Name | Tactic |
|----|------|--------|
| [T-5001](../techniques/T-5001.md) | SSRF via Tool | Lateral Movement |
| [T-7003](../techniques/T-7003.md) | API Data Harvesting | Collection |
| [T-8001](../techniques/T-8001.md) | Email Exfiltration | Exfiltration |
| [T-8002](../techniques/T-8002.md) | HTTP Callback | Exfiltration |
| [T-8003](../techniques/T-8003.md) | DNS Exfiltration | Exfiltration |
| [T-8004](../techniques/T-8004.md) | Tool Chain Exfiltration | Exfiltration |
| [T-8006](../techniques/T-8006.md) | Webhook Exfiltration | Exfiltration |

## Detection

- **HMA Checks:** AST-EXFIL-001, NET-001, NET-002, NET-003, NET-004, NET-005, NET-006, SKILL-006, SKILL-021, SKILL-022, SKILL-024
