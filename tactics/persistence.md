# Persistence

**Kill Chain Stage:** 6

## Description

Establish persistent access surviving restarts and session changes

## Techniques

| ID | Name | Evidence tier | Attack class |
|----|------|---------------|--------------|
| [T-6001](../techniques/T-6001.md) | Memory Injection | validated | MEM-POISON |
| [T-6002](../techniques/T-6002.md) | Self-Replicating Memory Entry | validated | MEM-POISON |
| [T-6003](../techniques/T-6003.md) | Configuration Modification | observed | GATEWAY-EXPLOIT |
| [T-6004](../techniques/T-6004.md) | Skill/Plugin Backdoor | validated | SKILL-FRONTMATTER |
| [T-6005](../techniques/T-6005.md) | Scheduled Task Injection | observed | HEARTBEAT-RCE |
| [T-6006](../techniques/T-6006.md) | Tool Registration Persistence | validated | SKILL-FRONTMATTER |
| [T-6007](../techniques/T-6007.md) | Persistent Agent State Manipulation | validated | PERSIST-STATE |
