# Credential Harvest

**Kill Chain Stage:** 3

## Description

Extract API keys, tokens, and credentials from agent context and connected services

## Techniques

| ID | Name | Evidence tier | Attack class |
|----|------|---------------|--------------|
| [T-3001](../techniques/T-3001.md) | System Prompt Credential Extraction | observed | RETROACTIVE-PRIV |
| [T-3002](../techniques/T-3002.md) | Environment Variable Leakage | observed | NEMO-CRED-LEAK |
| [T-3003](../techniques/T-3003.md) | Tool Response Credential Capture | validated | RETROACTIVE-PRIV |
| [T-3004](../techniques/T-3004.md) | Memory Credential Mining | validated | MEM-POISON |
| [T-3005](../techniques/T-3005.md) | Configuration File Access | observed | RETROACTIVE-PRIV |
| [T-3006](../techniques/T-3006.md) | Context Window Credential Leak | validated | RETROACTIVE-PRIV |
