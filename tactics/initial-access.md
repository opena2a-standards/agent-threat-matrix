# Initial Access

**Kill Chain Stage:** 2

## Description

Gain control over agent behavior through prompt manipulation or input exploitation

## Techniques

| ID | Name | Evidence tier | Attack class |
|----|------|---------------|--------------|
| [T-2001](../techniques/T-2001.md) | Direct Prompt Injection | observed | SOUL-INJECT |
| [T-2002](../techniques/T-2002.md) | Indirect Prompt Injection | observed | RAG-POISON |
| [T-2003](../techniques/T-2003.md) | Role-Play Jailbreak | observed | SOUL-INJECT |
| [T-2004](../techniques/T-2004.md) | Context Window Exploitation | validated | SOUL-DRIFT |
| [T-2005](../techniques/T-2005.md) | Tool Description Injection | validated | SKILL-FRONTMATTER |
| [T-2006](../techniques/T-2006.md) | Unicode/Encoding Bypass | observed | UNICODE-STEGO |
| [T-2007](../techniques/T-2007.md) | Multi-Turn Manipulation | validated | SOUL-INJECT |
| [T-2008](../techniques/T-2008.md) | System Prompt Boundary Bypass | validated | SOUL-INJECT |
| [T-2009](../techniques/T-2009.md) | Parser Differential Exploitation | validated | PARSER-DIFFERENTIAL |
