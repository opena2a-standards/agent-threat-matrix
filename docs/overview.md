# Overview

## Purpose

AI agents operate differently from traditional software. They make decisions based on natural language, delegate actions to tools with varying trust levels, communicate with other agents via open protocols, and maintain persistent memory that can be poisoned. These properties create attack surfaces that existing frameworks do not adequately model.

The **AI Agent Threat Matrix** classifies attacks against AI agent systems into 9 tactics and 61 techniques, organized by kill chain stage. Every technique carries an explicit evidence tier: observed in the wild, validated in a controlled lab environment, or adapted from a traditional environment and marked as such. Every technique maps to automated detection and a defensive control; 58 of the 61 also carry a reproducible lab scenario.

### What This Covers (and What It Doesn't)

This matrix covers the **agent layer**, the infrastructure between the model and the user:

- Governance file manipulation (SOUL.md, system prompts, behavioral constraints)
- Skill and plugin supply chain attacks
- MCP and A2A protocol exploitation
- Agent memory poisoning and persistence
- Credential exposure through agent infrastructure
- Sandbox escape via framework defaults
- Cross-agent lateral movement and identity attacks

This matrix does **not** cover:

- Model-level attacks (adversarial examples, training data poisoning): see [MITRE ATLAS](https://atlas.mitre.org/), which also names some agent techniques; [the ATLAS mapping](../cross-references/mitre-atlas-mapping.md) relates its tactics to this matrix's
- Prompt injection as a standalone topic: see [OWASP Top 10 for LLM](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- Traditional enterprise network attacks: see [MITRE ATT&CK](https://attack.mitre.org/)

The Agent Threat Matrix is designed to work **alongside** these frameworks, not replace them.
