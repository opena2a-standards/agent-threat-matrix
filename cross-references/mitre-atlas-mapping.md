# MITRE ATLAS: Agent Threat Matrix Mapping

This document maps the tactics of [MITRE ATLAS](https://atlas.mitre.org/) (Adversarial Threat Landscape for AI Systems) to AI Agent Threat Matrix (ATM) tactics. It is read against **ATLAS release 2026.09** (released 2026-09-15; data in [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data)), which holds 16 tactics. This mapping is an analyst reading that relates the two at the tactic grain; its mapping table names no technique ids. A technique-grain crosswalk belongs in the optional `atlasMapping` field of each technique in [matrix.json](../matrix.json).

The ATLAS release notes describe ATLAS as a knowledge base of "adversary tactics and techniques involving AI, including attacks against AI-enabled systems, abuse or manipulation of AI capabilities, and harmful autonomous behavior materially enabled by AI". It is not limited to models. ATLAS release 2026.09 has 28 techniques and sub-techniques with "Agent" in the name (ATLAS 5.6.0 has 20), for example Modify AI Agent Configuration, Credentials from AI Agent Configuration and AI Agent Tool Invocation. ATM is limited to the **agent infrastructure layer**, from governance files through multi-agent communication.

**Versions.** ATLAS 5.6.0 (2026-04-30) holds the same 16 tactic ids. One has been renamed since: AML.TA0001, "AI Attack Staging" in 5.6.0, is "AI Attack Adaptation" from release 2026.08. The release 2026.09 matrix lists it third, after Resource Development; 5.6.0 listed it after Collection. This page previously listed AML.TA0000 as "ML Model Access" and AML.TA0007 as "Evasion"; ATLAS names them "AI Model Access" and "Defense Evasion". The table below uses the release 2026.09 names and matrix order.

---

## Tactic-Level Mapping

| ATLAS Tactic | ATM Tactic(s) | Overlap | Notes |
|-------------|---------------|---------|-------|
| **Reconnaissance** (AML.TA0002) | Reconnaissance (Stage 1) | High | Both address target enumeration. ATLAS names searching public research, vulnerability analyses, application repositories and victim websites, gathering RAG-indexed targets, and active scanning, including probing AI agent trigger channels. ATM names agent endpoint enumeration, tool discovery, system prompt extraction, security level probing, capability mapping, agent card discovery and context window probing. |
| **Resource Development** (AML.TA0003) | None | None | ATLAS names adversary preparation: acquiring public AI artifacts (including AI agent configurations), obtaining and developing capabilities (including AI agent tools), establishing accounts and infrastructure, and publishing poisoned AI artifacts. ATM does not model attacker-side preparation; it starts when a prepared artifact reaches an agent (Initial Access and Persistence rows). |
| **AI Attack Adaptation** (AML.TA0001) | None | None | Named "AI Attack Staging" in ATLAS 5.6.0. ATLAS names the adversary turning capabilities and target knowledge into attack-ready outputs: proxy models, adversarial data, crafted prompts and retrieval content, deepfakes, generated malicious commands, and the tasking and coordination of the adversary's own autonomous agents. ATM does not model attacker-side preparation; crafted prompts and retrieval content arrive in ATM as Initial Access (direct and indirect prompt injection). |
| **Initial Access** (AML.TA0004) | Initial Access (Stage 2) | Medium | ATLAS names AI supply chain compromise (including AI agent tools), valid accounts, exploiting public-facing applications, phishing, drive-by compromise, prompt infiltration via public-facing applications, crafted AI assistant links, and misconfigured or publicly exposed AI services. ATM names agent-input attacks: direct and indirect prompt injection, role-play jailbreak, context window exploitation, tool description injection, Unicode and encoding bypass, multi-turn manipulation, system prompt boundary bypass and parser differential exploitation. ATLAS places LLM prompt injection itself under Execution. |
| **AI Model Access** (AML.TA0000) | None | None | ATLAS names inference API access, full model access, physical environment access, and access through an AI-enabled product or service. ATM starts at the agent layer above the model and does not model access to the model itself. |
| **Execution** (AML.TA0005) | Initial Access (Stage 2), Privilege Escalation (Stage 4) | Medium | ATLAS names user execution of unsafe AI artifacts, command and scripting interpreters, LLM prompt injection, AI agent tool invocation, AI agent clickbait and deploying an AI agent. ATM has no Execution tactic: prompt injection sits in Initial Access, and making an agent invoke tools to attacker-chosen effect (capability override, tool parameter injection) sits in Privilege Escalation. |
| **Persistence** (AML.TA0006) | Persistence (Stage 6) | High | ATLAS names model and training data poisoning, LLM prompt self-replication, RAG poisoning, AI agent context poisoning (memory and thread), modifying AI agent configuration, and AI agent tool and tool data poisoning. ATM names memory injection, self-replicating memory entries, configuration modification, skill/plugin backdoors, scheduled task injection, tool registration persistence and persistent agent state manipulation. |
| **Privilege Escalation** (AML.TA0012) | Privilege Escalation (Stage 4) | Medium | ATLAS names valid accounts, AI agent tool invocation, LLM jailbreak and escape to host. ATM names capability override, admin impersonation, tool parameter injection, delegation abuse, policy bypass via encoding, safety instruction displacement, and tool impersonation and squatting. Escape to host relates to the sandbox escape attack class listed below. |
| **Defense Evasion** (AML.TA0007) | Initial Access (Stage 2), Privilege Escalation (Stage 4) | Medium | ATLAS names evading AI models, LLM jailbreak, LLM prompt obfuscation, false RAG entry injection, impersonation and masquerading, modifying AI agent configuration, manipulating LLM chat history, delayed execution of LLM instructions, sandbox evasion, and AI supply chain rug pulls and reputation inflation. ATM places evasion inside the tactic it serves: Unicode and encoding bypass, context window exploitation and multi-turn manipulation in Initial Access; policy bypass via encoding and safety instruction displacement in Privilege Escalation. |
| **Credential Access** (AML.TA0013) | Credential Harvest (Stage 3) | High | ATLAS names unsecured credentials, RAG credential harvesting, credentials from AI agent configuration, OS credential dumping, AI agent tool credential harvesting, exploitation for credential access and stealing web session cookies. ATM names credentials read from system prompts, environment variables, tool responses, agent memory, configuration files and the context window. Both name credentials taken from agent configuration and from tool output. |
| **Discovery** (AML.TA0008) | Reconnaissance (Stage 1), Collection (Stage 7) | Medium | ATLAS names discovering AI artifacts, model ontology and family, model outputs, LLM hallucinations, LLM system information, enterprise resources and environment, AI agent configuration and AI agent runtime capabilities. ATM names tool discovery and capability mapping in Reconnaissance, and file system enumeration and configuration harvesting in Collection. |
| **Lateral Movement** (AML.TA0015) | Lateral Movement (Stage 5) | Medium | ATLAS names valid accounts, phishing, AI agent tool invocation, alternate authentication material and exploitation of remote services, and its tactic description names AI agents and AI operations infrastructure as pivot targets. ATM names SSRF via tool, A2A agent pivoting, MCP server hopping, credential reuse, database pivoting and internal API discovery. |
| **Collection** (AML.TA0009) | Collection (Stage 7) | Medium | ATLAS names AI artifact collection, data from information repositories, the local system and AI services (including AI agent tools), automated collection and staged data. ATM names file system enumeration, database extraction, API data harvesting, memory dump, configuration harvesting, PII discovery and context assembly pipeline attacks. |
| **Command and Control** (AML.TA0014) | Persistence (Stage 6), Exfiltration (Stage 8) | Low | ATLAS names cyber communication channels, AI service APIs and web interfaces, AI artifact repositories, and AI agents on the victim's system used as command and control agents. ATM has no Command and Control tactic. Its nearest techniques keep an agent under attacker instruction (memory injection, configuration modification, scheduled task injection) or open an outbound channel (HTTP callback, webhook exfiltration). |
| **Exfiltration** (AML.TA0010) | Exfiltration (Stage 8) | High | ATLAS names exfiltration via the AI inference API and via cyber means, extracting the LLM system prompt, LLM data leakage, LLM response rendering and exfiltration via AI agent tool invocation. ATM names email, HTTP callback, DNS, tool chain, conversation and webhook exfiltration. ATLAS places system prompt extraction under Exfiltration; ATM places it under Reconnaissance. |
| **Impact** (AML.TA0011) | Impact (Stage 9) | Medium | ATLAS names evading AI models, denial of AI service, eroding model and dataset integrity, cost harvesting, chaff data, external harms, data destruction via AI agent tool invocation, machine compromise (including a local AI agent) and AI agent response biasing. ATM names data manipulation, service disruption, malicious code deployment, multi-agent consensus manipulation, reputation poisoning and supply chain compromise. |

---

## ATLAS areas with no ATM counterpart

These are model-layer, ML-pipeline and attacker-side concerns outside the agent infrastructure scope.

| ATLAS Area | Description | Why ATM Excludes It |
|-----------|-------------|---------------------|
| AI Model Access | Inference API, full model and physical environment access to a model | Model layer: ATM starts at the agent above the model |
| Adversarial Examples | Crafted inputs that cause misclassification (ATLAS: Craft Adversarial Data, Evade AI Model) | Model inference layer, not agent infrastructure |
| Model Extraction | Querying a model to reconstruct its weights/architecture | Model IP theft, not agent behavior |
| Training Data Poisoning | Corrupting training datasets to insert backdoors | Model training pipeline, not agent runtime |
| Model Backdoors | Trojans embedded in model weights (ATLAS: Manipulate AI Model) | Model layer: agents use models but don't control their weights |
| Data Poisoning | Manipulating datasets used for training or fine-tuning | Training pipeline, not agent operational layer |
| Model Inversion | Extracting training data from model outputs | Model privacy, not agent infrastructure |
| Resource Development | Adversary acquiring AI artifacts, capabilities, infrastructure and accounts | Attacker-side preparation, outside agent defensive scope |
| AI Attack Adaptation | Proxy models, adversarial data, crafted prompts, deepfakes, and the adversary's own autonomous agents | Attacker-side preparation, outside agent defensive scope |
| AI Supply Chain Compromise (model and data artifacts) | Compromised model registries, poisoned pre-trained models and datasets | Model distribution. The AI agent tool sub-technique of the same ATLAS technique is agent-layer; ATM names that part as tool description injection, skill/plugin backdoor and supply chain compromise |

---

## ATM areas ATLAS names in part or not at all

These are agent-infrastructure attack surfaces that emerge when an ML model is embedded in an autonomous agent system. ATLAS release 2026.09 names some of them at the technique level. Each subsection states the nearest ATLAS names and what ATLAS does not name; "no ATLAS technique names X" means no technique or sub-technique name or description in ATLAS release 2026.09 uses the term.

### Governance attack classes

| Attack class | Description |
|-------------|-------------|
| SOUL-POISON | Malicious instructions injected into governance files (SOUL.md, CLAUDE.md) at write-time |
| SOUL-DRIFT | Multi-turn sequences gradually eroding behavioral boundaries |
| SOUL-INJECT | Conflicting instructions via tool outputs or indirect channels |
| PHANTOM-SOUL | Agent deployed with zero behavioral constraints |
| SOUL-FORK | Different behavior under evaluation vs production |
| SOUL-HIJACK | External content achieving governance override |
| SOUL-BOUNDARY | Exploiting ambiguous constraint definitions |
| SOUL-DELEGATE | Delegation without authorization chain verification |
| SOUL-IMPERSONATE | False capability claims beyond authorization |
| SOUL-HV | Harm avoidance override variants |

Governance files exist only in LLM-based agents that use natural language behavioral constraints. The nearest ATLAS names are Modify AI Agent Configuration (Persistence, Defense Evasion), whose description includes changes to the system prompt, and LLM Jailbreak (Privilege Escalation, Defense Evasion). No ATLAS technique names governance files as such.

### Agent memory attacks

| ATM Technique | Description |
|--------------|-------------|
| T-6001 Memory Injection | Persistent instructions planted in agent memory surviving session restarts |
| T-6002 Self-Replicating Memory Entry | Memory entries that re-inject themselves when recalled |
| T-3004 Memory Credential Mining | Extracting credentials from agent memory stores |
| T-7004 Memory Dump | Enumerating all entries in agent memory |

ATLAS names memory manipulation: AI Agent Context Poisoning, with its Memory and Thread sub-techniques, is an ATLAS Persistence technique. ATM also treats agent memory as a store that credential mining and memory dumps read from (Credential Harvest, Collection).

### Multi-Agent Protocol Attacks

| ATM Technique | Description |
|--------------|-------------|
| T-1006 Agent Card Discovery | Discovering agent capabilities via A2A protocol (/.well-known/agent.json) |
| T-5002 A2A Agent Pivoting | Lateral movement from compromised agent to peer agents via A2A protocol |
| T-9004 Multi-Agent Consensus Manipulation | Poisoning voting/consensus mechanisms in multi-agent decision systems |
| T-4004 Delegation Abuse | Exploiting agent-to-agent delegation without authorization chain verification |

ATLAS has a Lateral Movement tactic, which this mapping relates to ATM Lateral Movement, and its description names AI agents as pivot targets. No ATLAS technique names the A2A protocol, agent cards or multi-agent consensus. ATLAS's Autonomous AI Agent Communication technique (AI Attack Adaptation) describes communication between autonomous agents carrying out an attack, not attacks on a victim's multi-agent system.

### Skill/Plugin Supply Chain (agent-specific)

| ATM Technique | Description |
|--------------|-------------|
| T-2005 Tool Description Injection | Malicious instructions in MCP tool descriptions |
| T-6004 Skill/Plugin Backdoor | Backdoor installed via compromised skill package |
| T-6006 Tool Registration Persistence | Malicious tool registered in agent's tool catalog |
| T-5003 MCP Server Hopping | Pivoting between MCP servers in a tool chain |

ATLAS names this layer at the technique level. AI Agent Tool Poisoning (Persistence) describes poisoning a tool's model-visible definition, implementation or runtime responses, and lists MCP servers and agent skills among the tools; AI Supply Chain Compromise has an AI Agent Tool sub-technique (Initial Access). ATM names the agent-side mechanics: description injection, skill backdoors, tool registration persistence and hopping between MCP servers.

### Sandbox and Runtime Exploitation (agent-specific)

| Attack class | Description |
|-------------|-------------|
| NEMO-SANDBOX-ESCAPE | Docker privileged mode, Landlock LSM degradation |
| NEMO-OPENCLAW-INHERIT | Inherited platform flaws surviving sandboxing |
| NEMO-NETWORK-EXPOSE | Network services bound to public interfaces |
| NEMO-CRED-LEAK | Credential exposure in agent runtime configuration |

ATLAS names the sandbox boundary in general terms: Escape to Host (Privilege Escalation) and Virtualization/Sandbox Evasion (Defense Evasion). Misconfigured or Publicly Exposed AI Services (Initial Access) is the nearest ATLAS name for exposed network services, and Credentials from AI Agent Configuration (Credential Access) for runtime credential exposure. No ATLAS technique names Docker or Landlock.

### Agent-Specific Exfiltration Channels

| ATM Technique | Description |
|--------------|-------------|
| T-8004 Tool Chain Exfiltration | Chaining read_file + fetch_url to bypass single-tool restrictions |
| T-8005 Conversation Exfiltration | Data extracted through conversation responses to the requesting user |
| T-8006 Webhook Exfiltration | Pre-allowed messaging APIs (Telegram, Slack) used from within sandboxed agents |

ATLAS names exfiltration through agent channels: Exfiltration via AI Agent Tool Invocation, LLM Response Rendering and LLM Data Leakage (Exfiltration). ATM separates the channels: chains of individually allowed tools, conversation responses, and pre-allowed webhook APIs.

### Unicode Steganography (agent-specific application)

| ATM Technique | Description |
|--------------|-------------|
| T-2006 Unicode/Encoding Bypass | Invisible Unicode characters encoding instructions in source code or tool outputs |
| T-4005 Policy Bypass via Encoding | Unicode steganography bypassing regex-based governance policy filters |

Confirmed in the wild (os-info-checker npm attack, May 2025). The nearest ATLAS name is LLM Prompt Obfuscation (Defense Evasion), which describes hiding prompt injections from humans, guardrails and other detection mechanisms. No ATLAS technique names Unicode or steganography.

---

## Summary

The two readings are complementary. ATLAS names attacks on AI systems from training through inference and, in recent releases, a set of attacks on AI agents. ATM is limited to the agent infrastructure layer, from governance files through multi-agent communication. An organization deploying AI agents draws on both: ATLAS for the model layer and the agent techniques it names, and ATM for the agent layer built on top of the model.
