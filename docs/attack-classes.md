# Attack classes

## Attack Classes (40)

Attack classes group related techniques by the underlying vulnerability pattern. The tables below are rendered from [`matrix.json`](../matrix.json): `python3 scripts/check_readme_claims.py` fails when they differ, and `--fix` re-renders them. Each page in [attack-classes/](../attack-classes/) names the class's techniques and the HMA checks mapped to it. Real-world evidence is recorded per technique in [EVIDENCE_AUDIT.md](../EVIDENCE_AUDIT.md).

<!-- BEGIN GENERATED: attack-class-tables -->

### Governance (11 classes)
| Class | Description | Techniques |
|-------|-------------|------------|
| [ASSEMBLY-INJECT](../attack-classes/ASSEMBLY-INJECT.md) | Attacks targeting the system prompt assembly process where components combine into exploitable injections | T-7007 |
| [PHANTOM-SOUL](../attack-classes/PHANTOM-SOUL.md) | Agent deployed with zero behavioral constraints: no SOUL.md, no system prompt, no governance | T-1006 |
| [SOUL-BOUNDARY](../attack-classes/SOUL-BOUNDARY.md) | Exploiting ambiguous or incomplete constraint definitions to find unguarded actions | T-2008 |
| [SOUL-DELEGATE](../attack-classes/SOUL-DELEGATE.md) | Exploiting delegation and capability transfer mechanisms to exceed authorized scope | T-4001 |
| [SOUL-DRIFT](../attack-classes/SOUL-DRIFT.md) | Gradually displacing safety instructions from the active context through conversation manipulation | T-2004, T-4006 |
| [SOUL-FORK](../attack-classes/SOUL-FORK.md) | Different behavior under evaluation vs production: agent passes safety tests but behaves differently in deployment | T-5002 |
| [SOUL-HIJACK](../attack-classes/SOUL-HIJACK.md) | External content achieving full override of agent behavioral constitution | T-4002, T-5002 |
| [SOUL-HV](../attack-classes/SOUL-HV.md) | Techniques to bypass agent harm avoidance constraints (4 sub-types) | T-2001, T-2003 |
| [SOUL-IMPERSONATE](../attack-classes/SOUL-IMPERSONATE.md) | False capability claims exceeding actual authorization level | T-4002 |
| [SOUL-INJECT](../attack-classes/SOUL-INJECT.md) | Directly manipulating or overriding the agent's system-level instructions and behavioral boundaries | T-1003, T-2001, T-2003, T-2007, T-2008 |
| [SOUL-POISON](../attack-classes/SOUL-POISON.md) | Malicious instructions injected into governance files at write-time | T-2001, T-2003, T-2007, T-2008 |

### Supply Chain (11 classes)
| Class | Description | Techniques |
|-------|-------------|------------|
| [FAKETOOL-INJECT](../attack-classes/FAKETOOL-INJECT.md) | MCP tool impersonation, squatting, and schema poisoning attacks | T-4007 |
| [HEARTBEAT-RCE](../attack-classes/HEARTBEAT-RCE.md) | Exploiting scheduled task or heartbeat mechanisms to achieve persistent code execution | T-6005, T-9003 |
| [MEM-POISON](../attack-classes/MEM-POISON.md) | Injecting malicious entries into agent persistent memory to maintain control across sessions | T-2002, T-3004, T-6001, T-6002, T-7004 |
| [ORG-SKILL-SPREAD](../attack-classes/ORG-SKILL-SPREAD.md) | Propagating malicious capabilities across an organization's agent fleet through shared skills and registries | T-9002, T-9004, T-9005, T-9006 |
| [PERSIST-STATE](../attack-classes/PERSIST-STATE.md) | Cross-session persistence via memory poisoning, state tampering, and cached context injection | T-6007 |
| [RAG-POISON](../attack-classes/RAG-POISON.md) | Injecting malicious content into retrieval-augmented generation data sources | T-2002, T-7006 |
| [SKILL-EXFIL](../attack-classes/SKILL-EXFIL.md) | Using legitimate tool capabilities for unauthorized data transfer | T-5001, T-7003, T-8001, T-8002, T-8003, T-8004, T-8006 |
| [SKILL-FRONTMATTER](../attack-classes/SKILL-FRONTMATTER.md) | Embedding malicious instructions in skill or plugin metadata and description fields | T-2005, T-6004, T-6006 |
| [SKILL-MEM-AMP](../attack-classes/SKILL-MEM-AMP.md) | Skill plants payload in agent memory that survives skill uninstall: cross-session persistence | T-3004 |
| [SUPPLY-CHAIN-INSTALL](../attack-classes/SUPPLY-CHAIN-INSTALL.md) | Unsigned installation scripts executed without integrity verification: curl\|sh without checksum | T-9003 |
| [UNICODE-STEGO](../attack-classes/UNICODE-STEGO.md) | Using invisible Unicode characters, homoglyphs, and encoding tricks to bypass filters | T-2006, T-4005 |

### Infrastructure (10 classes)
| Class | Description | Techniques |
|-------|-------------|------------|
| [A2A-EXPOSE](../attack-classes/A2A-EXPOSE.md) | Agent-to-Agent protocol endpoints publicly discoverable without access control | T-1006, T-5002 |
| [AITOOL-EXPOSE](../attack-classes/AITOOL-EXPOSE.md) | AI development tools (Jupyter, MLflow, Gradio, Streamlit) exposed without authentication | T-1001, T-1004, T-1005 |
| [CODE-INJECTION](../attack-classes/CODE-INJECTION.md) | Injecting and executing arbitrary code through SQL injection, command injection, or code generation | T-7002, T-9001 |
| [GATEWAY-EXPLOIT](../attack-classes/GATEWAY-EXPLOIT.md) | Modifying gateway or proxy configurations to intercept, redirect, or manipulate agent traffic | T-6003 |
| [INTEGRITY-BYPASS](../attack-classes/INTEGRITY-BYPASS.md) | Digest or hash verification bypass on empty or missing values: tampered artifacts pass silently | T-9001 |
| [LLM-EXPOSE](../attack-classes/LLM-EXPOSE.md) | LLM inference endpoints exposed without authentication, allowing arbitrary prompt execution | T-1001, T-1004 |
| [MCP-EXPLOIT](../attack-classes/MCP-EXPLOIT.md) | Attacking Model Context Protocol server configurations, tool registrations, and inter-server trust | T-1002, T-1005, T-4003, T-5003, T-5005, T-5006 |
| [PARSER-DIFFERENTIAL](../attack-classes/PARSER-DIFFERENTIAL.md) | Exploits differences between parser implementations to bypass security controls | T-2009 |
| [RETROACTIVE-PRIV](../attack-classes/RETROACTIVE-PRIV.md) | Exploiting previously granted access or cached credentials to gain unauthorized capabilities | T-1001, T-1004, T-1007, T-3001, T-3003, T-3005, T-3006, T-5004, T-8005 |
| [TOCTOU-RACE](../attack-classes/TOCTOU-RACE.md) | Time-of-check-time-of-use race between verification and execution: swap window for attackers | T-9001 |

### NemoClaw-Specific (5 classes)
| Class | Description | Techniques |
|-------|-------------|------------|
| [NEMO-CRED-LEAK](../attack-classes/NEMO-CRED-LEAK.md) | Unintended exposure of credentials through environment variables, logs, or error messages | T-3002, T-7005 |
| [NEMO-NETWORK-EXPOSE](../attack-classes/NEMO-NETWORK-EXPOSE.md) | NemoClaw network services bound to public interfaces: gateway, k3s API, mDNS beacons | T-1001, T-1004, T-5001 |
| [NEMO-OPENCLAW-INHERIT](../attack-classes/NEMO-OPENCLAW-INHERIT.md) | Inherited OpenClaw flaws that survive NemoClaw sandboxing: heartbeat persistence, pre-allowed APIs | T-1001 |
| [NEMO-SANDBOX-ESCAPE](../attack-classes/NEMO-SANDBOX-ESCAPE.md) | Breaking out of agent sandbox restrictions to access the underlying file system or OS | T-7001 |
| [NEMO-SUPPLY-CHAIN](../attack-classes/NEMO-SUPPLY-CHAIN.md) | Compromising upstream dependencies or infrastructure to affect downstream agent deployments | T-9006 |

### Identity (2 classes)
| Class | Description | Techniques |
|-------|-------------|------------|
| [AGENT-IMPERSONATE](../attack-classes/AGENT-IMPERSONATE.md) | Impersonating trusted agents or administrative roles to gain unauthorized access | T-4002, T-4004 |
| [BEHAVIORAL-IMPERSONATE](../attack-classes/BEHAVIORAL-IMPERSONATE.md) | Using stolen credentials detected via behavioral baseline mismatch: agent DNA forgery | T-4002 |

### Sandbox (1 class)
| Class | Description | Techniques |
|-------|-------------|------------|
| [SANDBOX-ESCAPE](../attack-classes/SANDBOX-ESCAPE.md) | General sandbox escape via privileged containers, LSM degradation, or process environment leakage | T-7001 |

<!-- END GENERATED: attack-class-tables -->
