# Attack paths

## Attack Paths

Complete kill chain traversals demonstrated in DVAA:

**Path A (API Agent Full Compromise):**
T-1001 → T-2001 → T-3001 → T-5004 → T-7001 → T-8002
(LegacyBot → ToolBot: recon, inject, harvest creds, pivot, enumerate files, exfiltrate)

**Path B (Memory Persistence Chain):**
T-1001 → T-2001 → T-6001 → T-7004 → T-8005
(MemoryBot: recon, inject, persist in memory, dump memory, exfiltrate via conversation)

**Path C (Multi-Agent A2A Chain):**
T-1006 → T-2001 → T-4002 → T-5002 → T-9001
(Orchestrator → Worker → ToolBot: discover agent card, inject, impersonate admin, pivot via A2A, modify data)

**Path D (Supply Chain to Full Compromise):**
T-1002 → T-2005 → T-6004 → T-5003 → T-9006
(PluginBot → ProxyBot: discover tools, inject via tool description, backdoor skill, hop MCP servers, compromise downstream)
