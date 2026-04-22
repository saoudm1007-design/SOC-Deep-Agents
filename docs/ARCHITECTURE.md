# Architecture — SOC Analyst Deep Agents

## System Overview

A purely agentic SOC triage system built on LangChain Deep Agents. Every alert is investigated end-to-end by the LLM — no hardcoded rules, no regex shortcuts, no if/else verdict logic.

## Data Flow

```
                         ALERT (JSON / text / CSV)
                                  |
                                  v
                    +-----------------------------+
                    |   Coordinator-MainAgent     |
                    |   (Gemini 2.5 Flash)        |
                    |                             |
                    |   Step 1: write_todos       |
                    |   (plan investigation)      |
                    |                             |
                    |   Step 2: task              |
                    |   (delegate to subagents)   |
                    |                             |
                    |   Step 3: synthesize        |
                    |   (combine all findings)    |
                    +--+----------+----------+----+
                       |          |          |
                       v          v          v
              +----------+  +----------+  +----------+
              | Network  |  | Log &    |  | User     |
              | Intel    |  | Payload  |  | Behavior |
              | Agent    |  | Agent    |  | Agent    |
              | 7 tools  |  | 3 tools  |  | 1 tool   |
              +----------+  +----------+  +----------+
                       |          |          |
                       v          v          v
                    +-----------------------------+
                    |   Coordinator synthesizes   |
                    |   all subagent findings     |
                    |   into VERDICT_JSON         |
                    +-----------------------------+
                                  |
                                  v
                    +-----------------------------+
                    |   VerdictOutput (Pydantic)   |
                    |                             |
                    |   verdict: Malicious/Benign |
                    |   confidence: 0.0 - 1.0     |
                    |   reasoning: "..."          |
                    |   mitre_techniques: [...]    |
                    |   recommended_actions: [...] |
                    |   investigated_tools: [...]  |
                    +-----------------------------+
                                  |
                         +--------+--------+
                         |                 |
                         v                 v
                  Chainlit Dashboard    Benchmark CSV
                  (streaming UI)       (accuracy/cost)
```

## Component Details

### Coordinator-MainAgent

The brain of the system. Receives the alert and orchestrates the entire investigation.

- **Framework**: LangChain Deep Agents (`create_deep_agent`)
- **LLM**: Gemini 2.5 Flash via OpenRouter (configurable)
- **Built-in tools**:
  - `write_todos` — plans investigation steps before acting (Chain-of-Thought)
  - `task` — delegates work to specialist subagents (ReAct loop)
- **System prompt**: ~1,500 lines with 26 investigation rules, PICERL methodology, confidence calibration, known-benign/high-risk pattern guidance
- **Memory**: LangGraph MemorySaver with per-alert thread isolation
- **Output**: Parses `VERDICT_JSON:` block from LLM text, validates against Pydantic schema, retries up to 2x on malformed output

### Network Intelligence Subagent (7 tools)

Investigates network-layer indicators: IPs, domains, DNS, traffic patterns.

| Tool | Data Source | Cache | Purpose |
|------|-----------|-------|---------|
| `ip_full_profile` | AbuseIPDB + ip-api + OTX (parallel) | 24h | Merged IP reputation + geo + threat intel |
| `ip_reputation` | AbuseIPDB + VirusTotal | 24h | Abuse confidence score, malicious flag |
| `geoip_lookup` | ip-api.com | 1h | Country, ISP, VPN/Tor/proxy detection |
| `dns_lookup` | dnspython | — | DGA score, DNS tunnel score |
| `whois_lookup` | python-whois | 7d | Domain age, registrar, privacy flags |
| `threat_intel_lookup` | AlienVault OTX | — | Pulse count, malware families |
| `network_traffic_analyzer` | Local heuristics | — | Volume, timing, suspicious ports |

### Log & Payload Subagent (3 tools)

Analyzes log entries, encoded payloads, and known vulnerabilities.

| Tool | Data Source | Cache | Purpose |
|------|-----------|-------|---------|
| `log_pattern_analyzer` | 40+ MITRE ATT&CK regex | — | Pattern matching with confidence scores |
| `payload_decoder` | Pure Python | — | Multi-layer decode (base64/URL/hex/gzip) + IOC extraction |
| `cve_lookup` | NVD API | 7d | CVSS score, severity, 6 pre-cached critical CVEs |

### User Behavior Subagent (1 tool)

Evaluates user and entity behavior anomalies (UEBA).

| Tool | Signals | Purpose |
|------|---------|---------|
| `user_behavior_analyzer` | 10 behavioral signals | Risk score (0-1), anomaly flags |

**10 Behavioral Signals:**
1. Off-hours access
2. Impossible travel
3. Privilege escalation
4. First-time resource access
5. Mass file access
6. Failed login count (>10 = brute force)
7. Admin account anomalies
8. Service account misuse
9. Sensitive resource access
10. Abnormally long sessions

## Key Design Decisions

### Why 3 Subagents?

With 11 tools in one agent, the LLM gets confused about which to call. Subagents specialize — like a real SOC team:
- Network analyst checks IPs and domains
- Log analyst checks patterns and payloads
- UEBA analyst checks user behavior

Each subagent has a focused prompt and only sees its relevant tools. The coordinator decides which subagents to involve based on the alert content.

### Why Deep Agents?

Plain LangChain agents don't support hierarchical delegation. Deep Agents provide:
- **`write_todos`** — forces planning before action (Chain-of-Thought)
- **`task`** — built-in subagent delegation
- **MemorySaver** — maintains investigation state across turns
- **Thread isolation** — each alert gets its own conversation thread

### Why No Hardcoded Rules?

The project proposal explicitly requires: "No Hard-Coding: You cannot hard-code rules for specific IPs found in the training set. The agent must dynamically query tools."

Our system is purely agentic:
- `agent.py` is 308 lines — no if/else verdict logic
- Every alert goes through the LLM coordinator
- Tools provide evidence, the LLM makes the judgment
- Same alert can trigger different investigation paths depending on context

### Graceful Degradation

When external APIs are down or keys are missing:
- Tools return `data_source: "unavailable"` instead of crashing
- Coordinator prompt instructs: "lower confidence when tools return unavailable"
- Private/RFC1918 IPs skip external API calls at the tool level (no data available anyway)
- diskcache provides 24h-7d caching to reduce API dependency

### Multi-Provider Support

The system supports 3 LLM providers:
- **OpenRouter** (default) — routes to Gemini, GPT, Claude, Llama, etc.
- **Ollama** — local LLMs, fully offline, no API key needed
- **Anthropic Claude** — direct API with prompt caching support

Switch providers from the dashboard dropdown or `.env` config.

## ReAct Loop in Practice

Example: SQL Injection alert arrives

```
OBSERVE: Alert with source_ip=45.133.1.22, payload contains "' OR '1'='1"

THINK (write_todos):
  1. Check source IP reputation and geolocation
  2. Analyze log payload for attack patterns
  3. Check user behavior if username present

ACT (task → network_intel_agent):
  - ip_full_profile(45.133.1.22) → abuse_confidence: 95%, country: Russia, VPN: true
  - threat_intel(45.133.1.22) → OTX pulse_count: 12, linked to SQLi campaigns

OBSERVE: Network intel confirms malicious source

ACT (task → log_payload_agent):
  - log_pattern_analyzer(payload) → SQL injection match (T1190), confidence: 0.9
  - payload_decoder(payload) → decoded: admin' OR '1'='1, sqlmap user-agent

OBSERVE: Log analysis confirms SQL injection pattern

THINK (synthesize):
  Multiple signals confirm attack:
  - Known malicious IP (abuse score 95%, 12 OTX reports)
  - SQL injection pattern with sqlmap tool signature
  - Confidence: 0.95

ACT (output VERDICT_JSON):
  verdict: Malicious, confidence: 0.95, MITRE: T1190
```

## File Structure

```
soc-agent/
├── agent.py             # Coordinator-mainagent (308 lines, pure agentic)
├── subagents.py         # 3 SubAgent definitions
├── tool_registry.py     # 11 @tool wrappers, NETWORK/LOG/USER lists
├── models.py            # AlertInput, VerdictOutput, ToolResult (Pydantic)
├── config.py            # Settings (OpenRouter/Claude/Ollama)
├── dashboard.py         # Chainlit web UI with action buttons
├── benchmark.py         # Accuracy + latency + cost tracker
├── prompts/
│   ├── coordinator.py   # ~1,500 lines, 26 investigation rules
│   ├── network_agent.py # Network specialist prompt
│   ├── log_agent.py     # Log/payload specialist prompt
│   └── user_agent.py    # UEBA specialist prompt
├── tools/               # 11 tool implementations
├── tests/               # 183 tests
├── demo/                # 6 demo alerts + 4 scenarios
└── paper/paper.md       # Research paper
```
