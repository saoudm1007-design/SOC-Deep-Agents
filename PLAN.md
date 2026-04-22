# Autonomous SOC Analyst AI Agent — Deep Agents Architecture
# Project Plan

## Overview

Build a Tier 1 SOC Analyst AI agent using LangChain Deep Agents (`deepagents` library).
The agent ingests JSON security alerts and outputs a structured verdict:

```json
{
  "verdict": "Malicious|Benign|Suspicious",
  "confidence": 0.95,
  "reasoning": "...",
  "mitre_techniques": ["T1190"],
  "recommended_actions": ["..."],
  "investigated_tools": ["..."]
}
```

---

## Tech Stack

| Component        | Choice                                      | Why                                              |
|------------------|---------------------------------------------|--------------------------------------------------|
| Agent Framework  | `deepagents` (LangChain Deep Agents)        | Built-in planning, subagents, structured output  |
| LLM              | OpenRouter `google/gemini-2.5-flash`        | 100% accuracy on 20 alerts, $0.006/alert         |
| Dashboard        | Chainlit 2.x                               | Native streaming, tool step components           |
| Validation       | Pydantic v2                                 | Strict output schema via `response_format`        |
| Caching          | diskcache                                   | File-based, persists across restarts             |
| HTTP             | httpx                                       | Non-blocking tool calls                          |

---

## Architecture

```
Alert JSON
    |
    v
Coordinator-MainAgent  [create_deep_agent]
    |
    |  Built-in write_todos -> plans investigation steps
    |
    |---> Network Intelligence Subagent
    |        Tools: ip_full_profile, ip_reputation, geoip, dns, whois, threat_intel, network_traffic
    |        Returns: IP risk, geolocation, domain analysis, threat intel, traffic patterns
    |
    |---> Log & Payload Subagent
    |        Tools: log_pattern_analyzer, payload_decoder, cve_lookup
    |        Returns: MITRE patterns, decoded payload, CVE severity
    |
    '---> User Behavior Subagent
             Tools: user_behavior_analyzer
             Returns: risk score, anomaly flags, account type
    |
    v
VERDICT_JSON parsed from coordinator output (Pydantic-validated)
    |
    v
Chainlit Dashboard (streaming trace + verdict card)
```

---

## Project File Structure

```
soc-agent/
├── agent.py           # Coordinator-mainagent (pure agentic)
├── subagents.py       # 3 subagent definitions (network, log, user)
├── prompts/           # System prompts for coordinator + each subagent
├── models.py          # AlertInput, VerdictOutput, ToolResult Pydantic models
├── config.py          # pydantic-settings: API keys, model config
├── dashboard.py       # Chainlit streaming UI
├── tool_registry.py   # LangChain @tool wrappers (11 tools)
├── benchmark.py       # Accuracy + latency + cost tracker
├── compare_models.py  # Multi-model comparison runner
├── requirements.txt
├── .env.example
├── .gitignore
├── Makefile
├── README.md
├── tools/
│   ├── ip_full_profile.py # Parallel merged IP lookup (preferred)
│   ├── ip_reputation.py   # AbuseIPDB + VirusTotal, 24h cache
│   ├── geoip.py           # ip-api.com, VPN/proxy detection, 1h cache
│   ├── dns_lookup.py      # dnspython, DGA heuristic, tunnel score
│   ├── whois_lookup.py    # Domain age, registrar, privacy flags, 7d cache
│   ├── threat_intel.py    # AlienVault OTX, free API
│   ├── network_traffic.py # Volume + timing exfiltration detection
│   ├── log_pattern.py     # 40+ MITRE-mapped regex patterns
│   ├── payload_decoder.py # base64/URL/hex/gzip + IOC extraction
│   ├── cve_lookup.py      # NVD NIST API, 7-day cache, pre-cached CVEs
│   └── user_behavior.py   # Stateless weighted risk scorer (10 signals)
├── tests/
│   ├── test_tools.py
│   ├── test_agent.py
│   ├── test_prompts.py
│   ├── test_dashboard.py
│   ├── test_edge_cases.py
│   ├── test_bonus.py
│   └── fixtures/
│       └── sample_alerts.json (+ 65, 200, 600 alert sets)
├── demo/
│   ├── run_demo.py
│   ├── demo_6_alerts.json
│   └── scenarios/ (4 canonical scenarios)
└── paper/
    └── paper.md
```

---

## The 11 Tools

| Tool                      | Subagent           | Source                             |
|---------------------------|--------------------|------------------------------------|
| `ip_full_profile`         | Network            | Parallel: reputation + geoip + OTX |
| `verify_ip_reputation`    | Network            | AbuseIPDB + VirusTotal             |
| `geoip_lookup`            | Network            | ip-api.com (no key needed)         |
| `dns_lookup`              | Network            | dnspython + DGA heuristic          |
| `whois_lookup`            | Network            | Domain age, registrar, privacy     |
| `threat_intel_lookup`     | Network            | AlienVault OTX (free API)          |
| `network_traffic_analyzer`| Network            | Volume + timing + port analysis    |
| `log_pattern_analyzer`    | Log & Payload      | 40+ MITRE regex patterns           |
| `payload_decoder`         | Log & Payload      | base64/URL/hex/gzip (pure Py)      |
| `cve_lookup`              | Log & Payload      | NVD NIST API + 7-day cache         |
| `user_behavior_analyzer`  | User Behavior      | Stateless heuristic scorer         |

---

## Subagent Definitions

### Network Intelligence Subagent
- **Name:** `network_intel_agent`
- **Tools:** ip_full_profile, ip_reputation, geoip, dns, whois, threat_intel, network_traffic (7 tools)
- **Purpose:** Investigate IPs, geolocate connections, analyze domains, check threat intel, detect exfiltration

### Log & Payload Subagent
- **Name:** `log_payload_agent`
- **Tools:** log_pattern_analyzer, payload_decoder, cve_lookup (3 tools)
- **Purpose:** Detect attack patterns in logs, decode obfuscated payloads, look up CVEs

### User Behavior Subagent
- **Name:** `user_behavior_agent`
- **Tools:** user_behavior_analyzer (1 tool)
- **Purpose:** Score user behavioral risk across 10 signals, detect anomalies

---

## Prompt Engineering Strategy

**Coordinator system prompt:**
- SOC analyst persona (PICERL methodology)
- Instructs to use write_todos to plan before delegating
- Delegates to subagents by name with specific questions
- Synthesizes subagent findings into a final verdict
- 26 investigation rules (known-benign patterns, high-risk escalation, confidence calibration)
- Output: VERDICT_JSON block parsed and validated against Pydantic schema

**Subagent prompts:**
- Each focused on their domain only
- Return structured findings (not a verdict — coordinator decides)
- No hallucination of tool results

---

## Evaluation Criteria Alignment

| Component          | Points | Our Strategy                                           |
|--------------------|--------|--------------------------------------------------------|
| Agent Architecture | 25     | Coordinator-mainagent + 3 subagents + Deep Agents      |
| Prompt Engineering | 15     | 26 rules + subagent-specific prompts + VERDICT_JSON    |
| Web Interface      | 15     | Chainlit streaming trace + verdict card + batch mode   |
| Paper Quality      | 15     | Architecture diagram, results tables, failure analysis |
| Code Quality       | 10     | Modular, Pydantic models, Makefile, 183 tests          |
| Performance Rank   | 20     | 100% on 20, 95.7% on 600, $0.006/alert                |
