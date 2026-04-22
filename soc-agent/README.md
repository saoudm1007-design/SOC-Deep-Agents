# 🛡️ SOC Analyst Deep Agents

Autonomous AI SOC triage agent — coordinator + 3 subagents + 10 tools. Purely agentic, no hardcoded rules. 100% accuracy on 20 alerts, 95.7% on 600. Built with LangChain Deep Agents + Chainlit.

- **100 % accuracy** on the 20-alert benchmark (20/20, 10/10 malicious recall)
- **~11.5 s average latency** per alert — purely agentic, no hardcoded rules
- Structured `VerdictOutput` JSON suitable for SOAR integration
- Live Chainlit dashboard with full reasoning trace, action buttons, batch summary
- **Multi-provider**: Cloud (OpenRouter — 8 models) and Local (Ollama — 6 models)

---

## Architecture

```
Alert JSON
    │
    ▼
Coordinator (Gemini 2.5 Flash)
    │
    ├───────────────┼───────────────┐
network_intel    log_payload     user_behavior
(6 tools)        (3 tools)       (1 tool)
    │                │                │
    └────────────────┼────────────────┘
                     ▼
            VERDICT_JSON (schema-validated)
```

| Subagent         | Tools                                                                               |
|------------------|-------------------------------------------------------------------------------------|
| `network_intel`  | ip_reputation, geoip, dns_lookup, whois, threat_intel (OTX), network_traffic        |
| `log_payload`    | log_pattern (40+ MITRE regex), payload_decoder, cve_lookup                          |
| `user_behavior`  | UEBA risk scorer (10 signals)                                                       |

---

## Quick start

```bash
cd soc-agent
python -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env                   # then add your OpenRouter key

make test            # 183 unit + integration + edge-case tests
make demo            # 4 canonical scenarios end-to-end
make benchmark       # 20-alert accuracy + latency + cost CSV
make run             # Chainlit dashboard at http://localhost:8008
```

---

## Configuration — `.env`

| Variable                   | Required?  | Notes                                      |
|----------------------------|------------|--------------------------------------------|
| `MODEL_PROVIDER`           | yes        | `openrouter` (default) \| `claude` \| `ollama` |
| `OPENROUTER_API_KEY`       | if OpenRouter | Get from https://openrouter.ai           |
| `OPENROUTER_MODEL`         | no         | Default `google/gemini-2.5-flash`          |
| `ANTHROPIC_API_KEY`        | if Claude  | For `MODEL_PROVIDER=claude`                |
| `OLLAMA_BASE_URL`          | if Ollama  | Default `http://localhost:11434`           |
| `ABUSEIPDB_API_KEY`        | optional   | Improves IP reputation signal              |
| `VIRUSTOTAL_API_KEY`       | optional   | Second IP reputation source                |
| `NVD_API_KEY`              | optional   | Higher NVD rate limits                     |
| `CACHE_DIR`                | no         | Default `.cache` (diskcache)               |

All API-key-gated tools degrade gracefully: when a key is absent or the
upstream API is down, the tool returns `data_source="unavailable"` and
the coordinator lowers its confidence accordingly.

---

## Project layout

```
soc-agent/
├── agent.py                 # coordinator + verdict parsing
├── subagents.py             # three SubAgent TypedDicts
├── tool_registry.py         # 10 @tool wrappers, NETWORK/LOG/USER lists
├── models.py                # AlertInput, VerdictOutput, ToolResult
├── config.py                # pydantic-settings (.env loader)
├── prompts/                 # coordinator + 3 subagent prompts
├── tools/                   # 10 defensive tools
├── dashboard.py             # Chainlit UI
├── benchmark.py             # accuracy + latency + cost tracker
├── demo/
│   ├── run_demo.py          # colourised terminal demo runner
│   └── scenarios/           # 4 canonical JSON scenarios
├── tests/                   # 183 tests (tools, prompts, agent, dashboard, edge cases)
└── paper/paper.md           # research write-up
```

---

## Input formats (dashboard & CLI)

**Plain text**

```
Failed SSH login from 185.220.101.5 — count: 150
```

**JSON alert**

```json
{"src_ip": "185.220.101.5", "payload": "authentication failed count: 150"}
```

**File upload** — `.json` (object or array), `.csv` (columns:
`alert_id`, `src_ip`, `payload`), or `.txt` (one alert per line).
The dashboard switches to **batch mode** automatically when multiple
alerts are supplied and renders a summary table.

---

## Benchmark results

See `paper/paper.md` §3 for details. Summary:

| Metric                      | Value            |
|-----------------------------|------------------|
| Accuracy                    | 100 % (20/20)    |
| Malicious recall            | 100 % (10/10)    |
| Benign precision            | 100 % (10/10)    |
| Avg latency                 | 11.5 s           |

All alerts investigated end-to-end by the agentic pipeline — no
hardcoded rules or regex shortcuts.

---

## License & credits

Course project — Agentic AI, April 2026.
Built on `deepagents` 0.5.2, `langgraph`, `langchain-openai`, `chainlit`.
Threat-intel sources: AbuseIPDB, VirusTotal, AlienVault OTX, ip-api.com,
NVD, public DNS.
