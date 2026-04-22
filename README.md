# 🛡️ SOC Analyst Deep Agents

Autonomous AI SOC triage agent — coordinator + 3 subagents + 10 tools. Purely agentic, no hardcoded rules. 100% accuracy on 20 alerts, 95.7% on 600. Built with LangChain Deep Agents + Chainlit.


---

## How It Works

```
Alert JSON
    |
    v
Coordinator-MainAgent (Gemini 2.5 Flash)
    |
    |--- Network Intel Agent (7 tools)
    |--- Log & Payload Agent (3 tools)
    |--- User Behavior Agent (1 tool)
    |
    v
VERDICT_JSON { verdict, confidence, reasoning, mitre, actions }
```

The coordinator plans the investigation, delegates to specialist subagents, and synthesizes their findings into a final verdict. Every decision is made by the LLM — no regex, no if/else, no hardcoded rules.

---

## Results

| Dataset | Accuracy | Malicious Recall | Avg Latency | Cost/Alert |
|---------|----------|------------------|-------------|------------|
| 20 alerts | **100%** | 100% | 11.5s | $0.006 |
| 65 alerts | **98.5%** | 100% | 16.9s | $0.006 |
| 200 alerts | **97.5%** | 98% | 17.5s | $0.006 |
| 600 alerts | **95.7%** | 96% | 12.0s | $0.006 |

12+ models benchmarked. See [docs/MODEL_COMPARISON.md](docs/MODEL_COMPARISON.md) for full results.

---

## Quick Start

```bash
cd soc-agent
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add your OpenRouter API key

make test              # 183 tests
make run               # Chainlit dashboard at http://localhost:8008
make benchmark         # 20-alert accuracy test
make demo              # 4 demo scenarios
```

---

## Features

- **Purely agentic** — no hardcoded rules, LLM reasons about every alert
- **10 investigation tools** — IP reputation, geolocation, DNS/DGA, WHOIS, threat intel, network traffic, MITRE pattern matching, payload decoding, CVE lookup, UEBA
- **3 specialist subagents** — network intel, log/payload analysis, user behavior
- **Chainlit dashboard** — real-time reasoning trace, batch mode, action buttons
- **Multi-provider** — Cloud (OpenRouter: Gemini, GPT, Claude, Grok) + Local (Ollama)
- **183 tests** — tools, prompts, agent, dashboard, edge cases
- **$0.006/alert** — 333x cheaper than a human analyst

---

## Dashboard

The web dashboard shows the full investigation trace:

- **Architecture / Tools / Benchmarks** info buttons
- **Run Demo** button (6 alerts)
- **Batch mode** with summary table showing agents and tools used per alert
- **Model selector** — switch between cloud and local LLMs
- **Verdict cards** with confidence bar, MITRE techniques, recommended actions

---

## Documentation

| Doc | Description |
|-----|-------------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture, data flow, design decisions |
| [PROMPTS.md](docs/PROMPTS.md) | Prompt engineering strategy, 26 investigation rules |
| [BENCHMARKS.md](docs/BENCHMARKS.md) | All benchmark results, failure analysis, cost breakdown |
| [MODEL_COMPARISON.md](docs/MODEL_COMPARISON.md) | 12+ models tested with accuracy/latency/cost |
| [INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md) | Setup instructions, API keys, Ollama install |
| [HOW_TO_USE.md](docs/HOW_TO_USE.md) | Dashboard usage, input formats, commands |
| [PROJECT_REPORT.md](docs/PROJECT_REPORT.md) | Research paper |
| [PRESENTATION_GUIDE.pdf](docs/PRESENTATION_GUIDE.pdf) | Presentation script with demo alerts |

---

## Project Structure

```
soc-agent/
├── agent.py             # Coordinator-mainagent (pure agentic)
├── subagents.py         # 3 subagent definitions
├── tool_registry.py     # 11 @tool wrappers
├── models.py            # AlertInput, VerdictOutput, ToolResult
├── config.py            # OpenRouter / Claude / Ollama config
├── dashboard.py         # Chainlit web UI
├── benchmark.py         # Accuracy + latency + cost tracker
├── prompts/             # Coordinator + 3 subagent prompts
├── tools/               # 11 tool implementations
├── tests/               # 183 tests
├── demo/                # 6 demo alerts + 4 scenarios
└── paper/               # Research paper
```

---

## Tech Stack

- **Agent Framework:** [deepagents](https://github.com/langchain-ai/deepagents) (LangChain + LangGraph)
- **LLM:** Google Gemini 2.5 Flash via OpenRouter
- **Dashboard:** Chainlit 2.x
- **Validation:** Pydantic v2
- **Caching:** diskcache

---

## License

Course project — Agentic AI, Spring 2026.
