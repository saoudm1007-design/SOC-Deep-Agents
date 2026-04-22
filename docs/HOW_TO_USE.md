# How to Use — SOC Analyst Deep Agents

## Starting the Dashboard

```bash
cd soc-agent
source .venv/bin/activate
make run
```

Open http://localhost:8008 in your browser.

---

## Input Methods

### 1. Plain Text

Type or paste a raw log line directly into the chat:

```
Failed SSH login from 185.220.101.5 — count: 150
```

### 2. JSON Alert

Paste a JSON object:

```json
{
  "alert_id": "evt_5501",
  "source_ip": "45.133.1.22",
  "destination_ip": "192.168.1.10",
  "log_payload": "GET /login.php?user=admin' OR '1'='1 HTTP/1.1 - 403 Forbidden"
}
```

### 3. JSON Array (Batch Mode)

Paste an array of alerts — the agent processes each one and shows a summary table:

```json
[
  {"alert_id": "A1", "log_payload": "SSH brute force from 1.2.3.4 count: 500"},
  {"alert_id": "A2", "log_payload": "apt-get update by root from 192.168.1.5"}
]
```

### 4. File Upload

Click the attachment icon and upload a file:
- `.json` — single alert `{}` or array `[{}, {}]`
- `.csv` — columns: `alert_id`, `src_ip`, `payload`
- `.txt` — one alert per line

---

## Dashboard Commands

Type these commands in the chat to view information:

| Command | What it shows |
|---------|---------------|
| `/architecture` | Architecture diagram, ReAct loop, CoT, Deep Agents, PICERL |
| `/tools` | All 11 investigation tools with descriptions |
| `/benchmarks` | Accuracy tables, cost analysis, model comparison |
| `/demo` | Runs 6 demo alerts automatically |

---

## Dashboard Buttons

The welcome message includes 4 clickable action buttons:

- **Architecture** — Shows how the agent works
- **Tools** — Shows all tools and their data sources
- **Benchmarks** — Shows accuracy and cost results
- **Run Demo (6 alerts)** — Runs the demo alert set

---

## Switching Models

Open the Settings panel (gear icon) to change models:

### Cloud Models (OpenRouter)
Select from the dropdown. Default is `google/gemini-2.5-flash` (recommended — 100% accuracy, $0.006/alert).

### Local Models (Ollama)
Select from the Ollama dropdown. Requires Ollama running locally (`ollama serve`).

### Custom Model
1. Select the provider type: `Cloud (OpenRouter)` or `Local (Ollama)`
2. Type the model name in the text field (e.g., `google/gemini-2.0-flash` or `phi3`)
3. The custom model overrides both dropdowns

---

## Understanding the Output

### Verdict Card

Each investigated alert produces a verdict card:

```
🔴 Verdict: Malicious
Confidence: ███████████████████░  95%

Reasoning
SQL injection attempt detected via sqlmap targeting login.php...

MITRE ATT&CK Techniques
  • T1190 — Exploit Public-Facing Application

Recommended Actions
  1. Block source IP at the firewall
  2. Review web server logs for exploitation attempts

Main & Subagents Used: Coordinator-MainAgent, Network Intel Agent, Log & Payload Agent
Tools Used: ip_full_profile, ip_reputation, geoip, dns, whois, threat_intel, network_traffic, log_pattern, payload_decoder, cve_lookup
```

### Verdict Colors
- 🔴 **Malicious** — confirmed attack, action required
- 🟡 **Suspicious** — partial evidence, needs analyst review
- 🟢 **Benign** — legitimate activity, no action needed

### Confidence Scale
- **95-100%** — Multi-signal confirmed (2+ sources agree)
- **80-94%** — Strong evidence from 2+ sources
- **60-79%** — Single strong signal or multiple weak signals
- **40-59%** — Suspicious, partial evidence

### Batch Summary Table

When multiple alerts are processed, a summary table appears at the end showing all results with verdict, confidence, MITRE techniques, subagents used, and tools used.

---

## Running from the Command Line

### Benchmark (20 alerts)
```bash
make benchmark
```

### Benchmark (custom alert file)
```bash
python benchmark.py --file tests/fixtures/sample_alerts_200.json
python benchmark.py --file tests/fixtures/sample_alerts_600.json
```

### Benchmark (specific alerts)
```bash
python benchmark.py --ids ALERT-001 ALERT-011 ALERT-018
```

### Demo (4 canonical scenarios)
```bash
make demo
```

### Run Tests
```bash
make test              # all 183 tests
make test-tools        # tool unit tests only
make test-agent        # agent integration tests only
make test-edge         # edge case tests only
```

---

## Alert Field Names

The agent accepts multiple naming conventions:

| Field | Accepted Names |
|-------|---------------|
| Alert ID | `alert_id`, `id`, `alertId` |
| Source IP | `source_ip`, `src_ip`, `srcip`, `source.ip` |
| Destination IP | `destination_ip`, `dst_ip`, `dstip`, `destination.ip` |
| Log/Payload | `log_payload`, `payload`, `raw_log`, `message`, `log_message` |
| Event Type | `event_type` |
| Severity | `severity` |
| Timestamp | `timestamp` |
