"""
SOC Analyst Deep Agents — Chainlit Dashboard
Run: cd soc-agent && .venv/bin/chainlit run dashboard.py
"""
import json
import csv
import io
import uuid
import asyncio
from typing import Optional

import chainlit as cl
from chainlit.input_widget import Select, TextInput

from models import AlertInput, VerdictOutput
from agent import run_agent_stream
from config import settings


# ── Verdict styling ───────────────────────────────────────────────────────────

_VERDICT_EMOJI = {"Malicious": "🔴", "Suspicious": "🟡", "Benign": "🟢"}
_VERDICT_COLOR = {"Malicious": "#c0392b", "Suspicious": "#e67e22", "Benign": "#27ae60"}


def _confidence_bar(conf: float) -> str:
    filled = round(conf * 20)
    empty  = 20 - filled
    return "█" * filled + "░" * empty + f"  {conf * 100:.0f}%"


def _verdict_card(v: VerdictOutput) -> str:
    emoji = _VERDICT_EMOJI.get(v.verdict, "⚪")
    bar   = _confidence_bar(v.confidence)

    mitre_lines = ""
    if v.mitre_techniques:
        mitre_lines = "\n".join(f"  • `{t}`" for t in v.mitre_techniques)
        mitre_lines = f"\n**MITRE ATT&CK Techniques**\n{mitre_lines}\n"

    action_lines = ""
    if v.recommended_actions:
        action_lines = "\n".join(f"  {i+1}. {a}" for i, a in enumerate(v.recommended_actions))
        action_lines = f"\n**Recommended Actions**\n{action_lines}\n"

    agents_used = ", ".join(f"`{a}`" for a in _resolve_agents(v.investigated_tools)) if v.investigated_tools else "none"
    tools_from_agents = ", ".join(_resolve_tools_from_agents(v.investigated_tools)) if v.investigated_tools else "none"

    return f"""## {emoji} Verdict: **{v.verdict}**

**Confidence:** `{bar}`

**Reasoning**
{v.reasoning}
{mitre_lines}{action_lines}
**Main & Subagents Used:** {agents_used}

**Tools Used:** {tools_from_agents}
"""


# ── Session settings ──────────────────────────────────────────────────────────

CLOUD_MODELS = [
    "google/gemini-2.5-flash [Recommended]",
    "google/gemini-2.5-flash-lite",
    "x-ai/grok-4.1-fast",
    "deepseek/deepseek-chat",
    "openai/gpt-4.1-mini",
    "anthropic/claude-3.5-haiku",
    "meta-llama/llama-3.3-70b-instruct",
    "qwen/qwen-turbo",
]

OLLAMA_MODELS = [
    "none",
    "llama3.1",
    "llama3.2",
    "mistral",
    "qwen2.5",
    "deepseek-r1",
    "gemma2",
]


def _resolve_cloud_model(display_name: str) -> str:
    """Strip display labels like [Recommended] to get the actual model ID."""
    return display_name.split(" [")[0].strip()


@cl.on_chat_start
async def on_chat_start():
    """Initialise session settings and show welcome message."""
    await cl.ChatSettings(
        [
            Select(
                id="cloud_model",
                label="Cloud Model (OpenRouter)",
                values=CLOUD_MODELS,
                initial_index=0,
            ),
            Select(
                id="ollama_model",
                label="Local Model (Ollama) — overrides cloud if set",
                values=OLLAMA_MODELS,
                initial_index=0,
            ),
            Select(
                id="custom_provider",
                label="Custom Model Provider Type",
                values=["Cloud (OpenRouter)", "Local (Ollama)"],
                initial_index=0,
            ),
            TextInput(
                id="custom_model",
                label="Custom Model Name (overrides all dropdowns if filled)",
                initial="",
            ),
        ]
    ).send()

    cl.user_session.set("cloud_model", CLOUD_MODELS[0])
    cl.user_session.set("ollama_model", "none")
    cl.user_session.set("custom_model", "")

    actions = [
        cl.Action(name="architecture", label="Architecture", payload={"action": "architecture"}, description="How the agent works"),
        cl.Action(name="tools", label="Tools", payload={"action": "tools"}, description="All 10 investigation tools"),
        cl.Action(name="benchmarks", label="Benchmarks", payload={"action": "benchmarks"}, description="Accuracy and cost results"),
        cl.Action(name="demo", label="Run Demo (6 alerts)", payload={"action": "demo"}, description="Run 6 demo alerts"),
    ]

    await cl.Message(
        content=_welcome_message(),
        author="SOC Agent",
        actions=actions,
    ).send()


@cl.action_callback("architecture")
async def on_architecture(action: cl.Action):
    await cl.Message(content=ARCHITECTURE_PAGE, author="SOC Agent").send()

@cl.action_callback("tools")
async def on_tools(action: cl.Action):
    await cl.Message(content=TOOLS_PAGE, author="SOC Agent").send()

@cl.action_callback("benchmarks")
async def on_benchmarks(action: cl.Action):
    await cl.Message(content=BENCHMARKS_PAGE, author="SOC Agent").send()

@cl.action_callback("demo")
async def on_demo(action: cl.Action):
    import os
    demo_path = os.path.join(os.path.dirname(__file__), "demo", "demo_6_alerts.json")
    if os.path.exists(demo_path):
        with open(demo_path) as f:
            demo_alerts = json.load(f)
        alerts = [AlertInput.from_dict(d) for d in demo_alerts]
        await _run_batch(alerts)
    else:
        await cl.Message(content="Demo file not found.", author="SOC Agent").send()


@cl.on_settings_update
async def on_settings_update(settings_values: dict):
    cl.user_session.set("cloud_model", settings_values.get("cloud_model", CLOUD_MODELS[0]))
    cl.user_session.set("ollama_model", settings_values.get("ollama_model", "none"))
    cl.user_session.set("custom_provider", settings_values.get("custom_provider", "Cloud (OpenRouter)"))
    cl.user_session.set("custom_model", settings_values.get("custom_model", ""))


def _welcome_message() -> str:
    return """# SOC Analyst Deep Agents

**Autonomous Tier-1 SOC triage agent** — purely agentic, no hardcoded rules.

Submit a security alert as **plain text**, **JSON**, **CSV**, or **file upload** to investigate.

Type one of these commands to learn more:
- `/architecture` — How the agent works
- `/tools` — All 10 investigation tools
- `/benchmarks` — Accuracy and cost results

Or just paste an alert to start investigating.

---
*Use the Settings panel to switch models.*
"""


# ── Info pages ───────────────────────────────────────────────────────────────

ARCHITECTURE_PAGE = """# Agent Architecture

## How It Works

```
ALERT (JSON / text)
        |
        v
+---------------------------+
|  Coordinator-MainAgent    |
|  (Gemini 2.5 Flash)       |
|                           |
|  1. write_todos (plan)    |
|  2. task (delegate)       |
|  3. synthesize verdict    |
+--+--------+----------+---+
   |        |          |
   v        v          v
+-------+ +--------+ +--------+
|Network| |Log &   | |User    |
|Intel  | |Payload | |Behavior|
|Agent  | |Agent   | |Agent   |
|7 tools| |3 tools | |1 tool  |
+-------+ +--------+ +--------+
   |        |          |
   v        v          v
+---------------------------+
|  Coordinator synthesizes  |
|  VERDICT_JSON             |
+---------------------------+
        |
        v
  { verdict, confidence,
    reasoning, mitre,
    actions, tools }
```

## Key Concepts

### ReAct Loop (Reasoning + Acting)
The agent follows an iterative loop: **Observe** the alert, **Think** about what to investigate, **Act** by calling tools, **Observe** results, **Think** again, and repeat until it has enough evidence for a verdict.

### Chain-of-Thought (CoT)
The coordinator uses `write_todos` to plan investigation steps before calling any tools. This forces structured step-by-step reasoning rather than jumping to conclusions.

### LangChain Deep Agents
Built on the `deepagents` framework (LangChain + LangGraph):
- **Coordinator** plans and delegates via built-in `write_todos` and `task` tools
- **Subagents** specialize in their domain (network, logs, user behavior)
- **MemorySaver** maintains state throughout each investigation
- Each alert gets an isolated thread — no cross-contamination

### PICERL Methodology
The coordinator follows the SOC analyst PICERL framework:
- **P**reparation: Plan the investigation
- **I**dentification: Find indicators of compromise
- **C**ontainment: Recommend containment actions
- **E**radication: Suggest removal steps
- **R**ecovery: Recommend recovery actions
- **L**essons Learned: Document findings

### Why 3 Subagents?
With 11 tools in one agent, the LLM gets confused about which to call. Subagents specialize — like a real SOC team:
- **Network Intel** (7 tools): IP reputation, geolocation, DNS, WHOIS, threat intel, traffic analysis
- **Log & Payload** (3 tools): MITRE ATT&CK pattern matching, payload decoding, CVE lookup
- **User Behavior** (1 tool): UEBA risk scoring across 10 behavioral signals

### Output Schema
Every verdict includes:
- **verdict**: Malicious, Benign, or Suspicious
- **confidence**: 0.0 - 1.0
- **reasoning**: Why the agent reached this conclusion
- **mitre_techniques**: Mapped ATT&CK techniques
- **recommended_actions**: What a SOC analyst should do next
- **investigated_tools**: Which tools were used
"""

TOOLS_PAGE = """# Investigation Tools (10 + 1 Merged)

## Network Intelligence Subagent (7 tools)

### 1. ip_full_profile (Preferred)
Runs ip_reputation + geoip + threat_intel **in parallel**. Returns merged profile with abuse score, country, VPN/proxy detection, and OTX pulse count. Saves 2-4 seconds vs calling individually.

### 2. ip_reputation
Queries **AbuseIPDB + VirusTotal**. Returns abuse confidence score (0-100), ISP, usage type. 24-hour disk cache.

### 3. geoip_lookup
Queries **ip-api.com** (free). Returns country, city, ISP, VPN/Tor/proxy detection. 1-hour cache.

### 4. dns_lookup
Resolves hostnames via **dnspython**. Calculates DGA score (Domain Generation Algorithm) and DNS tunnel score. DGA > 0.5 = likely C2 infrastructure.

### 5. whois_lookup
Domain registration lookup. Returns domain age, registrar, privacy protection. Domains < 30 days old = strong phishing/C2 indicator. 7-day cache.

### 6. threat_intel_lookup
Queries **AlienVault OTX** (free). Returns pulse count (threat reports), malware families, threat tags. Pulse count >= 3 = known malicious.

### 7. network_traffic_analyzer
Analyzes network flow metadata. Detects large transfers (>1GB), off-hours activity, suspicious ports (4444, 6667, 9001), and exfiltration patterns.

---

## Log & Payload Subagent (3 tools)

### 8. log_pattern_analyzer
Matches against **40+ MITRE ATT&CK regex patterns**: brute force (T1110), credential dumping (T1003), lateral movement (T1021), ransomware (T1486), C2 beaconing (T1071), web attacks (T1190), LOLBin abuse (T1059), and more.

### 9. payload_decoder
Decodes **multi-layer obfuscation**: base64, URL encoding, hex, gzip. Extracts IOCs (IPs, domains, URLs, shell commands). Detects PowerShell IEX, mimikatz, Log4Shell.

### 10. cve_lookup
Queries **NVD API**. Returns CVSS score, severity, description. Pre-cached for 6 critical CVEs (Log4Shell, EternalBlue, ProxyLogon, BlueKeep).

---

## User Behavior Subagent (1 tool)

### 11. user_behavior_analyzer
Scores risk across **10 behavioral signals**:
1. Off-hours access
2. Impossible travel
3. Privilege escalation
4. First-time resource access
5. Mass file access
6. Failed login count
7. Admin account anomalies
8. Service account misuse
9. Sensitive resource access
10. Abnormally long sessions

Returns risk_score (0.0-1.0), risk_level (Low/Medium/High/Critical), and anomaly flags.

---

## Tool Design Principles

- **All tools return structured Pydantic models** with `data_source` field (api/local/unavailable)
- **Graceful degradation**: When APIs are down, tools return `unavailable` and the coordinator lowers confidence
- **Private IP handling**: RFC1918 IPs skip external API calls (no data available anyway)
- **Disk caching**: diskcache reduces API calls and cost (24h for IP, 7d for CVE/WHOIS)
"""

BENCHMARKS_PAGE = """# Benchmark Results

## Accuracy Across Dataset Sizes (Pure Agentic)

| Dataset | Accuracy | Malicious Recall | Benign Precision | Avg Latency | Cost |
|---------|----------|------------------|------------------|-------------|------|
| 20 alerts | **100%** (20/20) | 100% (10/10) | 100% (10/10) | 11.5s | ~$0.11 |
| 65 alerts | **98.5%** (64/65) | 100% (43/43) | 95% (21/22) | 16.9s | ~$0.37 |
| 200 alerts | **97.5%** (195/200) | 98% (109/111) | 97% (86/89) | 17.5s | ~$1.14 |
| 600 alerts | **95.7%** (574/600) | 96% (327/340) | 95% (247/260) | 12.0s | ~$3.46 |

## Cost Analysis

- **$0.006 per alert** (half a cent)
- 1,000 alerts = **$6**
- Human Tier-1 analyst: ~$40/hour, ~20 alerts/hour = **$2/alert**
- Our agent is **333x cheaper** than a human analyst

## Model Comparison (12+ models tested)

| Model | Accuracy | Avg Latency | Cost/20 alerts |
|-------|----------|-------------|----------------|
| **google/gemini-2.5-flash** | **100%** | 11.5s | $0.11 |
| x-ai/grok-4.1-fast | 95% | 41.4s | $0.08 |
| anthropic/claude-3.5-haiku | 95% | 55.2s | $0.56 |
| openai/gpt-4.1-mini | 95% | 21.4s | -- |
| deepseek/deepseek-chat | 90% | 43.0s | $0.06 |
| google/gemini-2.5-flash-lite | 85-90% | 11.3s | $0.05 |
| meta-llama/llama-3.3-70b | 85% | 38.4s | $0.05 |
| openai/gpt-4.1-nano | 70% | 52.3s | -- |

## Common Failure Patterns

1. **Internal-only attacks**: RFC1918 IPs have no external reputation data
2. **UEBA false positives**: Legitimate admin activity flagged as anomalous
3. **Subtle cloud attacks**: Policy changes that look routine to log analysis

## Test Suite

- **183 tests** across 6 test files (tools, prompts, agent, dashboard, edge cases, bonus)
- Run: `make test`
"""


# ── Input parsing ─────────────────────────────────────────────────────────────

def _parse_input(text: str) -> list[AlertInput]:
    """Parse user message into one or more AlertInput objects."""
    text = text.strip()

    # Try JSON
    if text.startswith("{") or text.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return [AlertInput.from_dict(data)]
            if isinstance(data, list):
                return [AlertInput.from_dict(d) for d in data if isinstance(d, dict)]
        except json.JSONDecodeError:
            pass

    # Try CSV (header row required)
    if "," in text and "\n" in text:
        try:
            reader = csv.DictReader(io.StringIO(text))
            alerts = [AlertInput.from_dict(dict(row)) for row in reader]
            if alerts:
                return alerts
        except Exception:
            pass

    # Plain text — treat entire message as log payload
    return [AlertInput.from_dict({"payload": text, "alert_id": str(uuid.uuid4())[:8]})]


def _parse_file(content: bytes, mime: str, filename: str) -> list[AlertInput]:
    """Parse uploaded file content into AlertInput list."""
    text = content.decode("utf-8", errors="replace").strip()

    if filename.endswith(".json") or "json" in mime:
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return [AlertInput.from_dict(data)]
            if isinstance(data, list):
                return [AlertInput.from_dict(d) for d in data if isinstance(d, dict)]
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}") from e

    if filename.endswith(".csv") or "csv" in mime:
        reader = csv.DictReader(io.StringIO(text))
        alerts = [AlertInput.from_dict(dict(row)) for row in reader]
        if not alerts:
            raise ValueError("CSV file is empty or has no valid rows")
        return alerts

    # .txt — one alert per non-empty line
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return [AlertInput.from_dict({"payload": line, "alert_id": str(uuid.uuid4())[:8]})
            for line in lines]


# ── Tool-to-agent mapping ────────────────────────────────────────────────────

_NAME_TO_DISPLAY = {
    # Subagent names (as the LLM reports them)
    "network_intel_agent": "Network Intel Agent",
    "log_payload_agent": "Log & Payload Agent",
    "user_behavior_agent": "User Behavior Agent",
    # Tool names (if reported individually)
    "ip_full_profile_tool": "Network Intel Agent",
    "ip_reputation_tool": "Network Intel Agent",
    "geoip_tool": "Network Intel Agent",
    "dns_tool": "Network Intel Agent",
    "whois_tool": "Network Intel Agent",
    "threat_intel_tool": "Network Intel Agent",
    "network_traffic_tool": "Network Intel Agent",
    "log_pattern_tool": "Log & Payload Agent",
    "payload_decoder_tool": "Log & Payload Agent",
    "cve_tool": "Log & Payload Agent",
    "user_behavior_tool": "User Behavior Agent",
}

_AGENT_TOOLS = {
    "network_intel_agent": "ip_full_profile, ip_reputation, geoip, dns, whois, threat_intel, network_traffic",
    "log_payload_agent": "log_pattern, payload_decoder, cve_lookup",
    "user_behavior_agent": "user_behavior_analyzer",
}


def _resolve_agents(names: list[str]) -> list[str]:
    agents = ["Coordinator-MainAgent"]
    for n in names:
        display = _NAME_TO_DISPLAY.get(n)
        if display and display not in agents:
            agents.append(display)
    return agents


def _resolve_tools_from_agents(names: list[str]) -> list[str]:
    tools = []
    for n in names:
        if n in _AGENT_TOOLS:
            tools.append(_AGENT_TOOLS[n])
    return tools if tools else ["—"]


# ── Single alert investigation ────────────────────────────────────────────────

async def _investigate(alert: AlertInput) -> VerdictOutput:
    """Run the agent stream and render live steps in Chainlit."""
    custom = cl.user_session.get("custom_model", "").strip()
    ollama_choice = cl.user_session.get("ollama_model", "none")
    cloud_choice = cl.user_session.get("cloud_model", CLOUD_MODELS[0])

    import agent as _agent_mod

    custom_provider = cl.user_session.get("custom_provider", "Cloud (OpenRouter)")

    if custom:
        if custom_provider == "Local (Ollama)":
            settings.model_provider = "ollama"
            settings.ollama_model = custom
        else:
            settings.model_provider = "openrouter"
            settings.openrouter_model = custom
    elif ollama_choice and ollama_choice != "none":
        settings.model_provider = "ollama"
        settings.ollama_model = ollama_choice
    else:
        settings.model_provider = "openrouter"
        settings.openrouter_model = _resolve_cloud_model(cloud_choice)

    _agent_mod._agent = None

    verdict: Optional[VerdictOutput] = None

    async with cl.Step(name=f"Investigating Alert {alert.alert_id or ''}", type="run") as root_step:
        root_step.input = f"Source IP: `{alert.source_ip or 'N/A'}`\n```\n{alert.log_payload or ''}\n```"

        loop = asyncio.get_event_loop()
        try:
            stream_events = await loop.run_in_executor(
                None, lambda: list(run_agent_stream(alert))
            )
        except Exception as e:
            await cl.Message(content=f"Error during investigation: {e}", author="SOC Agent").send()
            return None

        for event in stream_events:
            etype   = event["type"]
            content = event.get("content", "")

            if etype == "thought":
                if isinstance(content, str) and content.strip():
                    await cl.Message(
                        content=f"**Coordinator:** {content}",
                        author="Coordinator",
                        parent_id=root_step.id,
                    ).send()

            elif etype == "tool_call":
                tool_name = event.get("tool_name", "tool")
                label = "Planning" if tool_name == "write_todos" else "Delegating to subagent" if tool_name == "task" else tool_name
                step = cl.Step(name=label, type="tool",
                               parent_id=root_step.id, default_open=False)
                await step.__aenter__()
                step.input = content
                await step.__aexit__(None, None, None)

            elif etype == "tool_result":
                tool_name = event.get("tool_name", "tool")
                result_text = str(content)[:800]
                label = "Plan ready" if tool_name == "write_todos" else "Subagent result" if tool_name == "task" else f"{tool_name} result"
                step = cl.Step(name=label, type="tool",
                               parent_id=root_step.id, default_open=False)
                await step.__aenter__()
                step.output = result_text
                await step.__aexit__(None, None, None)

            elif etype == "verdict":
                verdict = content
                root_step.output = f"Verdict: **{verdict.verdict}** ({verdict.confidence:.0%})"

    return verdict


# ── Batch mode ────────────────────────────────────────────────────────────────

async def _run_batch(alerts: list[AlertInput]):
    """Investigate multiple alerts and show a summary table."""
    await cl.Message(
        content=f"📦 **Batch mode:** {len(alerts)} alerts detected. Investigating...",
        author="SOC Agent",
    ).send()

    results: list[tuple[AlertInput, VerdictOutput]] = []

    for i, alert in enumerate(alerts, 1):
        await cl.Message(
            content=f"**Alert {i}/{len(alerts)}** — `{alert.alert_id}`",
            author="SOC Agent",
        ).send()
        verdict = await _investigate(alert)
        if verdict:
            results.append((alert, verdict))
            await cl.Message(content=_verdict_card(verdict), author="SOC Agent").send()

    # Summary table
    if results:
        table_rows = []
        for i, (a, v) in enumerate(results):
            agents_used = _resolve_agents(v.investigated_tools) if v.investigated_tools else ["Coordinator"]
            tools_from_agents = _resolve_tools_from_agents(v.investigated_tools) if v.investigated_tools else ["—"]

            table_rows.append(
                f"| `{a.alert_id or i+1}` | {_VERDICT_EMOJI[v.verdict]} {v.verdict} "
                f"| {v.confidence:.0%} | {', '.join(v.mitre_techniques[:2]) or '—'} "
                f"| {', '.join(agents_used)} | {', '.join(tools_from_agents)} |"
            )

        table = (
            "## 📊 Batch Summary\n\n"
            "| Alert ID | Verdict | Confidence | MITRE | Main & Subagents Used | Tools Used |\n"
            "|----------|---------|------------|-------|-----------------------|------------|\n"
            + "\n".join(table_rows)
        )
        await cl.Message(content=table, author="SOC Agent").send()


# ── Main message handler ──────────────────────────────────────────────────────

@cl.on_message
async def on_message(message: cl.Message):
    """Handle incoming user messages — text, JSON, CSV, or file upload."""

    # ── File upload ───────────────────────────────────────────────────────────
    if message.elements:
        for element in message.elements:
            raw = None
            name = getattr(element, "name", "upload.txt")
            mime = getattr(element, "mime", "text/plain")

            # Chainlit 2.x: read from path on disk
            if hasattr(element, "path") and element.path:
                try:
                    with open(element.path, "rb") as f:
                        raw = f.read()
                except Exception as e:
                    await cl.Message(content=f"Error reading file: {e}", author="SOC Agent").send()
                    return
            # Chainlit 1.x fallback: content attribute
            elif hasattr(element, "content") and element.content:
                raw = element.content if isinstance(element.content, bytes) \
                      else element.content.encode()

            if not raw:
                await cl.Message(content="Could not read uploaded file.", author="SOC Agent").send()
                return

            try:
                alerts = _parse_file(raw, mime, name)
            except ValueError as e:
                await cl.Message(content=f"File parse error: {e}", author="SOC Agent").send()
                return

            if len(alerts) == 1:
                verdict = await _investigate(alerts[0])
                if verdict:
                    await cl.Message(content=_verdict_card(verdict), author="SOC Agent").send()
            else:
                await _run_batch(alerts)
            return

    # ── Text / JSON input ─────────────────────────────────────────────────────
    text = message.content.strip()
    if not text:
        await cl.Message(content="Please provide an alert to investigate.", author="SOC Agent").send()
        return

    # ── Info commands ────────────────────────────────────────────────────────
    text_lower = text.lower().strip()
    if text_lower in ("/architecture", "architecture", "/arch"):
        await cl.Message(content=ARCHITECTURE_PAGE, author="SOC Agent").send()
        return
    if text_lower in ("/tools", "tools", "/tool"):
        await cl.Message(content=TOOLS_PAGE, author="SOC Agent").send()
        return
    if text_lower in ("/benchmarks", "benchmarks", "/benchmark", "/results"):
        await cl.Message(content=BENCHMARKS_PAGE, author="SOC Agent").send()
        return
    if text_lower in ("/demo", "demo"):
        import os
        demo_path = os.path.join(os.path.dirname(__file__), "demo", "demo_6_alerts.json")
        if os.path.exists(demo_path):
            with open(demo_path) as f:
                demo_alerts = json.load(f)
            alerts = [AlertInput.from_dict(d) for d in demo_alerts]
            await _run_batch(alerts)
        else:
            await cl.Message(content="Demo file not found. Place `demo_6_alerts.json` in `demo/` folder.", author="SOC Agent").send()
        return

    try:
        alerts = _parse_input(text)
    except Exception as e:
        await cl.Message(content=f"Input parse error: {e}", author="SOC Agent").send()
        return

    if len(alerts) == 1:
        verdict = await _investigate(alerts[0])
        if verdict:
            await cl.Message(content=_verdict_card(verdict), author="SOC Agent").send()
    else:
        await _run_batch(alerts)
