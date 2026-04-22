"""
SOC Analyst Deep Agents — pure agentic coordinator.

Architecture:
  Alert → create_deep_agent (coordinator) → delegates to 3 subagents via `task` tool
  All results → VerdictOutput (response_format enforces structured JSON)
"""
import re
import json
import uuid
import logging
from typing import Optional

from langchain_openai import ChatOpenAI
from deepagents import create_deep_agent
from langgraph.checkpoint.memory import MemorySaver

from config import settings
from models import AlertInput, VerdictOutput
from prompts import COORDINATOR_PROMPT
from subagents import SUBAGENTS

log = logging.getLogger(__name__)


# ── LLM initialisation ───────────────────────────────────────────────────────

def _build_llm() -> ChatOpenAI:
    """Construct the LLM based on config. Defaults to OpenRouter.

    When the OpenRouter model routes to Anthropic (anthropic/*), we enable
    prompt caching via the anthropic-beta header so the large coordinator
    system prompt is cached across turns. Anthropic charges ~10% of input
    cost on cache hits (90% savings on the system prompt).
    """
    if settings.model_provider == "openrouter":
        extra_headers = {}
        if settings.openrouter_model.startswith("anthropic/"):
            extra_headers["anthropic-beta"] = "prompt-caching-2024-07-31"
        return ChatOpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=settings.openrouter_api_key,
            model=settings.openrouter_model,
            temperature=0,
            default_headers=extra_headers or None,
        )
    if settings.model_provider == "claude":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model,
            temperature=0,
        )
    # Ollama fallback
    from langchain_ollama import ChatOllama
    return ChatOllama(
        base_url=settings.ollama_base_url,
        model=settings.ollama_model,
        temperature=0,
    )


# ── Agent construction ────────────────────────────────────────────────────────

def _build_agent():
    """Build and return the coordinator deep agent (cached at module level)."""
    llm = _build_llm()
    # Note: response_format is intentionally omitted — Gemini via OpenRouter does not
    # support deepagents' structured output mechanism. We parse VERDICT_JSON from
    # the coordinator's final text message instead (see _parse_verdict_from_content).
    return create_deep_agent(
        model=llm,
        tools=[],              # coordinator delegates — subagents own the tools
        system_prompt=COORDINATOR_PROMPT,
        subagents=SUBAGENTS,
        checkpointer=MemorySaver(),  # per-alert state isolation via thread_id
    )


# Module-level agent instance (lazy, built on first call)
_agent = None

# Per-thread last-run usage tracker (populated by run_agent, read by callers
# like benchmark.py that want token-level cost tracking).
LAST_RUN_USAGE: dict = {"input": 0, "output": 0, "cache_read": 0, "cache_creation": 0}


def _get_agent():
    global _agent
    if _agent is None:
        _agent = _build_agent()
    return _agent


# ── Entry point ───────────────────────────────────────────────────────────────

def _build_user_message(alert: AlertInput, alert_id: str) -> str:
    parts = [f"SECURITY ALERT — ID: {alert_id}"]
    if alert.source_ip:
        parts.append(f"Source IP: {alert.source_ip}")
    if alert.destination_ip:
        parts.append(f"Destination IP: {alert.destination_ip}")
    if alert.event_type:
        parts.append(f"Event Type: {alert.event_type}")
    if alert.log_payload:
        parts.append(f"Log/Payload:\n{alert.log_payload}")
    return "\n".join(parts)


def _extract_model_content(event: dict) -> tuple[str, list]:
    """Extract text content and tool_calls from a model event."""
    msg = event.get("model", {}).get("messages", [None])[-1]
    if msg is None:
        return "", []
    content = msg.content if isinstance(msg.content, str) else ""
    tool_calls = getattr(msg, "tool_calls", []) or []
    return content, tool_calls


def _extract_usage(event: dict) -> dict:
    """Extract token usage from a model event (OpenAI/OpenRouter schema).

    Returns {'input': n, 'output': n, 'cache_read': n, 'cache_creation': n}
    Missing fields default to 0.
    """
    msg = event.get("model", {}).get("messages", [None])[-1]
    if msg is None:
        return {}
    usage = getattr(msg, "usage_metadata", None) or {}
    details = usage.get("input_token_details", {}) or {}
    return {
        "input":          usage.get("input_tokens", 0),
        "output":         usage.get("output_tokens", 0),
        "cache_read":     details.get("cache_read", 0),
        "cache_creation": details.get("cache_creation", 0),
    }


def _parse_verdict_from_content(all_content: str, alert_id: str) -> Optional[VerdictOutput]:
    """
    Extract VERDICT_JSON block from the coordinator's accumulated text output.
    The coordinator is instructed to output 'VERDICT_JSON:' followed by a JSON object.
    """
    # Primary: look for our explicit VERDICT_JSON tag
    match = re.search(r"VERDICT_JSON:\s*(\{.*?\})", all_content, re.DOTALL | re.IGNORECASE)
    if match:
        try:
            data = json.loads(match.group(1))
            return VerdictOutput(**data)
        except Exception as e:
            log.warning("alert=%s VERDICT_JSON parse failed: %s", alert_id, e)

    # Secondary: find any JSON object with a "verdict" key
    for match in re.finditer(r"\{[^{}]*\"verdict\"[^{}]*\}", all_content, re.DOTALL):
        try:
            data = json.loads(match.group())
            if data.get("verdict") in ("Malicious", "Suspicious", "Benign"):
                return VerdictOutput(**data)
        except Exception:
            continue

    return None


def run_agent(alert: AlertInput) -> VerdictOutput:
    """
    Investigate a security alert and return a structured verdict.

    Flow:
      1. Deep agent — full investigation via coordinator + 3 subagents
      2. Parse VERDICT_JSON block from coordinator's final text output
    """
    # Reset per-run token counter
    LAST_RUN_USAGE.update({"input": 0, "output": 0, "cache_read": 0, "cache_creation": 0})

    alert_id = alert.alert_id or str(uuid.uuid4())[:8]
    user_message = _build_user_message(alert, alert_id)
    config = {"configurable": {"thread_id": f"soc-{alert_id}"}}
    agent = _get_agent()

    all_content_parts: list[str] = []

    for event in agent.stream(
        {"messages": [("user", user_message)]},
        config=config,
    ):
        # deepagents uses "model" key (not "agent") for LLM output events
        if "model" in event:
            content, _ = _extract_model_content(event)
            usage = _extract_usage(event)
            for k, v in usage.items():
                LAST_RUN_USAGE[k] = LAST_RUN_USAGE.get(k, 0) + v
            if content:
                all_content_parts.append(content)
                # Early exit: stop streaming once verdict is in final message
                if "VERDICT_JSON:" in content:
                    break

    all_content = "\n".join(all_content_parts)
    verdict = _parse_verdict_from_content(all_content, alert_id)

    # Retry up to twice on empty / malformed final message — Gemini
    # occasionally returns a blank synthesis even when the investigation
    # went well. Fresh thread_id avoids cached state.
    for attempt in range(2):
        if verdict is not None:
            break
        log.warning("alert=%s empty verdict — retry %d/2", alert_id, attempt + 1)
        retry_config = {"configurable": {"thread_id": f"soc-{alert_id}-retry{attempt}"}}
        retry_msg = (
            user_message
            + "\n\nYour PREVIOUS response did not end with the required "
            "VERDICT_JSON: block. Re-examine the alert and emit a final "
            "message with VERDICT_JSON: { verdict, confidence, reasoning, "
            "mitre_techniques, recommended_actions, investigated_tools }. "
            "Benign is the default verdict when no attack indicators are "
            "found by any subagent. Do NOT emit Suspicious at 0.4 — make "
            "a decision between Malicious or Benign."
        )
        retry_parts: list[str] = []
        try:
            for event in agent.stream({"messages": [("user", retry_msg)]}, config=retry_config):
                if "model" in event:
                    content, _ = _extract_model_content(event)
                    if content:
                        retry_parts.append(content)
                        if "VERDICT_JSON:" in content:
                            break
            verdict = _parse_verdict_from_content("\n".join(retry_parts), alert_id)
        except Exception as e:
            log.warning("alert=%s retry %d failed: %s", alert_id, attempt + 1, e)

    if verdict is None:
        log.warning("alert=%s could not parse verdict — using fallback", alert_id)
        verdict = VerdictOutput(
            verdict="Suspicious",
            confidence=0.4,
            reasoning=(
                "Investigation completed but structured verdict could not be extracted. "
                f"Raw output length: {len(all_content)} chars. Manual review recommended."
            ),
            mitre_techniques=[],
            recommended_actions=["Manual analyst review required"],
            investigated_tools=["llm_investigation"],
        )

    log.info("alert=%s verdict=%s conf=%.2f", alert_id, verdict.verdict, verdict.confidence)
    return verdict


def run_agent_stream(alert: AlertInput):
    """
    Generator version of run_agent — yields streaming events for Chainlit dashboard.

    Yields:
        {"type": "thought",     "content": str}
        {"type": "tool_call",   "content": str, "tool_name": str}
        {"type": "tool_result", "content": str, "tool_name": str}
        {"type": "verdict",     "content": VerdictOutput}
    """
    alert_id = alert.alert_id or str(uuid.uuid4())[:8]
    user_message = _build_user_message(alert, alert_id)
    config = {"configurable": {"thread_id": f"soc-{alert_id}"}}
    agent = _get_agent()

    all_content_parts: list[str] = []
    verdict = None

    for event in agent.stream(
        {"messages": [("user", user_message)]},
        config=config,
    ):
        if "model" in event:
            content, tool_calls = _extract_model_content(event)
            if content:
                all_content_parts.append(content)
                yield {"type": "thought", "content": content}
                if "VERDICT_JSON:" in content:
                    break
            for tc in tool_calls:
                yield {
                    "type": "tool_call",
                    "content": json.dumps(tc.get("args", {}), indent=2),
                    "tool_name": tc.get("name", "tool"),
                }

        elif "tools" in event:
            tool_msg = event["tools"]["messages"][-1]
            yield {
                "type": "tool_result",
                "content": str(tool_msg.content)[:500],
                "tool_name": getattr(tool_msg, "name", "tool"),
            }

    all_content = "\n".join(all_content_parts)
    verdict = _parse_verdict_from_content(all_content, alert_id)

    if verdict is None:
        verdict = VerdictOutput(
            verdict="Suspicious",
            confidence=0.4,
            reasoning="Investigation completed but verdict could not be extracted. Manual review required.",
            mitre_techniques=[],
            recommended_actions=["Manual analyst review required"],
            investigated_tools=["llm_investigation"],
        )

    yield {"type": "verdict", "content": verdict}
