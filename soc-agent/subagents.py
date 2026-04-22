"""
Subagent definitions for the SOC Deep Agent.
Three specialist subagents are passed to create_deep_agent via the subagents= parameter.
The coordinator delegates to them using the built-in `task` tool.
"""
from deepagents.middleware.subagents import SubAgent

from tool_registry import NETWORK_TOOLS, LOG_TOOLS, USER_TOOLS
from prompts import NETWORK_AGENT_PROMPT, LOG_AGENT_PROMPT, USER_AGENT_PROMPT


network_intel_agent: SubAgent = {
    "name": "network_intel_agent",
    "description": (
        "Investigates network-layer indicators: IP reputation, geolocation, "
        "DNS/DGA analysis, domain age via WHOIS, AlienVault OTX threat intelligence, "
        "and network traffic volume/timing for exfiltration patterns. "
        "Use when the alert contains an IP address, domain, URL, or network traffic data."
    ),
    "system_prompt": NETWORK_AGENT_PROMPT,
    "tools": NETWORK_TOOLS,
}

log_payload_agent: SubAgent = {
    "name": "log_payload_agent",
    "description": (
        "Analyzes log entries, encoded payloads, and CVEs. "
        "Matches 40+ MITRE ATT&CK signatures against log text, decodes multi-layer "
        "obfuscated payloads (base64/URL/hex/gzip), extracts IOCs, and looks up CVE details. "
        "Use when the alert contains log entries, encoded strings, command-line activity, "
        "file operations, CVE references, or attack tool signatures."
    ),
    "system_prompt": LOG_AGENT_PROMPT,
    "tools": LOG_TOOLS,
}

user_behavior_agent: SubAgent = {
    "name": "user_behavior_agent",
    "description": (
        "Evaluates user and entity behavior anomalies (UEBA). "
        "Scores risk across 10 signals: off-hours access, impossible travel, "
        "privilege escalation, first-time resource access, mass file access, "
        "failed login counts, admin/service account anomalies, and sensitive data access. "
        "Use when the alert contains a username, login event, or behavioral anomaly."
    ),
    "system_prompt": USER_AGENT_PROMPT,
    "tools": USER_TOOLS,
}

SUBAGENTS = [network_intel_agent, log_payload_agent, user_behavior_agent]
