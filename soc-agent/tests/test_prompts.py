"""
Milestone 3 — Prompt verification tests.
Checks: imports, length, keyword coverage, VerdictOutput schema.
Run: cd soc-agent && python3 -m pytest tests/test_prompts.py -v
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from prompts import (
    COORDINATOR_PROMPT,
    NETWORK_AGENT_PROMPT,
    LOG_AGENT_PROMPT,
    USER_AGENT_PROMPT,
)
from models import VerdictOutput


# ─────────────────────────────────────────────
# Prompt sanity checks
# ─────────────────────────────────────────────
class TestPromptsLoad:
    def test_all_prompts_are_strings(self):
        for p in [COORDINATOR_PROMPT, NETWORK_AGENT_PROMPT, LOG_AGENT_PROMPT, USER_AGENT_PROMPT]:
            assert isinstance(p, str) and len(p) > 100

    def test_coordinator_min_length(self):
        assert len(COORDINATOR_PROMPT) >= 1000

    def test_subagent_prompts_min_length(self):
        for p in [NETWORK_AGENT_PROMPT, LOG_AGENT_PROMPT, USER_AGENT_PROMPT]:
            assert len(p) >= 500


class TestCoordinatorPrompt:
    def test_mentions_picerl(self):
        assert "PICERL" in COORDINATOR_PROMPT

    def test_mentions_all_three_subagents(self):
        assert "network_intel_agent" in COORDINATOR_PROMPT
        assert "log_payload_agent" in COORDINATOR_PROMPT
        assert "user_behavior_agent" in COORDINATOR_PROMPT

    def test_mentions_builtin_tools(self):
        assert "write_todos" in COORDINATOR_PROMPT
        assert "task" in COORDINATOR_PROMPT
        assert "write_file" in COORDINATOR_PROMPT

    def test_mentions_verdict_values(self):
        assert "Malicious" in COORDINATOR_PROMPT
        assert "Suspicious" in COORDINATOR_PROMPT
        assert "Benign" in COORDINATOR_PROMPT

    def test_mentions_confidence(self):
        assert "confidence" in COORDINATOR_PROMPT.lower()

    def test_mentions_mitre(self):
        assert "MITRE" in COORDINATOR_PROMPT or "T1" in COORDINATOR_PROMPT

    def test_output_schema_fields(self):
        # All VerdictOutput fields must appear in coordinator prompt
        for field in ["verdict", "confidence", "reasoning",
                      "mitre_techniques", "recommended_actions", "investigated_tools"]:
            assert field in COORDINATOR_PROMPT, f"Missing field: {field}"

    def test_no_placeholder_text(self):
        for placeholder in ["TODO", "FIXME", "PLACEHOLDER", "YOUR_TEXT_HERE"]:
            assert placeholder not in COORDINATOR_PROMPT


class TestNetworkAgentPrompt:
    def test_mentions_all_network_tools(self):
        assert "geoip_lookup" in NETWORK_AGENT_PROMPT
        assert "verify_ip_reputation" in NETWORK_AGENT_PROMPT
        assert "dns_lookup" in NETWORK_AGENT_PROMPT
        assert "whois_lookup" in NETWORK_AGENT_PROMPT
        assert "threat_intel_lookup" in NETWORK_AGENT_PROMPT
        assert "network_traffic_analyzer" in NETWORK_AGENT_PROMPT

    def test_mentions_dga(self):
        assert "DGA" in NETWORK_AGENT_PROMPT or "dga" in NETWORK_AGENT_PROMPT.lower()

    def test_mentions_tor(self):
        assert "Tor" in NETWORK_AGENT_PROMPT or "tor" in NETWORK_AGENT_PROMPT.lower()

    def test_mentions_domain_age(self):
        assert "days" in NETWORK_AGENT_PROMPT.lower()

    def test_has_response_format(self):
        assert "NETWORK ANALYSIS SUMMARY" in NETWORK_AGENT_PROMPT

    def test_mentions_escalation_triggers(self):
        assert "ESCALATION" in NETWORK_AGENT_PROMPT.upper()


class TestLogAgentPrompt:
    def test_mentions_all_log_tools(self):
        assert "log_pattern_analyzer" in LOG_AGENT_PROMPT
        assert "payload_decoder" in LOG_AGENT_PROMPT
        assert "cve_lookup" in LOG_AGENT_PROMPT

    def test_mentions_log4shell(self):
        assert "log4shell" in LOG_AGENT_PROMPT.lower() or "jndi" in LOG_AGENT_PROMPT.lower()

    def test_mentions_encoding_types(self):
        assert "base64" in LOG_AGENT_PROMPT.lower()

    def test_mentions_mitre(self):
        assert "MITRE" in LOG_AGENT_PROMPT

    def test_mentions_cvss(self):
        assert "CVSS" in LOG_AGENT_PROMPT or "cvss" in LOG_AGENT_PROMPT.lower()

    def test_has_response_format(self):
        assert "LOG & PAYLOAD ANALYSIS SUMMARY" in LOG_AGENT_PROMPT

    def test_mentions_escalation_triggers(self):
        assert "ESCALATION" in LOG_AGENT_PROMPT.upper()


class TestUserAgentPrompt:
    def test_mentions_user_behavior_tool(self):
        assert "user_behavior_analyzer" in USER_AGENT_PROMPT

    def test_mentions_ueba(self):
        assert "UEBA" in USER_AGENT_PROMPT or "behavior" in USER_AGENT_PROMPT.lower()

    def test_mentions_impossible_travel(self):
        assert "impossible" in USER_AGENT_PROMPT.lower()

    def test_mentions_off_hours(self):
        assert "off-hours" in USER_AGENT_PROMPT.lower() or "off_hours" in USER_AGENT_PROMPT

    def test_mentions_privilege_escalation(self):
        assert "privilege" in USER_AGENT_PROMPT.lower() or "escalation" in USER_AGENT_PROMPT.lower()

    def test_has_response_format(self):
        assert "USER BEHAVIOR ANALYSIS SUMMARY" in USER_AGENT_PROMPT

    def test_mentions_escalation_triggers(self):
        assert "ESCALATION" in USER_AGENT_PROMPT.upper()

    def test_mentions_risk_levels(self):
        for level in ["Low", "Medium", "High", "Critical"]:
            assert level in USER_AGENT_PROMPT


# ─────────────────────────────────────────────
# VerdictOutput schema validation
# ─────────────────────────────────────────────
class TestVerdictOutputSchema:
    def test_valid_malicious(self):
        v = VerdictOutput(
            verdict="Malicious",
            confidence=0.95,
            reasoning="Log4Shell exploit detected via JNDI pattern in HTTP request.",
            mitre_techniques=["T1190 — Exploit Public-Facing Application"],
            recommended_actions=["Patch CVE-2021-44228 immediately"],
            investigated_tools=["log_pattern_analyzer", "cve_lookup"],
        )
        assert v.verdict == "Malicious"
        assert v.confidence == 0.95

    def test_valid_benign(self):
        v = VerdictOutput(
            verdict="Benign",
            confidence=0.12,
            reasoning="Scheduled Windows update from trusted Microsoft IP.",
            mitre_techniques=[],
            recommended_actions=["No action required"],
            investigated_tools=["geoip_lookup", "dns_lookup"],
        )
        assert v.verdict == "Benign"

    def test_valid_suspicious(self):
        v = VerdictOutput(
            verdict="Suspicious",
            confidence=0.55,
            reasoning="New domain registered 5 days ago with encoded payload.",
            mitre_techniques=["T1027 — Obfuscated Files or Information"],
            recommended_actions=["Monitor for additional activity"],
            investigated_tools=["whois_lookup", "payload_decoder"],
        )
        assert v.verdict == "Suspicious"

    def test_invalid_verdict_rejected(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            VerdictOutput(
                verdict="Unknown",
                confidence=0.5,
                reasoning="test",
            )

    def test_confidence_out_of_range_rejected(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            VerdictOutput(
                verdict="Malicious",
                confidence=1.5,
                reasoning="test",
            )

    def test_reasoning_max_length(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            VerdictOutput(
                verdict="Malicious",
                confidence=0.9,
                reasoning="x" * 601,  # exceeds 600 char limit
            )

    def test_default_empty_lists(self):
        v = VerdictOutput(verdict="Benign", confidence=0.1, reasoning="clean")
        assert v.mitre_techniques == []
        assert v.recommended_actions == []
        assert v.investigated_tools == []


if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        ["python3", "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    sys.exit(result.returncode)
