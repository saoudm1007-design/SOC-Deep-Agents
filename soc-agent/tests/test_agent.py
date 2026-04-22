"""
Milestone 4 — Integration tests for agent.py, tool_registry.py, subagents.py.

LLM integration tests are skipped unless RUN_LLM_TESTS=1 env var is set.

Run: cd soc-agent && .venv/bin/python -m pytest tests/test_agent.py -v
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from models import AlertInput, VerdictOutput


# ─────────────────────────────────────────────
# Tool registry — import + structure checks
# ─────────────────────────────────────────────
class TestToolRegistry:
    def test_imports(self):
        from tool_registry import (
            ip_reputation_tool, geoip_tool, dns_tool, whois_tool,
            threat_intel_tool, network_traffic_tool,
            log_pattern_tool, payload_decoder_tool, cve_tool,
            user_behavior_tool,
        )
        tools = [ip_reputation_tool, geoip_tool, dns_tool, whois_tool,
                 threat_intel_tool, network_traffic_tool,
                 log_pattern_tool, payload_decoder_tool, cve_tool,
                 user_behavior_tool]
        assert len(tools) == 10

    def test_tool_lists(self):
        from tool_registry import NETWORK_TOOLS, LOG_TOOLS, USER_TOOLS, ALL_TOOLS
        # NETWORK_TOOLS: 6 original + 1 parallel fan-out composite (ip_full_profile_tool)
        assert len(NETWORK_TOOLS) == 7
        assert len(LOG_TOOLS) == 3
        assert len(USER_TOOLS) == 1
        assert len(ALL_TOOLS) == 11

    def test_tools_have_name_and_description(self):
        from tool_registry import ALL_TOOLS
        for t in ALL_TOOLS:
            assert hasattr(t, "name") and t.name
            assert hasattr(t, "description") and len(t.description) > 20

    def test_log_pattern_tool_runs(self):
        from tool_registry import log_pattern_tool
        result = log_pattern_tool.invoke({"log_payload": "mimikatz sekurlsa::logonpasswords"})
        assert "T1003" in result

    def test_cve_tool_runs_static(self):
        from tool_registry import cve_tool
        result = cve_tool.invoke({"cve_id": "CVE-2021-44228"})
        assert "10.0" in result or "CRITICAL" in result

    def test_user_behavior_tool_runs(self):
        from tool_registry import user_behavior_tool
        result = user_behavior_tool.invoke({
            "log_payload": "impossible_travel detected T03:00:00Z",
            "username": "john",
        })
        assert "risk_score" in result

    def test_payload_decoder_tool_runs(self):
        import base64
        from tool_registry import payload_decoder_tool
        encoded = base64.b64encode(b"powershell -nop -w hidden").decode()
        result = payload_decoder_tool.invoke({"payload": encoded})
        assert "base64" in result


# ─────────────────────────────────────────────
# Subagents — structure validation
# ─────────────────────────────────────────────
class TestSubagents:
    def test_imports(self):
        from subagents import SUBAGENTS, network_intel_agent, log_payload_agent, user_behavior_agent
        assert len(SUBAGENTS) == 3

    def test_subagent_required_fields(self):
        from subagents import SUBAGENTS
        for agent in SUBAGENTS:
            assert "name" in agent
            assert "description" in agent
            assert "system_prompt" in agent
            assert "tools" in agent

    def test_subagent_names(self):
        from subagents import SUBAGENTS
        names = [a["name"] for a in SUBAGENTS]
        assert "network_intel_agent" in names
        assert "log_payload_agent" in names
        assert "user_behavior_agent" in names

    def test_subagent_tool_counts(self):
        from subagents import network_intel_agent, log_payload_agent, user_behavior_agent
        assert len(network_intel_agent["tools"]) == 7
        assert len(log_payload_agent["tools"]) == 3
        assert len(user_behavior_agent["tools"]) == 1

    def test_subagent_descriptions_are_detailed(self):
        from subagents import SUBAGENTS
        for agent in SUBAGENTS:
            assert len(agent["description"]) >= 100

    def test_subagent_prompts_are_loaded(self):
        from subagents import SUBAGENTS
        for agent in SUBAGENTS:
            assert len(agent["system_prompt"]) >= 300


# ─────────────────────────────────────────────
# Agent build (no LLM call — just checks it builds)
# ─────────────────────────────────────────────
class TestAgentBuild:
    def test_build_llm(self):
        from agent import _build_llm
        llm = _build_llm()
        assert llm is not None

    def test_build_agent(self):
        from agent import _build_agent, _get_agent
        _agent = None  # reset cache
        agent = _build_agent()
        assert agent is not None

    def test_parse_verdict_from_content(self):
        from agent import _parse_verdict_from_content
        content = '''
        After investigation I conclude:
        VERDICT_JSON:
        {"verdict": "Malicious", "confidence": 0.92, "reasoning": "SQL injection confirmed",
         "mitre_techniques": ["T1190 — Exploit Public-Facing Application"],
         "recommended_actions": ["Block IP"], "investigated_tools": ["log_pattern_analyzer"]}
        '''
        v = _parse_verdict_from_content(content, "TEST")
        assert v is not None
        assert v.verdict == "Malicious"
        assert v.confidence == 0.92

    def test_parse_verdict_fallback_json(self):
        from agent import _parse_verdict_from_content
        # secondary: plain JSON with verdict key, no tag
        content = '{"verdict": "Benign", "confidence": 0.88, "reasoning": "clean", "mitre_techniques": [], "recommended_actions": [], "investigated_tools": []}'
        v = _parse_verdict_from_content(content, "TEST")
        assert v is not None
        assert v.verdict == "Benign"

    def test_parse_verdict_returns_none_when_no_json(self):
        from agent import _parse_verdict_from_content
        v = _parse_verdict_from_content("no verdict here", "TEST")
        assert v is None


    def test_run_agent_returns_verdict_output(self):
        """run_agent returns proper VerdictOutput with all fields."""
        from agent import run_agent
        alert = AlertInput.from_dict({"payload": "mimikatz lsass dump"})
        result = run_agent(alert)
        assert isinstance(result, VerdictOutput)
        assert result.verdict in ("Malicious", "Suspicious", "Benign")
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.reasoning, str) and len(result.reasoning) > 10
        assert isinstance(result.mitre_techniques, list)
        assert isinstance(result.recommended_actions, list)
        assert isinstance(result.investigated_tools, list)


# ─────────────────────────────────────────────
# LLM integration tests (skipped by default)
# ─────────────────────────────────────────────
SKIP_LLM = os.getenv("RUN_LLM_TESTS", "0") != "1"

@pytest.mark.skipif(SKIP_LLM, reason="Set RUN_LLM_TESTS=1 to run live LLM tests")
class TestLLMIntegration:
    def test_sql_injection_malicious(self):
        from agent import run_agent
        alert = AlertInput.from_dict({
            "alert_id": "LLM-SQL-001",
            "src_ip": "45.33.32.156",
            "payload": (
                "GET /login?user=' OR '1'='1&pass=x HTTP/1.1 400 "
                "src=45.33.32.156 user_agent=sqlmap/1.7"
            ),
        })
        result = run_agent(alert)
        assert result.verdict == "Malicious"
        assert result.confidence >= 0.85

    def test_benign_system_update(self):
        from agent import run_agent
        alert = AlertInput.from_dict({
            "alert_id": "LLM-BENIGN-001",
            "src_ip": "13.107.4.50",
            "payload": "Windows Update service downloaded KB5025221 from windowsupdate.com",
        })
        result = run_agent(alert)
        assert result.verdict == "Benign"

    def test_verdict_has_all_fields(self):
        from agent import run_agent
        alert = AlertInput.from_dict({
            "alert_id": "LLM-FULL-001",
            "src_ip": "185.220.101.5",
            "payload": "failed_password count: 150 authentication_fail admin",
        })
        result = run_agent(alert)
        assert result.verdict in ("Malicious", "Suspicious", "Benign")
        assert 0.0 <= result.confidence <= 1.0
        assert len(result.reasoning) > 20
        assert len(result.investigated_tools) > 0


if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        [".venv/bin/python", "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    sys.exit(result.returncode)
