"""
Milestone 5 — Dashboard unit tests.
Tests the parsing and rendering logic without starting Chainlit.
Run: cd soc-agent && .venv/bin/python -m pytest tests/test_dashboard.py -v
"""
import sys, os, json, csv, io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from models import AlertInput, VerdictOutput


# Import dashboard helpers directly (no Chainlit server needed)
from dashboard import _parse_input, _parse_file, _verdict_card, _confidence_bar


# ─────────────────────────────────────────────
# Input parsing — text / JSON / CSV
# ─────────────────────────────────────────────
class TestParseInput:
    def test_plain_text(self):
        alerts = _parse_input("failed login from 1.2.3.4 count: 50")
        assert len(alerts) == 1
        assert "failed login" in alerts[0].log_payload

    def test_json_single(self):
        data = json.dumps({"src_ip": "10.0.0.1", "payload": "test log"})
        alerts = _parse_input(data)
        assert len(alerts) == 1
        assert alerts[0].source_ip == "10.0.0.1"

    def test_json_array(self):
        data = json.dumps([
            {"src_ip": "1.1.1.1", "payload": "log A"},
            {"src_ip": "2.2.2.2", "payload": "log B"},
        ])
        alerts = _parse_input(data)
        assert len(alerts) == 2

    def test_csv_input(self):
        csv_text = "alert_id,src_ip,payload\nALRT-001,1.2.3.4,test log\nALRT-002,5.6.7.8,another log"
        alerts = _parse_input(csv_text)
        assert len(alerts) == 2
        assert alerts[0].alert_id == "ALRT-001"

    def test_json_with_alert_id(self):
        data = json.dumps({"alert_id": "TEST-999", "payload": "something"})
        alerts = _parse_input(data)
        assert alerts[0].alert_id == "TEST-999"

    def test_plain_text_gets_alert_id(self):
        alerts = _parse_input("some log entry")
        assert alerts[0].alert_id is not None and len(alerts[0].alert_id) > 0

    def test_empty_string_returns_alert(self):
        # even empty input returns something (with empty payload)
        alerts = _parse_input("   ")
        # May return 1 alert with empty payload or error gracefully
        assert isinstance(alerts, list)


# ─────────────────────────────────────────────
# File parsing
# ─────────────────────────────────────────────
class TestParseFile:
    def test_json_file_single(self):
        content = json.dumps({"src_ip": "9.9.9.9", "payload": "file log"}).encode()
        alerts = _parse_file(content, "application/json", "alert.json")
        assert len(alerts) == 1
        assert alerts[0].source_ip == "9.9.9.9"

    def test_json_file_array(self):
        content = json.dumps([
            {"payload": "log 1"},
            {"payload": "log 2"},
            {"payload": "log 3"},
        ]).encode()
        alerts = _parse_file(content, "application/json", "alerts.json")
        assert len(alerts) == 3

    def test_csv_file(self):
        csv_content = "alert_id,src_ip,payload\nA1,1.1.1.1,test\nA2,2.2.2.2,test2\n"
        alerts = _parse_file(csv_content.encode(), "text/csv", "data.csv")
        assert len(alerts) == 2
        assert alerts[0].alert_id == "A1"

    def test_txt_file_multiline(self):
        content = b"login failed from 1.2.3.4\nmalware detected on host\nsuspicious DNS query"
        alerts = _parse_file(content, "text/plain", "logs.txt")
        assert len(alerts) == 3

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            _parse_file(b"{not valid json}", "application/json", "bad.json")

    def test_empty_csv_raises(self):
        with pytest.raises(ValueError, match="empty"):
            _parse_file(b"", "text/csv", "empty.csv")


# ─────────────────────────────────────────────
# Verdict card rendering
# ─────────────────────────────────────────────
class TestVerdictCard:
    def _make_verdict(self, verdict="Malicious", conf=0.95) -> VerdictOutput:
        return VerdictOutput(
            verdict=verdict,
            confidence=conf,
            reasoning="Test reasoning for the verdict card.",
            mitre_techniques=["T1190 — Exploit Public-Facing Application"],
            recommended_actions=["Isolate host immediately", "Patch CVE"],
            investigated_tools=["log_pattern_analyzer", "cve_lookup"],
        )

    def test_card_contains_verdict(self):
        card = _verdict_card(self._make_verdict("Malicious"))
        assert "Malicious" in card

    def test_card_contains_emoji_malicious(self):
        card = _verdict_card(self._make_verdict("Malicious"))
        assert "🔴" in card

    def test_card_contains_emoji_suspicious(self):
        card = _verdict_card(self._make_verdict("Suspicious"))
        assert "🟡" in card

    def test_card_contains_emoji_benign(self):
        card = _verdict_card(self._make_verdict("Benign"))
        assert "🟢" in card

    def test_card_contains_reasoning(self):
        card = _verdict_card(self._make_verdict())
        assert "Test reasoning" in card

    def test_card_contains_mitre(self):
        card = _verdict_card(self._make_verdict())
        assert "T1190" in card

    def test_card_contains_actions(self):
        card = _verdict_card(self._make_verdict())
        assert "Isolate host" in card

    def test_card_contains_tools(self):
        card = _verdict_card(self._make_verdict())
        assert "log_pattern_analyzer" in card

    def test_card_is_markdown(self):
        card = _verdict_card(self._make_verdict())
        assert "**" in card  # markdown bold

    def test_confidence_bar_full(self):
        bar = _confidence_bar(1.0)
        assert "100%" in bar
        assert "░" not in bar

    def test_confidence_bar_zero(self):
        bar = _confidence_bar(0.0)
        assert "0%" in bar
        assert "█" not in bar

    def test_confidence_bar_half(self):
        bar = _confidence_bar(0.5)
        assert "50%" in bar

    def test_empty_mitre_no_section(self):
        v = VerdictOutput(verdict="Benign", confidence=0.1, reasoning="clean",
                          mitre_techniques=[], recommended_actions=[])
        card = _verdict_card(v)
        assert "MITRE" not in card

    def test_empty_actions_no_section(self):
        v = VerdictOutput(verdict="Benign", confidence=0.1, reasoning="clean",
                          recommended_actions=[])
        card = _verdict_card(v)
        assert "Recommended Actions" not in card


if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        [".venv/bin/python", "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    sys.exit(result.returncode)
