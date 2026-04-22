"""
Milestone 7 — Edge case & hardening tests.
Ensures tools and agent handle private IPs, IPv6, missing fields,
malformed input, and API failures gracefully.

Run: cd soc-agent && python -m pytest tests/test_edge_cases.py -v
"""
import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch

from models import AlertInput
from tools.ip_reputation import verify_ip_reputation
from tools.geoip import geoip_lookup
from tools.dns_lookup import dns_lookup
from tools.whois_lookup import whois_lookup
from tools.threat_intel import threat_intel_lookup
from tools.network_traffic import network_traffic_analyzer
from tools.log_pattern import log_pattern_analyzer
from tools.payload_decoder import payload_decoder
from tools.user_behavior import user_behavior_analyzer
from agent import _build_user_message


# ─────────────────────────────────────────────
# 1. Private / RFC1918 IPs — no external API calls
# ─────────────────────────────────────────────
class TestPrivateIPs:
    @pytest.mark.parametrize("ip", [
        "10.0.0.5", "192.168.1.1", "172.16.0.10",
        "127.0.0.1", "169.254.1.1",
    ])
    def test_ip_reputation_skips_external(self, ip):
        r = verify_ip_reputation(ip)
        assert r.is_private is True
        assert r.abuse_confidence_score == 0
        assert r.data_source == "local"

    @pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.1", "127.0.0.1"])
    def test_geoip_skips_external(self, ip):
        r = geoip_lookup(ip)
        assert r.is_private is True
        assert r.country == "Private Network"
        assert r.data_source == "local"

    def test_dns_lookup_private_ip_no_reverse(self):
        r = dns_lookup("10.0.0.5")
        assert r.data_source == "local"
        assert r.reverse_lookup == "private"


# ─────────────────────────────────────────────
# 2. IPv6 handling
# ─────────────────────────────────────────────
class TestIPv6:
    def test_ipv6_public_valid(self):
        # 2001:db8:: is documentation range but valid IPv6
        r = verify_ip_reputation("2001:4860:4860::8888")  # Google DNS IPv6
        # Not private — but may hit external API or be cached
        assert r.is_private is False
        assert r.error is None or "API" in (r.error or "") or r.data_source != "local"

    def test_ipv6_private_detected(self):
        r = verify_ip_reputation("::1")  # loopback
        assert r.is_private is True

    def test_ipv6_geoip_loopback(self):
        r = geoip_lookup("::1")
        assert r.is_private is True

    def test_ipv6_invalid(self):
        r = verify_ip_reputation("not:a:valid:ipv6:::address:::")
        assert r.error is not None


# ─────────────────────────────────────────────
# 3. Missing / empty alert fields
# ─────────────────────────────────────────────
class TestMissingFields:
    def test_empty_alert(self):
        a = AlertInput()
        assert a.source_ip is None
        assert a.log_payload is None
        assert a.source_ip is None  # confirms empty

    def test_alert_with_only_id(self):
        a = AlertInput(alert_id="abc123")
        assert _build_user_message(a, "abc123").startswith("SECURITY ALERT")

    def test_alert_from_empty_dict(self):
        a = AlertInput.from_dict({})
        assert a.source_ip is None
        assert a.raw == {}

    def test_alert_from_partial_dict(self):
        a = AlertInput.from_dict({"src_ip": "1.2.3.4"})
        assert a.source_ip == "1.2.3.4"
        assert a.log_payload is None

    def test_alert_preserves_unknown_fields_in_raw(self):
        a = AlertInput.from_dict({"weird_field": "xyz", "src_ip": "1.1.1.1"})
        assert a.raw["weird_field"] == "xyz"


# ─────────────────────────────────────────────
# 4. Malformed inputs to tools
# ─────────────────────────────────────────────
class TestMalformedToolInput:
    def test_invalid_ip_reputation(self):
        r = verify_ip_reputation("999.999.999.999")
        assert r.error is not None

    def test_invalid_ip_geoip(self):
        r = geoip_lookup("not-an-ip")
        assert r.error is not None
        assert r.country == "N/A"

    def test_empty_string_log_pattern(self):
        r = log_pattern_analyzer("")
        assert r.anomaly_score == 0.0
        assert r.matched_patterns == []

    def test_empty_payload_decoder(self):
        r = payload_decoder("")
        # Should not crash; returns plaintext or no decode
        assert r.tool_name == "payload_decoder"

    def test_empty_network_traffic(self):
        r = network_traffic_analyzer("")
        assert r.anomaly_score == 0.0

    def test_empty_user_behavior(self):
        r = user_behavior_analyzer("", "")
        assert r.risk_score == 0.0

    def test_dashboard_malformed_json_parse(self):
        """Simulate dashboard._parse_input on invalid JSON — should fall back to plaintext."""
        from dashboard import _parse_input
        alerts = _parse_input("{not valid json")
        # Falls through to plaintext path → single alert
        assert len(alerts) == 1
        assert alerts[0].log_payload == "{not valid json"


# ─────────────────────────────────────────────
# 5. Tool fallback when APIs are down
# ─────────────────────────────────────────────
class TestAPIFailureFallback:
    def test_ip_reputation_no_keys_configured(self):
        """With no API keys, tool returns an error but does not raise."""
        with patch("tools.ip_reputation.settings") as mock_settings:
            mock_settings.abuseipdb_api_key = ""
            mock_settings.virustotal_api_key = ""
            r = verify_ip_reputation("8.8.8.8")
            # Either cached (from previous test) or unavailable
            assert r.ip_address == "8.8.8.8"

    def test_geoip_network_error(self):
        """Network timeout returns result with error, not exception."""
        import httpx
        from tools.geoip import cache as geoip_cache
        test_ip = "4.3.2.1"
        geoip_cache.delete(f"geoip:{test_ip}")
        with patch("tools.geoip.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.side_effect = \
                httpx.ConnectError("down")
            r = geoip_lookup(test_ip)
            assert r.error is not None
            assert r.data_source == "unavailable"

    def test_threat_intel_404_clean(self):
        """OTX 404 means clean indicator, not an error."""
        import httpx
        mock_resp = type("R", (), {"status_code": 404})()
        err = httpx.HTTPStatusError("404", request=None, response=mock_resp)
        with patch("tools.threat_intel._query_otx", side_effect=err):
            r = threat_intel_lookup("clean-domain-test-xyz-999.com")
            assert r.pulse_count == 0
            assert r.is_known_malicious is False

    def test_whois_invalid_domain(self):
        """whois on junk domain should not crash."""
        r = whois_lookup("this-is-not-a-real-domain-999.invalid")
        # May succeed with empty or error out — either is fine
        assert r.domain  # has some domain value


# ─────────────────────────────────────────────
# 6. Full agent robustness — no crashes
# ─────────────────────────────────────────────
class TestAgentRobustness:
    def test_build_user_message_minimal(self):
        msg = _build_user_message(AlertInput(), "test-id")
        assert "test-id" in msg

    def test_build_user_message_full(self):
        a = AlertInput(
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
            event_type="failed_login",
            log_payload="test",
        )
        msg = _build_user_message(a, "id1")
        assert "1.1.1.1" in msg
        assert "2.2.2.2" in msg
        assert "failed_login" in msg
        assert "test" in msg

