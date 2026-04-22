"""
Tool registry — wraps all 10 SOC tools with the @tool decorator.
Each function must have a clear docstring (used by the LLM to decide when to call it).
"""
from langchain_core.tools import tool

from tools.ip_reputation import verify_ip_reputation
from tools.geoip import geoip_lookup as _geoip
from tools.dns_lookup import dns_lookup as _dns
from tools.whois_lookup import whois_lookup as _whois
from tools.threat_intel import threat_intel_lookup as _threat_intel
from tools.network_traffic import network_traffic_analyzer as _net_traffic
from tools.log_pattern import log_pattern_analyzer as _log_pattern
from tools.payload_decoder import payload_decoder as _payload_decoder
from tools.cve_lookup import cve_lookup as _cve
from tools.user_behavior import user_behavior_analyzer as _user_behavior
from tools.ip_full_profile import ip_full_profile as _ip_full_profile


# ── Network Intelligence Tools ──────────────────────────────────────────────

@tool
def ip_full_profile_tool(ip_address: str) -> str:
    """
    PREFERRED IP LOOKUP — runs reputation (AbuseIPDB + VirusTotal), geolocation
    (country + VPN/proxy detection), and AlienVault OTX threat intelligence
    in PARALLEL and returns one merged profile. Use this instead of calling
    ip_reputation_tool, geoip_tool, and threat_intel_tool separately — it
    saves 2-4 seconds per IP investigation. Use the individual tools only
    when you need follow-up on a specific source.
    """
    r = _ip_full_profile(ip_address)
    return r.model_dump_json()


@tool
def ip_reputation_tool(ip_address: str) -> str:
    """
    Check the reputation of an IP address using AbuseIPDB and VirusTotal.
    Returns abuse confidence score, ISP, usage type, and whether the IP is known malicious.
    Use for any alert containing a source or destination IP address.
    """
    r = verify_ip_reputation(ip_address)
    return r.model_dump_json()


@tool
def geoip_tool(ip_address: str) -> str:
    """
    Geolocate an IP address: country, city, ISP, and VPN/proxy/Tor detection.
    Flags high-risk countries and anonymizing infrastructure.
    Use to determine the geographic origin of suspicious connections.
    """
    r = _geoip(ip_address)
    return r.model_dump_json()


@tool
def dns_tool(hostname: str) -> str:
    """
    Resolve a hostname and score it for DGA (Domain Generation Algorithm) patterns
    and DNS tunneling indicators. A DGA score > 0.5 suggests C2 infrastructure.
    Use for any alert containing a domain name or suspicious hostname.
    """
    r = _dns(hostname)
    return r.model_dump_json()


@tool
def whois_tool(domain: str) -> str:
    """
    Look up domain registration information: age, registrar, and privacy protection.
    Domains less than 30 days old are a strong indicator of phishing or C2 infrastructure.
    Use when a domain or URL appears in an alert.
    """
    r = _whois(domain)
    return r.model_dump_json()


@tool
def threat_intel_tool(indicator: str) -> str:
    """
    Look up a domain, URL, or IP address in AlienVault OTX threat intelligence.
    Returns pulse count (number of threat reports), malware families, and threat tags.
    A pulse count >= 3 means the indicator is known malicious.
    Use for any network indicator that needs external threat context.
    """
    r = _threat_intel(indicator)
    return r.model_dump_json()


@tool
def network_traffic_tool(log_payload: str, source_ip: str = "", destination_ip: str = "") -> str:
    """
    Analyze network traffic metadata for exfiltration patterns.
    Detects large data transfers (> 1 GB), off-hours activity, suspicious ports (4444, 6667, 9001),
    and internal-to-external transfer anomalies.
    Use when an alert describes network connections or data transfers.
    """
    r = _net_traffic(log_payload, source_ip=source_ip, destination_ip=destination_ip)
    return r.model_dump_json()


# ── Log & Payload Tools ──────────────────────────────────────────────────────

@tool
def log_pattern_tool(log_payload: str) -> str:
    """
    Match log text against 40+ MITRE ATT&CK attack signatures including brute force,
    credential dumping, lateral movement, ransomware, C2 beaconing, web attacks (SQLi, XSS,
    Log4Shell), LOLBin abuse, Kerberos attacks, and data staging.
    Returns matched patterns with MITRE IDs, confidence scores, and an anomaly score.
    Use for any alert containing log entries, command-line activity, or event descriptions.
    """
    r = _log_pattern(log_payload)
    return r.model_dump_json()


@tool
def payload_decoder_tool(payload: str) -> str:
    """
    Decode encoded or obfuscated payloads: base64, URL encoding, hex, and gzip (multi-layer).
    Extracts IOCs (IPs, domains, URLs, shell commands) from decoded content.
    Detects suspicious content: PowerShell IEX, DownloadString, mimikatz, Log4Shell, shellcode.
    Use when an alert contains an encoded string, obfuscated command, or suspicious payload.
    """
    r = _payload_decoder(payload)
    return r.model_dump_json()


@tool
def cve_tool(cve_id: str) -> str:
    """
    Look up a CVE by ID in the NVD database. Returns CVSS score, severity, description,
    and affected products. Pre-cached for critical CVEs: Log4Shell (CVE-2021-44228),
    EternalBlue (CVE-2017-0144), ProxyLogon (CVE-2021-26855), BlueKeep (CVE-2019-0708).
    Use when an alert references a specific CVE ID or known vulnerability.
    """
    r = _cve(cve_id)
    return r.model_dump_json()


# ── User Behavior Tool ───────────────────────────────────────────────────────

@tool
def user_behavior_tool(log_payload: str, username: str = "", resource_accessed: str = "") -> str:
    """
    Score user behavior risk across 10 signals: off-hours access, impossible travel,
    privilege escalation, first-time resource access, mass file access, high failed login count,
    admin account activity, service account anomalies, sensitive resource access, long sessions.
    Returns a 0–1 risk score, risk level (Low/Medium/High/Critical), and anomaly flags.
    Use for any alert containing a username, login event, or behavioral anomaly.
    """
    r = _user_behavior(log_payload, username=username, resource_accessed=resource_accessed)
    return r.model_dump_json()


# ── Tool lists per subagent ──────────────────────────────────────────────────

NETWORK_TOOLS = [
    ip_full_profile_tool,   # preferred — parallel reputation + geoip + threat intel
    geoip_tool,
    ip_reputation_tool,
    dns_tool,
    whois_tool,
    threat_intel_tool,
    network_traffic_tool,
]

LOG_TOOLS = [
    log_pattern_tool,
    payload_decoder_tool,
    cve_tool,
]

USER_TOOLS = [
    user_behavior_tool,
]

ALL_TOOLS = NETWORK_TOOLS + LOG_TOOLS + USER_TOOLS
