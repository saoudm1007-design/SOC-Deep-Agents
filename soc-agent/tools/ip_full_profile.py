"""
Composite IP profiler — runs ip_reputation, geoip, and threat_intel_lookup
concurrently against the same IP and returns a merged result.

Replaces three serial LLM-directed tool calls with one parallel fan-out,
saving ~2-4s per IP investigation in the network_intel subagent.
"""
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from models import ToolResult
from tools.ip_reputation import verify_ip_reputation, IPReputationResult
from tools.geoip import geoip_lookup, GeoIPResult
from tools.threat_intel import threat_intel_lookup, ThreatIntelResult


class IPFullProfileResult(ToolResult):
    tool_name: str = "ip_full_profile"
    ip_address: str
    reputation: Optional[dict] = None
    geoip:      Optional[dict] = None
    threat_intel: Optional[dict] = None
    is_known_malicious: bool = False
    is_vpn_or_proxy: bool = False
    is_high_risk_country: bool = False
    is_private: bool = False


def ip_full_profile(ip_address: str) -> IPFullProfileResult:
    """
    Parallel lookup of reputation + geolocation + threat intelligence for an IP.
    Returns a merged profile with fast boolean flags for the coordinator.
    """
    result = IPFullProfileResult(ip_address=ip_address, data_source="parallel")

    with ThreadPoolExecutor(max_workers=3) as ex:
        fut_rep    = ex.submit(verify_ip_reputation, ip_address)
        fut_geo    = ex.submit(geoip_lookup, ip_address)
        fut_intel  = ex.submit(threat_intel_lookup, ip_address)

        rep:   IPReputationResult = fut_rep.result()
        geo:   GeoIPResult        = fut_geo.result()
        intel: ThreatIntelResult  = fut_intel.result()

    result.reputation   = rep.summary()
    result.geoip        = geo.summary()
    result.threat_intel = intel.summary()

    # Promote commonly-checked flags to top level for quick coordinator access
    result.is_known_malicious   = (
        rep.abuse_confidence_score >= 50
        or rep.virustotal_malicious >= 3
        or intel.is_known_malicious
    )
    result.is_vpn_or_proxy      = bool(geo.is_vpn_or_proxy or rep.is_tor_exit)
    result.is_high_risk_country = bool(geo.is_high_risk_country)
    result.is_private           = bool(rep.is_private or geo.is_private)

    return result
