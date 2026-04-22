import httpx
import diskcache
from typing import Optional
from models import ToolResult
from config import settings

cache = diskcache.Cache(settings.cache_dir)
CACHE_TTL = 86400  # 24 hours


class IPReputationResult(ToolResult):
    tool_name: str = "verify_ip_reputation"
    ip_address: str
    abuse_confidence_score: int = 0
    total_reports: int = 0
    last_reported: Optional[str] = None
    is_tor_exit: bool = False
    virustotal_malicious: int = 0
    categories: list[str] = []
    is_private: bool = False


def _is_valid_ip(ip: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _query_abuseipdb(ip: str) -> dict:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": False}
    with httpx.Client(timeout=5) as client:
        resp = client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json().get("data", {})


def _query_virustotal(ip: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": settings.virustotal_api_key}
    with httpx.Client(timeout=5) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"malicious": stats.get("malicious", 0)}


def verify_ip_reputation(ip_address: str) -> IPReputationResult:
    """Check the reputation of an IP address using AbuseIPDB and VirusTotal."""
    cache_key = f"ip_rep:{ip_address}"

    if not _is_valid_ip(ip_address):
        return IPReputationResult(
            ip_address=ip_address,
            data_source="local",
            error=f"Not a valid IP address: {ip_address}",
        )

    if _is_private_ip(ip_address):
        return IPReputationResult(
            ip_address=ip_address,
            is_private=True,
            data_source="local",
            abuse_confidence_score=0,
        )

    if cache_key in cache:
        return IPReputationResult(**cache[cache_key])

    result = IPReputationResult(ip_address=ip_address)

    if settings.abuseipdb_api_key:
        try:
            data = _query_abuseipdb(ip_address)
            result.abuse_confidence_score = data.get("abuseConfidenceScore", 0)
            result.total_reports = data.get("totalReports", 0)
            result.last_reported = data.get("lastReportedAt")
            result.is_tor_exit = data.get("isTor", False)
            result.categories = [str(c) for c in data.get("reports", [])[:3]]
            result.data_source = "abuseipdb"
        except Exception as e:
            result.error = f"AbuseIPDB error: {str(e)}"

    if settings.virustotal_api_key:
        try:
            vt_data = _query_virustotal(ip_address)
            result.virustotal_malicious = vt_data.get("malicious", 0)
            if not settings.abuseipdb_api_key:
                result.data_source = "virustotal"
        except Exception as e:
            if not result.data_source:
                result.error = f"VirusTotal error: {str(e)}"

    if not settings.abuseipdb_api_key and not settings.virustotal_api_key:
        result.data_source = "unavailable"
        result.error = "No API keys configured"

    cache.set(cache_key, result.model_dump(), expire=CACHE_TTL)
    return result
