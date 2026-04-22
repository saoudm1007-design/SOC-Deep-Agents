import httpx
import diskcache
from typing import Optional
from models import ToolResult
from config import settings

cache = diskcache.Cache(settings.cache_dir)
CACHE_TTL = 3600  # 1 hour

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"


class ThreatIntelResult(ToolResult):
    tool_name: str = "threat_intel_lookup"
    indicator: str
    indicator_type: str = "unknown"   # domain, url, ip, hostname
    pulse_count: int = 0              # number of threat reports
    malware_families: list[str] = []
    threat_tags: list[str] = []
    is_known_malicious: bool = False
    country: Optional[str] = None
    otx_url: Optional[str] = None


def _detect_indicator_type(indicator: str) -> str:
    """Classify the indicator as domain, url, ip, or hostname."""
    import ipaddress
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return "url"
    if "/" in indicator:
        return "url"
    # Count dots — domain has 1-2 dots (e.g. evil.com, sub.evil.com)
    parts = indicator.split(".")
    if len(parts) >= 2:
        return "domain"
    return "hostname"


def _query_otx(indicator: str, ind_type: str) -> dict:
    """Query AlienVault OTX for threat intelligence on an indicator."""
    # Map our type to OTX endpoint type
    otx_type_map = {
        "ip": "IPv4",
        "domain": "domain",
        "url": "url",
        "hostname": "hostname",
    }
    otx_type = otx_type_map.get(ind_type, "domain")
    url = f"{OTX_BASE}/{otx_type}/{indicator}/general"

    headers = {}
    # OTX API key is optional — public endpoints work without it
    otx_key = getattr(settings, "otx_api_key", "")
    if otx_key:
        headers["X-OTX-API-KEY"] = otx_key

    with httpx.Client(timeout=8) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json()


def threat_intel_lookup(indicator: str) -> ThreatIntelResult:
    """
    Look up a domain, URL, or IP in AlienVault OTX threat intelligence.
    Returns pulse count (threat reports), malware families, and tags.
    A high pulse count or known malware family is a strong malicious indicator.
    """
    indicator = indicator.strip().rstrip("/")
    cache_key = f"otx:{indicator}"

    if cache_key in cache:
        return ThreatIntelResult(**cache[cache_key])

    ind_type = _detect_indicator_type(indicator)
    result = ThreatIntelResult(indicator=indicator, indicator_type=ind_type)
    result.otx_url = f"https://otx.alienvault.com/indicator/{ind_type}/{indicator}"

    try:
        data = _query_otx(indicator, ind_type)

        result.pulse_count = data.get("pulse_info", {}).get("count", 0)
        result.country = data.get("country_name") or data.get("country_code")

        # Extract malware families from pulses
        pulses = data.get("pulse_info", {}).get("pulses", [])
        families = set()
        tags = set()
        for pulse in pulses[:10]:
            for mf in pulse.get("malware_families", []):
                families.add(mf.get("display_name", "").strip())
            for tag in pulse.get("tags", [])[:5]:
                tags.add(tag.lower())

        result.malware_families = [f for f in families if f][:5]
        result.threat_tags = list(tags)[:10]
        result.is_known_malicious = result.pulse_count >= 3
        result.data_source = "otx"

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            # Not found in OTX — clean indicator
            result.pulse_count = 0
            result.data_source = "otx"
        else:
            result.error = f"OTX error: {e.response.status_code}"
            result.data_source = "unavailable"
    except Exception as e:
        result.error = str(e)
        result.data_source = "unavailable"

    cache.set(cache_key, result.model_dump(), expire=CACHE_TTL)
    return result
