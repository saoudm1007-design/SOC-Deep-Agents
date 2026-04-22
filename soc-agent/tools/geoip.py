import httpx
import diskcache
from typing import Optional
from models import ToolResult
from config import settings

cache = diskcache.Cache(settings.cache_dir)
CACHE_TTL = 3600  # 1 hour

HIGH_RISK_COUNTRIES = {"KP", "IR", "RU", "CN", "SY", "CU", "VE", "BY"}

VPN_ISP_KEYWORDS = [
    "vpn", "proxy", "tor", "anonymizer", "hosting", "datacenter",
    "digitalocean", "linode", "vultr", "hetzner", "ovh", "choopa",
]


class GeoIPResult(ToolResult):
    tool_name: str = "geoip_lookup"
    ip_address: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    is_vpn_or_proxy: bool = False
    is_tor: bool = False
    is_high_risk_country: bool = False
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


def geoip_lookup(ip_address: str) -> GeoIPResult:
    """Look up the geographic location and ISP of an IP address."""
    cache_key = f"geoip:{ip_address}"

    if not _is_valid_ip(ip_address):
        return GeoIPResult(
            ip_address=ip_address,
            country="N/A",
            data_source="local",
            error=f"Not a valid IP address: {ip_address}",
        )

    if _is_private_ip(ip_address):
        return GeoIPResult(
            ip_address=ip_address,
            country="Private Network",
            is_private=True,
            data_source="local",
        )

    if cache_key in cache:
        return GeoIPResult(**cache[cache_key])

    result = GeoIPResult(ip_address=ip_address)

    try:
        url = f"http://ip-api.com/json/{ip_address}"
        params = {"fields": "status,country,countryCode,regionName,city,isp,proxy,hosting"}
        with httpx.Client(timeout=5) as client:
            resp = client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()

        if data.get("status") == "success":
            result.country = data.get("country")
            result.country_code = data.get("countryCode")
            result.region = data.get("regionName")
            result.city = data.get("city")
            result.isp = data.get("isp", "")
            result.is_vpn_or_proxy = data.get("proxy", False) or data.get("hosting", False)
            result.is_high_risk_country = result.country_code in HIGH_RISK_COUNTRIES
            result.data_source = "ip-api"

            isp_lower = (result.isp or "").lower()
            if any(kw in isp_lower for kw in VPN_ISP_KEYWORDS):
                result.is_vpn_or_proxy = True
        else:
            result.error = data.get("message", "ip-api lookup failed")
            result.data_source = "unavailable"

    except Exception as e:
        result.error = str(e)
        result.data_source = "unavailable"

    cache.set(cache_key, result.model_dump(), expire=CACHE_TTL)
    return result
