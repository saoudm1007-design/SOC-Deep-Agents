import re
import diskcache
from datetime import datetime, timezone
from typing import Optional
from models import ToolResult
from config import settings

cache = diskcache.Cache(settings.cache_dir)
CACHE_TTL = 86400  # 24 hours — domain registration rarely changes


class WhoisResult(ToolResult):
    tool_name: str = "whois_lookup"
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    registrant_country: Optional[str] = None
    is_new_domain: bool = False        # True if domain < 30 days old
    is_very_new_domain: bool = False   # True if domain < 7 days old
    is_privacy_protected: bool = False


def _extract_domain(query: str) -> str:
    """Extract the registered domain from a full hostname."""
    query = query.lower().strip()
    parts = query.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return query


def _parse_date(date_val) -> Optional[datetime]:
    """Parse whois date value which can be string, datetime, or list."""
    if date_val is None:
        return None
    if isinstance(date_val, list):
        date_val = date_val[0]
    if isinstance(date_val, datetime):
        return date_val
    if isinstance(date_val, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(date_val[:19], fmt[:len(date_val[:19])])
            except ValueError:
                continue
    return None


def whois_lookup(domain: str) -> WhoisResult:
    """
    Look up domain registration info: age, registrar, country.
    New domains (< 30 days) are a strong indicator of C2 infrastructure or phishing.
    """
    # Extract registered domain from hostname
    registered_domain = _extract_domain(domain)
    cache_key = f"whois:{registered_domain}"

    if cache_key in cache:
        return WhoisResult(**cache[cache_key])

    result = WhoisResult(domain=registered_domain)

    try:
        import whois
        w = whois.whois(registered_domain)

        # Registrar
        result.registrar = str(w.registrar)[:100] if w.registrar else None

        # Privacy protection heuristic
        registrar_lower = (result.registrar or "").lower()
        if any(kw in registrar_lower for kw in ["privacy", "protect", "whoisguard", "redacted"]):
            result.is_privacy_protected = True

        # Creation date + age
        creation = _parse_date(w.creation_date)
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - creation).days
            result.creation_date = creation.strftime("%Y-%m-%d")
            result.domain_age_days = age_days
            result.is_new_domain = age_days < 30
            result.is_very_new_domain = age_days < 7

        # Expiration date
        expiry = _parse_date(w.expiration_date)
        if expiry:
            result.expiration_date = expiry.strftime("%Y-%m-%d")

        # Country
        country = w.country
        if isinstance(country, list):
            country = country[0]
        result.registrant_country = str(country) if country else None

        result.data_source = "whois"

    except Exception as e:
        result.error = str(e)
        result.data_source = "unavailable"

    cache.set(cache_key, result.model_dump(), expire=CACHE_TTL)
    return result
