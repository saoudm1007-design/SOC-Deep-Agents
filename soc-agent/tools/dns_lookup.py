import math
import diskcache
from typing import Optional
import dns.resolver
import dns.reversename
import dns.exception
from models import ToolResult
from config import settings

cache = diskcache.Cache(settings.cache_dir)
CACHE_TTL = 3600  # 1 hour

TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "amazon.com", "cloudflare.com",
    "apple.com", "ubuntu.com", "archive.ubuntu.com", "github.com",
    "amazonaws.com", "windows.com", "office.com", "azure.com",
}

COMMON_WORDS = {
    "mail", "web", "api", "app", "admin", "login", "secure", "static",
    "cdn", "media", "img", "docs", "help", "support", "update", "news",
}


class DNSResult(ToolResult):
    tool_name: str = "dns_lookup"
    query: str
    resolved_records: list[str] = []
    ttl_seconds: Optional[int] = None
    is_nxdomain: bool = False
    dga_score: float = 0.0
    dns_tunnel_score: float = 0.0
    is_trusted_domain: bool = False
    reverse_lookup: Optional[str] = None


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def _dga_score(domain: str) -> float:
    parts = domain.split(".")
    label = parts[0] if parts else domain
    if len(label) < 6:
        return 0.0
    for word in COMMON_WORDS:
        if word in label:
            return 0.0
    score = 0.0
    length = len(label)
    if length > 12:
        score += 0.2
    if length > 20:
        score += 0.2
    entropy = _shannon_entropy(label)
    if entropy > 3.5:
        score += 0.25
    vowels = sum(1 for c in label if c in "aeiou")
    consonants = sum(1 for c in label if c.isalpha() and c not in "aeiou")
    if vowels == 0 or (consonants / max(vowels, 1)) > 3:
        score += 0.2
    digits = sum(1 for c in label if c.isdigit())
    if digits / length > 0.3:
        score += 0.15
    return min(round(score, 2), 1.0)


def _dns_tunnel_score(domain: str, query_type: str = "A") -> float:
    parts = domain.rstrip(".").split(".")
    if len(parts) < 3:
        return 0.0
    score = 0.0
    subdomains = parts[:-2]
    if len(subdomains) >= 2:
        score += 0.2
    if len(subdomains) >= 3:
        score += 0.1
    if query_type.upper() == "TXT":
        score += 0.3
    deepest = subdomains[0] if subdomains else ""
    has_digits = any(c.isdigit() for c in deepest)
    has_alpha = any(c.isalpha() for c in deepest)
    if has_digits and has_alpha and len(deepest) > 8:
        score += 0.25
    combined = "".join(subdomains)
    if _shannon_entropy(combined) > 3.5:
        score += 0.15
    return min(round(score, 2), 1.0)


def dns_lookup(query: str, check_dga: bool = True, query_type: str = "A") -> DNSResult:
    """Resolve a hostname or IP, score for DGA patterns, and detect DNS tunneling."""
    cache_key = f"dns:{query}:{check_dga}"
    if cache_key in cache:
        return DNSResult(**cache[cache_key])

    result = DNSResult(query=query)

    import ipaddress as _ipaddress
    try:
        _addr = _ipaddress.ip_address(query)
        is_ip = True
        if _addr.is_private or _addr.is_loopback or _addr.is_link_local:
            result.data_source = "local"
            result.reverse_lookup = "private"
            cache.set(cache_key, result.model_dump(), expire=CACHE_TTL)
            return result
    except ValueError:
        is_ip = False

    if not is_ip:
        result.dns_tunnel_score = _dns_tunnel_score(query, query_type)

    for trusted in TRUSTED_DOMAINS:
        if query == trusted or query.endswith(f".{trusted}"):
            result.is_trusted_domain = True
            break

    try:
        if is_ip:
            rev = dns.reversename.from_address(query)
            answers = dns.resolver.resolve(rev, "PTR")
            result.resolved_records = [str(r) for r in answers]
            result.reverse_lookup = result.resolved_records[0] if result.resolved_records else None
            result.data_source = "dns"
        else:
            answers = dns.resolver.resolve(query, "A")
            result.resolved_records = [str(r) for r in answers]
            result.ttl_seconds = answers.rrset.ttl
            result.data_source = "dns"
            if check_dga and not result.is_trusted_domain:
                result.dga_score = _dga_score(query)
    except dns.resolver.NXDOMAIN:
        result.is_nxdomain = True
        result.data_source = "dns"
        if check_dga:
            result.dga_score = min(_dga_score(query) + 0.1, 1.0)
    except dns.exception.DNSException as e:
        result.error = str(e)
        result.data_source = "unavailable"

    cache.set(cache_key, result.model_dump(), expire=CACHE_TTL)
    return result
