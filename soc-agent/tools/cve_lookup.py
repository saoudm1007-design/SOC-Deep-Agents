import re
import httpx
import diskcache
from typing import Optional
from models import ToolResult
from config import settings

cache = diskcache.Cache(settings.cache_dir)
CACHE_TTL = 86400  # 24 hours

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Pre-cached critical CVEs — always available offline
STATIC_CVE_DB: dict[str, dict] = {
    "CVE-2021-44228": {
        "description": "Log4Shell — Apache Log4j2 JNDI injection RCE. "
                       "Allows unauthenticated remote code execution via crafted log messages.",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "cwe": "CWE-917",
        "affected_products": ["Apache Log4j 2.0-beta9 to 2.14.1"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    },
    "CVE-2017-0144": {
        "description": "EternalBlue — Windows SMBv1 RCE. Exploited by WannaCry and NotPetya ransomware.",
        "cvss_score": 9.3,
        "severity": "CRITICAL",
        "cwe": "CWE-119",
        "affected_products": ["Windows Vista", "Windows 7", "Windows Server 2008"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
    },
    "CVE-2021-26855": {
        "description": "ProxyLogon — Microsoft Exchange Server SSRF leading to RCE.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "cwe": "CWE-918",
        "affected_products": ["Exchange Server 2013/2016/2019"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"],
    },
    "CVE-2019-0708": {
        "description": "BlueKeep — Windows RDP pre-auth RCE, wormable.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "cwe": "CWE-416",
        "affected_products": ["Windows 7", "Windows Server 2008 R2"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
    },
    "CVE-2022-30190": {
        "description": "Follina — Microsoft MSDT RCE via crafted Office documents (0-day).",
        "cvss_score": 7.8,
        "severity": "HIGH",
        "cwe": "CWE-610",
        "affected_products": ["Microsoft Office 2013-2021", "Windows 11"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-30190"],
    },
    "CVE-2023-44487": {
        "description": "HTTP/2 Rapid Reset — application-layer DoS enabling record-breaking DDoS.",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "cwe": "CWE-400",
        "affected_products": ["All HTTP/2 implementations (Apache, nginx, IIS, Go HTTP)"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
    },
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


class CVEResult(ToolResult):
    tool_name: str = "cve_lookup"
    cve_id: str
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: Optional[str] = None        # NONE | LOW | MEDIUM | HIGH | CRITICAL
    cwe: Optional[str] = None
    affected_products: list[str] = []
    references: list[str] = []
    is_critical: bool = False             # CVSS >= 9.0


def _severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _query_nvd(cve_id: str) -> Optional[dict]:
    """Query NVD API v2 for CVE details."""
    nvd_key = getattr(settings, "nvd_api_key", "")
    headers = {"apiKey": nvd_key} if nvd_key else {}
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(NVD_BASE, params={"cveId": cve_id.upper()}, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        return vulns[0].get("cve", {})
    except Exception:
        return None


def _parse_nvd_response(cve: dict, cve_id: str) -> CVEResult:
    result = CVEResult(cve_id=cve_id.upper(), data_source="nvd")

    # Description
    descriptions = cve.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            result.description = d.get("value", "")[:500]
            break

    # CVSS score (prefer v3.1 → v3.0 → v2)
    metrics = cve.get("metrics", {})
    score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            break

    result.cvss_score = score
    result.severity = _severity_from_score(score)
    result.is_critical = (score or 0) >= 9.0

    # CWE
    weaknesses = cve.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("lang") == "en":
                result.cwe = desc.get("value")
                break
        if result.cwe:
            break

    # References
    refs = cve.get("references", [])
    result.references = [r["url"] for r in refs[:5] if "url" in r]

    # Affected CPE (products)
    configs = cve.get("configurations", [])
    products = []
    for cfg in configs[:2]:
        for node in cfg.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe = cpe_match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    version = parts[5] if len(parts) > 5 else ""
                    products.append(f"{vendor} {product} {version}".strip())
    result.affected_products = list(dict.fromkeys(products))[:5]

    return result


def cve_lookup(cve_id: str) -> CVEResult:
    """
    Look up a CVE by ID in the NVD database.
    Returns CVSS score, severity, description, and affected products.
    Pre-cached for 6 critical CVEs (Log4Shell, EternalBlue, ProxyLogon, BlueKeep, Follina, HTTP/2 Reset).
    """
    cve_id = cve_id.strip().upper()
    # Normalize input — handle "log4shell" style or raw IDs in text
    if not cve_id.startswith("CVE-"):
        found = CVE_RE.search(cve_id)
        if found:
            cve_id = found.group().upper()
        else:
            result = CVEResult(cve_id=cve_id, data_source="unavailable")
            result.error = f"Invalid CVE ID format: {cve_id}"
            return result

    cache_key = f"cve:{cve_id}"
    if cache_key in cache:
        return CVEResult(**cache[cache_key])

    # Check static DB first
    if cve_id in STATIC_CVE_DB:
        static = STATIC_CVE_DB[cve_id]
        result = CVEResult(
            cve_id=cve_id,
            data_source="static",
            description=static["description"],
            cvss_score=static["cvss_score"],
            severity=static["severity"],
            cwe=static.get("cwe"),
            affected_products=static.get("affected_products", []),
            references=static.get("references", []),
            is_critical=static["cvss_score"] >= 9.0,
        )
        cache.set(cache_key, result.model_dump(), expire=CACHE_TTL)
        return result

    # Query NVD API
    cve_data = _query_nvd(cve_id)
    if cve_data:
        result = _parse_nvd_response(cve_data, cve_id)
    else:
        result = CVEResult(cve_id=cve_id, data_source="unavailable")
        result.error = f"CVE {cve_id} not found in NVD"

    cache.set(cache_key, result.model_dump(), expire=CACHE_TTL)
    return result
