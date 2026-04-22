import re
import base64
import binascii
import gzip
import urllib.parse
from typing import Optional
from models import ToolResult


class PayloadDecoderResult(ToolResult):
    tool_name: str = "payload_decoder"
    encoding_detected: Optional[str] = None   # base64 | url | hex | gzip | plaintext
    decoded_text: Optional[str] = None
    decode_layers: int = 0                     # how many decode passes were needed
    extracted_ips: list[str] = []
    extracted_domains: list[str] = []
    extracted_urls: list[str] = []
    extracted_commands: list[str] = []
    contains_suspicious_content: bool = False
    suspicion_reasons: list[str] = []


# Regex patterns for IOC extraction
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|co|ru|cn|onion|xyz|top|tk|cc|info|biz|site)\b",
    re.I,
)
_URL_RE = re.compile(r"https?://[^\s\"'<>]{4,100}", re.I)
_CMD_RE = re.compile(
    r"(?:cmd\.exe|powershell|/bin/sh|/bin/bash|wget|curl|nc\s|netcat|"
    r"mshta|certutil|bitsadmin|regsvr32|rundll32|wscript|cscript)\b",
    re.I,
)
_SUSPICIOUS_STRINGS = [
    (r"invoke-expression|iex\s*\(", "PowerShell IEX (code execution)"),
    (r"-enc(?:odedcommand)?", "Base64-encoded PowerShell command"),
    (r"downloadstring|downloadfile|webclient", "Remote download attempt"),
    (r"shellcode|shellexec|createthread|virtualalloc", "Shellcode injection patterns"),
    (r"mimikatz|sekurlsa|lsass", "Credential dumping tool signature"),
    (r"\$\{jndi:", "Log4Shell / JNDI injection"),
    (r"union\s+select|drop\s+table|'[_\s]*or[_\s]*'", "SQL injection strings"),
    (r"<script|javascript:|onerror=|onload=", "XSS payload"),
    (r"\.onion|tor[_\s]exit", "Tor / dark-web reference"),
    (r"(?:rm|del)\s+-rf?\s*/|format\s+c:|dd\s+if=/dev/zero", "Destructive command"),
]


_B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")


def _try_base64(data: str) -> Optional[str]:
    """Attempt standard and URL-safe base64 decode.
    Only proceeds if the input looks like actual base64 (≥95% valid b64 chars, no spaces).
    """
    s = data.strip()
    if len(s) < 8:
        return None
    # Reject if too many non-base64 characters (spaces, punctuation, etc.)
    non_b64 = sum(1 for c in s if c not in _B64_CHARS)
    if non_b64 / len(s) > 0.05:
        return None
    cleaned = s.rstrip("=")
    for variant in (cleaned, cleaned + "=" * (-len(cleaned) % 4)):
        for decode_fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decode_fn(variant + "==")
                text = decoded.decode("utf-8", errors="replace")
                # Require high printability — reject binary/garbage results
                printable = sum(c.isprintable() for c in text)
                if len(text) >= 4 and printable / len(text) >= 0.85:
                    return text
            except Exception:
                continue
    return None


def _try_hex(data: str) -> Optional[str]:
    """Attempt hex decode.
    Only proceeds if input looks like a hex string (mostly hex chars, prefixed or dense).
    """
    s = data.strip()
    # Must look like hex: optional 0x/\x prefixes OR purely hex chars with no spaces
    looks_like_hex = bool(re.match(r'^(?:(?:\\x|0x)[0-9a-fA-F]{2})+$', s)) or \
                     bool(re.match(r'^[0-9a-fA-F]{8,}$', s))
    if not looks_like_hex:
        return None
    cleaned = re.sub(r"\\x|0x", "", s)
    if len(cleaned) < 8 or len(cleaned) % 2 != 0:
        return None
    try:
        decoded = binascii.unhexlify(cleaned).decode("utf-8", errors="replace")
        printable = sum(c.isprintable() for c in decoded)
        if len(decoded) >= 4 and printable / len(decoded) >= 0.85:
            return decoded
    except Exception:
        pass
    return None


def _try_url_decode(data: str) -> Optional[str]:
    """Attempt URL percent-decode."""
    if "%" not in data:
        return None
    decoded = urllib.parse.unquote(data)
    return decoded if decoded != data else None


def _try_gzip(data: str) -> Optional[str]:
    """Attempt gzip decompress (after base64 decode)."""
    try:
        raw = base64.b64decode(data + "==")
        return gzip.decompress(raw).decode("utf-8", errors="replace")
    except Exception:
        return None


def _multi_decode(payload: str) -> tuple[str, str, int]:
    """
    Iteratively decode up to 3 layers.
    Returns (decoded_text, encoding_detected, layer_count).
    """
    current = payload.strip()
    encoding = "plaintext"
    layers = 0

    for _ in range(3):
        if decoded := _try_gzip(current):
            current, encoding, layers = decoded, "gzip", layers + 1
            continue
        if decoded := _try_base64(current):
            current, encoding, layers = decoded, "base64", layers + 1
            continue
        if decoded := _try_url_decode(current):
            current, encoding, layers = decoded, "url", layers + 1
            continue
        if decoded := _try_hex(current):
            current, encoding, layers = decoded, "hex", layers + 1
            continue
        break

    return current, encoding, layers


def _extract_iocs(text: str) -> dict:
    ips = list({m for m in _IP_RE.findall(text) if not m.startswith("127.")})[:10]
    domains = list({m for m in _DOMAIN_RE.findall(text)})[:10]
    urls = list({m for m in _URL_RE.findall(text)})[:10]
    commands = list({m.group() for m in _CMD_RE.finditer(text)})[:10]
    return {"ips": ips, "domains": domains, "urls": urls, "commands": commands}


def _check_suspicious(text: str) -> tuple[bool, list[str]]:
    reasons = []
    for pattern, label in _SUSPICIOUS_STRINGS:
        if re.search(pattern, text, re.I):
            reasons.append(label)
    return bool(reasons), reasons


def payload_decoder(payload: str) -> PayloadDecoderResult:
    """
    Decode encoded/obfuscated payloads (base64, URL encoding, hex, gzip)
    and extract IOCs: IPs, domains, URLs, shell commands.
    Detects multi-layer encoding used to evade signature-based detection.
    """
    result = PayloadDecoderResult(data_source="local")

    if not payload or not payload.strip():
        result.error = "Empty payload"
        return result

    decoded_text, encoding, layers = _multi_decode(payload)

    result.encoding_detected = encoding
    result.decoded_text = decoded_text[:2000]  # cap for storage
    result.decode_layers = layers

    iocs = _extract_iocs(decoded_text)
    result.extracted_ips = iocs["ips"]
    result.extracted_domains = iocs["domains"]
    result.extracted_urls = iocs["urls"]
    result.extracted_commands = iocs["commands"]

    suspicious, reasons = _check_suspicious(decoded_text)
    result.contains_suspicious_content = suspicious
    result.suspicion_reasons = reasons

    return result
