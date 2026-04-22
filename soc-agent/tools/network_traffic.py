import re
from typing import Optional
from models import ToolResult

# Ports associated with known malicious activity
SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    1337: "Common backdoor",
    31337: "Elite/backdoor",
    6667: "IRC C2",
    6666: "IRC C2",
    9001: "Tor relay",
    9030: "Tor directory",
    8443: "Alternative HTTPS (common C2)",
    4899: "Radmin remote access",
    5900: "VNC (if unexpected)",
}

# Ports that should only carry specific protocols
EXPECTED_PORT_PROTOCOLS = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    53: "DNS",
    3306: "MySQL",
    5432: "PostgreSQL",
    3389: "RDP",
}

# Business hours: 7 AM to 9 PM
BUSINESS_HOURS = range(7, 21)


class NetworkTrafficResult(ToolResult):
    tool_name: str = "network_traffic_analyzer"
    bytes_transferred: Optional[int] = None
    duration_seconds: Optional[int] = None
    transfer_rate_mbps: Optional[float] = None
    is_large_transfer: bool = False        # > 1 GB
    is_off_hours: bool = False
    suspicious_port: Optional[str] = None
    is_internal_to_external: bool = False
    is_encrypted: bool = False
    anomaly_score: float = 0.0
    anomaly_reasons: list[str] = []
    traffic_direction: str = "unknown"    # inbound | outbound | internal | unknown


def _parse_bytes(log: str) -> Optional[int]:
    """Extract byte/data volume from log text."""
    # Match patterns like: 4.5GB, 5800000000, 150MB, 1.2TB
    patterns = [
        (r"(\d+(?:\.\d+)?)\s*TB", 1_099_511_627_776),
        (r"(\d+(?:\.\d+)?)\s*GB", 1_073_741_824),
        (r"(\d+(?:\.\d+)?)\s*MB", 1_048_576),
        (r"(\d+(?:\.\d+)?)\s*KB", 1_024),
        (r"\b[Bb]ytes[=:\s]+(\d{6,})", 1),
        (r"[Ss]ent\s+(\d{6,})", 1),
        (r"[Ss]ize[=:\s]+(\d{6,})", 1),
    ]
    for pattern, multiplier in patterns:
        m = re.search(pattern, log, re.I)
        if m:
            return int(float(m.group(1)) * multiplier)
    return None


def _parse_duration(log: str) -> Optional[int]:
    """Extract duration in seconds from log text."""
    m = re.search(r"[Dd]uration[=:\s]+(\d+)\s*s", log, re.I)
    if m:
        return int(m.group(1))
    m = re.search(r"(\d+)\s*seconds?", log, re.I)
    if m:
        return int(m.group(1))
    return None


def _parse_hour(log: str) -> Optional[int]:
    """Extract hour from timestamp in log text."""
    # ISO timestamp: 2026-04-12T03:04:11Z
    m = re.search(r"T(\d{2}):\d{2}:\d{2}", log)
    if m:
        return int(m.group(1))
    # Syslog: Oct 27 03:14:22
    m = re.search(r"\s(\d{2}):\d{2}:\d{2}\s", log)
    if m:
        return int(m.group(1))
    return None


def _parse_ports(log: str) -> list[int]:
    """Extract port numbers from log text."""
    ports = []
    for m in re.finditer(r"[Pp]ort[=:\s]+(\d+)|[DS][Pp]ort[=:\s]+(\d+)|:(\d{2,5})\b", log):
        port = int(m.group(1) or m.group(2) or m.group(3))
        if 1 <= port <= 65535:
            ports.append(port)
    return list(set(ports))


def network_traffic_analyzer(log_payload: str, source_ip: str = "", destination_ip: str = "") -> NetworkTrafficResult:
    """
    Analyze network traffic metadata for anomalies: large transfers,
    off-hours activity, suspicious ports, and exfiltration patterns.
    Catches data exfiltration that log_pattern_analyzer misses (volume + timing).
    """
    result = NetworkTrafficResult(data_source="local")
    reasons = []
    score = 0.0

    # --- Parse fields ---
    bytes_val = _parse_bytes(log_payload)
    duration = _parse_duration(log_payload)
    hour = _parse_hour(log_payload)
    ports = _parse_ports(log_payload)

    result.bytes_transferred = bytes_val
    result.duration_seconds = duration

    # Transfer rate
    if bytes_val and duration and duration > 0:
        result.transfer_rate_mbps = round((bytes_val / duration) / 1_048_576, 2)

    # Determine if transfer is internal-to-internal (both endpoints private).
    # Bulk intra-network transfers are routinely legitimate (backups,
    # replication, DB sync), so we score them much lower than outbound egress.
    import ipaddress as _ip
    def _is_priv(ip: str) -> bool:
        try:
            return _ip.ip_address(ip).is_private
        except Exception:
            return False
    both_internal = bool(source_ip and destination_ip
                         and _is_priv(source_ip) and _is_priv(destination_ip))

    # --- Large transfer check ---
    # Internal transfers over SSH (port 22) at GB scale are NOT backup —
    # backup software uses rsync/SMB/NFS/dedicated backup protocols, not raw
    # SSH. Large SSH data flows = lateral movement / data staging.
    ssh_like = 22 in ports
    backup_keywords = bool(re.search(
        r"\b(rsync|backup|replication|sync|snapshot|veeam|commvault|"
        r"borg|duplicity|rclone|nfs|smb|cifs)\b",
        log_payload, re.I,
    ))

    if bytes_val:
        gb = bytes_val / 1_073_741_824
        if gb >= 1.0:
            result.is_large_transfer = True
            if both_internal and ssh_like and not backup_keywords:
                # Lateral movement / exfil staging over SSH — treat as external egress
                score += 0.35
                reasons.append(
                    f"Large internal SSH transfer: {gb:.1f} GB — "
                    "lateral movement or data staging pattern"
                )
            elif both_internal and backup_keywords:
                # Explicitly a backup / replication protocol
                score += 0.05
                reasons.append(
                    f"Large internal transfer: {gb:.1f} GB (backup/replication)"
                )
            elif both_internal:
                # Internal-to-internal transfer, no SSH, no explicit backup
                # keyword — still overwhelmingly likely a backup / replication /
                # DB sync (those are the common reasons for GB-scale intra-
                # network traffic). No external egress = not exfiltration.
                score += 0.03
                reasons.append(
                    f"Large internal transfer: {gb:.1f} GB "
                    "(both endpoints private, no external egress — "
                    "consistent with backup / replication / DB sync)"
                )
            else:
                score += 0.3
                reasons.append(f"Large data transfer: {gb:.1f} GB")
        elif gb >= 0.1:
            if both_internal and backup_keywords:
                reasons.append(f"Moderate internal transfer: {gb*1024:.0f} MB")
            else:
                score += 0.1
                reasons.append(f"Moderate data transfer: {gb*1024:.0f} MB")

    # --- Off-hours check ---
    if hour is not None and hour not in BUSINESS_HOURS:
        result.is_off_hours = True
        score += 0.2
        reasons.append(f"Activity at off-hours ({hour:02d}:xx)")

    # Combined: large transfer + off-hours = very suspicious
    if result.is_large_transfer and result.is_off_hours:
        score += 0.2
        reasons.append("Large transfer during off-hours — exfiltration pattern")

    # --- Suspicious port check ---
    for port in ports:
        if port in SUSPICIOUS_PORTS:
            result.suspicious_port = f"Port {port}: {SUSPICIOUS_PORTS[port]}"
            score += 0.35
            reasons.append(f"Suspicious port {port} ({SUSPICIOUS_PORTS[port]})")
            break

    # --- Encryption check ---
    if re.search(r"\b(encrypted|ssl|tls|https)\b", log_payload, re.I):
        result.is_encrypted = True

    # Encrypted + large + off-hours = exfil over encrypted channel
    if result.is_encrypted and result.is_large_transfer and result.is_off_hours:
        score += 0.15
        reasons.append("Encrypted large transfer at off-hours (covert exfil pattern)")

    # --- Traffic direction ---
    src_private = _is_priv(source_ip) if source_ip else None
    dst_private = _is_priv(destination_ip) if destination_ip else None

    if src_private is not None and dst_private is not None:
        if src_private and not dst_private:
            result.traffic_direction = "outbound"
            result.is_internal_to_external = True
            if result.is_large_transfer:
                score += 0.1
                reasons.append("Internal-to-external large transfer")
        elif not src_private and dst_private:
            result.traffic_direction = "inbound"
        elif src_private and dst_private:
            result.traffic_direction = "internal"
        else:
            result.traffic_direction = "external"

    # --- Outbound to external destination keywords ---
    if re.search(r"(outbound|egress|external\s+host)", log_payload, re.I):
        result.is_internal_to_external = True

    result.anomaly_score = round(min(score, 1.0), 2)
    result.anomaly_reasons = reasons

    return result
