import re
from typing import Optional
from models import ToolResult


class UserBehaviorResult(ToolResult):
    tool_name: str = "user_behavior_analyzer"
    risk_score: float = 0.0             # 0.0–1.0 composite risk
    risk_level: str = "Low"             # Low | Medium | High | Critical
    anomaly_flags: list[str] = []       # human-readable risk factors
    is_off_hours: bool = False
    is_new_asset: bool = False          # first-time access to resource
    is_privilege_escalation: bool = False
    is_impossible_travel: bool = False
    is_mass_access: bool = False        # accessing many files/resources
    failed_attempts: Optional[int] = None
    account_type: Optional[str] = None  # admin | service | user
    session_duration_minutes: Optional[int] = None


# Risk weights for individual signals
_WEIGHTS = {
    "off_hours":            0.15,
    "new_asset":            0.20,
    "priv_escalation":      0.30,
    "impossible_travel":    0.35,
    "mass_access":          0.25,
    "many_failures":        0.20,   # >= 10 failed attempts
    "admin_account":        0.10,
    "very_long_session":    0.10,   # > 8 hours
    "service_off_hours":    0.15,   # service account active outside window
    "sensitive_resource":   0.20,
}

BUSINESS_HOURS = range(7, 21)  # 7 AM – 9 PM

_SENSITIVE_RESOURCES = re.compile(
    r"(?:confidential|salary|payroll|executive|finance|hr_|legal|"
    r"secret|private|credential|password|shadow|ntds)",
    re.I,
)

_ADMIN_TERMS = re.compile(
    r"\b(?:admin|administrator|root|superuser|wheel|privileged)\b", re.I
)
_SERVICE_TERMS = re.compile(
    r"(?:^|[\s,;])(?:svc_\w+|service_?account|system_?account|\w+machine\$|\w+_svc\b)", re.I
)


def _parse_hour(log: str) -> Optional[int]:
    m = re.search(r"T(\d{2}):\d{2}:\d{2}", log)
    if m:
        return int(m.group(1))
    m = re.search(r"\b([01]?\d|2[0-3]):(\d{2})(?::\d{2})?\s*(?:[AP]M)?", log)
    if m:
        hour = int(m.group(1))
        # Handle AM/PM
        ampm = re.search(r"\b(AM|PM)\b", log, re.I)
        if ampm:
            if ampm.group(1).upper() == "PM" and hour != 12:
                hour += 12
            elif ampm.group(1).upper() == "AM" and hour == 12:
                hour = 0
        return hour
    return None


def _parse_failures(log: str) -> Optional[int]:
    m = re.search(r"(?:fail(?:ed|ure)?|attempt)[s]?[:\s]+(\d+)", log, re.I)
    if m:
        return int(m.group(1))
    return None


def _parse_session_minutes(log: str) -> Optional[int]:
    m = re.search(r"session[_\s]?(?:duration|length)[=:\s]+(\d+)\s*(min|hour|h\b|m\b)", log, re.I)
    if m:
        val, unit = int(m.group(1)), m.group(2).lower()
        return val * 60 if unit.startswith("h") else val
    m = re.search(r"(\d+)\s*(?:hours?)\s+(?:\d+\s*)?minutes?", log, re.I)
    if m:
        return int(m.group(1)) * 60
    return None


def _risk_level(score: float) -> str:
    if score >= 0.75:
        return "Critical"
    if score >= 0.50:
        return "High"
    if score >= 0.25:
        return "Medium"
    return "Low"


def user_behavior_analyzer(
    log_payload: str,
    username: str = "",
    resource_accessed: str = "",
) -> UserBehaviorResult:
    """
    Stateless user behavior risk scorer.
    Evaluates: off-hours access, privilege escalation, impossible travel,
    mass file access, failed login counts, sensitive resource access,
    and long session anomalies.
    Returns a 0–1 risk score with labeled anomaly flags.
    """
    result = UserBehaviorResult(data_source="local")
    flags: list[str] = []
    score = 0.0

    combined = f"{log_payload} {username} {resource_accessed}".strip()

    # --- Account type classification ---
    if _ADMIN_TERMS.search(combined):
        result.account_type = "admin"
        score += _WEIGHTS["admin_account"]
        flags.append("Admin/privileged account activity")
    elif _SERVICE_TERMS.search(combined):
        result.account_type = "service"
    else:
        result.account_type = "user"

    # --- Off-hours detection ---
    hour = _parse_hour(combined)
    if hour is not None and hour not in BUSINESS_HOURS:
        result.is_off_hours = True
        score += _WEIGHTS["off_hours"]
        flags.append(f"Activity outside business hours ({hour:02d}:xx)")
        if result.account_type == "service":
            score += _WEIGHTS["service_off_hours"]
            flags.append("Service account active outside scheduled window")

    # --- Impossible travel ---
    if re.search(r"(?:impossible[_\s]travel|location.*mismatch|different.*location|"
                 r"prev.*location|geo.*anomaly)", combined, re.I):
        result.is_impossible_travel = True
        score += _WEIGHTS["impossible_travel"]
        flags.append("Impossible travel / geographic anomaly detected")

    # --- Privilege escalation ---
    if re.search(r"(?:escalat|sudo|runas|privilege.*change|role.*change|"
                 r"added.*admin|added.*sudo|wheel.*group|elevated)", combined, re.I):
        result.is_privilege_escalation = True
        score += _WEIGHTS["priv_escalation"]
        flags.append("Privilege escalation or role change")

    # --- New / first-time asset access ---
    if re.search(r"(?:first[_\s]time|new[_\s]device|new[_\s]asset|"
                 r"first[_\s]access|First_time_access|never[_\s]accessed)", combined, re.I):
        result.is_new_asset = True
        score += _WEIGHTS["new_asset"]
        flags.append("First-time access to resource or device")

    # --- Mass access ---
    if re.search(r"(?:mass[_\s]access|\d{3,}\s*files?|\d{3,}\s*records?|"
                 r"bulk[_\s]download|enumerate|scraped?)", combined, re.I):
        result.is_mass_access = True
        score += _WEIGHTS["mass_access"]
        flags.append("Mass file/record access pattern")

    # --- Sensitive resource access ---
    if _SENSITIVE_RESOURCES.search(combined):
        score += _WEIGHTS["sensitive_resource"]
        flags.append("Access to sensitive/confidential resource")

    # --- Failed attempts ---
    failures = _parse_failures(combined)
    if failures is not None:
        result.failed_attempts = failures
        if failures >= 10:
            score += _WEIGHTS["many_failures"]
            flags.append(f"High failure count: {failures} failed attempts")

    # --- Long session ---
    session_min = _parse_session_minutes(combined)
    if session_min is not None:
        result.session_duration_minutes = session_min
        if session_min > 480:  # > 8 hours
            score += _WEIGHTS["very_long_session"]
            flags.append(f"Unusually long session: {session_min} minutes")

    # Compound signals
    if result.is_off_hours and result.is_privilege_escalation:
        score += 0.10
        flags.append("Off-hours privilege escalation (compound risk)")

    if result.is_new_asset and result.is_off_hours:
        score += 0.10
        flags.append("First-time access at off-hours (compound risk)")

    result.risk_score = round(min(score, 1.0), 2)
    result.risk_level = _risk_level(result.risk_score)
    result.anomaly_flags = flags

    return result
