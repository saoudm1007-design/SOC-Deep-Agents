from typing import Optional
from pydantic import BaseModel, Field


class AlertInput(BaseModel):
    """Normalized security alert — accepts multiple field naming conventions."""
    alert_id: Optional[str] = None
    timestamp: Optional[str] = None
    source_ip: Optional[str] = Field(default=None, alias="src_ip")
    destination_ip: Optional[str] = Field(default=None, alias="dst_ip")
    service: Optional[str] = None
    log_payload: Optional[str] = Field(default=None, alias="payload")
    event_type: Optional[str] = None
    severity: Optional[str] = None
    raw: Optional[dict] = None

    model_config = {"populate_by_name": True}

    @classmethod
    def from_dict(cls, data: dict) -> "AlertInput":
        """Normalize alert dicts with various field naming conventions."""
        normalized = dict(data)

        # Normalize alert ID
        for key in ("id", "alert_id", "alertId"):
            if key in normalized and "alert_id" not in normalized:
                normalized["alert_id"] = normalized[key]

        # Normalize source IP
        for key in ("srcip", "src_ip", "source.ip", "source_ip"):
            if key in normalized and "source_ip" not in normalized:
                normalized["source_ip"] = normalized[key]

        # Normalize destination IP
        for key in ("dstip", "dst_ip", "destination.ip", "destination_ip"):
            if key in normalized and "destination_ip" not in normalized:
                normalized["destination_ip"] = normalized[key]

        # Normalize log payload
        for key in ("raw_log", "log_payload", "payload", "message", "log_message"):
            if key in normalized and "log_payload" not in normalized:
                normalized["log_payload"] = normalized[key]

        normalized["raw"] = data
        return cls(**{k: v for k, v in normalized.items() if v is not None})


class ToolResult(BaseModel):
    """Base model for all tool outputs."""
    tool_name: str
    success: bool = True
    data_source: str = "api"
    error: Optional[str] = None

    model_config = {"extra": "allow"}

    def summary(self) -> dict:
        """Return non-null fields only — keeps token count low."""
        return self.model_dump(exclude_none=True)


class VerdictOutput(BaseModel):
    """Structured verdict output — used as response_format for Deep Agents."""
    verdict: str = Field(
        description="Malicious, Benign, or Suspicious",
        pattern="^(Malicious|Benign|Suspicious)$",
    )
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(max_length=600)
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    investigated_tools: list[str] = Field(default_factory=list)
