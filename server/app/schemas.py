import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class EnrollRequest(BaseModel):
    enroll_token: str
    hostname: str
    platform: str = "unknown"
    agent_version: str = "0.1.0"


class EnrollResponse(BaseModel):
    device_id: str
    api_key: str


class TelemetryEvent(BaseModel):
    source: str
    severity: str = "info"
    action: str
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[datetime.datetime] = None


class TelemetryBatch(BaseModel):
    events: list[TelemetryEvent] = Field(default_factory=list)


class CheckinResponse(BaseModel):
    isolated: bool
    commands: list[dict]
    blocklist: dict[str, list[str]]


class DeviceOut(BaseModel):
    id: str
    hostname: str
    platform: str
    agent_version: str
    enrolled_at: datetime.datetime
    last_seen: datetime.datetime
    isolated: bool
    online: bool
    risk_score: float = 0.0
    risk_band: str = "clear"

    model_config = ConfigDict(from_attributes=True)


class EventOut(BaseModel):
    id: int
    device_id: str
    hostname: str = ""
    timestamp: datetime.datetime
    source: str
    severity: str
    action: str
    summary: str
    details: dict[str, Any]


class BlocklistAdd(BaseModel):
    kind: str  # domain | process | port
    value: str
