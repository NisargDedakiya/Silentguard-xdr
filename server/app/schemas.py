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
    # MITRE ATT&CK technique evidenced by this event, e.g.
    # {"id": "T1059", "name": "Command and Scripting Interpreter", "url": ...}
    mitre: Optional[dict[str, str]] = None


class BlocklistAdd(BaseModel):
    kind: str  # domain | process | port
    value: str


class LoginRequest(BaseModel):
    email: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserCreate(BaseModel):
    email: str
    password: str
    role: str = "read_only"


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    is_active: bool
    last_login_at: Optional[datetime.datetime] = None
    created_at: datetime.datetime

    model_config = ConfigDict(from_attributes=True)


class IOCCreate(BaseModel):
    ioc_type: str  # domain|ip|url|sha256|certificate
    value: str
    confidence: int = 50
    source: str = "manual"
    description: str = ""
    expires_at: Optional[datetime.datetime] = None


class IOCImport(BaseModel):
    source: str = "import"
    iocs: list[dict[str, Any]] = Field(default_factory=list)


class IOCOut(BaseModel):
    id: int
    ioc_type: str
    value: str
    confidence: int
    source: str
    description: str
    expires_at: Optional[datetime.datetime] = None
    created_at: datetime.datetime

    model_config = ConfigDict(from_attributes=True)


class IntelRuleCreate(BaseModel):
    kind: str  # yara|sigma
    name: str
    content: str
    enabled: bool = True


class IntelRuleOut(BaseModel):
    id: int
    kind: str
    name: str
    content: str
    enabled: bool
    created_at: datetime.datetime

    model_config = ConfigDict(from_attributes=True)


class DetectionOut(BaseModel):
    id: int
    device_id: str
    hostname: str = ""
    rule_id: str
    name: str
    severity: str
    risk_score: int
    technique_id: str
    technique_name: str
    status: str
    created_at: datetime.datetime
    details: dict[str, Any] = Field(default_factory=dict)


class AuditOut(BaseModel):
    id: int
    timestamp: datetime.datetime
    actor: str  # admin token fingerprint
    action: str
    target: str
    details: dict[str, Any] = Field(default_factory=dict)


class QuarantineOut(BaseModel):
    id: str
    device_id: str
    hostname: str = ""
    original_path: str
    sha256: str
    reason: str
    verdict: str
    status: str
    quarantined_at: datetime.datetime
    restored_at: Optional[datetime.datetime] = None
