from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator


class NormalizedAlert(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    agent_name: str = ""
    host: str = ""
    rule_id: str = ""
    rule_level: int = 0
    rule_description: str = ""
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    event_type: str = "unknown"
    raw_data: dict[str, Any] = Field(default_factory=dict, exclude=True)
    fingerprint: str | None = None

    @model_validator(mode="after")
    def generate_fingerprint(self) -> NormalizedAlert:
        raw = f"{self.rule_id}|{self.source_ip or ''}|{self.host}|{self.user or ''}"
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()
        return self


class RawWazuhAlert(BaseModel):
    """Raw Wazuh alert as received from the Wazuh manager."""
    timestamp: str | None = None
    rule: dict[str, Any] | None = None
    agent: dict[str, Any] | None = None
    data: dict[str, Any] | None = None
    location: str | None = None
    decoder: dict[str, Any] | None = None
    id: str | None = None
    full_log: str | None = None
    predecoder: dict[str, Any] | None = None
    output: dict[str, Any] | None = None


class IncidentCreate(BaseModel):
    alert_ids: list[str]
    correlation_rule: str = "auto"
    title: str | None = None


class IncidentUpdate(BaseModel):
    status: str | None = None
    risk_score: float | None = None
    title: str | None = None
    description: str | None = None


class AIAnalysisRequest(BaseModel):
    incident_id: str
    provider: str | None = None


class AIAnalysisAlertRequest(BaseModel):
    alert_id: str
    provider: str | None = None


class FeedbackCreate(BaseModel):
    action: str  # score_adjustment, merge, split, fp_mark, note, ai_override
    reason: str | None = None
    new_value: dict[str, Any] | None = None


class AIOverrideRequest(BaseModel):
    root_cause: str | None = None
    summary: str | None = None
    recommended_actions: list[str] | None = None
    mitre_techniques: list[str] | None = None
    severity: str | None = None
    reason: str | None = None


class MergeIncidentsRequest(BaseModel):
    incident_ids: list[str]
    title: str | None = None


class SplitIncidentRequest(BaseModel):
    incident_id: str
    alert_ids: list[str]
    title: str | None = None


class AIAnalysisResponse(BaseModel):
    root_cause: str
    confidence: float
    summary: str
    recommended_actions: list[str]
    mitre_techniques: list[str]
    severity: str


class ThreatIntelResult(BaseModel):
    ip: str
    reputation: str | None = None
    country: str | None = None
    confidence: float | None = None
    asn: str | None = None
    isp: str | None = None
    last_reported: datetime | None = None
    reports_count: int | None = None
    categories: list[str] = Field(default_factory=list)
    source: str = "unknown"


class DeadLetterCreate(BaseModel):
    original_payload: dict[str, Any]
    error: str
    error_type: str = "unknown"
    source: str = "ingestion_service"


class WebhookCreate(BaseModel):
    url: str
    secret: str | None = None
    events: list[str] = ["incident_created", "critical_alert"]


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class ResetPasswordRequest(BaseModel):
    user_id: str
    new_password: str


class ForgotPasswordRequest(BaseModel):
    username: str


class ResetWithTokenRequest(BaseModel):
    token: str
    new_password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    email: str | None = None


class UpdateUserRequest(BaseModel):
    role: str | None = None
    active: bool | None = None
    email: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    password_change_required: bool = False


class PaginatedResponse(BaseModel):
    items: list[Any]
    total: int
    page: int
    page_size: int
    total_pages: int


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    uptime_seconds: float
