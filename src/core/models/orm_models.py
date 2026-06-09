
import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from src.core.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, default=_uuid)
    event_id = Column(String, unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    agent_name = Column(String, nullable=True)
    host = Column(String, nullable=True, index=True)
    rule_id = Column(String, nullable=True, index=True)
    rule_level = Column(Integer, nullable=True)
    rule_description = Column(Text, nullable=True)
    source_ip = Column(String, nullable=True, index=True)
    destination_ip = Column(String, nullable=True)
    user = Column(String, nullable=True, index=True)
    event_type = Column(String, nullable=True, index=True)
    fingerprint = Column(String, nullable=True, index=True)
    raw_data = Column(JSON, nullable=True)
    ingested_at = Column(DateTime, default=_utcnow)
    normalized = Column(Boolean, default=True)

    incidents = relationship("IncidentAlert", back_populates="alert")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=_uuid)
    title = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    status = Column(String, default="open", index=True)  # open, investigating, resolved, false_positive
    severity = Column(String, nullable=True, index=True)  # low, medium, high, critical
    risk_score = Column(Float, default=0.0)
    mitre_technique_id = Column(String, nullable=True)
    mitre_technique = Column(String, nullable=True)
    mitre_tactic = Column(String, nullable=True)
    root_cause = Column(Text, nullable=True)
    ai_confidence = Column(Float, nullable=True)
    ai_summary = Column(Text, nullable=True)
    recommended_actions = Column(JSON, nullable=True)
    source_ips = Column(JSON, nullable=True)
    affected_hosts = Column(JSON, nullable=True)
    affected_users = Column(JSON, nullable=True)
    alert_count = Column(Integer, default=0)
    first_alert_at = Column(DateTime, nullable=True)
    last_alert_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    closed_at = Column(DateTime, nullable=True)

    alerts = relationship("IncidentAlert", back_populates="incident", cascade="all, delete-orphan")
    feedback = relationship("AnalystFeedback", back_populates="incident", cascade="all, delete-orphan")


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    id = Column(String, primary_key=True, default=_uuid)
    incident_id = Column(String, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    alert_id = Column(String, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    correlation_rule = Column(String, nullable=True)
    added_at = Column(DateTime, default=_utcnow)

    incident = relationship("Incident", back_populates="alerts")
    alert = relationship("Alert", back_populates="incidents")


class DedupFingerprint(Base):
    __tablename__ = "dedup_fingerprints"

    id = Column(String, primary_key=True, default=_uuid)
    fingerprint = Column(String, nullable=False, index=True)
    alert_id = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=_utcnow)


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id = Column(String, primary_key=True, default=_uuid)
    cache_key = Column(String, unique=True, nullable=False, index=True)
    provider = Column(String, nullable=False)
    data = Column(JSON, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=_utcnow)


class DeadLetterRecord(Base):
    __tablename__ = "dead_letter_queue"

    id = Column(String, primary_key=True, default=_uuid)
    original_payload = Column(JSON, nullable=False)
    error = Column(Text, nullable=False)
    error_type = Column(String, nullable=True)
    source = Column(String, nullable=False)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    status = Column(String, default="pending", index=True)  # pending, retried, discarded, reprocessed
    created_at = Column(DateTime, default=_utcnow)
    last_retry_at = Column(DateTime, nullable=True)


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id = Column(String, primary_key=True, default=_uuid)
    incident_id = Column(String, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    analyst_id = Column(String, nullable=False)
    action = Column(String, nullable=False)  # score_adjustment, merge, split, fp_mark, note, ai_override
    previous_value = Column(JSON, nullable=True)
    new_value = Column(JSON, nullable=True)
    reason = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=_utcnow)

    incident = relationship("Incident", back_populates="feedback")


class Webhook(Base):
    __tablename__ = "webhooks"

    id = Column(String, primary_key=True, default=_uuid)
    url = Column(String, nullable=False)
    secret = Column(String, nullable=True)
    events = Column(JSON, nullable=False)  # ["incident_created", "incident_updated", "critical_alert"]
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class WebhookDeliveryLog(Base):
    __tablename__ = "webhook_delivery_log"

    id = Column(String, primary_key=True, default=_uuid)
    webhook_id = Column(String, ForeignKey("webhooks.id", ondelete="SET NULL"), nullable=True)
    event = Column(String, nullable=False)
    payload = Column(JSON, nullable=True)
    status = Column(String, nullable=False)  # success, failed, pending
    status_code = Column(Integer, nullable=True)
    error = Column(Text, nullable=True)
    attempt = Column(Integer, default=1)
    delivered_at = Column(DateTime, default=_utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=_uuid)
    actor_id = Column(String, nullable=True)
    actor_role = Column(String, nullable=True)
    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    resource_id = Column(String, nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime, default=_utcnow)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token = Column(String, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_utcnow)


class CorrelationRuleStat(Base):
    __tablename__ = "correlation_rule_stats"

    id = Column(String, primary_key=True, default=_uuid)
    rule_name = Column(String, unique=True, nullable=False, index=True)
    total_incidents = Column(Integer, default=0)
    false_positive_count = Column(Integer, default=0)
    false_positive_rate = Column(Float, default=0.0)
    enabled = Column(Boolean, default=True)
    weight = Column(Float, default=1.0)
    last_fp_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=_uuid)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False, default="analyst")  # analyst, senior_analyst, admin
    active = Column(Boolean, default=True)
    force_password_change = Column(Boolean, default=False)
    password_changed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
