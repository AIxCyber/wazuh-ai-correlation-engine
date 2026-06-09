
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from src.ai.engine import AIAnalysisEngine
from src.correlation.engine import CorrelationEngine
from src.core.config import get_config
from src.scoring.engine import RiskScoringEngine
from src.api.middleware.auth import (
    change_password as auth_change_password,
    decode_token,
    generate_reset_token,
    hash_password,
    login_user,
    require_permission,
    reset_password as auth_reset_password,
    reset_password_with_token,
)
from src.core.database import get_db
from src.core.email import is_smtp_configured, send_reset_email
from src.core.logging import get_logger
from src.core.metrics import active_incidents
from src.core.models.orm_models import (
    Alert,
    AnalystFeedback,
    AuditLog,
    CorrelationRuleStat,
    DeadLetterRecord,
    Incident,
    IncidentAlert,
    User,
)
from src.ingestion.dlq import DeadLetterQueue
from src.ingestion.service import AlertIngestionService
from src.normalization.schema import (
    AIAnalysisAlertRequest, AIAnalysisRequest, AIOverrideRequest,
    ChangePasswordRequest, CreateUserRequest, FeedbackCreate,
    ForgotPasswordRequest, LoginRequest, MergeIncidentsRequest,
    ResetPasswordRequest, ResetWithTokenRequest, SplitIncidentRequest,
    UpdateUserRequest,
)
from src.reporting.engine import ReportingEngine
from src.webhooks.engine import WebhookEngine

logger = get_logger(__name__)

cfg = get_config()

router = APIRouter()
ingestion_service = AlertIngestionService()
dlq_service = DeadLetterQueue()
ai_engine = AIAnalysisEngine()
reporting = ReportingEngine()
webhook_engine = WebhookEngine()
correlation_engine = CorrelationEngine()

_start_time = time.time()


@router.get("/health")
def health_check():
    from sqlalchemy import text as sa_text

    from src.core.database import get_session_local
    db_status = "ok"
    try:
        session = get_session_local()()
        session.execute(sa_text("SELECT 1"))
        session.close()
    except Exception:
        db_status = "error"

    return {
        "status": "ok" if db_status == "ok" else "degraded",
        "version": "1.0.0",
        "database": db_status,
        "uptime_seconds": time.time() - _start_time,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@router.get("/ready")
def readiness_check():
    from sqlalchemy import text as sa_text

    from src.core.database import get_session_local
    session = get_session_local()()
    try:
        session.execute(sa_text("SELECT 1"))
        session.close()
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unavailable: {str(e)}",
        )


@router.post("/auth/login")
def auth_login(req: LoginRequest, db: Session = Depends(get_db)):
    result = login_user(req.username, req.password, db)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    _log_audit(db, req.username, "login", "auth", None, {"method": "password"})
    return result


@router.post("/auth/refresh")
def auth_refresh(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No token")
    payload = decode_token(auth.split(" ")[1])
    user = db.query(User).filter(User.id == payload["sub"], User.active.is_(True)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive")
    from src.api.middleware.auth import create_access_token
    return {
        "access_token": create_access_token(user.id, user.role),
        "token_type": "bearer",
        "expires_in": 3600,
        "password_change_required": user.force_password_change,
    }


@router.post("/auth/change-password")
def auth_change_password_endpoint(
    req: ChangePasswordRequest,
    current_user: dict = Depends(require_permission("view_dashboard")),
    db: Session = Depends(get_db),
):
    ok = auth_change_password(current_user["id"], req.old_password, req.new_password, db)
    if not ok:
        raise HTTPException(status_code=400, detail="Password change failed. Check your current password or choose a different new password.")
    _log_audit(db, current_user["id"], "change_password", "auth", current_user["id"], None)
    return {"detail": "Password changed"}


@router.post("/auth/reset-password")
def auth_reset_password_endpoint(
    req: ResetPasswordRequest,
    current_user: dict = Depends(require_permission("manage_users")),
    db: Session = Depends(get_db),
):
    ok = auth_reset_password(req.user_id, req.new_password, db)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    _log_audit(db, current_user["id"], "reset_password", "auth", req.user_id, None)
    return {"detail": "Password reset. User will be required to change on next login."}


@router.post("/auth/forgot-password")
def auth_forgot_password(
    req: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    username = req.username.strip()
    token = generate_reset_token(username, db)
    if not token:
        return {"sent": False, "detail": "If the user exists, a reset code has been generated."}

    from src.core.models.orm_models import User
    user = db.query(User).filter(User.username == username).first()
    emailed = False
    if user and user.email and is_smtp_configured():
        emailed = send_reset_email(user.email, token, username)

    return {
        "sent": True,
        "mode": "email" if emailed else "onscreen",
        "detail": "Reset code sent to your email." if emailed else "Use the code below to reset your password.",
        "token": None if emailed else token,
    }


@router.post("/auth/reset-with-token")
def auth_reset_with_token(
    req: ResetWithTokenRequest,
    db: Session = Depends(get_db),
):
    username = reset_password_with_token(req.token.strip(), req.new_password, db)
    if not username:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    _log_audit(db, username, "reset_password_with_token", "auth", None, None)
    return {"detail": "Password reset successfully. You can now log in with your new password."}


@router.get("/auth/requires-password-change")
def auth_requires_password_change(
    current_user: dict = Depends(require_permission("view_dashboard")),
    db: Session = Depends(get_db),
):
    from src.core.models.orm_models import User
    user = db.query(User).filter(User.id == current_user["id"]).first()
    return {"required": user.force_password_change if user else False}


@router.get("/incidents")
def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    status: str | None = None,
    host: str | None = None,
    user: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_incidents")),
):
    query = db.query(Incident)
    if severity:
        query = query.filter(Incident.severity == severity)
    if status:
        query = query.filter(Incident.status == status)
    if host:
        query = query.filter(Incident.affected_hosts.astext.contains(host))
    if user:
        query = query.filter(Incident.affected_users.astext.contains(user))
    if date_from:
        query = query.filter(Incident.created_at >= datetime.fromisoformat(date_from))
    if date_to:
        query = query.filter(Incident.created_at <= datetime.fromisoformat(date_to))

    total = query.count()
    incidents = query.order_by(Incident.created_at.desc()).offset(
        (page - 1) * page_size
    ).limit(page_size).all()

    return {
        "items": [_incident_to_dict(i) for i in incidents],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
    }


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_incidents")),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    result = _incident_to_dict(incident)
    result["alerts"] = []
    for ia in incident.alerts:
        alert_data = {
            "id": ia.alert.id,
            "event_id": ia.alert.event_id,
            "timestamp": ia.alert.timestamp.isoformat() if ia.alert.timestamp else None,
            "host": ia.alert.host,
            "rule_id": ia.alert.rule_id,
            "rule_level": ia.alert.rule_level,
            "rule_description": ia.alert.rule_description,
            "source_ip": ia.alert.source_ip,
            "event_type": ia.alert.event_type,
            "correlation_rule": ia.correlation_rule,
        }
        result["alerts"].append(alert_data)

    return result


@router.put("/incidents/{incident_id}")
def update_incident(
    incident_id: str,
    update: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("adjust_scores")),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    allowed = {"status", "risk_score", "title", "description", "severity"}
    previous = {}
    for field, value in update.items():
        if field in allowed and value is not None:
            previous[field] = getattr(incident, field, None)
            setattr(incident, field, value)

    incident.updated_at = datetime.now(UTC)
    if update.get("status") == "resolved":
        incident.closed_at = datetime.now(UTC)

    if update.get("status") == "false_positive":
        incident.closed_at = datetime.now(UTC)
        correlation_engine.record_false_positive(incident_id, db)
        _log_audit(
            db, current_user.get("id"), "false_positive",
            "incident", incident_id, {"changes": update, "previous": previous},
        )

    db.commit()

    _log_audit(
        db, current_user.get("id"), "update_incident",
        "incident", incident_id, {"changes": update, "previous": previous},
    )

    return _incident_to_dict(incident)


@router.delete("/incidents/{incident_id}")
def delete_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("delete_data")),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    db.delete(incident)
    db.commit()
    _log_audit(db, current_user.get("id"), "delete_incident", "incident", incident_id, {})
    return {"status": "deleted"}


@router.get("/alerts")
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    event_type: str | None = None,
    host: str | None = None,
    source_ip: str | None = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_alerts")),
):
    query = db.query(Alert)
    if event_type:
        query = query.filter(Alert.event_type == event_type)
    if host:
        query = query.filter(Alert.host == host)
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)

    total = query.count()
    alerts = query.order_by(Alert.timestamp.desc()).offset(
        (page - 1) * page_size
    ).limit(page_size).all()

    return {
        "items": [_alert_to_dict(a) for a in alerts],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
    }


@router.get("/alerts/{alert_id}")
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_alerts")),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_to_dict(alert)


@router.post("/alerts/ingest")
def ingest_alerts(
    payload: list[dict[str, Any]],
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("run_analysis")),
):
    ingested = []
    for item in payload:
        alert = ingestion_service.ingest_single(item)
        if alert:
            db_alert = Alert(
                event_id=alert.event_id,
                timestamp=alert.timestamp,
                agent_name=alert.agent_name,
                host=alert.host,
                rule_id=alert.rule_id,
                rule_level=alert.rule_level,
                rule_description=alert.rule_description,
                source_ip=alert.source_ip,
                destination_ip=alert.destination_ip,
                user=alert.user,
                event_type=alert.event_type,
                fingerprint=alert.fingerprint,
                raw_data=alert.raw_data,
            )
            db.add(db_alert)
            ingested.append(alert.model_dump(exclude={"raw_data"}))

    db.commit()
    return {"ingested": len(ingested), "alerts": ingested}


@router.post("/analyze")
def analyze_incident(
    req: AIAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("run_analysis")),
):
    incident = db.query(Incident).filter(Incident.id == req.incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident_dict = _incident_to_dict(incident)
    incident_dict["alerts"] = []
    for ia in incident.alerts:
        incident_dict["alerts"].append(_alert_to_dict(ia.alert))

    result = ai_engine.analyze(incident_dict, provider=req.provider)
    if not result:
        raise HTTPException(status_code=500, detail="AI analysis failed")

    incident.root_cause = result.root_cause
    incident.ai_confidence = result.confidence
    incident.ai_summary = result.summary
    incident.recommended_actions = result.recommended_actions
    if result.mitre_techniques:
        incident.mitre_technique_id = result.mitre_techniques[0] if result.mitre_techniques else None
    incident.updated_at = datetime.now(UTC)
    db.commit()

    _log_audit(
        db, current_user.get("id"), "ai_analysis",
        "incident", req.incident_id, {"provider": req.provider or "default"},
    )

    return result.model_dump()


@router.post("/analyze/alert")
def analyze_alert(
    req: AIAnalysisAlertRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("run_analysis")),
):
    alert = db.query(Alert).filter(Alert.id == req.alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    incident_dict = {
        "id": f"alert-{alert.id}",
        "title": alert.rule_description or "Alert Analysis",
        "description": alert.rule_description or "",
        "severity": "medium",
        "risk_score": min(alert.rule_level * 10, 100) if alert.rule_level else 50,
        "source_ips": [alert.source_ip] if alert.source_ip else [],
        "affected_hosts": [alert.host] if alert.host else [],
        "affected_users": [alert.user] if alert.user else [],
        "alerts": [_alert_to_dict(alert)],
    }

    result = ai_engine.analyze(incident_dict, provider=req.provider)
    if not result:
        raise HTTPException(status_code=500, detail="AI analysis failed")

    _log_audit(
        db, current_user.get("id"), "ai_analysis",
        "alert", req.alert_id, {"provider": req.provider or "default"},
    )

    return result.model_dump()


@router.post("/incidents/{incident_id}/ai-override")
def override_ai_analysis(
    incident_id: str,
    req: AIOverrideRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("adjust_scores")),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    previous = {
        "root_cause": incident.root_cause,
        "ai_summary": incident.ai_summary,
        "recommended_actions": incident.recommended_actions,
        "mitre_technique_id": incident.mitre_technique_id,
        "severity": incident.severity,
    }

    if req.root_cause is not None:
        incident.root_cause = req.root_cause
    if req.summary is not None:
        incident.ai_summary = req.summary
    if req.recommended_actions is not None:
        incident.recommended_actions = req.recommended_actions
    if req.mitre_techniques is not None and len(req.mitre_techniques) > 0:
        incident.mitre_technique_id = req.mitre_techniques[0]
    if req.severity is not None:
        incident.severity = req.severity

    incident.updated_at = datetime.now(UTC)
    db.commit()

    feedback = AnalystFeedback(
        incident_id=incident_id,
        analyst_id=current_user.get("id"),
        action="ai_override",
        previous_value=previous,
        new_value={
            "root_cause": incident.root_cause,
            "ai_summary": incident.ai_summary,
            "recommended_actions": incident.recommended_actions,
            "mitre_technique_id": incident.mitre_technique_id,
            "severity": incident.severity,
        },
        reason=req.reason or "AI analysis overridden by analyst",
    )
    db.add(feedback)
    db.commit()

    _log_audit(
        db, current_user.get("id"), "override_ai_analysis",
        "incident", incident_id, {"overrides": req.model_dump(exclude_none=True)},
    )

    return _incident_to_dict(incident)


@router.post("/incidents/merge")
def merge_incidents(
    req: MergeIncidentsRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("merge_incidents")),
):
    if len(req.incident_ids) < 2:
        raise HTTPException(status_code=400, detail="At least 2 incident IDs required")

    incidents_map = {
        i.id: i for i in db.query(Incident).filter(Incident.id.in_(req.incident_ids)).all()
    }
    if len(incidents_map) != len(req.incident_ids):
        raise HTTPException(status_code=404, detail="One or more incidents not found")

    incidents = [incidents_map[iid] for iid in req.incident_ids]
    master = incidents[0]
    source_ips = set(master.source_ips or [])
    affected_hosts = set(master.affected_hosts or [])
    affected_users = set(master.affected_users or [])
    total_alerts = master.alert_count or 0
    all_alert_ids = [ia.alert_id for ia in master.alerts]

    for other in incidents[1:]:
        source_ips.update(other.source_ips or [])
        affected_hosts.update(other.affected_hosts or [])
        affected_users.update(other.affected_users or [])
        total_alerts += other.alert_count or 0
        for ia in other.alerts:
            db_ia = IncidentAlert(
                incident_id=master.id, alert_id=ia.alert_id,
                correlation_rule="merge",
            )
            db.add(db_ia)
            all_alert_ids.append(ia.alert_id)
        other.status = "merged"
        other.updated_at = datetime.now(UTC)

    master.source_ips = list(source_ips)
    master.affected_hosts = list(affected_hosts)
    master.affected_users = list(affected_users)
    master.alert_count = total_alerts
    if req.title:
        master.title = req.title
    master.first_alert_at = min(
        (i.first_alert_at for i in incidents if i.first_alert_at),
        default=master.first_alert_at,
    )
    master.last_alert_at = max(
        (i.last_alert_at for i in incidents if i.last_alert_at),
        default=master.last_alert_at,
    )
    master.updated_at = datetime.now(UTC)
    db.commit()

    feedback = AnalystFeedback(
        incident_id=master.id,
        analyst_id=current_user.get("id"),
        action="merge",
        previous_value={"merged_ids": req.incident_ids},
        new_value={"merged_ids": [master.id] + req.incident_ids[1:]},
        reason=f"Merged {len(req.incident_ids)} incidents",
    )
    db.add(feedback)
    db.commit()

    _log_audit(db, current_user.get("id"), "merge_incidents", "incident", master.id, req.model_dump())
    return {"merged_incident_id": master.id, "source_ids": req.incident_ids}


@router.post("/incidents/{incident_id}/split")
def split_incident(
    incident_id: str,
    req: SplitIncidentRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("split_incidents")),
):
    if incident_id != req.incident_id:
        raise HTTPException(status_code=400, detail="Path ID and body ID must match")

    incident = db.query(Incident).filter(Incident.id == req.incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    existing_alert_ids = {ia.alert_id for ia in incident.alerts}
    move_ids = [aid for aid in req.alert_ids if aid in existing_alert_ids]
    if not move_ids:
        raise HTTPException(status_code=400, detail="No valid alert IDs to split")

    new_incident = Incident(
        title=req.title or f"Split from {incident.title or incident_id}",
        description=incident.description,
        severity=incident.severity,
        status="open",
        risk_score=incident.risk_score,
    )
    db.add(new_incident)
    db.flush()

    moved_alerts = []
    for ia in list(incident.alerts):
        if ia.alert_id in move_ids:
            db_ia = IncidentAlert(
                incident_id=new_incident.id, alert_id=ia.alert_id,
                correlation_rule="split",
            )
            db.add(db_ia)
            incident.alerts.remove(ia)
            db.delete(ia)
            moved_alerts.append(ia.alert_id)

    incident.alert_count = (incident.alert_count or 0) - len(moved_alerts)
    new_incident.alert_count = len(moved_alerts)

    # Recalculate source_ips, hosts, users
    remaining_alerts = db.query(Alert).filter(Alert.event_id.in_(
        [ia.alert_id for ia in incident.alerts]
    )).all()
    incident.source_ips = list({a.source_ip for a in remaining_alerts if a.source_ip})
    incident.affected_hosts = list({a.host for a in remaining_alerts if a.host})
    incident.affected_users = list({a.user for a in remaining_alerts if a.user})

    moved_alerts_data = db.query(Alert).filter(Alert.event_id.in_(move_ids)).all()
    new_incident.source_ips = list({a.source_ip for a in moved_alerts_data if a.source_ip})
    new_incident.affected_hosts = list({a.host for a in moved_alerts_data if a.host})
    new_incident.affected_users = list({a.user for a in moved_alerts_data if a.user})

    new_incident.first_alert_at = min(
        (a.timestamp for a in moved_alerts_data if a.timestamp), default=None
    )
    new_incident.last_alert_at = max(
        (a.timestamp for a in moved_alerts_data if a.timestamp), default=None
    )

    incident.updated_at = datetime.now(UTC)
    db.commit()

    feedback = AnalystFeedback(
        incident_id=incident_id,
        analyst_id=current_user.get("id"),
        action="split",
        previous_value={"split_alert_ids": move_ids},
        new_value={"new_incident_id": new_incident.id},
        reason=f"Split {len(move_ids)} alerts into new incident",
    )
    db.add(feedback)
    db.commit()

    _log_audit(
        db, current_user.get("id"), "split_incident",
        "incident", incident_id, {"new_incident_id": new_incident.id, "alert_ids": move_ids},
    )
    return {"original_incident_id": incident_id, "new_incident_id": new_incident.id, "moved_alerts": len(move_ids)}


@router.post("/incidents/{incident_id}/feedback")
def add_feedback(
    incident_id: str,
    feedback: FeedbackCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("add_notes")),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    entry = AnalystFeedback(
        incident_id=incident_id,
        analyst_id=current_user.get("id"),
        action=feedback.action,
        reason=feedback.reason,
        new_value=feedback.new_value,
    )
    db.add(entry)
    db.commit()

    _log_audit(
        db, current_user.get("id"), f"feedback_{feedback.action}",
        "incident", incident_id, {"reason": feedback.reason},
    )
    return {"id": entry.id, "action": feedback.action}


@router.get("/incidents/{incident_id}/feedback")
def list_feedback(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_incidents")),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    entries = db.query(AnalystFeedback).filter(
        AnalystFeedback.incident_id == incident_id
    ).order_by(AnalystFeedback.timestamp.desc()).all()

    return {
        "items": [{
            "id": e.id, "analyst_id": e.analyst_id, "action": e.action,
            "previous_value": e.previous_value, "new_value": e.new_value,
            "reason": e.reason, "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        } for e in entries],
        "total": len(entries),
    }


@router.get("/admin/dlq")
def list_dlq(
    status: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(require_permission("manage_dlq")),
):
    records, total = dlq_service.list_records(status=status, page=page, page_size=page_size)
    return {
        "items": records,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/admin/dlq/{dlq_id}/retry")
def retry_dlq(
    dlq_id: str,
    current_user: dict = Depends(require_permission("manage_dlq")),
):
    success = dlq_service.retry(dlq_id)
    if not success:
        raise HTTPException(status_code=404, detail="DLQ record not found")
    return {"status": "retried"}


@router.post("/admin/dlq/{dlq_id}/discard")
def discard_dlq(
    dlq_id: str,
    current_user: dict = Depends(require_permission("manage_dlq")),
):
    success = dlq_service.discard(dlq_id)
    if not success:
        raise HTTPException(status_code=404, detail="DLQ record not found")
    return {"status": "discarded"}


@router.post("/admin/dlq/retry-all")
def retry_all_dlq(
    current_user: dict = Depends(require_permission("manage_dlq")),
):
    count = dlq_service.retry_all_pending()
    return {"retried": count}


@router.get("/admin/audit-log")
def list_audit_log(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_config")),
):
    query = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
    total = query.count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [{"id": l.id, "actor_id": l.actor_id, "action": l.action,
                    "resource_type": l.resource_type, "resource_id": l.resource_id,
                    "details": l.details, "created_at": l.timestamp.isoformat() if l.timestamp else None}
                   for l in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


@router.get("/admin/config")
def view_config(
    current_user: dict = Depends(require_permission("view_config")),
):
    sensitive_keys = {"jwt_secret", "password", "secret", "api_key", "token"}
    safe = {}
    for key, val in cfg.model_dump().items():
        if any(s in key.lower() for s in sensitive_keys):
            safe[key] = "***REDACTED***"
        elif val is None:
            safe[key] = None
        else:
            safe[key] = str(val)
    return safe


@router.get("/admin/correlation-stats")
def correlation_stats(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_config")),
):
    stats = db.query(CorrelationRuleStat).order_by(CorrelationRuleStat.false_positive_rate.desc()).all()
    return {
        "items": [{
            "rule_name": s.rule_name,
            "total_incidents": s.total_incidents or 0,
            "false_positive_count": s.false_positive_count or 0,
            "false_positive_rate": round(s.false_positive_rate or 0.0, 4),
            "enabled": s.enabled,
            "weight": round(s.weight or 1.0, 2),
            "last_fp_at": s.last_fp_at.isoformat() if s.last_fp_at else None,
            "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        } for s in stats],
        "total": len(stats),
    }


@router.get("/admin/scoring-baseline")
def scoring_baseline(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_config")),
):
    engine = RiskScoringEngine()
    return engine.get_historical_baseline(db, days=days)


@router.get("/admin/stats")
def admin_stats(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_dashboard")),
):
    total_alerts = db.query(Alert).count()
    total_incidents = db.query(Incident).count()
    open_incidents = db.query(Incident).filter(Incident.status == "open").count()
    critical_incidents = db.query(Incident).filter(
        Incident.severity == "critical", Incident.status == "open"
    ).count()
    dlq_total = db.query(DeadLetterRecord).count()

    for sev in ("critical", "high", "medium", "low"):
        count = db.query(Incident).filter(
            Incident.severity == sev, Incident.status == "open"
        ).count()
        active_incidents.labels(severity=sev).set(count)

    return {
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "critical_incidents": critical_incidents,
        "dlq_total": dlq_total,
    }


@router.get("/admin/users")
def admin_list_users(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("manage_users")),
):
    users = db.query(User).all()
    return {
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "role": u.role,
                "active": u.active,
                "force_password_change": u.force_password_change,
                "password_changed_at": u.password_changed_at.isoformat() if u.password_changed_at else None,
                "created_at": u.created_at.isoformat() if u.created_at else None,
            }
            for u in users
        ]
    }


@router.post("/admin/users")
def admin_create_user(
    req: CreateUserRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("manage_users")),
):
    existing = db.query(User).filter(User.username == req.username).first()
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(
        username=req.username,
        email=req.email,
        hashed_password=hash_password(req.password),
        role=req.role,
        force_password_change=True,
    )
    db.add(user)
    db.commit()
    _log_audit(db, current_user["id"], "create_user", "user", user.id, {"username": user.username})
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "active": user.active,
    }


@router.put("/admin/users/{user_id}")
def admin_update_user(
    user_id: str,
    req: UpdateUserRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("manage_users")),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    changes = {}
    if req.role is not None:
        changes["role"] = req.role
        user.role = req.role
    if req.active is not None:
        changes["active"] = req.active
        user.active = req.active
    if req.email is not None:
        changes["email"] = req.email
        user.email = req.email
    if changes:
        db.commit()
        _log_audit(db, current_user["id"], "update_user", "user", user_id, changes)
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "active": user.active,
    }


@router.delete("/admin/users/{user_id}")
def admin_delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("manage_users")),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    db.delete(user)
    db.commit()
    _log_audit(db, current_user["id"], "delete_user", "user", user_id, {"username": user.username})
    return {"status": "deleted"}


@router.post("/webhooks/configure")
def configure_webhook(
    config: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("manage_webhooks")),
):
    wh_id = webhook_engine.register(
        url=config["url"],
        events=config.get("events", ["incident_created", "critical_alert"]),
        secret=config.get("secret"),
    )
    _log_audit(db, current_user.get("id"), "create_webhook", "webhook", wh_id, config)
    return {"id": wh_id, "status": "created"}


@router.get("/webhooks")
def list_webhooks(
    current_user: dict = Depends(require_permission("manage_webhooks")),
):
    return {"webhooks": webhook_engine.list_webhooks()}


@router.delete("/webhooks/{webhook_id}")
def delete_webhook(
    webhook_id: str,
    current_user: dict = Depends(require_permission("manage_webhooks")),
):
    success = webhook_engine.delete(webhook_id)
    if not success:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"status": "deleted"}


@router.post("/incidents/{incident_id}/report")
def generate_report(
    incident_id: str,
    formats: list[str] = Query(["json", "html"]),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("export_reports")),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident_dict = _incident_to_dict(incident)
    incident_dict["alerts"] = []
    for ia in incident.alerts:
        incident_dict["alerts"].append(_alert_to_dict(ia.alert))

    report_paths = reporting.generate_report(incident_dict, formats=formats)
    return {"report_paths": report_paths}


def _incident_to_dict(i: Incident) -> dict[str, Any]:
    return {
        "id": i.id,
        "title": i.title,
        "description": i.description,
        "status": i.status,
        "severity": i.severity,
        "risk_score": i.risk_score,
        "mitre_technique_id": i.mitre_technique_id,
        "mitre_technique": i.mitre_technique,
        "mitre_tactic": i.mitre_tactic,
        "root_cause": i.root_cause,
        "ai_confidence": i.ai_confidence,
        "ai_summary": i.ai_summary,
        "recommended_actions": i.recommended_actions,
        "source_ips": i.source_ips,
        "affected_hosts": i.affected_hosts,
        "affected_users": i.affected_users,
        "alert_count": i.alert_count,
        "first_alert_at": i.first_alert_at.isoformat() if i.first_alert_at else None,
        "last_alert_at": i.last_alert_at.isoformat() if i.last_alert_at else None,
        "created_at": i.created_at.isoformat() if i.created_at else None,
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
        "closed_at": i.closed_at.isoformat() if i.closed_at else None,
    }


def _alert_to_dict(a: Alert) -> dict[str, Any]:
    return {
        "id": a.id,
        "event_id": a.event_id,
        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        "agent_name": a.agent_name,
        "host": a.host,
        "rule_id": a.rule_id,
        "rule_level": a.rule_level,
        "rule_description": a.rule_description,
        "source_ip": a.source_ip,
        "destination_ip": a.destination_ip,
        "user": a.user,
        "event_type": a.event_type,
        "fingerprint": a.fingerprint,
        "ingested_at": a.ingested_at.isoformat() if a.ingested_at else None,
    }


def _log_audit(
    db: Session, actor_id: str | None, action: str,
    resource_type: str, resource_id: str | None, details: dict,
) -> None:
    try:
        log = AuditLog(
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
        )
        db.add(log)
        db.commit()
    except Exception as e:
        logger.error("audit_log_failed", extra={"error": str(e)})
