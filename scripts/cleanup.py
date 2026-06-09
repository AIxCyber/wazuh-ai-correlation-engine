"""Data retention cleanup job. Run periodically (e.g., via cron or scheduler)."""
import os
import sys
from datetime import UTC, datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.config import get_config
from src.core.database import get_session_local, init_db
from src.core.logging import get_logger
from src.core.models.orm_models import Alert, AuditLog, Incident, WebhookDeliveryLog

logger = get_logger(__name__)


def cleanup_alerts(session, retention_days: int) -> int:
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    deleted = session.query(Alert).filter(Alert.timestamp < cutoff).delete()
    if deleted:
        logger.info("cleanup_alerts", extra={"deleted": deleted, "cutoff": cutoff.isoformat()})
    return deleted


def cleanup_incidents(session, retention_days: int) -> int:
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    deleted = (
        session.query(Incident)
        .filter(Incident.status.in_(["resolved", "false_positive"]))
        .filter(Incident.closed_at < cutoff)
        .delete()
    )
    if deleted:
        logger.info("cleanup_incidents", extra={"deleted": deleted})
    return deleted


def cleanup_audit_logs(session, retention_days: int) -> int:
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    deleted = session.query(AuditLog).filter(AuditLog.timestamp < cutoff).delete()
    if deleted:
        logger.info("cleanup_audit_logs", extra={"deleted": deleted})
    return deleted


def cleanup_webhook_logs(session, retention_days: int) -> int:
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    deleted = (
        session.query(WebhookDeliveryLog)
        .filter(WebhookDeliveryLog.delivered_at < cutoff)
        .delete()
    )
    if deleted:
        logger.info("cleanup_webhook_logs", extra={"deleted": deleted})
    return deleted


def run_cleanup():
    cfg = get_config()
    init_db()

    session = get_session_local()()
    try:
        total = 0
        total += cleanup_alerts(session, cfg.alert_retention_days)
        total += cleanup_incidents(session, cfg.incident_retention_days)
        total += cleanup_audit_logs(session, cfg.audit_log_retention_days)
        total += cleanup_webhook_logs(session, cfg.webhook_log_retention_days)
        session.commit()
        logger.info("cleanup_complete", extra={"total_deleted": total})
    except Exception as e:
        session.rollback()
        logger.error("cleanup_failed", extra={"error": str(e)})
    finally:
        session.close()


if __name__ == "__main__":
    run_cleanup()
