"""Seed the database with initial admin user and sample data."""
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api.middleware.auth import hash_password
from src.core.database import get_session_local, init_db
from src.core.logging import get_logger
from src.core.models.orm_models import Alert, Incident, IncidentAlert, User

logger = get_logger(__name__)


def seed_admin_user():
    session = get_session_local()()
    try:
        existing = session.query(User).filter(User.username == "admin").first()
        if existing:
            logger.info("admin_user_already_exists")
            return

        admin = User(
            username="admin",
            email="admin@soc.local",
            hashed_password=hash_password("admin123"),
            role="admin",
            active=True,
            force_password_change=True,
        )
        analyst = User(
            username="analyst",
            email="analyst@soc.local",
            hashed_password=hash_password("analyst123"),
            role="analyst",
            active=True,
            force_password_change=True,
        )
        senior = User(
            username="senior",
            email="senior@soc.local",
            hashed_password=hash_password("senior123"),
            role="senior_analyst",
            active=True,
            force_password_change=True,
        )

        session.add_all([admin, analyst, senior])
        session.commit()
        logger.info("seed_users_created")
    finally:
        session.close()


def seed_sample_alerts():
    session = get_session_local()()
    try:
        count = session.query(Alert).count()
        if count > 0:
            logger.info("sample_alerts_already_exist", extra={"count": count})
            return

        now = datetime.now(UTC)
        alerts = []

        alert_templates = [
            {"host": "web-01", "source_ip": "203.0.113.5", "rule_id": "5710",
             "rule_level": 10, "rule_description": "SSH Brute Force Attempt",
             "event_type": "brute_force", "user": "root", "count": 5},
            {"host": "web-02", "source_ip": "203.0.113.5", "rule_id": "5710",
             "rule_level": 10, "rule_description": "SSH Brute Force Attempt",
             "event_type": "brute_force", "user": "root", "count": 3},
            {"host": "db-01", "source_ip": "198.51.100.20", "rule_id": "550",
             "rule_level": 12, "rule_description": "Malware Detected",
             "event_type": "malware", "user": None, "count": 2},
            {"host": "mail-01", "source_ip": "192.0.2.10", "rule_id": "806",
             "rule_level": 8, "rule_description": "Privilege Escalation Attempt",
             "event_type": "privilege_escalation", "user": "admin", "count": 1},
            {"host": "web-01", "source_ip": "203.0.113.50", "rule_id": "1100",
             "rule_level": 9, "rule_description": "Lateral Movement Detected",
             "event_type": "lateral_movement", "user": "svc_account", "count": 2},
        ]

        for template in alert_templates:
            for i in range(template["count"]):
                ts = now - timedelta(
                    minutes=template["count"] * 5 - i * 5,
                    seconds=i * 30,
                )
                import hashlib
                raw_fp = f"{template['rule_id']}|{template['source_ip']}|{template['host']}|{template['user'] or ''}"
                fingerprint = hashlib.sha256(raw_fp.encode()).hexdigest()

                alert = Alert(
                    event_id=str(uuid.uuid4()),
                    timestamp=ts,
                    agent_name=template["host"],
                    host=template["host"],
                    rule_id=template["rule_id"],
                    rule_level=template["rule_level"],
                    rule_description=template["rule_description"],
                    source_ip=template["source_ip"],
                    event_type=template["event_type"],
                    user=template["user"],
                    fingerprint=fingerprint,
                    raw_data={"raw_timestamp": ts.isoformat()},
                )
                alerts.append(alert)

        session.add_all(alerts)
        session.commit()

        # Create incidents from alerts
        for event_type in ("brute_force", "malware", "privilege_escalation", "lateral_movement"):
            type_alerts = (
                session.query(Alert)
                .filter(Alert.event_type == event_type)
                .order_by(Alert.timestamp.asc())
                .all()
            )
            if not type_alerts:
                continue

            incident = Incident(
                title=f"{event_type.replace('_', ' ').title()} Attack",
                status="open",
                severity="medium",
                risk_score=45.0,
                alert_count=len(type_alerts),
                first_alert_at=type_alerts[0].timestamp,
                last_alert_at=type_alerts[-1].timestamp,
                source_ips=list(set(a.source_ip for a in type_alerts if a.source_ip)),
                affected_hosts=list(set(a.host for a in type_alerts if a.host)),
                affected_users=list(set(a.user for a in type_alerts if a.user)),
                mitre_technique_id="T1110" if event_type == "brute_force" else
                "T1204" if event_type == "malware" else
                "T1068" if event_type == "privilege_escalation" else "T1021",
                mitre_technique="Brute Force" if event_type == "brute_force" else
                "User Execution" if event_type == "malware" else
                "Exploitation for Privilege Escalation" if event_type == "privilege_escalation" else
                "Remote Services",
                mitre_tactic="Credential Access" if event_type == "brute_force" else
                "Execution" if event_type == "malware" else
                "Privilege Escalation" if event_type == "privilege_escalation" else
                "Lateral Movement",
            )
            session.add(incident)
            session.flush()

            for a in type_alerts:
                ia = IncidentAlert(incident_id=incident.id, alert_id=a.id, correlation_rule="auto")
                session.add(ia)

        session.commit()
        logger.info("seed_data_created", extra={"alerts": len(alerts)})

    finally:
        session.close()


def seed_all():
    init_db()
    seed_admin_user()
    seed_sample_alerts()
    logger.info("seeding_complete")


if __name__ == "__main__":
    seed_all()
