
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from src.core.logging import get_logger
from src.core.models.orm_models import Incident

logger = get_logger(__name__)

# Scoring factor weights
RULE_SEVERITY_WEIGHT = 25
CRITICAL_ASSET_WEIGHT = 20
THREAT_INTEL_WEIGHT = 20
REPEAT_ACTIVITY_WEIGHT = 15
MULTIPLE_HOSTS_WEIGHT = 10
PRIVILEGED_ACCOUNT_WEIGHT = 10

CRITICAL_ASSETS = {"domain-controller", "db-", "mail-", "vpn", "firewall", "cloud-admin"}


class RiskScoringEngine:
    def get_historical_baseline(self, db: Session, days: int = 30) -> dict[str, Any]:
        cutoff = datetime.now() - timedelta(days=days)
        stats = db.query(
            func.avg(Incident.risk_score).label("mean_score"),
            func.stddev(Incident.risk_score).label("stddev_score"),
            func.min(Incident.risk_score).label("min_score"),
            func.max(Incident.risk_score).label("max_score"),
            func.count(Incident.id).label("total_incidents"),
        ).filter(
            Incident.created_at >= cutoff,
            Incident.risk_score.isnot(None),
        ).first()

        result = {
            "period_days": days,
            "total_incidents": stats.total_incidents or 0,
            "mean_score": round(float(stats.mean_score or 0), 2),
            "stddev_score": round(float(stats.stddev_score or 0), 2),
            "min_score": round(float(stats.min_score or 0), 2),
            "max_score": round(float(stats.max_score or 0), 2),
        }

        result["score_distribution"] = {
            "low": db.query(Incident).filter(
                Incident.created_at >= cutoff, Incident.severity == "low"
            ).count(),
            "medium": db.query(Incident).filter(
                Incident.created_at >= cutoff, Incident.severity == "medium"
            ).count(),
            "high": db.query(Incident).filter(
                Incident.created_at >= cutoff, Incident.severity == "high"
            ).count(),
            "critical": db.query(Incident).filter(
                Incident.created_at >= cutoff, Incident.severity == "critical"
            ).count(),
        }
        return result

    def normalize_score(self, score: float, baseline: dict[str, Any] | None = None) -> float:
        if not baseline or baseline["total_incidents"] < 10:
            return score
        mean = baseline["mean_score"]
        stddev = baseline["stddev_score"]
        if stddev < 1:
            return score
        z_score = (score - mean) / stddev
        if z_score > 2.0:
            factor = 1.0 + min((z_score - 2.0) * 0.1, 0.3)
            score = min(score * factor, 100.0)
        elif z_score < -1.5:
            score = max(score * 0.9, 0)
        return round(score, 1)

    def score_incident(self, incident: dict[str, Any], db: Session | None = None) -> dict[str, Any]:
        score = 0.0
        breakdown = {}

        # 1. Rule Severity (0-25)
        rule_scores = []
        for alert in incident.get("alerts", []):
            rule_level = alert.get("rule_level", 0) if isinstance(alert, dict) else alert.rule_level
            rule_scores.append(min(rule_level / 15.0, 1.0) * RULE_SEVERITY_WEIGHT)
        rule_severity_score = max(rule_scores) if rule_scores else 0
        score += rule_severity_score
        breakdown["rule_severity"] = {"score": rule_severity_score, "max": RULE_SEVERITY_WEIGHT}

        # 2. Critical Asset (0-20)
        hosts = incident.get("affected_hosts", [])
        critical_hits = [h for h in hosts if any(c in str(h).lower() for c in CRITICAL_ASSETS)]
        critical_score = (CRITICAL_ASSET_WEIGHT if critical_hits else 0)
        score += critical_score
        breakdown["critical_asset"] = {"score": critical_score, "max": CRITICAL_ASSET_WEIGHT, "hits": critical_hits}

        # 3. Threat Intel Hit (0-20)
        threat_hit = incident.get("threat_intel_hit", False)
        if isinstance(incident.get("threat_intel"), dict):
            for ip_data in incident["threat_intel"].values():
                if ip_data.get("reputation") == "malicious":
                    threat_hit = True
                    break
        threat_score = THREAT_INTEL_WEIGHT if threat_hit else 0
        score += threat_score
        breakdown["threat_intel"] = {"score": threat_score, "max": THREAT_INTEL_WEIGHT}

        # 4. Repeat Activity (0-15)
        alert_count = incident.get("alert_count", len(incident.get("alerts", [])))
        repeat_score = min(alert_count / 10.0, 1.0) * REPEAT_ACTIVITY_WEIGHT
        score += repeat_score
        breakdown["repeat_activity"] = {"score": repeat_score, "max": REPEAT_ACTIVITY_WEIGHT, "alert_count": alert_count}

        # 5. Multiple Hosts (0-10)
        unique_hosts = len(set(hosts))
        multi_host_score = min(unique_hosts / 3.0, 1.0) * MULTIPLE_HOSTS_WEIGHT
        score += multi_host_score
        breakdown["multiple_hosts"] = {"score": multi_host_score, "max": MULTIPLE_HOSTS_WEIGHT, "host_count": unique_hosts}

        # 6. Privileged Account (0-10)
        users = incident.get("affected_users", [])
        privileged_users = [u for u in users if str(u).lower() in ("root", "admin", "administrator", "supervisor")]
        priv_score = PRIVILEGED_ACCOUNT_WEIGHT if privileged_users else 0
        score += priv_score
        breakdown["privileged_account"] = {"score": priv_score, "max": PRIVILEGED_ACCOUNT_WEIGHT, "users": privileged_users}

        score = min(score, 100.0)

        if db is not None:
            baseline = self.get_historical_baseline(db, days=30)
            normalized = self.normalize_score(score, baseline)
            if normalized != score:
                logger.info(
                    "score_normalized",
                    extra={"original": round(score, 1), "normalized": normalized, "mean": baseline.get("mean_score")},
                )
                score = normalized

        severity = self._score_to_severity(score)
        incident["risk_score"] = round(score, 1)
        incident["severity"] = severity
        incident["score_breakdown"] = breakdown

        logger.info(
            "incident_scored",
            extra={
                "score": score,
                "severity": severity,
                "alert_count": alert_count,
                "hosts": unique_hosts,
            },
        )
        return incident

    def _score_to_severity(self, score: float) -> str:
        if score >= 81:
            return "critical"
        if score >= 61:
            return "high"
        if score >= 31:
            return "medium"
        return "low"
