
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from src.core.config import get_config
from src.core.logging import get_logger
from src.core.metrics import incidents_generated
from src.core.models.orm_models import CorrelationRuleStat
from src.normalization.schema import NormalizedAlert

logger = get_logger(__name__)


class CorrelationRule(ABC):
    @abstractmethod
    def get_group_key(self, alert: NormalizedAlert) -> str: ...

    @property
    @abstractmethod
    def name(self) -> str: ...


class TimeBasedRule(CorrelationRule):
    def __init__(self, window_minutes: int | None = None) -> None:
        cfg = get_config()
        self.window_minutes = window_minutes or cfg.correlation_window_minutes

    def get_group_key(self, alert: NormalizedAlert) -> str:
        window_start = alert.timestamp - timedelta(minutes=self.window_minutes)
        return f"time:{window_start.strftime('%Y-%m-%dT%H:%M')}"

    @property
    def name(self) -> str:
        return "time_based"


class AssetBasedRule(CorrelationRule):
    def get_group_key(self, alert: NormalizedAlert) -> str:
        host = alert.host or "unknown"
        return f"asset:{host}"

    @property
    def name(self) -> str:
        return "asset_based"


class UserBasedRule(CorrelationRule):
    def get_group_key(self, alert: NormalizedAlert) -> str:
        user = alert.user or "unknown"
        return f"user:{user}"

    @property
    def name(self) -> str:
        return "user_based"


class NetworkBasedRule(CorrelationRule):
    def get_group_key(self, alert: NormalizedAlert) -> str:
        ip = alert.source_ip or "unknown"
        return f"network:{ip}"

    @property
    def name(self) -> str:
        return "network_based"


class RuleBasedRule(CorrelationRule):
    def get_group_key(self, alert: NormalizedAlert) -> str:
        return f"rule:{alert.event_type}"

    @property
    def name(self) -> str:
        return "rule_based"


class SemanticCorrelationRule(CorrelationRule):
    def __init__(self, threshold: float | None = None) -> None:
        self.cfg = get_config()
        self.threshold = threshold or getattr(self.cfg, "correlation_semantic_threshold", 0.85)
        from src.correlation.embedding import get_embedder
        from src.correlation.vector_store import VectorStore
        self.embedder = get_embedder()
        self.store = VectorStore()
        self.group_map: dict[str, str] = {}

    def get_group_key(self, alert: NormalizedAlert) -> str:
        embedding = self.embedder.encode_alert(alert)
        alert_id = getattr(alert, "event_id", "") or str(id(alert))

        similar = self.store.search(embedding, threshold=self.threshold, k=3)
        if similar:
            sid, _ = similar[0]
            key = self.group_map.get(sid)
            if key:
                self.store.add(alert_id, embedding)
                self.group_map[alert_id] = key
                return key

        key = f"semantic:{alert_id}"
        self.store.add(alert_id, embedding)
        self.group_map[alert_id] = key
        return key

    @property
    def name(self) -> str:
        return "semantic_based"


class CorrelationEngine:
    def __init__(self) -> None:
        self.cfg = get_config()
        self.rules: list[CorrelationRule] = self._load_rules()

    def _load_rules(self) -> list[CorrelationRule]:
        rule_map = {
            "time_based": TimeBasedRule,
            "asset_based": AssetBasedRule,
            "user_based": UserBasedRule,
            "network_based": NetworkBasedRule,
            "rule_based": RuleBasedRule,
            "semantic_based": SemanticCorrelationRule,
        }
        return [
            rule_map[name]()
            for name in self.cfg.correlation_rules
            if name in rule_map
        ]

    def _get_enabled_rules(self) -> list[CorrelationRule]:
        cfg = get_config()
        enabled_names: set[str] = set()
        if hasattr(cfg, "correlation_rules"):
            enabled_names = set(cfg.correlation_rules)
        return [r for r in self.rules if r.name in enabled_names]

    def record_false_positive(self, incident_id: str, db: Session) -> None:
        from src.core.models.orm_models import Incident, IncidentAlert
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return
        rule_names: set[str] = set()
        for ia in incident.alerts:
            if ia.correlation_rule:
                rule_names.add(ia.correlation_rule)
        now = datetime.now()
        for rn in rule_names:
            stat = db.query(CorrelationRuleStat).filter(CorrelationRuleStat.rule_name == rn).first()
            if not stat:
                stat = CorrelationRuleStat(rule_name=rn, weight=1.0)
                db.add(stat)
            stat.false_positive_count = (stat.false_positive_count or 0) + 1
            stat.total_incidents = (stat.total_incidents or 0) + 1
            stat.false_positive_rate = (
                stat.false_positive_count / stat.total_incidents if stat.total_incidents > 0 else 0.0
            )
            stat.last_fp_at = now
            if stat.false_positive_rate > 0.5:
                stat.weight = max(0.1, stat.weight - 0.1)
            logger.info(
                "false_positive_recorded",
                extra={"rule": rn, "rate": stat.false_positive_rate, "weight": stat.weight},
            )
        db.commit()

    def record_incident_generated(self, rule_name: str, db: Session) -> None:
        if not rule_name:
            return
        stat = db.query(CorrelationRuleStat).filter(CorrelationRuleStat.rule_name == rule_name).first()
        if not stat:
            stat = CorrelationRuleStat(rule_name=rule_name)
            db.add(stat)
        stat.total_incidents = (stat.total_incidents or 0) + 1
        db.commit()

    def correlate(self, alerts: list[NormalizedAlert], db: Session | None = None) -> list[dict[str, Any]]:
        if not alerts:
            return []

        enabled = self._get_enabled_rules()
        groups: dict[str, list[NormalizedAlert]] = {}
        for alert in alerts:
            for rule in enabled:
                key = rule.get_group_key(alert)
                if key not in groups:
                    groups[key] = []
                groups[key].append(alert)

        incidents = []
        for key, group_alerts in groups.items():
            if len(group_alerts) < 1:
                continue

            rule_name = key.split(":")[0]
            source_ips = list({a.source_ip for a in group_alerts if a.source_ip})
            hosts = list({a.host for a in group_alerts if a.host})
            users = list({a.user for a in group_alerts if a.user})
            timestamps = [a.timestamp for a in group_alerts]

            incident = {
                "title": f"{rule_name.capitalize()} correlation: {group_alerts[0].event_type}",
                "correlation_rule": rule_name,
                "alert_count": len(group_alerts),
                "alerts": [a.model_dump(exclude={"raw_data"}) for a in group_alerts],
                "alert_ids": [a.event_id for a in group_alerts],
                "source_ips": source_ips,
                "affected_hosts": hosts,
                "affected_users": users,
                "first_alert_at": min(timestamps),
                "last_alert_at": max(timestamps),
                "risk_score": 0.0,
                "severity": "low",
                "status": "open",
                "event_types": list({a.event_type for a in group_alerts}),
            }

            incidents.append(incident)

        incidents_generated.labels(severity="pending").inc(len(incidents))
        logger.info(
            "correlation_complete",
            extra={"alerts": len(alerts), "incidents": len(incidents)},
        )
        return incidents
