
from datetime import UTC, datetime, timedelta

from src.core.config import get_config
from src.core.database import get_session_local
from src.core.logging import get_logger
from src.core.models.orm_models import DedupFingerprint
from src.normalization.schema import NormalizedAlert

logger = get_logger(__name__)


class DeduplicationEngine:
    def __init__(self) -> None:
        self.cfg = get_config()

    def is_duplicate(self, alert: NormalizedAlert) -> bool:
        if not alert.fingerprint:
            return False

        session = get_session_local()()
        try:
            existing = (
                session.query(DedupFingerprint)
                .filter(
                    DedupFingerprint.fingerprint == alert.fingerprint,
                    DedupFingerprint.expires_at > datetime.now(UTC),
                )
                .first()
            )
            return existing is not None
        finally:
            session.close()

    def mark_as_seen(self, alert: NormalizedAlert) -> None:
        if not alert.fingerprint:
            return

        session = get_session_local()()
        try:
            expires_at = datetime.now(UTC) + timedelta(
                minutes=self.cfg.correlation_window_minutes
            )
            record = DedupFingerprint(
                fingerprint=alert.fingerprint,
                alert_id=alert.event_id,
                expires_at=expires_at,
            )
            session.add(record)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error("dedup_mark_failed", extra={"error": str(e)})
        finally:
            session.close()

    def deduplicate(self, alerts: list[NormalizedAlert]) -> list[NormalizedAlert]:
        unique: list[NormalizedAlert] = []
        for alert in alerts:
            if not self.is_duplicate(alert):
                self.mark_as_seen(alert)
                unique.append(alert)

        duplicates = len(alerts) - len(unique)
        if duplicates > 0:
            logger.info(
                "deduplication_removed",
                extra={"total": len(alerts), "unique": len(unique), "duplicates": duplicates},
            )
        return unique
