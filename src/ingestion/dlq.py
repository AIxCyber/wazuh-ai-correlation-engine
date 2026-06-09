
import uuid
from datetime import UTC, datetime
from typing import Any

from src.core.config import get_config
from src.core.database import get_session_local
from src.core.logging import get_logger
from src.core.metrics import dlq_size
from src.core.models.orm_models import DeadLetterRecord

logger = get_logger(__name__)


class DeadLetterQueue:
    def __init__(self) -> None:
        self.cfg = get_config()

    def add(
        self,
        original_payload: dict[str, Any],
        error: str,
        error_type: str = "unknown",
        source: str = "ingestion_service",
    ) -> str:
        record_id = str(uuid.uuid4())
        session = get_session_local()()
        try:
            record = DeadLetterRecord(
                id=record_id,
                original_payload=original_payload,
                error=error,
                error_type=error_type,
                source=source,
                status="pending",
            )
            session.add(record)
            session.commit()
            self._update_metrics()
            logger.warning(
                "dlq_record_added",
                extra={"dlq_id": record_id, "error": error, "source": source},
            )
        except Exception as e:
            session.rollback()
            logger.error("dlq_write_failed", extra={"error": str(e)})
        finally:
            session.close()

        return record_id

    def list_records(
        self,
        status: str | None = None,
        source: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[dict[str, Any]], int]:
        session = get_session_local()()
        try:
            query = session.query(DeadLetterRecord)
            if status:
                query = query.filter(DeadLetterRecord.status == status)
            if source:
                query = query.filter(DeadLetterRecord.source == source)

            total = query.count()
            records = (
                query.order_by(DeadLetterRecord.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )

            result = []
            for r in records:
                result.append({
                    "id": r.id,
                    "error": r.error,
                    "error_type": r.error_type,
                    "source": r.source,
                    "retry_count": r.retry_count,
                    "status": r.status,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "last_retry_at": r.last_retry_at.isoformat() if r.last_retry_at else None,
                })

            return result, total
        finally:
            session.close()

    def retry(self, record_id: str) -> bool:
        session = get_session_local()()
        try:
            record = session.query(DeadLetterRecord).filter_by(id=record_id).first()
            if not record:
                return False

            record.retry_count += 1
            record.last_retry_at = datetime.now(UTC)
            record.status = "retried"
            session.commit()
            self._update_metrics()
            logger.info("dlq_retried", extra={"dlq_id": record_id})
            return True
        except Exception as e:
            session.rollback()
            logger.error("dlq_retry_failed", extra={"dlq_id": record_id, "error": str(e)})
            return False
        finally:
            session.close()

    def discard(self, record_id: str) -> bool:
        session = get_session_local()()
        try:
            record = session.query(DeadLetterRecord).filter_by(id=record_id).first()
            if not record:
                return False

            record.status = "discarded"
            session.commit()
            self._update_metrics()
            logger.info("dlq_discarded", extra={"dlq_id": record_id})
            return True
        except Exception:
            session.rollback()
            return False
        finally:
            session.close()

    def retry_all_pending(self) -> int:
        session = get_session_local()()
        try:
            records = session.query(DeadLetterRecord).filter_by(status="pending").all()
            count = len(records)
            now = datetime.now(UTC)
            for record in records:
                record.retry_count += 1
                record.last_retry_at = now
                record.status = "retried"
            session.commit()
            self._update_metrics()
            logger.info("dlq_retried_all", extra={"count": count})
            return count
        finally:
            session.close()

    def get_record(self, record_id: str) -> dict[str, Any] | None:
        session = get_session_local()()
        try:
            record = session.query(DeadLetterRecord).filter_by(id=record_id).first()
            if not record:
                return None
            return {
                "id": record.id,
                "original_payload": record.original_payload,
                "error": record.error,
                "error_type": record.error_type,
                "source": record.source,
                "retry_count": record.retry_count,
                "status": record.status,
                "created_at": record.created_at.isoformat() if record.created_at else None,
                "last_retry_at": record.last_retry_at.isoformat() if record.last_retry_at else None,
            }
        finally:
            session.close()

    def _update_metrics(self) -> None:
        session = get_session_local()()
        try:
            count = session.query(DeadLetterRecord).filter_by(status="pending").count()
            dlq_size.set(count)
        finally:
            session.close()
