
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from src.core.config import get_config
from src.core.database import get_session_local
from src.core.logging import get_logger
from src.core.models.orm_models import Webhook, WebhookDeliveryLog

logger = get_logger(__name__)


class WebhookEngine:
    def __init__(self) -> None:
        self.cfg = get_config()

    def dispatch(self, event: str, payload: dict[str, Any]) -> int:
        session = get_session_local()()
        try:
            webhooks = session.query(Webhook).filter(
                Webhook.active.is_(True),
                Webhook.events.contains(event),
            ).all()
        finally:
            session.close()

        delivered = 0
        for wh in webhooks:
            success = self._deliver(wh, event, payload)
            if success:
                delivered += 1

        return delivered

    def _deliver(self, webhook: Webhook, event: str, payload: dict[str, Any]) -> bool:
        body = json.dumps({
            "event": event,
            "timestamp": datetime.now(UTC).isoformat(),
            "webhook_source": self.cfg.app_name,
            **payload,
        })

        headers = {"Content-Type": "application/json"}

        if webhook.secret:
            signature = hmac.new(
                webhook.secret.encode(),
                body.encode(),
                hashlib.sha256,
            ).hexdigest()
            headers["X-Webhook-Signature"] = signature

        attempt = 1
        max_retries = self.cfg.retry_max_attempts

        while attempt <= max_retries:
            try:
                resp = httpx.post(
                    webhook.url,
                    content=body,
                    headers=headers,
                    timeout=self.cfg.retry_base_delay * 2,
                )
                self._log_delivery(webhook.id, event, body, resp.status_code, None, attempt)
                return resp.is_success
            except httpx.HTTPError as e:
                logger.warning(
                    "webhook_delivery_failed",
                    extra={
                        "webhook_id": webhook.id,
                        "url": webhook.url,
                        "attempt": attempt,
                        "error": str(e),
                    },
                )
                if attempt < max_retries:
                    time.sleep(self.cfg.retry_base_delay * attempt)
                attempt += 1

        self._log_delivery(webhook.id, event, body, None, "Max retries exceeded", attempt - 1)
        return False

    def _log_delivery(
        self,
        webhook_id: str,
        event: str,
        payload: str,
        status_code: int | None,
        error: str | None,
        attempt: int,
    ) -> None:
        session = get_session_local()()
        try:
            log = WebhookDeliveryLog(
                webhook_id=webhook_id,
                event=event,
                payload=json.loads(payload),
                status="success" if status_code and 200 <= status_code < 300 else "failed",
                status_code=status_code,
                error=error,
                attempt=attempt,
            )
            session.add(log)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error("webhook_log_failed", extra={"error": str(e)})
        finally:
            session.close()

    def register(self, url: str, events: list[str], secret: str | None = None) -> str:
        session = get_session_local()()
        try:
            wh = Webhook(url=url, events=events, secret=secret, active=True)
            session.add(wh)
            session.commit()
            logger.info("webhook_registered", extra={"webhook_id": wh.id, "url": url})
            return wh.id
        except Exception as e:
            session.rollback()
            logger.error("webhook_register_failed", extra={"error": str(e)})
            raise
        finally:
            session.close()

    def list_webhooks(self) -> list[dict[str, Any]]:
        session = get_session_local()()
        try:
            webhooks = session.query(Webhook).all()
            return [
                {
                    "id": w.id,
                    "url": w.url,
                    "events": w.events,
                    "active": w.active,
                    "created_at": w.created_at.isoformat() if w.created_at else None,
                }
                for w in webhooks
            ]
        finally:
            session.close()

    def delete(self, webhook_id: str) -> bool:
        session = get_session_local()()
        try:
            wh = session.query(Webhook).filter_by(id=webhook_id).first()
            if not wh:
                return False
            session.delete(wh)
            session.commit()
            return True
        except Exception:
            session.rollback()
            return False
        finally:
            session.close()
