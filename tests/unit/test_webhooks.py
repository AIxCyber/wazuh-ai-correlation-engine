from unittest.mock import MagicMock, patch

import httpx

from src.core.database import get_session_local
from src.core.models.orm_models import Webhook
from src.webhooks.engine import WebhookEngine


def _get_webhook(wh_id: str) -> Webhook:
    session = get_session_local()()
    try:
        return session.query(Webhook).filter_by(id=wh_id).first()
    finally:
        session.close()


def test_webhook_register(db_session):
    engine = WebhookEngine()
    wh_id = engine.register("https://example.com/webhook", ["incident_created"], None)
    assert wh_id is not None


def test_webhook_list(db_session):
    engine = WebhookEngine()
    engine.register("https://example.com/wh1", ["incident_created"], None)
    engine.register("https://example.com/wh2", ["critical_alert"], "secret123")
    webhooks = engine.list_webhooks()
    assert len(webhooks) == 2


def test_webhook_delete(db_session):
    engine = WebhookEngine()
    wh_id = engine.register("https://example.com/wh", ["incident_created"], None)
    result = engine.delete(wh_id)
    assert result is True
    assert len(engine.list_webhooks()) == 0


def test_webhook_delete_nonexistent(db_session):
    engine = WebhookEngine()
    result = engine.delete("nonexistent")
    assert result is False


def test_webhook_dispatch_no_webhooks(db_session):
    engine = WebhookEngine()
    count = engine.dispatch("incident_created", {"test": "data"})
    assert count == 0


def test_webhook_dispatch_success(db_session):
    engine = WebhookEngine()
    wh_id = engine.register("https://example.com/wh", ["incident_created"], "mysecret")

    with patch.object(engine, "_deliver", return_value=True) as mock_deliver:
        count = engine.dispatch("incident_created", {"event_id": "evt-001"})
        assert count == 1
        mock_deliver.assert_called_once()


def test_webhook_dispatch_event_mismatch(db_session):
    engine = WebhookEngine()
    engine.register("https://example.com/wh", ["incident_created"], None)
    count = engine.dispatch("alert_triggered", {"event_id": "evt-002"})
    assert count == 0


def test_webhook_deliver_success(db_session):
    engine = WebhookEngine()
    wh_id = engine.register("https://example.com/wh", ["test_event"], None)
    wh = _get_webhook(wh_id)

    with patch("httpx.post") as mock_post:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.is_success = True
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp
        engine._deliver(wh, "test_event", {"key": "value"})


def test_webhook_deliver_http_error_no_retry_on_500(db_session):
    """500 status does not trigger retry; only httpx.HTTPError does."""
    engine = WebhookEngine()
    wh_id = engine.register("https://example.com/wh", ["test_event"], None)
    wh = _get_webhook(wh_id)

    with patch("httpx.post") as mock_post:
        mock_fail = MagicMock(spec=httpx.Response)
        mock_fail.is_success = False
        mock_fail.status_code = 500
        mock_post.return_value = mock_fail

        result = engine._deliver(wh, "test_event", {"key": "value"})
        assert result is False
        assert mock_post.call_count == 1


def test_webhook_deliver_connection_error_recovers(db_session):
    """httpx.HTTPError triggers retry; subsequent success works."""
    engine = WebhookEngine()
    engine.cfg.retry_max_attempts = 3
    wh_id = engine.register("https://example.com/wh", ["test_event"], None)
    wh = _get_webhook(wh_id)

    with patch("httpx.post") as mock_post:
        err = httpx.HTTPError("Connection reset")
        mock_success = MagicMock(spec=httpx.Response)
        mock_success.is_success = True
        mock_success.status_code = 200
        mock_post.side_effect = [err, mock_success]

        result = engine._deliver(wh, "test_event", {"key": "value"})
        assert result is True
        assert mock_post.call_count == 2


def test_webhook_deliver_connection_error_with_retries(db_session):
    engine = WebhookEngine()
    engine.cfg.retry_max_attempts = 3
    wh_id = engine.register("https://example.com/wh", ["test_event"], None)
    wh = _get_webhook(wh_id)

    with patch("httpx.post") as mock_post:
        mock_post.side_effect = httpx.HTTPError("Connection refused")
        result = engine._deliver(wh, "test_event", {"key": "value"})
        assert result is False
        assert mock_post.call_count == 3


def test_webhook_deliver_with_signature(db_session):
    engine = WebhookEngine()
    wh_id = engine.register("https://example.com/wh", ["test_event"], "signing-secret")
    wh = _get_webhook(wh_id)

    with patch("httpx.post") as mock_post:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.is_success = True
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        result = engine._deliver(wh, "test_event", {"alert": "test"})
        assert result is True

        call_kwargs = mock_post.call_args[1]
        assert "X-Webhook-Signature" in call_kwargs["headers"]
        assert call_kwargs["headers"]["X-Webhook-Signature"] is not None


def test_webhook_log_delivery_error_handling(db_session):
    engine = WebhookEngine()
    wh_id = engine.register("https://example.com/wh", ["test_event"], None)

    with patch("src.webhooks.engine.WebhookDeliveryLog") as mock_log_model:
        mock_log_model.side_effect = Exception("DB error")
        engine._log_delivery(wh_id, "test_event", '{"key":"val"}', 200, None, 1)


def test_webhook_register_exception(db_session):
    engine = WebhookEngine()
    with patch.object(engine, "register", side_effect=Exception("register_fail")):
        try:
            engine.register("https://example.com/wh", ["event"])
            assert False, "Should have raised"
        except Exception:
            pass


def test_webhook_delete_exception(db_session):
    engine = WebhookEngine()
    wh_id = engine.register("https://example.com/wh", ["event"], None)

    with patch("sqlalchemy.orm.Session.delete", side_effect=Exception("del_fail")):
        result = engine.delete(wh_id)
        assert result is False
