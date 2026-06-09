"""Integration tests for API - completely self-contained, no conftest dependency."""
import os
import uuid
from datetime import UTC, datetime

os.environ.setdefault("APP_ENV", "testing")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.api.main import app
from src.api.middleware.auth import hash_password
from src.core import database as db_module
from src.core.models.orm_models import Alert, Incident, IncidentAlert, User


@pytest.fixture(autouse=True)
def api_env():
    """Set up clean in-memory database for each test."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def set_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    db_module.Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    old_engine = db_module.engine
    old_session = db_module.SessionLocal
    db_module.engine = engine
    db_module.SessionLocal = Session

    session = Session()
    admin = User(username="admin", hashed_password=hash_password("admin123"), role="admin", active=True)
    analyst = User(username="analyst", hashed_password=hash_password("analyst123"), role="analyst", active=True)
    session.add_all([admin, analyst])
    session.commit()

    for i in range(3):
        alert = Alert(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            host=f"host-{i}",
            rule_id=f"571{i}",
            rule_level=10,
            event_type="brute_force",
            source_ip=f"10.0.0.{i}",
        )
        session.add(alert)
        session.flush()
        inc = Incident(title=f"Incident {i}", status="open", severity="high", risk_score=75.0, alert_count=1)
        session.add(inc)
        session.flush()
        session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
    session.commit()
    session.close()

    with TestClient(app) as client:
        yield client

    db_module.engine = old_engine
    db_module.SessionLocal = old_session


class TestAPI:
    def test_health(self, api_env):
        resp = api_env.get("/api/v1/health")
        assert resp.status_code == 200

    def test_root(self, api_env):
        resp = api_env.get("/")
        assert resp.status_code == 200

    def test_login_success(self, api_env):
        resp = api_env.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_login_failure(self, api_env):
        resp = api_env.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401

    def test_incidents_unauthenticated(self, api_env):
        resp = api_env.get("/api/v1/incidents")
        assert resp.status_code == 401

    def test_incidents_list(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/incidents", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["total"] >= 3

    def test_incident_detail(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/incidents", headers={"Authorization": f"Bearer {token}"})
        inc_id = resp.json()["items"][0]["id"]
        resp = api_env.get(f"/api/v1/incidents/{inc_id}", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_incident_not_found(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/incidents/nonexistent", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 404

    def test_alerts(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert len(resp.json()["items"]) >= 3

    def test_admin_stats(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/admin/stats", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["total_alerts"] >= 3

    def test_dlq_admin(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/admin/dlq", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_dlq_unauthorized(self, api_env):
        resp = api_env.post("/api/v1/auth/login", json={"username": "analyst", "password": "analyst123"})
        token = resp.json()["access_token"]
        resp = api_env.get("/api/v1/admin/dlq", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_metrics(self, api_env):
        resp = api_env.get("/metrics")
        assert resp.status_code == 200

    def test_analyze(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/incidents", headers={"Authorization": f"Bearer {token}"})
        inc_id = resp.json()["items"][0]["id"]
        resp = api_env.post("/api/v1/analyze", json={"incident_id": inc_id},
                            headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_update_incident(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/incidents", headers={"Authorization": f"Bearer {token}"})
        inc_id = resp.json()["items"][0]["id"]
        resp = api_env.put(f"/api/v1/incidents/{inc_id}", json={"status": "investigating"},
                           headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "investigating"

    def test_ingest(self, api_env):
        token = self._login(api_env)
        payload = [{"timestamp": "2025-01-15T10:00:00Z", "rule": {"id": "999", "level": 5},
                    "agent": {"name": "test"}, "data": {"srcip": "1.2.3.4"}}]
        resp = api_env.post("/api/v1/alerts/ingest", json=payload,
                            headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["ingested"] == 1

    def test_report(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/incidents", headers={"Authorization": f"Bearer {token}"})
        inc_id = resp.json()["items"][0]["id"]
        resp = api_env.post(f"/api/v1/incidents/{inc_id}/report?formats=json&formats=html",
                            headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_webhook_config(self, api_env):
        token = self._login(api_env)
        resp = api_env.post("/api/v1/webhooks/configure",
                            json={"url": "https://example.com/hook", "events": ["incident_created"]},
                            headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_webhooks_list(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/webhooks", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_analyze_alert(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})
        alert_id = resp.json()["items"][0]["id"]
        resp = api_env.post("/api/v1/analyze/alert", json={"alert_id": alert_id},
                            headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        assert "root_cause" in resp.json()

    def test_analyze_alert_not_found(self, api_env):
        token = self._login(api_env)
        resp = api_env.post("/api/v1/analyze/alert", json={"alert_id": "nonexistent"},
                            headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 404

    def test_audit_log(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/admin/audit-log", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        assert "items" in resp.json()

    def test_admin_config(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/admin/config", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json().get("jwt_secret") == "***REDACTED***"

    def test_feedback_create(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/incidents", headers={"Authorization": f"Bearer {token}"})
        inc_id = resp.json()["items"][0]["id"]
        resp = api_env.post(f"/api/v1/incidents/{inc_id}/feedback",
                            json={"action": "note", "reason": "Test note"},
                            headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        assert resp.json()["action"] == "note"

    def test_feedback_list(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/incidents", headers={"Authorization": f"Bearer {token}"})
        inc_id = resp.json()["items"][0]["id"]
        api_env.post(f"/api/v1/incidents/{inc_id}/feedback",
                     json={"action": "note", "reason": "Test"},
                     headers={"Authorization": f"Bearer {token}"})
        resp = api_env.get(f"/api/v1/incidents/{inc_id}/feedback",
                           headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        assert resp.json()["total"] >= 1

    def test_merge_incidents(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/incidents", headers={"Authorization": f"Bearer {token}"})
        items = resp.json()["items"]
        ids = [items[0]["id"], items[1]["id"]]
        resp = api_env.post("/api/v1/incidents/merge",
                            json={"incident_ids": ids, "title": "Merged"},
                            headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        assert resp.json()["merged_incident_id"] == ids[0]

    def test_split_incident(self, api_env):
        token = self._login(api_env)
        resp = api_env.get("/api/v1/incidents", headers={"Authorization": f"Bearer {token}"})
        inc = resp.json()["items"][0]
        inc_resp = api_env.get(f"/api/v1/incidents/{inc['id']}",
                               headers={"Authorization": f"Bearer {token}"})
        inc_data = inc_resp.json()
        alert_ids = [a["id"] for a in inc_data.get("alerts", [])]
        if not alert_ids:
            pytest.skip("No alerts on incident to split")
        resp = api_env.post(f"/api/v1/incidents/{inc['id']}/split",
                            json={"incident_id": inc["id"], "alert_ids": [alert_ids[0]]},
                            headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        assert resp.json()["new_incident_id"] is not None

    def _login(self, client):
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        assert resp.status_code == 200, resp.text
        return resp.json()["access_token"]
