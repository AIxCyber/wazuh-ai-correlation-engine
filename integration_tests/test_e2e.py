"""Comprehensive end-to-end test covering all API endpoints and edge cases."""
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
from src.core.models.orm_models import Alert, Incident, IncidentAlert, User, Webhook


@pytest.fixture
def fresh_db():
    """Create isolated in-memory DB with rich seed data for each test."""
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
    senior = User(username="senior", hashed_password=hash_password("senior123"), role="senior_analyst", active=True)
    inactive = User(username="disabled", hashed_password=hash_password("disabled123"), role="analyst", active=False)
    session.add_all([admin, analyst, senior, inactive])
    session.commit()

    for i in range(5):
        alert = Alert(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            host=f"host-{i}",
            agent_name="agent-001",
            rule_id=f"57{i}0",
            rule_level=10 + i,
            rule_description=f"Test Rule {i}",
            event_type="brute_force" if i < 3 else "malware",
            source_ip=f"10.0.0.{i}",
            fingerprint=f"fp-{i}",
        )
        session.add(alert)
        session.flush()
        inc = Incident(
            title=f"Incident {i}",
            status="open" if i < 4 else "closed",
            severity="high" if i < 3 else "critical",
            risk_score=75.0 + i * 5,
            alert_count=1,
        )
        session.add(inc)
        session.flush()
        session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
    session.commit()

    # Pre-register a webhook
    wh = Webhook(id=str(uuid.uuid4()), url="https://hooks.example.com/wh", events="incident_created,critical_alert")
    session.add(wh)
    session.commit()
    session.close()

    yield Session, engine

    db_module.engine = old_engine
    db_module.SessionLocal = old_session


class TestEndToEnd:
    """Comprehensive E2E: auth, RBAC, CRUD, DLQ, webhooks, reports, edge cases."""

    def _login(self, client, username="admin", password="admin123"):
        resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
        assert resp.status_code == 200, resp.text
        return resp.json()["access_token"]

    # --- Auth ---
    def test_public_endpoints(self, fresh_db):
        Session, _ = fresh_db
        with TestClient(app) as c:
            assert c.get("/").status_code == 200
            assert c.get("/api/v1/health").status_code == 200
            assert c.get("/api/v1/ready").status_code == 200
            assert c.get("/metrics").status_code == 200

    def test_login_success(self, fresh_db):
        with TestClient(app) as c:
            r = c.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
            assert r.status_code == 200
            data = r.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"

    def test_login_bad_credentials(self, fresh_db):
        with TestClient(app) as c:
            assert c.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401
            assert c.post("/api/v1/auth/login", json={"username": "nobody", "password": "x"}).status_code == 401

    def test_login_inactive_user(self, fresh_db):
        with TestClient(app) as c:
            assert c.post("/api/v1/auth/login", json={"username": "disabled", "password": "disabled123"}).status_code == 401

    def test_auth_refresh(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            r = c.post("/api/v1/auth/refresh", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
            assert "access_token" in r.json()

    # --- RBAC ---
    def test_unauthenticated_blocked(self, fresh_db):
        with TestClient(app) as c:
            assert c.get("/api/v1/incidents").status_code == 401
            assert c.get("/api/v1/alerts").status_code == 401
            assert c.get("/api/v1/admin/stats").status_code == 401

    def test_analyst_blocked_from_admin(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c, "analyst", "analyst123")
            h = {"Authorization": f"Bearer {token}"}
            # Analysts can access /admin/stats (view_dashboard permission)
            assert c.get("/api/v1/admin/stats", headers=h).status_code == 200
            # But still blocked from other admin endpoints
            assert c.get("/api/v1/admin/dlq", headers=h).status_code == 403

    # --- Incidents CRUD ---
    def test_incidents_pagination(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            r = c.get("/api/v1/incidents?page=1&page_size=2", headers=h)
            assert r.status_code == 200
            d = r.json()
            assert len(d["items"]) <= 2
            assert d["page"] == 1
            assert d["total"] == 5

    def test_incidents_filter_by_severity(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            r = c.get("/api/v1/incidents?severity=critical", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
            all_critical = all(i["severity"] == "critical" for i in r.json()["items"])
            assert all_critical

    def test_incident_detail_with_alerts(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            r = c.get("/api/v1/incidents", headers=h)
            iid = r.json()["items"][0]["id"]
            r2 = c.get(f"/api/v1/incidents/{iid}", headers=h)
            assert r2.status_code == 200
            assert "alerts" in r2.json()
            assert len(r2.json()["alerts"]) >= 1

    def test_incident_not_found(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            r = c.get("/api/v1/incidents/nonexistent", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 404

    def test_update_incident_all_fields(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            r = c.get("/api/v1/incidents", headers=h)
            iid = r.json()["items"][0]["id"]
            r2 = c.put(f"/api/v1/incidents/{iid}", headers=h, json={
                "status": "resolved", "risk_score": 95, "severity": "critical", "title": "Updated"
            })
            assert r2.status_code == 200
            d = r2.json()
            assert d["status"] == "resolved"
            assert d["risk_score"] == 95
            assert d["severity"] == "critical"

    def test_delete_incident(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            r = c.get("/api/v1/incidents", headers=h)
            iid = r.json()["items"][0]["id"]
            r2 = c.delete(f"/api/v1/incidents/{iid}", headers=h)
            assert r2.status_code == 200
            assert c.get(f"/api/v1/incidents/{iid}", headers=h).status_code == 404

    def test_delete_nonexistent_incident(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            r = c.delete("/api/v1/incidents/nonexistent", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 404

    # --- Alert CRUD ---
    def test_alerts_pagination(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            r = c.get("/api/v1/alerts?page=1&page_size=3", headers=h)
            assert r.status_code == 200
            d = r.json()
            assert len(d["items"]) <= 3
            assert d["page"] == 1

    def test_alerts_filter_by_event_type(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            r = c.get("/api/v1/alerts?event_type=malware", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
            assert all(a["event_type"] == "malware" for a in r.json()["items"])

    def test_alert_detail(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            r = c.get("/api/v1/alerts", headers=h)
            aid = r.json()["items"][0]["id"]
            r2 = c.get(f"/api/v1/alerts/{aid}", headers=h)
            assert r2.status_code == 200
            assert r2.json()["id"] == aid

    def test_alert_not_found(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            r = c.get("/api/v1/alerts/nonexistent", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 404

    # --- Ingest ---
    def test_ingest_valid(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            payload = [{"timestamp": "2026-01-15T10:00:00Z", "rule": {"id": "999", "level": 5, "description": "Test"},
                        "agent": {"name": "web-01"}, "data": {"srcip": "1.2.3.4"}}]
            r = c.post("/api/v1/alerts/ingest", json=payload, headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
            assert r.json()["ingested"] == 1

    def test_ingest_multiple(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            payload = [
                {"timestamp": "2026-01-15T10:00:00Z", "rule": {"id": "1", "level": 3},
                 "agent": {"name": "h1"}, "data": {"srcip": "1.1.1.1"}},
                {"timestamp": "2026-01-15T10:01:00Z", "rule": {"id": "2", "level": 7},
                 "agent": {"name": "h2"}, "data": {"srcip": "2.2.2.2"}},
            ]
            r = c.post("/api/v1/alerts/ingest", json=payload, headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
            assert r.json()["ingested"] == 2

    # --- Analyze ---
    def test_analyze_incident(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            r = c.get("/api/v1/incidents", headers=h)
            iid = r.json()["items"][0]["id"]
            r2 = c.post("/api/v1/analyze", json={"incident_id": iid}, headers=h)
            assert r2.status_code == 200
            d = r2.json()
            assert d["root_cause"] is not None
            assert d["confidence"] is not None
            assert d["summary"] is not None

    def test_analyze_nonexistent_incident(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            r = c.post("/api/v1/analyze", json={"incident_id": "nonexistent"},
                       headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 404

    # --- Admin Stats & DLQ ---
    def test_admin_stats(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            r = c.get("/api/v1/admin/stats", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
            d = r.json()
            assert d["total_alerts"] >= 5
            assert d["total_incidents"] >= 5
            assert d["open_incidents"] >= 4

    def test_dlq_lifecycle(self, fresh_db):
        """Test DLQ: send bad data to DLQ, list, retry, discard."""
        from src.ingestion.dlq import DeadLetterQueue
        dlq = DeadLetterQueue()
        dlq.add({"event": "bad"}, error="parse error")
        items, total = dlq.list_records()
        dlq_id = items[0]["id"]

        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            r = c.get("/api/v1/admin/dlq", headers=h)
            assert r.status_code == 200
            assert r.json()["total"] >= 1

            r2 = c.post(f"/api/v1/admin/dlq/{dlq_id}/retry", headers=h)
            assert r2.status_code == 200

            r3 = c.post(f"/api/v1/admin/dlq/{dlq_id}/discard", headers=h)
            assert r3.status_code == 200

            r4 = c.post("/api/v1/admin/dlq/retry-all", headers=h)
            assert r4.status_code == 200

    # --- Webhooks ---
    def test_webhook_lifecycle(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            r = c.post("/api/v1/webhooks/configure", json={
                "url": "https://example.com/new-hook",
                "events": ["incident_created"],
                "secret": "abc123",
            }, headers=h)
            assert r.status_code == 200
            wh_id = r.json()["id"]

            r2 = c.get("/api/v1/webhooks", headers=h)
            assert r2.status_code == 200
            assert len(r2.json()["webhooks"]) >= 2  # seeded + new

            r3 = c.delete(f"/api/v1/webhooks/{wh_id}", headers=h)
            assert r3.status_code == 200

            r4 = c.delete("/api/v1/webhooks/nonexistent", headers=h)
            assert r4.status_code == 404

    # --- Reports ---
    def test_report_json_and_html(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            r = c.get("/api/v1/incidents", headers=h)
            iid = r.json()["items"][0]["id"]
            r2 = c.post(f"/api/v1/incidents/{iid}/report?formats=json&formats=html", headers=h)
            assert r2.status_code == 200
            paths = r2.json()["report_paths"]
            assert "json" in paths
            assert "html" in paths

    # --- Forgot Password Flow ---
    def test_forgot_password_onscreen(self, fresh_db):
        with TestClient(app) as c:
            r = c.post("/api/v1/auth/forgot-password", json={"username": "analyst"})
            assert r.status_code == 200
            d = r.json()
            assert d["sent"] is True
            assert d["mode"] == "onscreen"
            assert len(d["token"]) == 8

    def test_forgot_password_nonexistent_user(self, fresh_db):
        with TestClient(app) as c:
            r = c.post("/api/v1/auth/forgot-password", json={"username": "nonexistent"})
            assert r.status_code == 200
            d = r.json()
            assert d["sent"] is False

    def test_reset_with_token(self, fresh_db):
        with TestClient(app) as c:
            r = c.post("/api/v1/auth/forgot-password", json={"username": "analyst"})
            token = r.json()["token"]

            r2 = c.post("/api/v1/auth/reset-with-token", json={"token": token, "new_password": "newpass123"})
            assert r2.status_code == 200
            assert "Password reset" in r2.json()["detail"]

            # Verify can login with new password
            r3 = c.post("/api/v1/auth/login", json={"username": "analyst", "password": "newpass123"})
            assert r3.status_code == 200

    def test_reset_with_invalid_token(self, fresh_db):
        with TestClient(app) as c:
            r = c.post("/api/v1/auth/reset-with-token", json={"token": "badbad", "new_password": "newpass123"})
            assert r.status_code == 400

    # --- User Management CRUD ---
    def test_admin_create_user(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            r = c.post("/api/v1/admin/users", json={"username": "newuser", "password": "newpass123", "role": "analyst"}, headers=h)
            assert r.status_code == 200
            assert r.json()["username"] == "newuser"

    def test_admin_create_duplicate_user(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            r = c.post("/api/v1/admin/users", json={"username": "admin", "password": "x"}, headers=h)
            assert r.status_code == 409

    def test_admin_update_user_role(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            users = c.get("/api/v1/admin/users", headers=h).json()["users"]
            analyst = next(u for u in users if u["username"] == "analyst")
            r = c.put(f"/api/v1/admin/users/{analyst['id']}", json={"role": "senior_analyst"}, headers=h)
            assert r.status_code == 200
            assert r.json()["role"] == "senior_analyst"

    def test_admin_deactivate_user(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            users = c.get("/api/v1/admin/users", headers=h).json()["users"]
            analyst = next(u for u in users if u["username"] == "analyst")
            r = c.put(f"/api/v1/admin/users/{analyst['id']}", json={"active": False}, headers=h)
            assert r.status_code == 200
            assert r.json()["active"] is False

    def test_admin_delete_user(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            # create temp user first
            c.post("/api/v1/admin/users", json={"username": "todelete", "password": "pass123"}, headers=h)
            users = c.get("/api/v1/admin/users", headers=h).json()["users"]
            target = next(u for u in users if u["username"] == "todelete")
            r = c.delete(f"/api/v1/admin/users/{target['id']}", headers=h)
            assert r.status_code == 200
            users_after = c.get("/api/v1/admin/users", headers=h).json()["users"]
            assert all(u["username"] != "todelete" for u in users_after)

    def test_admin_cannot_delete_self(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c)
            h = {"Authorization": f"Bearer {token}"}
            users = c.get("/api/v1/admin/users", headers=h).json()["users"]
            admin_user = next(u for u in users if u["username"] == "admin")
            r = c.delete(f"/api/v1/admin/users/{admin_user['id']}", headers=h)
            assert r.status_code == 400

    def test_analyst_cannot_manage_users(self, fresh_db):
        with TestClient(app) as c:
            token = self._login(c, "analyst", "analyst123")
            h = {"Authorization": f"Bearer {token}"}
            assert c.post("/api/v1/admin/users", json={"username": "x", "password": "x"}, headers=h).status_code == 403
            assert c.get("/api/v1/admin/users", headers=h).status_code == 403

    # --- Edge Cases ---
    def test_expired_token(self, fresh_db):
        with TestClient(app) as c:
            r = c.get("/api/v1/incidents", headers={"Authorization": "Bearer invalidtoken"})
            assert r.status_code == 401

    def test_missing_auth_header(self, fresh_db):
        with TestClient(app) as c:
            assert c.get("/api/v1/incidents").status_code == 401

    def test_head_request_blocked(self, fresh_db):
        """HEAD is not defined on our routes (only GET/POST/PUT/DELETE)."""
        with TestClient(app) as c:
            token = self._login(c)
            r = c.head("/api/v1/incidents", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 405
