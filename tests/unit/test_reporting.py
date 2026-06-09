import os
import tempfile

from src.reporting.engine import ReportingEngine


def test_generate_json_report():
    engine = ReportingEngine()
    engine.output_dir = tempfile.mkdtemp()
    incident = {
        "id": "test-001",
        "title": "Test Incident",
        "severity": "high",
        "risk_score": 75.0,
        "status": "open",
        "alert_count": 5,
        "affected_hosts": ["web-01"],
        "source_ips": ["1.2.3.4"],
        "affected_users": ["root"],
        "ai_summary": "Test summary",
        "root_cause": "Test root cause",
        "ai_confidence": 0.85,
        "recommended_actions": ["Block IP", "Reset credentials"],
        "mitre_mapping": [{"technique_id": "T1110", "technique": "Brute Force", "tactic": "Credential Access"}],
        "score_breakdown": {"rule_severity": {"score": 20, "max": 25}},
        "alerts": [{"timestamp": "2025-01-15T10:00:00Z", "event_type": "brute_force", "host": "web-01", "rule_id": "5710"}],
    }
    path = engine.generate_json(incident)
    assert os.path.exists(path)
    assert "test-001" in path
    os.unlink(path)


def test_generate_html_report():
    engine = ReportingEngine()
    engine.output_dir = tempfile.mkdtemp()
    incident = {
        "id": "test-002",
        "title": "HTML Test",
        "severity": "low",
        "risk_score": 25.0,
        "status": "open",
        "alert_count": 1,
        "affected_hosts": ["h1"],
        "source_ips": [],
        "affected_users": [],
    }
    path = engine.generate_html(incident)
    assert os.path.exists(path)
    assert path.endswith(".html")
    content = open(path).read()
    assert "HTML Test" in content
    assert "Incident Report" in content
    os.unlink(path)


def test_generate_report_json_and_html():
    engine = ReportingEngine()
    engine.output_dir = tempfile.mkdtemp()
    incident = {
        "id": "test-003",
        "title": "Combined Test",
        "severity": "medium",
        "risk_score": 50.0,
        "status": "open",
        "alert_count": 3,
        "affected_hosts": ["h1", "h2"],
        "source_ips": ["1.1.1.1"],
        "affected_users": ["user1"],
    }
    results = engine.generate_report(incident, formats=["json", "html"])
    assert "json" in results
    assert "html" in results
    assert os.path.exists(results["json"])
    assert os.path.exists(results["html"])
    os.unlink(results["json"])
    os.unlink(results["html"])
