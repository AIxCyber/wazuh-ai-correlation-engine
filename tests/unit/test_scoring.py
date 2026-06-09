from src.scoring.engine import RiskScoringEngine


def test_scoring_low():
    engine = RiskScoringEngine()
    incident = {
        "alerts": [{"rule_level": 1}],
        "affected_hosts": ["host-01"],
        "affected_users": ["user-01"],
        "alert_count": 1,
    }
    result = engine.score_incident(incident)
    assert result["risk_score"] <= 30
    assert result["severity"] == "low"


def test_scoring_critical():
    engine = RiskScoringEngine()
    incident = {
        "alerts": [{"rule_level": 15}],
        "affected_hosts": ["db-01"],
        "affected_users": ["root"],
        "alert_count": 50,
        "threat_intel_hit": True,
    }
    # Add threat intel data
    result = engine.score_incident(incident)
    assert result["risk_score"] >= 50
    assert result["severity"] in ("high", "critical")


def test_scoring_breakdown():
    engine = RiskScoringEngine()
    incident = {
        "alerts": [{"rule_level": 10}],
        "affected_hosts": ["db-01"],
        "affected_users": ["admin"],
        "alert_count": 15,
    }
    result = engine.score_incident(incident)
    assert "score_breakdown" in result
    breakdown = result["score_breakdown"]
    assert "rule_severity" in breakdown
    assert "repeat_activity" in breakdown
    assert "privileged_account" in breakdown


def test_severity_mapping():
    engine = RiskScoringEngine()
    assert engine._score_to_severity(10) == "low"
    assert engine._score_to_severity(45) == "medium"
    assert engine._score_to_severity(70) == "high"
    assert engine._score_to_severity(90) == "critical"
