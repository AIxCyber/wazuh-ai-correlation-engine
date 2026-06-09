from src.ai.engine import AIAnalysisEngine
from src.ai.providers.rule_based import RuleBasedProvider


def test_rule_based_provider():
    provider = RuleBasedProvider()
    assert provider.name() == "rule"

    incident = {
        "title": "Brute Force Attack",
        "event_types": ["brute_force"],
        "affected_hosts": ["web-01", "web-02"],
        "source_ips": ["203.0.113.5"],
        "affected_users": ["root"],
        "alert_count": 50,
        "severity": "high",
        "mitre_technique_id": "T1110",
    }

    result = provider.analyze(incident)
    assert result is not None
    assert "brute-force" in result.root_cause.lower()
    assert result.confidence > 0
    assert len(result.recommended_actions) > 0
    assert result.severity == "high"


def test_ai_engine_default_provider():
    engine = AIAnalysisEngine()
    assert "rule" in engine.providers
    assert "openai" in engine.providers
    assert "local" in engine.providers


def test_ai_engine_fallback():
    engine = AIAnalysisEngine()
    incident = {
        "title": "Test Incident",
        "event_types": ["malware"],
        "affected_hosts": ["host-01"],
        "source_ips": ["1.2.3.4"],
        "alert_count": 5,
        "severity": "medium",
    }

    # Request non-existent provider should fall back to rule
    result = engine.analyze(incident, provider="non_existent")
    assert result is not None
    assert result.confidence > 0


def test_summarize_alerts():
    provider = RuleBasedProvider()
    summary = provider.summarize_alerts([
        {"event_type": "brute_force", "host": "web-01"},
        {"event_type": "malware", "host": "db-01"},
    ])
    assert "alerts" in summary.lower()
    assert "brute_force" in summary
    assert "malware" in summary


def test_empty_summarize():
    provider = RuleBasedProvider()
    summary = provider.summarize_alerts([])
    assert summary == "No alerts to summarize."


def test_generate_actions_for_brute_force():
    provider = RuleBasedProvider()
    actions = provider._generate_actions(["brute_force"], "medium")
    assert any("Block" in a for a in actions)
    assert any("Reset" in a for a in actions)


def test_generate_actions_for_critical():
    provider = RuleBasedProvider()
    actions = provider._generate_actions(["brute_force"], "critical")
    assert any("ESCALATE" in a for a in actions)
