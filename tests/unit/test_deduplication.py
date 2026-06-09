from src.deduplication.engine import DeduplicationEngine
from src.normalization.schema import NormalizedAlert


def test_deduplication_is_not_duplicate(db_session):
    engine = DeduplicationEngine()
    alert = NormalizedAlert(
        timestamp="2025-01-15T10:30:00Z",
        host="web-01",
        source_ip="1.2.3.4",
        rule_id="5710",
        event_type="brute_force",
    )
    assert not engine.is_duplicate(alert)


def test_deduplication_mark_and_check(db_session):
    engine = DeduplicationEngine()
    alert = NormalizedAlert(
        timestamp="2025-01-15T10:30:00Z",
        host="web-01",
        source_ip="1.2.3.4",
        rule_id="5710",
        event_type="brute_force",
    )
    engine.mark_as_seen(alert)
    assert engine.is_duplicate(alert)


def test_deduplication_engine_removes_duplicates(db_session):
    engine = DeduplicationEngine()
    alert1 = NormalizedAlert(
        timestamp="2025-01-15T10:30:00Z",
        host="web-01",
        source_ip="1.2.3.4",
        rule_id="5710",
        event_type="brute_force",
    )
    alert2 = NormalizedAlert(
        timestamp="2025-01-15T10:31:00Z",
        host="web-01",
        source_ip="1.2.3.4",
        rule_id="5710",
        event_type="brute_force",
    )

    result = engine.deduplicate([alert1, alert2])
    assert len(result) == 1


def test_deduplication_unique_alerts(db_session):
    engine = DeduplicationEngine()
    alert1 = NormalizedAlert(
        timestamp="2025-01-15T10:30:00Z",
        host="web-01",
        source_ip="1.2.3.4",
        rule_id="5710",
        event_type="brute_force",
    )
    alert2 = NormalizedAlert(
        timestamp="2025-01-15T10:31:00Z",
        host="db-01",
        source_ip="5.6.7.8",
        rule_id="550",
        event_type="malware",
    )
    result = engine.deduplicate([alert1, alert2])
    assert len(result) == 2
