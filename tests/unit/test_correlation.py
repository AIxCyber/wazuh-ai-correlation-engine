import numpy as np

from src.correlation.embedding import EmbeddingService
from src.correlation.engine import (
    AssetBasedRule,
    CorrelationEngine,
    NetworkBasedRule,
    RuleBasedRule,
    SemanticCorrelationRule,
    TimeBasedRule,
    UserBasedRule,
)
from src.correlation.vector_store import VectorStore
from src.normalization.schema import NormalizedAlert


def test_time_based_rule():
    rule = TimeBasedRule(window_minutes=5)
    alert = NormalizedAlert(timestamp="2025-01-15T10:30:00Z", event_type="test", host="h1")
    key = rule.get_group_key(alert)
    assert key.startswith("time:")
    assert rule.name == "time_based"


def test_asset_based_rule():
    rule = AssetBasedRule()
    alert = NormalizedAlert(timestamp="2025-01-15T10:30:00Z", host="web-01", event_type="test")
    key = rule.get_group_key(alert)
    assert key == "asset:web-01"


def test_user_based_rule():
    rule = UserBasedRule()
    alert = NormalizedAlert(timestamp="2025-01-15T10:30:00Z", user="root", event_type="test")
    key = rule.get_group_key(alert)
    assert key == "user:root"


def test_user_based_rule_unknown():
    rule = UserBasedRule()
    alert = NormalizedAlert(timestamp="2025-01-15T10:30:00Z", event_type="test")
    key = rule.get_group_key(alert)
    assert key == "user:unknown"


def test_network_based_rule():
    rule = NetworkBasedRule()
    alert = NormalizedAlert(
        timestamp="2025-01-15T10:30:00Z",
        source_ip="203.0.113.5",
        event_type="test",
    )
    key = rule.get_group_key(alert)
    assert key == "network:203.0.113.5"


def test_rule_based_rule():
    rule = RuleBasedRule()
    alert = NormalizedAlert(timestamp="2025-01-15T10:30:00Z", event_type="brute_force")
    key = rule.get_group_key(alert)
    assert key == "rule:brute_force"


def test_correlation_engine():
    engine = CorrelationEngine()
    assert len(engine.rules) > 0

    alerts = [
        NormalizedAlert(timestamp="2025-01-15T10:30:00Z", host="web-01", source_ip="1.2.3.4", event_type="brute_force", user="root"),
        NormalizedAlert(timestamp="2025-01-15T10:31:00Z", host="web-01", source_ip="1.2.3.4", event_type="brute_force", user="root"),
        NormalizedAlert(timestamp="2025-01-15T10:32:00Z", host="db-01", source_ip="5.6.7.8", event_type="malware"),
    ]

    incidents = engine.correlate(alerts)
    assert len(incidents) > 0
    assert all(isinstance(i, dict) for i in incidents)


def test_correlation_empty_alerts():
    engine = CorrelationEngine()
    incidents = engine.correlate([])
    assert incidents == []


def test_vector_store_add_and_search():
    store = VectorStore()
    e1 = np.array([1.0, 0.0, 0.0], dtype=np.float32)
    e2 = np.array([0.9, 0.1, 0.0], dtype=np.float32)
    e3 = np.array([0.0, 1.0, 0.0], dtype=np.float32)

    store.add("a", e1)
    store.add("b", e2)
    store.add("c", e3)
    assert store.size == 3

    results = store.search(np.array([0.95, 0.05, 0.0], dtype=np.float32), threshold=0.8)
    assert len(results) >= 2
    assert results[0][0] == "a"
    assert results[0][1] >= 0.8


def test_vector_store_remove_expired():
    store = VectorStore()
    store.add("a", np.array([1.0, 0.0, 0.0], dtype=np.float32))
    import time
    store._timestamps["a"] = time.time() - 9999
    removed = store.remove_expired(window_seconds=3600)
    assert removed == 1
    assert store.size == 0


def test_vector_store_empty_search():
    store = VectorStore()
    results = store.search(np.array([1.0, 0.0, 0.0], dtype=np.float32), threshold=0.8)
    assert results == []


def test_vector_store_clear():
    store = VectorStore()
    store.add("a", np.array([1.0, 0.0, 0.0], dtype=np.float32))
    store.clear()
    assert store.size == 0


def test_vector_store_get():
    store = VectorStore()
    store.add("a", np.array([1.0, 0.0, 0.0], dtype=np.float32))
    assert store.get("a") is not None
    assert store.get("nonexistent") is None


def test_vector_store_remove():
    store = VectorStore()
    store.add("a", np.array([1.0, 0.0, 0.0], dtype=np.float32))
    store.remove("a")
    assert store.size == 0


def test_embedding_fallback_encode():
    es = EmbeddingService()
    vec = es.encode("test alert")
    assert vec.shape == (384,)
    norm = np.linalg.norm(vec)
    assert abs(norm - 1.0) < 1e-5


def test_embedding_deterministic():
    es = EmbeddingService()
    v1 = es.encode("brute force from 10.0.0.1")
    v2 = es.encode("brute force from 10.0.0.1")
    assert np.allclose(v1, v2)


def test_embedding_different_texts_differ():
    es = EmbeddingService()
    v1 = es.encode("SSH brute force attack")
    v2 = es.encode("malware detected on server")
    sim = v1 @ v2
    assert sim < 0.99


def test_embedding_encode_alert():
    es = EmbeddingService()
    alert = NormalizedAlert(
        timestamp="2025-01-01T00:00:00Z", agent_name="a", host="srv1",
        rule_id="1", rule_level=5, rule_description="SSH brute force",
        source_ip="10.0.0.1", event_type="brute_force", raw_data={},
    )
    vec = es.encode_alert(alert)
    assert vec.shape == (384,)
    assert abs(np.linalg.norm(vec) - 1.0) < 1e-5


def test_embedding_encode_alert_dict():
    es = EmbeddingService()
    alert = {
        "rule_description": "SSH brute force",
        "event_type": "brute_force",
        "source_ip": "10.0.0.1",
        "host": "srv1",
    }
    vec = es.encode_alert(alert)
    assert vec.shape == (384,)


def test_semantic_correlation_rule_similar_alerts():
    rule = SemanticCorrelationRule(threshold=0.5)
    a1 = NormalizedAlert(
        timestamp="2025-01-01T00:00:00Z", agent_name="a", host="srv1",
        rule_id="1", rule_level=5, rule_description="SSH brute force on srv1",
        source_ip="10.0.0.1", event_type="brute_force", raw_data={},
    )
    a2 = NormalizedAlert(
        timestamp="2025-01-01T00:01:00Z", agent_name="a", host="srv1",
        rule_id="1", rule_level=5, rule_description="SSH brute force on srv1",
        source_ip="10.0.0.1", event_type="brute_force", raw_data={},
    )

    k1 = rule.get_group_key(a1)
    k2 = rule.get_group_key(a2)
    assert k1 == k2, "Similar alerts should share a group key"
    assert rule.name == "semantic_based"


def test_semantic_correlation_rule_different_alerts():
    rule = SemanticCorrelationRule(threshold=0.99)
    a1 = NormalizedAlert(
        timestamp="2025-01-01T00:00:00Z", agent_name="a", host="srv1",
        rule_id="1", rule_level=5, rule_description="SSH brute force",
        source_ip="10.0.0.1", event_type="brute_force", raw_data={},
    )
    a2 = NormalizedAlert(
        timestamp="2025-01-01T00:01:00Z", agent_name="b", host="srv2",
        rule_id="2", rule_level=3, rule_description="USB device inserted",
        source_ip="", event_type="unknown", raw_data={},
    )

    k1 = rule.get_group_key(a1)
    k2 = rule.get_group_key(a2)
    assert k1 != k2, "Different alerts should get different group keys"


def test_correlation_engine_includes_semantic():
    engine = CorrelationEngine()
    names = [r.name for r in engine.rules]
    assert "semantic_based" in names
