import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import httpx
import pytest

from src.ingestion.service import AlertIngestionService
from src.normalization.normalizer import normalize_wazuh_alert
from src.normalization.schema import NormalizedAlert, RawWazuhAlert


def test_normalize_valid_alert(sample_raw_alert):
    raw = RawWazuhAlert(**sample_raw_alert)
    alert = normalize_wazuh_alert(raw)

    assert alert.event_id is not None
    assert alert.timestamp is not None
    assert alert.agent_name == "web-01"
    assert alert.host == "web-01"
    assert alert.rule_id == "5710"
    assert alert.rule_level == 10
    assert alert.rule_description == "SSH Brute Force"
    assert alert.source_ip == "203.0.113.5"
    assert alert.user == "root"
    assert alert.event_type == "authentication"
    assert alert.fingerprint is not None


def test_normalize_missing_fields():
    raw_data = {"id": "test-001"}
    raw = RawWazuhAlert(**raw_data)
    alert = normalize_wazuh_alert(raw)

    assert alert.event_id is not None
    assert alert.event_type == "unknown"
    assert alert.source_ip is None


def test_normalize_with_groups():
    raw = RawWazuhAlert(
        timestamp="2025-01-15T10:00:00Z",
        rule={"id": "550", "level": 12, "description": "Malware", "groups": ["malware", "virus"]},
        agent={"name": "db-01"},
        data={"hostname": "db-01"},
    )
    alert = normalize_wazuh_alert(raw)
    assert alert.event_type == "malware"


def test_ingest_single_alert(db_session):
    service = AlertIngestionService()
    raw = {
        "timestamp": "2025-01-15T10:00:00Z",
        "rule": {"id": "5710", "level": 10, "description": "Test"},
        "agent": {"name": "host-01"},
        "data": {"srcip": "1.2.3.4"},
    }
    alert = service.ingest_single(raw)
    assert alert is not None
    assert alert.source_ip == "1.2.3.4"


def test_ingest_malformed_alert(db_session):
    service = AlertIngestionService()
    raw = {"bad": "data", "rule": ["not", "a", "dict"]}
    alert = service.ingest_single(raw)
    assert alert is None


def test_ingest_from_local_single_file(db_session):
    service = AlertIngestionService()
    alert_data = {
        "timestamp": "2025-01-15T10:00:00Z",
        "rule": {"id": "5710", "level": 10, "description": "Test"},
        "agent": {"name": "host-01"},
        "data": {"srcip": "1.2.3.4"},
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(alert_data, f)
        fpath = f.name

    try:
        result = service.ingest_from_local(file_path=fpath)
        assert len(result) == 1
        assert result[0].source_ip == "1.2.3.4"
    finally:
        os.unlink(fpath)


def test_ingest_from_local_directory(db_session):
    service = AlertIngestionService()
    tmpdir = tempfile.mkdtemp()
    try:
        for i in range(3):
            fpath = os.path.join(tmpdir, f"alert_{i}.json")
            with open(fpath, "w") as f:
                json.dump({
                    "timestamp": "2025-01-15T10:00:00Z",
                    "rule": {"id": str(5710 + i), "level": 10, "description": f"Test {i}"},
                    "agent": {"name": f"host-0{i}"},
                }, f)

        result = service.ingest_from_local(file_path=tmpdir)
        assert len(result) == 3
    finally:
        import shutil
        shutil.rmtree(tmpdir)


def test_ingest_from_local_list_of_alerts(db_session):
    service = AlertIngestionService()
    alerts = [
        {
            "timestamp": "2025-01-15T10:00:00Z",
            "rule": {"id": "5710", "level": 10, "description": "First"},
            "agent": {"name": "host-01"},
        },
        {
            "timestamp": "2025-01-15T10:00:01Z",
            "rule": {"id": "5711", "level": 12, "description": "Second"},
            "agent": {"name": "host-02"},
        },
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(alerts, f)
        fpath = f.name

    try:
        result = service.ingest_from_local(file_path=fpath)
        assert len(result) == 2
    finally:
        os.unlink(fpath)


def test_ingest_from_local_with_dlq_failures(db_session):
    service = AlertIngestionService()
    mixed = [
        {
            "id": "valid-01",
            "timestamp": "2025-01-15T10:00:00Z",
            "rule": {"id": "5710", "level": 10, "description": "Valid"},
            "agent": {"name": "host-01"},
        },
        {"id": "bad-01", "rule": ["not", "a", "dict"]},
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(mixed, f)
        fpath = f.name

    try:
        result = service.ingest_from_local(file_path=fpath)
        assert len(result) == 1
        dlq_items, _ = service.dlq.list_records()
        assert len(dlq_items) >= 1
    finally:
        os.unlink(fpath)


def test_ingest_from_local_invalid_json(db_session):
    service = AlertIngestionService()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("{invalid json")
        fpath = f.name

    try:
        result = service.ingest_from_local(file_path=fpath)
        assert len(result) == 0
    finally:
        os.unlink(fpath)


def test_ingest_from_local_non_json_file_skipped(db_session):
    service = AlertIngestionService()
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "readme.txt"), "w") as f:
            f.write("not json")

        result = service.ingest_from_local(file_path=tmpdir)
        assert len(result) == 0
    finally:
        import shutil
        shutil.rmtree(tmpdir)


@patch("httpx.get")
def test_ingest_from_api_success(mock_get, db_session):
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.json.return_value = {
        "data": [
            {
                "timestamp": "2025-01-15T10:00:00Z",
                "rule": {"id": "5710", "level": 10, "description": "API Alert"},
                "agent": {"name": "api-host"},
            }
        ]
    }
    mock_resp.is_success = True
    mock_get.return_value = mock_resp

    service = AlertIngestionService()
    result = service.ingest_from_api("https://api.example.com/alerts", "test-key-123")
    assert len(result) == 1
    mock_get.assert_called_once()


@patch("httpx.get")
def test_ingest_from_api_list_response(mock_get, db_session):
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.json.return_value = {
        "data": [
            {
                "timestamp": "2025-01-15T10:00:00Z",
                "rule": {"id": "5710", "level": 10, "description": "Direct List"},
                "agent": {"name": "host-01"},
            }
        ]
    }
    mock_resp.is_success = True
    mock_get.return_value = mock_resp

    service = AlertIngestionService()
    result = service.ingest_from_api("https://api.example.com/alerts", "key")
    assert len(result) == 1


@patch("httpx.get")
def test_ingest_from_api_dlq_on_failure(mock_get, db_session):
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.json.return_value = {
        "data": [
            {"id": "bad", "rule": ["not", "a", "dict"]},
        ]
    }
    mock_resp.is_success = True
    mock_get.return_value = mock_resp

    service = AlertIngestionService()
    result = service.ingest_from_api("https://api.example.com/alerts", "key")
    assert len(result) == 0
    dlq_items, _ = service.dlq.list_records()
    assert len(dlq_items) == 1


@patch("httpx.get")
def test_ingest_from_api_http_error(mock_get, db_session):
    from tenacity import RetryError
    mock_get.side_effect = httpx.HTTPError("API down")

    service = AlertIngestionService()
    with pytest.raises(RetryError):
        service.ingest_from_api("https://api.example.com/alerts", "key")


def test_buffer_and_flush(db_session):
    service = AlertIngestionService()
    assert len(service.flush_buffer()) == 0

    alert = NormalizedAlert(
        event_id="test-001",
        timestamp="2025-01-15T10:00:00Z",
        rule_id="5710",
        rule_level=10,
        rule_description="Test",
        source_ip="1.2.3.4",
    )
    service.buffer_alert(alert)
    assert len(service._buffer) == 1

    batch = service.flush_buffer()
    assert len(batch) == 1
    assert len(service._buffer) == 0


def test_buffer_triggers_flush(db_session):
    service = AlertIngestionService()
    service.cfg.batch_size = 2

    for i in range(2):
        alert = NormalizedAlert(
            event_id=f"test-{i:03d}",
            timestamp="2025-01-15T10:00:00Z",
            rule_id="5710",
            rule_level=10,
            rule_description="Test",
        )
        service.buffer_alert(alert)

    assert len(service._buffer) == 0
