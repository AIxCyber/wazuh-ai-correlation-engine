import json
import os
import tempfile

from src.ingestion.dlq import DeadLetterQueue
from src.ingestion.service import AlertIngestionService


def test_ingest_from_local_file(db_session):
    service = AlertIngestionService()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump([
            {"timestamp": "2025-01-15T10:00:00Z", "rule": {"id": "5710", "level": 10}, "agent": {"name": "h1"}, "data": {"srcip": "1.2.3.4"}},
        ], f)
        fpath = f.name

    try:
        alerts = service.ingest_from_local(fpath)
        assert len(alerts) == 1
        assert alerts[0].source_ip == "1.2.3.4"
    finally:
        os.unlink(fpath)


def test_ingest_malformed_file(db_session):
    service = AlertIngestionService()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("not valid json")
        fpath = f.name

    try:
        alerts = service.ingest_from_local(fpath)
        assert alerts == []
    finally:
        os.unlink(fpath)


def test_dlq_add_and_list(db_session):
    dlq = DeadLetterQueue()
    dlq_id = dlq.add({"test": "data"}, "Test error", "ValueError", "test")
    assert dlq_id is not None

    records, total = dlq.list_records()
    assert total == 1
    assert records[0]["error"] == "Test error"
    assert records[0]["status"] == "pending"


def test_dlq_retry(db_session):
    dlq = DeadLetterQueue()
    dlq_id = dlq.add({"test": "data"}, "Test error", "ValueError", "test")
    result = dlq.retry(dlq_id)
    assert result is True


def test_dlq_discard(db_session):
    dlq = DeadLetterQueue()
    dlq_id = dlq.add({"test": "data"}, "Test error", "ValueError", "test")
    result = dlq.discard(dlq_id)
    assert result is True


def test_dlq_get_record(db_session):
    dlq = DeadLetterQueue()
    dlq_id = dlq.add({"test": "data"}, "Test error", "ValueError", "test")
    record = dlq.get_record(dlq_id)
    assert record is not None
    assert record["error"] == "Test error"


def test_dlq_retry_all(db_session):
    dlq = DeadLetterQueue()
    dlq.add({"a": 1}, "err1", "E1", "test")
    dlq.add({"b": 2}, "err2", "E2", "test")
    count = dlq.retry_all_pending()
    assert count == 2


def test_dlq_get_nonexistent(db_session):
    dlq = DeadLetterQueue()
    record = dlq.get_record("nonexistent")
    assert record is None


def test_dlq_retry_nonexistent(db_session):
    dlq = DeadLetterQueue()
    result = dlq.retry("nonexistent")
    assert result is False


def test_dlq_discard_nonexistent(db_session):
    dlq = DeadLetterQueue()
    result = dlq.discard("nonexistent")
    assert result is False


def test_dlq_filter_by_status(db_session):
    dlq = DeadLetterQueue()
    dlq.add({"a": 1}, "err1", "E1", "test")
    id2 = dlq.add({"b": 2}, "err2", "E2", "test")
    dlq.discard(id2)

    pending, total_p = dlq.list_records(status="pending")
    assert total_p == 1

    discarded, total_d = dlq.list_records(status="discarded")
    assert total_d == 1
