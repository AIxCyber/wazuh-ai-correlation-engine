"""Standalone tests for core internals (database engine init, logging formats)."""
import logging
import sys

import pytest


def test_get_engine_initialization():
    """Test get_engine() creates engine when it is None (sqlite path)."""
    from src.core import database as db_module
    from src.core.database import Base

    old_engine = db_module.engine
    old_session = db_module.SessionLocal
    db_module.engine = None
    db_module.SessionLocal = None

    try:
        eng = db_module.get_engine()
        assert eng is not None
        assert "sqlite" in str(eng.url)

        sess_local = db_module.get_session_local()
        assert sess_local is not None

        Base.metadata.create_all(bind=eng)
        from sqlalchemy import inspect as sa_inspect
        inspector = sa_inspect(eng)
        tables = inspector.get_table_names()
        assert "users" in tables

        session = sess_local()
        from sqlalchemy import text
        session.execute(text("SELECT 1"))
        session.close()
    finally:
        db_module.engine = old_engine
        db_module.SessionLocal = old_session


def test_get_db_yields_session():
    """Test get_db generator yields a working session."""
    from src.core.database import get_db

    gen = get_db()
    session = next(gen)
    assert session is not None
    from sqlalchemy import text
    session.execute(text("SELECT 1"))
    with pytest.raises(StopIteration):
        next(gen)
    gen.close()


def test_json_formatter_with_exception():
    """Test JSONFormatter handles an exception record."""
    from src.core.logging import JSONFormatter

    fmt = JSONFormatter()
    record = logging.LogRecord(
        "test", logging.ERROR, "test.py", 42, "msg", (), None,
    )
    output = fmt.format(record)
    assert "test.py" in output or "msg" in output

    # Record with exception info
    try:
        try:
            raise ValueError("test exception")
        except ValueError:
            record.exc_info = sys.exc_info()
            output_with_exc = fmt.format(record)
            assert "exception" in output_with_exc or "test exception" in output_with_exc
    finally:
        record.exc_info = None


def test_text_formatter():
    """Test TextFormatter output."""
    from src.core.logging import TextFormatter

    fmt = TextFormatter()
    record = logging.LogRecord(
        "test", logging.INFO, "test.py", 42, "hello world", (), None,
    )
    output = fmt.format(record)
    assert "hello world" in output
    assert "[" in output


def test_config_get():
    """Test config returns values from env or defaults."""
    from src.core.config import get_config
    cfg = get_config()
    assert cfg.app_name == "wazuh-ai-correlation-engine"
    assert cfg.api_port == 8000
    assert cfg.debug is False
