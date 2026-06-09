import os
import sys
from pathlib import Path

import pytest

from src.core.database import Base, get_session_local
from src.core.logging import setup_logging

# Import all ORM models so they register with Base.metadata
from src.core.models import orm_models  # noqa: F401

# Ensure tests run from project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))

setup_logging()


@pytest.fixture(autouse=True)
def test_db():
    """Use in-memory SQLite for tests."""
    from sqlalchemy import inspect
    from sqlalchemy.pool import StaticPool

    import src.core.database as db_module
    engine = db_module.create_engine("sqlite://", echo=False, poolclass=StaticPool)

    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def set_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    list(Base.metadata.tables.keys())
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    inspector.get_table_names()

    old_engine = db_module.engine
    old_session = db_module.SessionLocal

    db_module.engine = engine
    db_module.SessionLocal = db_module.sessionmaker(autocommit=False, autoflush=False, bind=engine)

    yield

    Base.metadata.drop_all(bind=engine)
    db_module.engine = old_engine
    db_module.SessionLocal = old_session


@pytest.fixture
def db_session():
    session = get_session_local()()
    yield session
    session.close()


@pytest.fixture
def sample_raw_alert():
    return {
        "timestamp": "2025-01-15T10:30:00Z",
        "rule": {"id": "5710", "level": 10, "description": "SSH Brute Force", "groups": ["ssh", "authentication"]},
        "agent": {"name": "web-01", "id": "001"},
        "data": {"srcip": "203.0.113.5", "user": "root", "hostname": "web-01"},
        "id": "test-alert-001",
    }


@pytest.fixture
def sample_alerts_data():
    return [
        {
            "timestamp": "2025-01-15T10:30:00Z",
            "rule": {"id": "5710", "level": 10, "description": "SSH Brute Force", "groups": ["ssh"]},
            "agent": {"name": "web-01"},
            "data": {"srcip": "203.0.113.5", "user": "root", "hostname": "web-01"},
            "id": "alert-1",
        },
        {
            "timestamp": "2025-01-15T10:31:00Z",
            "rule": {"id": "5710", "level": 10, "description": "SSH Brute Force", "groups": ["ssh"]},
            "agent": {"name": "web-01"},
            "data": {"srcip": "203.0.113.5", "user": "root", "hostname": "web-01"},
            "id": "alert-2",
        },
        {
            "timestamp": "2025-01-15T10:32:00Z",
            "rule": {"id": "550", "level": 12, "description": "Malware", "groups": ["malware"]},
            "agent": {"name": "db-01"},
            "data": {"srcip": "198.51.100.20", "hostname": "db-01"},
            "id": "alert-3",
        },
    ]
