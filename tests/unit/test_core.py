from src.core.config import get_config
from src.core.database import Base, get_session_local, init_db
from src.core.logging import get_logger, setup_logging


def test_config_loads():
    cfg = get_config()
    assert cfg.app_name == "wazuh-ai-correlation-engine"
    assert cfg.log_level in ("INFO", "DEBUG", "WARNING", "ERROR")
    assert cfg.api_port == 8000


def test_config_values():
    cfg = get_config()
    assert cfg.correlation_window_minutes == 5
    assert cfg.jwt_expire_minutes == 60
    assert cfg.rate_limit_per_minute == 100
    assert cfg.ai_mode in ("rule", "openai", "local")


def test_logging_setup():
    setup_logging()
    logger = get_logger("test")
    assert logger is not None
    assert logger.name == "test"


def test_init_db_creates_tables():
    # Already called by conftest, just verify it doesn't crash
    init_db()


def test_get_session_local():
    session = get_session_local()()
    assert session is not None
    session.close()


def test_base_metadata():
    assert len(Base.metadata.tables) > 0
    assert "alerts" in Base.metadata.tables
    assert "incidents" in Base.metadata.tables
    assert "users" in Base.metadata.tables
    assert "dead_letter_queue" in Base.metadata.tables
    assert "webhooks" in Base.metadata.tables
