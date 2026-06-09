
from collections.abc import Generator
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from src.core.config import get_config


class Base(DeclarativeBase):
    pass


engine = None
SessionLocal = None


def get_engine():
    global engine
    if engine is None:
        cfg = get_config()
        engine = create_engine(
            cfg.database_url,
            echo=cfg.debug,
            pool_size=cfg.database_pool_size,
            max_overflow=cfg.database_max_overflow,
        )

        if "sqlite" in cfg.database_url:

            @event.listens_for(engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

    return engine


def get_session_local():
    global SessionLocal
    if SessionLocal is None:
        eng = get_engine()
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=eng)
    return SessionLocal


def init_db() -> None:
    Base.metadata.create_all(bind=get_engine())


def get_db() -> Generator[Session, Any, None]:
    session = get_session_local()()
    try:
        yield session
    finally:
        session.close()
