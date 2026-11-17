"""SQLAlchemy database configuration and session management for FirmLock.

This module provides:
- SQLAlchemy engine configuration (SQLite).
- Declarative Base for ORM models.
- SessionLocal factory.
- FastAPI database session dependency.
- Database initialization helper.

create_all() is used as an initial development approach for this MVP. A proper
migration tool (e.g. Alembic) will be required before production deployment.
"""

from __future__ import annotations

from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    """Declarative base class for all ORM models."""


def _build_engine(database_url: str) -> Engine:
    """Create a SQLAlchemy engine for the configured database."""
    connect_args: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        # Required for SQLite when the same connection may be used across threads.
        connect_args["check_same_thread"] = False
    return create_engine(database_url, connect_args=connect_args, future=True)


engine = _build_engine(settings.database_url)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection: object, _connection_record: object) -> None:
    """Enforce foreign key constraints for SQLite connections."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create database tables for the current metadata.

    For the MVP this uses SQLAlchemy's create_all. This is convenient for
    initial development but does not handle schema evolution; migrations
    (Alembic) will be needed before production deployment.
    """
    # Import models so their metadata is registered on Base before create_all.
    import app.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
