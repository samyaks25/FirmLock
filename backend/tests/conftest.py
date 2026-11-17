"""Shared test configuration and fixtures for FirmLock backend tests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Generator

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.login_protection import get_login_protection
from app.core.rate_limit import get_rate_limiter
from app.database import connection
from app.database.connection import Base, get_db
from app.main import app
from app.services.scanner import scan_manager


def _run_alembic_upgrade(db_url: str) -> None:
    """Run Alembic migrations to bring a test database up to date.

    Creates a temporary alembic.ini configuration pointing to the test database
    and runs 'upgrade head'.
    """
    # Create a temporary alembic config
    alembic_cfg = AlembicConfig("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)

    # Run upgrade head
    command.upgrade(alembic_cfg, "head")


@pytest.fixture(scope="function", autouse=True)
def reset_security_state() -> Generator[None, None, None]:
    """Reset rate limiter and login protection state before each test."""
    rate_limiter = get_rate_limiter()
    login_protection = get_login_protection()

    # Clear all rate limit windows
    rate_limiter._windows.clear()

    # Clear all login attempt tracking
    login_protection._attempts.clear()

    yield

    # Clean up after test
    rate_limiter._windows.clear()
    login_protection._attempts.clear()


@pytest.fixture(scope="function")
def test_db() -> Generator[tuple[Engine, sessionmaker], None, None]:
    """Create a temporary SQLite database for testing with Alembic migrations."""
    tmpdir = tempfile.TemporaryDirectory()
    db_fd, db_path = tempfile.mkstemp(suffix=".db", dir=tmpdir.name)
    os.close(db_fd)
    db_url = f"sqlite:///{Path(db_path).as_posix()}"

    engine = create_engine(db_url, connect_args={"check_same_thread": False}, future=True)

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    # Run Alembic migrations to create schema (instead of Base.metadata.create_all)
    _run_alembic_upgrade(db_url)

    # Override the module-level SessionLocal and engine for background tasks
    original_session_local = connection.SessionLocal
    original_engine = connection.engine
    connection.SessionLocal = TestingSessionLocal
    connection.engine = engine

    # Also override scan_manager's SessionLocal
    original_scan_session_local = scan_manager.SessionLocal
    scan_manager.SessionLocal = TestingSessionLocal

    yield engine, TestingSessionLocal

    # Restore original
    connection.SessionLocal = original_session_local
    connection.engine = original_engine
    scan_manager.SessionLocal = original_scan_session_local
    engine.dispose()
    tmpdir.cleanup()


@pytest.fixture(scope="function")
def db_session(test_db) -> Generator[Session, None, None]:
    """Provide a database session for direct database access in tests."""
    _, TestingSessionLocal = test_db
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def client(test_db, db_session) -> Generator[TestClient, None, None]:
    """Create a TestClient with database dependency override."""
    engine, TestingSessionLocal = test_db

    def override_get_db() -> Generator[Session, None, None]:
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()