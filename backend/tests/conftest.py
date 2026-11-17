"""Shared test configuration and fixtures for FirmLock backend tests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Generator
from unittest import mock

# Tests run in inline mode by default to avoid requiring Redis/Celery/worker.
os.environ.setdefault("FIRMLOCK_SCAN_EXECUTION_MODE", "inline")

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.login_protection import get_login_protection
from app.core.rate_limit import get_rate_limiter
from app.database import connection
from app.database.connection import get_db
from app.main import app
from app.services.scanner import scan_manager


@pytest.fixture(autouse=True)
def mock_celery():
    """Mock Celery task enqueueing without executing scans when applicable."""
    if settings.scan_execution_mode != "celery":
        yield
        return

    try:
        from app.tasks import scan_tasks
    except Exception:
        yield
        return

    class MockTaskResult:
        def __init__(self, task_id="test-task-id"):
            self.id = task_id

    def execute_sync(scan_id):
        return MockTaskResult()

    patches = []
    if hasattr(scan_tasks, "execute_scan"):
        patches.append(mock.patch.object(scan_tasks.execute_scan, "delay", side_effect=execute_sync))
        patches.append(
            mock.patch.object(
                scan_tasks.execute_scan,
                "apply_async",
                side_effect=lambda args, **kwargs: execute_sync(*args),
            )
        )

    if not patches:
        yield
        return

    with patches[0]:
        if len(patches) > 1:
            with patches[1]:
                yield
        else:
            yield


def _run_alembic_upgrade(db_url: str) -> None:
    alembic_cfg = AlembicConfig("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(alembic_cfg, "head")


@pytest.fixture(scope="function", autouse=True)
def reset_security_state() -> Generator[None, None, None]:
    rate_limiter = get_rate_limiter()
    login_protection = get_login_protection()
    rate_limiter._windows.clear()
    login_protection._attempts.clear()
    yield
    rate_limiter._windows.clear()
    login_protection._attempts.clear()


@pytest.fixture(scope="function")
def test_db() -> Generator[tuple[Engine, sessionmaker], None, None]:
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
    _run_alembic_upgrade(db_url)

    original_session_local = connection.SessionLocal
    original_engine = connection.engine
    connection.SessionLocal = TestingSessionLocal
    connection.engine = engine

    original_scan_session_local = scan_manager.SessionLocal
    scan_manager.SessionLocal = TestingSessionLocal

    original_tasks_session_local = None
    scan_tasks_module = None
    if settings.scan_execution_mode == "celery":
        try:
            from app.tasks import scan_tasks as scan_tasks_module
            original_tasks_session_local = getattr(scan_tasks_module, "SessionLocal", None)
            scan_tasks_module.SessionLocal = TestingSessionLocal
        except Exception:
            scan_tasks_module = None

    yield engine, TestingSessionLocal

    connection.SessionLocal = original_session_local
    connection.engine = original_engine
    scan_manager.SessionLocal = original_scan_session_local
    if scan_tasks_module is not None and original_tasks_session_local is not None:
        scan_tasks_module.SessionLocal = original_tasks_session_local
    engine.dispose()
    tmpdir.cleanup()


@pytest.fixture(scope="function")
def db_session(test_db) -> Generator[Session, None, None]:
    _, TestingSessionLocal = test_db
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def client(test_db, db_session) -> Generator[TestClient, None, None]:
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
