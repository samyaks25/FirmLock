"""SQLAlchemy database configuration and session management for FirmLock.

This module provides:
- SQLAlchemy engine configuration (SQLite).
- Declarative Base for ORM models.
- SessionLocal factory.
- FastAPI database session dependency.
- Database initialization helper (for tests and fresh DB setup).
- Database migration version checking.

Schema changes are managed via Alembic migrations. The `init_db()` function
creates tables via `create_all()` and is intended ONLY for:
- Automated test environments (isolated temporary databases)
- Fresh database initialization when migrations are not available

Production and development databases should use `alembic upgrade head`.
"""

from __future__ import annotations

from typing import Generator

from sqlalchemy import create_engine, event, inspect, text
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


def check_migration_version() -> tuple[bool, str]:
    """Check if the database schema is up to date with Alembic migrations.

    Returns:
        tuple: (is_up_to_date, message)
            - is_up_to_date: True if the database is at the head revision
            - message: Description of the current state

    This function checks the alembic_version table against the latest
    migration revision in the migrations/versions directory.
    """
    try:
        inspector = inspect(engine)
        if not inspector.has_table("alembic_version"):
            return False, "Database not initialized with Alembic (alembic_version table missing). Run 'alembic upgrade head' to initialize."

        with engine.connect() as conn:
            result = conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()
            if result is None:
                return False, "Alembic version table is empty. Run 'alembic upgrade head' to initialize."

            current_rev = result[0]

        # Find the head revision from the migrations directory
        from pathlib import Path
        versions_dir = Path(__file__).resolve().parents[2] / "migrations" / "versions"
        if not versions_dir.exists():
            return False, "Migrations directory not found."

        # Get all migration files and find the head (latest)
        migration_files = list(versions_dir.glob("*.py"))
        if not migration_files:
            return False, "No migration files found in migrations/versions/."

        # The head revision is the one with no down_revision pointing to it
        # For simplicity, we'll check if current_rev matches any migration file
        revision_ids = set()
        for f in migration_files:
            # Extract revision ID from filename (format: <rev>_<slug>.py)
            rev_id = f.stem.split("_")[0]
            revision_ids.add(rev_id)

        if current_rev not in revision_ids:
            return False, f"Unknown revision '{current_rev}' in database. Database may be from a different branch."

        # Check if there are any newer migrations by looking for a linear history
        # This is a simplified check - for a full check we'd need to parse the migration graph
        # For now, we assume the latest file (by name) is the head
        # This works for linear migration history
        head_rev = max(revision_ids)  # lexicographic sort works for our revision format
        if current_rev != head_rev:
            return False, f"Database schema is outdated (current: {current_rev}, head: {head_rev}). Run 'alembic upgrade head' to apply pending migrations."

        return True, f"Database schema is up to date (revision: {current_rev})."

    except Exception as e:
        return False, f"Failed to check migration version: {e}"


def init_db() -> None:
    """Create database tables for the current metadata.

    WARNING: This uses SQLAlchemy's create_all() and does NOT create the
    alembic_version table. This function is intended ONLY for:
    - Automated test environments (isolated temporary databases)
    - Fresh database initialization when migrations are explicitly not used

    For production and development databases, use Alembic migrations:
        alembic upgrade head

    If you use this on an existing database, it will not track schema version
    and future migrations will not work correctly.
    """
    # Import models so their metadata is registered on Base before create_all.
    import app.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
