"""Alembic environment configuration for FirmLock.

This module configures the Alembic migration environment. It loads the database
URL from the FIRMLOCK_DATABASE_URL environment variable (with a fallback to the
default SQLite path) and registers all SQLAlchemy model metadata for autogenerate
support.

The models are imported from app.models.models to ensure their table definitions
are available to Alembic's autogenerate feature.
"""

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import create_engine, pool

from alembic import context

# Ensure the backend directory is on sys.path so that app.* imports work.
# This file lives at backend/migrations/env.py, so backend is two levels up.
BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Import application configuration and models
from app.core.config import Settings
from app.database.connection import Base
import app.models.models  # noqa: F401  # registers all models on Base.metadata

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for autogenerate support
target_metadata = Base.metadata


def get_database_url() -> str:
    """Return the database URL from environment or default.

    Priority:
    1. sqlalchemy.url from alembic config (set via -x or set_main_option)
    2. FIRMLOCK_DATABASE_URL environment variable (explicit override)
    3. Default SQLite path matching app.core.config.Settings
    """
    # Check alembic config first (for programmatic use in tests)
    config_url = config.get_main_option("sqlalchemy.url")
    if config_url:
        return config_url

    # Use the same logic as Settings to compute the default
    settings = Settings()
    return os.getenv("FIRMLOCK_DATABASE_URL", settings.database_url)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine,
    though an Engine is acceptable here as well. By skipping the Engine
    creation we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine and associate a
    connection with the context.
    """
    url = get_database_url()

    # SQLite-specific connect args
    connect_args: dict = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    # Create engine with future=True for SQLAlchemy 2.x style
    connectable = create_engine(
        url,
        connect_args=connect_args,
        poolclass=pool.NullPool,
        future=True,
    )

    # Enable foreign keys for SQLite
    if url.startswith("sqlite"):
        from sqlalchemy import event
        from sqlalchemy.engine import Engine

        @event.listens_for(connectable, "connect")
        def _set_sqlite_pragma(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            # Include schemas if needed (not used currently)
            include_schemas=False,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()