"""Alembic environment configuration."""

from logging.config import fileConfig
import os
import sys
from alembic import context
from sqlalchemy import engine_from_config, inspect, pool, text

# Ensure backend path is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.config import get_settings
from app.models import Base

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set database URL dynamically from config / environment / Pydantic settings
settings = get_settings()
db_url = config.get_main_option("sqlalchemy.url") or os.environ.get("DATABASE_URL") or settings.DATABASE_URL
if db_url.startswith("postgresql://"):
    db_url = "postgresql+psycopg://" + db_url.removeprefix("postgresql://")
elif db_url.startswith("postgres://"):
    db_url = "postgresql+psycopg://" + db_url.removeprefix("postgres://")
# Alembic stores options in ConfigParser, where a literal percent character
# (including URL-encoded credentials such as ``%40``) must be escaped.
config.set_main_option("sqlalchemy.url", db_url.replace("%", "%%"))

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url") or os.environ.get("DATABASE_URL") or settings.DATABASE_URL
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,  # Enables batch mode for SQLite schema alterations
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    configuration = config.get_section(config.config_ini_section)
    if configuration is None:
        configuration = {}
    configuration["sqlalchemy.url"] = config.get_main_option("sqlalchemy.url") or os.environ.get("DATABASE_URL") or settings.DATABASE_URL

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        if connection.dialect.name == "postgresql":
            # Alembic defaults version_num to VARCHAR(32), but RepoLens retains
            # one historical revision identifier longer than that. Bootstrap
            # new databases with sufficient capacity and widen older tables
            # before Alembic attempts to record that immutable revision.
            if inspect(connection).has_table("alembic_version"):
                connection.execute(text(
                    "ALTER TABLE alembic_version "
                    "ALTER COLUMN version_num TYPE VARCHAR(128)"
                ))
            else:
                connection.execute(text(
                    "CREATE TABLE alembic_version ("
                    "version_num VARCHAR(128) NOT NULL, "
                    "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)"
                    ")"
                ))
            connection.commit()

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # Enables batch mode for SQLite schema alterations
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
