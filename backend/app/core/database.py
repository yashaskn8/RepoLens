"""Database configuration and session management using SQLAlchemy."""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.core.config import get_settings

settings = get_settings()
database_url = settings.DATABASE_URL
if database_url.startswith("postgresql://"):
    database_url = "postgresql+psycopg://" + database_url.removeprefix("postgresql://")
elif database_url.startswith("postgres://"):
    database_url = "postgresql+psycopg://" + database_url.removeprefix("postgres://")

# Engine arguments based on database dialect
connect_args = {}
engine_args = {}
if settings.is_sqlite:
    connect_args["check_same_thread"] = False
elif database_url.startswith(("postgresql", "postgres")):
    # Bound both pool admission and server-side work for PostgreSQL. Individual
    # indexing queries may impose a smaller transaction-local deadline.
    connect_args["options"] = (
        f"-c statement_timeout={settings.DATABASE_STATEMENT_TIMEOUT_MS} "
        f"-c lock_timeout={settings.DATABASE_LOCK_TIMEOUT_MS}"
    )
    engine_args.update(pool_size=settings.DATABASE_POOL_SIZE,
                       max_overflow=settings.DATABASE_MAX_OVERFLOW,
                       pool_timeout=settings.DATABASE_POOL_TIMEOUT_SECONDS)

engine = create_engine(
    database_url,
    connect_args=connect_args,
    pool_pre_ping=True,
    **engine_args,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for yielding database sessions with automatic closure."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
