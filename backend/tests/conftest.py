"""Pytest fixtures for backend test suite."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.cli.create_operator import create_or_elevate_operator
from app.core.database import Base, get_db
import app.models  # Register all SQLAlchemy models
from app.main import app
from app.models.change_analysis import ChangeAnalysisModel
from app.models.scan import ScanModel
from app.models.user import UserModel
from app.services.auth_service import AuthService

# In-memory SQLite engine for fast and isolated testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@event.listens_for(TestingSessionLocal, "before_flush")
def _auto_assign_owner_for_legacy_tests(session, flush_context, instances):
    """Automatically bind unowned scans/analyses in legacy tests to the active default test user."""
    for obj in list(session.new):
        if isinstance(obj, (ScanModel, ChangeAnalysisModel)):
            if obj.owner_user_id is None and getattr(obj, "_explicit_unowned", False) is False:
                default_user = session.query(UserModel).filter_by(email="default_test_user@example.com").first()
                if default_user:
                    obj.owner_user_id = default_user.id


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create all tables in memory once for the test session."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session():
    """Yield an isolated test session per test function."""
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection, join_transaction_mode="create_savepoint")

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    """FastAPI TestClient with overridden database dependency and default operator session."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    # Create default authenticated operator user and session for API compatibility
    user = create_or_elevate_operator(
        db_session,
        email="default_test_user@example.com",
        password="DefaultTestPass12345!",
    )
    auth_service = AuthService(db_session)
    raw_session, raw_csrf, _ = auth_service.create_session(user)

    with TestClient(app) as test_client:
        test_client.cookies.set("repolens_session", raw_session)
        test_client.cookies.set("repolens_csrf", raw_csrf)
        test_client.headers["X-CSRF-Token"] = raw_csrf
        yield test_client
    app.dependency_overrides.clear()
