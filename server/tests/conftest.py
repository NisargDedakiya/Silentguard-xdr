import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import ADMIN_TOKEN, ENROLL_TOKEN
from app.database import Base, get_db
from app.main import app

ADMIN_HEADERS = {"X-Admin-Token": ADMIN_TOKEN}


@pytest.fixture()
def db_session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,  # single in-memory DB shared across connections
    )
    Base.metadata.create_all(bind=engine)
    yield sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    engine.dispose()


@pytest.fixture()
def client(db_session_factory):
    def override_get_db():
        db = db_session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def enrolled_device(client):
    """Enroll a device and return its credentials."""
    resp = client.post(
        "/api/agent/enroll",
        json={"enroll_token": ENROLL_TOKEN, "hostname": "test-vm", "platform": "Linux test"},
    )
    assert resp.status_code == 200
    data = resp.json()
    return {"device_id": data["device_id"], "headers": {"X-Agent-Key": data["api_key"]}}
