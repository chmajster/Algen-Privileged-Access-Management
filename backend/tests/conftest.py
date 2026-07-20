import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["DATABASE_URL"] = "sqlite:///./test_pam_lite.db"
os.environ["PAM_EXECUTOR_MODE"] = "mock"
os.environ["SECRET_KEY"] = "test-secret"
os.environ["PAM_LOCAL_AUTH_MODE"] = "database"
os.environ["PAM_DEFAULT_ADMIN_USER"] = "admin"
os.environ["PAM_DEFAULT_ADMIN_EMAIL"] = "admin@example.local"
os.environ["PAM_DEFAULT_ADMIN_PASSWORD"] = "admin123"

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.seed import seed_demo_data  # noqa: E402


@pytest.fixture()
def client():
    db_file = Path("test_pam_lite.db")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_demo_data(db)
    finally:
        db.close()
    with TestClient(app) as test_client:
        yield test_client
    engine.dispose()
    if db_file.exists():
        db_file.unlink()


def auth_headers(client: TestClient, username: str = "admin", password: str = "admin123") -> dict[str, str]:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
