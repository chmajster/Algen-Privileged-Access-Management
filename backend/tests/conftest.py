import os
import shutil
import pytest
from fastapi.testclient import TestClient

os.environ.update({
    "DATABASE_URL":"sqlite:///./test_pam_v2.db", "SECRET_KEY":"test-secret",
    "PAM_LOCAL_AUTH_MODE":"database", "PAM_DEFAULT_ADMIN_USER":"admin",
    "PAM_DEFAULT_ADMIN_EMAIL":"admin@example.local", "PAM_DEFAULT_ADMIN_PASSWORD":"admin123",
    "PAM_ARTIFACT_DIR":"./test-artifacts", "PAM_BROWSER_PROFILE_DIR":"./test-profiles",
    "PAM_MFA_REQUIRED_FOR_ADMIN":"false",
})

from app.database import Base, SessionLocal, engine, init_db
from app.main import app
from app.seed import seed_demo_data


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine); init_db()
    with SessionLocal() as db: seed_demo_data(db)
    with TestClient(app) as value: yield value
    Base.metadata.drop_all(bind=engine)
    shutil.rmtree("test-artifacts",ignore_errors=True); shutil.rmtree("test-profiles",ignore_errors=True)


def auth_headers(client:TestClient,username="admin",password="admin123"):
    response=client.post("/api/auth/login",json={"username":username,"password":password,"provider":"local_db"})
    assert response.status_code==200,response.text
    return {"Authorization":f"Bearer {response.json()['access_token']}"}
