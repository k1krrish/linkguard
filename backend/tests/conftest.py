import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import investigations


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("LINKGUARD_ALLOW_PRIVATE_TARGETS", raising=False)
    monkeypatch.delenv("LINKGUARD_MAX_UPLOAD_MB", raising=False)
    investigations.reset_store()
    yield
    investigations.reset_store()


@pytest.fixture
def client():
    return TestClient(app)
