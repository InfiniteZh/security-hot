"""API endpoint tests using FastAPI TestClient."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure imports work
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def client(monkeypatch, tmp_db):
    """FastAPI TestClient with a clean news.db."""
    import backend.app.data as data_mod
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import db as scripts_db
    scripts_db.init_schema(scripts_db.connect(tmp_db))
    monkeypatch.setattr(data_mod, "_NEWS_DB", tmp_db)
    monkeypatch.setenv("SECURITY_HOT_REFRESH_TOKEN", "test-token")
    from backend.app.main import app
    return TestClient(app)


def test_regenerate_brief_requires_token(client):
    r = client.post("/api/brief/regenerate")
    assert r.status_code == 401


def test_regenerate_brief_accepts_valid_token(client):
    r = client.post("/api/brief/regenerate",
                    headers={"X-Refresh-Token": "test-token"})
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "accepted"
    assert "date" in body
