"""Tests for GET /api/search unified search endpoint."""
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


def test_search_returns_shape(client):
    """GET /api/search?q=test → 200 with keys: query, vulns, news, links."""
    r = client.get("/api/search?q=test")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["query"], str)
    assert isinstance(body["vulns"], list)
    assert isinstance(body["news"], list)
    assert isinstance(body["links"], list)


def test_search_query_too_short(client):
    """GET /api/search?q=a → 422 (min_length=2)."""
    r = client.get("/api/search?q=a")
    assert r.status_code == 422


def test_search_limit_caps_results(client):
    """GET /api/search?q=CVE&limit=3 → at most 3 vulns and 3 news."""
    r = client.get("/api/search?q=CVE&limit=3")
    assert r.status_code == 200
    body = r.json()
    assert len(body["vulns"]) <= 3
    assert len(body["news"]) <= 3


def test_search_links_have_cve(client):
    """If links are returned, each must have a cve_id starting with 'CVE-'."""
    r = client.get("/api/search?q=CVE")
    assert r.status_code == 200
    body = r.json()
    for link in body["links"]:
        assert "cve_id" in link
        assert link["cve_id"].startswith("CVE-")


def test_search_empty_query(client):
    """GET /api/search (no q param) → 422."""
    r = client.get("/api/search")
    assert r.status_code == 422
