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


def test_hidden_endpoint_returns_off_topic_articles(client, tmp_db):
    """Insert one off-topic + one relevant; /api/news/hidden returns only the off-topic."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import db as scripts_db
    c = scripts_db.connect(tmp_db)
    on_id = scripts_db.upsert_article(c, {
        "canonical_url": "https://x.com/sec", "title": "Real CVE", "summary": "",
        "source_slug": "x", "source_title": "X", "lang": "en",
        "published": None, "fetched_at": "2026-05-25T11:00:00Z",
        "first_seen_date": "2026-05-25",
    })
    off_id = scripts_db.upsert_article(c, {
        "canonical_url": "https://x.com/off", "title": "Cooking recipes", "summary": "",
        "source_slug": "x", "source_title": "X", "lang": "en",
        "published": None, "fetched_at": "2026-05-25T11:00:00Z",
        "first_seen_date": "2026-05-25",
    })
    c.execute("UPDATE articles SET is_relevant=1 WHERE id=?", [on_id])
    c.execute("UPDATE articles SET is_relevant=0, llm_reason='off topic' WHERE id=?", [off_id])
    c.commit()
    c.close()

    r = client.get("/api/news/hidden?date=2026-05-25")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert body[0]["title"] == "Cooking recipes"


def test_mirrors_endpoint_returns_cluster_members(client, tmp_db):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import db as scripts_db
    c = scripts_db.connect(tmp_db)
    ids = []
    for i in range(3):
        ids.append(scripts_db.upsert_article(c, {
            "canonical_url": f"https://x/{i}", "title": f"T{i}", "summary": "",
            "source_slug": f"s{i}", "source_title": f"Src{i}", "lang": "en",
            "published": None, "fetched_at": "2026-05-25T11:00:00Z",
            "first_seen_date": "2026-05-25",
        }))
    scripts_db.create_cluster(c, primary_id=ids[0], mirror_ids=[ids[1], ids[2]],
                              created_at="2026-05-25T12:00:00Z")
    c.close()

    r = client.get(f"/api/news/{ids[0]}/mirrors")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 2  # only mirrors, not primary
    titles = {a["title"] for a in body}
    assert titles == {"T1", "T2"}


def test_mirrors_endpoint_404_for_unclustered(client, tmp_db):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import db as scripts_db
    c = scripts_db.connect(tmp_db)
    rid = scripts_db.upsert_article(c, {
        "canonical_url": "https://x/solo", "title": "Solo", "summary": "",
        "source_slug": "x", "source_title": "X", "lang": "en",
        "published": None, "fetched_at": "2026-05-25T11:00:00Z",
        "first_seen_date": "2026-05-25",
    })
    c.close()
    r = client.get(f"/api/news/{rid}/mirrors")
    assert r.status_code == 404
