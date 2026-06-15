"""API endpoint tests using FastAPI TestClient."""
from __future__ import annotations

import json
import sys
import time
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


def test_news_heat_endpoint_returns_empty_board(client):
    r = client.get("/api/heat?kind=news")
    assert r.status_code == 200
    assert r.json() == []


def test_ops_root_points_to_project_root():
    import backend.app.routes.ops as ops_mod

    assert ops_mod.ROOT == Path(__file__).resolve().parents[1]


def test_healthz_exposes_refresh_progress(client, tmp_path, monkeypatch):
    import backend.app.routes.ops as ops_mod
    from backend.app.runtime import refresh_state

    progress_dir = tmp_path / "backend" / "cache"
    progress_dir.mkdir(parents=True)
    (progress_dir / ".refresh_progress.json").write_text(json.dumps({
        "stage": "fetching",
        "label": "news_rss",
        "total": 713,
        "done": 380,
        "rate": 3.33,
        "eta_s": 99.9,
        "elapsed_s": 114.0,
        "ts": time.time(),
    }), encoding="utf-8")
    monkeypatch.setattr(ops_mod, "ROOT", tmp_path)
    monkeypatch.setattr(refresh_state, "_refresh_in_flight", True)
    monkeypatch.setattr(refresh_state, "_refresh_stage", "fetching")
    monkeypatch.setattr(refresh_state, "_refresh_started_at", time.monotonic())

    r = client.get("/api/healthz")

    assert r.status_code == 200
    assert r.json()["refresh_progress"] == {
        "stage": "fetching",
        "label": "news_rss",
        "total": 713,
        "done": 380,
        "rate": 3.33,
        "eta_s": 99.9,
        "elapsed_s": 114.0,
        "ts": r.json()["refresh_progress"]["ts"],
    }


def test_hidden_endpoint_returns_off_topic_and_uncategorized(client, tmp_db):
    """/api/news/hidden surfaces two buckets for human audit of the LLM filter:
      1. off-topic (is_relevant=0), date-filtered
      2. relevant-but-uncategorized (llm_category IS NULL), NOT date-filtered —
         these never land on any day's news view, so the audit view is their
         only review home.
    A relevant article that DID get a category is not hidden.
    """
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
    unc_id = scripts_db.upsert_article(c, {
        "canonical_url": "https://x.com/pending", "title": "Pending classification", "summary": "",
        "source_slug": "x", "source_title": "X", "lang": "en",
        "published": None, "fetched_at": "2026-05-25T11:00:00Z",
        "first_seen_date": "2026-05-25",
    })
    # relevant AND categorized → must NOT appear in hidden
    c.execute("UPDATE articles SET is_relevant=1, llm_category='vuln' WHERE id=?", [on_id])
    # off-topic → hidden (bucket 1)
    c.execute("UPDATE articles SET is_relevant=0, llm_reason='off topic' WHERE id=?", [off_id])
    # relevant but uncategorized → hidden (bucket 2)
    c.execute("UPDATE articles SET is_relevant=1, llm_category=NULL WHERE id=?", [unc_id])
    c.commit()
    c.close()

    r = client.get("/api/news/hidden?date=2026-05-25")
    assert r.status_code == 200
    body = r.json()
    titles = {a["title"] for a in body}
    assert titles == {"Cooking recipes", "Pending classification"}
    assert "Real CVE" not in titles


def test_regenerate_brief_returns_409_when_in_flight(client, monkeypatch):
    """Second concurrent regen call must return 409."""
    import backend.app.main as main_mod
    # Simulate one already in flight
    main_mod._brief_regen_in_flight = True
    try:
        r = client.post("/api/brief/regenerate",
                        headers={"X-Refresh-Token": "test-token"})
        assert r.status_code == 409
    finally:
        main_mod._brief_regen_in_flight = False  # cleanup for other tests
