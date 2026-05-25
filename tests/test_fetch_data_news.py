"""News fetcher integration tests against SQLite."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import db  # noqa: E402


@pytest.mark.asyncio
async def test_fetch_news_writes_to_sqlite(tmp_db, monkeypatch, httpx_mock):
    """When fetch_news encounters new articles, they show up in articles table."""
    db.init_schema(db.connect(tmp_db))
    # Seed one source so due_sources returns it
    c = db.connect(tmp_db)
    db.upsert_source(c, {
        "slug": "mocksrc", "title": "Mock", "url": "https://mock.example/feed",
        "lang": "en", "tier": "top", "interval_minutes": 30,
    })
    c.close()
    # Mock the RSS endpoint
    rss = """<?xml version="1.0"?><rss version="2.0"><channel>
    <item><title>Test Article</title><link>https://mock.example/post-1</link>
    <description>desc</description><pubDate>Mon, 25 May 2026 10:00:00 GMT</pubDate></item>
    </channel></rss>"""
    httpx_mock.add_response(url="https://mock.example/feed", text=rss,
                            headers={"ETag": "W/abc", "Last-Modified": "Mon, 25 May 2026 10:00:00 GMT"})

    # Monkeypatch the DB path used by fetch_data
    import fetch_data
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", tmp_db)
    # Run only the news fetcher with concurrency=1
    await fetch_data.fetch_news_to_sqlite(concurrency=1, now_iso="2026-05-25T12:00:00Z")

    c = db.connect(tmp_db)
    rows = list(c.execute("SELECT title, source_slug, llm_score FROM articles"))
    assert len(rows) == 1
    assert rows[0]["title"] == "Test Article"
    assert rows[0]["source_slug"] == "mocksrc"
    assert rows[0]["llm_score"] is None  # decoupled: no LLM at fetch time
    c.close()


@pytest.mark.asyncio
async def test_304_response_does_not_create_articles(tmp_db, monkeypatch, httpx_mock):
    db.init_schema(db.connect(tmp_db))
    c = db.connect(tmp_db)
    db.upsert_source(c, {
        "slug": "mocksrc", "title": "Mock", "url": "https://mock.example/feed",
        "lang": "en", "tier": "top", "interval_minutes": 30,
    })
    c.execute("UPDATE sources SET last_etag=?, last_fetched=? WHERE slug='mocksrc'",
              ["W/abc", "2026-05-25T11:00:00Z"])
    c.commit()
    c.close()
    httpx_mock.add_response(url="https://mock.example/feed", status_code=304)

    import fetch_data
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", tmp_db)
    result = await fetch_data.fetch_news_to_sqlite(
        concurrency=1, now_iso="2026-05-25T11:35:00Z"
    )
    assert result["not_modified"] == 1
    assert result["count"] == 0

    c = db.connect(tmp_db)
    n = c.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
    assert n == 0
    c.close()
