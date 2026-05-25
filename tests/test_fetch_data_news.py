"""News fetcher integration tests against SQLite."""
from __future__ import annotations

import asyncio
import io
import json
import sys
import zipfile
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


@pytest.mark.asyncio
async def test_ndjson_archive_dumped(tmp_db, archive_dir, monkeypatch):
    """After fetch_news_to_sqlite runs, today's NDJSON dump must contain all
    fetched articles (one per line)."""
    db.init_schema(db.connect(tmp_db))
    # Insert 2 articles directly to skip RSS mocking
    c = db.connect(tmp_db)
    for i, link in enumerate(["https://x.com/1", "https://x.com/2"]):
        db.upsert_article(c, {
            "canonical_url": link, "title": f"T{i}", "summary": "",
            "source_slug": "x", "source_title": "X", "lang": "en",
            "published": None, "fetched_at": "2026-05-25T12:00:00Z",
            "first_seen_date": "2026-05-25",
        })
    c.close()

    import fetch_data
    monkeypatch.setattr(fetch_data, "ARCHIVE_DIR", archive_dir)
    fetch_data.dump_ndjson_archive(db_path=tmp_db, date="2026-05-25")

    archive_file = archive_dir / "2026-05-25.jsonl"
    assert archive_file.exists()
    lines = archive_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    parsed = [json.loads(l) for l in lines]
    titles = {p["title"] for p in parsed}
    assert titles == {"T0", "T1"}


def _make_osv_zip(entries: list[dict]) -> bytes:
    """Build an in-memory zip with one JSON file per entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i, e in enumerate(entries):
            zf.writestr(f"{e.get('id', f'entry-{i}')}.json", json.dumps(e))
    return buf.getvalue()


@pytest.mark.asyncio
async def test_osv_fetcher_only_stores_malware(tmp_path, monkeypatch):
    """OSV fetcher must discard non-malware entries at write time."""
    import scripts.fetch_data as fd

    malware_entry = {
        "id": "MAL-2026-1234",
        "summary": "Malicious npm package",
        "affected": [{"package": {"name": "@evil/pkg", "ecosystem": "npm"}}],
        "database_specific": {"type": "malware"},
        "published": "2026-05-25T00:00:00Z",
        "modified": "2026-05-25T00:00:00Z",
    }
    normal_entry = {
        "id": "GHSA-xxxx-yyyy",
        "summary": "Normal vulnerability",
        "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}}],
        "published": "2026-05-24T00:00:00Z",
        "modified": "2026-05-24T00:00:00Z",
    }
    zip_bytes = _make_osv_zip([malware_entry, normal_entry])

    monkeypatch.setattr(fd, "CACHE", tmp_path)

    class FakeResp:
        status_code = 200
        content = zip_bytes
        def raise_for_status(self): pass

    class FakeClient:
        async def get(self, *a, **kw):
            return FakeResp()

    count = await fd._fetch_one_osv_ecosystem(FakeClient(), "npm")
    written = json.loads((tmp_path / "osv-npm.json").read_text())
    assert count == 1, f"expected 1 malware entry, got {count}"
    assert len(written["items"]) == 1
    assert written["items"][0]["id"] == "MAL-2026-1234"
