"""News fetcher integration tests against SQLite."""
from __future__ import annotations

import asyncio
import inspect
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import db  # noqa: E402


@pytest.mark.asyncio
async def test_run_fetchers_defaults_to_24_concurrency(monkeypatch):
    from backend.app.ingest import fetchers

    seen = {}

    async def fake_run(selected, concurrency, snapshot=True, incremental=False):
        seen["selected"] = selected
        seen["concurrency"] = concurrency
        seen["snapshot"] = snapshot
        seen["incremental"] = incremental
        return 0

    monkeypatch.setattr(fetchers, "run", fake_run)

    result = await fetchers.run_fetchers(["news"])

    assert result["ok"] is True
    assert seen == {
        "selected": ["news"],
        "concurrency": 24,
        "snapshot": True,
        "incremental": False,
    }


def test_direct_news_fetcher_default_concurrency_is_24():
    import fetch_data

    sig = inspect.signature(fetch_data.fetch_news_to_sqlite)
    assert sig.parameters["concurrency"].default == 24


@pytest.mark.asyncio
async def test_partial_fetch_exit_code_ignores_prior_manifest_failures(tmp_path, monkeypatch):
    from backend.app.ingest import fetchers

    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "manifest.json").write_text(json.dumps({
        "fetched_at": "2026-06-02T00:00:00Z",
        "results": [
            {"name": "kev", "ok": False, "status": "error", "count": 0},
            {"name": "news", "ok": True, "status": "ok", "count": 1},
        ],
    }), encoding="utf-8")

    async def fake_news_fetcher(*, concurrency):
        return {"name": "news", "count": 0}

    monkeypatch.setattr(fetchers, "CACHE", cache)
    monkeypatch.setattr(fetchers, "FETCHERS", {"news": fake_news_fetcher})
    monkeypatch.setattr(fetchers, "snapshot_today", lambda only=None: {})

    code = await fetchers.run(["news"], concurrency=1, snapshot=True)

    assert code == 0
    manifest = json.loads((cache / "manifest.json").read_text(encoding="utf-8"))
    by_name = {r["name"]: r for r in manifest["results"]}
    assert by_name["kev"]["ok"] is False
    assert by_name["news"]["ok"] is True
    assert by_name["news"]["status"] == "no_data"


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


@pytest.mark.asyncio
async def test_epss_trims_to_referenced_cves(tmp_path, monkeypatch):
    """EPSS post-fetch trim keeps only CVEs referenced elsewhere."""
    import scripts.fetch_data as fd

    monkeypatch.setattr(fd, "CACHE", tmp_path)

    # Fake a KEV file with one CVE
    kev = {"items": [{"cveID": "CVE-2026-1111"}]}
    (tmp_path / "kev.json").write_text(json.dumps(kev))
    # Fake GHSA with one CVE
    ghsa = {"items": [{"cve_id": "CVE-2026-2222"}]}
    (tmp_path / "ghsa.json").write_text(json.dumps(ghsa))
    # Fake PoCs with one CVE
    pocs = {"items": [{"cve_id": "CVE-2026-3333"}]}
    (tmp_path / "pocs.json").write_text(json.dumps(pocs))
    # No news.db in tmp_path → skip news CVEs

    # Write a fat EPSS with 4 CVEs (one referenced, three not)
    epss_data = {
        "score_date": "2026-05-25",
        "model_version": "test",
        "items": {
            "CVE-2026-1111": {"score": 0.9, "percentile": 0.99},
            "CVE-2026-2222": {"score": 0.5, "percentile": 0.50},
            "CVE-2026-9999": {"score": 0.01, "percentile": 0.10},
            "CVE-2026-8888": {"score": 0.02, "percentile": 0.15},
        },
        "count": 4,
        "fetched_at": "2026-05-25T00:00:00Z",
    }
    (tmp_path / "epss.json").write_text(json.dumps(epss_data))

    fd.trim_epss_to_referenced(cache_dir=tmp_path)

    trimmed = json.loads((tmp_path / "epss.json").read_text())
    assert "CVE-2026-1111" in trimmed["items"]
    assert "CVE-2026-2222" in trimmed["items"]
    assert "CVE-2026-9999" not in trimmed["items"]
    assert "CVE-2026-8888" not in trimmed["items"]
    assert trimmed["count"] == 2
