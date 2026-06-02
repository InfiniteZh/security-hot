"""Industry-news ingestion into SQLite.

Fetches RSS sources with Conditional GET and upserts articles into news.db,
applies the URL-canonicalize + keyword-block pipeline, and dumps per-day
NDJSON archives. Replaces the legacy news.json write path.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import httpx

from .. import _util
from .. import db as _db
from .._util import (
    HEADERS,
    ROOT,
    SCRIPTS,
    clean_summary,
    _articles_keyword_filter,
    _canonical_url,
    _entry_published_iso,
)
from .catalog import _news_sources_to_use, _slug_from_url

# refresh_progress is a script-level module; keep scripts/ importable for the
# lazy `import refresh_progress` inside fetch_news_to_sqlite.
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


async def _fetch_one_source_to_sqlite(
    client: httpx.AsyncClient,
    src: dict,
    conn,
    now_iso: str,
) -> tuple[int, int]:
    """Fetch one RSS source with Conditional GET; upsert into SQLite.

    Returns (n_inserted, status_code). status_code=304 means not modified.
    """
    headers: dict[str, str] = {}
    if src.get("last_etag"):
        headers["If-None-Match"] = src["last_etag"]
    if src.get("last_modified"):
        headers["If-Modified-Since"] = src["last_modified"]
    try:
        r = await client.get(src["url"], headers=headers)
    except Exception as exc:
        _db.record_source_fetch(conn, src["slug"], now=now_iso,
                                etag=None, last_modified=None,
                                ok=False, error=str(exc)[:200])
        return (0, 0)
    if r.status_code == 304:
        _db.record_source_fetch(conn, src["slug"], now=now_iso,
                                etag=src.get("last_etag"),
                                last_modified=src.get("last_modified"),
                                ok=True)
        print(f"[news] {src['slug']:>20}: 304 not-modified", file=sys.stderr)
        return (0, 304)
    if r.status_code >= 400:
        _db.record_source_fetch(conn, src["slug"], now=now_iso,
                                etag=None, last_modified=None,
                                ok=False, error=f"HTTP {r.status_code}")
        return (0, r.status_code)

    parsed = feedparser.parse(r.content)
    first_seen_date = now_iso[:10]

    # Filter by publish time window, not per-source count cap.
    # Window comes from NEWS_DAYS_BACK env (default 30).
    # Articles with malformed publish dates (year < 2020 or > now+7d) are
    # dropped as RSS metadata garbage.
    days_back = int(os.environ.get("NEWS_DAYS_BACK", "30"))
    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days_back)
    future_dt = datetime.now(timezone.utc) + timedelta(days=7)

    def _in_window(entry) -> bool:
        pub_iso = _entry_published_iso(entry)
        if not pub_iso:
            # No publish date — accept (assume recent since we just fetched it).
            return True
        try:
            dt = datetime.fromisoformat(pub_iso.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return False  # unparseable → garbage
        return cutoff_dt <= dt <= future_dt

    entries_raw = [{
        "title": (e.get("title") or "(untitled)")[:500],
        "summary": clean_summary(e.get("summary", ""), limit=2000),
        "link": _canonical_url(e.get("link", "")),
        "_raw": e,
    } for e in parsed.entries if e.get("link") and _in_window(e)]

    # Layer 2: keyword block (Layer 1 dedupe is handled by SQLite UNIQUE)
    kept, _dropped = _articles_keyword_filter(entries_raw)

    n = 0
    for art in kept:
        if not art["link"]:
            continue
        rowid = _db.upsert_article(conn, {
            "canonical_url": art["link"],
            "title": art["title"],
            "summary": art["summary"],
            "source_slug": src["slug"],
            "source_title": src.get("title"),
            "lang": src.get("lang"),
            "rss_category": src.get("category"),
            "published": _entry_published_iso(art["_raw"]),
            "fetched_at": now_iso,
            "first_seen_date": first_seen_date,
        })
        if rowid:
            n += 1
    _db.record_source_fetch(conn, src["slug"], now=now_iso,
                            etag=(r.headers.get("ETag") or "")[:512] or None,
                            last_modified=(r.headers.get("Last-Modified") or "")[:512] or None,
                            ok=True)
    return (n, r.status_code)


def dump_ndjson_archive(*, db_path=None, date: str) -> Path:
    """Dump all articles with first_seen_date == date to a per-day NDJSON.

    Includes is_relevant=0 articles for human audit. Idempotent: overwrites
    the day's file each time.
    """
    _util.ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = _util.ARCHIVE_DIR / f"{date}.jsonl"
    conn = _db.connect(db_path)
    rows = conn.execute(
        "SELECT * FROM articles WHERE first_seen_date = ? ORDER BY fetched_at",
        [date],
    )
    with out_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
    conn.close()
    return out_path


async def fetch_news_to_sqlite(
    *,
    concurrency: int = 24,
    now_iso: str | None = None,
    db_path=None,
) -> dict:
    """SQLite-backed news fetcher. Replaces the news.json write path.

    Picks 'due' sources via db.due_sources(), respects ETag/If-Modified-Since,
    upserts new articles into the articles table.
    """
    ts = now_iso if now_iso is not None else datetime.now(timezone.utc).isoformat()
    conn = _db.connect(db_path)
    _db.init_schema(conn)  # idempotent — safe to call every run

    # Self-bootstrap: seed sources table from NEWS_SOURCES + OPML if empty.
    # Avoids needing migrate_to_sqlite as a separate step on fresh deployments.
    # On subsequent runs the table is non-empty and we skip the upsert loop
    # (saves O(700) writes per cron tick); operators can manually edit the
    # sources table to add/remove feeds.
    existing_sources = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
    if existing_sources == 0:
        _TOP_SLUGS = {
            "freebuf", "anquanke", "4hou", "kanxue", "secrss", "qianxin",
            "thn", "bleeping", "krebs", "schneier", "talos", "unit42",
            "msrc", "googlep0", "mandiant", "datadog",
        }
        for src in _news_sources_to_use():
            slug = src.get("slug") or _slug_from_url(src.get("url", ""))
            tier = "top" if slug in _TOP_SLUGS else "tail"
            _db.upsert_source(conn, {
                "slug": slug,
                "title": src.get("title") or slug,
                "url": src.get("url"),
                "lang": src.get("lang"),
                "tier": tier,
                "interval_minutes": 30 if tier == "top" else 240,
            })
        print(f"[news] bootstrapped {conn.execute('SELECT COUNT(*) FROM sources').fetchone()[0]} sources", file=sys.stderr)

    due = _db.due_sources(conn, ts)
    print(f"[news] {len(due)} sources due (out of total in sources table)", file=sys.stderr)

    sem = asyncio.Semaphore(concurrency)
    inserted_total = 0
    not_modified = 0
    _feeds_done = 0

    try:
        import refresh_progress as _prog
        _prog.start("fetching")
        _prog.report("fetching", len(due), 0, label="news_rss")
    except ImportError:
        _prog = None

    timeout = httpx.Timeout(30.0, connect=10.0)
    async with httpx.AsyncClient(headers=HEADERS, timeout=timeout,
                                  follow_redirects=True) as client:
        async def one(src):
            nonlocal inserted_total, not_modified, _feeds_done
            async with sem:
                n, status = await _fetch_one_source_to_sqlite(client, dict(src), conn, ts)
                inserted_total += n
                if status == 304:
                    not_modified += 1
                _feeds_done += 1
                if _prog and _feeds_done % 10 == 0:
                    _prog.report("fetching", len(due), _feeds_done, label="news_rss")
        await asyncio.gather(*[one(s) for s in due])
    if _prog:
        _prog.report("fetching", len(due), len(due), label="news_rss")

    conn.close()
    # Dump today's archive (idempotent: overwrites the day's file)
    today = ts[:10]
    try:
        dump_ndjson_archive(db_path=db_path, date=today)
    except Exception as exc:
        print(f"[news] archive dump failed: {exc}", file=sys.stderr)
    return {
        "name": "news", "ok": True, "status": "ok",
        "count": inserted_total, "due_sources": len(due),
        "not_modified": not_modified,
    }
