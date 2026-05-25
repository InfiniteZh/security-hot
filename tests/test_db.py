"""db.py: connection management + schema initialization."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import db  # noqa: E402


def test_connect_creates_wal_database(tmp_db: Path):
    c = db.connect(tmp_db)
    assert isinstance(c, sqlite3.Connection)
    journal_mode = c.execute("PRAGMA journal_mode").fetchone()[0]
    assert journal_mode == "wal"
    c.close()


def test_init_schema_creates_all_tables(tmp_db: Path):
    c = db.connect(tmp_db)
    db.init_schema(c)
    tables = {r[0] for r in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    assert {"articles", "sources", "clusters", "daily_briefs"} <= tables
    c.close()


def test_init_schema_creates_fts(tmp_db: Path):
    c = db.connect(tmp_db)
    db.init_schema(c)
    fts = c.execute(
        "SELECT name FROM sqlite_master WHERE name = 'articles_fts'"
    ).fetchone()
    assert fts is not None
    c.close()


def test_init_schema_is_idempotent(tmp_db: Path):
    c = db.connect(tmp_db)
    db.init_schema(c)
    db.init_schema(c)  # second call must not raise
    c.close()


def test_upsert_article_inserts_new(conn):
    db.init_schema(conn)
    rowid = db.upsert_article(conn, {
        "canonical_url": "https://example.com/post-1",
        "title": "Hello",
        "summary": "World",
        "source_slug": "example",
        "source_title": "Example",
        "lang": "en",
        "published": "2026-05-25T10:00:00Z",
        "fetched_at": "2026-05-25T11:00:00Z",
        "first_seen_date": "2026-05-25",
    })
    assert rowid > 0
    row = conn.execute("SELECT title FROM articles WHERE id = ?", [rowid]).fetchone()
    assert row["title"] == "Hello"


def test_upsert_article_is_idempotent_on_canonical_url(conn):
    db.init_schema(conn)
    payload = {
        "canonical_url": "https://example.com/post-1",
        "title": "Hello",
        "summary": "",
        "source_slug": "example",
        "source_title": "Example",
        "lang": "en",
        "published": "2026-05-25T10:00:00Z",
        "fetched_at": "2026-05-25T11:00:00Z",
        "first_seen_date": "2026-05-25",
    }
    db.upsert_article(conn, payload)
    db.upsert_article(conn, payload)  # second call must not raise / duplicate
    n = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
    assert n == 1


def test_upsert_article_does_not_clobber_llm_fields(conn):
    """Re-fetching an article (e.g. on next cron) must not wipe out previously
    scored LLM fields."""
    db.init_schema(conn)
    base = {
        "canonical_url": "https://example.com/post-1",
        "title": "Hello",
        "summary": "",
        "source_slug": "example",
        "source_title": "Example",
        "lang": "en",
        "published": "2026-05-25T10:00:00Z",
        "fetched_at": "2026-05-25T11:00:00Z",
        "first_seen_date": "2026-05-25",
    }
    rowid = db.upsert_article(conn, base)
    conn.execute(
        "UPDATE articles SET llm_score=8, llm_category='vuln', is_relevant=1 WHERE id=?",
        [rowid],
    )
    conn.commit()
    # Simulate fetcher re-seeing the same article
    db.upsert_article(conn, base)
    row = conn.execute(
        "SELECT llm_score, llm_category, is_relevant FROM articles WHERE id=?", [rowid]
    ).fetchone()
    assert row["llm_score"] == 8
    assert row["llm_category"] == "vuln"
    assert row["is_relevant"] == 1


def test_fts_search_finds_article(conn):
    db.init_schema(conn)
    db.upsert_article(conn, {
        "canonical_url": "https://example.com/cve",
        "title": "TYPO3 CVE-2026-46725 disclosure",
        "summary": "Remote code execution",
        "source_slug": "x", "source_title": "X", "lang": "en",
        "published": None, "fetched_at": "2026-05-25T11:00:00Z",
        "first_seen_date": "2026-05-25",
    })
    rows = list(conn.execute(
        "SELECT rowid FROM articles_fts WHERE articles_fts MATCH 'TYPO3'"
    ))
    assert len(rows) == 1
