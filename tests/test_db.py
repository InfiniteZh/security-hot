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


def test_upsert_source_inserts(conn):
    db.init_schema(conn)
    db.upsert_source(conn, {
        "slug": "freebuf",
        "title": "FreeBuf",
        "url": "https://freebuf.com/feed",
        "lang": "zh",
        "tier": "top",
        "interval_minutes": 30,
    })
    row = conn.execute("SELECT slug, tier FROM sources WHERE slug='freebuf'").fetchone()
    assert row["tier"] == "top"


def test_upsert_source_updates_interval_on_conflict(conn):
    """On conflict, refresh url/title/tier/interval but never reset
    last_fetched / last_etag / last_modified."""
    db.init_schema(conn)
    db.upsert_source(conn, {
        "slug": "freebuf", "title": "FreeBuf", "url": "https://freebuf.com/feed",
        "lang": "zh", "tier": "top", "interval_minutes": 30,
    })
    conn.execute(
        "UPDATE sources SET last_fetched=?, last_etag=? WHERE slug=?",
        ["2026-05-25T10:00:00Z", "abc123", "freebuf"],
    )
    conn.commit()
    db.upsert_source(conn, {
        "slug": "freebuf", "title": "FreeBuf", "url": "https://freebuf.com/feed",
        "lang": "zh", "tier": "top", "interval_minutes": 60,  # changed
    })
    row = conn.execute(
        "SELECT interval_minutes, last_fetched, last_etag FROM sources WHERE slug='freebuf'"
    ).fetchone()
    assert row["interval_minutes"] == 60
    assert row["last_fetched"] == "2026-05-25T10:00:00Z"
    assert row["last_etag"] == "abc123"


def test_due_sources_excludes_recently_fetched(conn):
    db.init_schema(conn)
    # Source A fetched 5 min ago, interval 30 → NOT due
    # Source B fetched 60 min ago, interval 30 → DUE
    # Source C never fetched → DUE
    now = "2026-05-25T12:00:00Z"
    for slug, last in [("A", "2026-05-25T11:55:00Z"), ("B", "2026-05-25T11:00:00Z"), ("C", None)]:
        db.upsert_source(conn, {
            "slug": slug, "title": slug, "url": f"https://{slug}.com",
            "lang": "en", "tier": "top", "interval_minutes": 30,
        })
        if last:
            conn.execute("UPDATE sources SET last_fetched=? WHERE slug=?", [last, slug])
    conn.commit()
    due = db.due_sources(conn, now)
    slugs = {s["slug"] for s in due}
    assert slugs == {"B", "C"}


def test_due_sources_excludes_failing_sources(conn):
    db.init_schema(conn)
    db.upsert_source(conn, {
        "slug": "broken", "title": "broken", "url": "https://broken.example",
        "lang": "en", "tier": "tail", "interval_minutes": 30,
    })
    conn.execute("UPDATE sources SET consecutive_failures=5 WHERE slug='broken'")
    conn.commit()
    due = db.due_sources(conn, "2026-05-25T12:00:00Z")
    assert all(s["slug"] != "broken" for s in due)


def test_due_sources_excludes_ok_zero_sources(conn):
    db.init_schema(conn)
    db.upsert_source(conn, {
        "slug": "marked_down", "title": "x", "url": "https://x",
        "lang": "en", "tier": "tail", "interval_minutes": 30,
    })
    conn.execute("UPDATE sources SET ok = 0 WHERE slug = 'marked_down'")
    conn.commit()
    due = db.due_sources(conn, "2026-05-25T12:00:00Z")
    assert all(s["slug"] != "marked_down" for s in due)


def test_record_source_success_resets_failures(conn):
    db.init_schema(conn)
    db.upsert_source(conn, {
        "slug": "x", "title": "x", "url": "https://x.com",
        "lang": "en", "tier": "top", "interval_minutes": 30,
    })
    conn.execute("UPDATE sources SET consecutive_failures=3 WHERE slug='x'")
    conn.commit()
    db.record_source_fetch(conn, "x", now="2026-05-25T12:00:00Z",
                           etag="W/abc", last_modified=None, ok=True)
    row = conn.execute(
        "SELECT consecutive_failures, last_etag, ok FROM sources WHERE slug='x'"
    ).fetchone()
    assert row["consecutive_failures"] == 0
    assert row["last_etag"] == "W/abc"
    assert row["ok"] == 1


def test_record_source_failure_increments_failures(conn):
    db.init_schema(conn)
    db.upsert_source(conn, {
        "slug": "x", "title": "x", "url": "https://x.com",
        "lang": "en", "tier": "top", "interval_minutes": 30,
    })
    db.record_source_fetch(conn, "x", now="2026-05-25T12:00:00Z",
                           etag=None, last_modified=None, ok=False, error="HTTP 500")
    row = conn.execute(
        "SELECT consecutive_failures, ok, error FROM sources WHERE slug='x'"
    ).fetchone()
    assert row["consecutive_failures"] == 1
    assert row["ok"] == 0
    assert row["error"] == "HTTP 500"


def test_create_cluster_links_articles(conn):
    db.init_schema(conn)
    # Insert 3 articles
    ids = []
    for i in range(3):
        ids.append(db.upsert_article(conn, {
            "canonical_url": f"https://a.com/{i}", "title": f"T{i}", "summary": "",
            "source_slug": "x", "source_title": "X", "lang": "en",
            "published": None, "fetched_at": "2026-05-25T11:00:00Z",
            "first_seen_date": "2026-05-25",
        }))
    cluster_id = db.create_cluster(conn, primary_id=ids[0], mirror_ids=[ids[1], ids[2]],
                                   created_at="2026-05-25T12:00:00Z")
    assert cluster_id > 0
    members = list(conn.execute(
        "SELECT id, is_cluster_primary FROM articles WHERE cluster_id = ?", [cluster_id]
    ))
    assert len(members) == 3
    primary = [m for m in members if m["is_cluster_primary"]]
    assert len(primary) == 1 and primary[0]["id"] == ids[0]
    cluster_row = conn.execute(
        "SELECT member_count FROM clusters WHERE id = ?", [cluster_id]
    ).fetchone()
    assert cluster_row["member_count"] == 3


def test_upsert_embedding_writes_and_replaces(conn):
    db.init_schema(conn)
    rid = db.upsert_article(conn, {
        "canonical_url": "https://x/1", "title": "T", "summary": "",
        "source_slug": "x", "source_title": "X", "lang": "en",
        "published": None, "fetched_at": "2026-05-25T11:00:00Z",
        "first_seen_date": "2026-05-25",
    })
    db.upsert_embedding(conn, rid, b"\x00" * 1536, "test-model", "2026-05-25T12:00:00Z")
    row = conn.execute("SELECT embedding, model FROM article_embeddings WHERE article_id=?", [rid]).fetchone()
    assert len(row["embedding"]) == 1536
    assert row["model"] == "test-model"
    # Replace
    db.upsert_embedding(conn, rid, b"\xff" * 1536, "new-model", "2026-05-25T13:00:00Z")
    row = conn.execute("SELECT embedding, model FROM article_embeddings WHERE article_id=?", [rid]).fetchone()
    assert row["model"] == "new-model"
    assert row["embedding"][0] == 0xff


def test_upsert_brief_replaces_on_conflict(conn):
    db.init_schema(conn)
    db.upsert_brief(conn, date="2026-05-25", category="vuln",
                    text="first version", article_count=3,
                    generated_at="2026-05-25T12:00:00Z")
    db.upsert_brief(conn, date="2026-05-25", category="vuln",
                    text="second version", article_count=5,
                    generated_at="2026-05-25T13:00:00Z")
    row = conn.execute(
        "SELECT text, article_count FROM daily_briefs WHERE date=? AND category=?",
        ["2026-05-25", "vuln"]
    ).fetchone()
    assert row["text"] == "second version"
    assert row["article_count"] == 5
