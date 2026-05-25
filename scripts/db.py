"""SQLite helpers for the news pipeline.

Single-file source of truth for connection management, schema, and CRUD
helpers for articles / sources / clusters / daily_briefs.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = ROOT / "backend" / "cache" / "news.db"


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS articles (
    id              INTEGER PRIMARY KEY,
    canonical_url   TEXT    UNIQUE NOT NULL,
    title           TEXT    NOT NULL,
    summary         TEXT,
    source_slug     TEXT    NOT NULL,
    source_title    TEXT,
    lang            TEXT,
    rss_category    TEXT,
    published       TEXT,
    fetched_at      TEXT    NOT NULL,
    first_seen_date TEXT,
    llm_score          INTEGER,
    llm_category       TEXT,
    llm_reason         TEXT,
    is_relevant        BOOLEAN,
    llm_scored_at      TEXT,
    llm_summary_zh     TEXT,
    llm_summarized_at  TEXT,
    cluster_id          INTEGER,
    is_cluster_primary  BOOLEAN DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_published     ON articles(published DESC);
CREATE INDEX IF NOT EXISTS idx_score         ON articles(llm_score DESC, published DESC);
CREATE INDEX IF NOT EXISTS idx_category      ON articles(llm_category);
CREATE INDEX IF NOT EXISTS idx_cluster       ON articles(cluster_id);
CREATE INDEX IF NOT EXISTS idx_first_seen    ON articles(first_seen_date);
CREATE INDEX IF NOT EXISTS idx_is_relevant   ON articles(is_relevant);

CREATE TABLE IF NOT EXISTS sources (
    slug             TEXT PRIMARY KEY,
    title            TEXT,
    url              TEXT NOT NULL,
    lang             TEXT,
    tier             TEXT NOT NULL DEFAULT 'tail',
    interval_minutes INTEGER NOT NULL,
    last_fetched     TEXT,
    last_etag        TEXT,
    last_modified    TEXT,
    ok               BOOLEAN DEFAULT 1,
    error            TEXT,
    consecutive_failures INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS clusters (
    id                  INTEGER PRIMARY KEY,
    primary_article_id  INTEGER NOT NULL,
    member_count        INTEGER NOT NULL,
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS daily_briefs (
    date           TEXT NOT NULL,
    category       TEXT NOT NULL,
    text           TEXT NOT NULL,
    article_count  INTEGER NOT NULL,
    generated_at   TEXT NOT NULL,
    PRIMARY KEY (date, category)
);

CREATE VIRTUAL TABLE IF NOT EXISTS articles_fts USING fts5(
    title, summary, llm_summary_zh,
    content='articles', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);

CREATE TRIGGER IF NOT EXISTS articles_ai AFTER INSERT ON articles BEGIN
  INSERT INTO articles_fts(rowid, title, summary, llm_summary_zh)
  VALUES (new.id, new.title, new.summary, new.llm_summary_zh);
END;

CREATE TRIGGER IF NOT EXISTS articles_ad AFTER DELETE ON articles BEGIN
  INSERT INTO articles_fts(articles_fts, rowid, title, summary, llm_summary_zh)
  VALUES('delete', old.id, old.title, old.summary, old.llm_summary_zh);
END;

CREATE TRIGGER IF NOT EXISTS articles_au AFTER UPDATE ON articles BEGIN
  INSERT INTO articles_fts(articles_fts, rowid, title, summary, llm_summary_zh)
  VALUES('delete', old.id, old.title, old.summary, old.llm_summary_zh);
  INSERT INTO articles_fts(rowid, title, summary, llm_summary_zh)
  VALUES (new.id, new.title, new.summary, new.llm_summary_zh);
END;
"""


def connect(path: Path | str | None = None) -> sqlite3.Connection:
    """Open SQLite in WAL mode with sane pragmas. Caller owns close()."""
    target = Path(path) if path else DEFAULT_DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(target))
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode = WAL")
    c.execute("PRAGMA foreign_keys = ON")
    c.execute("PRAGMA synchronous = NORMAL")  # WAL + NORMAL = fast + safe
    return c


def init_schema(conn: sqlite3.Connection) -> None:
    """Create all tables, indexes, FTS table, and triggers. Idempotent."""
    conn.executescript(SCHEMA_SQL)
    conn.commit()


ARTICLE_INSERT_COLS = [
    "canonical_url", "title", "summary", "source_slug", "source_title",
    "lang", "rss_category", "published", "fetched_at", "first_seen_date",
]


def upsert_article(conn: sqlite3.Connection, row: dict) -> int:
    """INSERT-or-IGNORE on canonical_url. Returns the article id.

    LLM and cluster fields are NEVER touched by upsert — they are the
    sole responsibility of llm_rank.py and cluster_articles.py.
    """
    cols = ARTICLE_INSERT_COLS
    placeholders = ",".join("?" for _ in cols)
    col_list = ",".join(cols)
    values = [row.get(c) for c in cols]
    cur = conn.execute(
        f"INSERT OR IGNORE INTO articles ({col_list}) VALUES ({placeholders})",
        values,
    )
    if cur.lastrowid and cur.rowcount > 0:
        conn.commit()
        return cur.lastrowid
    # Row already existed — look up its id
    existing = conn.execute(
        "SELECT id FROM articles WHERE canonical_url = ?",
        [row["canonical_url"]],
    ).fetchone()
    return existing["id"] if existing else 0
