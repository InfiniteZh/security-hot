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
    is_cluster_primary  BOOLEAN DEFAULT 0,
    FOREIGN KEY (cluster_id) REFERENCES clusters(id)
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
    created_at          TEXT NOT NULL,
    FOREIGN KEY (primary_article_id) REFERENCES articles(id)
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


SOURCE_UPSERT_COLS = ["slug", "title", "url", "lang", "tier", "interval_minutes"]


def upsert_source(conn: sqlite3.Connection, row: dict) -> None:
    """INSERT-or-UPDATE source. Preserves last_fetched/last_etag/last_modified
    on conflict so that re-importing the source list doesn't reset polling
    state."""
    placeholders = ",".join("?" for _ in SOURCE_UPSERT_COLS)
    col_list = ",".join(SOURCE_UPSERT_COLS)
    update_clause = ", ".join(
        f"{c} = excluded.{c}" for c in SOURCE_UPSERT_COLS if c != "slug"
    )
    conn.execute(
        f"""INSERT INTO sources ({col_list}) VALUES ({placeholders})
            ON CONFLICT(slug) DO UPDATE SET {update_clause}""",
        [row.get(c) for c in SOURCE_UPSERT_COLS],
    )
    conn.commit()


def due_sources(conn: sqlite3.Connection, now_iso: str) -> list[sqlite3.Row]:
    """Return sources whose last_fetched + interval_minutes <= now, that are
    not in a failed (>=5 consecutive failures) state."""
    return list(conn.execute("""
        SELECT * FROM sources
        WHERE ok = 1
          AND consecutive_failures < 5
          AND (last_fetched IS NULL
               OR datetime(last_fetched, '+' || interval_minutes || ' minutes') <= datetime(?))
        ORDER BY (last_fetched IS NULL) DESC, last_fetched ASC
    """, [now_iso]))


def record_source_fetch(
    conn: sqlite3.Connection,
    slug: str,
    *,
    now: str,
    etag: str | None,
    last_modified: str | None,
    ok: bool,
    error: str | None = None,
) -> None:
    """Update polling state after a fetch attempt. On success, reset
    consecutive_failures; on failure, increment it."""
    if ok:
        conn.execute("""
            UPDATE sources SET
              last_fetched = ?, last_etag = ?, last_modified = ?,
              ok = 1, error = NULL, consecutive_failures = 0
            WHERE slug = ?
        """, [now, etag, last_modified, slug])
    else:
        conn.execute("""
            UPDATE sources SET
              last_fetched = ?, ok = 0, error = ?,
              consecutive_failures = consecutive_failures + 1
            WHERE slug = ?
        """, [now, error, slug])
    conn.commit()


def create_cluster(
    conn: sqlite3.Connection,
    *,
    primary_id: int,
    mirror_ids: list[int],
    created_at: str,
) -> int:
    """Create a cluster row + link primary and mirror articles in one txn.

    Use defer_foreign_keys to handle the articles<->clusters cycle.
    """
    member_count = 1 + len(mirror_ids)
    conn.execute("PRAGMA defer_foreign_keys = ON")
    cur = conn.execute(
        "INSERT INTO clusters (primary_article_id, member_count, created_at) VALUES (?, ?, ?)",
        [primary_id, member_count, created_at],
    )
    cluster_id = cur.lastrowid
    conn.execute(
        "UPDATE articles SET cluster_id = ?, is_cluster_primary = 1 WHERE id = ?",
        [cluster_id, primary_id],
    )
    if mirror_ids:
        placeholders = ",".join("?" for _ in mirror_ids)
        conn.execute(
            f"UPDATE articles SET cluster_id = ?, is_cluster_primary = 0 WHERE id IN ({placeholders})",
            [cluster_id, *mirror_ids],
        )
    conn.commit()
    return cluster_id


def upsert_brief(
    conn: sqlite3.Connection,
    *,
    date: str,
    category: str,
    text: str,
    article_count: int,
    generated_at: str,
) -> None:
    """INSERT OR REPLACE — re-running on the same (date, category) overwrites."""
    conn.execute("""
        INSERT INTO daily_briefs (date, category, text, article_count, generated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(date, category) DO UPDATE SET
          text = excluded.text,
          article_count = excluded.article_count,
          generated_at = excluded.generated_at
    """, [date, category, text, article_count, generated_at])
    conn.commit()
