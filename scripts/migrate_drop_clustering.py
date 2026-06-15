"""One-shot migration: remove the embedding/mirror-clustering feature from news.db.

Drops the `article_embeddings` and `clusters` tables plus the
`articles.cluster_id` / `articles.is_cluster_primary` columns and their index.
Idempotent and safe to re-run: each step is guarded by an existence check.

Fresh deploys never need this — db.init_schema() simply no longer creates those
objects. It only matters for an existing news.db that predates the removal.

    uv run python scripts/migrate_drop_clustering.py
    uv run python scripts/migrate_drop_clustering.py --db /path/to/news.db
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import db  # noqa: E402


def _has_table(conn, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", [name]
    ).fetchone() is not None


def _has_column(conn, table: str, col: str) -> bool:
    return any(r["name"] == col for r in conn.execute(f"PRAGMA table_info({table})"))


_DROP_COLS = ("cluster_id", "is_cluster_primary")


def _unique_single_cols(conn, table: str) -> set[str]:
    """Single-column UNIQUE constraints (origin='u'), which PRAGMA table_info
    does not report. Needed so the rebuilt table keeps canonical_url UNIQUE."""
    out: set[str] = set()
    for idx in conn.execute(f"PRAGMA index_list({table})"):
        if idx["origin"] != "u":
            continue
        cols = list(conn.execute(f"PRAGMA index_info({idx['name']})"))
        if len(cols) == 1:
            out.add(cols[0]["name"])
    return out


def _rebuild_articles_without_cluster_cols(conn) -> bool:
    """Drop the FK-bearing cluster columns via a full table rebuild.

    SQLite refuses ALTER TABLE DROP COLUMN on a column named in a FOREIGN KEY
    clause (cluster_id → clusters), so we recreate the table without those two
    columns and without the FK, preserving every other column / constraint and
    all `id` values (FTS external-content stays consistent). Returns True if a
    rebuild happened, False if the columns were already gone."""
    if not any(_has_column(conn, "articles", c) for c in _DROP_COLS):
        return False
    info = list(conn.execute("PRAGMA table_info(articles)"))
    unique = _unique_single_cols(conn, "articles")
    keep = [r for r in info if r["name"] not in _DROP_COLS]
    defs = []
    for r in keep:
        piece = f"{r['name']} {r['type']}"
        if r["pk"]:
            piece += " PRIMARY KEY"
        if r["notnull"] and not r["pk"]:
            piece += " NOT NULL"
        if r["name"] in unique:
            piece += " UNIQUE"
        if r["dflt_value"] is not None:
            piece += f" DEFAULT {r['dflt_value']}"
        defs.append(piece)
    col_list = ", ".join(r["name"] for r in keep)
    conn.execute("CREATE TABLE articles_new (\n  " + ",\n  ".join(defs) + "\n)")
    conn.execute(f"INSERT INTO articles_new ({col_list}) SELECT {col_list} FROM articles")
    conn.execute("DROP TABLE articles")
    conn.execute("ALTER TABLE articles_new RENAME TO articles")
    return True


def migrate(db_path=None) -> dict:
    conn = db.connect(db_path)
    # FKs off: dropping the clusters parent table referenced by articles.cluster_id,
    # and rebuilding articles, would otherwise trip constraints mid-migration.
    conn.execute("PRAGMA foreign_keys = OFF")
    done: list[str] = []
    try:
        for idx in ("idx_cluster", "idx_emb_model"):
            conn.execute(f"DROP INDEX IF EXISTS {idx}")
        for tbl in ("article_embeddings", "clusters"):
            if _has_table(conn, tbl):
                conn.execute(f"DROP TABLE {tbl}")
                done.append(f"table:{tbl}")
        if _rebuild_articles_without_cluster_cols(conn):
            done.append("columns:articles.cluster_id,is_cluster_primary")
        conn.commit()
        # Recreate the indexes + FTS triggers the rebuild dropped (idempotent).
        db.init_schema(conn)
        conn.execute("PRAGMA foreign_key_check")
    finally:
        conn.close()
    print(f"[migrate] dropped: {', '.join(done) if done else '(nothing — already clean)'}",
          file=sys.stderr)
    return {"dropped": done}


def main() -> int:
    p = argparse.ArgumentParser(description="Drop clustering/embedding objects from news.db.")
    p.add_argument("--db", default=None)
    args = p.parse_args()
    migrate(Path(args.db) if args.db else None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
