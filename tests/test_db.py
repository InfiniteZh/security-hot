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
