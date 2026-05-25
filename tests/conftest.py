"""Shared pytest fixtures for security-hot."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Path to an empty SQLite file in a per-test tmp directory."""
    return tmp_path / "news.db"


@pytest.fixture
def conn(tmp_db: Path) -> sqlite3.Connection:
    """Open WAL-mode SQLite connection on a per-test DB."""
    c = sqlite3.connect(str(tmp_db))
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode = WAL")
    c.execute("PRAGMA foreign_keys = ON")
    yield c
    c.close()


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    """A clean cache directory for tests touching backend/cache."""
    p = tmp_path / "cache"
    p.mkdir()
    return p


@pytest.fixture
def archive_dir(tmp_path: Path) -> Path:
    """A clean archive directory for NDJSON dumps."""
    p = tmp_path / "archive" / "news"
    p.mkdir(parents=True)
    return p
