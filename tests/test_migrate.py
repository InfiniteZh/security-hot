"""migrate_to_sqlite.py: one-time news.json + daily_brief.json → news.db."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import db  # noqa: E402
import migrate_to_sqlite as migrate  # noqa: E402


def _write_news_json(cache_dir: Path, articles: list[dict]) -> Path:
    p = cache_dir / "news.json"
    p.write_text(json.dumps({"articles": articles, "sources": [], "fetched_at": "2026-05-25T12:00:00Z"}))
    return p


def test_migrate_news_articles_populates_articles_table(tmp_db: Path, cache_dir: Path):
    _write_news_json(cache_dir, [
        {"title": "T1", "link": "https://a.com/1", "summary": "S1",
         "source_slug": "s1", "source_title": "S1 Title", "lang": "en",
         "published": "2026-05-25T10:00:00Z",
         "llm_score": 7, "llm_category": "vuln", "llm_reason": "RCE"},
        {"title": "T2", "link": "https://a.com/2", "summary": "S2",
         "source_slug": "s2", "source_title": "S2 Title", "lang": "zh",
         "published": "2026-05-25T11:00:00Z"},
    ])
    migrate.run(db_path=tmp_db, cache_dir=cache_dir, force=False)
    c = db.connect(tmp_db)
    rows = list(c.execute("SELECT title, llm_score, llm_category FROM articles ORDER BY title"))
    assert len(rows) == 2
    assert rows[0]["title"] == "T1"
    assert rows[0]["llm_score"] == 7
    assert rows[0]["llm_category"] == "vuln"
    assert rows[1]["llm_score"] is None
    c.close()


def test_migrate_refuses_without_force_when_db_exists(tmp_db: Path, cache_dir: Path):
    _write_news_json(cache_dir, [])
    tmp_db.write_text("")  # any non-empty file triggers the check
    with pytest.raises(SystemExit) as exc:
        migrate.run(db_path=tmp_db, cache_dir=cache_dir, force=False)
    assert exc.value.code != 0


def test_migrate_force_overwrites_existing_db(tmp_db: Path, cache_dir: Path):
    _write_news_json(cache_dir, [
        {"title": "T1", "link": "https://a.com/1", "summary": "",
         "source_slug": "s", "source_title": "S", "lang": "en", "published": None},
    ])
    tmp_db.write_text("garbage")
    migrate.run(db_path=tmp_db, cache_dir=cache_dir, force=True)
    c = db.connect(tmp_db)
    n = c.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
    assert n == 1
    c.close()
