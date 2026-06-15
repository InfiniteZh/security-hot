"""Tests for news→vuln bridge: extracting CVE entries from news.db."""
import json
import sqlite3
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# The bridge only considers articles published within the last 7 days
# (`published >= date('now','-7 days')`). Anchor the seed data to "yesterday"
# so the fixture stays inside that rolling window no matter when the test runs.
_RECENT_DAY = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")


def _seed_db(db_path: Path) -> None:
    """Create a minimal news.db with articles containing CVE-IDs."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE IF NOT EXISTS articles (
        id INTEGER PRIMARY KEY,
        canonical_url TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        summary TEXT,
        source_slug TEXT NOT NULL,
        source_title TEXT,
        lang TEXT,
        rss_category TEXT,
        published TEXT,
        fetched_at TEXT NOT NULL,
        first_seen_date TEXT,
        llm_score INTEGER,
        llm_category TEXT,
        llm_reason TEXT,
        is_relevant BOOLEAN,
        llm_scored_at TEXT,
        llm_summary_zh TEXT,
        llm_summarized_at TEXT
    )""")
    articles = [
        ("https://vuldb.com/1", "CVE-2026-1111 | Apache HTTP Server path traversal",
         "A path traversal vulnerability...", "vuldb_com", "VulDB", "en",
         f"{_RECENT_DAY}T10:00:00Z", f"{_RECENT_DAY}T10:00:00Z"),
        ("https://vulners.com/1", "CVE-2026-1111",
         "Apache HTTP Server vuln", "vulners_com", "Vulners", "en",
         f"{_RECENT_DAY}T09:00:00Z", f"{_RECENT_DAY}T09:00:00Z"),
        ("https://vulners.com/2", "CVE-2026-2222",
         "Chrome RCE", "vulners_com", "Vulners", "en",
         f"{_RECENT_DAY}T11:00:00Z", f"{_RECENT_DAY}T11:00:00Z"),
        ("https://sploitus.com/1", "Exploit for CVE-2026-2222",
         "PoC exploit for Chrome", "sploitus_com", "Sploitus", "en",
         f"{_RECENT_DAY}T11:30:00Z", f"{_RECENT_DAY}T11:30:00Z"),
        ("https://bleeping.com/1", "CVE-2026-9999 exploited in wild",
         "Article about CVE", "bleeping_com", "BleepingComputer", "en",
         f"{_RECENT_DAY}T12:00:00Z", f"{_RECENT_DAY}T12:00:00Z"),
    ]
    for url, title, summary, slug, stitle, lang, pub, fetched in articles:
        conn.execute(
            "INSERT OR IGNORE INTO articles (canonical_url, title, summary, source_slug, source_title, lang, published, fetched_at) VALUES (?,?,?,?,?,?,?,?)",
            [url, title, summary, slug, stitle, lang, pub, fetched],
        )
    conn.commit()
    conn.close()


def test_news_cve_bridge_extracts_cves(tmp_path):
    db_path = tmp_path / "news.db"
    _seed_db(db_path)

    from backend.app.data import _news_cve_to_vulns
    vulns = _news_cve_to_vulns(db_path=db_path)

    cve_ids = {v.cve_id for v in vulns}
    assert "CVE-2026-1111" in cve_ids
    assert "CVE-2026-2222" in cve_ids
    assert "CVE-2026-9999" not in cve_ids


def test_news_cve_bridge_multi_source_tags(tmp_path):
    db_path = tmp_path / "news.db"
    _seed_db(db_path)

    from backend.app.data import _news_cve_to_vulns
    vulns = _news_cve_to_vulns(db_path=db_path)

    by_cve = {v.cve_id: v for v in vulns}
    v1111 = by_cve["CVE-2026-1111"]
    assert "Apache" in v1111.title or "path traversal" in v1111.title
    assert v1111.hn_mentions == 0
    assert len(v1111.references) >= 2
    assert v1111.source == "news-bridge"


def test_news_cve_bridge_empty_db(tmp_path):
    db_path = tmp_path / "news.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE IF NOT EXISTS articles (
        id INTEGER PRIMARY KEY, canonical_url TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL, summary TEXT, source_slug TEXT NOT NULL,
        source_title TEXT, lang TEXT, rss_category TEXT, published TEXT,
        fetched_at TEXT NOT NULL, first_seen_date TEXT,
        llm_score INTEGER, llm_category TEXT, llm_reason TEXT,
        is_relevant BOOLEAN, llm_scored_at TEXT, llm_summary_zh TEXT,
        llm_summarized_at TEXT
    )""")
    conn.commit()
    conn.close()

    from backend.app.data import _news_cve_to_vulns
    vulns = _news_cve_to_vulns(db_path=db_path)
    assert vulns == []
