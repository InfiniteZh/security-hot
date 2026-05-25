"""cluster_articles.py: Jaccard 3-shingle algorithm + primary selection."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import cluster_articles as ca  # noqa: E402
import db  # noqa: E402


def test_shingles_3char():
    s = ca.shingles("abcdef")
    assert s == {"abc", "bcd", "cde", "def"}


def test_shingles_normalizes():
    """Lowercase + drops non-word chars."""
    a = ca.shingles("Hello, World!")
    b = ca.shingles("helloworld")
    assert a == b


def test_jaccard_identical_is_1():
    assert ca.jaccard({"a", "b"}, {"a", "b"}) == 1.0


def test_jaccard_disjoint_is_0():
    assert ca.jaccard({"a", "b"}, {"c", "d"}) == 0.0


def test_jaccard_partial():
    # |A ∩ B| = 1, |A ∪ B| = 3
    assert abs(ca.jaccard({"a", "b"}, {"b", "c"}) - 1/3) < 1e-9


def test_jaccard_empty_inputs():
    assert ca.jaccard(set(), set()) == 0.0


def test_titles_with_high_overlap_pass_threshold():
    """Similar titles should score well above 0.5 (3-char shingles, no spaces)."""
    a = ca.shingles("Microsoft patches Outlook RCE vulnerability")
    b = ca.shingles("Microsoft patches Outlook RCE flaw")
    assert ca.jaccard(a, b) >= 0.5


def test_translated_titles_do_not_pass_threshold():
    """Chinese vs English title for same event should NOT cluster."""
    zh = ca.shingles("微软修补 Outlook 远程代码执行漏洞")
    en = ca.shingles("Microsoft patches Outlook RCE vulnerability")
    assert ca.jaccard(zh, en) < 0.5


import pytest
from pathlib import Path


@pytest.fixture
def tmp_db(tmp_path):
    return tmp_path / "test.db"


def test_union_find_groups_3_similar_articles(tmp_db):
    """End-to-end: 3 articles with similar titles → 1 cluster of 3."""
    db.init_schema(db.connect(tmp_db))
    c = db.connect(tmp_db)
    base_titles = [
        ("https://a.com/1", "Microsoft patches Outlook RCE vulnerability", "en"),
        ("https://b.com/1", "Microsoft patches Outlook RCE vulnerability bug", "en"),
        ("https://c.com/1", "Microsoft patches Outlook RCE vulnerability today", "en"),
        ("https://d.com/1", "completely unrelated article about coffee", "en"),
    ]
    for url, title, lang in base_titles:
        db.upsert_article(c, {
            "canonical_url": url, "title": title, "summary": "",
            "source_slug": url.split("//")[1].split(".")[0],
            "source_title": "X", "lang": lang,
            "published": None, "fetched_at": "2026-05-25T11:00:00Z",
            "first_seen_date": "2026-05-25",
        })
    c.close()

    n_clusters = ca.cluster_articles_in_db(db_path=tmp_db,
                                          window_hours=72,
                                          now_iso="2026-05-25T12:00:00Z")
    assert n_clusters == 1

    c = db.connect(tmp_db)
    rows = list(c.execute(
        "SELECT canonical_url, cluster_id, is_cluster_primary FROM articles ORDER BY canonical_url"
    ))
    # 3 articles in the cluster, 1 unrelated
    in_cluster = [r for r in rows if r["cluster_id"] is not None]
    assert len(in_cluster) == 3
    primaries = [r for r in in_cluster if r["is_cluster_primary"]]
    assert len(primaries) == 1
    c.close()


def test_zh_articles_preferred_as_primary(tmp_db):
    """When mirror group has both zh and en articles, primary should be zh."""
    db.init_schema(db.connect(tmp_db))
    c = db.connect(tmp_db)
    db.upsert_article(c, {
        "canonical_url": "https://en.com/x", "title": "Apache Struts critical vulnerability disclosure", "summary": "",
        "source_slug": "en", "source_title": "EN", "lang": "en",
        "published": None, "fetched_at": "2026-05-25T10:00:00Z",
        "first_seen_date": "2026-05-25",
    })
    db.upsert_article(c, {
        "canonical_url": "https://zh.com/x", "title": "Apache Struts critical vulnerability disclosure today", "summary": "",
        "source_slug": "zh", "source_title": "ZH", "lang": "zh",
        "published": None, "fetched_at": "2026-05-25T10:30:00Z",  # later than EN
        "first_seen_date": "2026-05-25",
    })
    c.close()
    ca.cluster_articles_in_db(db_path=tmp_db, window_hours=72,
                              now_iso="2026-05-25T12:00:00Z")
    c = db.connect(tmp_db)
    primary = c.execute(
        "SELECT canonical_url FROM articles WHERE is_cluster_primary = 1"
    ).fetchone()
    assert primary["canonical_url"] == "https://zh.com/x"
    c.close()


def test_clustering_is_idempotent(tmp_db):
    """Re-running clustering does NOT create duplicate clusters."""
    db.init_schema(db.connect(tmp_db))
    c = db.connect(tmp_db)
    for url, title in [
        ("https://a/1", "Microsoft patches Outlook RCE vulnerability"),
        ("https://b/1", "Microsoft patches Outlook RCE vulnerability bug"),
    ]:
        db.upsert_article(c, {
            "canonical_url": url, "title": title, "summary": "",
            "source_slug": "x", "source_title": "X", "lang": "en",
            "published": None, "fetched_at": "2026-05-25T11:00:00Z",
            "first_seen_date": "2026-05-25",
        })
    c.close()
    ca.cluster_articles_in_db(db_path=tmp_db, window_hours=72,
                              now_iso="2026-05-25T12:00:00Z")
    ca.cluster_articles_in_db(db_path=tmp_db, window_hours=72,
                              now_iso="2026-05-25T12:00:00Z")
    c = db.connect(tmp_db)
    n_clusters = c.execute("SELECT COUNT(*) FROM clusters").fetchone()[0]
    assert n_clusters == 1
    c.close()
