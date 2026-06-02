"""cluster_articles.py: cosine-similarity clustering + primary selection.

Jaccard / shingle tests have been removed — the algorithm now uses
multilingual-e5-small embeddings (see embed_articles.py).

Integration tests inject hand-crafted embeddings directly so they don't
require loading the model (~470 MB download).
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import cluster_articles as ca  # noqa: E402
import db  # noqa: E402


# ---------------------------------------------------------------------------
# UnionFind unit tests (algorithm-level, no DB needed)
# ---------------------------------------------------------------------------

def test_union_find_single_element():
    uf = ca.UnionFind([1])
    assert uf.find(1) == 1


def test_union_find_two_elements_union():
    uf = ca.UnionFind([1, 2])
    uf.union(1, 2)
    assert uf.find(1) == uf.find(2)


def test_union_find_path_compression():
    uf = ca.UnionFind([1, 2, 3])
    uf.union(1, 2)
    uf.union(2, 3)
    assert uf.find(1) == uf.find(3)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _insert_article_with_embedding(conn, url, title, lang, vec: np.ndarray, source_slug=None):
    # Derive a distinct source per URL by default: clustering's cross-source
    # guard (cluster.py) only unions articles from DIFFERENT source_slugs, since
    # a "mirror" means the same story reported by multiple outlets. Hardcoding a
    # single source would (correctly) suppress all clustering.
    slug = source_slug or urlparse(url).netloc or url
    rid = db.upsert_article(conn, {
        "canonical_url": url, "title": title, "summary": "",
        "source_slug": slug, "source_title": slug.upper(), "lang": lang,
        "published": None, "fetched_at": "2026-05-25T11:00:00Z",
        "first_seen_date": "2026-05-25",
    })
    db.upsert_embedding(conn, rid, vec.tobytes(), "test-model", "2026-05-25T12:00:00Z")
    return rid


# ---------------------------------------------------------------------------
# Core clustering logic tests (inject embeddings, no model load)
# ---------------------------------------------------------------------------

def test_cluster_groups_by_cosine_similarity(tmp_db):
    """Don't load model — inject hand-crafted embeddings to test clustering logic."""
    db.init_schema(db.connect(tmp_db))
    c = db.connect(tmp_db)
    # Three articles: A and B similar (same vector), C orthogonal
    v_ab = np.array([1.0] + [0.0] * 383, dtype=np.float32)
    v_c = np.array([0.0, 1.0] + [0.0] * 382, dtype=np.float32)
    pairs = [
        ("https://a/1", "Microsoft patches Outlook", "en", v_ab),
        ("https://b/1", "微软修补 Outlook 漏洞", "zh", v_ab),  # same vec → should cluster
        ("https://c/1", "Cooking pasta", "en", v_c),
    ]
    ids = []
    for url, title, lang, vec in pairs:
        ids.append(_insert_article_with_embedding(c, url, title, lang, vec))
    c.close()
    n = ca.cluster_articles_in_db(db_path=tmp_db, window_hours=72, now_iso="2026-05-25T13:00:00Z")
    assert n == 1
    c = db.connect(tmp_db)
    primary = c.execute("SELECT canonical_url, lang FROM articles WHERE is_cluster_primary = 1").fetchone()
    assert primary["lang"] == "zh"  # zh wins
    c.close()


def test_cluster_no_clusters_when_all_orthogonal(tmp_db):
    """Orthogonal vectors should produce zero clusters."""
    db.init_schema(db.connect(tmp_db))
    c = db.connect(tmp_db)
    vecs = [
        np.array([1.0] + [0.0] * 383, dtype=np.float32),
        np.array([0.0, 1.0] + [0.0] * 382, dtype=np.float32),
        np.array([0.0, 0.0, 1.0] + [0.0] * 381, dtype=np.float32),
    ]
    for i, vec in enumerate(vecs):
        _insert_article_with_embedding(c, f"https://x/{i}", f"Title {i}", "en", vec)
    c.close()
    n = ca.cluster_articles_in_db(db_path=tmp_db, window_hours=72, now_iso="2026-05-25T13:00:00Z")
    assert n == 0


def test_union_find_groups_3_similar_articles(tmp_db):
    """End-to-end: 3 articles with the same embedding vector → 1 cluster of 3."""
    db.init_schema(db.connect(tmp_db))
    c = db.connect(tmp_db)
    v = np.array([1.0] + [0.0] * 383, dtype=np.float32)
    v_unrelated = np.array([0.0, 1.0] + [0.0] * 382, dtype=np.float32)
    articles = [
        ("https://a.com/1", "Microsoft patches Outlook RCE vulnerability", "en", v),
        ("https://b.com/1", "Microsoft patches Outlook RCE vulnerability bug", "en", v),
        ("https://c.com/1", "Microsoft patches Outlook RCE vulnerability today", "en", v),
        ("https://d.com/1", "completely unrelated article about coffee", "en", v_unrelated),
    ]
    for url, title, lang, vec in articles:
        _insert_article_with_embedding(c, url, title, lang, vec)
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
    # Same vector → guaranteed to cluster
    v = np.array([1.0] + [0.0] * 383, dtype=np.float32)
    db.upsert_article(c, {
        "canonical_url": "https://en.com/x",
        "title": "Apache Struts critical vulnerability disclosure",
        "summary": "",
        "source_slug": "en", "source_title": "EN", "lang": "en",
        "published": None, "fetched_at": "2026-05-25T10:00:00Z",
        "first_seen_date": "2026-05-25",
    })
    en_id = c.execute("SELECT id FROM articles WHERE canonical_url='https://en.com/x'").fetchone()["id"]
    db.upsert_embedding(c, en_id, v.tobytes(), "test-model", "2026-05-25T12:00:00Z")

    db.upsert_article(c, {
        "canonical_url": "https://zh.com/x",
        "title": "Apache Struts critical vulnerability disclosure today",
        "summary": "",
        "source_slug": "zh", "source_title": "ZH", "lang": "zh",
        "published": None, "fetched_at": "2026-05-25T10:30:00Z",  # later than EN
        "first_seen_date": "2026-05-25",
    })
    zh_id = c.execute("SELECT id FROM articles WHERE canonical_url='https://zh.com/x'").fetchone()["id"]
    db.upsert_embedding(c, zh_id, v.tobytes(), "test-model", "2026-05-25T12:00:00Z")
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
    v = np.array([1.0] + [0.0] * 383, dtype=np.float32)
    for url, title in [
        ("https://a/1", "Microsoft patches Outlook RCE vulnerability"),
        ("https://b/1", "Microsoft patches Outlook RCE vulnerability bug"),
    ]:
        _insert_article_with_embedding(c, url, title, "en", v)
    c.close()

    ca.cluster_articles_in_db(db_path=tmp_db, window_hours=72,
                              now_iso="2026-05-25T12:00:00Z")
    ca.cluster_articles_in_db(db_path=tmp_db, window_hours=72,
                              now_iso="2026-05-25T12:00:00Z")
    c = db.connect(tmp_db)
    n_clusters = c.execute("SELECT COUNT(*) FROM clusters").fetchone()[0]
    assert n_clusters == 1
    c.close()
