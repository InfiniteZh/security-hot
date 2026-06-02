"""embed_articles.py: embed + store roundtrip.

Marked slow — downloads ~470MB model on first run."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import db
import embed_articles


@pytest.mark.slow
def test_embed_and_cluster_roundtrip(tmp_db, monkeypatch):
    """Embed two near-duplicate titles, verify their cosine sim is high."""
    db.init_schema(db.connect(tmp_db))
    c = db.connect(tmp_db)
    pairs = [
        ("https://a/1", "Microsoft patches critical Outlook RCE vulnerability"),
        ("https://b/1", "Microsoft fixes critical Outlook RCE flaw"),
        ("https://c/1", "Cooking pasta in 10 minutes"),
    ]
    fetched_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    ids = []
    for url, title in pairs:
        ids.append(db.upsert_article(c, {
            "canonical_url": url, "title": title, "summary": "",
            "source_slug": "x", "source_title": "X", "lang": "en",
            "published": None, "fetched_at": fetched_at,
            "first_seen_date": "2026-05-25",
        }))
    c.close()

    class FakeModel:
        def encode(self, texts, **kwargs):
            base = np.zeros(embed_articles.EMBEDDING_DIM, dtype=np.float32)
            base[0] = 1.0
            near = np.zeros(embed_articles.EMBEDDING_DIM, dtype=np.float32)
            near[0] = 0.95
            near[1] = 0.3122499
            far = np.zeros(embed_articles.EMBEDDING_DIM, dtype=np.float32)
            far[2] = 1.0
            vectors = [base, near, far]
            return np.array(vectors[:len(texts)])

    monkeypatch.setattr(embed_articles, "_load_model", lambda: FakeModel())
    n = embed_articles.embed_unembedded_articles(db_path=tmp_db, window_hours=72, verbose=False)
    assert n == 3

    c = db.connect(tmp_db)
    blobs = {r["article_id"]: r["embedding"] for r in c.execute("SELECT article_id, embedding FROM article_embeddings")}
    c.close()
    assert len(blobs) == 3
    vecs = {aid: embed_articles._from_blob(b) for aid, b in blobs.items()}
    sim_ab = float(np.dot(vecs[ids[0]], vecs[ids[1]]))   # already normalized
    sim_ac = float(np.dot(vecs[ids[0]], vecs[ids[2]]))
    assert sim_ab > 0.85, f"near-duplicate sim too low: {sim_ab}"
    assert sim_ac < 0.6, f"unrelated sim too high: {sim_ac}"
