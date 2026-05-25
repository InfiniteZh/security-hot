"""Mirror clustering: group articles whose titles are semantically similar.

Algorithm: cosine similarity on multilingual-e5-small embeddings (384-dim),
threshold 0.85. Embeddings must be pre-computed by embed_articles.py — this
script only reads from article_embeddings and writes clusters.

Cross-lingual mirrors (e.g. "微软修补 Outlook RCE" ↔ "Microsoft patches
Outlook RCE") are caught because the embedding space is language-agnostic.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

import db

COSINE_THRESHOLD = 0.85


class UnionFind:
    """Standard union-find with path compression + union by rank."""
    def __init__(self, items):
        self.parent = {x: x for x in items}
        self.rank = {x: 0 for x in items}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, x, y):
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self.rank[rx] < self.rank[ry]:
            rx, ry = ry, rx
        self.parent[ry] = rx
        if self.rank[rx] == self.rank[ry]:
            self.rank[rx] += 1


def _pick_primary(group: list[dict]) -> int:
    """Pick the primary article id for a cluster.

    Rules (in order):
      1. lang='zh' beats lang='en'
      2. Within same lang, earliest fetched_at wins
    """
    def sort_key(row):
        is_zh = 0 if row.get("lang") == "zh" else 1  # zh first
        return (is_zh, row.get("fetched_at") or "9999")
    return sorted(group, key=sort_key)[0]["id"]


def cluster_articles_in_db(
    *,
    db_path=None,
    window_hours: int = 72,
    now_iso: str | None = None,
) -> int:
    """Find mirror clusters within the last `window_hours` using cosine similarity
    on pre-computed embeddings and write them to the DB.

    Idempotent: articles already in a cluster (cluster_id IS NOT NULL) are
    skipped; the function only considers fresh articles.

    Requires embed_articles.py to have been run first — articles without
    embeddings are silently skipped (they won't cluster).

    Returns the number of new clusters created.
    """
    if now_iso is None:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat().replace("+00:00", "Z")
    conn = db.connect(db_path)
    db.init_schema(conn)  # idempotent — keeps schema in sync if DB pre-dates a table
    try:
        # Pull articles with embeddings (skip unembedded — must run embed_articles first)
        rows = list(conn.execute("""
            SELECT a.id, a.title, a.lang, a.fetched_at, e.embedding
            FROM articles a
            JOIN article_embeddings e ON e.article_id = a.id
            WHERE a.fetched_at >= ? AND a.cluster_id IS NULL
        """, [cutoff]))
        if len(rows) < 2:
            return 0

        # Build matrix
        ids = [r["id"] for r in rows]
        n = len(ids)
        # Embeddings are already L2-normalized (encode(normalize_embeddings=True))
        # so dot product == cosine similarity.
        M = np.zeros((n, 384), dtype=np.float32)
        for i, r in enumerate(rows):
            M[i] = np.frombuffer(r["embedding"], dtype=np.float32)

        # Full pairwise: n x n. At n=15000 this is 900MB float32 — okay on a
        # workstation; if memory tightens use chunked computation.
        sim = M @ M.T  # cosine similarity matrix

        uf = UnionFind(ids)
        # Iterate upper triangle, union pairs above threshold
        for i in range(n):
            # Mask self + already-paired to keep loop tight
            row_sim = sim[i, i+1:]
            hits = np.where(row_sim >= COSINE_THRESHOLD)[0]
            for offset in hits:
                j = i + 1 + int(offset)
                uf.union(ids[i], ids[j])

        # Group + write
        members_by_root: dict = {}
        for r in rows:
            members_by_root.setdefault(uf.find(r["id"]), []).append(dict(r))

        n_clusters = 0
        for root_id, group in members_by_root.items():
            if len(group) < 2:
                continue
            primary_id = _pick_primary(group)
            mirror_ids = [g["id"] for g in group if g["id"] != primary_id]
            db.create_cluster(conn, primary_id=primary_id, mirror_ids=mirror_ids, created_at=now_iso)
            n_clusters += 1
        return n_clusters
    finally:
        conn.close()


def main() -> int:
    p = argparse.ArgumentParser(description="Mirror-cluster articles by embedding cosine similarity.")
    p.add_argument("--window", type=int, default=72, help="Look-back window in hours")
    p.add_argument("--db", default=None)
    args = p.parse_args()
    n = cluster_articles_in_db(
        db_path=Path(args.db) if args.db else None,
        window_hours=args.window,
    )
    print(f"[cluster] {n} new clusters created", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
