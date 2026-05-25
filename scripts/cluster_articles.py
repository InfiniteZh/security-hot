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

# Even with the cross-source guard, alternating-source chains
# A(X)→B(Y)→C(X)→D(Y) form transitive megaclusters at 0.85 because
# baseline cross-domain cosine on tech-domain titles sits in 0.70-0.85.
# Empirical: true cross-source mirrors in our data sit at 0.99-1.00
# (aggregators republishing literally identical titles). 0.95 keeps
# those while rejecting transitive noise. Paraphrases / translations
# we miss are rare and acceptable trade-off; raising recall on those
# would require sub-title features (NER, vendor extraction).
COSINE_THRESHOLD = 0.95


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


def _cluster_one_day_partition(rows: list, conn, now_iso: str) -> int:
    """Pure clustering pass on articles already filtered to one day.

    Cross-source only: two articles only union if they're from DIFFERENT
    source_slugs. 'Mirror' means same story reported by multiple sources;
    a single source posting 30 batch CVE notices (VulDB, NVD enumerators)
    is not a mirror — it's that source's high-throughput posting style.
    Without this guard, template-heavy feeds form huge clusters dominated
    by their own back-catalog.
    Returns number of new clusters created in this partition.
    """
    if len(rows) < 2:
        return 0
    ids = [r["id"] for r in rows]
    sources = [r.get("source_slug") or "" for r in rows]
    n = len(ids)
    M = np.zeros((n, 384), dtype=np.float32)
    for i, r in enumerate(rows):
        M[i] = np.frombuffer(r["embedding"], dtype=np.float32)
    sim = M @ M.T

    uf = UnionFind(ids)
    for i in range(n):
        row_sim = sim[i, i+1:]
        hits = np.where(row_sim >= COSINE_THRESHOLD)[0]
        for offset in hits:
            j = i + 1 + int(offset)
            if sources[i] == sources[j]:
                continue  # same-source pair — not a real mirror
            uf.union(ids[i], ids[j])

    members_by_root: dict = {}
    for r in rows:
        members_by_root.setdefault(uf.find(r["id"]), []).append(dict(r))

    n_clusters = 0
    for _root_id, group in members_by_root.items():
        if len(group) < 2:
            continue
        # Final guard: a cluster must span ≥2 distinct sources. Without
        # this, a same-source chain could still get pulled in indirectly
        # via a 3-source A↔B↔C path where B is the only outsider.
        distinct_sources = {g.get("source_slug") or "" for g in group}
        if len(distinct_sources) < 2:
            continue
        primary_id = _pick_primary(group)
        mirror_ids = [g["id"] for g in group if g["id"] != primary_id]
        db.create_cluster(conn, primary_id=primary_id, mirror_ids=mirror_ids, created_at=now_iso)
        n_clusters += 1
    return n_clusters


def cluster_articles_in_db(
    *,
    db_path=None,
    window_hours: int = 72,
    now_iso: str | None = None,
) -> int:
    """Cluster mirror articles using cosine similarity on pre-computed embeddings.

    Partitions by **publish day** (COALESCE(published, fetched_at) → YYYY-MM-DD).
    Each day is clustered independently — a mirror campaign across days
    won't form a transitive supercluster, and the per-partition N
    (typically 500-1500/day) keeps the pairwise matrix small.

    Idempotent: only considers articles where cluster_id IS NULL.
    Requires embed_articles.py to have run first; articles without
    embeddings are silently skipped.
    """
    if now_iso is None:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat().replace("+00:00", "Z")
    conn = db.connect(db_path)
    db.init_schema(conn)
    try:
        # Bucket by publish day; SQLite date() handles both ISO 'T' and ' ' formats.
        rows_by_day: dict[str, list] = {}
        for r in conn.execute("""
            SELECT a.id, a.title, a.lang, a.source_slug, a.fetched_at, e.embedding,
                   substr(COALESCE(a.published, a.fetched_at), 1, 10) AS pub_day
            FROM articles a
            JOIN article_embeddings e ON e.article_id = a.id
            WHERE a.fetched_at >= ? AND a.cluster_id IS NULL
        """, [cutoff]):
            rows_by_day.setdefault(r["pub_day"], []).append(dict(r))

        total_new = 0
        for day in sorted(rows_by_day.keys()):
            day_rows = rows_by_day[day]
            n_new = _cluster_one_day_partition(day_rows, conn, now_iso)
            if n_new > 0 or len(day_rows) > 5:
                print(f"[cluster] {day}: {len(day_rows)} articles → {n_new} clusters", file=sys.stderr)
            total_new += n_new
        return total_new
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
