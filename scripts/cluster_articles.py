"""Mirror clustering: group articles whose titles are highly similar.

Algorithm: 3-character shingles + Jaccard similarity, threshold 0.7.
Bucketed by title-head character to keep comparisons sub-quadratic.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import db


def shingles(title: str) -> set[str]:
    """3-character n-grams of the normalized title.

    Normalization: lowercase + strip non-word chars (keeps CJK, drops
    spaces/punctuation/emoji).
    """
    normalized = re.sub(r"\W", "", (title or "").lower())
    if len(normalized) < 3:
        return set()
    return {normalized[i:i+3] for i in range(len(normalized) - 2)}


def jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard similarity. 0 if both sets empty."""
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


JACCARD_THRESHOLD = 0.7


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
    """Find mirror clusters within the last `window_hours` and write them.

    Idempotent: articles already in a cluster (cluster_id IS NOT NULL) are
    skipped; the function only considers fresh articles.

    Returns the number of new clusters created.
    """
    if now_iso is None:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat().replace("+00:00", "Z")
    conn = db.connect(db_path)
    try:
        rows = list(conn.execute("""
            SELECT id, title, lang, fetched_at FROM articles
            WHERE fetched_at >= ? AND cluster_id IS NULL
        """, [cutoff]))
        if len(rows) < 2:
            return 0

        # Pre-compute shingles for each title and bucket by head char
        sigs = {r["id"]: shingles(r["title"]) for r in rows}
        buckets: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            title_norm = re.sub(r"\W", "", (r["title"] or "").lower())
            head = title_norm[0] if title_norm else "_"
            buckets[head].append(dict(r))

        uf = UnionFind([r["id"] for r in rows])

        for head, group in buckets.items():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    a, b = group[i]["id"], group[j]["id"]
                    if jaccard(sigs[a], sigs[b]) >= JACCARD_THRESHOLD:
                        uf.union(a, b)

        # Collect clusters of size >= 2
        members_by_root: dict[int, list[dict]] = defaultdict(list)
        for r in rows:
            members_by_root[uf.find(r["id"])].append(dict(r))

        n_clusters = 0
        for root_id, group in members_by_root.items():
            if len(group) < 2:
                continue
            primary_id = _pick_primary(group)
            mirror_ids = [g["id"] for g in group if g["id"] != primary_id]
            db.create_cluster(
                conn, primary_id=primary_id, mirror_ids=mirror_ids,
                created_at=now_iso,
            )
            n_clusters += 1
        return n_clusters
    finally:
        conn.close()


def main() -> int:
    p = argparse.ArgumentParser(description="Mirror-cluster articles by title Jaccard similarity.")
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
