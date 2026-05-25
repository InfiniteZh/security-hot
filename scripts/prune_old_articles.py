"""Prune articles older than NEWS_DAYS_BACK from news.db.

Also drops articles with malformed publish dates (year < 2020 or > now+7d),
which are RSS metadata garbage. Cascades: removes associated embeddings,
breaks dangling cluster_id pointers, and deletes empty clusters.

Run on demand; not part of cron. Safe to re-run.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import db


def prune(*, db_path=None, days: int | None = None, dry_run: bool = False) -> dict:
    if days is None:
        days = int(os.environ.get("NEWS_DAYS_BACK", "30"))
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=days)).isoformat().replace("+00:00", "Z")
    floor = "2020-01-01T00:00:00Z"
    ceil = (now + timedelta(days=7)).isoformat().replace("+00:00", "Z")

    conn = db.connect(db_path)
    db.init_schema(conn)
    try:
        # Count what we'd delete before doing it
        n_old = conn.execute("""
            SELECT COUNT(*) FROM articles
            WHERE published IS NOT NULL
              AND (published < ? OR published < ? OR published > ?)
        """, [cutoff, floor, ceil]).fetchone()[0]
        n_total = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]

        if dry_run:
            print(f"[prune] DRY RUN: would delete {n_old} of {n_total} articles "
                  f"(cutoff={cutoff[:10]}, floor=2020-01-01, ceil={ceil[:10]})",
                  file=sys.stderr)
            return {"dry_run": True, "would_delete": n_old, "total": n_total}

        # Collect cluster ids that might become empty after the prune
        affected_clusters = [
            r[0] for r in conn.execute("""
                SELECT DISTINCT cluster_id FROM articles
                WHERE cluster_id IS NOT NULL
                  AND published IS NOT NULL
                  AND (published < ? OR published < ? OR published > ?)
            """, [cutoff, floor, ceil])
        ]

        # Delete embeddings first (FK references articles)
        n_emb = conn.execute("""
            DELETE FROM article_embeddings
            WHERE article_id IN (
                SELECT id FROM articles
                WHERE published IS NOT NULL
                  AND (published < ? OR published < ? OR published > ?)
            )
        """, [cutoff, floor, ceil]).rowcount

        # Delete articles
        n_del = conn.execute("""
            DELETE FROM articles
            WHERE published IS NOT NULL
              AND (published < ? OR published < ? OR published > ?)
        """, [cutoff, floor, ceil]).rowcount

        # Clean up clusters that lost members
        # If a cluster's primary was deleted, the surviving members are now
        # cluster_id-pointing-to-a-still-existing-cluster-row, but the
        # primary_article_id is broken. Detect and either reassign primary
        # or delete the cluster.
        n_cluster_dropped = 0
        n_cluster_recovered = 0
        for cid in affected_clusters:
            survivors = list(conn.execute(
                "SELECT id, lang, fetched_at FROM articles WHERE cluster_id = ?", [cid]
            ))
            if len(survivors) < 2:
                # Cluster collapsed: drop the cluster + null out the lone survivor
                conn.execute("UPDATE articles SET cluster_id = NULL, is_cluster_primary = 0 WHERE cluster_id = ?", [cid])
                conn.execute("DELETE FROM clusters WHERE id = ?", [cid])
                n_cluster_dropped += 1
                continue
            # Cluster still viable: ensure a valid primary exists
            current_primary = conn.execute(
                "SELECT id FROM articles WHERE cluster_id = ? AND is_cluster_primary = 1", [cid]
            ).fetchone()
            if current_primary is None:
                # Old primary was deleted — pick a new one (zh-first, then earliest)
                survivors_sorted = sorted(
                    survivors,
                    key=lambda r: (0 if r["lang"] == "zh" else 1, r["fetched_at"] or "9999"),
                )
                new_primary_id = survivors_sorted[0]["id"]
                conn.execute("UPDATE articles SET is_cluster_primary = 1 WHERE id = ?", [new_primary_id])
                conn.execute("UPDATE clusters SET primary_article_id = ?, member_count = ? WHERE id = ?",
                             [new_primary_id, len(survivors), cid])
                n_cluster_recovered += 1
            else:
                # Just refresh member_count
                conn.execute("UPDATE clusters SET member_count = ? WHERE id = ?",
                             [len(survivors), cid])

        conn.commit()
        n_after = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
        n_clusters_after = conn.execute("SELECT COUNT(*) FROM clusters").fetchone()[0]
        print(
            f"[prune] deleted {n_del} articles + {n_emb} embeddings "
            f"({n_total} → {n_after}); "
            f"clusters: dropped {n_cluster_dropped}, primary-recovered {n_cluster_recovered}, "
            f"remaining {n_clusters_after}",
            file=sys.stderr,
        )
        return {
            "deleted_articles": n_del,
            "deleted_embeddings": n_emb,
            "remaining_articles": n_after,
            "clusters_dropped": n_cluster_dropped,
            "clusters_primary_recovered": n_cluster_recovered,
            "clusters_remaining": n_clusters_after,
        }
    finally:
        conn.close()


def main() -> int:
    p = argparse.ArgumentParser(description="Purge articles older than NEWS_DAYS_BACK (default 30).")
    p.add_argument("--days", type=int, default=None, help="Override NEWS_DAYS_BACK")
    p.add_argument("--db", default=None)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    prune(
        db_path=Path(args.db) if args.db else None,
        days=args.days,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
