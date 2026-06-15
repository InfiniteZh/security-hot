"""Prune articles older than NEWS_DAYS_BACK from news.db.

Also drops articles with malformed publish dates (year < 2020 or > now+7d),
which are RSS metadata garbage. The FTS index is kept consistent by the
articles_ad delete trigger.

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

        # Delete articles (the articles_ad trigger keeps articles_fts in sync)
        n_del = conn.execute("""
            DELETE FROM articles
            WHERE published IS NOT NULL
              AND (published < ? OR published < ? OR published > ?)
        """, [cutoff, floor, ceil]).rowcount

        conn.commit()
        n_after = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
        print(
            f"[prune] deleted {n_del} articles ({n_total} → {n_after})",
            file=sys.stderr,
        )
        return {
            "deleted_articles": n_del,
            "remaining_articles": n_after,
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
