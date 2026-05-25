"""One-time migration: backend/cache/news.json + daily_brief.json → news.db.

Idempotent guard: refuses to run if news.db exists, unless --force.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from xml.etree import ElementTree as ET
from urllib.parse import urlparse

import db

# ─── Tier whitelist: known high-signal Chinese + English security media ───
TOP_SOURCE_SLUGS = {
    # Chinese
    "freebuf", "anquanke", "4hou", "kanxue", "secrss", "qianxin", "tencentyun-security",
    "alibaba-security", "baidu-security", "huawei-security",
    # English
    "krebsonsecurity", "bleepingcomputer", "securityweek", "thehackernews",
    "darkreading", "schneier", "sans-isc", "talos-intelligence",
    "google-projectzero", "microsoft-msrc", "naked-security", "threatpost",
}

INTERVAL_BY_TIER = {"top": 30, "tail": 240}


def _slug_from_url(url: str) -> str:
    host = urlparse(url).hostname or ""
    return host.lower().replace("www.", "").split(".")[0] or url

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE = ROOT / "backend" / "cache"


def _canonical_url(link: str) -> str:
    """Conservative fallback: strip whitespace + lowercase scheme/host.

    The full canonical_url logic lives in fetch_data.py; here we just
    do enough to satisfy the UNIQUE constraint on already-canonicalized
    URLs (since news.json was already deduped via that path).
    """
    return (link or "").strip()


def _migrate_articles(conn, news_json: Path, now_iso: str) -> int:
    if not news_json.exists():
        print(f"[migrate] {news_json} not found, skipping articles", file=sys.stderr)
        return 0
    raw = json.loads(news_json.read_text(encoding="utf-8"))
    n = 0
    for a in raw.get("articles", []):
        link = _canonical_url(a.get("link") or "")
        if not link:
            continue
        rowid = db.upsert_article(conn, {
            "canonical_url": link,
            "title": a.get("title") or "(untitled)",
            "summary": a.get("summary") or "",
            "source_slug": a.get("source_slug") or "unknown",
            "source_title": a.get("source_title"),
            "lang": a.get("lang"),
            "rss_category": a.get("category"),
            "published": a.get("published"),
            "fetched_at": a.get("fetched_at") or now_iso,
            "first_seen_date": a.get("first_seen") or (a.get("published") or now_iso)[:10],
        })
        # LLM fields backfill — direct UPDATE since upsert deliberately
        # never touches them
        if rowid and (a.get("llm_score") is not None or a.get("llm_summary_zh")):
            conn.execute("""
                UPDATE articles SET
                  llm_score = ?, llm_category = ?, llm_reason = ?,
                  llm_summary_zh = ?, llm_scored_at = ?
                WHERE id = ?
            """, [
                a.get("llm_score"), a.get("llm_category"), a.get("llm_reason"),
                a.get("llm_summary_zh"), a.get("llm_scored_at"),
                rowid,
            ])
        n += 1
    conn.commit()
    return n


def _migrate_briefs(conn, brief_json: Path, now_iso: str) -> int:
    if not brief_json.exists():
        print(f"[migrate] {brief_json} not found, skipping briefs", file=sys.stderr)
        return 0
    raw = json.loads(brief_json.read_text(encoding="utf-8"))
    n = 0
    for date_key, by_cat in raw.items():
        if not isinstance(by_cat, dict):
            continue
        for category, payload in by_cat.items():
            if not isinstance(payload, dict):
                continue
            db.upsert_brief(
                conn, date=date_key, category=category,
                text=payload.get("text") or "",
                article_count=int(payload.get("article_count") or 0),
                generated_at=payload.get("generated_at") or now_iso,
            )
            n += 1
    return n


def _migrate_sources(conn, curated: list[dict] | None, opml_path: Path | None) -> int:
    n = 0
    seen: set[str] = set()
    for src in (curated or []):
        slug = src["slug"]
        tier = "top" if slug in TOP_SOURCE_SLUGS else "tail"
        db.upsert_source(conn, {
            "slug": slug, "title": src.get("title") or slug,
            "url": src["url"], "lang": src.get("lang"),
            "tier": tier, "interval_minutes": INTERVAL_BY_TIER[tier],
        })
        seen.add(slug)
        n += 1
    if opml_path and opml_path.exists():
        try:
            tree = ET.fromstring(opml_path.read_text(encoding="utf-8"))
        except ET.ParseError as exc:
            print(f"[migrate] OPML parse error: {exc}", file=sys.stderr)
            return n
        for outline in tree.iter("outline"):
            url = outline.attrib.get("xmlUrl")
            if not url:
                continue
            slug = _slug_from_url(url)
            if slug in seen:
                continue
            tier = "top" if slug in TOP_SOURCE_SLUGS else "tail"
            db.upsert_source(conn, {
                "slug": slug,
                "title": outline.attrib.get("text") or slug,
                "url": url, "lang": None,
                "tier": tier, "interval_minutes": INTERVAL_BY_TIER[tier],
            })
            seen.add(slug)
            n += 1
    return n


def run(
    *,
    db_path: Path,
    cache_dir: Path,
    force: bool,
    curated_sources: list[dict] | None = None,
    opml_path: Path | None = None,
) -> None:
    if db_path.exists() and not force:
        print(f"[migrate] {db_path} already exists. Pass --force to overwrite.", file=sys.stderr)
        sys.exit(2)
    if db_path.exists():
        db_path.unlink()
        for suffix in ("-shm", "-wal"):
            sidecar = db_path.with_name(db_path.name + suffix)
            if sidecar.exists():
                sidecar.unlink()

    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    conn = db.connect(db_path)
    db.init_schema(conn)
    n_articles = _migrate_articles(conn, cache_dir / "news.json", now_iso)
    n_briefs = _migrate_briefs(conn, cache_dir / "daily_brief.json", now_iso)
    n_sources = _migrate_sources(conn, curated_sources, opml_path)
    conn.close()

    print(f"[migrate] articles={n_articles} briefs={n_briefs} sources={n_sources} → {db_path}",
          file=sys.stderr)


def main() -> int:
    p = argparse.ArgumentParser(description="Migrate news.json + daily_brief.json into SQLite.")
    p.add_argument("--db", default=str(db.DEFAULT_DB_PATH))
    p.add_argument("--cache", default=str(DEFAULT_CACHE))
    p.add_argument("--opml", default=str(ROOT / "rss" / "merged.opml"))
    p.add_argument("--force", action="store_true")
    args = p.parse_args()

    # Pull curated NEWS_SOURCES list from fetch_data.py
    sys.path.insert(0, str(ROOT / "scripts"))
    from fetch_data import NEWS_SOURCES  # noqa: E402

    run(db_path=Path(args.db), cache_dir=Path(args.cache), force=args.force,
        curated_sources=NEWS_SOURCES, opml_path=Path(args.opml))
    return 0


if __name__ == "__main__":
    sys.exit(main())
