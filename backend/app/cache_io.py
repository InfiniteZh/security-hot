"""Low-level cache + SQLite access primitives.

Single source of truth for the two mutable globals the test-suite monkeypatches:
``_state`` (JSON mtime cache) and ``_NEWS_DB`` (news.db path). Every loader that
reads either global does so **dynamically at call time** via this module's
attributes, so a ``monkeypatch.setattr(data, "_NEWS_DB", tmp)`` that the data
façade write-throughs to ``cache_io._NEWS_DB`` reaches the real logic here.
"""
from __future__ import annotations

import json
import re
import sqlite3 as _sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Article, NewsCategory, Severity

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / "backend" / "cache"

_NEWS_DB = ROOT / "backend" / "cache" / "news.db"

_RELOAD_TTL = 30  # seconds
_VALID_CATEGORIES: set[str] = {"incident", "vuln", "supply-chain", "research", "industry"}

_state: dict[str, tuple[Any, ...]] = {}


# ─────────── SQLite helpers ───────────

def _news_conn() -> _sqlite3.Connection:
    c = _sqlite3.connect(str(_NEWS_DB))
    c.row_factory = _sqlite3.Row
    # foreign_keys is session-scoped; explicit set is required even on WAL-init'd file.
    # WAL mode is already sticky in the file header but re-stating it is harmless.
    c.execute("PRAGMA journal_mode = WAL")
    c.execute("PRAGMA foreign_keys = ON")
    c.execute("PRAGMA synchronous = NORMAL")
    return c


def _row_to_article(row, mirror_titles_by_cluster: dict) -> Article:
    cluster_id = row["cluster_id"]
    mirror_titles = mirror_titles_by_cluster.get(cluster_id, []) if cluster_id else []
    raw_cat = row["llm_category"]
    llm_cat: NewsCategory | None = raw_cat if raw_cat in _VALID_CATEGORIES else None
    return Article(
        id=row["id"],
        title=row["title"] or "",
        link=row["canonical_url"] or "",
        published=row["published"] or "",
        summary=row["summary"] or "",
        source_slug=row["source_slug"] or "",
        source_title=row["source_title"] or "",
        lang=row["lang"] if row["lang"] in ("zh", "en") else "en",
        category=row["rss_category"],
        llm_score=int(row["llm_score"]) if row["llm_score"] is not None else None,
        llm_reason=row["llm_reason"],
        llm_category=llm_cat,
        llm_summary_zh=row["llm_summary_zh"],
        is_relevant=bool(row["is_relevant"]) if row["is_relevant"] is not None else None,
        mirror_count=len(mirror_titles),
        mirror_source_titles=mirror_titles[:6],
    )


# ─────────── cache loaders ───────────

def _load_json(name: str, default):
    path = CACHE / name
    if not path.exists():
        return default
    cached = _state.get(name)
    mtime = path.stat().st_mtime
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        data = default
    _state[name] = (mtime, data)
    return data


def _json_obj(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _json_list(raw: str | None) -> list[dict] | None:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(data, list):
        return None
    return [x for x in data if isinstance(x, dict)]


def _normalize_iocs(raw: Any) -> list[dict]:
    out: list[dict] = []
    for item in raw or []:
        if isinstance(item, dict):
            value = item.get("value")
            typ = item.get("type")
            if value:
                out.append({"value": str(value), "type": str(typ or "unknown")})
        elif isinstance(item, str) and item:
            out.append({"value": item, "type": "unknown"})
    return out


# ─────────── helpers ───────────

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def severity_from_cvss(cvss: float | None) -> Severity:
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "unknown"


def parse_iso_date(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    # try a few formats
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # ISO with +/- offset
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
