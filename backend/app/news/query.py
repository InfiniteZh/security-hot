"""SQLite-backed reads for the 行业资讯 (news) domain: articles, search,
sources, and dispatch records.

Every function resolves the mutable globals ``_NEWS_DB`` / ``_state`` and the
``_news_conn`` / ``_row_to_article`` primitives from :mod:`cache_io` at call
time, so a test ``monkeypatch.setattr(data, "_NEWS_DB", tmp)`` that the data
façade mirrors onto ``cache_io._NEWS_DB`` is honored here.
"""
from __future__ import annotations

import re
import sqlite3 as _sqlite3
import time

from .. import cache_io
from ..cache_io import _RELOAD_TTL, _json_list, _json_obj, _normalize_iocs
from ..models import Article, DispatchEntry, SourceStatus

_DEFAULT_DISPATCH_TOPIC = "schedule_task_normal"


def _normalize_packages(raw) -> list[dict]:
    """归一化 v3 多包数组。兼容旧单包字段（package/ecosystem）。
    每个元素保留 ecosystem / package / versions(affected_version) / fix_version。"""
    out: list[dict] = []
    if not isinstance(raw, list):
        return out
    for p in raw:
        if not isinstance(p, dict):
            continue
        name = str(p.get("package") or "").strip()
        if not name:
            continue
        versions = p.get("versions")
        if versions is None:
            versions = p.get("affected_version")
        if isinstance(versions, str):
            versions = [versions] if versions.strip() else []
        elif not isinstance(versions, list):
            versions = []
        out.append({
            "ecosystem": str(p.get("ecosystem") or "").strip(),
            "package": name,
            "versions": [str(v) for v in versions if str(v).strip()],
            "fix_version": str(p.get("fix_version") or "").strip(),
        })
    return out


# ─────────── public loaders ───────────

def _load_dispatch_cache() -> list[DispatchEntry]:
    if not cache_io._NEWS_DB.exists():
        return []
    mtime = cache_io._NEWS_DB.stat().st_mtime
    now = time.time()
    cached = cache_io._state.get("__dispatches_sqlite__")
    if cached and cached[0] == mtime and (now - float(cached[1])) < _RELOAD_TTL:
        return cached[2]

    items: list[DispatchEntry] = []
    conn = cache_io._news_conn()
    try:
        rows = list(conn.execute("""
            SELECT vuln_id, origin, related_news_json, message_json, dispatched_at
            FROM vuln_dispatches
            ORDER BY dispatched_at DESC
        """))
    except _sqlite3.Error:
        rows = []

    for row in rows:
        msg = _json_obj(row["message_json"])
        related = _json_list(row["related_news_json"])
        if msg is None or related is None:
            continue
        ref_id = str(msg.get("ref_id") or row["vuln_id"] or "").strip()
        dispatched_at = str(row["dispatched_at"] or "").strip()
        origin = str(row["origin"] or msg.get("origin") or "vuln").strip()
        if not ref_id or not dispatched_at or origin not in ("vuln", "news"):
            continue
        packages = _normalize_packages(msg.get("packages"))
        # 兼容极旧的单包 schema（package/ecosystem 顶层字段）
        if not packages and msg.get("package"):
            packages = _normalize_packages([{
                "ecosystem": msg.get("ecosystem"),
                "package": msg.get("package"),
                "affected_version": msg.get("affected_versions"),
            }])
        first = packages[0] if packages else {}
        try:
            items.append(DispatchEntry(
                ref_id=ref_id,
                origin=origin,  # type: ignore[arg-type]
                package=(first.get("package") or None),
                ecosystem=(first.get("ecosystem") or None),
                packages=packages,
                iocs=_normalize_iocs(msg.get("iocs")),
                title=(msg.get("title") or None),
                severity=(msg.get("severity") or None),
                cve_id=(msg.get("cve_id") or None),
                summary_zh=(msg.get("summary_zh") or msg.get("summary") or None),
                references=[r for r in (msg.get("references") or []) if isinstance(r, dict)],
                related_news=related,
                dispatched_at=dispatched_at,
                topic=(msg.get("topic") or _DEFAULT_DISPATCH_TOPIC),
                message=msg,
            ))
        except (TypeError, ValueError):
            continue

    try:
        news_rows = list(conn.execute("""
            SELECT id, title, canonical_url, llm_score, poisoning_triage_json,
                   poisoning_dispatched_at
            FROM articles
            WHERE COALESCE(poisoning_dispatched, 0) = 1
              AND poisoning_dispatched_at IS NOT NULL
            ORDER BY poisoning_dispatched_at DESC
        """))
    except _sqlite3.Error:
        news_rows = []
    finally:
        conn.close()

    for row in news_rows:
        triage = _json_obj(row["poisoning_triage_json"])
        if triage is None:
            continue
        dispatched_at = str(row["poisoning_dispatched_at"] or "").strip()
        if not dispatched_at:
            continue
        related_news = [{
            "title": row["title"] or "",
            "url": row["canonical_url"] or "",
            "llm_score": row["llm_score"],
        }]
        packages = _normalize_packages(triage.get("packages"))
        if not packages and triage.get("package"):
            packages = _normalize_packages([{
                "ecosystem": triage.get("ecosystem"),
                "package": triage.get("package"),
            }])
        first = packages[0] if packages else {}
        iocs = _normalize_iocs(triage.get("iocs"))
        references = [{"url": row["canonical_url"] or "", "label": row["title"] or ""}]
        # news 来源只持久化了 triage 结果（非完整 Kafka 报文），按 build_message
        # 的字段重建一份等价投递内容供抽屉展示。
        message = {
            "schema_version": triage.get("schema_version"),
            "source": "security-hot",
            "kind": "poisoning_intel",
            "origin": "news",
            "ref_id": str(row["id"]),
            "article_id": row["id"],
            "title": row["title"] or "",
            "canonical_url": row["canonical_url"] or "",
            "packages": packages,
            "iocs": iocs,
            "llm_score": row["llm_score"],
            "references": references,
            "related_news": related_news,
            "triage": triage,
            "topic": _DEFAULT_DISPATCH_TOPIC,
            "dispatched_at": dispatched_at,
        }
        try:
            items.append(DispatchEntry(
                ref_id=str(row["id"]),
                origin="news",
                package=(first.get("package") or None),
                ecosystem=(first.get("ecosystem") or None),
                packages=packages,
                iocs=iocs,
                title=(row["title"] or None),
                summary_zh=(triage.get("reason") or None),
                references=references,
                related_news=related_news,
                dispatched_at=dispatched_at,
                topic=_DEFAULT_DISPATCH_TOPIC,
                message=message,
            ))
        except (TypeError, ValueError):
            continue

    items.sort(key=lambda x: x.dispatched_at or "", reverse=True)
    cache_io._state["__dispatches_sqlite__"] = (mtime, now, items)
    return items


def load_dispatches(limit: int = 100, origin: str = "all") -> list[DispatchEntry]:
    items = _load_dispatch_cache()
    if origin in ("vuln", "news"):
        items = [x for x in items if x.origin == origin]
    return items[:limit]


def all_articles() -> list[Article]:
    """SQLite-backed: articles where is_relevant != 0.

    Cached against news.db mtime — every request was rebuilding ~10k Pydantic
    models, dominating hot-path latency. Invalidates on any DB write."""
    if not cache_io._NEWS_DB.exists():
        return []
    mtime = cache_io._NEWS_DB.stat().st_mtime
    cached = cache_io._state.get("__articles_sqlite__")
    if cached and cached[0] == mtime:
        return cached[1]

    conn = cache_io._news_conn()
    rows = list(conn.execute("""
        SELECT * FROM articles
        WHERE (is_relevant = 1 OR is_relevant IS NULL)
        ORDER BY COALESCE(llm_score, -1) DESC, COALESCE(published, fetched_at) DESC
    """))
    conn.close()
    items = [cache_io._row_to_article(r) for r in rows]
    cache_io._state["__articles_sqlite__"] = (mtime, items)
    return items


_CJK_RE = re.compile(r"[一-鿿　-ヿ＀-￯]")


def search_articles(q: str, limit: int = 200) -> list[Article]:
    """Full-text article search across title + summary + llm_summary_zh + source_title.

    Two paths, chosen by query character set:

    * Pure ASCII (vendors, CVE-IDs, English keywords) → FTS5 MATCH on
      `articles_fts` (unicode61 tokenizer). CVE-IDs and other hyphenated
      tokens are quoted as phrases; short ASCII words get a trailing `*`
      for prefix search.
    * Anything containing CJK characters → LIKE %q% scan across all four
      columns. FTS5 unicode61 doesn't segment Chinese (it lumps each
      no-space run into one token), so MATCH would return nothing useful
      for queries like "备份" or "微软". The LIKE scan is slower but works
      directly on the indexed string and gives substring semantics users
      expect.

    Source-name hits (e.g. "BleepingComputer") work in either path: ASCII
    path adds a source_title LIKE union; CJK path already covers source_title.
    Restricts to articles where is_relevant != 0.
    """
    q = (q or "").strip()
    if not q or len(q) < 2:
        return []
    if not cache_io._NEWS_DB.exists():
        return []

    conn = cache_io._news_conn()
    try:
        rows_by_id: dict[int, tuple[float, dict]] = {}
        has_cjk = bool(_CJK_RE.search(q))

        if not has_cjk:
            # FTS5 path. Build a syntactically-safe query string.
            tokens = [t for t in re.split(r"\s+", q) if t]
            fts_terms: list[str] = []
            for t in tokens:
                if re.search(r"[^A-Za-z0-9]", t):
                    fts_terms.append('"' + t.replace('"', '""') + '"')
                else:
                    fts_terms.append(t + "*")
            fts_query = " ".join(fts_terms)
            try:
                for r in conn.execute(
                    """
                    SELECT a.*, fts.rank AS fts_rank
                    FROM articles a
                    JOIN articles_fts fts ON fts.rowid = a.id
                    WHERE articles_fts MATCH ?
                      AND (a.is_relevant = 1 OR a.is_relevant IS NULL)
                    ORDER BY fts.rank
                    LIMIT ?
                    """,
                    [fts_query, limit],
                ):
                    rows_by_id[r["id"]] = (r["fts_rank"] or 0.0, dict(r))
            except _sqlite3.OperationalError:
                pass  # bad FTS5 syntax; LIKE fallback below still runs

        # LIKE path. For CJK (and mixed ASCII+CJK) queries, FTS5 is skipped
        # above so this path covers title/summary/llm_summary_zh/source_title.
        # For pure-ASCII queries, this only adds source_title (FTS5 doesn't
        # index source name).
        #
        # Multi-token queries combine with AND across columns: every
        # whitespace-separated token must appear in at least one of the
        # searched columns. This makes "Kopia 备份" match an article whose
        # title contains "Kopia" and whose Chinese summary contains "备份".
        tokens = [t.lower() for t in re.split(r"\s+", q) if t]
        if has_cjk:
            per_token = (
                "(lower(title) LIKE ? OR lower(summary) LIKE ? "
                "OR lower(llm_summary_zh) LIKE ? OR lower(source_title) LIKE ?)"
            )
            where_clauses = [per_token] * len(tokens)
            params: list = []
            for t in tokens:
                pat = f"%{t}%"
                params.extend([pat, pat, pat, pat])
            params.append(limit)
            sql = f"""
                SELECT * FROM articles
                WHERE {' AND '.join(where_clauses)}
                  AND (is_relevant = 1 OR is_relevant IS NULL)
                ORDER BY COALESCE(llm_score, -1) DESC,
                         COALESCE(published, fetched_at) DESC
                LIMIT ?
            """
        else:
            sql = """
                SELECT * FROM articles
                WHERE lower(source_title) LIKE ?
                  AND (is_relevant = 1 OR is_relevant IS NULL)
                LIMIT ?
            """
            params = [f"%{q.lower()}%", limit]
        for i, r in enumerate(conn.execute(sql, params)):
            if r["id"] not in rows_by_id:
                # Stable rank-after-FTS for LIKE-only hits.
                rows_by_id[r["id"]] = (1e9 + i, dict(r))

        sorted_rows = sorted(rows_by_id.values(), key=lambda t: t[0])[:limit]
        return [cache_io._row_to_article(r[1]) for r in sorted_rows]
    finally:
        conn.close()


def all_sources() -> list[SourceStatus]:
    """News sources from SQLite sources table."""
    if not cache_io._NEWS_DB.exists():
        return []
    out: list[SourceStatus] = []
    conn = cache_io._news_conn()
    for r in conn.execute("""
        SELECT slug, title, url, lang, ok, error, tier, consecutive_failures, last_fetched,
               (SELECT COUNT(*) FROM articles WHERE source_slug = sources.slug) AS count
        FROM sources
    """):
        lang_raw = r["lang"]
        lang_val = lang_raw if lang_raw in ("zh", "en") else "mixed"
        out.append(SourceStatus(
            slug=r["slug"], title=r["title"] or r["slug"], url=r["url"] or "",
            lang=lang_val,
            ok=bool(r["ok"]), count=int(r["count"] or 0),
            error=r["error"],
            consecutive_failures=int(r["consecutive_failures"] or 0),
            tier=r["tier"] or "tail",
            last_fetched=r["last_fetched"],
        ))
    conn.close()
    return out
