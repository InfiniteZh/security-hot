"""News / briefing / search / dispatch routes."""
from __future__ import annotations

import logging
import os
import secrets
import threading
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Query, Response
from fastapi.responses import JSONResponse

from ..data import (
    all_articles,
    load_dispatches,
    search_aggregated,
    search_articles,
)
from ..models import Article, DispatchEntry, SearchResult
from .ops import _matches_date, _today_utc_str, _validate_date

log = logging.getLogger("security-hot")

router = APIRouter()


# Brief-regenerate concurrency guard. The flag is canonically exposed on the
# `main` module (legacy single-source-of-truth that external callers/tests
# reference as `backend.app.main._brief_regen_in_flight`); we mirror it there
# via the helpers below so direct attribute pokes are honoured by the handler.
_brief_regen_lock = threading.Lock()
_brief_regen_in_flight: bool = False


def _get_brief_regen_in_flight() -> bool:
    from .. import main as _main
    return getattr(_main, "_brief_regen_in_flight", _brief_regen_in_flight)


def _set_brief_regen_in_flight(value: bool) -> None:
    global _brief_regen_in_flight
    _brief_regen_in_flight = value
    from .. import main as _main
    _main._brief_regen_in_flight = value


def _contains(needle: str, *haystacks: str | None) -> bool:
    needle = (needle or "").strip().lower()
    if not needle:
        return True
    for h in haystacks:
        if h and needle in h.lower():
            return True
    return False


@router.get("/api/news", response_model=list[Article], tags=["news"])
def api_news(
    response: Response,
    lang: Literal["all", "zh", "en"] = "all",
    category: Literal["all", "incident", "vuln", "supply-chain", "research", "industry"] = "all",
    q: str = "",
    source: str | None = Query(default=None, description="comma-separated source slugs"),
    date: str | None = Query(default=None, description="filter by published date (YYYY-MM-DD)"),
    limit: int = Query(default=80, ge=1, le=2000),
    sort: str = Query(default="heat", description="'heat' = LLM priority desc then time desc; 'time' = pure chronological."),
) -> list[Article]:
    target_date = _validate_date(date)
    # Search path: when q is set, use FTS5 (title + summary + llm_summary_zh)
    # unioned with a source_title LIKE filter. This gives ranked full-text
    # results that include Chinese AI summaries and ensures CVE-IDs and other
    # punctuated tokens are matched as phrases. Other filters still apply on
    # top so search composes with category/lang/date pickers.
    if q and q.strip():
        items = search_articles(q, limit=max(limit * 3, 300))
    else:
        items = all_articles()
    # Uncategorized articles flow into the hidden bucket (see /api/news/hidden).
    # The main news view always excludes them — no opt-in filter, since there's
    # no UI affordance to see them other than the hidden audit drawer.
    items = [a for a in items if a.llm_category not in (None, "", "uncategorized")]
    if lang != "all":
        items = [a for a in items if a.lang == lang]
    if category != "all":
        items = [a for a in items if a.llm_category == category]
    if source:
        slugs = {s.strip() for s in source.split(",") if s.strip()}
        items = [a for a in items if a.source_slug in slugs]
    if target_date:
        items = [a for a in items if _matches_date(a.published, target_date)]
    if sort == "time":
        items.sort(key=lambda x: x.published or "", reverse=True)
    else:
        items.sort(
            key=lambda x: (
                x.llm_score if x.llm_score is not None else -1,
                x.published or "",
            ),
            reverse=True,
        )
    # Full filtered count for the client's "showing N of M" overflow hint.
    response.headers["X-Total-Count"] = str(len(items))
    return items[:limit]


@router.get("/api/dispatches", response_model=list[DispatchEntry], tags=["vulnerability"])
def api_dispatches(
    limit: int = Query(default=100, ge=1, le=1000),
    origin: str = Query(default="all", description="all | vuln | news"),
) -> list[DispatchEntry]:
    return load_dispatches(limit=limit, origin=origin)


@router.post("/api/dispatches/resend", tags=["vulnerability"])
async def api_dispatch_resend(
    ref_id: str = Query(..., description="ref_id of the dispatch entry"),
    origin: str = Query(default="vuln", description="vuln | news"),
    x_refresh_token: str | None = Header(default=None),
) -> JSONResponse:
    """Re-send a previously dispatched message to Kafka verbatim.

    Looks up the stored message for (ref_id, origin) and pushes it to Kafka
    without re-running any LLM triage. Auth: SECURITY_HOT_REFRESH_TOKEN header.
    """
    import sys
    import time as _t
    from pathlib import Path as _P

    expected = os.environ.get("SECURITY_HOT_REFRESH_TOKEN")
    if not expected:
        raise HTTPException(status_code=503, detail="resend disabled — set SECURITY_HOT_REFRESH_TOKEN")
    if not x_refresh_token or not secrets.compare_digest(x_refresh_token, expected):
        raise HTTPException(status_code=401, detail="invalid refresh token")

    if origin not in ("vuln", "news"):
        raise HTTPException(status_code=400, detail="origin must be vuln | news")

    entries = load_dispatches(limit=1000, origin=origin)
    entry = next((e for e in entries if e.ref_id == ref_id), None)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"dispatch entry {ref_id!r} not found")
    if not entry.message:
        raise HTTPException(status_code=422, detail="no message payload stored for this entry")

    _root_scripts = str(_P(__file__).resolve().parents[3] / "scripts")
    if _root_scripts not in sys.path:
        sys.path.insert(0, _root_scripts)

    from dispatch_common import KAFKA_BOOTSTRAP, KAFKA_TOPIC, make_producer, send  # noqa: E402

    bootstrap = os.environ.get("KAFKA_BOOTSTRAP", KAFKA_BOOTSTRAP)
    topic = os.environ.get("KAFKA_TOPIC", entry.topic or KAFKA_TOPIC)

    t0 = _t.monotonic()
    try:
        producer = make_producer(bootstrap)
        await producer.start()
        try:
            await send(producer, topic, str(ref_id), entry.message)
        finally:
            await producer.stop()
    except Exception as exc:
        log.error("resend %s/%s failed: %s", origin, ref_id, exc)
        raise HTTPException(status_code=502, detail=f"Kafka send failed: {exc}") from exc

    elapsed = round(_t.monotonic() - t0, 2)
    log.info("resend ok origin=%s ref_id=%s topic=%s elapsed=%.2fs", origin, ref_id, topic, elapsed)
    return JSONResponse({"ok": True, "ref_id": ref_id, "origin": origin, "topic": topic, "elapsed_s": elapsed})


@router.get("/api/search", response_model=SearchResult, tags=["search"])
def api_search(
    q: str = Query(..., min_length=2, description="Search query"),
    limit: int = Query(default=10, ge=1, le=30, description="Max results per category"),
) -> SearchResult:
    return search_aggregated(q, limit)


@router.get("/api/brief", tags=["news"])
def api_brief(
    date: str | None = Query(default=None, description="YYYY-MM-DD; default today"),
) -> JSONResponse:
    """Return daily briefing per category for a given date — reads SQLite `daily_briefs` table."""
    from ..data import _news_conn, _NEWS_DB
    target = _validate_date(date) or _today_utc_str()
    if not _NEWS_DB.exists():
        return JSONResponse({"date": target, "briefs": {}})
    conn = _news_conn()
    rows = list(conn.execute(
        "SELECT category, text, article_count, generated_at FROM daily_briefs WHERE date = ?",
        [target],
    ))
    conn.close()
    briefs = {
        r["category"]: {
            "text": r["text"],
            "article_count": int(r["article_count"] or 0),
            "generated_at": r["generated_at"],
        }
        for r in rows
    }
    return JSONResponse({"date": target, "briefs": briefs})


async def _run_llm_brief_task(target_date: str) -> None:
    """Background-task wrapper. Invoked off the HTTP request path."""
    try:
        from .ingest.pipeline import generate_daily_brief

        await generate_daily_brief(target_date=target_date, verbose=True)
    except Exception as exc:
        log.error(f"brief regenerate failed: {exc}")
    finally:
        with _brief_regen_lock:
            _set_brief_regen_in_flight(False)


@router.post("/api/brief/regenerate", tags=["news"])
async def regenerate_brief(
    background: BackgroundTasks,
    date: str | None = Query(default=None, description="YYYY-MM-DD; default=today"),
    x_refresh_token: str | None = Header(default=None, alias="X-Refresh-Token"),
):
    """Trigger a background regeneration of today's (or specified) daily brief.

    Requires SECURITY_HOT_REFRESH_TOKEN header match. Only one regen runs at a time;
    concurrent calls return 409.
    """
    expected = os.environ.get("SECURITY_HOT_REFRESH_TOKEN")
    # Distinguish "feature disabled (server-side missing config)" from
    # "wrong token (user-side)" so the UI can show a useful message.
    if not expected:
        raise HTTPException(status_code=503, detail="brief regenerate disabled — set SECURITY_HOT_REFRESH_TOKEN in .env")
    if not x_refresh_token or not secrets.compare_digest(x_refresh_token, expected):
        raise HTTPException(status_code=401, detail="invalid refresh token")
    target = _validate_date(date) or _today_utc_str()
    with _brief_regen_lock:
        if _get_brief_regen_in_flight():
            raise HTTPException(status_code=409, detail="brief regeneration already in progress")
        _set_brief_regen_in_flight(True)
    background.add_task(_run_llm_brief_task, target)
    return JSONResponse(status_code=202, content={"status": "accepted", "date": target})


@router.get("/api/news/hidden", response_model=list[Article], tags=["news"])
def api_news_hidden(
    date: str | None = Query(default=None, description="YYYY-MM-DD published date; default = today UTC"),
    limit: int = Query(default=50, ge=1, le=1000),
) -> list[Article]:
    """Audit view of what the LLM filter held back — two buckets:

      1. is_relevant=0 (explicitly judged off-topic) — filtered by **published**
         date (falls back to fetched_at when published is NULL) to match
         /api/news semantics: the UI date strip selects a publish day and the
         hidden view respects that selection.
      2. relevant-but-uncategorized (llm_category NULL/''/‘uncategorized') —
         NOT date-filtered, since these never make it onto any specific day's
         news view, so the audit view is their only review home.
    """
    from ..data import _news_conn, _NEWS_DB, _row_to_article
    if not _NEWS_DB.exists():
        return []
    target = _validate_date(date) or _today_utc_str()
    conn = _news_conn()
    # The hidden bucket has two membership rules:
    #   1. is_relevant=0 (LLM explicitly judged off-topic) — date-filtered
    #   2. llm_category IS NULL/'uncategorized' (no category assigned) —
    #      NOT date-filtered, since these articles never make it onto any
    #      specific day's news view anyway, and burying them by date would
    #      leave no place to review them.
    rows = list(conn.execute("""
        SELECT * FROM articles
        WHERE (
            (is_relevant = 0
             AND substr(COALESCE(published, fetched_at), 1, 10) = ?)
            OR (is_relevant != 0
                AND (llm_category IS NULL
                     OR llm_category = ''
                     OR llm_category = 'uncategorized'))
        )
        ORDER BY published DESC, fetched_at DESC LIMIT ?
    """, [target, limit]))
    conn.close()
    return [_row_to_article(r) for r in rows]
