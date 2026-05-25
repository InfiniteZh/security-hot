"""FastAPI app for security-hot.

Run dev:
  uv run uvicorn backend.app.main:app --reload --port 8000

Endpoints:
  GET  /api/today        summary stats
  GET  /api/news         list articles (filter: lang, q, source, limit)
  GET  /api/vuln         list vulns (filter: kind, q, severity, limit)
  GET  /api/heat         top heat board (limit)
  GET  /api/sources      source health
  GET  /api/manifest     fetcher manifest
  /                      mounted web/ static frontend
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
import subprocess
import sys
import threading
from pathlib import Path
from typing import Literal

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

# Centralised logging so subprocess output + app logs share a single format.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("security-hot")

from .data import (
    all_articles,
    all_sources,
    all_vulns,
    heat_board,
    manifest as manifest_fn,
    today_summary,
)
from .models import (
    Article,
    HeatEntry,
    Manifest,
    SourceStatus,
    TodaySummary,
    Vuln,
)

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"

app = FastAPI(
    title="security-hot",
    version="0.1.0",
    description="Daily aggregator for security news, vulnerability intel, and papers.",
)

# CORS: defaults to localhost:8000 + 127.0.0.1:8000 (single-process mode).
# Override with comma-separated SECURITY_HOT_ALLOWED_ORIGINS, or set it to '*'
# to allow any origin (only do this in trusted environments).
_default_origins = "http://localhost:8000,http://127.0.0.1:8000"
_allowed_raw = os.environ.get("SECURITY_HOT_ALLOWED_ORIGINS", _default_origins).strip()
_allowed_origins = ["*"] if _allowed_raw == "*" else [o.strip() for o in _allowed_raw.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def _contains(needle: str, *haystacks: str | None) -> bool:
    needle = (needle or "").strip().lower()
    if not needle:
        return True
    for h in haystacks:
        if h and needle in h.lower():
            return True
    return False


_DATE_RE = __import__("re").compile(r"^\d{4}-\d{2}-\d{2}$")


def _matches_date(timestamp: str | None, target: str) -> bool:
    if not timestamp:
        return False
    return timestamp[:10] == target


def _validate_date(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if not _DATE_RE.match(value):
        raise HTTPException(status_code=400, detail=f"date must be YYYY-MM-DD, got {value!r}")
    return value


@app.get("/api/today", response_model=TodaySummary, tags=["overview"])
def api_today() -> TodaySummary:
    return today_summary()


@app.get("/api/news", response_model=list[Article], tags=["news"])
def api_news(
    lang: Literal["all", "zh", "en"] = "all",
    category: Literal["all", "incident", "vuln", "supply-chain", "research", "industry"] = "all",
    q: str = "",
    source: str | None = Query(default=None, description="comma-separated source slugs"),
    date: str | None = Query(default=None, description="filter by published date (YYYY-MM-DD)"),
    limit: int = Query(default=80, ge=1, le=500),
    sort: str = Query(default="heat", description="'heat' = LLM priority desc then time desc; 'time' = pure chronological."),
) -> list[Article]:
    target_date = _validate_date(date)
    items = all_articles()
    if lang != "all":
        items = [a for a in items if a.lang == lang]
    if category != "all":
        items = [a for a in items if a.llm_category == category]
    if source:
        slugs = {s.strip() for s in source.split(",") if s.strip()}
        items = [a for a in items if a.source_slug in slugs]
    if q:
        items = [a for a in items if _contains(q, a.title, a.summary, a.source_title)]
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
    return items[:limit]


@app.get("/api/vuln", response_model=list[Vuln], tags=["vulnerability"])
def api_vuln(
    kind: Literal["all", "cve", "supply", "poc", "itw"] = "all",
    q: str = "",
    severity: Literal["any", "critical", "high", "medium", "low"] = "any",
    date: str | None = Query(default=None, description="filter by published date (YYYY-MM-DD); matches CISA dateAdded for KEV, published_at for GHSA/OSV"),
    limit: int = Query(default=60, ge=1, le=500),
    sort: Literal["heat", "time"] = "heat",
) -> list[Vuln]:
    target_date = _validate_date(date)
    items = all_vulns()
    if kind != "all":
        items = [v for v in items if v.kind == kind]
    if severity != "any":
        items = [v for v in items if v.severity == severity]
    if q:
        items = [v for v in items if _contains(q, v.title, v.summary, v.cve_id, v.ghsa_id, v.package, v.vendor, v.product)]
    if target_date:
        # Filter strictly by the source-of-truth publish date. `first_seen` is
        # intentionally excluded — it tracks when *our* cache first observed
        # the row, so on cold-start days it stamps the entire backlog with
        # today and would return everything.
        items = [v for v in items if _matches_date(v.published, target_date)]
    if sort == "heat":
        items.sort(key=lambda x: -x.heat)
    else:
        items.sort(key=lambda x: x.published or "", reverse=True)
    return items[:limit]


@app.get("/api/vuln/{vuln_id}", response_model=Vuln, tags=["vulnerability"])
def api_vuln_detail(vuln_id: str) -> Vuln:
    """Return a single vulnerability by CVE-ID, GHSA-ID, or internal id.

    Lookup is case-insensitive on CVE/GHSA prefixes.
    """
    needle = vuln_id.strip().upper()
    for v in all_vulns():
        if v.cve_id and v.cve_id.upper() == needle:
            return v
        if v.ghsa_id and v.ghsa_id.upper() == needle:
            return v
        if v.id.upper() == needle:
            return v
    raise HTTPException(status_code=404, detail=f"vuln '{vuln_id}' not found")


@app.get("/api/heat", response_model=list[HeatEntry], tags=["overview"])
def api_heat(
    limit: int = Query(default=10, ge=1, le=50),
    kind: Literal["vuln", "news"] = Query(default="vuln", description="vuln=CVE heat (default, back-compat); news=top AI-scored articles"),
    date: str | None = Query(default=None, description="YYYY-MM-DD; only news heat honors this (vuln heat is timeless)"),
) -> list[HeatEntry]:
    if kind == "news":
        from .data import news_heat_board
        target = _validate_date(date)
        return news_heat_board(limit, date=target)
    return heat_board(limit)


@app.get("/api/sources", response_model=list[SourceStatus], tags=["sources"])
def api_sources() -> list[SourceStatus]:
    return all_sources()


@app.get("/api/manifest", response_model=Manifest, tags=["overview"])
def api_manifest() -> Manifest:
    return manifest_fn()


@app.get("/api/brief", tags=["news"])
def api_brief(
    date: str | None = Query(default=None, description="YYYY-MM-DD; default today"),
) -> JSONResponse:
    """Return daily briefing per category for a given date — reads SQLite `daily_briefs` table."""
    from .data import _news_conn, _NEWS_DB
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


def _today_utc_str() -> str:
    from datetime import datetime as _dt, timezone as _tz
    return _dt.now(_tz.utc).strftime("%Y-%m-%d")


def _run_llm_brief_subprocess(target_date: str) -> None:
    """Background-task wrapper. Invoked off the HTTP request path."""
    global _brief_regen_in_flight
    try:
        subprocess.run(
            ["uv", "run", "python", "scripts/llm_rank.py", "--task", "daily_brief", "--date", target_date],
            cwd=str(ROOT), check=False, timeout=300,
        )
    except Exception as exc:
        log.error(f"brief regenerate failed: {exc}")
    finally:
        with _brief_regen_lock:
            _brief_regen_in_flight = False


@app.post("/api/brief/regenerate", tags=["news"])
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
    if not expected or not x_refresh_token or not secrets.compare_digest(x_refresh_token, expected):
        raise HTTPException(status_code=401, detail="invalid refresh token")
    target = _validate_date(date) or _today_utc_str()
    global _brief_regen_in_flight
    with _brief_regen_lock:
        if _brief_regen_in_flight:
            raise HTTPException(status_code=409, detail="brief regeneration already in progress")
        _brief_regen_in_flight = True
    background.add_task(_run_llm_brief_subprocess, target)
    return JSONResponse(status_code=202, content={"status": "accepted", "date": target})


@app.get("/api/diff", tags=["overview"])
def api_diff(
    since: str = Query(..., description="show items first seen on or after this date (YYYY-MM-DD)"),
    limit: int = Query(default=100, ge=1, le=1000),
) -> JSONResponse:
    """List items first seen on or after `since` — uses the snapshot layer's
    `first_seen` annotation (vulns) and `published` date (news) for filtering.
    """
    target = _validate_date(since)
    assert target is not None  # _validate_date raises on bad input
    vulns = all_vulns()
    new_vulns = [v for v in vulns if (v.first_seen or "") >= target]
    new_vulns.sort(key=lambda x: (x.first_seen or "", -x.heat), reverse=True)

    articles = all_articles()
    new_news = [a for a in articles if (a.published or "") and a.published[:10] >= target]
    new_news.sort(key=lambda x: x.published or "", reverse=True)

    return JSONResponse({
        "since": target,
        "vuln_added": len(new_vulns),
        "news_added": len(new_news),
        "vulns": [v.model_dump() for v in new_vulns[:limit]],
        "news": [a.model_dump() for a in new_news[:limit]],
    })


@app.get("/api/healthz", tags=["overview"])
def healthz() -> JSONResponse:
    """Liveness + per-fetcher freshness/status summary.

    Overall `ok` is True iff every fetcher's `status` is `ok`. `degraded`
    becomes True if any fetcher is `no_data` (data missing but pipeline alive);
    `error` flags hard failures (network/auth/parse).
    """
    from datetime import datetime, timezone
    m = manifest_fn()
    now = datetime.now(timezone.utc)
    fetchers: list[dict] = []
    overall_status = "ok"
    for r in m.results:
        # Per-fetcher freshness (falls back to the run's overall timestamp
        # for older manifest entries that predate finished_at recording).
        age_minutes: float | None = None
        stamp_iso = r.finished_at or m.fetched_at
        if stamp_iso:
            try:
                stamp = datetime.fromisoformat(stamp_iso.replace("Z", "+00:00"))
                age_minutes = round((now - stamp).total_seconds() / 60, 1)
            except ValueError:
                pass
        fetchers.append({
            "name": r.name,
            "status": r.status or ("ok" if r.ok else "error"),
            "count": r.count,
            "age_minutes": age_minutes,
            "elapsed_s": r.elapsed_s,
            "error": r.error,
            "has_diagnostic": r.diagnostic is not None,
        })
        if r.status == "error":
            overall_status = "error"
        elif r.status == "no_data" and overall_status == "ok":
            overall_status = "degraded"
    return JSONResponse({
        "ok": overall_status == "ok",
        "status": overall_status,
        "last_fetch": m.fetched_at,
        "fetchers": fetchers,
    })


REFRESH_TOKEN_ENV = "SECURITY_HOT_REFRESH_TOKEN"
_refresh_lock = threading.Lock()
_refresh_in_flight = False

_brief_regen_lock = threading.Lock()
_brief_regen_in_flight: bool = False


def _run_fetcher(only: list[str] | None) -> None:
    """Spawn fetch_data.py in a subprocess. Designed to run inside a
    BackgroundTask; releases the in-flight lock in `finally` so a crashed
    subprocess doesn't permanently jam the endpoint."""
    global _refresh_in_flight
    try:
        cmd = [sys.executable, str(ROOT / "scripts" / "fetch_data.py")]
        if only:
            cmd.extend(["--only", ",".join(only)])
        log.info("fetcher refresh starting: %s", " ".join(cmd))
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, cwd=str(ROOT))
        if proc.returncode == 0:
            log.info("fetcher refresh finished ok (%d bytes stderr)", len(proc.stderr or ""))
        else:
            log.warning("fetcher refresh exited %s: %s", proc.returncode, (proc.stderr or "")[:500])
    finally:
        with _refresh_lock:
            _refresh_in_flight = False


@app.post("/api/refresh", tags=["overview"])
def api_refresh(
    background: BackgroundTasks,
    only: str | None = Query(default=None, description="comma-separated fetcher names; default = all"),
    x_refresh_token: str | None = Header(default=None),
) -> JSONResponse:
    """Trigger a fetcher run in the background.

    Auth: set `SECURITY_HOT_REFRESH_TOKEN` env var. If unset, the endpoint is
    disabled (returns 503). Pass `X-Refresh-Token: <token>` to authorize.
    Token compare is constant-time (secrets.compare_digest).
    """
    expected = os.environ.get(REFRESH_TOKEN_ENV)
    if not expected:
        raise HTTPException(status_code=503, detail=f"refresh disabled; set {REFRESH_TOKEN_ENV} to enable")
    if not x_refresh_token or not secrets.compare_digest(x_refresh_token, expected):
        raise HTTPException(status_code=401, detail="invalid refresh token")
    global _refresh_in_flight
    with _refresh_lock:
        if _refresh_in_flight:
            return JSONResponse({"queued": False, "reason": "already running"}, status_code=409)
        _refresh_in_flight = True
    chosen = [s.strip() for s in only.split(",") if s.strip()] if only else None
    background.add_task(_run_fetcher, chosen)
    return JSONResponse({"queued": True, "only": chosen}, status_code=202)


@app.get("/api/news/hidden", response_model=list[Article], tags=["news"])
def api_news_hidden(
    date: str | None = Query(default=None, description="YYYY-MM-DD; default=today UTC"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[Article]:
    """Articles judged is_relevant=0 — for human audit of LLM filter."""
    from .data import _news_conn, _NEWS_DB, _row_to_article
    if not _NEWS_DB.exists():
        return []
    target = _validate_date(date) or _today_utc_str()
    conn = _news_conn()
    rows = list(conn.execute("""
        SELECT * FROM articles
        WHERE is_relevant = 0 AND first_seen_date = ?
        ORDER BY fetched_at DESC LIMIT ?
    """, [target, limit]))
    conn.close()
    return [_row_to_article(r, {}) for r in rows]


@app.get("/api/news/{article_id}/mirrors", response_model=list[Article], tags=["news"])
def api_article_mirrors(article_id: int) -> list[Article]:
    """Return all mirror articles in the same cluster (excludes primary)."""
    from .data import _news_conn, _NEWS_DB, _row_to_article
    if not _NEWS_DB.exists():
        raise HTTPException(status_code=404, detail="news.db not found")
    conn = _news_conn()
    primary = conn.execute(
        "SELECT cluster_id FROM articles WHERE id = ?", [article_id]
    ).fetchone()
    if not primary or not primary["cluster_id"]:
        conn.close()
        raise HTTPException(status_code=404, detail="no cluster for this article")
    rows = list(conn.execute("""
        SELECT * FROM articles
        WHERE cluster_id = ? AND id != ?
        ORDER BY fetched_at ASC
    """, [primary["cluster_id"], article_id]))
    conn.close()
    return [_row_to_article(r, {}) for r in rows]


# mount frontend static files
if WEB.exists():
    app.mount("/", StaticFiles(directory=str(WEB), html=True), name="web")
