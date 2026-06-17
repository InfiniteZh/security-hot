"""Operations / overview routes: today, sources, manifest, pipeline, diff,
healthz, refresh."""
from __future__ import annotations

import json as _json
import logging
import os
import re
import secrets
import time as _time
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel as _BaseModel

from ..runtime import pipeline_status as ps
from ..runtime import refresh_state
from ..data import (
    all_articles,
    all_sources,
    all_vulns,
    manifest as manifest_fn,
    today_summary,
)
from ..models import Manifest, SourceStatus, TodaySummary

log = logging.getLogger("security-hot")

ROOT = Path(__file__).resolve().parents[3]

router = APIRouter()


_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _matches_date(timestamp: str | None, target: str) -> bool:
    if not timestamp:
        return False
    return timestamp[:10] == target


def _within_window(timestamp: str | None, end: str, days: int) -> bool:
    """True if ``timestamp``'s calendar day falls in the inclusive window
    ``[end - (days-1), end]``. ``days <= 1`` collapses to a single-day match.

    Used by the vuln view, whose publish dates are sparse across the calendar:
    a single-day filter on "today" is almost always empty, so the UI defaults
    to a rolling N-day window instead. News keeps strict single-day semantics.
    """
    if not timestamp:
        return False
    day = timestamp[:10]
    if days <= 1:
        return day == end
    from datetime import datetime as _dt, timedelta as _td
    try:
        start = (_dt.strptime(end, "%Y-%m-%d") - _td(days=days - 1)).strftime("%Y-%m-%d")
    except ValueError:
        return day == end
    return start <= day <= end


def _validate_date(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if not _DATE_RE.match(value):
        raise HTTPException(status_code=400, detail=f"date must be YYYY-MM-DD, got {value!r}")
    return value


def _today_utc_str() -> str:
    from datetime import datetime as _dt, timezone as _tz
    return _dt.now(_tz.utc).strftime("%Y-%m-%d")


@router.get("/api/today", response_model=TodaySummary, tags=["overview"])
def api_today() -> TodaySummary:
    return today_summary()


@router.get("/api/sources", response_model=list[SourceStatus], tags=["sources"])
def api_sources() -> list[SourceStatus]:
    return all_sources()


@router.get("/api/manifest", response_model=Manifest, tags=["overview"])
def api_manifest() -> Manifest:
    return manifest_fn()


@router.get("/api/pipeline", tags=["overview"])
def api_pipeline(request: Request) -> JSONResponse:
    """Durable per-step status of the WHOLE pipeline (fetchers + enrichment/LLM).

    Each step carries: last run time, ok/failed/pending, count, elapsed, the
    failure reason (stderr tail) if any, and — when the in-process scheduler is
    running — the next scheduled run. This is what the frontend status modal reads.
    """
    from ..runtime.scheduler_jobs import _JOB_LABELS

    ps.bootstrap_from_manifest_if_empty(ROOT / "backend" / "cache" / "manifest.json")
    steps = ps.load_steps()

    # Next-run time per scheduler job (only present in the in-process scheduler
    # deployment; cron / local-dev has no scheduler object → next_run is null).
    sched = getattr(request.app.state, "scheduler", None)
    jobs: dict[str, dict] = {}
    if sched is not None:
        try:
            for job in sched.get_jobs():
                nrt = getattr(job, "next_run_time", None)
                jobs[job.id] = {
                    "next_run": nrt.isoformat() if nrt else None,
                    "label": _JOB_LABELS.get(job.id, job.id),
                }
        except Exception:
            log.exception("pipeline: failed to read scheduler jobs")

    for s in steps:
        job = jobs.get(s.get("job") or "")
        s["next_run"] = job["next_run"] if job else None
        s["job_label"] = _JOB_LABELS.get(s.get("job") or "", s.get("job"))

    n_error = sum(1 for s in steps if s.get("status") == "error")
    n_pending = sum(1 for s in steps if s.get("status") == "pending")
    overall = "error" if n_error else ("ok" if (len(steps) - n_pending) else "pending")

    return JSONResponse({
        "now": ps.now_iso(),
        "scheduler_enabled": sched is not None,
        "refresh_in_flight": refresh_state._refresh_in_flight,
        "refresh_stage": refresh_state._refresh_stage,
        "overall": overall,
        "error_count": n_error,
        "jobs": jobs,
        "steps": steps,
    })


@router.get("/api/diff", tags=["overview"])
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


@router.get("/api/healthz", tags=["overview"])
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
    refresh_elapsed_s = (
        round(_time.monotonic() - refresh_state._refresh_started_at, 1)
        if refresh_state._refresh_in_flight and refresh_state._refresh_started_at
        else None
    )

    progress = None
    if refresh_state._refresh_in_flight:
        try:
            _pf = ROOT / "backend" / "cache" / ".refresh_progress.json"
            if _pf.exists():
                _pd = _json.loads(_pf.read_text(encoding="utf-8"))
                if _time.time() - _pd.get("ts", 0) < 600:
                    progress = _pd
        except (OSError, ValueError):
            pass

    return JSONResponse({
        "ok": overall_status == "ok",
        "status": overall_status,
        "last_fetch": m.fetched_at,
        "fetchers": fetchers,
        "refresh_in_flight": refresh_state._refresh_in_flight,
        "refresh_stage": refresh_state._refresh_stage,
        "refresh_elapsed_s": refresh_elapsed_s,
        "refresh_stage_history": refresh_state._refresh_stage_history if refresh_state._refresh_stage_history else None,
        "refresh_progress": progress,
    })


@router.post("/api/refresh", tags=["overview"])
async def api_refresh(
    background: BackgroundTasks,
    only: str | None = Query(default=None, description="comma-separated fetcher names; default = all"),
    llm: str | None = Query(default=None, description="LLM scope: news | vuln | all | none (default: none)"),
    x_refresh_token: str | None = Header(default=None),
) -> JSONResponse:
    """Trigger a fetcher run in the background.

    Auth: set `SECURITY_HOT_REFRESH_TOKEN` env var. If unset, the endpoint is
    disabled (returns 503). Pass `X-Refresh-Token: <token>` to authorize.
    Token compare is constant-time (secrets.compare_digest).

    `llm` chains the in-process AI pipeline after fetch: `news` runs classify+summarize+brief;
    `vuln` runs vuln_assess; `all` runs everything news-side. With no explicit
    `llm`, single-source `only=news` and `only=murphy` still chain their dispatch
    pipelines; all other single-source pulls stay fetch-only.
    """
    from ..runtime.pipeline_runner import _resolve_refresh_pipeline, _run_fetcher

    expected = os.environ.get(refresh_state.REFRESH_TOKEN_ENV)
    if not expected:
        raise HTTPException(status_code=503, detail=f"refresh disabled; set {refresh_state.REFRESH_TOKEN_ENV} to enable")
    if not x_refresh_token or not secrets.compare_digest(x_refresh_token, expected):
        raise HTTPException(status_code=401, detail="invalid refresh token")
    if not await refresh_state._begin_refresh("manual refresh"):
        return JSONResponse({"queued": False, "reason": "already running"}, status_code=409)
    chosen = [s.strip() for s in only.split(",") if s.strip()] if only else None
    llm_scope, llm_tasks = _resolve_refresh_pipeline(chosen, llm)
    background.add_task(_run_fetcher, chosen, llm_tasks or None)
    return JSONResponse({"queued": True, "only": chosen, "llm": llm_tasks, "llm_scope": llm_scope}, status_code=202)


class _UnbanBody(_BaseModel):
    slugs: list[str] = []  # 空列表 = 全部解封


@router.post("/api/sources/unban", tags=["sources"])
async def api_sources_unban(
    body: _UnbanBody,
    x_refresh_token: str | None = Header(default=None),
) -> JSONResponse:
    """Reset consecutive_failures for benched sources, re-admitting them to polling.

    Pass `{"slugs": [...]}` to unban specific sources; empty list unbans all.
    Requires `X-Refresh-Token` (same token as /api/refresh).
    """
    from ..ingest import db as _db
    from ..news import cache_io as _cache_io

    expected = os.environ.get(refresh_state.REFRESH_TOKEN_ENV)
    if not expected:
        raise HTTPException(status_code=503, detail=f"unban disabled; set {refresh_state.REFRESH_TOKEN_ENV} to enable")
    if not x_refresh_token or not secrets.compare_digest(x_refresh_token, expected):
        raise HTTPException(status_code=401, detail="invalid refresh token")

    conn = _db.connect(_cache_io._NEWS_DB)
    n = _db.unban_sources(conn, body.slugs if body.slugs else None)
    conn.close()
    return JSONResponse({"ok": True, "reset": n})
