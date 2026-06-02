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
import json as _json
import logging
import os
import secrets
import threading
import time as _time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

# Load .env BEFORE any code reads os.environ. `uv run uvicorn ...` does not
# auto-load .env, which silently disables the brief regenerate endpoint and
# breaks the LLM background tasks that inherit this process's env.
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

# Centralised logging so pipeline output + app logs share a single format.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("security-hot")

from . import pipeline_status as ps
from .ingest import run_fetchers
from .data import (
    all_articles,
    all_sources,
    all_vulns,
    heat_board,
    load_dispatches,
    manifest as manifest_fn,
    search_aggregated,
    search_articles,
    today_summary,
)
from .models import (
    Article,
    DispatchEntry,
    HeatEntry,
    Manifest,
    SearchResult,
    SourceStatus,
    TodaySummary,
    Vuln,
)

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
_main_loop: asyncio.AbstractEventLoop | None = None


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Start the optional in-process pipeline scheduler (see scheduler.py).
    # The job functions live further down this module; they exist by the time
    # startup runs. Stays None when SECURITY_HOT_SCHEDULER_ENABLED is unset.
    from .ingest.pool import shutdown_pool, start_pool
    from .scheduler import start_scheduler, stop_scheduler
    global _main_loop
    _main_loop = asyncio.get_running_loop()
    app.state.ingest_pool = start_pool()
    app.state.scheduler = start_scheduler(
        fetch_news=_sched_fetch_news,
        fetch_murphy=_sched_fetch_murphy,
        daily_brief=_sched_daily_brief,
        fetch_other=_sched_fetch_other,
    )
    yield
    sched = getattr(app.state, "scheduler", None)
    if sched is not None:
        log.info("scheduler stopping")
        stop_scheduler(sched)
    shutdown_pool()
    _main_loop = None


app = FastAPI(
    title="security-hot",
    version="0.1.0",
    description="Daily aggregator for security news, vulnerability intel, and papers.",
    lifespan=_lifespan,
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
    return items[:limit]


@app.get("/api/dispatches", response_model=list[DispatchEntry], tags=["vulnerability"])
def api_dispatches(
    limit: int = Query(default=100, ge=1, le=1000),
    origin: str = Query(default="all", description="all | vuln | news"),
) -> list[DispatchEntry]:
    return load_dispatches(limit=limit, origin=origin)


@app.get("/api/search", response_model=SearchResult, tags=["search"])
def api_search(
    q: str = Query(..., min_length=2, description="Search query"),
    limit: int = Query(default=10, ge=1, le=30, description="Max results per category"),
) -> SearchResult:
    return search_aggregated(q, limit)


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
    date: str | None = Query(default=None, description="YYYY-MM-DD; filters both vuln and news heat boards"),
) -> list[HeatEntry]:
    target = _validate_date(date)
    if kind == "news":
        from .data import news_heat_board
        return news_heat_board(limit, date=target)
    return heat_board(limit, date=target)


@app.get("/api/sources", response_model=list[SourceStatus], tags=["sources"])
def api_sources() -> list[SourceStatus]:
    return all_sources()


@app.get("/api/manifest", response_model=Manifest, tags=["overview"])
def api_manifest() -> Manifest:
    return manifest_fn()


# Human labels for the scheduler jobs (frontend renders these as group headers).
_JOB_LABELS = {
    "fetch_news": "资讯抓取",
    "fetch_murphy": "墨菲漏洞预警",
    "fetch_other": "其它情报源",
    "heavy_pipeline": "富化 + LLM 流水线",
    "daily_brief": "每日简报",
}


@app.get("/api/pipeline", tags=["overview"])
def api_pipeline() -> JSONResponse:
    """Durable per-step status of the WHOLE pipeline (fetchers + enrichment/LLM).

    Each step carries: last run time, ok/failed/pending, count, elapsed, the
    failure reason (stderr tail) if any, and — when the in-process scheduler is
    running — the next scheduled run. This is what the frontend status modal reads.
    """
    ps.bootstrap_from_manifest_if_empty(ROOT / "backend" / "cache" / "manifest.json")
    steps = ps.load_steps()

    # Next-run time per scheduler job (only present in the in-process scheduler
    # deployment; cron / local-dev has no scheduler object → next_run is null).
    sched = getattr(app.state, "scheduler", None)
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
        "refresh_in_flight": _refresh_in_flight,
        "refresh_stage": _refresh_stage,
        "overall": overall,
        "error_count": n_error,
        "jobs": jobs,
        "steps": steps,
    })


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


async def _run_llm_brief_task(target_date: str) -> None:
    """Background-task wrapper. Invoked off the HTTP request path."""
    global _brief_regen_in_flight
    try:
        from .ingest.pipeline import generate_daily_brief

        await generate_daily_brief(target_date=target_date, verbose=True)
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
    # Distinguish "feature disabled (server-side missing config)" from
    # "wrong token (user-side)" so the UI can show a useful message.
    if not expected:
        raise HTTPException(status_code=503, detail="brief regenerate disabled — set SECURITY_HOT_REFRESH_TOKEN in .env")
    if not x_refresh_token or not secrets.compare_digest(x_refresh_token, expected):
        raise HTTPException(status_code=401, detail="invalid refresh token")
    target = _validate_date(date) or _today_utc_str()
    global _brief_regen_in_flight
    with _brief_regen_lock:
        if _brief_regen_in_flight:
            raise HTTPException(status_code=409, detail="brief regeneration already in progress")
        _brief_regen_in_flight = True
    background.add_task(_run_llm_brief_task, target)
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
    refresh_elapsed_s = round(_time.monotonic() - _refresh_started_at, 1) if _refresh_in_flight and _refresh_started_at else None

    progress = None
    if _refresh_in_flight:
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
        "refresh_in_flight": _refresh_in_flight,
        "refresh_stage": _refresh_stage,
        "refresh_elapsed_s": refresh_elapsed_s,
        "refresh_stage_history": _refresh_stage_history if _refresh_stage_history else None,
        "refresh_progress": progress,
    })


REFRESH_TOKEN_ENV = "SECURITY_HOT_REFRESH_TOKEN"
_refresh_lock = asyncio.Lock()
_refresh_in_flight = False
_refresh_stage = ""  # "", "fetching", "classifying", "summarizing", "assessing", "done", "error"
_refresh_started_at: float | None = None
_refresh_stage_started_at: float | None = None
_refresh_stage_history: dict = {}       # {stage: elapsed_s} for the most recent completed run

_brief_regen_lock = threading.Lock()
_brief_regen_in_flight: bool = False


_LLM_TASKS_BY_SCOPE = {
    "news": ["news_classify", "news_summarize", "daily_brief"],
    "vuln": ["vuln_assess"],
    "all":  ["news_classify", "news_summarize", "daily_brief"],
}

def _reset_refresh_state() -> None:
    global _refresh_started_at, _refresh_stage, _refresh_stage_started_at, _refresh_stage_history
    _refresh_started_at = _time.monotonic()
    _refresh_stage = ""
    _refresh_stage_started_at = None
    _refresh_stage_history = {}
    try:
        (ROOT / "backend" / "cache" / ".refresh_progress.json").unlink(missing_ok=True)
    except OSError:
        pass


async def _begin_refresh(source: str) -> bool:
    global _refresh_in_flight
    async with _refresh_lock:
        if _refresh_in_flight:
            log.info("%s: skipped — refresh already in flight", source)
            return False
        _refresh_in_flight = True
        _reset_refresh_state()
        return True


async def _finish_refresh() -> None:
    global _refresh_in_flight
    async with _refresh_lock:
        _refresh_in_flight = False


def _run_coro_blocking(coro):
    if _main_loop is not None and _main_loop.is_running():
        future = asyncio.run_coroutine_threadsafe(coro, _main_loop)
        return future.result()
    return asyncio.run(coro)


def _set_stage(stage: str) -> None:
    global _refresh_stage, _refresh_stage_started_at, _refresh_stage_history
    now = _time.monotonic()
    if _refresh_stage and _refresh_stage_started_at:
        _refresh_stage_history[_refresh_stage] = round(now - _refresh_stage_started_at, 1)
    _refresh_stage = stage
    _refresh_stage_started_at = now


def _record_step_status(script: str, step: str | None, ok: bool, elapsed: float,
                        stderr: str | None, returncode: int | None) -> None:
    """Persist one pipeline step's outcome to the durable status store
    (backend/app/pipeline_status.py). Fetchers are recorded per-fetcher from the
    manifest they just wrote; enrichment/LLM scripts by their canonical name.
    Best-effort: a status-write failure must never break the pipeline."""
    try:
        if Path(script).name == "fetch_data.py":
            ps.upsert_from_manifest(ROOT / "backend" / "cache" / "manifest.json")
        elif step:
            ps.upsert_step(step, ok=ok, elapsed_s=elapsed,
                           error=None if ok else stderr, returncode=returncode)
    except Exception:
        log.exception("failed to record pipeline status for %s", script)


def _record_pipeline_result(step: str, result: dict) -> None:
    if step not in {"embed", "cluster", "classify", "summarize", "daily_brief"}:
        return
    ok = bool(result.get("ok"))
    error = result.get("error")
    if not ok and error is None and isinstance(result.get("result"), dict):
        error = _json.dumps(result["result"], ensure_ascii=False)
    try:
        ps.upsert_step(
            step,
            ok=ok,
            elapsed_s=float(result.get("elapsed_s") or 0),
            error=error,
            returncode=0 if ok else 1,
        )
    except Exception:
        log.exception("failed to record pipeline result for %s", step)


async def _run_news_pipeline(*, include_daily_brief: bool = False) -> dict:
    from .ingest.pipeline import generate_daily_brief, on_news_fetched

    results = await on_news_fetched(stage_cb=_set_stage)
    for name in ("embed", "cluster"):
        if name in results:
            _record_pipeline_result(name, results[name])
    if "classify" in results:
        _record_pipeline_result("classify", results["classify"])
    if "summarize" in results:
        _record_pipeline_result("summarize", results["summarize"])
    if include_daily_brief:
        t0 = _time.monotonic()
        try:
            brief = await generate_daily_brief(verbose=True)
            results["daily_brief"] = {
                "ok": True,
                "result": brief,
                "elapsed_s": round(_time.monotonic() - t0, 2),
            }
        except Exception as exc:
            results["daily_brief"] = {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "elapsed_s": round(_time.monotonic() - t0, 2),
            }
        _record_pipeline_result("daily_brief", results["daily_brief"])
    return results


async def _run_vuln_pipeline() -> dict:
    from .ingest.pipeline import on_vuln_fetched

    return await on_vuln_fetched(stage_cb=_set_stage)


def _fetcher_names_from_args(args: list[str]) -> list[str] | None:
    if not args or args[0] != "fetch_data.py":
        return None
    for idx, arg in enumerate(args[1:]):
        if arg == "--only" and idx + 2 < len(args):
            return [s.strip() for s in args[idx + 2].split(",") if s.strip()]
        if arg.startswith("--only="):
            return [s.strip() for s in arg.split("=", 1)[1].split(",") if s.strip()]
    return None


def _fetcher_concurrency_from_args(args: list[str]) -> int | None:
    for idx, arg in enumerate(args[1:]):
        if arg == "--concurrency" and idx + 2 < len(args):
            try:
                return int(args[idx + 2])
            except ValueError:
                return None
        if arg.startswith("--concurrency="):
            try:
                return int(arg.split("=", 1)[1])
            except ValueError:
                return None
    return None


async def _run_fetch_step(label: str, names: list[str] | None, concurrency: int | None = None) -> bool:
    log.info("scheduler: %s -> run_fetchers(%s)", label, names or "all")
    t0 = _time.monotonic()
    try:
        result = await run_fetchers(names, concurrency)
        elapsed = _time.monotonic() - t0
        ok = bool(result.get("ok"))
        returncode = int(result.get("returncode", 1))
        _record_step_status("fetch_data.py", None, ok, elapsed, None, returncode)
        if ok:
            log.info("scheduler: %s ok", label)
        else:
            log.warning("scheduler: %s exited %s", label, returncode)
        return ok
    except Exception as exc:
        elapsed = _time.monotonic() - t0
        error = f"{type(exc).__name__}: {exc}"[:500]
        _record_step_status("fetch_data.py", None, False, elapsed, error, 1)
        log.warning("scheduler: %s failed: %s", label, error)
        return False


async def _run_fetcher(only: list[str] | None, llm_tasks: list[str] | None = None) -> None:
    """Run fetchers in-process, then optionally chain the service pipeline."""
    try:
        _set_stage("fetching")
        ok = await _run_fetch_step("fetcher refresh", only)
        if not ok:
            _set_stage("error")
            return

        tasks = set(llm_tasks or [])
        if {"news_classify", "news_summarize", "daily_brief"} & tasks:
            log.info("manual refresh: running news pipeline")
            await _run_news_pipeline(include_daily_brief="daily_brief" in tasks)
        if "vuln_assess" in tasks:
            log.info("manual refresh: running vuln pipeline")
            await _run_vuln_pipeline()
        _set_stage("done")
    finally:
        await _finish_refresh()


@asynccontextmanager
async def _pipeline_run():
    """Own the shared refresh state for one scheduler pipeline run."""
    owned = await _begin_refresh("scheduler")
    if not owned:
        yield False
        return
    try:
        yield True
    except Exception:
        log.exception("scheduler: pipeline run crashed")
        try:
            _set_stage("error")
        except Exception:
            log.exception("scheduler: failed to record error stage")
    finally:
        await _finish_refresh()


async def _sched_fetch_news_async() -> None:
    async with _pipeline_run() as owned:
        if not owned:
            return
        _set_stage("fetching")
        ok = await _run_fetch_step("fetch news", ["news"])
        if not ok:
            _set_stage("error")
            return
        await _run_news_pipeline(include_daily_brief=False)
        _set_stage("done")


def _sched_fetch_news() -> None:
    _run_coro_blocking(_sched_fetch_news_async())


async def _sched_fetch_murphy_async() -> None:
    # Murphy is a time-sensitive vuln-warn feed → its own short-interval job
    # (default 5min) instead of the 4h "other" bucket. Incremental + idempotent.
    # This job aborts the rest of the pipeline if the fetch fails and then runs
    # vuln assessment + dispatch in-process.
    async with _pipeline_run() as owned:
        if not owned:
            return

        _set_stage("fetching")
        ok = await _run_fetch_step("fetch murphy", ["murphy"])
        if not ok:
            _set_stage("error")
            return

        await _run_vuln_pipeline()
        _set_stage("done")


def _sched_fetch_murphy() -> None:
    _run_coro_blocking(_sched_fetch_murphy_async())


def _sched_daily_brief() -> None:
    async def _run() -> None:
        async with _pipeline_run() as owned:
            if not owned:
                return
            from .ingest.pipeline import generate_daily_brief

            _set_stage("summarizing")
            t0 = _time.monotonic()
            try:
                result = await generate_daily_brief(verbose=True)
                _record_pipeline_result(
                    "daily_brief",
                    {"ok": True, "result": result, "elapsed_s": round(_time.monotonic() - t0, 2)},
                )
                _set_stage("done")
            except Exception as exc:
                _record_pipeline_result(
                    "daily_brief",
                    {
                        "ok": False,
                        "error": f"{type(exc).__name__}: {exc}",
                        "elapsed_s": round(_time.monotonic() - t0, 2),
                    },
                )
                _set_stage("error")

    _run_coro_blocking(_run())


async def _sched_fetch_other_async() -> None:
    # murphy is intentionally excluded here — it has its own 5min job above.
    async with _pipeline_run() as owned:
        if not owned:
            return
        _set_stage("fetching")
        ok = await _run_fetch_step(
            "fetch other",
            ["kev", "ghsa", "pocs", "itw", "heat", "epss", "osv", "nuclei", "hn", "masto"],
        )
        if not ok:
            _set_stage("error")
            return
        await _run_vuln_pipeline()
        _set_stage("done")


def _sched_fetch_other() -> None:
    _run_coro_blocking(_sched_fetch_other_async())


@app.post("/api/refresh", tags=["overview"])
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
    `vuln` runs vuln_assess; `all` runs everything news-side; default `none`
    skips LLM entirely.
    """
    expected = os.environ.get(REFRESH_TOKEN_ENV)
    if not expected:
        raise HTTPException(status_code=503, detail=f"refresh disabled; set {REFRESH_TOKEN_ENV} to enable")
    if not x_refresh_token or not secrets.compare_digest(x_refresh_token, expected):
        raise HTTPException(status_code=401, detail="invalid refresh token")
    if not await _begin_refresh("manual refresh"):
        return JSONResponse({"queued": False, "reason": "already running"}, status_code=409)
    chosen = [s.strip() for s in only.split(",") if s.strip()] if only else None
    llm_tasks = _LLM_TASKS_BY_SCOPE.get((llm or "none").lower(), [])
    background.add_task(_run_fetcher, chosen, llm_tasks or None)
    return JSONResponse({"queued": True, "only": chosen, "llm": llm_tasks}, status_code=202)


@app.get("/api/news/hidden", response_model=list[Article], tags=["news"])
def api_news_hidden(
    date: str | None = Query(default=None, description="YYYY-MM-DD published date; default = today UTC"),
    limit: int = Query(default=50, ge=1, le=1000),
) -> list[Article]:
    """Articles judged is_relevant=0 — for human audit of LLM filter.

    Filtered by **published** date (falls back to fetched_at when published is
    NULL) to match /api/news semantics — the date strip in the UI selects a
    publish day, and the hidden view should respect that selection.
    """
    from .data import _news_conn, _NEWS_DB, _row_to_article
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
