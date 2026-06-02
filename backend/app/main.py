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

This module is the app factory: it builds the FastAPI `app`, loads .env,
configures logging + CORS, wires the lifespan (ingest pool + scheduler), and
mounts the route packages. The actual endpoint handlers live in the
routes_* modules; the refresh state machine, pipeline orchestration, and
scheduler job bodies live in their own modules.
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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

from .runtime import refresh_state
from .routes import news as routes_news, ops as routes_ops, vuln as routes_vuln
from .runtime.scheduler_jobs import (
    _sched_daily_brief,
    _sched_enrich,
    _sched_fetch_murphy,
    _sched_fetch_news,
    _sched_fetch_other,
)

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"

# Brief-regenerate guard flag, mirrored from routes_news so external callers
# and tests can reference/poke `backend.app.main._brief_regen_in_flight`
# (kept here for back-compat with the pre-split single-module layout).
_brief_regen_in_flight: bool = False


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Start the optional in-process pipeline scheduler (see scheduler.py).
    # The job functions live in scheduler_jobs. Stays None when
    # SECURITY_HOT_SCHEDULER_ENABLED is unset.
    from .ingest.pool import shutdown_pool, start_pool
    from .runtime.scheduler import start_scheduler, stop_scheduler
    refresh_state._main_loop = asyncio.get_running_loop()
    app.state.ingest_pool = start_pool()
    app.state.scheduler = start_scheduler(
        fetch_news=_sched_fetch_news,
        fetch_murphy=_sched_fetch_murphy,
        daily_brief=_sched_daily_brief,
        fetch_other=_sched_fetch_other,
        enrich=_sched_enrich,
    )
    yield
    sched = getattr(app.state, "scheduler", None)
    if sched is not None:
        log.info("scheduler stopping")
        stop_scheduler(sched)
    shutdown_pool()
    refresh_state._main_loop = None


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

app.include_router(routes_ops.router)
app.include_router(routes_news.router)
app.include_router(routes_vuln.router)

# mount frontend static files
if WEB.exists():
    app.mount("/", StaticFiles(directory=str(WEB), html=True), name="web")
