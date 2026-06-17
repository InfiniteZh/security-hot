"""In-process refresh state machine — single source of truth.

Shared between the HTTP refresh endpoint (routes_ops.api_refresh) and the
APScheduler jobs (scheduler_jobs). Consumers must read the mutable globals via
`from . import refresh_state` and reference `refresh_state.<name>` so they see
live values rather than an import-time snapshot.
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
import time as _time
from pathlib import Path

from fastapi import HTTPException

log = logging.getLogger("security-hot")

# backend/app/runtime/ is 3 levels below repo root → parents[3] (see
# pipeline_runner.py); parents[2] wrongly resolves to .../backend.
ROOT = Path(__file__).resolve().parents[3]

REFRESH_TOKEN_ENV = "SECURITY_HOT_REFRESH_TOKEN"


def require_refresh_token(x_refresh_token: str | None, *, feature: str = "this endpoint") -> None:
    """Constant-time guard shared by all token-protected endpoints.

    Raises 503 when the token env var is unset (feature disabled), 401 on
    mismatch. Centralizes the check so every endpoint reads the same env var
    name and uses secrets.compare_digest.
    """
    expected = os.environ.get(REFRESH_TOKEN_ENV)
    if not expected:
        raise HTTPException(status_code=503, detail=f"{feature} disabled; set {REFRESH_TOKEN_ENV} to enable")
    if not x_refresh_token or not secrets.compare_digest(x_refresh_token, expected):
        raise HTTPException(status_code=401, detail="invalid or missing refresh token")

# The running event loop, captured in main's lifespan. Used by
# _run_coro_blocking to marshal scheduler coroutines onto the app loop.
_main_loop: asyncio.AbstractEventLoop | None = None

_refresh_lock = asyncio.Lock()
_refresh_in_flight = False
_refresh_stage = ""  # "", "fetching", "classifying", "summarizing", "assessing", "done", "error"
_refresh_started_at: float | None = None
_refresh_stage_started_at: float | None = None
_refresh_stage_history: dict = {}       # {stage: elapsed_s} for the most recent completed run


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
    global _refresh_stage, _refresh_stage_started_at
    now = _time.monotonic()
    if _refresh_stage and _refresh_stage_started_at:
        _refresh_stage_history[_refresh_stage] = round(now - _refresh_stage_started_at, 1)
    _refresh_stage = stage
    _refresh_stage_started_at = now
