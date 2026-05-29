"""Optional in-process scheduler for the data pipeline.

In a Docker deployment there is no host crontab, so `docs/cron-template.txt`
never fires. This module runs the same scripts that cron would, but inside the
uvicorn process via APScheduler's BackgroundScheduler — so `docker compose up`
gives you a self-refreshing panel with zero host config and no sidecar.

Disabled by default (so local dev / `--reload` / tests don't spawn heavy LLM
subprocesses). Enable by setting `SECURITY_HOT_SCHEDULER_ENABLED=1` — the
docker-compose `web` service sets it for you. Do not enable it with
`uvicorn --reload`: the reload supervisor can briefly overlap app processes,
which can duplicate scheduled jobs.

Cadence mirrors the documented cron template and is fully env-tunable:

    SECURITY_HOT_SCHEDULER_ENABLED      master switch (default off)
    SECURITY_HOT_FETCH_NEWS_MINUTES     news fetch interval     (default 15)
    SECURITY_HOT_PIPELINE_HOURS         embed/cluster/LLM cycle (default 2)
    SECURITY_HOT_FETCH_OTHER_HOURS      non-news fetchers       (default 4)
    SECURITY_HOT_BRIEF_HOUR_UTC         daily brief hour, UTC   (default 23)

All jobs run on a 2-thread pool with coalesce + max_instances=1, and each job
itself takes the shared refresh lock (see main._run_pipeline_steps), so the
scheduler never overlaps with a manual /api/refresh or with itself.
"""
from __future__ import annotations

import logging
import os
import threading

log = logging.getLogger("security-hot.scheduler")
_scheduler_lock = threading.Lock()
_scheduler = None


def _enabled() -> bool:
    return os.environ.get("SECURITY_HOT_SCHEDULER_ENABLED", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        val = int(raw)
        return val if val > 0 else default
    except ValueError:
        log.warning("scheduler: %s=%r is not an int, using default %d", name, raw, default)
        return default


def start_scheduler(*, fetch_news, heavy_pipeline, daily_brief, fetch_other):
    """Build + start the BackgroundScheduler. Returns the scheduler (so the
    caller can shut it down) or None when disabled / unavailable.

    Callables are injected from main.py to avoid an import cycle; each is a
    zero-arg function that runs one pipeline stage under the refresh lock.
    """
    if not _enabled():
        log.info("scheduler disabled — set SECURITY_HOT_SCHEDULER_ENABLED=1 to enable")
        return None

    try:
        from apscheduler.executors.pool import ThreadPoolExecutor
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        log.warning("scheduler enabled but apscheduler not installed — run `uv sync`")
        return None

    news_minutes = _int_env("SECURITY_HOT_FETCH_NEWS_MINUTES", 15)
    pipeline_hours = _int_env("SECURITY_HOT_PIPELINE_HOURS", 2)
    other_hours = _int_env("SECURITY_HOT_FETCH_OTHER_HOURS", 4)
    brief_hour = _int_env("SECURITY_HOT_BRIEF_HOUR_UTC", 23) % 24

    global _scheduler
    with _scheduler_lock:
        if _scheduler is not None and _scheduler.running:
            log.info("scheduler already running")
            return _scheduler

        sched = BackgroundScheduler(
            timezone="UTC",
            executors={"default": ThreadPoolExecutor(2)},
            job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 300},
        )
        sched.add_job(fetch_news, "interval", minutes=news_minutes, id="fetch_news")
        sched.add_job(heavy_pipeline, "interval", hours=pipeline_hours, id="heavy_pipeline")
        sched.add_job(fetch_other, "interval", hours=other_hours, id="fetch_other")
        sched.add_job(daily_brief, "cron", hour=brief_hour, minute=0, id="daily_brief")
        sched.start()
        _scheduler = sched

    log.info(
        "scheduler started — news=%dm pipeline=%dh other=%dh brief=%02d:00 UTC",
        news_minutes, pipeline_hours, other_hours, brief_hour,
    )
    return sched


def stop_scheduler(sched=None) -> None:
    """Stop the module-level scheduler and clear the duplicate-start guard."""
    global _scheduler
    with _scheduler_lock:
        target = sched or _scheduler
        if target is None:
            return
        if target.running:
            target.shutdown(wait=False)
        if target is _scheduler:
            _scheduler = None
