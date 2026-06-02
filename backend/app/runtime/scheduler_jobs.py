"""APScheduler job entry points.

Five sync job callables (registered in the scheduler) plus their async
implementations. Each owns the shared refresh state for one pipeline run via
_pipeline_run, then delegates the actual work to pipeline_runner.
"""
from __future__ import annotations

import logging
import time as _time
from contextlib import asynccontextmanager

from .pipeline_runner import (
    _record_pipeline_result,
    _run_enrich_pipeline,
    _run_fetch_step,
    _run_news_pipeline,
    _run_vuln_pipeline,
)
from .refresh_state import (
    _begin_refresh,
    _finish_refresh,
    _run_coro_blocking,
    _set_stage,
)

log = logging.getLogger("security-hot")


# Human labels for the scheduler jobs (frontend renders these as group headers).
_JOB_LABELS = {
    "fetch_news": "资讯抓取",
    "fetch_murphy": "墨菲漏洞预警",
    "fetch_other": "其它情报源",
    "heavy_pipeline": "富化 + LLM 流水线",
    "daily_brief": "每日简报",
}


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


async def _sched_enrich_async() -> None:
    # Embedding + mirror clustering on its own long cadence (default 2h),
    # decoupled from the 15-min news fetch and from manual /api/refresh.
    async with _pipeline_run() as owned:
        if not owned:
            return
        await _run_enrich_pipeline()
        _set_stage("done")


def _sched_enrich() -> None:
    _run_coro_blocking(_sched_enrich_async())


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
