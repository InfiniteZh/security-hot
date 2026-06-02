"""Pipeline orchestration + durable status recording.

Owns the news/enrich/vuln pipeline drivers and the helpers that persist each
step's outcome to pipeline_status. Shares the refresh state machine
(refresh_state) for stage transitions; depends on the ingest layer for the
actual work.
"""
from __future__ import annotations

import json as _json
import logging
import time as _time
from pathlib import Path

from . import pipeline_status as ps
from ..ingest import run_fetchers
from .refresh_state import _set_stage

log = logging.getLogger("security-hot")

ROOT = Path(__file__).resolve().parents[2]


_LLM_TASKS_BY_SCOPE = {
    "news": ["news_classify", "news_summarize", "daily_brief"],
    "vuln": ["vuln_assess"],
    "all":  ["news_classify", "news_summarize", "daily_brief"],
}


def _resolve_refresh_pipeline(chosen: list[str] | None, llm: str | None) -> tuple[str, list[str]]:
    """Resolve which post-fetch pipeline a manual refresh should chain.

    Explicit `llm=` keeps its existing meaning. Without it, the two time-sensitive
    single-source pulls that feed dispatch are promoted from fetch-only:
    `news` → news classify/summarize/poisoning dispatch, `murphy` → vuln assess/dispatch.
    """
    if llm is not None:
        scope = (llm or "none").strip().lower()
    else:
        names = {s.strip().lower() for s in (chosen or []) if s.strip()}
        if names == {"news"}:
            scope = "news"
        elif names == {"murphy"}:
            scope = "vuln"
        else:
            scope = "none"
    return scope, list(_LLM_TASKS_BY_SCOPE.get(scope, []))


def _record_step_status(script: str, step: str | None, ok: bool, elapsed: float,
                        stderr: str | None, returncode: int | None) -> None:
    """Persist one pipeline step's outcome to the durable status store
    (backend/app/pipeline_status.py). Fetchers are recorded per-fetcher from the
    manifest they just wrote; enrichment/LLM scripts by their canonical name.
    Best-effort: a status-write failure must never break the pipeline."""
    try:
        if Path(script).name == "fetch_data.py":
            ps.upsert_from_manifest(ROOT / "backend" / "cache" / "manifest.json")
    except Exception:
        log.exception("failed to record pipeline status for %s", script)


def _record_pipeline_result(step: str, result: dict) -> None:
    if step not in {"embed", "cluster", "classify", "summarize", "daily_brief",
                    "poisoning_dispatch", "vuln_dispatch"}:
        return
    ok = bool(result.get("ok"))
    error = result.get("error")
    if not ok and error is None and isinstance(result.get("result"), dict):
        error = _json.dumps(result["result"], ensure_ascii=False)
    # Dispatch steps carry a "sent" count in their stats → surface it in the UI.
    count = None
    if step in {"poisoning_dispatch", "vuln_dispatch"} and isinstance(result.get("result"), dict):
        count = result["result"].get("sent")
    try:
        ps.upsert_step(
            step,
            ok=ok,
            elapsed_s=float(result.get("elapsed_s") or 0),
            error=error,
            returncode=0 if ok else 1,
            count=count,
        )
    except Exception:
        log.exception("failed to record pipeline result for %s", step)


async def _run_news_pipeline(*, include_daily_brief: bool = False) -> dict:
    from ..ingest.pipeline import generate_daily_brief, on_news_fetched

    results = await on_news_fetched(stage_cb=_set_stage)
    if "classify" in results:
        _record_pipeline_result("classify", results["classify"])
    if "summarize" in results:
        _record_pipeline_result("summarize", results["summarize"])
    if "poisoning_dispatch" in results:
        _record_pipeline_result("poisoning_dispatch", results["poisoning_dispatch"])
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


async def _run_enrich_pipeline() -> dict:
    """Embedding + mirror clustering on its own cadence (default 2h)."""
    from ..ingest.pipeline import on_news_enrich

    results = await on_news_enrich(stage_cb=_set_stage)
    for name in ("embed", "cluster"):
        if name in results:
            _record_pipeline_result(name, results[name])
    return results


async def _run_vuln_pipeline() -> dict:
    from ..ingest.pipeline import on_vuln_fetched

    results = await on_vuln_fetched(stage_cb=_set_stage)
    if "vuln_dispatch" in results:
        _record_pipeline_result("vuln_dispatch", results["vuln_dispatch"])
    return results


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
    from .refresh_state import _finish_refresh

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
