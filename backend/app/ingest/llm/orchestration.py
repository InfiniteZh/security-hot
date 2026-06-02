"""Event-driven service pipeline orchestration.

These coroutines are the entry points the in-process service invokes when
news/vuln fetches complete. They chain the LLM steps (classify → summarize →
dispatch, assess → dispatch) and the decoupled embed/cluster enrichment,
wrapping each step with ok/elapsed bookkeeping.

Depends on news_llm / vuln_llm plus the dispatch scripts and pool/cluster/
embed helpers (imported lazily to avoid import-time cycles and to keep the
heavy deps out of the fast path). The scripts dir is already on sys.path via
the llm_client bootstrap.
"""
from __future__ import annotations

import asyncio
import time

from .news import classify_news, summarize_news
from .vuln import assess_vulns


async def _run_pool_step(fn) -> dict:
    from concurrent.futures.process import BrokenProcessPool

    from ..pool import get_pool, shutdown_pool

    loop = asyncio.get_running_loop()
    t0 = time.monotonic()
    try:
        result = await loop.run_in_executor(get_pool(), fn)
        return {"ok": True, "result": result, "elapsed_s": round(time.monotonic() - t0, 2)}
    except BrokenProcessPool as exc:
        shutdown_pool()
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_s": round(time.monotonic() - t0, 2),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_s": round(time.monotonic() - t0, 2),
        }


async def on_news_enrich(stage_cb=None) -> dict:
    """Embedding + mirror clustering, decoupled from the per-fetch news pipeline.

    e5-small embedding is the slowest step in the news flow, so it no longer
    rides every 15-min fetch (nor manual /api/refresh). It runs on its own
    longer cadence (default 2h via SECURITY_HOT_ENRICH_MINUTES) — clustering
    value ("did multiple sources report this") converges over hours, not
    minutes, so a NULL cluster_id just means "not enriched yet" and the article
    still shows. Both steps are incremental + idempotent.
    """
    from ..enrich.cluster import cluster_recent
    from ..enrich.embed import embed_missing

    results: dict[str, dict] = {}
    if stage_cb:
        stage_cb("embedding")
    results["embed"] = await _run_pool_step(embed_missing)
    if stage_cb:
        stage_cb("clustering")
    results["cluster"] = await _run_pool_step(cluster_recent)
    return results


async def on_news_fetched(stage_cb=None) -> dict:
    import poisoning_dispatch

    results: dict[str, dict] = {}

    t0 = time.monotonic()
    try:
        if stage_cb:
            stage_cb("classifying")
        classify_result = await classify_news(days=7, verbose=True)
        classify_errors = int(classify_result.get("errors", 0))
        partial_batches = int(classify_result.get("partial_batches", 0))
        results["classify"] = {
            "ok": classify_errors == 0 and partial_batches == 0,
            "result": classify_result,
            "elapsed_s": round(time.monotonic() - t0, 2),
        }
        if classify_errors or partial_batches:
            results["classify"]["error"] = (
                f"classify incomplete: errors={classify_errors}, "
                f"partial_batches={partial_batches}"
            )
    except Exception as exc:
        results["classify"] = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_s": round(time.monotonic() - t0, 2),
        }

    t0 = time.monotonic()
    try:
        if stage_cb:
            stage_cb("summarizing")
        summarize_result = await summarize_news(min_score=5, days=7, verbose=True)
        summarize_errors = int(summarize_result.get("errors", 0))
        partial_batches = int(summarize_result.get("partial_batches", 0))
        results["summarize"] = {
            "ok": summarize_errors == 0 and partial_batches == 0,
            "result": summarize_result,
            "elapsed_s": round(time.monotonic() - t0, 2),
        }
        if summarize_errors or partial_batches:
            results["summarize"]["error"] = (
                f"summarize incomplete: errors={summarize_errors}, "
                f"partial_batches={partial_batches}"
            )
    except Exception as exc:
        results["summarize"] = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_s": round(time.monotonic() - t0, 2),
        }

    t0 = time.monotonic()
    try:
        if stage_cb:
            stage_cb("dispatching")
        stats = await poisoning_dispatch.run(fresh_days=3, limit=None, dry_run=False)
        results["poisoning_dispatch"] = {
            "ok": int(stats.get("errors", 0)) == 0,
            "result": stats,
            "elapsed_s": round(time.monotonic() - t0, 2),
        }
    except Exception as exc:
        results["poisoning_dispatch"] = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_s": round(time.monotonic() - t0, 2),
        }
    return results


async def on_vuln_fetched(stage_cb=None) -> dict:
    import vuln_dispatch

    results: dict[str, dict] = {}
    t0 = time.monotonic()
    try:
        if stage_cb:
            stage_cb("assessing")
        results["vuln_assess"] = {
            "ok": True,
            "result": await assess_vulns(days=7, verbose=True),
            "elapsed_s": round(time.monotonic() - t0, 2),
        }
    except Exception as exc:
        results["vuln_assess"] = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_s": round(time.monotonic() - t0, 2),
        }

    t0 = time.monotonic()
    try:
        if stage_cb:
            stage_cb("dispatching")
        stats = await vuln_dispatch.run()
        results["vuln_dispatch"] = {
            "ok": int(stats.get("errors", 0)) == 0,
            "result": stats,
            "elapsed_s": round(time.monotonic() - t0, 2),
        }
    except Exception as exc:
        results["vuln_dispatch"] = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_s": round(time.monotonic() - t0, 2),
        }
    return results
