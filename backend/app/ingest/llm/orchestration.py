"""Event-driven service pipeline orchestration.

These coroutines are the entry points the in-process service invokes when
news/vuln fetches complete. They chain the LLM steps (classify → summarize →
dispatch, assess → dispatch), wrapping each step with ok/elapsed bookkeeping.

Depends on news_llm / vuln_llm plus the dispatch scripts and the process pool
(imported lazily to avoid import-time cycles and to keep the heavy deps out of
the fast path). The scripts dir is already on sys.path via the llm_client
bootstrap.
"""
from __future__ import annotations

import time

from .news import classify_news, summarize_news
from .vuln import assess_vulns


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
