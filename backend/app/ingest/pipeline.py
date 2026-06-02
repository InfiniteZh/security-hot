"""LLM scoring, classification, summarization, and daily briefing.

Two-phase news pipeline for token efficiency:
  Phase 1 (news_classify) — fast: score (1-10) + category, batch 80-100
  Phase 2 (news_summarize) — targeted: Chinese summary for high-score English articles only
  vuln_assess — AI severity + Chinese summary for vulnerabilities
  daily_brief — per-category daily briefing digest

By default, only articles from the last 7 days are processed automatically.
Use --days 0 to process all articles, or trigger manually via the API.

Usage:
  uv run python scripts/llm_rank.py                         # all tasks (7d)
  uv run python scripts/llm_rank.py --task news_classify     # phase 1 only
  uv run python scripts/llm_rank.py --task news_summarize    # phase 2 only
  uv run python scripts/llm_rank.py --task vuln_assess       # vulns only
  uv run python scripts/llm_rank.py --task daily_brief       # generate daily briefing
  uv run python scripts/llm_rank.py --days 0                 # process ALL articles
  uv run python scripts/llm_rank.py --rescore                # re-process missing categories
  uv run python scripts/llm_rank.py --min-score 5            # summary threshold (default 5)

Env config:
  LLM_API_KEY       required (unset → no-op)
  LLM_BASE_URL      default https://api.minimaxi.com/v1
  LLM_MODEL         default MiniMax-M2.7
  LLM_CONCURRENCY   default 8
  LLM_TIMEOUT       default 90
  LLM_MAX_BATCHES   default 200

Façade module: this file delegates to the cohesive submodules below and
re-exports their symbols so that the public access surface
(`backend.app.ingest.pipeline.<symbol>`) — used by scripts/llm_rank.py,
main.py, the tests and poisoning_dispatch — stays byte-for-byte stable.

  llm_client     — LLM call infra (_llm_call, _get_config, _extract_json, …)
  prompts        — module-level prompt constants
  news_llm       — classify_news / summarize_news
  vuln_llm       — assess_vulns
  brief          — generate_daily_brief
  orchestration  — on_news_fetched / on_vuln_fetched / on_news_enrich / …
"""
from __future__ import annotations

import argparse
import asyncio

# Re-export the full public surface from the cohesive submodules. Star imports
# pull in the non-underscore symbols; the explicit imports below additionally
# rebind the underscore-prefixed infrastructure symbols (which `*` skips) so
# that `pipeline._get_config` / `pipeline._llm_call` etc. remain real module
# attributes — poisoning_dispatch relies on `from llm_rank import _get_config,
# _llm_call`, and llm_rank aliases this module as `llm_rank`.
from .llm.client import *  # noqa: F401,F403
from .llm.prompts import *  # noqa: F401,F403
from .llm.news import *  # noqa: F401,F403
from .llm.vuln import *  # noqa: F401,F403
from .llm.brief import *  # noqa: F401,F403
from .llm.orchestration import *  # noqa: F401,F403

from .llm.client import (  # noqa: F401
    ROOT,
    SCRIPTS,
    VULN_AI_JSON,
    _LLM_SEMAPHORE,
    _extract_json,
    _get_config,
    _is_within_days,
    _llm_call,
    _prog,
    _run_concurrent,
)
from .llm.prompts import (  # noqa: F401
    VULN_SYSTEM_PROMPT,
    _CLASSIFY_SYSTEM_PROMPT,
    ALL_CATEGORIES,
)
from .llm.news import (  # noqa: F401
    _build_classify_user_msg,
    classify_news,
    summarize_news,
)
from .llm.vuln import assess_vulns  # noqa: F401
from .llm.brief import generate_daily_brief  # noqa: F401
from .llm.orchestration import (  # noqa: F401
    _run_pool_step,
    on_news_enrich,
    on_news_fetched,
    on_vuln_fetched,
)


# ── CLI ──

async def _run_all(args):
    tasks = args.task.split(",") if args.task else ["news_classify", "news_summarize", "vuln_assess", "daily_brief"]
    results = {}
    for task in tasks:
        task = task.strip()
        if task == "news_classify":
            results["classify"] = await classify_news(
                days=args.days, rescore=args.rescore, limit=args.limit, verbose=not args.quiet)
        elif task == "news_summarize":
            results["summarize"] = await summarize_news(
                min_score=args.min_score, days=args.days, limit=args.limit, verbose=not args.quiet)
        elif task == "news_rank":
            results["classify"] = await classify_news(
                days=args.days, rescore=args.rescore, limit=args.limit, verbose=not args.quiet)
            results["summarize"] = await summarize_news(
                min_score=args.min_score, days=args.days, limit=args.limit, verbose=not args.quiet)
        elif task == "vuln_assess":
            results["vuln"] = await assess_vulns(
                days=args.days, limit=args.limit, verbose=not args.quiet)
        elif task == "daily_brief":
            results["brief"] = await generate_daily_brief(
                target_date=args.date, verbose=not args.quiet)
    return results


def main() -> int:
    p = argparse.ArgumentParser(description="Two-phase LLM pipeline for security-hot")
    p.add_argument("--task", default=None,
                   help="comma-separated: news_classify,news_summarize,news_rank,vuln_assess,daily_brief")
    p.add_argument("--days", type=int, default=7, help="only process articles within N days (0=all)")
    p.add_argument("--min-score", type=int, default=5, help="minimum score for Phase 2 summarization")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--rescore", action="store_true", help="re-process items missing llm_category")
    p.add_argument("--date", default=None, help="target date for daily_brief (YYYY-MM-DD)")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()
    results = asyncio.run(_run_all(args))
    has_errors = any(
        r.get("error") or r.get("errors") or r.get("partial_batches")
        for r in results.values()
        if isinstance(r, dict)
    )
    return 1 if has_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
