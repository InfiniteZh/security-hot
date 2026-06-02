"""Two-phase news LLM pipeline.

Phase 1 (classify_news) — fast: score (1-10) + category, batch 80.
Phase 2 (summarize_news) — targeted: Chinese summary for high-score
relevant articles only.

Depends on llm_client (infra) + prompts (constants) + db. No dependency on
the orchestration/vuln/brief modules, keeping the import graph acyclic.
"""
from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone, timedelta

import httpx

from .. import db as _db
from .client import _get_config, _prog, _llm_call_via_facade as _llm_call
from .prompts import _CLASSIFY_SYSTEM_PROMPT


# ── Phase 1: Fast classification + scoring ──

def _build_classify_user_msg(batch: list) -> str:
    """Pack a batch of articles into a single user message for the LLM."""
    lines = []
    for row in batch:
        lines.append(
            f"id={row['id']} | source={row['source_title']} | lang={row['lang']}\n"
            f"title: {row['title']}\n"
            f"summary: {(row['summary'] or '')[:300]}\n"
        )
    return "\n---\n".join(lines)


async def classify_news(
    days: int = 7,
    rescore: bool = False,
    limit: int | None = None,
    verbose: bool = True,
) -> dict:
    """Phase 1: classify + score un-scored articles.

    Reads articles WHERE llm_score IS NULL AND published >= now - days
    (unless --rescore, in which case all articles in window are re-scored).
    Calls LLM in batches of LLM_BATCH_SIZE (default 80).
    Writes back llm_score / llm_category / llm_reason / is_relevant / llm_scored_at.
    """
    cfg = _get_config()
    if not cfg["api_key"]:
        return {"error": "LLM_API_KEY not set"}
    batch_size = int(os.environ.get("LLM_BATCH_SIZE", "80"))

    conn = _db.connect()
    try:
        where = "WHERE 1=1"
        params: list = []
        if days > 0:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
            where += " AND COALESCE(published, fetched_at) >= ?"
            params.append(cutoff)
        if not rescore:
            where += " AND llm_score IS NULL"
        if limit:
            tail = f" LIMIT {limit}"
        else:
            tail = ""

        rows = list(conn.execute(
            f"SELECT id, title, summary, source_title, lang FROM articles {where}{tail}",
            params,
        ))
        if verbose:
            print(f"[phase1] {len(rows)} articles to classify, batch={batch_size}", file=sys.stderr)

        # Build batches
        batches = [rows[i:i+batch_size] for i in range(0, len(rows), batch_size)]
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        _classify_done = 0

        system_prompt = _CLASSIFY_SYSTEM_PROMPT
        sem = asyncio.Semaphore(cfg["concurrency"])
        _prog.start("classifying")
        _prog.report("classifying", len(rows), 0, label="news_classify")

        async def process(batch, batch_num, client):
            nonlocal _classify_done
            user_msg = _build_classify_user_msg(batch)
            async with sem:
                try:
                    result = await _llm_call(
                        client, system_prompt, user_msg,
                        cfg["base_url"], cfg["api_key"], cfg["model"], cfg["timeout"],
                    )
                except Exception as exc:
                    if verbose:
                        print(f"[phase1] batch {batch_num} failed: {exc}", file=sys.stderr)
                    _classify_done += len(batch)
                    _prog.report("classifying", len(rows), _classify_done, label="news_classify")
                    return
                items = result.get("items", [])
                for item in items:
                    rowid = item.get("id")
                    if not rowid:
                        continue
                    cat = item.get("category")
                    if cat not in {"incident", "vuln", "supply-chain", "research", "industry"}:
                        cat = None
                    conn.execute("""
                        UPDATE articles SET
                          llm_score = ?, llm_category = ?, llm_reason = ?,
                          is_relevant = ?, llm_scored_at = ?
                        WHERE id = ?
                    """, [
                        int(item.get("score") or 0),
                        cat,
                        (item.get("reason") or "")[:300],
                        1 if item.get("is_relevant") else 0,
                        now_iso, rowid,
                    ])
                conn.commit()
                _classify_done += len(batch)
                _prog.report("classifying", len(rows), _classify_done, label="news_classify")
                if verbose:
                    print(f"[phase1] batch {batch_num}/{len(batches)}: +{len(items)}", file=sys.stderr)

        async with httpx.AsyncClient(timeout=cfg["timeout"]) as client:
            await asyncio.gather(*[process(b, i+1, client) for i, b in enumerate(batches)])

        return {"classified": len(rows), "batches": len(batches)}
    finally:
        conn.close()


# ── Phase 2: Targeted summarization for high-score English articles ──

async def summarize_news(
    min_score: int = 5,
    days: int = 7,
    limit: int | None = None,
    verbose: bool = True,
) -> dict:
    """Phase 2: generate Chinese summaries for all scored articles.

    Filter: llm_score >= min_score AND is_relevant=1
            AND llm_summary_zh IS NULL.
    """
    from datetime import datetime, timezone, timedelta
    cfg = _get_config()
    if not cfg["api_key"]:
        return {"error": "LLM_API_KEY not set"}
    batch_size = int(os.environ.get("LLM_BATCH_SIZE", "30"))

    conn = _db.connect()
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
        limit_clause = f"LIMIT {limit}" if limit else ""
        rows = list(conn.execute(f"""
            SELECT id, title, summary, lang
            FROM articles
            WHERE llm_score >= ?
              AND is_relevant = 1
              AND llm_summary_zh IS NULL
              AND COALESCE(published, fetched_at) >= ?
            ORDER BY llm_score DESC
            {limit_clause}
        """, [min_score, cutoff]))

        if verbose:
            print(f"[phase2] {len(rows)} articles to summarize, batch={batch_size}", file=sys.stderr)

        batches = [rows[i:i+batch_size] for i in range(0, len(rows), batch_size)]
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        _summ_done = 0

        system_prompt = """你是安全资讯摘要助手。
为每篇安全文章生成 3-5 句中文摘要（200-300 字），内容应覆盖：
- 核心事件：发生了什么（CVE 编号 / 厂商 / 漏洞类型 / 攻击手法）
- 影响范围：涉及哪些产品、版本、用户群体
- 技术要点：利用条件、攻击向量、严重程度
- 应对建议：补丁、缓解措施或关注重点（如文章提及）
英文文章翻译为中文摘要；中文文章提炼精简摘要。
输出 JSON: {"items": [{"id": <int>, "summary": "中文摘要..."}]}
不要 markdown, 不要前缀。"""

        sem = asyncio.Semaphore(cfg["concurrency"])
        _prog.start("summarizing")
        _prog.report("summarizing", len(rows), 0, label="news_summarize")

        async def process(batch, batch_num, client):
            nonlocal _summ_done
            user_msg = "\n---\n".join(
                f"id={r['id']}\ntitle: {r['title']}\nsummary: {(r['summary'] or '')[:500]}"
                for r in batch
            )
            async with sem:
                try:
                    result = await _llm_call(
                        client, system_prompt, user_msg,
                        cfg["base_url"], cfg["api_key"], cfg["model"], cfg["timeout"],
                    )
                except Exception as exc:
                    if verbose:
                        print(f"[phase2] batch {batch_num} failed: {exc}", file=sys.stderr)
                    _summ_done += len(batch)
                    _prog.report("summarizing", len(rows), _summ_done, label="news_summarize")
                    return
                for item in result.get("items", []):
                    conn.execute(
                        "UPDATE articles SET llm_summary_zh = ?, llm_summarized_at = ? WHERE id = ?",
                        [(item.get("summary") or "")[:800], now_iso, item.get("id")],
                    )
                conn.commit()
                _summ_done += len(batch)
                _prog.report("summarizing", len(rows), _summ_done, label="news_summarize")
                if verbose:
                    print(f"[phase2] batch {batch_num}/{len(batches)}: +{len(result.get('items', []))}",
                          file=sys.stderr)

        async with httpx.AsyncClient(timeout=cfg["timeout"]) as client:
            await asyncio.gather(*[process(b, i+1, client) for i, b in enumerate(batches)])

        return {"summarized": len(rows), "batches": len(batches)}
    finally:
        conn.close()
