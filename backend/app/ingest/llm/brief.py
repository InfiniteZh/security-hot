"""Daily briefing per category.

For each of the 5 categories, pull the day's top relevant articles and
ask the LLM for a Chinese markdown digest, upserting into daily_briefs.

Depends on llm_client (infra) + prompts (ALL_CATEGORIES) + db. No dependency
on the news/vuln/orchestration modules, keeping the import graph acyclic.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

import httpx

from .. import db as _db
from .client import _get_config, _prog, _llm_call_via_facade as _llm_call
from .prompts import ALL_CATEGORIES


async def generate_daily_brief(
    target_date: str | None = None,
    verbose: bool = True,
) -> dict:
    """Generate a daily brief for each of the 5 categories.

    For each category, pull all relevant primary articles published on
    target_date, summarize via LLM, INSERT OR REPLACE into daily_briefs.
    """
    cfg = _get_config()
    if not cfg["api_key"]:
        return {"error": "LLM_API_KEY not set"}

    if target_date is None:
        target_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    conn = _db.connect()
    try:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        summaries: dict[str, dict] = {}

        system_prompt = """你是安全资讯日报编辑。基于给定的当日 N 篇文章，撰写中文 markdown 日报。

格式要求（严格 markdown，前端会渲染）：
1. **开篇导语**：1-2 句话总览今日该领域核心动态，独立一段
2. **核心要点**：3-5 个要点，每条以无序列表项 `- ` 开头，建议结构：
   - `- **关键词/事件名**：1-2 句简述（涉及的厂商、产品、CVE、影响范围）`
3. **态势总结**：结尾另起一段，可用 `**总结**：` 前缀，给出一句总评

排版细则：
- 重要实体（CVE 编号、厂商名、工具名、零日代号）用 `**加粗**`
- 技术术语、命令、文件名、代码片段用反引号 `` ` ``
- 段落之间用空行分隔；列表项之间不要空行
- 总长度 300-500 字；不要使用一级标题 `#`，最多用 `###` 三级标题分节
- 不要输出 "今日"/"日报" 等冗余开场白

输出格式：仅输出一个 JSON 对象 `{"text": "..."}`，其中 text 的值是**纯 markdown 字符串**（不是再嵌套的 JSON）。markdown 中的换行用 `\\n`、引号用 `\\"` 转义即可。除该 JSON 外不要任何前后文字、不要 ```json 围栏。"""

        _brief_total = sum(
            conn.execute(
                "SELECT COUNT(*) FROM articles WHERE substr(published,1,10)=? AND llm_category=? AND (is_relevant=1 OR is_relevant IS NULL)",
                [target_date, c]).fetchone()[0]
            for c in ALL_CATEGORIES)
        _brief_articles_done = 0
        _prog.start("summarizing")
        _prog.report("summarizing", _brief_total, 0, label="daily_brief")

        async with httpx.AsyncClient(timeout=cfg["timeout"]) as client:
            for category in ALL_CATEGORIES:
                # Filter by published date (not fetched_at) so counts match
                # the frontend news view. is_relevant accepts NULL for
                # cold-start before classify backlog finishes. Do not cap the
                # row count: the daily brief should see the full category set.
                rows = list(conn.execute("""
                    SELECT title, summary, source_title, llm_summary_zh
                    FROM articles
                    WHERE substr(published, 1, 10) = ?
                      AND llm_category = ?
                      AND (is_relevant = 1 OR is_relevant IS NULL)
                    ORDER BY COALESCE(llm_score, 5) DESC
                """, [target_date, category]))
                if not rows:
                    if verbose:
                        print(f"[brief] {category}: 0 articles, skipped", file=sys.stderr)
                    continue
                user_msg = f"分类: {category}\n" + "\n---\n".join(
                    f"[{r['source_title']}] {r['title']}\n摘要: {r['llm_summary_zh'] or r['summary'] or ''}"
                    for r in rows
                )
                try:
                    result = await _llm_call(
                        client, system_prompt, user_msg,
                        cfg["base_url"], cfg["api_key"], cfg["model"], cfg["timeout"],
                        max_concurrency=cfg["concurrency"],
                    )
                    text = result.get("text") or ""
                    # Some models nest the JSON envelope inside the text field
                    # (returning {"text": "{\"text\": \"...\"}"}). Unwrap once.
                    stripped = text.lstrip()
                    if stripped.startswith("{") and '"text"' in stripped[:20]:
                        try:
                            inner = json.loads(stripped)
                            if isinstance(inner, dict) and isinstance(inner.get("text"), str):
                                text = inner["text"]
                        except json.JSONDecodeError:
                            pass
                    _db.upsert_brief(
                        conn, date=target_date, category=category,
                        text=text, article_count=len(rows), generated_at=now_iso,
                    )
                    summaries[category] = {"chars": len(text), "articles": len(rows)}
                    _brief_articles_done += len(rows)
                    _prog.report("summarizing", _brief_total, _brief_articles_done, label="daily_brief")
                    if verbose:
                        print(f"[brief] {category}: {len(text)} chars from {len(rows)} articles",
                              file=sys.stderr)
                except Exception as exc:
                    _brief_articles_done += len(rows)
                    _prog.report("summarizing", _brief_total, _brief_articles_done, label="daily_brief")
                    if verbose:
                        print(f"[brief] {category} failed: {exc}", file=sys.stderr)

        if verbose:
            print(f"[brief] done: {len(summaries)} categories for {target_date}", file=sys.stderr)
        return {"date": target_date, "categories": summaries}
    finally:
        conn.close()
