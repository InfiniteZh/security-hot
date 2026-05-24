"""LLM scoring, classification, and summarization for security-hot.

Three tasks, all sharing the same LLM client/retry/batching infra:
  1. news_rank   — score (1-10) + classify + Chinese summary for news articles
  2. vuln_assess — AI severity + Chinese summary for vulnerabilities

Usage:
  uv run python scripts/llm_rank.py                    # all tasks
  uv run python scripts/llm_rank.py --task news_rank   # news only
  uv run python scripts/llm_rank.py --task vuln_assess  # vulns only
  uv run python scripts/llm_rank.py --rescore           # re-process items missing category

Env config:
  LLM_API_KEY       required (unset → no-op)
  LLM_BASE_URL      default https://api.minimaxi.com/v1
  LLM_MODEL         default abab6.5s-chat
  LLM_BATCH_SIZE    default 20
  LLM_TIMEOUT       default 60
  LLM_MAX_BATCHES   default 200
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
NEWS_JSON = ROOT / "backend" / "cache" / "news.json"
VULN_AI_JSON = ROOT / "backend" / "cache" / "vuln_ai.json"

NEWS_SYSTEM_PROMPT = """你是安全情报编辑。对每篇文章完成三项任务：

1. 打优先级分（1-10 整数）：
   - 9-10：在野 0day、命名供应链攻击+IOC、广泛部署软件严重 CVE、大平台重大事故
   - 7-8：带 PoC 高危 CVE、恶意包通报、新 TTP 勒索分析、新颖技术研究、安全公告（Patch Tuesday 等）、顶会论文
   - 4-6：厂商产品发布、CVE 回顾、威胁趋势、工具发布
   - 1-3：教程/观点/营销/广告/推广

2. 分类到以下之一（cat 字段）：
   - "incident"：安全事件（数据泄露、勒索攻击、APT 活动、服务中断）
   - "vuln"：漏洞情报（CVE 披露、补丁发布、PoC、在野利用）
   - "supply-chain"：供应链投毒（恶意包、依赖劫持、构建链攻击）
   - "research"：安全研究（新攻击技术、学术论文、工具发布、逆向分析）
   - "industry"：行业动态（厂商新闻、市场分析、人事变动、会议活动）

3. 如果原文是英文，写一段中文摘要（2-3句，<=150字），帮助中文读者快速判断是否值得关注。中文原文则 summary_zh 留空串。

输出严格 JSON: {"results":[{"id":<int>,"score":<int 1-10>,"cat":"<category>","reason":"中文<=24字","summary_zh":"...或空串"}]}
id 必须与输入序号对应。不要在 JSON 外输出任何文字。"""

VULN_SYSTEM_PROMPT = """你是漏洞情报分析师。对每条漏洞，基于描述、是否有 PoC/KEV/在野利用、影响范围，给出：

1. ai_severity: critical/high/medium/low — 你的独立判断，可以与 CVSS 不同
   例如：CVSS 7.5 但有在野利用+广泛部署 → critical；CVSS 9.0 但仅影响冷门软件 → high
2. summary: 中文 2-3 句话（<=200字），说明漏洞是什么、影响什么、紧急程度

输出严格 JSON: {"results":[{"id":<int>,"ai_severity":"<severity>","summary":"<中文摘要>"}]}
id 必须与输入序号对应。不要在 JSON 外输出任何文字。"""


def _extract_json(content: str) -> dict:
    content = content.strip()
    fenced = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", content)
    if fenced:
        content = fenced.group(1).strip()
    if not content.startswith("{"):
        m = re.search(r"\{[\s\S]+\}", content)
        if m:
            content = m.group(0)
    return json.loads(content)


async def _llm_call(
    client: httpx.AsyncClient,
    system_prompt: str,
    user_msg: str,
    base_url: str,
    api_key: str,
    model: str,
    timeout: float,
) -> dict:
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    url = f"{base_url.rstrip('/')}/chat/completions"
    r = await client.post(url, json=body, headers=headers, timeout=timeout)
    r.raise_for_status()
    content = r.json()["choices"][0]["message"]["content"]
    return _extract_json(content)


# ── News ranking + classification ──

VALID_CATS = {"incident", "vuln", "supply-chain", "research", "industry"}


def _news_needs_processing(a: dict, rescore: bool) -> bool:
    has_score = isinstance(a.get("llm_score"), (int, float))
    has_cat = a.get("llm_category") in VALID_CATS
    if rescore:
        return not has_cat
    return not has_score


async def rank_news(
    limit: int | None = None,
    rescore: bool = False,
    verbose: bool = True,
) -> dict:
    api_key = os.environ.get("LLM_API_KEY")
    if not api_key:
        if verbose:
            print("[llm_rank] LLM_API_KEY not set, skipping", file=sys.stderr)
        return {"skipped": True}

    base_url = os.environ.get("LLM_BASE_URL", "https://api.minimaxi.com/v1")
    model = os.environ.get("LLM_MODEL", "abab6.5s-chat")
    batch_size = int(os.environ.get("LLM_BATCH_SIZE", "20"))
    timeout = float(os.environ.get("LLM_TIMEOUT", "60"))
    max_batches = int(os.environ.get("LLM_MAX_BATCHES", "200"))

    if not NEWS_JSON.exists():
        if verbose:
            print("[llm_rank] news.json not found", file=sys.stderr)
        return {"error": "news.json missing"}
    data = json.loads(NEWS_JSON.read_text(encoding="utf-8"))
    articles = data.get("articles") or []
    if not articles:
        return {"scored": 0, "reason": "empty"}

    needs = [(i, a) for i, a in enumerate(articles) if _news_needs_processing(a, rescore)]
    if limit is not None:
        needs = needs[:limit]
    if not needs:
        if verbose:
            print(f"[llm_rank] all {len(articles)} articles already processed", file=sys.stderr)
        return {"scored": 0, "reason": "all-cached"}
    if verbose:
        print(f"[llm_rank:news] processing {len(needs)} articles via {model}", file=sys.stderr)

    scored = 0
    errors = 0
    consecutive_errors = 0
    t0 = time.monotonic()
    async with httpx.AsyncClient(timeout=timeout) as client:
        for batch_idx in range(0, min(len(needs), max_batches * batch_size), batch_size):
            chunk = needs[batch_idx : batch_idx + batch_size]
            batch_num = batch_idx // batch_size + 1

            msg_parts = []
            for local_id, (_, a) in enumerate(chunk):
                title = (a.get("title") or "").strip().replace("\n", " ")[:240]
                summary = (a.get("summary") or "").strip().replace("\n", " ")[:300]
                source = a.get("source_title") or a.get("source_slug") or ""
                lang = a.get("lang", "en")
                msg_parts.append(f"[{local_id}] (lang={lang}, source={source}) {title} — {summary}")
            user_msg = "请为下面这批文章打分并分类：\n\n" + "\n\n".join(msg_parts)

            parsed = None
            for attempt in range(3):
                try:
                    parsed = await _llm_call(client, NEWS_SYSTEM_PROMPT, user_msg, base_url, api_key, model, timeout)
                    break
                except Exception as exc:
                    if verbose:
                        print(f"[llm_rank:news] batch {batch_num} attempt {attempt+1} failed: {exc}", file=sys.stderr)
                    if attempt < 2:
                        await asyncio.sleep(2 ** attempt * 3)

            if parsed is None:
                errors += 1
                consecutive_errors += 1
                if consecutive_errors >= 5:
                    if verbose:
                        print("[llm_rank:news] 5 consecutive errors, aborting", file=sys.stderr)
                    break
                continue
            consecutive_errors = 0
            await asyncio.sleep(0.5)

            for item in parsed.get("results") or []:
                if not isinstance(item, dict):
                    continue
                try:
                    local_id = int(item["id"])
                    if local_id < 0 or local_id >= len(chunk):
                        continue
                    idx_a = chunk[local_id][0]
                    score = max(1, min(10, int(item["score"])))
                    cat = item.get("cat", "")
                    reason = str(item.get("reason") or "").strip()[:60]
                    summary_zh = str(item.get("summary_zh") or "").strip()[:300]
                except (KeyError, TypeError, ValueError):
                    continue
                articles[idx_a]["llm_score"] = score
                articles[idx_a]["llm_reason"] = reason
                if cat in VALID_CATS:
                    articles[idx_a]["llm_category"] = cat
                if summary_zh:
                    articles[idx_a]["llm_summary_zh"] = summary_zh
                scored += 1

            NEWS_JSON.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            if verbose:
                print(f"[llm_rank:news] batch {batch_num}: scored {scored} so far", file=sys.stderr)

    data["llm_meta"] = {
        "model": model,
        "base_url": base_url,
        "scored_this_run": scored,
        "errors": errors,
        "ranked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    NEWS_JSON.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    elapsed = round(time.monotonic() - t0, 1)
    if verbose:
        print(f"[llm_rank:news] done: {scored} scored in {elapsed}s ({errors} errors)", file=sys.stderr)
    return {"scored": scored, "errors": errors, "elapsed_s": elapsed}


# ── Vulnerability AI assessment ──

async def assess_vulns(limit: int | None = None, verbose: bool = True) -> dict:
    api_key = os.environ.get("LLM_API_KEY")
    if not api_key:
        if verbose:
            print("[llm_rank:vuln] LLM_API_KEY not set, skipping", file=sys.stderr)
        return {"skipped": True}

    base_url = os.environ.get("LLM_BASE_URL", "https://api.minimaxi.com/v1")
    model = os.environ.get("LLM_MODEL", "abab6.5s-chat")
    batch_size = int(os.environ.get("LLM_VULN_BATCH_SIZE", "10"))
    timeout = float(os.environ.get("LLM_TIMEOUT", "60"))
    max_batches = int(os.environ.get("LLM_MAX_BATCHES", "200"))

    from backend.app.data import all_vulns
    vulns = all_vulns()
    if not vulns:
        return {"assessed": 0, "reason": "empty"}

    existing: dict = {}
    if VULN_AI_JSON.exists():
        try:
            existing = json.loads(VULN_AI_JSON.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    needs = [(i, v) for i, v in enumerate(vulns)
             if (v.cve_id or v.id) not in existing]
    if limit is not None:
        needs = needs[:limit]
    if not needs:
        if verbose:
            print(f"[llm_rank:vuln] all {len(vulns)} vulns already assessed", file=sys.stderr)
        return {"assessed": 0, "reason": "all-cached"}
    if verbose:
        print(f"[llm_rank:vuln] assessing {len(needs)} vulns via {model}", file=sys.stderr)

    assessed = 0
    errors = 0
    consecutive_errors = 0
    t0 = time.monotonic()
    async with httpx.AsyncClient(timeout=timeout) as client:
        for batch_idx in range(0, min(len(needs), max_batches * batch_size), batch_size):
            chunk = needs[batch_idx : batch_idx + batch_size]
            batch_num = batch_idx // batch_size + 1

            msg_parts = []
            for local_id, (_, v) in enumerate(chunk):
                flags = []
                if v.is_kev:
                    flags.append("KEV")
                if v.is_itw:
                    flags.append("ITW")
                if v.pocs:
                    flags.append(f"PoC×{len(v.pocs)}")
                if v.is_ransomware:
                    flags.append("Ransomware")
                if v.is_supply_chain:
                    flags.append("SupplyChain")
                flag_str = f" [{', '.join(flags)}]" if flags else ""
                cvss_str = f" CVSS={v.cvss}" if v.cvss else ""
                epss_str = f" EPSS={v.epss_score:.3f}" if v.epss_score else ""
                msg_parts.append(
                    f"[{local_id}] {v.cve_id or v.id}{flag_str}{cvss_str}{epss_str}\n"
                    f"  Title: {v.title[:200]}\n"
                    f"  Summary: {v.summary[:400]}"
                )
            user_msg = "请评估以下漏洞：\n\n" + "\n\n".join(msg_parts)

            parsed = None
            for attempt in range(3):
                try:
                    parsed = await _llm_call(client, VULN_SYSTEM_PROMPT, user_msg, base_url, api_key, model, timeout)
                    break
                except Exception as exc:
                    if verbose:
                        print(f"[llm_rank:vuln] batch {batch_num} attempt {attempt+1} failed: {exc}", file=sys.stderr)
                    if attempt < 2:
                        await asyncio.sleep(2 ** attempt * 3)

            if parsed is None:
                errors += 1
                consecutive_errors += 1
                if consecutive_errors >= 5:
                    if verbose:
                        print("[llm_rank:vuln] 5 consecutive errors, aborting", file=sys.stderr)
                    break
                continue
            consecutive_errors = 0
            await asyncio.sleep(0.5)

            for item in parsed.get("results") or []:
                if not isinstance(item, dict):
                    continue
                try:
                    local_id = int(item["id"])
                    if local_id < 0 or local_id >= len(chunk):
                        continue
                    v = chunk[local_id][1]
                    sev = item.get("ai_severity", "")
                    if sev not in ("critical", "high", "medium", "low"):
                        continue
                    summary = str(item.get("summary") or "").strip()[:400]
                except (KeyError, TypeError, ValueError):
                    continue
                vuln_key = v.cve_id or v.id
                existing[vuln_key] = {
                    "ai_severity": sev,
                    "ai_summary": summary,
                    "assessed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                assessed += 1

            VULN_AI_JSON.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")
            if verbose:
                print(f"[llm_rank:vuln] batch {batch_num}: assessed {assessed} so far", file=sys.stderr)

    elapsed = round(time.monotonic() - t0, 1)
    if verbose:
        print(f"[llm_rank:vuln] done: {assessed} assessed in {elapsed}s ({errors} errors)", file=sys.stderr)
    return {"assessed": assessed, "errors": errors, "elapsed_s": elapsed}


# ── CLI ──

async def _run_all(args):
    tasks_to_run = args.task.split(",") if args.task else ["news_rank", "vuln_assess"]
    results = {}
    for task in tasks_to_run:
        task = task.strip()
        if task == "news_rank":
            results["news"] = await rank_news(limit=args.limit, rescore=args.rescore, verbose=not args.quiet)
        elif task == "vuln_assess":
            results["vuln"] = await assess_vulns(limit=args.limit, verbose=not args.quiet)
    return results


def main() -> int:
    p = argparse.ArgumentParser(description="LLM scoring, classification, and assessment")
    p.add_argument("--task", default=None, help="comma-separated: news_rank,vuln_assess (default: all)")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--rescore", action="store_true", help="re-process items missing llm_category")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()
    results = asyncio.run(_run_all(args))
    has_errors = any(r.get("errors") for r in results.values() if isinstance(r, dict))
    return 1 if has_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
