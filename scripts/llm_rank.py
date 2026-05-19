"""LLM priority scoring for cached news articles.

Runs after a news fetch (auto-invoked from fetch_data.py when LLM_API_KEY is
set, or manually via `uv run python scripts/llm_rank.py`). Reads
backend/cache/news.json, scores every article that doesn't yet have an
llm_score, writes the scored articles back in place. Skipping is by article
link, so re-running is incremental and cheap.

Default config targets MiniMax (api.minimaxi.com) but any chat-completions
endpoint that follows the OpenAI shape works — set LLM_BASE_URL +
LLM_MODEL accordingly.

Env config:
  LLM_API_KEY       required to enable scoring (unset → script no-ops)
  LLM_BASE_URL      default https://api.minimaxi.com/v1
  LLM_MODEL         default abab6.5s-chat
  LLM_BATCH_SIZE    default 25
  LLM_TIMEOUT       default 60 (seconds per request)
  LLM_MAX_BATCHES   default 200 — hard cap so a runaway run can't burn quota
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

SYSTEM_PROMPT = """你是一名安全情报分析师，为安全情报日报上的文章打优先级分。

每篇文章给一个 1-10 的整数分：
- 9-10：在野利用 0day、命名供应链攻击 + IOC、Cisco/Fortinet/Exchange/Chrome 等广泛部署软件的严重 CVE、AWS/GitHub/Cloudflare 等大平台的重大事故。
- 7-8：带 PoC 的高危 CVE、供应链恶意包通报、有新 TTP 的勒索软件案例分析、新颖技术研究、广泛部署软件的月度安全公告（Microsoft Patch Tuesday / Adobe Security Bulletin / Oracle CPU 等）、知名学术会议（BlackHat / DEFCON / USENIX / CCS / S&P）议程或论文公告。
- 4-6：厂商产品发布、CVE 历史回顾、笼统的威胁趋势文章、安全工具发布、产品评测对比。
- 1-3：教程 / 观点 / 厂商营销 / 广告 / 推广性质内容、个人感想随笔。

输出严格 JSON: {"results":[{"id": <int>, "score": <int 1-10>, "reason": "中文一句话理由，<=24 字"}]} —— id 必须与输入序号对应，每篇文章一条。不要在 JSON 外输出任何文字。"""


def _article_key(a: dict) -> str:
    return a.get("link") or (a.get("title") or "")[:160]


def _already_scored(a: dict) -> bool:
    score = a.get("llm_score")
    return isinstance(score, (int, float))


def _extract_json(content: str) -> dict:
    """Some models wrap JSON in ```json ... ``` fences or prepend prose."""
    content = content.strip()
    fenced = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", content)
    if fenced:
        content = fenced.group(1).strip()
    # If model prepended prose, try to grab the outer-most braces.
    if not content.startswith("{"):
        m = re.search(r"\{[\s\S]+\}", content)
        if m:
            content = m.group(0)
    return json.loads(content)


async def _score_batch(
    client: httpx.AsyncClient,
    articles: list[dict],
    base_url: str,
    api_key: str,
    model: str,
    timeout: float,
) -> dict[int, tuple[int, str]]:
    msg_parts = []
    for i, a in enumerate(articles):
        title = (a.get("title") or "").strip().replace("\n", " ")[:240]
        summary = (a.get("summary") or "").strip().replace("\n", " ")[:300]
        source = a.get("source_title") or a.get("source_slug") or ""
        msg_parts.append(f"[{i}] ({source}) {title} — {summary}")
    user_msg = "请为下面这批文章打分：\n\n" + "\n\n".join(msg_parts)

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    url = f"{base_url.rstrip('/')}/chat/completions"
    r = await client.post(url, json=body, headers=headers, timeout=timeout)
    r.raise_for_status()
    payload = r.json()
    content = payload["choices"][0]["message"]["content"]
    try:
        parsed = _extract_json(content)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"LLM returned non-JSON: {exc}; preview={content[:200]!r}") from exc

    results = parsed.get("results") or []
    out: dict[int, tuple[int, str]] = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        try:
            idx = int(item["id"])
            score = max(1, min(10, int(item["score"])))
            reason = str(item.get("reason") or "").strip()[:60]
        except (KeyError, TypeError, ValueError):
            continue
        out[idx] = (score, reason)
    return out


async def rank_news(limit: int | None = None, verbose: bool = True) -> dict:
    api_key = os.environ.get("LLM_API_KEY")
    if not api_key:
        if verbose:
            print("[llm_rank] LLM_API_KEY not set, skipping", file=sys.stderr)
        return {"skipped": True}

    base_url = os.environ.get("LLM_BASE_URL", "https://api.minimaxi.com/v1")
    model = os.environ.get("LLM_MODEL", "abab6.5s-chat")
    batch_size = int(os.environ.get("LLM_BATCH_SIZE", "25"))
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

    needs = [(i, a) for i, a in enumerate(articles) if not _already_scored(a)]
    if limit is not None:
        needs = needs[:limit]
    if not needs:
        if verbose:
            print(f"[llm_rank] all {len(articles)} articles already scored", file=sys.stderr)
        return {"scored": 0, "reason": "all-cached"}
    if verbose:
        print(f"[llm_rank] scoring {len(needs)} new articles via {model} @ {base_url}", file=sys.stderr)

    scored = 0
    errors = 0
    t0 = time.monotonic()
    async with httpx.AsyncClient(timeout=timeout) as client:
        for batch_idx in range(0, min(len(needs), max_batches * batch_size), batch_size):
            chunk = needs[batch_idx : batch_idx + batch_size]
            local_articles = [a for _, a in chunk]
            try:
                results = await _score_batch(client, local_articles, base_url, api_key, model, timeout)
            except Exception as exc:
                errors += 1
                if verbose:
                    print(f"[llm_rank] batch {batch_idx // batch_size + 1} failed: {exc}", file=sys.stderr)
                if errors >= 3:
                    if verbose:
                        print("[llm_rank] too many errors, aborting remaining batches", file=sys.stderr)
                    break
                continue
            for local_id, (idx_a, _) in enumerate(chunk):
                sr = results.get(local_id)
                if sr is None:
                    continue
                articles[idx_a]["llm_score"] = sr[0]
                articles[idx_a]["llm_reason"] = sr[1]
                scored += 1
            if verbose:
                print(f"[llm_rank] batch {batch_idx // batch_size + 1}: {len(results)} / {len(chunk)} scored", file=sys.stderr)

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
        print(f"[llm_rank] done: {scored} scored in {elapsed}s ({errors} batch error(s))", file=sys.stderr)
    return {"scored": scored, "errors": errors, "elapsed_s": elapsed}


def main() -> int:
    p = argparse.ArgumentParser(description="LLM-score articles in news.json")
    p.add_argument("--limit", type=int, default=None, help="cap how many articles to score this run")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()
    result = asyncio.run(rank_news(limit=args.limit, verbose=not args.quiet))
    return 1 if result.get("errors") else 0


if __name__ == "__main__":
    raise SystemExit(main())
