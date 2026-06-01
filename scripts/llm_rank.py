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
  LLM_CONCURRENCY   default 4
  LLM_TIMEOUT       default 90
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
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx

import db as _db
import refresh_progress as _prog

ROOT = Path(__file__).resolve().parent.parent

# Load .env so `uv run python scripts/llm_rank.py …` works without a manual
# `source .env`. Also applies when uvicorn shells out via subprocess for the
# /api/brief/regenerate background task.
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(ROOT / ".env")
except ImportError:
    pass  # optional dep — env vars must be exported manually if missing
VULN_AI_JSON = ROOT / "backend" / "cache" / "vuln_ai.json"

# ── Prompts ──

CLASSIFY_PROMPT = """你是安全情报编辑。对每篇文章完成两项任务：

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

输出严格 JSON: {"results":[{"id":<int>,"score":<int 1-10>,"cat":"<category>","reason":"中文<=50字"}]}
id 必须与输入序号对应。不要在 JSON 外输出任何文字。"""

SUMMARIZE_PROMPT = """你是安全情报翻译编辑。为每篇英文安全文章写一段中文摘要（2-3句，<=150字），帮助中文读者快速判断是否值得关注。摘要应包含：事件/漏洞的核心内容、影响范围、严重程度。

输出严格 JSON: {"results":[{"id":<int>,"summary_zh":"中文摘要"}]}
id 必须与输入序号对应。不要在 JSON 外输出任何文字。"""

VULN_SYSTEM_PROMPT = """你是漏洞情报分析师。对每条漏洞，基于描述、是否有 PoC/KEV/在野利用、受影响厂商和产品的部署广泛程度，给出：

1. ai_severity: critical/high/medium/low — 你的独立判断，可以与 CVSS 不同
   例如：CVSS 7.5 但有在野利用+广泛部署 → critical；CVSS 9.0 但仅影响冷门软件 → high
   注意：界面会同时展示 CVSS 评分和你的 AI 判断，用户可以对比两者。
2. summary: 中文 2-3 句话（<=200字），说明漏洞是什么、影响什么、紧急程度

输出严格 JSON: {"results":[{"id":<int>,"ai_severity":"<severity>","summary":"<中文摘要>"}]}
id 必须与输入序号对应。不要在 JSON 外输出任何文字。"""

DAILY_BRIEF_PROMPT = """你是安全情报日报编辑。基于以下某一分类的今日文章列表，写一段 200-400 字的中文日报摘要。

要求：
- 概述今日该分类下最重要的 3-5 个事件/趋势
- 用要点式列举，每个要点 1-2 句话
- 如有关联的多篇文章，合并为一个要点
- 结尾用一句话总结今日该分类的整体态势

输出严格 JSON: {"brief":"<日报正文>"}
不要在 JSON 外输出任何文字。"""

VALID_CATS = {"incident", "vuln", "supply-chain", "research", "industry"}


# ── Helpers ──

def _extract_json(content: str) -> dict:
    content = content.strip()
    fenced = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", content)
    if fenced:
        content = fenced.group(1).strip()
    if not content.startswith("{"):
        m = re.search(r"\{[\s\S]+\}", content)
        if m:
            content = m.group(0)
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # LLMs frequently embed unescaped real newlines inside string values
        # when the value is markdown — strict JSON forbids that. Fall back to
        # a tolerant single-key extraction for the brief envelope {"text": "..."}.
        m = re.search(r'"text"\s*:\s*"([\s\S]*)"\s*\}\s*$', content)
        if m:
            raw = m.group(1)
            # Decode the common escape sequences a well-behaved LLM would use
            # (\\n \\" \\\\) without going through json.loads.
            decoded = (raw
                       .replace("\\\\", "\x00")  # protect literal backslash
                       .replace("\\n", "\n")
                       .replace("\\t", "\t")
                       .replace('\\"', '"')
                       .replace("\x00", "\\"))
            return {"text": decoded}
        raise


async def _llm_call(client, system_prompt, user_msg, base_url, api_key, model, timeout,
                    max_retries: int = 3):
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    url = f"{base_url.rstrip('/')}/chat/completions"
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            r = await client.post(url, json=body, headers=headers, timeout=timeout)
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            return _extract_json(content)
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries:
                await asyncio.sleep(2 ** attempt)
    raise last_exc


def _get_config():
    return {
        "api_key": os.environ.get("LLM_API_KEY"),
        "base_url": os.environ.get("LLM_BASE_URL", "https://api.minimaxi.com/v1"),
        "model": os.environ.get("LLM_MODEL", "MiniMax-M2.7"),
        "concurrency": int(os.environ.get("LLM_CONCURRENCY", "4")),
        "timeout": float(os.environ.get("LLM_TIMEOUT", "90")),
        "max_batches": int(os.environ.get("LLM_MAX_BATCHES", "200")),
    }


def _is_within_days(published: str | None, days: int) -> bool:
    if days <= 0:
        return True
    if not published:
        return False
    try:
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(published.strip(), fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
        else:
            dt = datetime.fromisoformat(published.strip().replace("Z", "+00:00"))
        return dt >= datetime.now(timezone.utc) - timedelta(days=days)
    except (ValueError, TypeError):
        return False


async def _run_concurrent(items, process_fn, concurrency, lock, flush_fn=None, flush_every=4):
    sem = asyncio.Semaphore(concurrency)
    counter = 0

    async def bounded(chunk, batch_num, client):
        nonlocal counter
        async with sem:
            await process_fn(chunk, batch_num, client)
            if flush_fn:
                async with lock:
                    counter += 1
                    if counter % flush_every == 0:
                        flush_fn()

    async with httpx.AsyncClient(timeout=items["timeout"]) as client:
        await asyncio.gather(*[
            bounded(ch, i + 1, client)
            for i, ch in enumerate(items["chunks"])
        ])


# ── Phase 1: Fast classification + scoring ──

_CLASSIFY_SYSTEM_PROMPT = """你是安全资讯分类助手。

对每篇文章输出 5 个字段：
  • id           — 直接复用输入里的 id
  • score        — 0-10 的整数，10=极重要 / 7=值得关注 / 4=一般 / 0=低质量或噪音
  • category     — incident | vuln | supply-chain | research | industry
                   （仅当 is_relevant=true 时填，否则 null）
  • is_relevant  — true / false

  ★ is_relevant 判断准则 — 严格按"网络安全"主题判，不放水：

  true 仅当文章主题之一是：
    - 网络/信息/软件安全漏洞、CVE 披露、补丁公告
    - 恶意软件、APT、勒索软件、僵尸网络、钓鱼
    - 数据泄露、入侵事件、网络攻击事件
    - 软件供应链投毒、恶意 npm/PyPI/GitHub 包
    - 安全研究 / 红蓝队 / 攻防技术 / 安全工具 / 漏洞复现 / 提权 / 逃逸 / 加密学
    - 隐私保护、合规法规（GDPR/HIPAA/等保等）
    - 网络安全公司的产品/重大动作（仅当影响安全能力）

  false 包括（但不限于）：
    × 一般科技商业新闻（员工奖金、福利、薪资八卦、豪车豪宅）
    × 公司财报、季度业绩、半导体景气度
    × 产品发布会、新品评测（除非有安全功能重大变化）
    × 苹果/微软/谷歌的非安全产品动态（如 WWDC 主题演讲人事变动）
    × CEO 离任 / 高管变动（除非是首席安全官、与安全部门相关）
    × 大模型行业评论、AI 投资动态（除非是 ML 安全/红队/对齐）
    × 编程语言、前端框架、开发工具的非安全内容
    × 个人博客的生活随笔、感悟、读书笔记
    × 财经娱乐、体育、政治、地缘（除非和网络战 / 国家黑客组织相关）

  ★ "industry" 类别专指【网络安全行业动态】，不是泛指任何"科技行业"：
    industry  ✓ Crowdstrike 财报创新高 / 国务院发文加强关键信息基础设施保护
    industry  ✗ 三星员工奖金 / 京东商业地产 / 半导体股价
    遇到含糊不清的"科技新闻"，先判 is_relevant=false。

  • reason       — 1 句话理由 (中文, <= 80 字)

只输出 JSON,格式: {"items": [{...}, {...}]}
不要 markdown,不要解释,不要前缀,只 JSON。
"""


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


# ── Vulnerability AI assessment ──

async def assess_vulns(days: int = 7, limit: int | None = None, verbose: bool = True) -> dict:
    cfg = _get_config()
    if not cfg["api_key"]:
        return {"skipped": True}

    sys.path.insert(0, str(ROOT))
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
             if (v.cve_id or v.id) not in existing
             and _is_within_days(v.published or v.first_seen, days)]
    if limit:
        needs = needs[:limit]
    if not needs:
        if verbose:
            print(f"[vuln] all vulns assessed or outside {days}d window", file=sys.stderr)
        return {"assessed": 0}

    batch_size = 20
    if verbose:
        print(f"[vuln] assessing {len(needs)} vulns, batch={batch_size}, concurrency={cfg['concurrency']}", file=sys.stderr)

    assessed = 0
    errors = 0
    lock = asyncio.Lock()
    t0 = time.monotonic()

    all_chunks = [needs[i:i + batch_size] for i in range(0, min(len(needs), cfg["max_batches"] * batch_size), batch_size)]

    async def process(chunk, batch_num, client):
        nonlocal assessed, errors
        msg_parts = []
        for lid, (_, v) in enumerate(chunk):
            flags = []
            if v.is_kev: flags.append("KEV")
            if v.is_itw: flags.append("ITW")
            if v.pocs: flags.append(f"PoC×{len(v.pocs)}")
            if v.is_ransomware: flags.append("Ransomware")
            if v.is_supply_chain: flags.append("SupplyChain")
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            cvss_str = f" CVSS={v.cvss}" if v.cvss else ""
            epss_str = f" EPSS={v.epss_score:.3f}" if v.epss_score else ""
            ctx = []
            if v.vendor: ctx.append(f"Vendor={v.vendor}")
            if v.product: ctx.append(f"Product={v.product}")
            if v.ecosystem: ctx.append(f"Ecosystem={v.ecosystem}")
            if v.package: ctx.append(f"Package={v.package}")
            ctx_str = f" [{', '.join(ctx)}]" if ctx else ""
            msg_parts.append(
                f"[{lid}] {v.cve_id or v.id}{flag_str}{cvss_str}{epss_str}{ctx_str}\n"
                f"  Title: {v.title[:200]}\n  Summary: {v.summary[:400]}"
            )
        user_msg = "请评估以下漏洞：\n\n" + "\n\n".join(msg_parts)

        parsed = None
        for attempt in range(3):
            try:
                parsed = await _llm_call(client, VULN_SYSTEM_PROMPT, user_msg, cfg["base_url"], cfg["api_key"], cfg["model"], cfg["timeout"])
                break
            except Exception as exc:
                if verbose:
                    print(f"[vuln] batch {batch_num} attempt {attempt+1} failed: {exc}", file=sys.stderr)
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt * 3)

        if parsed is None:
            async with lock:
                errors += 1
            return

        n = 0
        async with lock:
            for item in parsed.get("results") or []:
                if not isinstance(item, dict):
                    continue
                try:
                    lid = int(item["id"])
                    if lid < 0 or lid >= len(chunk):
                        continue
                    v = chunk[lid][1]
                    sev = item.get("ai_severity", "")
                    if sev not in ("critical", "high", "medium", "low"):
                        continue
                    summary = str(item.get("summary") or "").strip()[:400]
                except (KeyError, TypeError, ValueError):
                    continue
                existing[v.cve_id or v.id] = {
                    "ai_severity": sev,
                    "ai_summary": summary,
                    "assessed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                assessed += 1
                n += 1
        if verbose:
            print(f"[vuln] batch {batch_num}/{len(all_chunks)}: +{n}, total {assessed}", file=sys.stderr)

    def flush():
        VULN_AI_JSON.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")

    await _run_concurrent(
        {"chunks": all_chunks, "timeout": cfg["timeout"]},
        process, min(cfg["concurrency"], 3), lock, flush, flush_every=3
    )
    flush()
    elapsed = round(time.monotonic() - t0, 1)
    if verbose:
        print(f"[vuln] done: {assessed} assessed in {elapsed}s ({errors} errors)", file=sys.stderr)
    return {"assessed": assessed, "errors": errors, "elapsed_s": elapsed}


# ── Daily briefing per category ──

CAT_NAMES = {
    "incident": "安全事件",
    "vuln": "漏洞情报",
    "supply-chain": "供应链投毒",
    "research": "安全研究",
    "industry": "行业动态",
}

ALL_CATEGORIES = ["incident", "vuln", "supply-chain", "research", "industry"]


async def generate_daily_brief(
    target_date: str | None = None,
    verbose: bool = True,
) -> dict:
    """Generate a daily brief for each of the 5 categories.

    For each category, pull top N high-score relevant articles published on
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
            min(conn.execute(
                "SELECT COUNT(*) FROM articles WHERE substr(published,1,10)=? AND llm_category=? AND (is_relevant=1 OR is_relevant IS NULL) AND (cluster_id IS NULL OR is_cluster_primary=1)",
                [target_date, c]).fetchone()[0], 12)
            for c in ALL_CATEGORIES)
        _brief_articles_done = 0
        _prog.start("summarizing")
        _prog.report("summarizing", _brief_total, 0, label="daily_brief")

        async with httpx.AsyncClient(timeout=cfg["timeout"]) as client:
            for category in ALL_CATEGORIES:
                # Filter by published date (not fetched_at) so counts match
                # the frontend news view. is_relevant accepts NULL for
                # cold-start before classify backlog finishes.
                rows = list(conn.execute("""
                    SELECT title, summary, source_title, llm_summary_zh
                    FROM articles
                    WHERE substr(published, 1, 10) = ?
                      AND llm_category = ?
                      AND (is_relevant = 1 OR is_relevant IS NULL)
                      AND (cluster_id IS NULL OR is_cluster_primary = 1)
                    ORDER BY COALESCE(llm_score, 5) DESC
                    LIMIT 12
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
    has_errors = any(r.get("errors") for r in results.values() if isinstance(r, dict))
    return 1 if has_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
