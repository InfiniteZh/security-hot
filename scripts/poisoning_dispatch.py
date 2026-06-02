"""供应链投毒情报投送 —— security-hot → Kafka(schedule_task_normal) → security_copilot disposal。

三层辨别只投"可处置"的情报（点名具体可被企业安装的包/IOC），不投纯趋势/事件报道：
  L0 免费 SQL 筛：llm_category='supply-chain' AND llm_score>=8 AND is_relevant
                  AND (cluster_id IS NULL OR is_cluster_primary=1) AND 未投送过
  L1 轻量 LLM triage：复用 llm_rank 的模型问"是否点名了具体可装的包/IOC"，仅 actionable 投
  （L2 权威兜底在 security_copilot disposal 的 extractor，已存在）

投送前拉取 canonical_url 全文（news.db 无全文，只有 RSS 摘要）。
幂等：poisoning_dispatched 标记防重发。

用法（cron，跟在 llm_rank 之后）：
  uv run python scripts/poisoning_dispatch.py                 # 默认 3 天内
  uv run python scripts/poisoning_dispatch.py --dry-run       # 只打印不发不标记
  uv run python scripts/poisoning_dispatch.py --limit 5 --fresh-days 14

环境变量：
  KAFKA_BOOTSTRAP（默认三 broker）、KAFKA_TOPIC（默认 schedule_task_normal）
  LLM_API_KEY/LLM_BASE_URL/LLM_MODEL（复用 llm_rank 配置）
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
import db  # noqa: E402
from dispatch_common import (  # noqa: E402
    KAFKA_BOOTSTRAP,
    KAFKA_TOPIC,
    TIER1_SUPPLY_SOURCES,
    TIER2_SUPPLY_SOURCES,
    extract_iocs,
    fetch_body,
    make_producer,
    send,
)
from llm_rank import _get_config, _llm_call  # noqa: E402  复用 llm_rank 的模型/调用

SCHEMA_VERSION = 2
MIN_SCORE = 8
TIER1_MIN_SCORE = 7

_TRIAGE_SYSTEM = """你是供应链投毒情报分诊员。判断一篇文章是否"可处置"——\
即是否点名了具体的、企业内网可能安装/使用的开源组件（含生态：npm/pypi/maven/go/cargo/nuget/gem 等），\
或给出了具体可联查的 IOC（域名/IP/文件 hash）。
纯趋势评论、宏观报道、无具体组件/IOC 的事件通报 → 不可处置。
只输出严格 JSON：{"actionable": true/false, "ecosystem": "", "package": "", "version": "", "iocs": [], "reason": "中文<=50字"}"""


# ── schema migration（幂等，新增 3 列）─────────────────────

_POISONING_COLUMNS = {
    "poisoning_dispatched": "INTEGER DEFAULT 0",
    "poisoning_triage_json": "TEXT",
    "poisoning_dispatched_at": "TEXT",
}


def migrate(conn: sqlite3.Connection) -> None:
    existing = {r["name"] for r in conn.execute("PRAGMA table_info(articles)")}
    for col, decl in _POISONING_COLUMNS.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE articles ADD COLUMN {col} {decl}")
    conn.commit()


# ── L0：候选选取 ──────────────────────────────────────────

def _source_tier(source_title: str | None) -> str:
    if source_title in TIER1_SUPPLY_SOURCES:
        return "tier1"
    if source_title in TIER2_SUPPLY_SOURCES:
        return "tier2"
    return "other"


def select_candidates(conn: sqlite3.Connection, fresh_days: int, limit: int | None) -> list[sqlite3.Row]:
    tier1 = sorted(TIER1_SUPPLY_SOURCES)
    placeholders = ",".join("?" for _ in tier1)
    sql = """
        SELECT id, canonical_url, title, summary, llm_summary_zh, llm_score, llm_category, source_title
        FROM articles
        WHERE llm_category = 'supply-chain'
          AND (
                llm_score >= ?
                OR (source_title IN ({tier1_placeholders}) AND llm_score >= ?)
              )
          AND (is_relevant = 1 OR is_relevant IS NULL)
          AND (cluster_id IS NULL OR is_cluster_primary = 1)
          AND COALESCE(poisoning_dispatched, 0) = 0
          AND (
                published IS NULL
                OR substr(published, 1, 10) >= date('now', ?)
              )
        ORDER BY llm_score DESC, published DESC
    """.format(tier1_placeholders=placeholders)
    params = [MIN_SCORE, *tier1, TIER1_MIN_SCORE, f"-{fresh_days} days"]
    rows = list(conn.execute(sql, params))
    if limit is not None:
        rows = rows[:limit]
    return rows


# ── L1：LLM triage ────────────────────────────────────────

async def triage(client, cfg, row: sqlite3.Row) -> dict:
    user_msg = json.dumps({
        "title": row["title"],
        "summary": row["summary"] or "",
        "summary_zh": row["llm_summary_zh"] or "",
    }, ensure_ascii=False)
    try:
        result = await _llm_call(
            client, _TRIAGE_SYSTEM, user_msg,
            cfg["base_url"], cfg["api_key"], cfg["model"], cfg["timeout"],
        )
    except Exception as e:
        return {"actionable": False, "reason": f"triage 调用失败: {e}",
                "ecosystem": "", "package": "", "version": "", "iocs": []}
    # 归一化字段
    return {
        "actionable": bool(result.get("actionable")),
        "ecosystem": result.get("ecosystem") or "",
        "package": result.get("package") or "",
        "version": result.get("version") or "",
        "iocs": result.get("iocs") or [],
        "reason": result.get("reason") or "",
    }


# ── 消息构造 ──────────────────────────────────────────────

def _message_iocs(values: list, package: str | None = None) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    exclude = {package.lower()} if package else set()
    for value in values or []:
        if isinstance(value, dict):
            raw = str(value.get("value") or "").strip()
        else:
            raw = str(value).strip()
        extracted = extract_iocs(raw, exclude=exclude)
        if not extracted and raw:
            extracted = [{"value": raw, "type": "unknown"}]
        for item in extracted:
            key = item["value"].lower()
            if key in seen:
                continue
            seen.add(key)
            out.append({"value": item["value"], "type": item["type"], "source": "news"})
    return out


def should_dispatch(triage_result: dict) -> bool:
    return bool(triage_result.get("actionable")) and (
        bool(triage_result.get("package"))
        or bool(triage_result.get("iocs"))
    )


def build_message(row: sqlite3.Row, triage_result: dict, full_body: str) -> dict:
    version = triage_result.get("version") or ""
    return {
        "schema_version": SCHEMA_VERSION,
        "source": "security-hot",
        "kind": "poisoning_intel",
        "origin": "news",
        "ref_id": row["id"],
        "article_id": row["id"],
        "title": row["title"],
        "canonical_url": row["canonical_url"],
        "ecosystem": triage_result.get("ecosystem") or "",
        "package": triage_result.get("package") or "",
        "affected_version": [version] if version else [],
        "fix_version": "",
        "iocs": _message_iocs(triage_result.get("iocs") or [], package=triage_result.get("package")),
        "cve_id": None,
        "ghsa_id": None,
        "severity": "unknown",
        "references": [{"url": row["canonical_url"], "label": row["source_title"] or ""}],
        "related_news": [],
        "summary": row["summary"] or "",
        "summary_zh": row["llm_summary_zh"] or "",
        "llm_score": row["llm_score"],
        "llm_category": row["llm_category"],
        "full_body": full_body,
        "triage": triage_result,
        "produced_at": int(time.time()),
    }


def mark_dispatched(conn: sqlite3.Connection, article_id: int, triage_result: dict) -> None:
    conn.execute(
        """UPDATE articles
           SET poisoning_dispatched = 1,
               poisoning_triage_json = ?,
               poisoning_dispatched_at = ?
           WHERE id = ?""",
        (json.dumps(triage_result, ensure_ascii=False),
         time.strftime("%Y-%m-%dT%H:%M:%S"), article_id),
    )
    conn.commit()


# ── 主流程 ────────────────────────────────────────────────

async def run(fresh_days: int, limit: int | None, dry_run: bool) -> dict:
    cfg = _get_config()
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP", KAFKA_BOOTSTRAP)
    topic = os.environ.get("KAFKA_TOPIC", KAFKA_TOPIC)

    conn = db.connect()
    migrate(conn)
    candidates = select_candidates(conn, fresh_days, limit)
    stats = {"candidates": len(candidates), "actionable": 0, "sent": 0,
             "skipped_not_actionable": 0, "errors": 0, "dry_run": dry_run}
    print(f"[dispatch] L0 候选 {len(candidates)} 条 (score>={MIN_SCORE}, tier1>={TIER1_MIN_SCORE}, fresh={fresh_days}d)",
          file=sys.stderr)
    if not candidates:
        conn.close()
        return stats

    producer = None
    if not dry_run:
        try:
            producer = make_producer(bootstrap)
            await producer.start()
        except Exception as e:
            print(f"[dispatch] 连接 Kafka 失败，退出: {e}", file=sys.stderr)
            conn.close()
            stats["errors"] += 1
            return stats

    try:
        async with httpx.AsyncClient(timeout=cfg["timeout"]) as client:
            for row in candidates:
                tri = await triage(client, cfg, row)
                tri["source_tier"] = _source_tier(row["source_title"])
                if not should_dispatch(tri):
                    stats["skipped_not_actionable"] += 1
                    if not dry_run:
                        mark_dispatched(conn, row["id"], tri)  # 标记避免反复 triage
                    print(f"[dispatch] 跳过 #{row['id']} 非可处置: {tri['reason']}", file=sys.stderr)
                    continue

                stats["actionable"] += 1
                full_body = await fetch_body(client, row["canonical_url"])
                msg = build_message(row, tri, full_body)

                if dry_run:
                    print(json.dumps(msg, ensure_ascii=False, indent=2))
                    continue

                try:
                    await send(producer, topic, str(row["id"]), msg)
                    mark_dispatched(conn, row["id"], tri)
                    stats["sent"] += 1
                    print(f"[dispatch] 已投送 #{row['id']} {row['title'][:50]}", file=sys.stderr)
                except Exception as e:
                    stats["errors"] += 1
                    print(f"[dispatch] 投送失败 #{row['id']}: {e}", file=sys.stderr)
    finally:
        if producer is not None:
            await producer.stop()
        conn.close()

    return stats


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="供应链投毒情报 → Kafka 投送")
    p.add_argument("--dry-run", action="store_true", help="只打印消息，不发不标记")
    p.add_argument("--limit", type=int, default=None, help="最多处理多少条")
    p.add_argument("--fresh-days", type=int, default=3, help="只处理 N 天内的文章")
    args = p.parse_args(argv)

    stats = asyncio.run(run(args.fresh_days, args.limit, args.dry_run))
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0 if stats["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
