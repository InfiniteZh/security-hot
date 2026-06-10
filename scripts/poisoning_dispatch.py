"""供应链投毒情报投送 —— security-hot → Kafka(schedule_task_normal) → security_copilot disposal。

当前只投 tier1 供应链权威源（正文结构化、含包清单+IOC 表），tier2 暂不进入候选。
后续扩展只需调整 dispatch_common.TIER1_SUPPLY_SOURCES / TIER2_SUPPLY_SOURCES。

三层辨别只投"可处置"的情报（点名具体可被企业安装的包/IOC），不投纯趋势/事件报道：
  L0 免费 SQL 筛：source_title∈TIER1_SUPPLY_SOURCES AND llm_category='supply-chain'
                  AND llm_score>=7 AND is_relevant
                  AND (cluster_id IS NULL OR is_cluster_primary=1) AND 未投送过
  L1 LLM triage（基于全文）：问"是否点名了具体可装的包/失陷指标"，仅 actionable 投；
                  package/version/iocs 经 dispatch_common 严格校验，散文/文件名/commit hash 一律剔除
  （L2 权威兜底在 security_copilot disposal 的 extractor，已存在）

先抓 canonical_url 全文再 triage（news.db 无全文，只有 RSS 摘要；薄摘要会漏判）。
净化后既无有效 package 又无有效 IOC → 不投。
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
import re
import sqlite3
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
import db  # noqa: E402
from dispatch_common import (  # noqa: E402
    BODY_AUGMENT_TYPES,
    KAFKA_BOOTSTRAP,
    KAFKA_TOPIC,
    TIER1_SUPPLY_SOURCES,
    TIER2_SUPPLY_SOURCES,
    extract_iocs,
    fetch_body,
    make_producer,
    send,
    valid_package,
    valid_version,
    valid_versions,
)
from llm_rank import _get_config, _llm_call  # noqa: E402  复用 llm_rank 的模型/调用

try:  # best-effort：CLI 独立运行时缺失也不致命
    import refresh_progress as _prog  # noqa: E402
except Exception:  # pragma: no cover
    _prog = None

SCHEMA_VERSION = 3
MIN_SCORE = 8
TIER1_MIN_SCORE = 7

# triage 喂给 LLM 的正文摘录上限（控 token）。一次投毒常列 30+ 包 + 多组 IOC，
# 摘录太短会漏包漏 IOC，故放宽到 16k（仍在单次 OUTPUT 之外，属 INPUT 侧）。
TRIAGE_BODY_LIMIT = 16000

_TRIAGE_SYSTEM = """你是供应链投毒情报分诊员。基于【正文】（而非仅标题/摘要）判断文章是否"可处置"——\
即是否点名了具体的、企业内网可能安装/使用的开源组件，或给出了具体可联查的失陷指标。
可处置场景（以下任一成立 → actionable=true）：
  A. 注册表包投毒：点名了具体的 npm/pypi/maven/go/cargo/nuget/gem/composer/packagist 等生态的恶意包；
  B. GitHub 仓库源码劫持：某个被广泛 git clone/pip install git+.../直接从 repo 安装的开源项目的主分支/标签/Release 被植入恶意代码，
     企业开发者可能在攻击窗口内拉取过。此场景 ecosystem 填 "github"，package 填完整 org/repo（如 Pythagora-io/gpt-pilot）。
不可处置：纯趋势评论、宏观报道、无具体组件/IOC 的事件通报（actionable=false，packages=[], iocs=[]）。
字段规则（严格遵守）：
- packages：列出文章点名的【所有】被投毒/恶意的具体包/仓库，一个都不要漏。每个元素：
    {"ecosystem":"<npm|pypi|maven|go|cargo|nuget|gem|composer|packagist|github 等，未知填空串>",
     "package":"<单个具体包名或 org/repo，不含空格/说明文字>",
     "versions":["<受影响版本号或 git commit hash（40位）>", ...]  // 多个就都列；无则空数组}
  正文若列了 30 个中毒包就返回 30 个元素。无任何具体包 → packages 为空数组 []。
- iocs：列出文章里【所有】真正的失陷指标，一个都不要漏——恶意域名 / IP / 文件哈希（SHA256 64位、SHA1 40位 git commit hash、MD5 32位）/ 恶意 URL。\
绝不要填：包名、文件名（如 index.js）、文件路径、加密算法描述、报告人账号、恶意软件家族名、生态名、\
合法基础设施（如 npm/pypi 注册中心、sigstore.dev 等代码签名基础设施、区块链公共节点）。无则空数组 []。
只输出严格 JSON：{"actionable": true/false, "packages": [...], "iocs": [], "reason": "中文<=50字"}"""


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
    # 只投 tier1 供应链权威源；tier2 暂不进入 Kafka 候选。
    sources = sorted(TIER1_SUPPLY_SOURCES)
    placeholders = ",".join("?" for _ in sources)
    sql = """
        SELECT id, canonical_url, title, summary, llm_summary_zh, llm_score, llm_category, source_title
        FROM articles
        WHERE llm_category = 'supply-chain'
          AND source_title IN ({source_placeholders})
          AND llm_score >= ?
          AND (is_relevant = 1 OR is_relevant IS NULL)
          AND (cluster_id IS NULL OR is_cluster_primary = 1)
          AND COALESCE(poisoning_dispatched, 0) = 0
          AND (
                published IS NULL
                OR substr(published, 1, 10) >= date('now', ?)
              )
        ORDER BY llm_score DESC, published DESC
    """.format(source_placeholders=placeholders)
    params = [*sources, TIER1_MIN_SCORE, f"-{fresh_days} days"]
    rows = list(conn.execute(sql, params))
    if limit is not None:
        rows = rows[:limit]
    return rows


# ── L1：LLM triage ────────────────────────────────────────

async def triage(client, cfg, row: sqlite3.Row, body: str = "") -> dict:
    user_msg = json.dumps({
        "title": row["title"],
        "summary": row["summary"] or "",
        "summary_zh": row["llm_summary_zh"] or "",
        "body": (body or "")[:TRIAGE_BODY_LIMIT],
    }, ensure_ascii=False)
    try:
        result = await _llm_call(
            client, _TRIAGE_SYSTEM, user_msg,
            cfg["base_url"], cfg["api_key"], cfg["model"], cfg["timeout"],
            max_concurrency=cfg["concurrency"],
        )
    except Exception as e:
        return {"actionable": False, "reason": f"triage 调用失败: {e}",
                "ecosystem": "", "package": "", "version": "", "iocs": []}
    # 归一化字段（v3：多包数组）。容忍旧式扁平 package/version → 包成单元素数组。
    packages = result.get("packages")
    if not packages and result.get("package"):
        packages = [{
            "ecosystem": result.get("ecosystem") or "",
            "package": result.get("package"),
            "versions": result.get("version") or [],
        }]
    return {
        "actionable": bool(result.get("actionable")),
        "packages": packages or [],
        "iocs": result.get("iocs") or [],
        "reason": result.get("reason") or "",
    }


# ── 消息构造 ──────────────────────────────────────────────

# LLM 偶尔会把 advisory 自身的 commit / 报告人账号 / 命名空间说明塞进 iocs——
# 这些不是失陷指标，带这些注解词的值整条丢弃。
_IOC_ANNOTATION_DROP = re.compile(
    r"\b(commit|source\s+account|source\s+commit|reporter|advisory|namespace|maintainer)\b",
    re.IGNORECASE,
)


def _message_iocs(values: list, exclude_names: set[str] | None = None) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    exclude = {n.lower() for n in (exclude_names or set()) if n}
    for value in values or []:
        if isinstance(value, dict):
            raw = str(value.get("value") or "").strip()
        else:
            raw = str(value).strip()
        if not raw or _IOC_ANNOTATION_DROP.search(raw):
            continue
        # 只保留正则识别出真实类型的 IOC；散文/文件名/算法描述（无可识别类型）一律丢弃。
        # 合法基础设施（trongrid.io 等）由 extract_iocs 内部 allowlist 直接剔除。
        for item in extract_iocs(raw, exclude=exclude):
            key = item["value"].lower()
            if key in seen:
                continue
            seen.add(key)
            out.append({"value": item["value"], "type": item["type"], "source": "news"})
    return out


# 正文里补抓的"高置信"IOC 类型：哈希几乎必然是失陷指标，且常列在表格里被 LLM 截断/漏掉；
# 域名/URL 不在此列（散文里的厂商域名/引用链接噪声大，仍只信 LLM triage）。

def _augment_iocs_from_body(iocs: list[dict], full_body: str,
                            exclude_names: set[str] | None = None) -> list[dict]:
    """用正文里正则抓到的高置信哈希补全 LLM 可能漏掉的 IOC（去重合并）。"""
    have = {i["value"].lower() for i in iocs}
    for item in extract_iocs(full_body or "", exclude={n.lower() for n in (exclude_names or set()) if n}):
        if item["type"] not in BODY_AUGMENT_TYPES:
            continue
        key = item["value"].lower()
        if key in have:
            continue
        have.add(key)
        iocs.append({"value": item["value"], "type": item["type"], "source": "news"})
    return iocs


def clean_packages(triage_result: dict) -> list[dict]:
    """净化 triage 的多包数组：逐包校验包名 + 逐元素校验版本，剔除非法/重复。"""
    out: list[dict] = []
    seen: set[str] = set()
    for p in triage_result.get("packages") or []:
        if not isinstance(p, dict):
            continue
        name = valid_package(p.get("package") or "")
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        raw_versions = p.get("versions")
        if raw_versions is None:
            raw_versions = p.get("version")  # 容忍旧式单 version 字段
        out.append({
            "ecosystem": (p.get("ecosystem") or "").strip().lower(),
            "package": name,
            "affected_version": valid_versions(raw_versions),
            "fix_version": valid_version(p.get("fix_version") or p.get("fix") or ""),
        })
    return out


def clean_fields(triage_result: dict) -> tuple[list[dict], list[dict]]:
    """对 triage 输出做严格净化，返回 (packages, iocs)。"""
    packages = clean_packages(triage_result)
    exclude = {p["package"] for p in packages}
    iocs = _message_iocs(triage_result.get("iocs") or [], exclude_names=exclude)
    return packages, iocs


def should_dispatch(triage_result: dict) -> bool:
    if not triage_result.get("actionable"):
        return False
    packages, iocs = clean_fields(triage_result)
    return bool(packages or iocs)


def build_message(row: sqlite3.Row, triage_result: dict, full_body: str) -> dict:
    packages, iocs = clean_fields(triage_result)
    iocs = _augment_iocs_from_body(iocs, full_body, exclude_names={p["package"] for p in packages})
    return {
        "schema_version": SCHEMA_VERSION,
        "source": "security-hot",
        "kind": "poisoning_intel",
        "origin": "news",
        "ref_id": row["id"],
        "article_id": row["id"],
        "title": row["title"],
        "canonical_url": row["canonical_url"],
        "packages": packages,
        "iocs": iocs,
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

def select_by_ids(conn: sqlite3.Connection, ids: list[int]) -> list[sqlite3.Row]:
    """按 article id 直接选取（重投用）：绕过 L0 的分数/源/新鲜度/已投过滤，
    只要这些行存在就重新走 triage→投送。"""
    if not ids:
        return []
    placeholders = ",".join("?" for _ in ids)
    return list(conn.execute(
        f"""SELECT id, canonical_url, title, summary, llm_summary_zh,
                   llm_score, llm_category, source_title
            FROM articles WHERE id IN ({placeholders})""",
        ids,
    ))


async def run(fresh_days: int, limit: int | None, dry_run: bool,
              redispatch_ids: list[int] | None = None) -> dict:
    cfg = _get_config()
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP", KAFKA_BOOTSTRAP)
    topic = os.environ.get("KAFKA_TOPIC", KAFKA_TOPIC)

    conn = db.connect()
    migrate(conn)
    if redispatch_ids:
        # 重投：直选这些 id（绕过 L0 过滤）。清标记只在真投时做，dry-run 不留副作用。
        if not dry_run:
            ph = ",".join("?" for _ in redispatch_ids)
            conn.execute(
                f"""UPDATE articles SET poisoning_dispatched=0,
                       poisoning_triage_json=NULL, poisoning_dispatched_at=NULL
                    WHERE id IN ({ph})""", redispatch_ids)
            conn.commit()
        candidates = select_by_ids(conn, redispatch_ids)
    else:
        candidates = select_candidates(conn, fresh_days, limit)
    stats = {"candidates": len(candidates), "actionable": 0, "sent": 0,
             "skipped_not_actionable": 0, "errors": 0, "dry_run": dry_run,
             "error_messages": []}
    if redispatch_ids:
        print(f"[dispatch] 重投 {len(candidates)} 条 (ids={redispatch_ids})", file=sys.stderr)
    else:
        print(f"[dispatch] L0 候选 {len(candidates)} 条 "
              f"(tier1 源={sorted(TIER1_SUPPLY_SOURCES)}, score>={TIER1_MIN_SCORE}, fresh={fresh_days}d)",
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
            msg = f"连接 Kafka 失败: {e}"
            stats["error_messages"].append(msg)
            print(f"[dispatch] {msg}，退出", file=sys.stderr)
            conn.close()
            stats["errors"] += 1
            return stats

    _total = len(candidates)
    if _prog is not None:
        _prog.start("dispatching")
        _prog.report("dispatching", _total, 0, label="poisoning_dispatch")
    try:
        async with httpx.AsyncClient(timeout=cfg["timeout"]) as client:
            for _i, row in enumerate(candidates, 1):
                if _prog is not None:
                    _prog.report("dispatching", _total, _i, label="poisoning_dispatch")
                # 先抓全文再 triage：tier1 源常把包清单/IOC 放正文，摘要太薄会误判漏投。
                full_body = await fetch_body(client, row["canonical_url"])
                tri = await triage(client, cfg, row, full_body)
                tri["source_tier"] = _source_tier(row["source_title"])
                if not should_dispatch(tri):
                    stats["skipped_not_actionable"] += 1
                    if not dry_run:
                        mark_dispatched(conn, row["id"], tri)  # 标记避免反复 triage
                    print(f"[dispatch] 跳过 #{row['id']} 非可处置: {tri['reason']}", file=sys.stderr)
                    continue

                stats["actionable"] += 1
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
                    stats["error_messages"].append(f"投送失败 #{row['id']}: {e}")
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
    p.add_argument("--redispatch", default=None,
                   help="强制重投指定 article id（逗号分隔）：清标记并绕过 L0 过滤重走 triage")
    args = p.parse_args(argv)

    redispatch_ids = None
    if args.redispatch:
        redispatch_ids = [int(x) for x in args.redispatch.split(",") if x.strip()]

    stats = asyncio.run(run(args.fresh_days, args.limit, args.dry_run,
                            redispatch_ids=redispatch_ids))
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0 if stats["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
