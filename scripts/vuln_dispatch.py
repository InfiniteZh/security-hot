"""恶意包漏洞情报投送 —— security-hot vuln feed → Kafka."""
from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import db  # noqa: E402
from backend.app.data import all_vulns, search_articles  # noqa: E402
from backend.app.models import Article, Reference, Vuln  # noqa: E402
from dispatch_common import (  # noqa: E402
    KAFKA_BOOTSTRAP,
    KAFKA_TOPIC,
    extract_iocs,
    make_producer,
    send,
)

SCHEMA_VERSION = 2


def migrate(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vuln_dispatches (
            vuln_id           TEXT PRIMARY KEY,
            origin            TEXT DEFAULT 'vuln',
            related_news_json TEXT,
            message_json      TEXT,
            dispatched_at     TEXT
        )
    """)
    conn.commit()


def dispatched_ids(conn: sqlite3.Connection) -> set[str]:
    return {r["vuln_id"] for r in conn.execute("SELECT vuln_id FROM vuln_dispatches")}


def _vuln_date(v: Vuln) -> str:
    """投递新鲜度判定用的日期（YYYY-MM-DD）：优先 published，回退 first_seen。"""
    return (v.published or v.first_seen or "")[:10]


def select_candidates(
    vulns: list[Vuln],
    already_dispatched: set[str],
    *,
    limit: int | None,
    since_days: int = 1,
    redispatch: str | None = None,
) -> list[Vuln]:
    # 冷启动护栏：只投"近 since_days 天内"的恶意包（since_days=0 → 仅今天）。
    # 否则首次运行幂等表为空时会把全部历史恶意包一次性灌爆下游。
    # 无日期的条目在冷启动窗口下一律跳过（避免误投未知时间的历史项）。
    cutoff = (datetime.date.today() - datetime.timedelta(days=since_days)).isoformat()
    out = [
        v for v in vulns
        if v.kind == "supply"
        and v.is_supply_chain
        and (redispatch is None or v.id == redispatch)
        and (redispatch is not None or v.id not in already_dispatched)
        and (redispatch is not None or (_vuln_date(v) != "" and _vuln_date(v) >= cutoff))
    ]
    if limit is not None:
        return out[:limit]
    return out


def _article_key(article: Article) -> str:
    if article.id is not None:
        return f"id:{article.id}"
    return f"url:{article.link}"


def _related_news_item(article: Article) -> dict:
    return {
        "title": article.title,
        "url": article.link,
        "summary_zh": article.llm_summary_zh or article.summary or "",
        "llm_score": article.llm_score,
        "source_title": article.source_title,
    }


def find_related_news(vuln: Vuln, limit: int = 5) -> list[dict]:
    queries = [q for q in (vuln.cve_id, vuln.package, vuln.ghsa_id) if q]
    by_key: dict[str, Article] = {}
    for q in queries:
        for article in search_articles(q, limit=max(limit * 4, 20)):
            by_key.setdefault(_article_key(article), article)
    articles = list(by_key.values())
    articles.sort(
        key=lambda a: (
            a.llm_score if a.llm_score is not None else -1,
            a.published or "",
        ),
        reverse=True,
    )
    return [_related_news_item(a) for a in articles[:limit]]


def _add_ioc(out: list[dict], seen: set[str], value: str, typ: str, source: str) -> None:
    key = value.lower()
    if not value or key in seen:
        return
    seen.add(key)
    out.append({"value": value, "type": typ, "source": source})


def merge_iocs(vuln: Vuln, related_news: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    exclude = {vuln.package.lower()} if vuln.package else set()
    for raw in vuln.iocs:
        extracted = extract_iocs(str(raw), exclude=exclude)
        if extracted:
            for item in extracted:
                _add_ioc(out, seen, item["value"], item["type"], "vuln")
        else:
            _add_ioc(out, seen, str(raw).strip(), "unknown", "vuln")
    news_text = "\n".join(
        str(item.get("summary") or item.get("summary_zh") or item.get("llm_summary_zh") or "")
        for item in related_news
    )
    for item in extract_iocs(news_text, exclude=exclude):
        _add_ioc(out, seen, item["value"], item["type"], "news")
    return out


def canonical_url(vuln: Vuln) -> str:
    for ref in vuln.references:
        if "oscs1024.com/hd/" in ref.url:
            return ref.url
    ref_id = vuln.id[7:] if vuln.id.startswith("MURPHY-") else vuln.id
    return f"https://www.oscs1024.com/hd/{ref_id}"


def _refs(refs: list[Reference]) -> list[dict]:
    return [{"url": r.url, "label": r.label} for r in refs]


def build_message(vuln: Vuln, related_news: list[dict]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "source": "security-hot",
        "kind": "poisoning_intel",
        "origin": "vuln",
        "ref_id": vuln.id,
        "title": vuln.title,
        "canonical_url": canonical_url(vuln),
        "ecosystem": vuln.ecosystem or "",
        "package": vuln.package or "",
        "affected_version": vuln.affected_versions,
        "fix_version": vuln.fix_versions[0] if vuln.fix_versions else "",
        "iocs": merge_iocs(vuln, related_news),
        "cve_id": vuln.cve_id,
        "ghsa_id": vuln.ghsa_id,
        "severity": vuln.ai_severity or vuln.severity,
        "references": _refs(vuln.references),
        "related_news": related_news,
        "summary_zh": vuln.ai_summary or vuln.summary or "",
        "full_body": "",
        "triage": {
            "actionable": True,
            "reason": "结构化恶意包，自动可处置",
            "source_tier": "vuln",
        },
        "produced_at": int(time.time()),
    }


def mark_dispatched(conn: sqlite3.Connection, vuln_id: str, related_news: list[dict], msg: dict) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO vuln_dispatches
           (vuln_id, origin, related_news_json, message_json, dispatched_at)
           VALUES (?, 'vuln', ?, ?, ?)""",
        (
            vuln_id,
            json.dumps(related_news, ensure_ascii=False),
            json.dumps(msg, ensure_ascii=False),
            time.strftime("%Y-%m-%dT%H:%M:%S"),
        ),
    )
    conn.commit()


async def run(
    *,
    limit: int | None = None,
    dry_run: bool = False,
    since_days: int = 1,
    redispatch: str | None = None,
) -> dict:
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP", KAFKA_BOOTSTRAP)
    topic = os.environ.get("KAFKA_TOPIC", KAFKA_TOPIC)
    conn = db.connect()
    migrate(conn)
    if redispatch:
        conn.execute("DELETE FROM vuln_dispatches WHERE vuln_id = ?", [redispatch])
        conn.commit()
    candidates = select_candidates(
        all_vulns(),
        dispatched_ids(conn),
        limit=limit,
        since_days=since_days,
        redispatch=redispatch,
    )
    stats = {"candidates": len(candidates), "sent": 0, "errors": 0,
             "dry_run": dry_run, "since_days": since_days}
    print(f"[vuln-dispatch] 候选 {len(candidates)} 条 (since_days={since_days})", file=sys.stderr)
    if not candidates:
        conn.close()
        return stats

    producer = None
    if not dry_run:
        try:
            producer = make_producer(bootstrap)
            await producer.start()
        except Exception as e:
            print(f"[vuln-dispatch] 连接 Kafka 失败，退出: {e}", file=sys.stderr)
            conn.close()
            stats["errors"] += 1
            return stats

    try:
        for vuln in candidates:
            related_news = find_related_news(vuln)
            msg = build_message(vuln, related_news)
            if dry_run:
                print(json.dumps(msg, ensure_ascii=False, indent=2))
                continue
            try:
                await send(producer, topic, vuln.id, msg)
                mark_dispatched(conn, vuln.id, related_news, msg)
                stats["sent"] += 1
                print(f"[vuln-dispatch] 已投送 {vuln.id} {vuln.title[:50]}", file=sys.stderr)
            except Exception as e:
                stats["errors"] += 1
                print(f"[vuln-dispatch] 投送失败 {vuln.id}: {e}", file=sys.stderr)
    finally:
        if producer is not None:
            await producer.stop()
        conn.close()
    return stats


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="恶意包漏洞情报 → Kafka 投送")
    p.add_argument("--dry-run", action="store_true", help="只打印消息，不发不标记")
    p.add_argument("--limit", type=int, default=None, help="最多处理多少条")
    p.add_argument("--since-days", type=int, default=1,
                   help="冷启动护栏：只投近 N 天内的恶意包（0=仅今天，默认 1 含当天+前一天缓冲）")
    p.add_argument("--redispatch", default=None, help="强制重投指定 vuln_id")
    args = p.parse_args(argv)

    stats = asyncio.run(run(limit=args.limit, dry_run=args.dry_run,
                            since_days=args.since_days, redispatch=args.redispatch))
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0 if stats["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
