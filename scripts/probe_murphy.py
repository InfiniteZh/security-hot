#!/usr/bin/env python3
"""Diagnostic probe for the MurphySec vuln_warn feed.

Standalone — does NOT touch backend/cache. Hits the same endpoint/params as
scripts/fetch_data.py:fetch_murphy, but with a configurable (wide) time window
and verbose output so you can see exactly what the feed returns: raw envelope,
available fields, totals, and how each item would be extracted/categorized.

Usage:
    uv run python scripts/probe_murphy.py                 # last 7 days, 2 pages
    uv run python scripts/probe_murphy.py --hours 24      # last 24h
    uv run python scripts/probe_murphy.py --days 30 --pages 5 --limit 50
    uv run python scripts/probe_murphy.py --raw           # dump first item raw JSON
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

import httpx
from dotenv import load_dotenv

# Reuse the real extraction helpers so the probe matches production behaviour.
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
import fetch_data as fd  # noqa: E402

load_dotenv()  # pull MURPHY_CUSTOMER_CODE etc. from .env

MURPHY_URL = fd.MURPHY_URL
MURPHY_TZ = fd.MURPHY_TZ


def _api_time(dt: datetime) -> str:
    return dt.astimezone(MURPHY_TZ).replace(microsecond=0).isoformat()


def main() -> int:
    import os

    p = argparse.ArgumentParser(description="Probe MurphySec vuln_warn feed")
    p.add_argument("--days", type=int, default=7, help="look back N days (default 7)")
    p.add_argument("--hours", type=int, default=None, help="look back N hours (overrides --days)")
    p.add_argument("--pages", type=int, default=2, help="max pages to pull (default 2)")
    p.add_argument("--limit", type=int, default=50, help="items per page (default 50)")
    p.add_argument("--sample", type=int, default=5, help="how many items to print in detail")
    p.add_argument("--raw", action="store_true", help="dump first item's raw JSON")
    args = p.parse_args()

    code = os.environ.get("MURPHY_CUSTOMER_CODE", "").strip()
    if not code:
        print("✗ MURPHY_CUSTOMER_CODE 未设置（检查 .env）", file=sys.stderr)
        return 2
    print(f"✓ CustomerCode 已加载（长度 {len(code)}，末4位 …{code[-4:]}）")

    now = datetime.now(timezone.utc)
    if args.hours is not None:
        start = now - timedelta(hours=args.hours)
        window_desc = f"最近 {args.hours} 小时"
    else:
        start = now - timedelta(days=args.days)
        window_desc = f"最近 {args.days} 天"
    start_time, end_time = _api_time(start), _api_time(now)
    print(f"窗口: {window_desc}  [{start_time} ~ {end_time}]  (scope=default, time=last_modify_time)\n")

    headers = {
        "Content-Type": "application/json",
        "CustomerCode": code,
        "User-Agent": fd.USER_AGENT,
    }

    all_items: list[dict] = []
    total: int | None = None
    with httpx.Client(timeout=90) as client:
        for page in range(1, args.pages + 1):
            body = {
                "page": page,
                "limit": args.limit,
                "scope": "default",
                "malicious_code": "include",
                "time_type": "last_modify_time",
                "order": "last_modify_time_desc",
                "start_time": start_time,
                "end_time": end_time,
            }
            try:
                resp = client.post(MURPHY_URL, json=body, headers=headers)
            except Exception as exc:  # noqa: BLE001
                print(f"✗ 请求失败 page={page}: {exc}", file=sys.stderr)
                return 1
            print(f"── page {page}: HTTP {resp.status_code} ──")
            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001
                print(f"  非 JSON 响应（前 200 字）: {resp.text[:200]}", file=sys.stderr)
                return 1
            api_code = payload.get("code") if isinstance(payload, dict) else None
            api_msg = payload.get("message") or payload.get("msg") if isinstance(payload, dict) else None
            print(f"  envelope: code={api_code} message={api_msg!r}")
            if api_code not in (None, 0, "0", 200, "200"):
                print(f"  ✗ API 返回错误码，停止。顶层 keys={list(payload)[:10]}", file=sys.stderr)
                return 1
            items = fd._murphy_items_from_payload(payload)
            if total is None:
                total = fd._murphy_total_from_payload(payload)
            print(f"  本页条数={len(items)}  接口声明 total={total}  envelope顶层keys={list(payload)[:8]}")
            all_items.extend(items)
            if not items or len(items) < args.limit:
                break
            if total is not None and page * args.limit >= total:
                break

    print(f"\n========== 汇总：共抓到 {len(all_items)} 条（窗口内, total≈{total}）==========")
    if not all_items:
        print("（窗口内没有数据 —— 试着加大 --days，或确认 CustomerCode 有该 scope 权限）")
        return 0

    if args.raw:
        print("\n--- 第 1 条原始 JSON ---")
        print(json.dumps(all_items[0], ensure_ascii=False, indent=2)[:4000])

    # 字段覆盖统计
    key_counter: Counter = Counter()
    for it in all_items:
        if isinstance(it, dict):
            key_counter.update(it.keys())
    print("\n--- 出现过的字段（次数）---")
    for k, c in key_counter.most_common():
        print(f"  {k}: {c}")

    # 抽取 + 归类预览（复用生产逻辑）
    cve_n = mal_n = 0
    sev_counter: Counter = Counter()
    eco_counter: Counter = Counter()
    print(f"\n--- 前 {args.sample} 条抽取预览 ---")
    for i, it in enumerate(all_items):
        cve = fd._murphy_first_cve(it)
        title = fd._murphy_first_text(it, fd.MURPHY_TITLE_KEYS)
        pkg = fd._murphy_first_text(it, fd.MURPHY_PACKAGE_KEYS)
        mtime = fd._murphy_item_time(it)
        malicious = any(
            str(it.get(k, "")).strip().lower() in ("1", "true", "yes", "malicious", "malware")
            for k in ("is_malicious", "isMalicious", "malicious", "malicious_code", "maliciousCode")
        )
        if cve:
            cve_n += 1
        if malicious:
            mal_n += 1
        kind = "supply"  # 生产里 murphy 现在统一 supply
        if i < args.sample:
            print(f"  [{i+1}] cve={cve or '-'} pkg={pkg or '-'} malicious={malicious} "
                  f"time={mtime or '-'}\n       title={title[:80]!r} → kind={kind}")
    print("\n--- 统计 ---")
    print(f"  带 CVE: {cve_n}/{len(all_items)}")
    print(f"  恶意包标记: {mal_n}/{len(all_items)}")
    print("  （生产中所有 murphy 条目 kind=supply / is_supply_chain=True）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
