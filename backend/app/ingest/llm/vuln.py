"""Vulnerability AI assessment.

Pulls normalized vulns from backend.app.data, asks the LLM for an
independent severity + Chinese summary per CVE, and caches the result in
vuln_ai.json. The public function is assess_vulns (the legacy vuln_assess
alias is intentionally absent).

Depends on llm_client (infra) + prompts (constants). No dependency on the
news/brief/orchestration modules, keeping the import graph acyclic.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time

from .client import (
    ROOT,
    VULN_AI_JSON,
    _get_config,
    _is_within_days,
    _run_concurrent,
    _llm_call_via_facade as _llm_call,
)
from .prompts import VULN_SYSTEM_PROMPT


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
