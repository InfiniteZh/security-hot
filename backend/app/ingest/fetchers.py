"""Fetch real data from security sources into local JSON cache.

Outputs (all under backend/cache/):
  kev.json       CISA Known Exploited Vulnerabilities catalog (latest 200)
  ghsa.json      GitHub Security Advisories (latest 100 reviewed)
  pocs.json      Recent PoC publications (poc-in-github.motikan2010.net mirror)
  murphy.json    MurphySec vuln_warn list (time-window incremental)
  itw.json       inthewild.io feed (recent in-the-wild exploitation entries)
  heat.json      cvecrowd.com discussion-heat snapshot (if reachable)
  news.json      curated RSS sources (zh + en), latest articles per source
  epss.json      FIRST.org EPSS daily scores ({cve_id: {score, percentile}})
  osv-npm.json   OSV.dev all advisories for npm ecosystem
  osv-pypi.json  OSV.dev all advisories for PyPI ecosystem
  nuclei.json    projectdiscovery/nuclei-templates CVE coverage ({cve_id: paths})
  hn.json        Hacker News stories matching security queries (vuln/0day/RCE/...)
  masto.json     Mastodon public hashtag timelines (cve / infosec / 0day / ...)
  manifest.json  counts, timestamps, errors per fetcher

Usage:
  uv run python scripts/fetch_data.py
  uv run python scripts/fetch_data.py --only kev,news
  uv run python scripts/fetch_data.py --concurrency 12

Module layout
-------------
This file is the orchestration entrypoint and a façade: the fetcher
implementations live in cohesive sibling modules, but `fetchers.*` keeps
exposing every public symbol so cron, tests, scripts/fetch_data.py and the
rest of `backend` can keep importing from this path unchanged.

  _util.py           stateless helpers + constants + paths
  sources.py         RSS source catalog + resolution
  murphy.py          MurphySec vuln_warn source
  vuln_sources.py    KEV / GHSA / PoC / ITW / heat / OSV / nuclei
  signal_sources.py  EPSS / Hacker News / Mastodon enrichment
  news_ingest.py     industry-news SQLite ingestion + NDJSON archive
  snapshot.py        first_seen annotation + history snapshot
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

import httpx

# ─── façade: re-export every public symbol from the split modules so that
#     `fetchers.<anything>` keeps resolving exactly as before the refactor ───
# `import *` only re-exports names without a leading underscore, so the
# underscore-prefixed helpers that callers/tests reach for (e.g.
# `_fetch_one_osv_ecosystem`, `_canonical_url`) are also imported by name.
from ._util import *  # noqa: F401,F403
from ._util import (
    ARCHIVE_DIR,
    CACHE,
    HEADERS,
    ROOT,
    SCRIPTS,
    USER_AGENT,
    now_iso,
    write_json,
    strip_html,
    clean_summary,
    _iso_from_feedparser,
    _entry_published_iso,
    _parse_iso_datetime,
    _TRACKING_PREFIXES,
    _is_tracking_param,
    _canonical_url,
    _DEFAULT_BLOCK_KEYWORDS,
    _articles_keyword_filter,
)
from .sources.catalog import *  # noqa: F401,F403
from .sources.catalog import (
    NEWS_SOURCES,
    _ZH_HOST_HINTS,
    _slug_from_url,
    _detect_lang,
    _load_alive_sources_from_opml,
    _news_sources_to_use,
)
from .sources.murphy import *  # noqa: F401,F403
from .sources.murphy import (
    fetch_murphy,
    MURPHY_URL,
    MURPHY_TZ,
    MURPHY_TIME_KEYS,
    MURPHY_ID_KEYS,
    MURPHY_PACKAGE_KEYS,
    MURPHY_TITLE_KEYS,
    _murphy_api_time,
    _murphy_container,
    _murphy_items_from_payload,
    _murphy_total_from_payload,
    _murphy_first_text,
    _murphy_first_cve,
    _murphy_item_key,
    _murphy_item_time,
    _load_murphy_cache,
    _fetch_murphy_page,
)
from .sources.vuln import *  # noqa: F401,F403
from .sources.vuln import (
    fetch_ghsa,
    fetch_heat,
    fetch_itw,
    fetch_kev,
    fetch_nuclei,
    fetch_osv,
    fetch_pocs,
    _osv_ecosystem_url,
    _normalize_osv_entry,
    _fetch_one_osv_ecosystem,
    _NUCLEI_CVE_RE,
    _NUCLEI_REPO_BLOB,
)
from .sources.signal import *  # noqa: F401,F403
from .sources.signal import (
    fetch_epss,
    fetch_hn,
    fetch_masto,
    trim_epss_to_referenced,
    _HN_QUERIES,
    _CVE_TITLE_RE,
    _hn_search_one,
    _MASTO_INSTANCES,
    _MASTO_TAGS,
    _masto_one_tag,
)
from .sources.news import *  # noqa: F401,F403
from .sources.news import (
    dump_ndjson_archive,
    fetch_news_to_sqlite,
    _fetch_one_source_to_sqlite,
)
from .sources.snapshot import *  # noqa: F401,F403
from .sources.snapshot import (
    snapshot_today,
    HISTORY,
    SNAPSHOT_KEYS,
    _latest_history_dir,
    _read_prev_seen,
)


# ─── façade write-through for path globals ───
# The split worker functions resolve `CACHE` / `ARCHIVE_DIR` from `_util` at
# call time. Callers and tests, however, historically patch them on *this*
# module (e.g. `monkeypatch.setattr(fetchers, "CACHE", tmp_path)`), back when
# everything lived here. Mirror such assignments into `_util` so the patch
# still reaches the worker functions exactly as before the split.
import types as _types
from . import _util as _util_mod


class _FetchersModule(_types.ModuleType):
    _MIRRORED = {"CACHE", "ARCHIVE_DIR"}

    def __setattr__(self, name, value):
        super().__setattr__(name, value)
        if name in self._MIRRORED:
            setattr(_util_mod, name, value)


sys.modules[__name__].__class__ = _FetchersModule


FETCHERS = {
    "kev": fetch_kev,
    "ghsa": fetch_ghsa,
    "pocs": fetch_pocs,
    "murphy": fetch_murphy,
    "itw": fetch_itw,
    "heat": fetch_heat,
    "news": fetch_news_to_sqlite,   # ← changed from fetch_news (legacy will be removed in T2.4)
    "epss": fetch_epss,
    "osv": fetch_osv,
    "nuclei": fetch_nuclei,
    "hn": fetch_hn,
    "masto": fetch_masto,
}


async def run(selected: list[str], concurrency: int, snapshot: bool = True, incremental: bool = False) -> int:
    timeout = httpx.Timeout(30.0, connect=10.0)
    limits = httpx.Limits(max_connections=concurrency * 2, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(
        headers=HEADERS, timeout=timeout, limits=limits, follow_redirects=True
    ) as client:
        # Merge into the prior manifest so a partial (--only X) run keeps the
        # other fetchers' rows — the frontend pipeline panel + per-source
        # refresh buttons render from manifest.results, so a fresh [] would
        # wipe every source except the ones just fetched.
        prev_order: list[str] = []
        results_by_name: dict = {}
        if (CACHE / "manifest.json").exists():
            try:
                _prev = json.loads((CACHE / "manifest.json").read_text(encoding="utf-8"))
                for _r in _prev.get("results", []):
                    if isinstance(_r, dict) and _r.get("name"):
                        results_by_name[_r["name"]] = _r
                        prev_order.append(_r["name"])
            except (json.JSONDecodeError, OSError):
                pass
        for name in selected:
            t0 = time.monotonic()
            try:
                fn = FETCHERS[name]
                if name == "news":
                    # New SQLite news fetcher manages its own httpx client (needs per-source
                    # Conditional GET headers). `incremental` is now a no-op — Conditional
                    # GET is always on, so re-running with the same content is naturally
                    # cheap (304 responses skip article writes entirely).
                    r = await fn(concurrency=concurrency)
                else:
                    r = await fn(client)
                elapsed = round(time.monotonic() - t0, 2)
                r["elapsed_s"] = elapsed
                r["ok"] = True
                count = int(r.get("count", 0))
                if count > 0:
                    r["status"] = "ok"
                else:
                    r["status"] = "no_data"
                tag = "ok" if r["status"] == "ok" else "no-data"
                print(f"[{tag}] {name:<8} count={count:>4} elapsed={elapsed}s", file=sys.stderr)
            except Exception as exc:
                elapsed = round(time.monotonic() - t0, 2)
                r = {
                    "name": name,
                    "ok": False,
                    "status": "error",
                    "count": 0,
                    "error": f"{type(exc).__name__}: {exc}"[:300],
                    "elapsed_s": elapsed,
                }
                print(f"[err] {name:<8} {r['error']}", file=sys.stderr)
            r["finished_at"] = now_iso()
            results_by_name[name] = r
        # Preserve prior row order; append any newly-seen fetchers in run order.
        ordered = prev_order + [n for n in selected if n not in prev_order]
        manifest = {
            "fetched_at": now_iso(),
            "results": [results_by_name[n] for n in ordered if n in results_by_name],
        }
        write_json("manifest.json", manifest)

    # Post-fetch: trim EPSS to only CVEs referenced by other sources
    if "epss" in selected:
        try:
            kept = trim_epss_to_referenced()
            print(f"[trim] epss: kept {kept} CVEs (from full EPSS dump)", file=sys.stderr)
        except Exception as exc:
            print(f"[trim] epss failed: {exc}", file=sys.stderr)

    if snapshot:
        # Map fetcher names → the cache files they own. Fetchers writing
        # multiple cache files (osv → osv-npm + osv-pypi) must list both;
        # fetchers not tracked in SNAPSHOT_KEYS (epss/heat) map to empty.
        FETCHER_TO_CACHES = {
            "kev": ["kev"], "ghsa": ["ghsa"], "pocs": ["pocs"], "murphy": ["murphy"], "itw": ["itw"],
            "news": [],  # SQLite fetcher (T2.x): no longer writes news.json
            "osv": ["osv-npm", "osv-pypi"],
            "nuclei": ["nuclei"], "hn": ["hn"], "masto": ["masto"],
            # Enrichment-style caches (no per-item first_seen tracking needed)
            "heat": [], "epss": [],
        }
        snapshot_only: set[str] = set()
        for fetched in selected:
            snapshot_only.update(FETCHER_TO_CACHES.get(fetched, []))
        try:
            summary = snapshot_today(only=snapshot_only or None)
            total_new = sum(v.get("new_today", 0) for v in summary.values())
            print(f"[snap] {len(summary)} caches, {total_new} new items today", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            print(f"[snap] failed: {exc}", file=sys.stderr)

    failed = sum(1 for r in manifest["results"] if not r.get("ok"))
    return 0 if failed == 0 else 1


async def run_fetchers(
    names: list[str] | None = None,
    concurrency: int | None = None,
    *,
    snapshot: bool = True,
    incremental: bool = False,
) -> dict:
    selected = list(names) if names is not None else list(FETCHERS)
    unknown = [name for name in selected if name not in FETCHERS]
    if unknown:
        raise ValueError(f"unknown fetcher(s): {unknown}; available: {list(FETCHERS)}")
    code = await run(selected, concurrency or 8, snapshot=snapshot, incremental=incremental)
    manifest_path = CACHE / "manifest.json"
    manifest = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            manifest = {}
    return {
        "ok": code == 0,
        "returncode": code,
        "selected": selected,
        "manifest": manifest,
    }


def main() -> int:
    p = argparse.ArgumentParser(description="Fetch security data into local JSON cache.")
    p.add_argument("--only", help="comma-separated subset of fetchers (default: all)")
    p.add_argument("--concurrency", type=int, default=8, help="news-feed concurrency (default 8)")
    p.add_argument("--no-snapshot", action="store_true", help="skip history snapshot + first_seen annotation")
    p.add_argument("--incremental", action="store_true", help="merge new articles into existing cache instead of replacing")
    p.add_argument("--list", action="store_true", help="list available fetchers and exit")
    args = p.parse_args()

    if args.list:
        for name in FETCHERS:
            print(name)
        return 0

    if args.only:
        selected = [s.strip() for s in args.only.split(",") if s.strip()]
        unknown = [s for s in selected if s not in FETCHERS]
        if unknown:
            sys.exit(f"unknown fetcher(s): {unknown}; available: {list(FETCHERS)}")
    else:
        selected = list(FETCHERS)
    return asyncio.run(run(selected, args.concurrency, snapshot=not args.no_snapshot, incremental=args.incremental))


if __name__ == "__main__":
    raise SystemExit(main())
