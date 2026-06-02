"""Side-channel enrichment sources.

EPSS daily scores, Hacker News security stories, and Mastodon hashtag
timelines. These are not rendered as standalone list cards; data.py joins
them onto vuln cards by CVE-ID. Also owns the post-fetch EPSS trim step that
discards scores for CVEs not referenced by any other source.
"""
from __future__ import annotations

import asyncio
import csv
import gzip
import io
import json
import re
from pathlib import Path

import httpx

from .. import _util
from .._util import HEADERS, now_iso, strip_html, write_json
from .murphy import _murphy_first_cve


async def fetch_epss(client: httpx.AsyncClient) -> dict:
    """Pull FIRST.org EPSS daily scores. CSV format:
        #model_version:..., score_date:YYYY-MM-DDTHH:MM:SS+TZ
        cve,epss,percentile
        CVE-XXXX-XXXX,0.00123,0.50012
    """
    url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    r = await client.get(url, headers=HEADERS, timeout=60)
    r.raise_for_status()
    raw_bytes = gzip.decompress(r.content)
    text = raw_bytes.decode("utf-8", errors="replace")

    score_date = None
    model_version = None
    items: dict[str, dict] = {}

    reader = csv.reader(io.StringIO(text))
    header_seen = False
    for row in reader:
        if not row:
            continue
        first = row[0]
        if first.startswith("#"):
            # metadata line; may contain multiple `key:value` separated by commas
            cells = [first.lstrip("#")] + list(row[1:])
            for cell in cells:
                cell = cell.strip()
                if cell.startswith("score_date:"):
                    score_date = cell.split(":", 1)[1].strip()
                elif cell.startswith("model_version:"):
                    model_version = cell.split(":", 1)[1].strip()
            continue
        if not header_seen and first.lower() == "cve":
            header_seen = True
            continue
        if not header_seen or len(row) < 3:
            continue
        cve = row[0].strip().upper()
        if not cve.startswith("CVE-"):
            continue
        try:
            items[cve] = {
                "score": float(row[1]),
                "percentile": float(row[2]),
            }
        except ValueError:
            continue

    out = {
        "score_date": score_date,
        "model_version": model_version,
        "items": items,
        "count": len(items),
        "fetched_at": now_iso(),
    }
    write_json("epss.json", out)
    return {"name": "epss", "count": len(items)}


def trim_epss_to_referenced(*, cache_dir: Path | None = None) -> int:
    """Post-fetch step: discard EPSS entries for CVEs not referenced by any vuln source or news.

    Reads KEV/GHSA/PoCs for CVE-IDs, plus news.db for CVE-mentioning article titles.
    Rewrites epss.json in place with only the intersection.
    Returns the number of retained entries.
    """
    d = cache_dir or _util.CACHE
    epss_path = d / "epss.json"
    if not epss_path.exists():
        return 0

    referenced: set[str] = set()

    for filename, key_path in [
        ("kev.json", "cveID"),
        ("ghsa.json", "cve_id"),
        ("pocs.json", "cve_id"),
        ("murphy.json", None),
    ]:
        p = d / filename
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            for item in data.get("items", []):
                if key_path:
                    cve = item.get(key_path)
                    if cve:
                        referenced.add(cve.upper())
                else:
                    cve = _murphy_first_cve(item)
                    if cve:
                        referenced.add(cve.upper())
        except (json.JSONDecodeError, OSError):
            pass

    news_db = d / "news.db"
    if news_db.exists():
        try:
            import sqlite3
            conn = sqlite3.connect(str(news_db))
            cve_re = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
            for (title,) in conn.execute("SELECT title FROM articles WHERE title LIKE '%CVE-%'"):
                for m in cve_re.findall(title or ""):
                    referenced.add(m.upper())
            conn.close()
        except Exception:
            pass

    epss = json.loads(epss_path.read_text(encoding="utf-8"))
    old_items = epss.get("items", {})
    new_items = {k: v for k, v in old_items.items() if k.upper() in referenced}
    epss["items"] = new_items
    epss["count"] = len(new_items)
    epss["trimmed_from"] = len(old_items)
    epss_path.write_text(json.dumps(epss, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(new_items)


_HN_QUERIES = ["vulnerability", "zero-day", "remote code execution", "exploit", "patch tuesday"]
# Word-bounded CVE matcher: avoid swallowing trailing digits or being prefixed
# by another digit/letter (e.g. "XCVE-2024-..." or "...-12345678" should not match).
_CVE_TITLE_RE = re.compile(r"(?<![A-Z0-9])CVE-\d{4}-\d{4,7}(?!\d)", re.IGNORECASE)


async def _hn_search_one(client: httpx.AsyncClient, query: str) -> tuple[str, list[dict], str | None]:
    base = "https://hn.algolia.com/api/v1/search_by_date"
    params = {
        "query": query,
        "tags": "story",
        "restrictSearchableAttributes": "title",
        "hitsPerPage": 50,
    }
    try:
        r = await client.get(base, params=params, headers=HEADERS, timeout=20)
        r.raise_for_status()
        return query, r.json().get("hits", []) or [], None
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        return query, [], f"{type(exc).__name__}: {exc}"[:160]


async def fetch_hn(client: httpx.AsyncClient) -> dict:
    """Pull recent Hacker News stories matching security queries.

    Uses Algolia's title-only search across several focused queries in parallel.
    Output includes CVE mentions extracted from titles for cross-reference.
    """
    results = await asyncio.gather(*[_hn_search_one(client, q) for q in _HN_QUERIES])

    seen: set[str] = set()
    items: list[dict] = []
    errors: dict[str, str] = {}
    for query, hits, err in results:
        if err:
            errors[query] = err
            continue
        for hit in hits:
            sid = hit.get("objectID")
            if not sid or sid in seen:
                continue
            seen.add(sid)
            title = (hit.get("title") or "").strip()
            mentions = sorted({m.upper() for m in _CVE_TITLE_RE.findall(title)})
            items.append({
                "id": sid,
                "title": title,
                "url": hit.get("url") or f"https://news.ycombinator.com/item?id={sid}",
                "hn_url": f"https://news.ycombinator.com/item?id={sid}",
                "author": hit.get("author"),
                "points": int(hit.get("points") or 0),
                "num_comments": int(hit.get("num_comments") or 0),
                "created_at": hit.get("created_at", ""),
                "matched_query": query,
                "cve_mentions": mentions,
            })
    items.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    items = items[:300]
    if errors and not items:
        # all queries failed — let outer run() mark fetcher errored
        raise RuntimeError(f"all HN queries failed: {errors}")
    out = {
        "items": items,
        "queries": _HN_QUERIES,
        "errors": errors,
        "count": len(items),
        "fetched_at": now_iso(),
    }
    write_json("hn.json", out)
    return {"name": "hn", "count": len(items), "partial_errors": len(errors)}


# Mastodon instances + hashtag list. infosec.exchange now requires auth for
# public timeline endpoints, so we fan out across two large public instances
# and dedupe federated copies by status `uri` (canonical URL).
_MASTO_INSTANCES = ["mastodon.social", "hachyderm.io"]
_MASTO_TAGS = ["cve", "infosec", "cybersecurity", "vulnerability", "0day", "ransomware"]


async def _masto_one_tag(
    client: httpx.AsyncClient, instance: str, tag: str
) -> tuple[str, str, list[dict], str | None]:
    url = f"https://{instance}/api/v1/timelines/tag/{tag}"
    params = {"limit": 40, "local": "false"}
    try:
        r = await client.get(url, params=params, headers=HEADERS, timeout=25)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, list):
            return instance, tag, [], f"non-list response: {str(data)[:120]}"
        return instance, tag, data, None
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        return instance, tag, [], f"{type(exc).__name__}: {exc}"[:160]


async def fetch_masto(client: httpx.AsyncClient) -> dict:
    """Public-timeline hashtag posts fanned out across multiple Mastodon instances.

    Federated copies of the same status are deduped by `uri` (canonical URL).
    Engagement (favourites + reblogs + replies) is captured per status so a
    later heat aggregator can use real social signal instead of a synthetic score.
    """
    jobs = [(inst, tag) for inst in _MASTO_INSTANCES for tag in _MASTO_TAGS]
    results = await asyncio.gather(*[_masto_one_tag(client, i, t) for (i, t) in jobs])

    seen: set[str] = set()
    items: list[dict] = []
    errors: dict[str, str] = {}
    for instance, tag, statuses, err in results:
        if err:
            errors[f"{instance}#{tag}"] = err
            continue
        for s in statuses:
            uri = s.get("uri") or s.get("url") or f"{instance}:{s.get('id', '')}"
            if uri in seen:
                continue
            seen.add(uri)
            content_text = strip_html(s.get("content") or "")
            mentions = sorted({m.upper() for m in _CVE_TITLE_RE.findall(content_text)})
            account = s.get("account") or {}
            items.append({
                "id": s.get("id"),
                "uri": uri,
                "url": s.get("url") or uri,
                "created_at": s.get("created_at", ""),
                "content": content_text[:600],
                "account": account.get("acct") or account.get("username", ""),
                "display_name": account.get("display_name", ""),
                "favourites": int(s.get("favourites_count") or 0),
                "reblogs": int(s.get("reblogs_count") or 0),
                "replies": int(s.get("replies_count") or 0),
                "tags": [t.get("name", "") for t in (s.get("tags") or []) if isinstance(t, dict)][:10],
                "matched_tag": tag,
                "source_instance": instance,
                "cve_mentions": mentions,
            })
    items.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    items = items[:600]
    if errors and not items:
        raise RuntimeError(f"all Mastodon fan-out failed: {errors}")
    out = {
        "instances": _MASTO_INSTANCES,
        "tags": _MASTO_TAGS,
        "items": items,
        "errors": errors,
        "count": len(items),
        "fetched_at": now_iso(),
    }
    write_json("masto.json", out)
    return {"name": "masto", "count": len(items), "partial_errors": len(errors)}
