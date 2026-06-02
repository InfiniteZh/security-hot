"""Vulnerability sources that write JSON caches.

CISA KEV, GitHub Security Advisories, nomi-sec PoC mirror, inthewild.io feed,
cvecrowd heat snapshot, OSV.dev ecosystem dumps, and nuclei-templates CVE
coverage. Each fetcher normalizes its source and writes a cache file under
backend/cache/.
"""
from __future__ import annotations

import io
import json
import re
import zipfile

import feedparser
import httpx

from .._util import HEADERS, clean_summary, now_iso, write_json, _iso_from_feedparser


async def fetch_kev(client: httpx.AsyncClient) -> dict:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    r = await client.get(url, timeout=30)
    r.raise_for_status()
    data = r.json()
    vulns = data.get("vulnerabilities", [])
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    items = vulns[:200]
    out = {
        "title": data.get("title", "CISA KEV"),
        "version": data.get("catalogVersion"),
        "date_released": data.get("dateReleased"),
        "count_total": len(vulns),
        "items": items,
        "fetched_at": now_iso(),
    }
    write_json("kev.json", out)
    return {"name": "kev", "count": len(items)}


async def fetch_ghsa(client: httpx.AsyncClient) -> dict:
    url = "https://api.github.com/advisories"
    params = {"per_page": 100, "sort": "updated", "direction": "desc"}
    headers = {**HEADERS, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    r = await client.get(url, params=params, headers=headers, timeout=30)
    r.raise_for_status()
    items = r.json()
    out = {"items": items, "count": len(items), "fetched_at": now_iso()}
    write_json("ghsa.json", out)
    return {"name": "ghsa", "count": len(items)}


async def fetch_pocs(client: httpx.AsyncClient) -> dict:
    # motikan2010 mirror exposes a clean JSON API
    url = "https://poc-in-github.motikan2010.net/api/v1/"
    params = {"sort": "-created_at", "count": 100}
    r = await client.get(url, params=params, headers=HEADERS, timeout=30)
    r.raise_for_status()
    data = r.json()
    pocs = data.get("pocs", [])
    out = {"items": pocs, "count": len(pocs), "fetched_at": now_iso()}
    write_json("pocs.json", out)
    return {"name": "pocs", "count": len(pocs)}


async def fetch_itw(client: httpx.AsyncClient) -> dict:
    url = "https://inthewild.io/feed"
    r = await client.get(url, headers=HEADERS, timeout=30)
    r.raise_for_status()
    parsed = feedparser.parse(r.content)
    items = []
    for entry in parsed.entries[:80]:
        items.append({
            "id": entry.get("id") or entry.get("link") or "",
            "title": entry.get("title", "").strip(),
            "link": entry.get("link", ""),
            "published": _iso_from_feedparser(entry),
            "summary": clean_summary(entry.get("summary", "")),
        })
    diagnostic = None
    if not items:
        diagnostic = {
            "endpoint": url,
            "http_status": r.status_code,
            "response_size": len(r.content),
            "bozo": parsed.bozo,
            "bozo_exception": str(parsed.bozo_exception) if parsed.bozo else None,
            "hint": "HTTP 200 but feed contains zero entries; upstream may be silent today or the feed schema changed",
        }
    out = {"items": items, "count": len(items), "fetched_at": now_iso(), "diagnostic": diagnostic}
    write_json("itw.json", out)
    return {"name": "itw", "count": len(items), "diagnostic": diagnostic}


async def fetch_heat(client: httpx.AsyncClient) -> dict:
    candidates = [
        "https://cvecrowd.com/api/cves",
        "https://cvecrowd.com/api/cves?period=24h",
    ]
    items = []
    used = None
    attempts: list[dict] = []
    for url in candidates:
        try:
            r = await client.get(url, headers={**HEADERS, "Accept": "application/json"}, timeout=20)
            attempts.append({
                "url": url,
                "http_status": r.status_code,
                "content_type": r.headers.get("content-type", ""),
                "response_size": len(r.content),
            })
            if r.status_code == 200 and "json" in r.headers.get("content-type", "").lower():
                data = r.json()
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    items = data.get("cves") or data.get("items") or data.get("data") or []
                used = url
                break
        except Exception as exc:
            attempts.append({"url": url, "error": f"{type(exc).__name__}: {exc}"[:160]})
            continue
    diagnostic = None
    if not items:
        diagnostic = {
            "attempts": attempts,
            "hint": "no candidate endpoint returned discussion-heat JSON; cvecrowd may have changed schema or paywalled the API",
        }
    out = {
        "items": items[:100],
        "source_url": used,
        "diagnostic": diagnostic,
        "fetched_at": now_iso(),
    }
    write_json("heat.json", out)
    return {"name": "heat", "count": len(out["items"]), "diagnostic": diagnostic}


def _osv_ecosystem_url(eco: str) -> str:
    return f"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"


def _normalize_osv_entry(raw: dict) -> dict:
    pkg_names: list[str] = []
    # Parallel array of version lists per package, so the consumer can
    # render `pkg@1.2.3` even when one OSV record covers multiple packages.
    pkg_versions: list[list[str]] = []
    for a in raw.get("affected") or []:
        pkg = (a.get("package") or {})
        name = pkg.get("name")
        if not name or name in pkg_names:
            continue
        pkg_names.append(name)
        versions = a.get("versions") or []
        pkg_versions.append([v for v in versions[:10] if isinstance(v, str)])
    refs: list[dict] = []
    for r in (raw.get("references") or [])[:6]:
        if isinstance(r, dict) and r.get("url"):
            refs.append({"url": r["url"], "type": r.get("type", "")})
    db_specific = raw.get("database_specific") or {}
    osv_id = raw.get("id", "")
    cves = [a for a in (raw.get("aliases") or []) if isinstance(a, str) and a.upper().startswith("CVE-")]
    # `details` often contains campaign attribution (e.g. "Mini Shai-Hulud is
    # back worm by the TeamPCP threat actor"). Strip OSV's boilerplate header
    # and the per-source `## Source: name (hash)` separators so only the
    # narrative remains.
    details = (raw.get("details") or "").strip()
    if details:
        if "Per source details" in details:
            details = details.split("Per source details. Do not edit below this line.", 1)[-1]
        # Strip OSV's "## Source: provider (hash)" headers and the surrounding
        # `_-=` / `=-_` decorative markers so only the narrative remains.
        details = re.sub(r"## Source: \S+ \([a-f0-9]+\)\s*", " ", details)
        # OSV uses `_-=` and `=-_` as decorative section markers around the
        # "Per source details" header; strip both forms outright.
        details = re.sub(r"_-=|=-_", " ", details)
        details = re.sub(r"-{3,}", " ", details)
        details = " ".join(details.split()).lstrip("_ ").strip()[:600]
    return {
        "id": osv_id,
        "aliases": raw.get("aliases", []),
        "cve_ids": cves,
        "summary": (raw.get("summary") or "").strip()[:400],
        "details": details,
        "packages": pkg_names[:5],
        "versions": pkg_versions[:5],
        "published": raw.get("published", ""),
        "modified": raw.get("modified", ""),
        "severity_raw": db_specific.get("severity"),
        "is_malware": osv_id.upper().startswith("MAL-") or db_specific.get("type", "").lower() == "malware",
        "references": refs,
    }


async def _fetch_one_osv_ecosystem(client: httpx.AsyncClient, ecosystem: str) -> int:
    url = _osv_ecosystem_url(ecosystem)
    r = await client.get(url, headers=HEADERS, timeout=180)
    r.raise_for_status()
    items: list[dict] = []
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                raw = json.loads(zf.read(name))
            except (json.JSONDecodeError, OSError):
                continue
            entry = _normalize_osv_entry(raw)
            if entry.get("is_malware"):
                items.append(entry)
    items.sort(key=lambda x: x.get("modified", ""), reverse=True)
    items = items[:500]
    out = {
        "ecosystem": ecosystem,
        "items": items,
        "count": len(items),
        "fetched_at": now_iso(),
    }
    write_json(f"osv-{ecosystem.lower()}.json", out)
    return len(items)


async def fetch_osv(client: httpx.AsyncClient) -> dict:
    """Pull OSV.dev full ecosystem dumps for npm and PyPI."""
    by_eco = {}
    for ecosystem in ("npm", "PyPI"):
        by_eco[ecosystem] = await _fetch_one_osv_ecosystem(client, ecosystem)
    return {"name": "osv", "count": sum(by_eco.values()), "by_ecosystem": by_eco}


_NUCLEI_CVE_RE = re.compile(r"(?<![A-Z0-9])(CVE-\d{4}-\d{4,7})(?!\d)", re.IGNORECASE)
_NUCLEI_REPO_BLOB = "https://github.com/projectdiscovery/nuclei-templates/blob/main/"


async def fetch_nuclei(client: httpx.AsyncClient) -> dict:
    """List all CVE-targeting templates in projectdiscovery/nuclei-templates.

    Uses GitHub Trees API (recursive=1) for a single request listing.
    Output: {cve_id: {"paths": [...], "primary": "...", "url": "..."}}
    """
    url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"
    headers = {**HEADERS, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    r = await client.get(url, headers=headers, timeout=60)
    r.raise_for_status()
    data = r.json()
    truncated = bool(data.get("truncated"))
    grouped: dict[str, list[str]] = {}
    for entry in data.get("tree", []):
        path = entry.get("path") or ""
        if not (path.endswith(".yaml") or path.endswith(".yml")):
            continue
        m = _NUCLEI_CVE_RE.search(path)
        if not m:
            continue
        cve = m.group(1).upper()
        grouped.setdefault(cve, []).append(path)

    # Priority by template category — http/cves is most actionable (live probe),
    # then code (static analysis), dns / ssl / network, finally cloud / kubernetes.
    priority_order = ("http/", "code/", "javascript/", "dns/", "ssl/", "network/",
                       "tcp/", "headless/", "file/", "cloud/", "kubernetes/")

    def _path_priority(p: str) -> tuple[int, str]:
        for i, prefix in enumerate(priority_order):
            if p.startswith(prefix):
                return (i, p)
        return (len(priority_order), p)

    items = {}
    for cve, paths in grouped.items():
        paths.sort(key=_path_priority)
        primary = paths[0]
        items[cve] = {
            "paths": paths,
            "primary": primary,
            "url": _NUCLEI_REPO_BLOB + primary,
        }
    out = {
        "items": items,
        "truncated": truncated,
        "tree_size": len(data.get("tree", [])),
        "count": len(items),
        "fetched_at": now_iso(),
    }
    write_json("nuclei.json", out)
    return {"name": "nuclei", "count": len(items)}
