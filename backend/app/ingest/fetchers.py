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
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import gzip
import hashlib
import io
import json
import os
import re
import sys
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse
from xml.etree import ElementTree as ET

import aiohttp
import feedparser
import httpx

from . import db as _db

ROOT = Path(__file__).resolve().parents[3]
CACHE = ROOT / "backend" / "cache"
CACHE.mkdir(parents=True, exist_ok=True)
ARCHIVE_DIR = ROOT / "backend" / "archive" / "news"

USER_AGENT = (
    "Mozilla/5.0 (compatible; security-hot/1.0; +https://github.com/) "
    "feedparser/python-httpx"
)
HEADERS = {"User-Agent": USER_AGENT}


# ─── curated RSS sources ───
NEWS_SOURCES: list[dict] = [
    # Chinese
    {"slug": "freebuf", "title": "FreeBuf", "url": "https://www.freebuf.com/feed", "lang": "zh"},
    {"slug": "anquanke", "title": "安全客", "url": "https://api.anquanke.com/data/v1/rss", "lang": "zh"},
    {"slug": "4hou", "title": "嘶吼", "url": "https://www.4hou.com/feed", "lang": "zh"},
    {"slug": "secwiki", "title": "SecWiki News", "url": "https://www.sec-wiki.com/news/rss", "lang": "zh"},
    {"slug": "vipread", "title": "信息安全知识库", "url": "https://vipread.com/feed", "lang": "zh"},
    {"slug": "xuanwu", "title": "腾讯玄武实验室", "url": "https://xlab.tencent.com/cn/atom.xml", "lang": "zh"},
    {"slug": "keenlab", "title": "腾讯科恩实验室", "url": "https://keenlab.tencent.com/zh/atom.xml", "lang": "zh"},
    {"slug": "seebug", "title": "Seebug Paper", "url": "https://paper.seebug.org/rss", "lang": "zh"},
    {"slug": "netlab360", "title": "360 Netlab", "url": "https://blog.netlab.360.com/rss", "lang": "zh"},
    {"slug": "meituan", "title": "美团技术团队", "url": "https://tech.meituan.com/feed", "lang": "zh"},
    # English
    {"slug": "thn", "title": "The Hacker News", "url": "https://thehackernews.com/feeds/posts/default", "lang": "en"},
    {"slug": "bleeping", "title": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "lang": "en"},
    {"slug": "krebs", "title": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "lang": "en"},
    {"slug": "schneier", "title": "Schneier on Security", "url": "https://www.schneier.com/feed/atom/", "lang": "en"},
    {"slug": "talos", "title": "Talos Intelligence", "url": "https://blog.talosintelligence.com/feeds/posts/default", "lang": "en"},
    {"slug": "unit42", "title": "Palo Alto Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "lang": "en"},
    {"slug": "msrc", "title": "Microsoft MSRC", "url": "https://msrc.microsoft.com/blog/feed/", "lang": "en"},
    {"slug": "datadog", "title": "Datadog Security Labs", "url": "https://securitylabs.datadoghq.com/rss/feed.xml", "lang": "en"},
    {"slug": "googlep0", "title": "Project Zero", "url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "lang": "en"},
    {"slug": "mandiant", "title": "Mandiant", "url": "https://www.mandiant.com/resources/blog/rss.xml", "lang": "en"},
    {"slug": "checkmarx", "title": "Checkmarx", "url": "https://checkmarx.com/blog/feed/", "lang": "en"},
    # Supply-chain-focused blogs — most useful early-warning signal for npm/PyPI/Go/Rust
    # poisoning. `category: "supply-intel"` lets the frontend pull them into the
    # supply-chain view independently of language filters.
    # Socket: their /blog/rss.xml is Cloudflare-gated, but /api/blog/feed.atom serves
    # cleanly without the bot challenge.
    {"slug": "socket", "title": "Socket", "url": "https://socket.dev/api/blog/feed.atom", "lang": "en", "category": "supply-intel"},
    {"slug": "safedep", "title": "SafeDep", "url": "https://safedep.io/rss.xml", "lang": "en", "category": "supply-intel"},
    {"slug": "aikido", "title": "Aikido", "url": "https://www.aikido.dev/blog/rss.xml", "lang": "en", "category": "supply-intel"},
    {"slug": "stepsec", "title": "StepSecurity", "url": "https://www.stepsecurity.io/blog/rss.xml", "lang": "en", "category": "supply-intel"},
    {"slug": "endor", "title": "Endor Labs", "url": "https://www.endorlabs.com/blog/rss.xml", "lang": "en", "category": "supply-intel"},
]


# Hosts that almost certainly serve Chinese content. Anything matching here
# (substring) is tagged lang=zh regardless of OPML metadata.
_ZH_HOST_HINTS = (
    "freebuf.com", "anquanke.com", "4hou.com", "secrss.com", "sec-wiki",
    "secwiki", "seebug.org", "vipread.com", "360.cn", "tencent.com",
    "alibaba.com", "weibo.com", "qq.com", "ke.qq", "huawei.com",
    "uedbox.com", "secquan.org", "secepo.com", "feishu", "csdn.net",
    "sec-in.com", "sec-news.com", "zhihu.com", "jianshu.com",
    "xianzhi.aliyun", "bilibili.com", "cnblogs.com",
    ".com.cn", ".org.cn", ".cn/",
)


def _slug_from_url(url: str) -> str:
    """Derive a stable slug from a feed URL — host segment with non-alnum
    collapsed to '_'. Used for de-duplication and as a stable id across
    runs even when the OPML title changes."""
    try:
        host = re.sub(r"^https?://", "", url).split("/")[0].lower()
        host = re.sub(r"^www\.", "", host)
        slug = re.sub(r"[^a-z0-9]+", "_", host).strip("_")
        return slug[:48] or "unknown"
    except Exception:
        return "unknown"


def _detect_lang(title: str, url: str, category_label: str) -> str:
    """Heuristic: any CJK char in title, or known-CN host, or 公众号 category
    ⇒ zh. Otherwise en. Mis-tagged Italian / French feeds default to en,
    which is fine for the news lang toggle."""
    if any("一" <= ch <= "鿿" for ch in (title or "")):
        return "zh"
    lower_url = (url or "").lower()
    if any(hint in lower_url for hint in _ZH_HOST_HINTS):
        return "zh"
    if "公众号" in (category_label or ""):
        return "zh"
    return "en"


def _load_alive_sources_from_opml(opml_path: Path) -> list[dict]:
    """Parse rss/merged.opml (output of merge_rss.py) into the
    NEWS_SOURCES dict shape. Returns empty list if file missing/invalid
    so the caller can fall back to the curated list.

    Slugs are URL-derived to stay stable across re-merges; falls back to
    feed title when host hashing collides.
    """
    if not opml_path.exists():
        return []
    try:
        tree = ET.parse(opml_path)
    except ET.ParseError:
        return []
    body = tree.getroot().find("body")
    if body is None:
        return []
    sources: list[dict] = []
    seen_slugs: dict[str, int] = {}

    def walk(node: ET.Element, parent_category: str) -> None:
        for child in node:
            if child.tag.split("}")[-1] != "outline":
                continue
            xml_url = (child.attrib.get("xmlUrl") or "").strip()
            title = (child.attrib.get("title") or child.attrib.get("text") or "").strip()
            if not xml_url:
                # Topical category container (e.g. "Pentest", "Companies").
                walk(child, title or parent_category)
                continue
            slug = _slug_from_url(xml_url)
            # Disambiguate when two feeds share a host (rare but happens).
            if slug in seen_slugs:
                seen_slugs[slug] += 1
                slug = f"{slug}_{seen_slugs[slug]}"
            else:
                seen_slugs[slug] = 1
            sources.append({
                "slug": slug,
                "title": title or xml_url,
                "url": xml_url,
                "lang": _detect_lang(title, xml_url, parent_category),
                "category": parent_category or "Uncategorized",
            })

    walk(body, "")
    return sources


def _news_sources_to_use() -> list[dict]:
    """Resolve the news source list at fetch time.

    Strategy:
      1. read rss/merged.opml — that's the full ~695 alive feed catalog
         produced by merge_rss.py
      2. merge the curated NEWS_SOURCES on top (their hand-tuned title,
         lang, and supply-intel category override the OPML defaults)
      3. fall back to NEWS_SOURCES alone if merged.opml doesn't exist

    Curated sources keep their original slug so cross-run continuity
    holds; new OPML sources get URL-derived slugs.
    """
    opml = ROOT / "rss" / "merged.opml"
    bulk = _load_alive_sources_from_opml(opml)
    if not bulk:
        return list(NEWS_SOURCES)
    # Overlay curated entries by URL match.
    curated_by_url = {s["url"]: s for s in NEWS_SOURCES}
    out: list[dict] = []
    consumed_curated_urls: set[str] = set()
    for s in bulk:
        if s["url"] in curated_by_url:
            override = curated_by_url[s["url"]]
            consumed_curated_urls.add(s["url"])
            out.append({**s, **override, "category": override.get("category") or s["category"]})
        else:
            out.append(s)
    # Any curated source not present in OPML (e.g. supply-intel vendors
    # we added by hand and never ran through merge_rss) still gets in.
    for s in NEWS_SOURCES:
        if s["url"] not in consumed_curated_urls:
            out.append(s)
    return out


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(name: str, data) -> Path:
    path = CACHE / name
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def strip_html(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&\w+;", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def clean_summary(text: str, limit: int = 320) -> str:
    text = strip_html(text)
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def _iso_from_feedparser(entry) -> str:
    """Normalize RSS/Atom dates to ISO 8601 UTC.

    feedparser parses every common date format into a `time.struct_time`
    under `published_parsed` (or `updated_parsed` / `created_parsed`).
    Falling back to the raw string risks lexicographic sort breaking when
    sources mix RFC 2822 ("Wed, 26 Nov 2025 …") with ISO ("2026-05-12 …").
    """
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        parsed = entry.get(key)
        if parsed:
            try:
                return time.strftime("%Y-%m-%dT%H:%M:%SZ", parsed)
            except (TypeError, ValueError):
                continue
    # No machine-readable date; return raw string (rare, but keep something).
    return (entry.get("published") or entry.get("updated") or "").strip()


# ─────────── fetchers ───────────

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


MURPHY_URL = "https://www.murphysec.com/platform/v2/vuln_warn/list"
MURPHY_TZ = timezone(timedelta(hours=8))
MURPHY_TIME_KEYS = (
    "last_modify_time", "lastModifyTime", "modify_time", "modified_at",
    "updated_at", "updated", "publish_time", "published_at", "created_at",
)
MURPHY_ID_KEYS = (
    "id", "vuln_id", "vulnId", "vuln_no", "vulnNo", "warning_id",
    "warningId", "mps_id", "mpsId", "ghsa_id", "ghsaId", "cve_id", "cveId",
)
MURPHY_PACKAGE_KEYS = (
    "package_name", "packageName", "package", "pkg_name", "pkgName",
    "component_name", "componentName", "artifact_id", "artifactId",
)
MURPHY_TITLE_KEYS = (
    "title", "vuln_name", "vulnName", "vuln_title", "vulnTitle", "name",
)


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(text, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _murphy_api_time(dt: datetime) -> str:
    return dt.astimezone(MURPHY_TZ).replace(microsecond=0).isoformat()


def _murphy_container(payload: dict) -> object:
    data = payload.get("data")
    if isinstance(data, dict):
        return data
    return payload


def _murphy_items_from_payload(payload: dict) -> list[dict]:
    container = _murphy_container(payload)
    if isinstance(container, list):
        return [x for x in container if isinstance(x, dict)]
    if not isinstance(container, dict):
        return []
    for key in ("list", "items", "records", "rows", "data"):
        value = container.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    return []


def _murphy_total_from_payload(payload: dict) -> int | None:
    container = _murphy_container(payload)
    if not isinstance(container, dict):
        return None
    for key in ("total", "count", "total_count", "totalCount"):
        value = container.get(key)
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _murphy_first_text(item: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _murphy_first_cve(item: dict) -> str:
    for key in ("cve_id", "cveId", "cve", "cve_no", "cveNo"):
        value = item.get(key)
        if value:
            match = re.search(r"CVE-\d{4}-\d{4,7}", str(value), re.IGNORECASE)
            if match:
                return match.group(0).upper()
    for value in item.values():
        if isinstance(value, str):
            match = re.search(r"CVE-\d{4}-\d{4,7}", value, re.IGNORECASE)
            if match:
                return match.group(0).upper()
    return ""


def _murphy_item_key(item: dict) -> str:
    for key in MURPHY_ID_KEYS:
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    cve = _murphy_first_cve(item)
    if cve:
        return cve
    package_name = _murphy_first_text(item, MURPHY_PACKAGE_KEYS).lower()
    title = _murphy_first_text(item, MURPHY_TITLE_KEYS).lower()
    if package_name and title:
        return f"pkg:{package_name}:{title[:120]}"
    if title:
        return f"title:{title[:160]}"
    digest = hashlib.sha1(
        json.dumps(item, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:20]
    return f"raw:{digest}"


def _murphy_item_time(item: dict) -> str:
    for key in MURPHY_TIME_KEYS:
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _load_murphy_cache() -> dict:
    path = CACHE / "murphy.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


async def _fetch_murphy_page(session: aiohttp.ClientSession, body: dict, customer_code: str) -> dict:
    headers = {
        "Content-Type": "application/json",
        "CustomerCode": customer_code,
        "User-Agent": USER_AGENT,
    }
    async with session.post(MURPHY_URL, json=body, headers=headers) as resp:
        text = await resp.text()
        if resp.status >= 400:
            raise RuntimeError(f"MurphySec HTTP {resp.status}: {text[:200]}")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"MurphySec returned non-JSON response: {text[:120]}") from exc
    code = payload.get("code") if isinstance(payload, dict) else None
    if code not in (None, 0, "0", 200, "200"):
        message = payload.get("message") or payload.get("msg") or "unknown API error"
        raise RuntimeError(f"MurphySec API code={code}: {message}")
    return payload


async def fetch_murphy(_client: httpx.AsyncClient) -> dict:
    """Fetch MurphySec vuln_warn entries.

    Always uses `scope=default` with a last_modify_time window. If no prior
    successful fetch exists, it only looks back a small configurable window
    instead of attempting a large backfill.
    """
    customer_code = os.environ.get("MURPHY_CUSTOMER_CODE", "").strip()
    if not customer_code:
        return {
            "name": "murphy",
            "count": 0,
            "diagnostic": {
                "status": "disabled",
                "reason": "MURPHY_CUSTOMER_CODE is not set",
            },
        }

    existing = _load_murphy_cache()
    previous_items = existing.get("items") if isinstance(existing.get("items"), list) else []
    last_success = _parse_iso_datetime(existing.get("last_success_at") or existing.get("fetched_at"))
    now_dt = datetime.now(timezone.utc)
    initial_incremental = last_success is None
    initial_lookback_minutes = int(os.environ.get("MURPHY_INITIAL_LOOKBACK_MINUTES", "240"))
    limit = int(os.environ.get("MURPHY_PAGE_LIMIT", "50"))
    max_pages = int(os.environ.get("MURPHY_MAX_PAGES", "100"))
    malicious_code = os.environ.get("MURPHY_MALICIOUS_CODE", "include")
    scope = "default"
    start_dt = last_success or (now_dt - timedelta(minutes=initial_lookback_minutes))
    start_time = _murphy_api_time(start_dt)
    end_time = _murphy_api_time(now_dt)

    fetched_items: list[dict] = []
    pages = 0
    total: int | None = None
    timeout = aiohttp.ClientTimeout(total=90, connect=15)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for page in range(1, max_pages + 1):
            body = {
                "page": page,
                "limit": limit,
                "scope": scope,
                "malicious_code": malicious_code,
                "time_type": "last_modify_time",
                "order": "last_modify_time_desc",
            }
            body["start_time"] = start_time
            body["end_time"] = end_time
            payload = await _fetch_murphy_page(session, body, customer_code)
            page_items = _murphy_items_from_payload(payload)
            pages = page
            if total is None:
                total = _murphy_total_from_payload(payload)
            for item in page_items:
                key = _murphy_item_key(item)
                fetched_items.append({**item, "_murphy_key": key})
            if not page_items or len(page_items) < limit:
                break
            if total is not None and page * limit >= total:
                break

    merged: dict[str, dict] = {}
    for item in previous_items:
        if not isinstance(item, dict):
            continue
        key = str(item.get("_murphy_key") or _murphy_item_key(item))
        merged[key] = {**item, "_murphy_key": key}
    for item in fetched_items:
        key = str(item.get("_murphy_key") or _murphy_item_key(item))
        previous = merged.get(key, {})
        first_seen = previous.get("first_seen")
        merged[key] = {**previous, **item, "_murphy_key": key}
        if first_seen:
            merged[key]["first_seen"] = first_seen

    cache_max = int(os.environ.get("MURPHY_CACHE_MAX_ITEMS", "1000"))
    items = sorted(merged.values(), key=_murphy_item_time, reverse=True)[:cache_max]
    out = {
        "items": items,
        "count": len(items),
        "fetched_delta": len(fetched_items),
        "mode": "incremental",
        "scope": scope,
        "malicious_code": malicious_code,
        "window": {"start_time": start_time, "end_time": end_time},
        "last_success_at": now_dt.isoformat(),
        "fetched_at": now_dt.isoformat(),
        "diagnostic": {
            "pages": pages,
            "total": total,
            "previous_count": len(previous_items),
            "initial_incremental": initial_incremental,
            "initial_lookback_minutes": initial_lookback_minutes if initial_incremental else None,
            "max_pages": max_pages,
            "truncated": pages >= max_pages and total is not None and pages * limit < total,
        },
    }
    write_json("murphy.json", out)
    return {
        "name": "murphy",
        "count": len(items),
        "fetched_delta": len(fetched_items),
        "mode": out["mode"],
        "scope": scope,
        "diagnostic": out["diagnostic"],
    }


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


async def fetch_one_feed(client: httpx.AsyncClient, source: dict, max_entries: int = 8) -> dict | None:
    try:
        r = await client.get(source["url"], headers=HEADERS, timeout=20)
        if r.status_code != 200:
            return {**source, "ok": False, "error": f"HTTP {r.status_code}", "entries": []}
        parsed = feedparser.parse(r.content)
        if not parsed.entries:
            return {**source, "ok": False, "error": "no entries", "entries": []}
        entries = []
        for e in parsed.entries[:max_entries]:
            entries.append({
                "id": e.get("id") or e.get("link") or "",
                "title": (e.get("title") or "").strip(),
                "link": e.get("link", ""),
                "published": _iso_from_feedparser(e),
                "summary": clean_summary(e.get("summary", "")),
            })
        return {**source, "ok": True, "entries": entries}
    except Exception as exc:
        return {**source, "ok": False, "error": f"{type(exc).__name__}: {exc}"[:200], "entries": []}


# ────────── Layer 1: URL + title dedupe ──────────
# Prefix-based instead of a named whitelist: tracking params multiply faster
# than we can enumerate. Anything starting with these prefixes (case-insensitive)
# is dropped from the canonical URL. Covers utm_*, ref/ref_*, scene/scene_*,
# spm (taobao/aliyun), mpshare/chksm/srcid (wechat), igshid (instagram),
# mc_eid/mkt_tok (mailchimp / marketo), s_cid/cmpid (mainstream news), etc.
_TRACKING_PREFIXES = (
    "utm_", "utm", "ref", "ref_", "from_", "_from", "from",
    "source", "spm", "scene", "share", "sharer", "shareid",
    "mpshare", "chksm", "srcid", "wt_mc", "wt_zmc",
    "mc_eid", "mc_cid", "mkt_tok",
    "s_cid", "cmpid", "cmp",
    "fbclid", "gclid", "igshid", "__twitter_impression",
)


def _is_tracking_param(key: str) -> bool:
    k = (key or "").lower()
    for prefix in _TRACKING_PREFIXES:
        if k == prefix or k.startswith(prefix):
            return True
    return False


def _canonical_url(url: str) -> str:
    """Strip tracking params and normalize host/path so the same article
    on two aggregators (or shared with different `?utm_*` tails) is one
    URL key for dedupe.

    Security: rejects any URL whose scheme is not http(s). RSS publishers
    can inject `javascript:` or `data:` URIs in <link> tags; if those reach
    the frontend they become stored XSS via clickable href attributes.
    """
    if not url:
        return ""
    try:
        p = urlparse(url.strip())
    except Exception:
        return ""
    if p.scheme.lower() not in ("http", "https"):
        return ""
    if not p.netloc:
        return ""
    qs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=False)
          if not _is_tracking_param(k)]
    query = urlencode(qs)
    path = p.path.rstrip("/") or "/"
    host = p.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return f"{p.scheme.lower()}://{host}{path}" + (f"?{query}" if query else "")


# ────────── Layer 2: keyword blocklist ──────────
# Default blocklist covers recruitment, promo / lottery, conference solicitation,
# personal housekeeping posts. Override via NEWS_BLOCK_KEYWORDS env (comma list)
# if you want stricter / looser filtering without redeploying.
_DEFAULT_BLOCK_KEYWORDS = [
    # ─── Recruitment ────────────────────────────────────────────
    "招聘", "招人", "招募", "诚聘", "实习生招", "校招", "社招",
    "求职", "投简历", "招贤纳士", "内推",
    "we're hiring", "we are hiring",

    # ─── Promotion / giveaway / sales ───────────────────────────
    "限免", "限时免费", "优惠码", "抽奖", "免费领取",
    "福利来了", "限时优惠", "购买链接",
    "加群", "加微信", "扫码加", "知识星球",

    # ─── Conference solicitation ────────────────────────────────
    # Use specific compound phrases (not bare 议程/报名) to avoid killing
    # BlackHat/DEFCON/USENIX agenda announcements which carry research signal.
    "议程公布", "嘉宾揭晓", "报名截止", "报名开启", "开启报名",
    "限时报名", "招商赞助", "赞助合作",

    # ─── Periodic digests (no information density) ──────────────
    # All catch retrospective compilations like "CNVD漏洞周报" / "Weekly Update".
    # We don't kill `年度` alone (kills "2025 年度十大漏洞盘点"), only compound.
    "周报", "月报", "全球网络安全日报",
    "Weekly Update", "Weekly Briefing", "Newsletter", "Digest",
    "年终总结", "年度总结", "年度盘点", "年度大事记",
    "年度荣耀", "年度颁奖",

    # ─── Personal / housekeeping ────────────────────────────────
    "新年快乐", "中秋快乐", "国庆快乐", "感谢支持",
    "公众号回顾", "年终总结征集",
    "随笔", "深夜随笔", "年中随笔", "心得体会",
    "我们的故事", "团队介绍", "加入我们",
    "产品发布会",  # marketing event vs. genuine product launch story

    # ─── Audio-only content (RSS gives us titles but not transcripts) ─
    "Podcast:", "播客:", "播客：",
]


def _articles_keyword_filter(articles: list[dict]) -> tuple[list[dict], list[dict]]:
    raw_extra = os.environ.get("NEWS_BLOCK_KEYWORDS") or ""
    extras = [k.strip() for k in raw_extra.split(",") if k.strip()]
    keywords = _DEFAULT_BLOCK_KEYWORDS + extras
    if not keywords:
        return articles, []
    # ASCII keywords get \b word boundaries to avoid substring traps like
    # "Digest" matching "Digestion". CJK keywords have no real word-boundary
    # concept in regex; just leave them as substring matches (which is what
    # we want anyway — Chinese text has no inter-word space).
    parts: list[str] = []
    for kw in keywords:
        if re.search(r"[一-鿿]", kw):  # CJK present → substring match
            parts.append(re.escape(kw))
        else:                                 # ASCII → word-bounded match
            parts.append(rf"\b{re.escape(kw)}\b")
    pattern = re.compile("|".join(parts), re.IGNORECASE)
    kept: list[dict] = []
    dropped: list[dict] = []
    for a in articles:
        blob = f"{a.get('title','')} {a.get('summary','')}"
        m = pattern.search(blob)
        if m:
            dropped.append({**a, "drop_reason": f"keyword:{m.group(0)}"})
        else:
            kept.append(a)
    return kept, dropped


def _entry_published_iso(entry) -> str | None:
    """Normalize feedparser entry published time to ISO 8601 UTC string."""
    from time import struct_time
    pt = entry.get("published_parsed") or entry.get("updated_parsed")
    if not pt or not isinstance(pt, struct_time):
        return None
    try:
        return datetime(*pt[:6], tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError):
        return None


def _make_canonical(link: str) -> str:
    """Apply the existing URL canonicalization to a single link."""
    return _canonical_url(link)


async def _fetch_one_source_to_sqlite(
    client: httpx.AsyncClient,
    src: dict,
    conn,
    now_iso: str,
) -> tuple[int, int]:
    """Fetch one RSS source with Conditional GET; upsert into SQLite.

    Returns (n_inserted, status_code). status_code=304 means not modified.
    """
    headers: dict[str, str] = {}
    if src.get("last_etag"):
        headers["If-None-Match"] = src["last_etag"]
    if src.get("last_modified"):
        headers["If-Modified-Since"] = src["last_modified"]
    try:
        r = await client.get(src["url"], headers=headers)
    except Exception as exc:
        _db.record_source_fetch(conn, src["slug"], now=now_iso,
                                etag=None, last_modified=None,
                                ok=False, error=str(exc)[:200])
        return (0, 0)
    if r.status_code == 304:
        _db.record_source_fetch(conn, src["slug"], now=now_iso,
                                etag=src.get("last_etag"),
                                last_modified=src.get("last_modified"),
                                ok=True)
        print(f"[news] {src['slug']:>20}: 304 not-modified", file=sys.stderr)
        return (0, 304)
    if r.status_code >= 400:
        _db.record_source_fetch(conn, src["slug"], now=now_iso,
                                etag=None, last_modified=None,
                                ok=False, error=f"HTTP {r.status_code}")
        return (0, r.status_code)

    parsed = feedparser.parse(r.content)
    first_seen_date = now_iso[:10]

    # Filter by publish time window, not per-source count cap.
    # Window comes from NEWS_DAYS_BACK env (default 30).
    # Articles with malformed publish dates (year < 2020 or > now+7d) are
    # dropped as RSS metadata garbage.
    days_back = int(os.environ.get("NEWS_DAYS_BACK", "30"))
    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days_back)
    future_dt = datetime.now(timezone.utc) + timedelta(days=7)

    def _in_window(entry) -> bool:
        pub_iso = _entry_published_iso(entry)
        if not pub_iso:
            # No publish date — accept (assume recent since we just fetched it).
            return True
        try:
            dt = datetime.fromisoformat(pub_iso.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return False  # unparseable → garbage
        return cutoff_dt <= dt <= future_dt

    entries_raw = [{
        "title": (e.get("title") or "(untitled)")[:500],
        "summary": clean_summary(e.get("summary", ""), limit=2000),
        "link": _make_canonical(e.get("link", "")),
        "_raw": e,
    } for e in parsed.entries if e.get("link") and _in_window(e)]

    # Layer 2: keyword block (Layer 1 dedupe is handled by SQLite UNIQUE)
    kept, _dropped = _articles_keyword_filter(entries_raw)

    n = 0
    for art in kept:
        if not art["link"]:
            continue
        rowid = _db.upsert_article(conn, {
            "canonical_url": art["link"],
            "title": art["title"],
            "summary": art["summary"],
            "source_slug": src["slug"],
            "source_title": src.get("title"),
            "lang": src.get("lang"),
            "rss_category": src.get("category"),
            "published": _entry_published_iso(art["_raw"]),
            "fetched_at": now_iso,
            "first_seen_date": first_seen_date,
        })
        if rowid:
            n += 1
    _db.record_source_fetch(conn, src["slug"], now=now_iso,
                            etag=(r.headers.get("ETag") or "")[:512] or None,
                            last_modified=(r.headers.get("Last-Modified") or "")[:512] or None,
                            ok=True)
    return (n, r.status_code)


def dump_ndjson_archive(*, db_path=None, date: str) -> Path:
    """Dump all articles with first_seen_date == date to a per-day NDJSON.

    Includes is_relevant=0 articles for human audit. Idempotent: overwrites
    the day's file each time.
    """
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = ARCHIVE_DIR / f"{date}.jsonl"
    conn = _db.connect(db_path)
    rows = conn.execute(
        "SELECT * FROM articles WHERE first_seen_date = ? ORDER BY fetched_at",
        [date],
    )
    with out_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
    conn.close()
    return out_path


async def fetch_news_to_sqlite(
    *,
    concurrency: int = 8,
    now_iso: str | None = None,
    db_path=None,
) -> dict:
    """SQLite-backed news fetcher. Replaces the news.json write path.

    Picks 'due' sources via db.due_sources(), respects ETag/If-Modified-Since,
    upserts new articles into the articles table.
    """
    ts = now_iso if now_iso is not None else datetime.now(timezone.utc).isoformat()
    conn = _db.connect(db_path)
    _db.init_schema(conn)  # idempotent — safe to call every run

    # Self-bootstrap: seed sources table from NEWS_SOURCES + OPML if empty.
    # Avoids needing migrate_to_sqlite as a separate step on fresh deployments.
    # On subsequent runs the table is non-empty and we skip the upsert loop
    # (saves O(700) writes per cron tick); operators can manually edit the
    # sources table to add/remove feeds.
    existing_sources = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
    if existing_sources == 0:
        _TOP_SLUGS = {
            "freebuf", "anquanke", "4hou", "kanxue", "secrss", "qianxin",
            "thn", "bleeping", "krebs", "schneier", "talos", "unit42",
            "msrc", "googlep0", "mandiant", "datadog",
        }
        for src in _news_sources_to_use():
            slug = src.get("slug") or _slug_from_url(src.get("url", ""))
            tier = "top" if slug in _TOP_SLUGS else "tail"
            _db.upsert_source(conn, {
                "slug": slug,
                "title": src.get("title") or slug,
                "url": src.get("url"),
                "lang": src.get("lang"),
                "tier": tier,
                "interval_minutes": 30 if tier == "top" else 240,
            })
        print(f"[news] bootstrapped {conn.execute('SELECT COUNT(*) FROM sources').fetchone()[0]} sources", file=sys.stderr)

    due = _db.due_sources(conn, ts)
    print(f"[news] {len(due)} sources due (out of total in sources table)", file=sys.stderr)

    sem = asyncio.Semaphore(concurrency)
    inserted_total = 0
    not_modified = 0
    _feeds_done = 0

    try:
        from scripts import refresh_progress as _prog
        _prog.start("fetching")
        _prog.report("fetching", len(due), 0, label="news_rss")
    except ImportError:
        _prog = None

    timeout = httpx.Timeout(30.0, connect=10.0)
    async with httpx.AsyncClient(headers=HEADERS, timeout=timeout,
                                  follow_redirects=True) as client:
        async def one(src):
            nonlocal inserted_total, not_modified, _feeds_done
            async with sem:
                n, status = await _fetch_one_source_to_sqlite(client, dict(src), conn, ts)
                inserted_total += n
                if status == 304:
                    not_modified += 1
                _feeds_done += 1
                if _prog and _feeds_done % 10 == 0:
                    _prog.report("fetching", len(due), _feeds_done, label="news_rss")
        await asyncio.gather(*[one(s) for s in due])
    if _prog:
        _prog.report("fetching", len(due), len(due), label="news_rss")

    conn.close()
    # Dump today's archive (idempotent: overwrites the day's file)
    today = ts[:10]
    try:
        dump_ndjson_archive(db_path=db_path, date=today)
    except Exception as exc:
        print(f"[news] archive dump failed: {exc}", file=sys.stderr)
    return {
        "name": "news", "ok": True, "status": "ok",
        "count": inserted_total, "due_sources": len(due),
        "not_modified": not_modified,
    }


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
    d = cache_dir or CACHE
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


# ─────────── snapshot / incremental layer ───────────
#
# Each cache file records a list (or dict) of items keyed by some stable
# identifier. The snapshot step:
#   1. reads the latest prior snapshot in backend/history/ (if any),
#   2. annotates current items with `first_seen` (carried over for existing
#      ids, set to today's date for newly seen ones),
#   3. writes the annotated cache back in place,
#   4. copies the annotated cache into backend/history/{today}/.
#
# This gives the API layer an unambiguous "new today" signal without forcing
# every fetcher to know about diff logic.

HISTORY = ROOT / "backend" / "history"

# (cache_filename_without_ext, list_key, id_field)
# id_field=None means the list_key holds a dict keyed by id (e.g. nuclei).
SNAPSHOT_KEYS: list[tuple[str, str, str | None]] = [
    ("kev", "items", "cveID"),
    ("ghsa", "items", "ghsa_id"),
    ("pocs", "items", "id"),
    ("murphy", "items", "_murphy_key"),
    ("itw", "items", "id"),
    ("news", "articles", "link"),
    ("nuclei", "items", None),
    ("hn", "items", "id"),
    ("masto", "items", "uri"),
]


def _latest_history_dir(today_dir: Path) -> Path | None:
    if not HISTORY.exists():
        return None
    prior = sorted(
        p for p in HISTORY.iterdir()
        if p.is_dir() and p.name != today_dir.name and len(p.name) == 10
    )
    return prior[-1] if prior else None


def _read_prev_seen(prev_dir: Path | None, cache_name: str, list_key: str, id_field: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if prev_dir is None:
        return out
    prev_path = prev_dir / f"{cache_name}.json"
    if not prev_path.exists():
        return out
    try:
        prev = json.loads(prev_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return out
    container = prev.get(list_key)
    if id_field is None and isinstance(container, dict):
        for k, v in container.items():
            if isinstance(v, dict) and v.get("first_seen"):
                out[k] = v["first_seen"]
    elif isinstance(container, list):
        for item in container:
            if not isinstance(item, dict):
                continue
            iid = item.get(id_field) if id_field else None
            if iid:
                out[str(iid)] = item.get("first_seen") or ""
    return out


def snapshot_today(only: set[str] | None = None) -> dict:
    """Annotate cache files with `first_seen` and copy them into history.

    If `only` is provided, restrict to that subset of cache_name(s); other
    caches keep whatever annotation they already have and are NOT copied to
    today's history dir (avoids implying those sources ran today).

    Same-day re-runs consult today's existing snapshot (read BEFORE write) so
    `new_today` doesn't false-positive when an item was already seen earlier
    today but the fetcher just rewrote the cache from scratch.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_dir = HISTORY / today
    today_exists_before_write = today_dir.exists() and any(today_dir.iterdir())
    today_dir.mkdir(parents=True, exist_ok=True)
    prev_dir = _latest_history_dir(today_dir)

    summary: dict[str, dict] = {}
    for cache_name, list_key, id_field in SNAPSHOT_KEYS:
        if only is not None and cache_name not in only:
            continue
        src = CACHE / f"{cache_name}.json"
        if not src.exists():
            continue
        try:
            data = json.loads(src.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        # Prefer first_seen from a strictly-prior day if available; else
        # fall back to today's earlier in-day snapshot for idempotency.
        prev_seen = _read_prev_seen(prev_dir, cache_name, list_key, id_field)
        if today_exists_before_write:
            same_day = _read_prev_seen(today_dir, cache_name, list_key, id_field)
            for k, v in same_day.items():
                prev_seen.setdefault(k, v)
        container = data.get(list_key)
        new_today = 0
        total = 0

        if id_field is None and isinstance(container, dict):
            for k, v in container.items():
                if not isinstance(v, dict):
                    continue
                total += 1
                existing = v.get("first_seen")
                prev_fs = prev_seen.get(k)
                if existing:
                    pass  # already annotated earlier today
                elif prev_fs:
                    v["first_seen"] = prev_fs
                else:
                    v["first_seen"] = today
                    new_today += 1
        elif isinstance(container, list):
            for item in container:
                if not isinstance(item, dict):
                    continue
                total += 1
                iid = str(item.get(id_field) or "") if id_field else ""
                existing = item.get("first_seen")
                prev_fs = prev_seen.get(iid) if iid else None
                if existing:
                    pass
                elif prev_fs:
                    item["first_seen"] = prev_fs
                else:
                    item["first_seen"] = today
                    new_today += 1
        else:
            continue

        # write annotated back in place
        src.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        # copy to history (relies on the in-place write above)
        (today_dir / f"{cache_name}.json").write_bytes(src.read_bytes())
        summary[cache_name] = {"new_today": new_today, "total": total}

    write_json("manifest.json", {
        **(json.loads((CACHE / "manifest.json").read_text(encoding="utf-8")) if (CACHE / "manifest.json").exists() else {}),
        "snapshot": {
            "date": today,
            "prev_snapshot": prev_dir.name if prev_dir else None,
            "summary": summary,
        },
    })
    return summary


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
    args = p.parse_args()

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
