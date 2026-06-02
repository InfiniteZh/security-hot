"""MurphySec vuln_warn source.

Time-window incremental fetcher for MurphySec's vuln_warn list, plus the
payload-shape helpers that tolerate MurphySec's loosely-typed API responses
and the merge/dedupe logic that maintains the incremental murphy.json cache.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone

import aiohttp
import httpx

from .. import _util
from .._util import USER_AGENT, write_json, _parse_iso_datetime


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
    path = _util.CACHE / "murphy.json"
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
