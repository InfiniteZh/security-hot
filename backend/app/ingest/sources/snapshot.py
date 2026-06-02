"""Snapshot / incremental layer.

Each cache file records a list (or dict) of items keyed by some stable
identifier. The snapshot step:
  1. reads the latest prior snapshot in backend/history/ (if any),
  2. annotates current items with `first_seen` (carried over for existing
     ids, set to today's date for newly seen ones),
  3. writes the annotated cache back in place,
  4. copies the annotated cache into backend/history/{today}/.

This gives the API layer an unambiguous "new today" signal without forcing
every fetcher to know about diff logic.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .. import _util
from .._util import ROOT, write_json


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
        src = _util.CACHE / f"{cache_name}.json"
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
        **(json.loads((_util.CACHE / "manifest.json").read_text(encoding="utf-8")) if (_util.CACHE / "manifest.json").exists() else {}),
        "snapshot": {
            "date": today,
            "prev_snapshot": prev_dir.name if prev_dir else None,
            "summary": summary,
        },
    })
    return summary
