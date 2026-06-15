"""Durable per-step status for the whole data pipeline.

Why this exists
---------------
`manifest.json` is rewritten on every fetch run and only contains the fetchers
that ran in *that* invocation — so with murphy polling every 5min it gets
clobbered down to a single entry within minutes. Worse, the LLM scripts
(llm_rank) never write manifest at all.

This module keeps a small, merge-on-write record of the LAST outcome of every
pipeline step — both data fetchers and LLM scripts — so the frontend
can answer: *what ran, when, did it fail, and why* — across runs and restarts.

Store: ``backend/cache/pipeline_status.json``::

    { "<step>": {name, kind, job, ok, status, count, elapsed_s,
                 last_run, error, diagnostic, returncode}, ... }

All writes go through the in-process refresh lock held by main.py's runners, so
within the (single) uvicorn process writers are already serialised.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Canonical pipeline order → (kind, owning scheduler job id). The dict order is
# the display order the frontend gets. `job` lets the API attach next_run_time.
STEP_META: dict[str, tuple[str, str]] = {
    # ── data fetchers ──────────────────────────────────────────────
    "news":   ("fetch", "fetch_news"),
    "murphy": ("fetch", "fetch_murphy"),
    "kev":    ("fetch", "fetch_other"),
    "ghsa":   ("fetch", "fetch_other"),
    "pocs":   ("fetch", "fetch_other"),
    "osv":    ("fetch", "fetch_other"),
    "epss":   ("fetch", "fetch_other"),
    "nuclei": ("fetch", "fetch_other"),
    "itw":    ("fetch", "fetch_other"),
    "heat":   ("fetch", "fetch_other"),
    "hn":     ("fetch", "fetch_other"),
    "masto":  ("fetch", "fetch_other"),
    # ── LLM ────────────────────────────────────────────────────────
    "classify":    ("llm", "heavy_pipeline"),
    "summarize":   ("llm", "heavy_pipeline"),
    # ── Kafka 投送（供应链投毒情报 → security_copilot disposal）──────
    "poisoning_dispatch": ("dispatch", "heavy_pipeline"),
    "vuln_dispatch":      ("dispatch", "fetch_murphy"),
    "daily_brief": ("llm", "daily_brief"),
}

# Tests monkeypatch this to redirect the store to a tmp dir.
# Must be backend/cache (parents[2]/cache), NOT backend/app/cache: only
# backend/cache is bind-mounted in docker-compose, so the panel store survives
# container restarts and sits next to manifest.json (matches this module's
# docstring). parents[1] would put it in the un-mounted backend/app/cache and
# lose all pipeline status on every restart.
CACHE_DIR = Path(__file__).resolve().parents[2] / "cache"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _store_path() -> Path:
    return CACHE_DIR / "pipeline_status.json"


def _load_raw() -> dict:
    p = _store_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _atomic_write(data: dict) -> None:
    p = _store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".pipeline_status.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _error_tail(text: str | None, limit: int = 600) -> str | None:
    """Keep the last `limit` chars of stderr — the tail usually holds the
    traceback / real cause, and we don't want to bloat the store."""
    if not text:
        return None
    text = text.strip()
    if not text:
        return None
    return text[-limit:]


def step_name(script: str, task: str | None = None) -> str | None:
    """Map a (script, --task) pair to a canonical step name. Returns None for
    fetch_data.py (those are recorded per-fetcher from the manifest instead)."""
    base = Path(script).name
    if base == "llm_rank.py":
        return {
            "news_classify": "classify",
            "news_summarize": "summarize",
            "daily_brief": "daily_brief",
        }.get(task or "")
    return None


def upsert_from_manifest(manifest_path: Path | str) -> None:
    """Read a freshly-written manifest.json and merge each fetcher result into
    the durable store, keyed by fetcher name. Silently no-ops on a missing or
    unreadable manifest (a crashed fetch shouldn't wipe prior status)."""
    mp = Path(manifest_path)
    try:
        manifest = json.loads(mp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    results = manifest.get("results") if isinstance(manifest, dict) else None
    if not isinstance(results, list):
        return
    fetched_at = manifest.get("fetched_at") if isinstance(manifest, dict) else None
    store = _load_raw()
    for r in results:
        if not isinstance(r, dict) or not r.get("name"):
            continue
        name = str(r["name"])
        kind, job = STEP_META.get(name, ("fetch", None))
        ok = bool(r.get("ok"))
        status = r.get("status") or ("ok" if ok else "error")
        # A fetcher that returns a "disabled" diagnostic (e.g. murphy with no
        # MURPHY_CUSTOMER_CODE) isn't "no data" — it never ran. Surface that
        # distinctly so the UI doesn't paint a normal-but-unconfigured source
        # as a problem.
        diag = r.get("diagnostic")
        if isinstance(diag, dict) and diag.get("status") == "disabled":
            status = "disabled"
        store[name] = {
            "name": name,
            "kind": kind,
            "job": job,
            "ok": ok,
            "status": status,
            "count": r.get("count", 0),
            "elapsed_s": r.get("elapsed_s", 0),
            "last_run": r.get("finished_at") or fetched_at or now_iso(),
            "error": r.get("error"),
            "diagnostic": r.get("diagnostic"),
            "partial_errors": r.get("partial_errors"),
            "returncode": 0 if ok else None,
        }
    _atomic_write(store)


def bootstrap_from_manifest_if_empty(manifest_path: Path | str) -> None:
    """First-run convenience: if nothing has been recorded yet, seed the store
    from whatever the current manifest holds so the UI isn't all-'pending' on a
    fresh deploy. No-op once the store exists."""
    if _store_path().exists():
        return
    upsert_from_manifest(manifest_path)


def upsert_step(
    name: str,
    *,
    ok: bool,
    elapsed_s: float = 0,
    error: str | None = None,
    returncode: int | None = None,
    count: int | None = None,
) -> None:
    """Merge the outcome of one enrichment / LLM step into the durable store."""
    kind, job = STEP_META.get(name, ("llm", None))
    store = _load_raw()
    store[name] = {
        "name": name,
        "kind": kind,
        "job": job,
        "ok": ok,
        "status": "ok" if ok else "error",
        "count": count if count is not None else store.get(name, {}).get("count", 0),
        "elapsed_s": round(elapsed_s, 2),
        "last_run": now_iso(),
        "error": _error_tail(error) if not ok else None,
        "diagnostic": None,
        "partial_errors": None,
        "returncode": returncode,
    }
    _atomic_write(store)


def load_steps() -> list[dict]:
    """Return all known steps in canonical pipeline order. Steps that have never
    run yet are included with status='pending' so the UI shows the full pipeline,
    not just whatever happened to run."""
    store = _load_raw()
    out: list[dict] = []
    seen: set[str] = set()
    for name, (kind, job) in STEP_META.items():
        seen.add(name)
        entry = store.get(name)
        if entry:
            out.append(entry)
        else:
            out.append({
                "name": name, "kind": kind, "job": job, "ok": None,
                "status": "pending", "count": 0, "elapsed_s": 0,
                "last_run": None, "error": None, "diagnostic": None,
                "partial_errors": None, "returncode": None,
            })
    # Any extra recorded steps not in STEP_META (forward-compat) → append.
    for name, entry in store.items():
        if name not in seen:
            out.append(entry)
    return out
