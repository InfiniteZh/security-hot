"""Shared refresh progress file for tqdm-style ETA in the frontend.

Scripts write progress via `report()`. The FastAPI healthz endpoint reads it.
File path: backend/cache/.refresh_progress.json
"""
from __future__ import annotations

import json
import time
from pathlib import Path

_PROGRESS_FILE = Path(__file__).resolve().parent.parent / "backend" / "cache" / ".refresh_progress.json"
_stage_t0: dict[str, float] = {}


def start(stage: str) -> None:
    _stage_t0[stage] = time.monotonic()


def report(stage: str, total: int, done: int, *, label: str = "") -> None:
    t0 = _stage_t0.get(stage)
    elapsed = (time.monotonic() - t0) if t0 is not None else 0.0
    rate = done / elapsed if elapsed > 0 and done > 0 else 0.0
    eta = (total - done) / rate if rate > 0 else None
    try:
        _PROGRESS_FILE.write_text(json.dumps({
            "stage": stage, "label": label,
            "total": total, "done": done,
            "rate": round(rate, 2),
            "eta_s": round(eta, 1) if eta is not None else None,
            "elapsed_s": round(elapsed, 1),
            "ts": time.time(),
        }), encoding="utf-8")
    except OSError:
        pass


def read() -> dict | None:
    try:
        if not _PROGRESS_FILE.exists():
            return None
        data = json.loads(_PROGRESS_FILE.read_text(encoding="utf-8"))
        if time.time() - data.get("ts", 0) > 600:
            return None
        return data
    except (OSError, json.JSONDecodeError):
        return None
