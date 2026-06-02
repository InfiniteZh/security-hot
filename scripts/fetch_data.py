#!/usr/bin/env python3
"""CLI shim: delegates to backend.app.ingest.fetchers.

Kept as scripts/fetch_data.py for cron + tests backward-compat. The real
implementation lives in backend/app/ingest/fetchers.py; this module swaps
itself for that one so `import fetch_data` / `import scripts.fetch_data`
resolve to the implementation (FETCHERS, fetch_murphy, ... all visible).
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_ROOT = _Path(__file__).resolve().parent.parent
if str(_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_ROOT))

from backend.app.ingest.fetchers import *  # noqa: F401,F403,E402
from backend.app.ingest import fetchers as _impl  # noqa: E402

_sys.modules[__name__] = _impl

if __name__ == "__main__":
    raise SystemExit(_impl.main())
