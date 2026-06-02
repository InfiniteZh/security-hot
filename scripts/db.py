from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_ROOT = _Path(__file__).resolve().parent.parent
if str(_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_ROOT))

from backend.app.ingest.db import *  # noqa: F401,F403,E402
from backend.app.ingest import db as _impl  # noqa: E402

_sys.modules[__name__] = _impl
