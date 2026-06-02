from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_ROOT = _Path(__file__).resolve().parent.parent
if str(_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_ROOT))
if str(_ROOT / "scripts") not in _sys.path:
    _sys.path.insert(0, str(_ROOT / "scripts"))

from backend.app.ingest.pipeline import *  # noqa: F401,F403,E402
from backend.app.ingest import pipeline as _impl  # noqa: E402

_sys.modules[__name__] = _impl

if __name__ == "__main__":
    raise SystemExit(_impl.main())
