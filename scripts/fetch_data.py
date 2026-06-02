#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.ingest import fetchers as _impl  # noqa: E402
from backend.app.ingest import run_fetchers  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Fetch security data into local JSON cache.")
    p.add_argument("--only", help="comma-separated subset of fetchers (default: all)")
    p.add_argument("--concurrency", type=int, default=8, help="news-feed concurrency (default 8)")
    p.add_argument("--no-snapshot", action="store_true", help="skip history snapshot + first_seen annotation")
    p.add_argument("--incremental", action="store_true", help="merge new articles into existing cache instead of replacing")
    p.add_argument("--list", action="store_true", help="list available fetchers and exit")
    args = p.parse_args()

    if args.list:
        for name in _impl.FETCHERS:
            print(name)
        return 0

    if args.only:
        selected = [s.strip() for s in args.only.split(",") if s.strip()]
        unknown = [s for s in selected if s not in _impl.FETCHERS]
        if unknown:
            sys.exit(f"unknown fetcher(s): {unknown}; available: {list(_impl.FETCHERS)}")
    else:
        selected = list(_impl.FETCHERS)

    result = asyncio.run(
        run_fetchers(
            selected,
            args.concurrency,
            snapshot=not args.no_snapshot,
            incremental=args.incremental,
        )
    )
    return int(result.get("returncode", 0))


if __name__ == "__main__":
    raise SystemExit(main())

sys.modules[__name__] = _impl
