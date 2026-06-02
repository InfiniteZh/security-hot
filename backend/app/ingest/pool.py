from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor

POOL: ProcessPoolExecutor | None = None


def start_pool() -> ProcessPoolExecutor:
    global POOL
    if POOL is None:
        POOL = ProcessPoolExecutor(max_workers=1)
    return POOL


def get_pool() -> ProcessPoolExecutor:
    return start_pool()


def shutdown_pool() -> None:
    global POOL
    if POOL is not None:
        POOL.shutdown(wait=False, cancel_futures=True)
        POOL = None
