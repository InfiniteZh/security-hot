"""LLM call infrastructure shared by the news/vuln/brief pipeline modules.

This is the foundation layer: it owns the OpenAI-compatible chat call,
JSON extraction, env-driven config, the day-window filter, and the
bounded-concurrency helper. It carries no business logic and must not
import any of the sibling business modules (news_llm/vuln_llm/brief/
orchestration) to keep the dependency graph acyclic.

It also performs the shared bootstrap (ROOT/SCRIPTS sys.path, .env load,
refresh_progress import) so every dependent module gets it via star import.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time  # noqa: F401  (re-exported for façade/CLI parity)
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[4]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import refresh_progress as _prog  # noqa: E402

# Load .env so `uv run python scripts/llm_rank.py …` works without a manual
# `source .env`. Also applies to uvicorn background tasks.
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(ROOT / ".env")
except ImportError:
    pass  # optional dep — env vars must be exported manually if missing

VULN_AI_JSON = ROOT / "backend" / "cache" / "vuln_ai.json"

DEFAULT_LLM_CONCURRENCY = 8
_LLM_SEMAPHORE = asyncio.Semaphore(DEFAULT_LLM_CONCURRENCY)
_LLM_SEMAPHORES: dict[int, asyncio.Semaphore] = {
    DEFAULT_LLM_CONCURRENCY: _LLM_SEMAPHORE,
}


def _llm_semaphore(limit: int | None = None) -> asyncio.Semaphore:
    limit = limit or DEFAULT_LLM_CONCURRENCY
    if limit <= 0:
        limit = DEFAULT_LLM_CONCURRENCY
    sem = _LLM_SEMAPHORES.get(limit)
    if sem is None:
        sem = asyncio.Semaphore(limit)
        _LLM_SEMAPHORES[limit] = sem
    return sem


# ── Helpers ──

def _extract_json(content: str) -> dict:
    content = content.strip()
    fenced = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", content)
    if fenced:
        content = fenced.group(1).strip()
    if not content.startswith("{"):
        m = re.search(r"\{[\s\S]+\}", content)
        if m:
            content = m.group(0)
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # LLMs frequently embed unescaped real newlines inside string values
        # when the value is markdown — strict JSON forbids that. Fall back to
        # a tolerant single-key extraction for the brief envelope {"text": "..."}.
        m = re.search(r'"text"\s*:\s*"([\s\S]*)"\s*\}\s*$', content)
        if m:
            raw = m.group(1)
            # Decode the common escape sequences a well-behaved LLM would use
            # (\\n \\" \\\\) without going through json.loads.
            decoded = (raw
                       .replace("\\\\", "\x00")  # protect literal backslash
                       .replace("\\n", "\n")
                       .replace("\\t", "\t")
                       .replace('\\"', '"')
                       .replace("\x00", "\\"))
            return {"text": decoded}
        raise


async def _llm_call(client, system_prompt, user_msg, base_url, api_key, model, timeout,
                    max_retries: int = 3, max_concurrency: int | None = None):
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0,
        # Cap the completion length. Without this the provider's (low) default
        # truncates large batch responses mid-JSON → parse failure (error) or
        # dropped trailing items (partial_batches). 32k comfortably fits an
        # 80-item classify batch (~16k); raise LLM_MAX_TOKENS only if a batch's
        # output genuinely needs more (this is the per-response OUTPUT cap, not
        # the model's total context window).
        "max_tokens": int(os.environ.get("LLM_MAX_TOKENS", "32000")),
        "response_format": {"type": "json_object"},
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    url = f"{base_url.rstrip('/')}/chat/completions"
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            async with _llm_semaphore(max_concurrency):
                r = await asyncio.wait_for(
                    client.post(url, json=body, headers=headers, timeout=timeout),
                    timeout=timeout,
                )
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            return _extract_json(content)
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries:
                await asyncio.sleep(2 ** attempt)
    raise last_exc


def _llm_call_via_facade(*args, **kwargs):
    """Late-bound delegate to the façade's _llm_call, shared by the
    news/vuln/brief business modules.

    Tests (and any caller) patch `pipeline._llm_call` — also exposed as
    `llm_rank._llm_call`. Resolving it from the façade at call time keeps the
    monolith's original late-binding semantics intact after the split. The
    façade import is lazy to avoid a module-load import cycle.
    """
    from .. import pipeline as _facade
    return _facade._llm_call(*args, **kwargs)


def _get_config():
    return {
        "api_key": os.environ.get("LLM_API_KEY"),
        "base_url": os.environ.get("LLM_BASE_URL", "https://api.minimaxi.com/v1"),
        "model": os.environ.get("LLM_MODEL", "MiniMax-M2.7"),
        "concurrency": int(os.environ.get("LLM_CONCURRENCY", str(DEFAULT_LLM_CONCURRENCY))),
        "timeout": float(os.environ.get("LLM_TIMEOUT", "90")),
        "max_batches": int(os.environ.get("LLM_MAX_BATCHES", "200")),
    }


def _is_within_days(published: str | None, days: int) -> bool:
    if days <= 0:
        return True
    if not published:
        return False
    try:
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(published.strip(), fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
        else:
            dt = datetime.fromisoformat(published.strip().replace("Z", "+00:00"))
        return dt >= datetime.now(timezone.utc) - timedelta(days=days)
    except (ValueError, TypeError):
        return False


async def _run_concurrent(items, process_fn, concurrency, lock, flush_fn=None, flush_every=4):
    sem = asyncio.Semaphore(concurrency)
    counter = 0

    async def bounded(chunk, batch_num, client):
        nonlocal counter
        async with sem:
            await process_fn(chunk, batch_num, client)
            if flush_fn:
                async with lock:
                    counter += 1
                    if counter % flush_every == 0:
                        flush_fn()

    async with httpx.AsyncClient(timeout=items["timeout"]) as client:
        await asyncio.gather(*[
            bounded(ch, i + 1, client)
            for i, ch in enumerate(items["chunks"])
        ])
