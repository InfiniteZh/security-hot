"""Tests for the durable pipeline-status store (backend/app/pipeline_status.py)."""
from __future__ import annotations

import json

import pytest

from backend.app import pipeline_status as ps


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Redirect the store + return the tmp cache dir."""
    monkeypatch.setattr(ps, "CACHE_DIR", tmp_path)
    return tmp_path


def _write_manifest(cache_dir, results, fetched_at="2026-05-29T00:00:00+00:00"):
    p = cache_dir / "manifest.json"
    p.write_text(json.dumps({"fetched_at": fetched_at, "results": results}), encoding="utf-8")
    return p


def test_upsert_from_manifest_records_each_fetcher(store):
    mp = _write_manifest(store, [
        {"name": "news", "ok": True, "status": "ok", "count": 66,
         "elapsed_s": 3.3, "finished_at": "2026-05-29T00:00:03+00:00"},
    ])
    ps.upsert_from_manifest(mp)
    steps = {s["name"]: s for s in ps.load_steps()}
    assert steps["news"]["ok"] is True
    assert steps["news"]["count"] == 66
    assert steps["news"]["last_run"] == "2026-05-29T00:00:03+00:00"
    assert steps["news"]["kind"] == "fetch"
    assert steps["news"]["job"] == "fetch_news"


def test_merge_does_not_clobber_other_fetchers(store):
    # Simulate the real failure mode: manifest is overwritten per run, but the
    # durable store must accumulate across runs.
    ps.upsert_from_manifest(_write_manifest(store, [
        {"name": "kev", "ok": True, "status": "ok", "count": 200,
         "finished_at": "2026-05-29T00:00:00+00:00"},
    ]))
    ps.upsert_from_manifest(_write_manifest(store, [
        {"name": "pocs", "ok": True, "status": "ok", "count": 12,
         "finished_at": "2026-05-29T00:05:00+00:00"},
    ]))
    steps = {s["name"]: s for s in ps.load_steps()}
    assert steps["kev"]["count"] == 200      # survived the pocs-only run
    assert steps["pocs"]["count"] == 12


def test_failed_fetcher_keeps_error_reason(store):
    ps.upsert_from_manifest(_write_manifest(store, [
        {"name": "ghsa", "ok": False, "status": "error", "count": 0,
         "error": "403 API rate limit exceeded",
         "finished_at": "2026-05-29T00:00:00+00:00"},
    ]))
    ghsa = {s["name"]: s for s in ps.load_steps()}["ghsa"]
    assert ghsa["ok"] is False
    assert ghsa["status"] == "error"
    assert "rate limit" in ghsa["error"]


def test_disabled_fetcher_is_not_no_data(store):
    # An unconfigured source returns a 'disabled' diagnostic + count 0; the
    # manifest may stamp it 'no_data' but the store should surface 'disabled'.
    ps.upsert_from_manifest(_write_manifest(store, [
        {"name": "heat", "ok": True, "status": "no_data", "count": 0,
         "diagnostic": {"status": "disabled", "reason": "source endpoint disabled"},
         "finished_at": "2026-05-29T00:00:00+00:00"},
    ]))
    heat = {s["name"]: s for s in ps.load_steps()}["heat"]
    assert heat["status"] == "disabled"
    assert heat["ok"] is True            # disabled is not a failure


def test_upsert_step_records_llm_failure_with_tail(store):
    long_err = "x" * 2000 + "FATAL: model timeout"
    ps.upsert_step("classify", ok=False, elapsed_s=12.5, error=long_err, returncode=1)
    classify = {s["name"]: s for s in ps.load_steps()}["classify"]
    assert classify["ok"] is False
    assert classify["kind"] == "llm"
    assert classify["job"] == "heavy_pipeline"
    assert classify["error"].endswith("FATAL: model timeout")
    assert len(classify["error"]) <= 600          # tail-trimmed


def test_upsert_step_ok_clears_error(store):
    ps.upsert_step("embed", ok=False, error="boom")
    ps.upsert_step("embed", ok=True, elapsed_s=4.0)
    embed = {s["name"]: s for s in ps.load_steps()}["embed"]
    assert embed["ok"] is True
    assert embed["error"] is None


def test_load_steps_includes_pending_for_never_run(store):
    # Nothing recorded yet → all 16 steps present as pending, in canonical order.
    steps = ps.load_steps()
    names = [s["name"] for s in steps]
    assert names == list(ps.STEP_META)
    assert all(s["status"] == "pending" for s in steps)


def test_step_name_mapping():
    assert ps.step_name("scripts/embed_articles.py") == "embed"
    assert ps.step_name("cluster_articles.py") == "cluster"
    assert ps.step_name("llm_rank.py", "news_classify") == "classify"
    assert ps.step_name("llm_rank.py", "news_summarize") == "summarize"
    assert ps.step_name("llm_rank.py", "daily_brief") == "daily_brief"
    assert ps.step_name("fetch_data.py") is None       # recorded via manifest
