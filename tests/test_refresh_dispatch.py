"""Manual-refresh pipeline resolution: single-source pulls auto-chain dispatch.

`_resolve_refresh_pipeline` lives in backend.app.runtime.pipeline_runner after the
main.py split (it was originally authored on backend.app.main).
"""
from backend.app.runtime.pipeline_runner import _resolve_refresh_pipeline


def test_single_news_refresh_chains_news_dispatch_pipeline():
    scope, tasks = _resolve_refresh_pipeline(["news"], None)

    assert scope == "news"
    assert tasks == ["news_classify", "news_summarize", "daily_brief"]


def test_single_murphy_refresh_chains_vuln_dispatch_pipeline():
    scope, tasks = _resolve_refresh_pipeline(["murphy"], None)

    assert scope == "vuln"
    assert tasks == ["vuln_assess"]


def test_explicit_refresh_scope_still_wins():
    scope, tasks = _resolve_refresh_pipeline(["murphy"], "none")

    assert scope == "none"
    assert tasks == []
