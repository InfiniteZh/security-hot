from pathlib import Path


WEB_INDEX = Path(__file__).resolve().parents[1] / "web" / "index.html"


def test_single_source_refresh_sends_pipeline_scope():
    html = WEB_INDEX.read_text()

    assert "function refreshScopeForSource(only)" in html
    assert 'params.set("llm", scope);' in html
    assert "refreshScopeForSource(only)" in html
    assert 'fetch(`/api/refresh?${params.toString()}`' in html


def test_vuln_source_filters_are_dynamic():
    html = WEB_INDEX.read_text()

    assert 'id="vuln-source-filter"' in html
    assert "function renderVulnSourceFilters()" in html
    assert "function vulnSourceKeys(v)" in html
    assert "vulnSourceKeys(v).some" in html
