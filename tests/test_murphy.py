"""MurphySec fetcher and normalization tests."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))


class _FakeMurphyResponse:
    status = 200

    def __init__(self, payload: dict):
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self) -> str:
        return json.dumps(self._payload)


def _fake_session_factory(payloads: list[dict], requests: list[dict]):
    class FakeSession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def post(self, url, *, json=None, headers=None):
            requests.append({"url": url, "json": json, "headers": headers})
            return _FakeMurphyResponse(payloads.pop(0))

    return FakeSession


@pytest.mark.asyncio
async def test_murphy_fetcher_initial_run_uses_incremental_window(tmp_path, monkeypatch):
    import fetch_data as fd

    monkeypatch.setattr(fd, "CACHE", tmp_path)
    monkeypatch.setenv("MURPHY_CUSTOMER_CODE", "test-code")
    monkeypatch.setenv("MURPHY_INITIAL_LOOKBACK_MINUTES", "240")
    requests: list[dict] = []
    payloads = [{
        "code": 0,
        "data": {
            "list": [{
                "vuln_id": "murphy-1",
                "cve_id": "CVE-2026-1111",
                "vuln_name": "Apache RCE",
                "last_modify_time": "2026-05-27T10:00:00+08:00",
            }],
            "total": 1,
        },
    }]
    monkeypatch.setattr(fd.aiohttp, "ClientSession", _fake_session_factory(payloads, requests))

    result = await fd.fetch_murphy(None)

    assert result["mode"] == "incremental"
    assert result["count"] == 1
    body = requests[0]["json"]
    assert body["scope"] == "default"
    assert body["malicious_code"] == "include"
    assert "start_time" in body
    assert "end_time" in body
    written = json.loads((tmp_path / "murphy.json").read_text())
    assert written["items"][0]["_murphy_key"] == "murphy-1"
    assert written["diagnostic"]["initial_incremental"] is True
    assert written["diagnostic"]["initial_lookback_minutes"] == 240


@pytest.mark.asyncio
async def test_murphy_fetcher_incremental_merges_existing_cache(tmp_path, monkeypatch):
    import fetch_data as fd

    monkeypatch.setattr(fd, "CACHE", tmp_path)
    monkeypatch.setenv("MURPHY_CUSTOMER_CODE", "test-code")
    (tmp_path / "murphy.json").write_text(json.dumps({
        "last_success_at": "2026-05-27T01:00:00+00:00",
        "items": [{
            "_murphy_key": "CVE-2026-0001",
            "cve_id": "CVE-2026-0001",
            "vuln_name": "Existing vuln",
            "last_modify_time": "2026-05-27T08:30:00+08:00",
        }],
    }), encoding="utf-8")
    requests: list[dict] = []
    payloads = [{
        "code": 0,
        "data": {
            "list": [{
                "vuln_id": "murphy-2",
                "cve_id": "CVE-2026-2222",
                "vuln_name": "Incremental vuln",
                "last_modify_time": "2026-05-27T10:10:00+08:00",
            }],
            "total": 1,
        },
    }]
    monkeypatch.setattr(fd.aiohttp, "ClientSession", _fake_session_factory(payloads, requests))

    result = await fd.fetch_murphy(None)

    assert result["mode"] == "incremental"
    assert result["fetched_delta"] == 1
    body = requests[0]["json"]
    assert body["scope"] == "default"
    assert body["start_time"] == "2026-05-27T09:00:00+08:00"
    assert "end_time" in body
    written = json.loads((tmp_path / "murphy.json").read_text())
    keys = {item["_murphy_key"] for item in written["items"]}
    assert {"CVE-2026-0001", "murphy-2"} <= keys


def test_murphy_items_normalize_into_vulns(tmp_path, monkeypatch):
    import backend.app.data as data_mod

    monkeypatch.setattr(data_mod, "CACHE", tmp_path)
    data_mod._state.clear()
    (tmp_path / "murphy.json").write_text(json.dumps({
        "items": [
            {
                "_murphy_key": "CVE-2026-1111",
                "cve_id": "CVE-2026-1111",
                "vuln_name": "Apache 远程代码执行漏洞",
                "description": "影响 Apache HTTP Server。",
                "level": "高危",
                "cvss_score": "8.8",
                "last_modify_time": "2026-05-27T10:00:00+08:00",
                "detail_url": "https://example.com/detail/CVE-2026-1111",
            },
            {
                "_murphy_key": "MPS-test-0001",
                "mps_id": "MPS-test-0001",
                "title": "NPM仓库evil-pkg等包内置恶意代码",
                "problem_type": {"cwe": "CWE-506", "meaning": "内嵌恶意代码"},
                "description": "投毒包窃取环境变量。",
                "last_modify_time": "2026-05-27T10:05:00+08:00",
            },
        ],
    }), encoding="utf-8")

    vulns = data_mod._murphy_to_vulns()
    by_id = {v.id: v for v in vulns}

    assert by_id["CVE-2026-1111"].severity == "high"
    assert by_id["CVE-2026-1111"].source == "murphysec"
    assert by_id["CVE-2026-1111"].references[0].url == "https://example.com/detail/CVE-2026-1111"
    malware = next(v for v in vulns if v.package == "evil-pkg")
    assert malware.kind == "supply"
    assert malware.is_supply_chain is True
    assert malware.ecosystem == "npm"
    assert "MALWARE" in malware.tags
