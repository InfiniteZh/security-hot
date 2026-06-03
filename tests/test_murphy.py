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
                "mps_id": "MPS-fthb-675x",
                "cve_id": "",
                "title": "恶意 NuGet 包 Sicoob.Sdk 冒充巴西银行 SDK",
                "description": "投毒包收集隐私数据。",
                "severity": "高危",
                "cvss_score": "8.2",
                "problem_type": {"cwe": "CWE-506", "meaning": "内嵌恶意代码"},
                "repository": "nuget",
                "affected_version": [
                    {
                        "repository": "nuget",
                        "name": "Sicoob.Sdk",
                        "affected": {
                            "version_range": "[2.0.0,2.0.4]",
                            "expression": {"fix_version": "2.0.5"},
                            "upstream_fix_version": "2.0.6",
                        },
                    }
                ],
                "ioc": [
                    "o4511335034847232.ingest.de.sentry.io",
                    "",
                    "o4511335034847232.ingest.de.sentry.io",
                ],
                "tags": ["投毒", "隐私数据收集"],
                "hazard_level": "高危",
                "last_modify_time": "2026-05-27T10:00:00+08:00",
                "published_date": "2026-05-27T09:00:00+08:00",
                "public_time": "2026-05-27T08:00:00+08:00",
                "references": [{"url": "https://www.oscs1024.com/hd/MPS-fthb-675x", "name": "OSCS"}],
                "cvssv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                "epss": "",
                "poc": False,
                "language": "C#",
            },
            {
                "mps_id": "MPS-axios-0001",
                "cve_id": "CVE-2026-1111",
                "title": "Axios 原型污染漏洞",
                "description": "Axios 处理对象属性时存在原型污染问题。",
                "severity": "中危",
                "cvss_score": "5.6",
                "problem_type": {"cwe": "CWE-1321", "meaning": "原型污染"},
                "repository": "npm",
                "affected_version": [
                    {
                        "repository": "npm",
                        "name": "axios",
                        "affected": {"version_range": "<0.30.0"},
                    }
                ],
                "tags": ["漏洞"],
                "last_modify_time": "2026-05-27T10:05:00+08:00",
                "references": [{"url": "https://example.com/detail/CVE-2026-1111", "name": "Detail"}],
            },
        ],
    }), encoding="utf-8")

    vulns = data_mod._murphy_to_vulns()
    by_id = {v.id: v for v in vulns}

    malware = by_id["MURPHY-MPS-fthb-675x"]
    assert malware.kind == "supply"
    assert malware.is_supply_chain is True
    assert malware.package == "Sicoob.Sdk"
    assert malware.ecosystem == "nuget"
    assert malware.affected_versions == ["[2.0.0,2.0.4]"]
    assert malware.iocs == ["o4511335034847232.ingest.de.sentry.io"]
    assert malware.fix_versions == ["2.0.5", "2.0.6"]
    assert malware.severity == "high"
    assert "MALWARE" in malware.tags
    assert malware.references[0].url == "https://www.oscs1024.com/hd/MPS-fthb-675x"

    cve = by_id["CVE-2026-1111"]
    assert cve.source == "murphysec"
    assert cve.sources == ["murphysec"]
    assert cve.package == "axios"
    assert cve.ecosystem == "npm"
    assert cve.affected_versions == ["<0.30.0"]
    assert cve.severity == "medium"
    assert cve.cve_id == "CVE-2026-1111"
    assert "MALWARE" not in cve.tags
    # Non-malicious dependency CVE → NOT supply-chain poisoning, must not dispatch.
    assert cve.kind == "cve"
    assert cve.is_supply_chain is False
    # ...while the genuinely poisoned package stays supply-chain.
    assert malware.is_supply_chain is True
    assert cve.references[0].url == "https://example.com/detail/CVE-2026-1111"


def test_all_vulns_preserves_merged_sources(tmp_path, monkeypatch):
    import backend.app.data as data_mod

    monkeypatch.setattr(data_mod, "CACHE", tmp_path)
    monkeypatch.setattr(data_mod, "_NEWS_DB", tmp_path / "missing-news.db")
    data_mod._state.clear()
    (tmp_path / "kev.json").write_text(json.dumps({
        "items": [{
            "cveID": "CVE-2026-1111",
            "vendorProject": "Example",
            "product": "Widget",
            "vulnerabilityName": "Example Widget RCE",
            "shortDescription": "Known exploited vulnerability.",
            "dateAdded": "2026-05-27",
        }]
    }), encoding="utf-8")
    (tmp_path / "murphy.json").write_text(json.dumps({
        "items": [{
            "mps_id": "MPS-axios-0001",
            "cve_id": "CVE-2026-1111",
            "title": "Axios 原型污染漏洞",
            "description": "Axios 处理对象属性时存在原型污染问题。",
            "severity": "中危",
            "repository": "npm",
            "affected_version": [{
                "repository": "npm",
                "name": "axios",
                "affected": {"version_range": "<0.30.0"},
            }],
            "last_modify_time": "2026-05-27T10:05:00+08:00",
        }]
    }), encoding="utf-8")

    vulns = data_mod.all_vulns()
    merged = next(v for v in vulns if v.id == "CVE-2026-1111")

    assert merged.source == "cisa-kev"
    assert merged.kind == "itw"
    # Axios prototype-pollution is an ordinary dependency CVE, not a poisoned
    # package — MurphySec no longer flags non-malicious items as supply-chain.
    assert merged.is_supply_chain is False
    assert merged.sources == ["cisa-kev", "murphysec"]
