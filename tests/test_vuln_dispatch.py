"""vuln_dispatch 单测（全 mock，不连真 broker）。"""
from __future__ import annotations

import datetime
import json
import sqlite3
import sys
from pathlib import Path

import pytest

_TODAY = datetime.date.today().isoformat()

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(_SCRIPTS))

import vuln_dispatch as vd  # noqa: E402
from backend.app.models import Article, Reference, Vuln  # noqa: E402


class _NoCloseConn(sqlite3.Connection):
    def close(self):  # noqa: D102
        pass


def _make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", factory=_NoCloseConn)
    conn.row_factory = sqlite3.Row
    return conn


def _vuln(**kw) -> Vuln:
    defaults = dict(
        id="MURPHY-MPS-1",
        kind="supply",
        title="恶意 NuGet 包 Sicoob.Sdk",
        summary="投毒包收集隐私数据。",
        severity="high",
        is_supply_chain=True,
        ecosystem="nuget",
        package="Sicoob.Sdk",
        affected_versions=["[2.0.0,2.0.4]"],
        iocs=["o4511335034847232.ingest.de.sentry.io"],
        fix_versions=[],
        references=[],
        tags=["MURPHY", "MALWARE"],  # 真投毒包携带 MALWARE 标记，过投送兜底闸
        source="murphysec",
        published=f"{_TODAY}T00:00:00Z",  # 默认今天，通过冷启动新鲜度护栏
    )
    defaults.update(kw)
    return Vuln(**defaults)


def _article(**kw) -> Article:
    defaults = dict(
        id=1,
        title="Sicoob.Sdk malicious package",
        link="https://news/1",
        published="2026-05-31T01:00:00Z",
        summary="IOC hxxp://evil.example/a and 1.2.3.4",
        source_slug="socket",
        source_title="Socket",
        lang="en",
        llm_score=9,
        llm_summary_zh="恶意包连接 evil.example",
    )
    defaults.update(kw)
    return Article(**defaults)


def test_select_candidates_filters_supply_chain_and_dispatched():
    vulns = [
        _vuln(id="MURPHY-1"),
        _vuln(id="MURPHY-2"),
        _vuln(id="CVE-1", kind="cve", is_supply_chain=False),
        _vuln(id="MURPHY-3", is_supply_chain=False),
    ]
    selected = vd.select_candidates(vulns, {"MURPHY-2"}, limit=None)
    assert [v.id for v in selected] == ["MURPHY-1"]
    assert [v.id for v in vd.select_candidates(vulns, {"MURPHY-2"}, limit=None, redispatch="MURPHY-2")] == ["MURPHY-2"]


def test_select_candidates_requires_malware_tag():
    # 兜底闸：即便 kind=="supply" 且 is_supply_chain，缺 MALWARE 标记(普通依赖
    # CVE 误标供应链)也不投送。
    vulns = [
        _vuln(id="POISON", tags=["MURPHY", "MALWARE"]),
        _vuln(id="PLAIN-CVE", tags=["MURPHY"]),  # 无 MALWARE → 拦下
    ]
    assert [v.id for v in vd.select_candidates(vulns, set(), limit=None)] == ["POISON"]


def test_cold_start_guard_filters_old_vulns():
    old = "2020-01-01T00:00:00Z"
    vulns = [_vuln(id="NEW"), _vuln(id="OLD", published=old)]
    # since_days=0 → 仅今天，过滤掉历史，避免冷启动洪水
    assert [v.id for v in vd.select_candidates(vulns, set(), limit=None, since_days=0)] == ["NEW"]
    # since_days 足够大 → 历史也纳入
    assert {v.id for v in vd.select_candidates(vulns, set(), limit=None, since_days=100000)} == {"NEW", "OLD"}
    # 无日期条目在冷启动窗口下被跳过（不误投未知时间历史项）
    undated = [_vuln(id="NODATE", published=None, first_seen=None)]
    assert vd.select_candidates(undated, set(), limit=None, since_days=0) == []
    # redispatch 绕过日期护栏（强制重投历史项）
    assert [v.id for v in vd.select_candidates(vulns, set(), limit=None, since_days=0, redispatch="OLD")] == ["OLD"]


def test_find_related_news_queries_and_sorts(monkeypatch):
    calls: list[str] = []
    results = {
        "CVE-2026-1111": [_article(id=1, link="https://news/1", llm_score=7, published="2026-05-30T00:00:00Z")],
        "Sicoob.Sdk": [
            _article(id=2, link="https://news/2", llm_score=10, published="2026-05-29T00:00:00Z"),
            _article(id=1, link="https://news/1", llm_score=7, published="2026-05-30T00:00:00Z"),
        ],
        "GHSA-aaaa-bbbb-cccc": [_article(id=3, link="https://news/3", llm_score=8, published="2026-05-31T00:00:00Z")],
    }

    def fake_search(q, limit):
        calls.append(q)
        return results[q]

    monkeypatch.setattr(vd, "search_articles", fake_search)
    related = vd.find_related_news(
        _vuln(cve_id="CVE-2026-1111", ghsa_id="GHSA-aaaa-bbbb-cccc"),
        limit=5,
    )
    assert calls == ["CVE-2026-1111", "Sicoob.Sdk", "GHSA-aaaa-bbbb-cccc"]
    assert [item["url"] for item in related] == ["https://news/2", "https://news/3", "https://news/1"]
    assert [item["llm_score"] for item in related] == [10, 8, 7]


def test_merge_iocs_dedupes_structured_and_news():
    related = [{
        "summary_zh": "连接 hxxps://evil.example/a，IP 1.2.3.4，hash "
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }]
    iocs = vd.merge_iocs(_vuln(iocs=["evil.example", "o4511335034847232.ingest.de.sentry.io"]), related)
    by_value = {item["value"]: item for item in iocs}
    assert by_value["evil.example"]["source"] == "vuln"
    assert by_value["o4511335034847232.ingest.de.sentry.io"]["type"] == "domain"
    assert by_value["https://evil.example/a"]["type"] == "url"
    assert by_value["1.2.3.4"]["type"] == "ipv4"
    assert by_value["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]["type"] == "sha256"


def test_merge_iocs_excludes_package_name_and_dsn_hex_false_positive():
    dsn = "d565e3f03d0b1a7c8935d7ff94237316@o4511335034847232.ingest.de.sentry.io/123"
    related = [{"summary_zh": f"Sicoob.Sdk uses sentry DSN {dsn}"}]
    vuln = _vuln(package="Sicoob.Sdk", iocs=[dsn])
    iocs = vd.merge_iocs(vuln, related)
    by_value = {item["value"]: item for item in iocs}
    assert "sicoob.sdk" not in by_value
    assert "d565e3f03d0b1a7c8935d7ff94237316" not in by_value
    assert by_value["o4511335034847232.ingest.de.sentry.io"]["type"] == "domain"


def test_build_message_schema_and_canonical_fallback(monkeypatch):
    monkeypatch.setattr(vd.time, "time", lambda: 1730000000)
    vuln = _vuln(
        id="MURPHY-MPS-fthb-675x",
        references=[Reference(url="https://example.com/ref", label="Detail")],
        ai_summary="AI 摘要",
    )
    msg = vd.build_message(vuln, [])
    assert msg["schema_version"] == 3
    assert msg["origin"] == "vuln"
    assert msg["ref_id"] == "MURPHY-MPS-fthb-675x"
    assert msg["canonical_url"] == "https://www.oscs1024.com/hd/MPS-fthb-675x"
    # v3: 顶层无 package/affected_version，统一进 packages[]
    assert "affected_version" not in msg and "package" not in msg
    assert len(msg["packages"]) == 1
    assert msg["packages"][0]["affected_version"] == ["[2.0.0,2.0.4]"]
    assert msg["packages"][0]["fix_version"] == ""
    assert msg["summary_zh"] == "AI 摘要"
    assert msg["triage"]["actionable"] is True
    assert msg["produced_at"] == 1730000000


def test_migrate_and_mark_dispatched():
    conn = _make_db()
    vd.migrate(conn)
    msg = {"ref_id": "MURPHY-1"}
    vd.mark_dispatched(conn, "MURPHY-1", [{"title": "n"}], msg)
    row = conn.execute("SELECT * FROM vuln_dispatches WHERE vuln_id='MURPHY-1'").fetchone()
    assert row["origin"] == "vuln"
    assert json.loads(row["related_news_json"])[0]["title"] == "n"
    assert json.loads(row["message_json"]) == msg


@pytest.mark.asyncio
async def test_run_dry_run_does_not_write(monkeypatch, capsys):
    conn = _make_db()
    monkeypatch.setattr(vd.db, "connect", lambda *a, **k: conn)
    monkeypatch.setattr(vd, "all_vulns", lambda: [_vuln(id="MURPHY-1")])
    monkeypatch.setattr(vd, "find_related_news", lambda vuln: [])

    stats = await vd.run(dry_run=True)
    assert stats["dry_run"] is True
    assert stats["sent"] == 0
    assert conn.execute("SELECT COUNT(*) FROM vuln_dispatches").fetchone()[0] == 0
    assert '"schema_version": 3' in capsys.readouterr().out


@pytest.mark.asyncio
async def test_run_kafka_success_writes_idempotency(monkeypatch):
    conn = _make_db()
    monkeypatch.setattr(vd.db, "connect", lambda *a, **k: conn)
    monkeypatch.setattr(vd, "all_vulns", lambda: [_vuln(id="MURPHY-1")])
    monkeypatch.setattr(vd, "find_related_news", lambda vuln: [])

    class FakeProducer:
        async def start(self): pass
        async def stop(self): pass

    sent = []
    monkeypatch.setattr(vd, "make_producer", lambda bootstrap: FakeProducer())

    async def fake_send(producer, topic, key, msg):
        sent.append((topic, key, msg))

    monkeypatch.setattr(vd, "send", fake_send)
    stats = await vd.run(dry_run=False)
    assert stats["sent"] == 1
    assert sent[0][1] == "MURPHY-1"
    assert conn.execute("SELECT COUNT(*) FROM vuln_dispatches").fetchone()[0] == 1


@pytest.mark.asyncio
async def test_run_kafka_failure_does_not_write(monkeypatch):
    conn = _make_db()
    monkeypatch.setattr(vd.db, "connect", lambda *a, **k: conn)
    monkeypatch.setattr(vd, "all_vulns", lambda: [_vuln(id="MURPHY-1")])
    monkeypatch.setattr(vd, "find_related_news", lambda vuln: [])

    class FakeProducer:
        async def start(self): pass
        async def stop(self): pass

    monkeypatch.setattr(vd, "make_producer", lambda bootstrap: FakeProducer())

    async def fail_send(producer, topic, key, msg):
        raise RuntimeError("broker down")

    monkeypatch.setattr(vd, "send", fail_send)
    stats = await vd.run(dry_run=False)
    assert stats["errors"] == 1
    assert conn.execute("SELECT COUNT(*) FROM vuln_dispatches").fetchone()[0] == 0
