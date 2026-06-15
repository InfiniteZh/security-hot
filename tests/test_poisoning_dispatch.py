"""poisoning_dispatch 单测（全 mock，不连真 broker / 不调真 LLM）。

跑：uv run pytest tests/test_poisoning_dispatch.py -v
"""
from __future__ import annotations

import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(_SCRIPTS))

spec = importlib.util.spec_from_file_location("poisoning_dispatch", _SCRIPTS / "poisoning_dispatch.py")
pd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pd)


class _NoCloseConn(sqlite3.Connection):
    """run() 会 close() 连接（正确行为）；测试用 :memory: 库需在 run 后断言，故屏蔽 close。"""
    def close(self):  # noqa: D102
        pass


def _make_db(tmp_path) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", factory=_NoCloseConn)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE articles (
            id INTEGER PRIMARY KEY, canonical_url TEXT UNIQUE, title TEXT,
            summary TEXT, llm_summary_zh TEXT, llm_score INTEGER, llm_category TEXT,
            is_relevant INTEGER,
            published TEXT, source_title TEXT
        )""")
    return conn


def _insert(conn, **kw):
    cols = ["canonical_url", "title", "summary", "llm_summary_zh", "llm_score",
            "llm_category", "is_relevant", "published",
            "source_title"]
    defaults = dict(canonical_url="https://x/1", title="t", summary="s", llm_summary_zh="zh",
                    llm_score=10, llm_category="supply-chain", is_relevant=1,
                    published="2026-05-29",
                    source_title="Socket")
    defaults.update(kw)
    conn.execute(
        f"INSERT INTO articles ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
        [defaults[c] for c in cols],
    )
    conn.commit()


# ── migration ─────────────────────────────────────────

def test_migrate_adds_columns(tmp_path):
    conn = _make_db(tmp_path)
    pd.migrate(conn)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(articles)")}
    assert {"poisoning_dispatched", "poisoning_triage_json", "poisoning_dispatched_at"} <= cols
    pd.migrate(conn)  # 幂等：再跑不报错


# ── L0 候选选取 ────────────────────────────────────────

def test_select_candidates_filters(tmp_path):
    conn = _make_db(tmp_path); pd.migrate(conn)
    _insert(conn, canonical_url="https://x/ok", llm_score=10)                      # ✓
    _insert(conn, canonical_url="https://x/low", llm_score=6)                       # ✗ 低分
    _insert(conn, canonical_url="https://x/cat", llm_category="incident", llm_score=10)  # ✗ 非投毒
    _insert(conn, canonical_url="https://x/irr", is_relevant=0, llm_score=10)       # ✗ 不相关
    rows = pd.select_candidates(conn, fresh_days=30, limit=None)
    urls = {r["canonical_url"] for r in rows}
    assert urls == {"https://x/ok"}


def test_select_candidates_tier1_lower_threshold(tmp_path):
    conn = _make_db(tmp_path); pd.migrate(conn)
    for source in pd.TIER1_SUPPLY_SOURCES:
        slug = source.lower().replace(" ", "-").replace(".", "").replace("/", "-")
        _insert(conn, canonical_url=f"https://x/tier1-{slug}", llm_score=7, source_title=source)
    _insert(conn, canonical_url="https://x/other", llm_score=7, source_title="Other")
    rows = pd.select_candidates(conn, fresh_days=30, limit=None)
    assert {r["source_title"] for r in rows} == pd.TIER1_SUPPLY_SOURCES


def test_select_candidates_ignores_tier2_sources_for_now(tmp_path):
    conn = _make_db(tmp_path); pd.migrate(conn)
    for source in pd.TIER2_SUPPLY_SOURCES:
        slug = source.lower().replace(" ", "-").replace(".", "").replace("/", "-")
        _insert(conn, canonical_url=f"https://x/tier2-{slug}", llm_score=10, source_title=source)

    rows = pd.select_candidates(conn, fresh_days=30, limit=None)

    assert rows == []


def test_select_candidates_includes_safedep_article_url(tmp_path):
    conn = _make_db(tmp_path); pd.migrate(conn)
    url = "https://safedep.io/malicious-faster-axios-npm-epsilon-stealer/"
    _insert(conn, canonical_url=url, source_title="SafeDep", title="faster-axios Epsilon stealer", llm_score=8)

    rows = pd.select_candidates(conn, fresh_days=30, limit=None)

    assert [r["canonical_url"] for r in rows] == [url]


def test_select_candidates_excludes_dispatched(tmp_path):
    conn = _make_db(tmp_path); pd.migrate(conn)
    _insert(conn, canonical_url="https://x/a", llm_score=9)
    conn.execute("UPDATE articles SET poisoning_dispatched=1 WHERE canonical_url='https://x/a'")
    conn.commit()
    assert pd.select_candidates(conn, fresh_days=30, limit=None) == []


# ── 消息构造 ───────────────────────────────────────────

def test_build_message_schema(tmp_path):
    conn = _make_db(tmp_path); pd.migrate(conn)
    _insert(conn, canonical_url="https://x/p", title="noon-contracts RAT", llm_score=10)
    row = list(conn.execute("SELECT * FROM articles"))[0]
    tri = {"actionable": True,
           "packages": [{"ecosystem": "npm", "package": "noon-contracts", "versions": []}],
           "iocs": [], "reason": "点名 npm 包"}
    msg = pd.build_message(row, tri, "完整正文")
    assert msg["schema_version"] == 3
    assert msg["kind"] == "poisoning_intel"
    assert msg["origin"] == "news"
    assert msg["ref_id"] == row["id"]
    assert msg["article_id"] == row["id"]
    assert msg["canonical_url"] == "https://x/p"
    # v3: 顶层无 package/affected_version，统一进 packages[]
    assert "package" not in msg and "affected_version" not in msg
    assert msg["packages"] == [{"ecosystem": "npm", "package": "noon-contracts",
                                "affected_version": [], "fix_version": ""}]
    assert msg["full_body"] == "完整正文"


def test_build_message_multi_package_and_versions(tmp_path):
    """一篇列多个包+多版本：全部进 packages[]，逐元素校验后保留有效版本。"""
    conn = _make_db(tmp_path); pd.migrate(conn)
    _insert(conn, canonical_url="https://x/multi", title="Red Hat npm worm", llm_score=10)
    row = list(conn.execute("SELECT * FROM articles"))[0]
    tri = {"actionable": True, "packages": [
        {"ecosystem": "npm", "package": "@redhat-cloud-services/types",
         "versions": "3.6.1,3.6.2,3.6.4"},                       # 逗号多版本
        {"ecosystem": "npm", "package": "@redhat-cloud-services/chrome",
         "versions": ["2.3.1"]},
        {"ecosystem": "npm", "package": "bad pkg name (prose)", "versions": []},  # 非法包名→剔除
    ], "iocs": [], "reason": "多包"}
    msg = pd.build_message(row, tri, "")
    pkgs = {p["package"]: p for p in msg["packages"]}
    assert set(pkgs) == {"@redhat-cloud-services/types", "@redhat-cloud-services/chrome"}
    assert pkgs["@redhat-cloud-services/types"]["affected_version"] == ["3.6.1", "3.6.2", "3.6.4"]
    assert pkgs["@redhat-cloud-services/chrome"]["affected_version"] == ["2.3.1"]


def test_iocs_drop_legit_infra_trongrid(tmp_path):
    """合法基础设施（trongrid.io / api.trongrid.io）不得当 IOC 投出。"""
    conn = _make_db(tmp_path); pd.migrate(conn)
    _insert(conn, canonical_url="https://x/php", title="Famous Chollima PHP", llm_score=8)
    row = list(conn.execute("SELECT * FROM articles"))[0]
    tri = {"actionable": True,
           "packages": [{"ecosystem": "packagist", "package": "roberts/leads", "versions": []}],
           "iocs": ["trongrid.io", "api.trongrid.io", "evil-c2.example"], "reason": "x"}
    msg = pd.build_message(row, tri, "")
    ioc_vals = {i["value"] for i in msg["iocs"]}
    assert "trongrid.io" not in ioc_vals
    assert "api.trongrid.io" not in ioc_vals
    assert "evil-c2.example" in ioc_vals   # 真 IOC 仍保留


def test_message_iocs_excludes_package_name_and_dsn_hex_false_positive():
    dsn = "d565e3f03d0b1a7c8935d7ff94237316@o4511335034847232.ingest.de.sentry.io/123"
    iocs = pd._message_iocs([f"Sicoob.Sdk {dsn}"], exclude_names={"Sicoob.Sdk"})
    values = {item["value"] for item in iocs}
    assert "sicoob.sdk" not in values
    assert "d565e3f03d0b1a7c8935d7ff94237316" not in values
    assert "o4511335034847232.ingest.de.sentry.io" in values


# ── 净化：剔除散文/文件名/commit/账号噪声（这是本次治理的核心）────────

def test_message_iocs_drops_prose_and_filenames():
    """LLM 塞进来的非失陷指标——文件名、文件路径、算法描述、家族名——全部丢弃。"""
    junk = ["index.js 4.2MB", "/tmp/p*.js", "ROT-21+AES-128-GCM", "Miasma",
            "RedHatInsights/javascript-clients"]
    iocs = pd._message_iocs(junk)
    assert iocs == []  # 无一可识别为真实 IOC 类型


def test_message_iocs_drops_advisory_commit_and_account():
    """advisory 自身 commit hash / 报告人账号带注解词 → 整条丢弃。"""
    vals = ["ed851ff141e13db6dd7c16a3d4f1b3b92eb9fa6a917f5243ba22ccb933554e43 (source commit)",
            "kam193 (source account)"]
    assert pd._message_iocs(vals) == []


def test_message_iocs_keeps_real_iocs():
    iocs = pd._message_iocs(["evil-c2.example", "1.2.3.4",
                             "https://malware.test/drop"])
    by_type = {i["type"] for i in iocs}
    assert by_type == {"domain", "ipv4", "url"}


def test_clean_fields_rejects_prose_package_and_version():
    tri = {"actionable": True, "packages": [
        {"ecosystem": "", "package": "Redhat cloud services npm namespace (Miasma worm)",
         "versions": "95 versions"}], "iocs": []}
    packages, iocs = pd.clean_fields(tri)
    assert packages == [] and iocs == []
    assert pd.should_dispatch(tri) is False  # 净化后无 package 无 IOC → 不投


def test_clean_fields_keeps_valid_package_and_version():
    tri = {"actionable": True, "packages": [
        {"ecosystem": "npm", "package": "@redhat-cloud-services/chrome",
         "versions": ["4.0.4"]}], "iocs": []}
    packages, iocs = pd.clean_fields(tri)
    assert len(packages) == 1
    assert packages[0]["package"] == "@redhat-cloud-services/chrome"
    assert packages[0]["affected_version"] == ["4.0.4"]
    assert pd.should_dispatch(tri) is True


def test_valid_versions_splits_and_validates():
    from dispatch_common import valid_versions
    assert valid_versions("3.6.1,3.6.2,3.6.4") == ["3.6.1", "3.6.2", "3.6.4"]
    assert valid_versions(["1.0.0", "1.0.0", "bad ver"]) == ["1.0.0"]   # 去重 + 剔散文
    assert valid_versions("多个版本") == []
    assert valid_versions("dev-drewroberts/feature/test-case") == []   # git 分支引用→空


def test_select_candidates_only_tier1_sources(tmp_path):
    conn = _make_db(tmp_path); pd.migrate(conn)
    _insert(conn, canonical_url="https://x/socket", source_title="Socket", llm_score=8)
    _insert(conn, canonical_url="https://x/safedep", source_title="SafeDep", llm_score=8)
    _insert(conn, canonical_url="https://x/stepsecurity", source_title="StepSecurity", llm_score=8)
    _insert(conn, canonical_url="https://x/endor", source_title="Endor Labs", llm_score=8)
    _insert(conn, canonical_url="https://x/aikido", source_title="Aikido", llm_score=8)
    _insert(conn, canonical_url="https://x/defend", source_title="defend.network", llm_score=8)
    _insert(conn, canonical_url="https://x/thn", source_title="The Hacker News", llm_score=10)
    rows = pd.select_candidates(conn, fresh_days=30, limit=None)
    assert {r["canonical_url"] for r in rows} == {
        "https://x/socket",
        "https://x/safedep",
        "https://x/stepsecurity",
        "https://x/endor",
        "https://x/aikido",
        "https://x/defend",
    }


# ── 端到端 run（mock LLM + producer + httpx）──────────

@pytest.mark.asyncio
async def test_run_actionable_sends_and_marks(tmp_path, monkeypatch):
    conn = _make_db(tmp_path); pd.migrate(conn)
    _insert(conn, canonical_url="https://x/act", llm_score=10)
    monkeypatch.setattr(pd.db, "connect", lambda *a, **k: conn)
    monkeypatch.setattr(pd, "_get_config", lambda: {
        "api_key": "k", "base_url": "http://llm", "model": "m", "timeout": 5})
    # triage → actionable
    async def fake_triage(client, cfg, row, body=""):
        return {"actionable": True,
                "packages": [{"ecosystem": "npm", "package": "noon-contracts", "versions": []}],
                "iocs": [], "reason": "ok"}
    monkeypatch.setattr(pd, "triage", fake_triage)
    async def fake_fetch(client, url):
        return "full body text"
    monkeypatch.setattr(pd, "fetch_body", fake_fetch)

    sent = []
    class FakeProducer:
        async def start(self): pass
        async def stop(self): pass
        async def send_and_wait(self, topic, key, value):
            sent.append((topic, key, value))
    import aiokafka
    monkeypatch.setattr(aiokafka, "AIOKafkaProducer", lambda **kw: FakeProducer())

    stats = await pd.run(fresh_days=30, limit=None, dry_run=False)
    assert stats["sent"] == 1
    assert len(sent) == 1
    # 已标记 dispatched
    assert list(conn.execute("SELECT poisoning_dispatched FROM articles"))[0][0] == 1


@pytest.mark.asyncio
async def test_run_not_actionable_marks_without_send(tmp_path, monkeypatch):
    conn = _make_db(tmp_path); pd.migrate(conn)
    _insert(conn, canonical_url="https://x/trend", llm_score=10)
    monkeypatch.setattr(pd.db, "connect", lambda *a, **k: conn)
    monkeypatch.setattr(pd, "_get_config", lambda: {
        "api_key": "k", "base_url": "http://llm", "model": "m", "timeout": 5})
    async def fake_triage(client, cfg, row, body=""):
        return {"actionable": False, "reason": "纯趋势", "packages": [], "iocs": []}
    monkeypatch.setattr(pd, "triage", fake_triage)
    async def fake_fetch(client, url): return "body"
    monkeypatch.setattr(pd, "fetch_body", fake_fetch)

    sent = []
    class FakeProducer:
        async def start(self): pass
        async def stop(self): pass
        async def send_and_wait(self, **kw): sent.append(kw)
    import aiokafka
    monkeypatch.setattr(aiokafka, "AIOKafkaProducer", lambda **kw: FakeProducer())

    stats = await pd.run(fresh_days=30, limit=None, dry_run=False)
    assert stats["sent"] == 0
    assert stats["skipped_not_actionable"] == 1
    assert sent == []
    # 非可处置也标记 dispatched，避免反复 triage
    assert list(conn.execute("SELECT poisoning_dispatched FROM articles"))[0][0] == 1


@pytest.mark.asyncio
async def test_run_actionable_without_package_or_ioc_marks_without_send(tmp_path, monkeypatch):
    conn = _make_db(tmp_path); pd.migrate(conn)
    _insert(conn, canonical_url="https://x/generic", llm_score=10)
    monkeypatch.setattr(pd.db, "connect", lambda *a, **k: conn)
    monkeypatch.setattr(pd, "_get_config", lambda: {
        "api_key": "k", "base_url": "http://llm", "model": "m", "timeout": 5})

    async def fake_triage(client, cfg, row, body=""):
        return {"actionable": True, "packages": [], "iocs": [], "reason": "泛泛分析"}

    monkeypatch.setattr(pd, "triage", fake_triage)
    async def fake_fetch(client, url): return "body"
    monkeypatch.setattr(pd, "fetch_body", fake_fetch)

    sent = []
    class FakeProducer:
        async def start(self): pass
        async def stop(self): pass
        async def send_and_wait(self, topic, key, value): sent.append((topic, key, value))
    import aiokafka
    monkeypatch.setattr(aiokafka, "AIOKafkaProducer", lambda **kw: FakeProducer())

    stats = await pd.run(fresh_days=30, limit=None, dry_run=False)
    assert stats["sent"] == 0
    assert sent == []
    assert list(conn.execute("SELECT poisoning_dispatched FROM articles"))[0][0] == 1


@pytest.mark.asyncio
async def test_run_dry_run_no_side_effects(tmp_path, monkeypatch, capsys):
    conn = _make_db(tmp_path); pd.migrate(conn)
    _insert(conn, canonical_url="https://x/dry", llm_score=10)
    monkeypatch.setattr(pd.db, "connect", lambda *a, **k: conn)
    monkeypatch.setattr(pd, "_get_config", lambda: {
        "api_key": "k", "base_url": "http://llm", "model": "m", "timeout": 5})
    async def fake_triage(client, cfg, row, body=""):
        return {"actionable": True,
                "packages": [{"ecosystem": "npm", "package": "p", "versions": []}],
                "iocs": [], "reason": "ok"}
    monkeypatch.setattr(pd, "triage", fake_triage)
    async def fake_fetch(client, url): return "body"
    monkeypatch.setattr(pd, "fetch_body", fake_fetch)

    stats = await pd.run(fresh_days=30, limit=None, dry_run=True)
    assert stats["dry_run"] is True
    assert stats["sent"] == 0
    # dry-run 不改库
    assert list(conn.execute("SELECT poisoning_dispatched FROM articles"))[0][0] in (0, None)
