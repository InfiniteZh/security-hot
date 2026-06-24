"""Regression: news-origin 投送在抽屉里的「重建报文」必须带上与 dispatcher
build_message 一致的 schema_version（取自单一真源 dispatch_common.SCHEMA_VERSION）。

背景：news 链路只把 triage 结论持久化到 articles.poisoning_triage_json，不存完整
Kafka 报文；抽屉展示时按 build_message 的字段拼一份等价报文。此前重建错误地
`triage.get("schema_version")` —— schema_version 是报文信封字段、不在 triage 里，
于是呈现 schema_version=null。本测试钉住「重建报文带真源版本号」这一行为。

跑：uv run pytest tests/test_news_dispatch_reconstruct.py -v
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from backend.app import cache_io  # noqa: E402
from backend.app.news import query  # noqa: E402
from dispatch_common import SCHEMA_VERSION  # noqa: E402

# triage 故意不含 schema_version —— 复刻真实落库内容（信封字段不属于 triage）。
_TRIAGE = {
    "actionable": True,
    "packages": [{"ecosystem": "npm", "package": "evil-pkg", "versions": ["1.0.0"]}],
    "iocs": [],
    "reason": "恶意包",
    "source_tier": "tier1",
}


def _make_news_db(path: Path) -> None:
    """构造仅含一条 poisoning-dispatched 文章的最小 news.db。"""
    conn = sqlite3.connect(str(path))
    conn.execute("""
        CREATE TABLE articles (
            id INTEGER PRIMARY KEY,
            title TEXT,
            canonical_url TEXT,
            llm_score INTEGER,
            poisoning_dispatched INTEGER DEFAULT 0,
            poisoning_triage_json TEXT,
            poisoning_dispatched_at TEXT
        )""")
    conn.execute(
        """INSERT INTO articles
           (id, title, canonical_url, llm_score, poisoning_dispatched,
            poisoning_triage_json, poisoning_dispatched_at)
           VALUES (?,?,?,?,?,?,?)""",
        (20110, "Evil pkg published", "https://socket.dev/blog/evil", 8, 1,
         json.dumps(_TRIAGE, ensure_ascii=False), "2026-06-21T21:00:12"),
    )
    conn.commit()
    conn.close()


@pytest.fixture
def news_db(tmp_path, monkeypatch):
    path = tmp_path / "news.db"
    _make_news_db(path)
    monkeypatch.setattr(cache_io, "_NEWS_DB", path)
    cache_io._state.clear()  # 避开 mtime 缓存命中
    yield path
    cache_io._state.clear()


def test_news_reconstruction_carries_schema_version(news_db):
    entries = query.load_dispatches(origin="news")
    assert len(entries) == 1
    msg = entries[0].message
    # 回归点：此前为 None（triage.get 取空），修复后等于真源常量。
    assert msg["schema_version"] is not None
    assert msg["schema_version"] == SCHEMA_VERSION == 3


def test_news_reconstruction_mirrors_build_message_envelope(news_db):
    """重建报文的信封字段与业务字段须与 dispatcher 的 build_message 对齐。"""
    msg = query.load_dispatches(origin="news")[0].message
    assert msg["kind"] == "poisoning_intel"
    assert msg["origin"] == "news"
    assert msg["source"] == "security-hot"
    # 业务数据来自 triage，经 _normalize_packages 归一后透传。
    assert msg["packages"] == [
        {"ecosystem": "npm", "package": "evil-pkg", "versions": ["1.0.0"], "fix_version": ""}
    ]
