"""llm_rank.py: classify/summarize/brief tests against SQLite."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import db  # noqa: E402


def test_llm_config_default_concurrency_is_8(monkeypatch):
    from backend.app.ingest.llm import client as llm_client

    monkeypatch.delenv("LLM_CONCURRENCY", raising=False)

    assert llm_client._get_config()["concurrency"] == 8


@pytest.mark.asyncio
async def test_llm_call_uses_requested_concurrency(monkeypatch):
    from backend.app.ingest.llm import client as llm_client

    seen = {}

    class FakeSemaphore:
        async def __aenter__(self):
            seen["entered"] = True

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def fake_post(*args, **kwargs):
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"choices": [{"message": {"content": "{\"ok\": true}"}}]},
        )

    def fake_sem(limit):
        seen["limit"] = limit
        return FakeSemaphore()

    monkeypatch.setattr(llm_client, "_llm_semaphore", fake_sem)
    fake_client = SimpleNamespace(post=fake_post)

    result = await llm_client._llm_call(
        fake_client, "system", "user", "https://llm.test/v1", "key", "model", 5,
        max_concurrency=12,
    )

    assert result == {"ok": True}
    assert seen == {"limit": 12, "entered": True}


@pytest.fixture
def db_with_unscored_articles(tmp_db):
    db.init_schema(db.connect(tmp_db))
    c = db.connect(tmp_db)
    for i in range(3):
        db.upsert_article(c, {
            "canonical_url": f"https://x.com/{i}", "title": f"Article {i}",
            "summary": "Security disclosure", "source_slug": "x",
            "source_title": "X", "lang": "en", "published": "2026-05-25T10:00:00Z",
            "fetched_at": "2026-05-25T11:00:00Z", "first_seen_date": "2026-05-25",
        })
    c.close()
    return tmp_db


@pytest.mark.asyncio
async def test_classify_news_updates_only_unscored(db_with_unscored_articles, monkeypatch):
    """classify_news must only touch articles where llm_score IS NULL."""
    tmp_db_path = db_with_unscored_articles
    # Pre-score one article so it's skipped
    c = db.connect(tmp_db_path)
    c.execute("UPDATE articles SET llm_score=9 WHERE canonical_url=?",
              ["https://x.com/0"])
    c.commit()
    c.close()

    # Mock the LLM call to return canned scores for ids 1 and 2
    import llm_rank
    async def fake_llm_call(client, system_prompt, user_msg, *args, **kwargs):
        # Look at user_msg to figure out which ids are in the batch
        ids_in_msg = []
        for line in user_msg.split("\n"):
            if line.startswith("id="):
                try:
                    ids_in_msg.append(int(line.split("|")[0].replace("id=", "").strip()))
                except (ValueError, IndexError):
                    pass
        items = []
        for i, art_id in enumerate(ids_in_msg):
            items.append({
                "id": art_id,
                "score": 7 if i == 0 else 0,
                "category": "vuln" if i == 0 else None,
                "is_relevant": i == 0,  # first → relevant, others → off-topic
                "reason": "test reason",
            })
        return {"items": items}

    monkeypatch.setattr(llm_rank, "_llm_call", fake_llm_call)
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", tmp_db_path)
    monkeypatch.setenv("LLM_API_KEY", "fake")

    await llm_rank.classify_news(days=30, verbose=False)

    c = db.connect(tmp_db_path)
    rows = list(c.execute("SELECT canonical_url, llm_score, is_relevant FROM articles ORDER BY canonical_url"))
    # Article 0 untouched (pre-scored)
    assert rows[0]["llm_score"] == 9
    # Articles 1 and 2 scored
    assert rows[1]["llm_score"] is not None
    assert rows[2]["llm_score"] is not None
    # is_relevant set
    relevants = [r["is_relevant"] for r in rows[1:]]
    assert any(r == 0 for r in relevants)
    assert any(r == 1 for r in relevants)
    c.close()


@pytest.mark.asyncio
async def test_classify_reports_partial_llm_batches(db_with_unscored_articles, monkeypatch):
    tmp_db_path = db_with_unscored_articles

    import llm_rank

    async def fake_llm_call(client, system_prompt, user_msg, *args, **kwargs):
        first_id = None
        for line in user_msg.split("\n"):
            if line.startswith("id="):
                first_id = int(line.split("|")[0].replace("id=", "").strip())
                break
        return {"items": [{
            "id": first_id,
            "score": 7,
            "category": "vuln",
            "is_relevant": True,
            "reason": "test reason",
        }]}

    monkeypatch.setattr(llm_rank, "_llm_call", fake_llm_call)
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", tmp_db_path)
    monkeypatch.setenv("LLM_API_KEY", "fake")
    monkeypatch.setenv("LLM_BATCH_SIZE", "80")

    result = await llm_rank.classify_news(days=30, verbose=False)

    assert result["requested"] == 3
    assert result["classified"] == 1
    assert result["errors"] == 0
    assert result["partial_batches"] == 1

    c = db.connect(tmp_db_path)
    rows = list(c.execute("SELECT llm_score FROM articles ORDER BY id"))
    assert rows[0]["llm_score"] == 7
    assert rows[1]["llm_score"] is None
    assert rows[2]["llm_score"] is None
    c.close()


@pytest.mark.asyncio
async def test_summarize_only_processes_relevant_high_score(tmp_db, monkeypatch):
    db.init_schema(db.connect(tmp_db))
    c = db.connect(tmp_db)
    # Insert mix: en+high+relevant ✓, en+low ✗, en+high+irrelevant ✗, zh+high+relevant ✓
    cases = [
        ("https://x.com/1", "Big RCE", "en", 9, 1),    # ✓ should be summarized
        ("https://x.com/2", "Small bug", "en", 3, 1),  # ✗ low score
        ("https://x.com/3", "Off-topic", "en", 8, 0),  # ✗ irrelevant
        ("https://x.com/4", "中文文章", "zh", 9, 1),    # ✓ should be summarized
    ]
    ids = []
    for url, title, lang, score, rel in cases:
        rowid = db.upsert_article(c, {
            "canonical_url": url, "title": title, "summary": "",
            "source_slug": "x", "source_title": "X", "lang": lang,
            "published": "2026-05-25T10:00:00Z",
            "fetched_at": "2026-05-25T11:00:00Z", "first_seen_date": "2026-05-25",
        })
        c.execute("UPDATE articles SET llm_score=?, is_relevant=? WHERE id=?",
                  [score, rel, rowid])
        ids.append(rowid)
    c.commit()
    c.close()

    import llm_rank
    async def fake_llm(client, system, user, *args, **kwargs):
        return {"items": [
            {"id": ids[0], "summary": "中文摘要：远程代码执行漏洞"},
            {"id": ids[3], "summary": "中文摘要：中文文章提炼"},
        ]}
    monkeypatch.setattr(llm_rank, "_llm_call", fake_llm)
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", tmp_db)
    monkeypatch.setenv("LLM_API_KEY", "fake")

    result = await llm_rank.summarize_news(min_score=5, days=30, verbose=False)

    assert result["requested"] == 2
    assert result["summarized"] == 2
    assert result["errors"] == 0
    assert result["partial_batches"] == 0

    c = db.connect(tmp_db)
    rows = list(c.execute("SELECT canonical_url, llm_summary_zh FROM articles ORDER BY id"))
    assert rows[0]["llm_summary_zh"] == "中文摘要：远程代码执行漏洞"
    assert rows[1]["llm_summary_zh"] is None
    assert rows[2]["llm_summary_zh"] is None
    assert rows[3]["llm_summary_zh"] == "中文摘要：中文文章提炼"
    c.close()


@pytest.mark.asyncio
async def test_summarize_reports_partial_llm_batches(tmp_db, monkeypatch):
    db.init_schema(db.connect(tmp_db))
    c = db.connect(tmp_db)
    ids = []
    for i in range(2):
        rowid = db.upsert_article(c, {
            "canonical_url": f"https://x.com/partial-{i}",
            "title": f"High score article {i}",
            "summary": "Security disclosure",
            "source_slug": "x",
            "source_title": "X",
            "lang": "en",
            "published": "2026-05-25T10:00:00Z",
            "fetched_at": "2026-05-25T11:00:00Z",
            "first_seen_date": "2026-05-25",
        })
        c.execute("UPDATE articles SET llm_score=8, is_relevant=1 WHERE id=?", [rowid])
        ids.append(rowid)
    c.commit()
    c.close()

    import llm_rank

    async def fake_llm(client, system, user, *args, **kwargs):
        return {"items": [{"id": ids[0], "summary": "中文摘要：第一篇"}]}

    monkeypatch.setattr(llm_rank, "_llm_call", fake_llm)
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", tmp_db)
    monkeypatch.setenv("LLM_API_KEY", "fake")
    monkeypatch.setenv("LLM_BATCH_SIZE", "30")

    result = await llm_rank.summarize_news(min_score=5, days=30, verbose=False)

    assert result["requested"] == 2
    assert result["summarized"] == 1
    assert result["errors"] == 0
    assert result["partial_batches"] == 1

    c = db.connect(tmp_db)
    rows = list(c.execute("SELECT id, llm_summary_zh FROM articles ORDER BY id"))
    assert rows[0]["llm_summary_zh"] == "中文摘要：第一篇"
    assert rows[1]["llm_summary_zh"] is None
    c.close()


@pytest.mark.asyncio
async def test_generate_daily_brief_covers_all_5_categories(tmp_db, monkeypatch):
    db.init_schema(db.connect(tmp_db))
    c = db.connect(tmp_db)
    # Seed 1 article per category on 2026-05-25
    for i, cat in enumerate(["incident", "vuln", "supply-chain", "research", "industry"]):
        rid = db.upsert_article(c, {
            "canonical_url": f"https://x.com/{i}", "title": f"{cat} story",
            "summary": "...", "source_slug": "x", "source_title": "X",
            "lang": "zh", "published": "2026-05-25T10:00:00Z",
            "fetched_at": "2026-05-25T11:00:00Z", "first_seen_date": "2026-05-25",
        })
        c.execute(
            "UPDATE articles SET llm_score=7, llm_category=?, is_relevant=1 WHERE id=?",
            [cat, rid],
        )
    c.commit()
    c.close()

    import llm_rank
    async def fake_llm(client, system, user, *args, **kwargs):
        # Echo the category back
        cat = "unknown"
        for c2 in ["incident", "vuln", "supply-chain", "research", "industry"]:
            if c2 in user:
                cat = c2
                break
        return {"text": f"今日{cat}摘要 ..."}
    monkeypatch.setattr(llm_rank, "_llm_call", fake_llm)
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", tmp_db)
    monkeypatch.setenv("LLM_API_KEY", "fake")

    result = await llm_rank.generate_daily_brief(target_date="2026-05-25", verbose=False)

    c = db.connect(tmp_db)
    rows = list(c.execute(
        "SELECT category, article_count FROM daily_briefs WHERE date = ? ORDER BY category",
        ["2026-05-25"],
    ))
    cats = {r["category"] for r in rows}
    assert cats == {"incident", "vuln", "supply-chain", "research", "industry"}
    c.close()


@pytest.mark.asyncio
async def test_generate_daily_brief_includes_all_articles_in_category(tmp_db, monkeypatch):
    db.init_schema(db.connect(tmp_db))
    c = db.connect(tmp_db)
    for i in range(13):
        rid = db.upsert_article(c, {
            "canonical_url": f"https://x.com/vuln-{i}", "title": f"vuln story {i}",
            "summary": f"summary {i}", "source_slug": "x", "source_title": "X",
            "lang": "zh", "published": "2026-05-25T10:00:00Z",
            "fetched_at": "2026-05-25T11:00:00Z", "first_seen_date": "2026-05-25",
        })
        c.execute(
            "UPDATE articles SET llm_score=7, llm_category='vuln', is_relevant=1 WHERE id=?",
            [rid],
        )
    c.commit()
    c.close()

    import llm_rank
    seen = {}

    async def fake_llm(client, system, user, *args, **kwargs):
        seen["user"] = user
        return {"text": "漏洞简报"}

    monkeypatch.setattr(llm_rank, "_llm_call", fake_llm)
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", tmp_db)
    monkeypatch.setenv("LLM_API_KEY", "fake")

    await llm_rank.generate_daily_brief(target_date="2026-05-25", verbose=False)

    assert seen["user"].count("vuln story") == 13
    c = db.connect(tmp_db)
    row = c.execute(
        "SELECT article_count FROM daily_briefs WHERE date = ? AND category = 'vuln'",
        ["2026-05-25"],
    ).fetchone()
    assert row["article_count"] == 13
    c.close()
