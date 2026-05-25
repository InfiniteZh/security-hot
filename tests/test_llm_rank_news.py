"""llm_rank.py: classify/summarize/brief tests against SQLite."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import db  # noqa: E402


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
