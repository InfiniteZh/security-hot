# Vuln Data Slimming + News→Vuln Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** (1) Reduce OSV cache from 228MB to <2MB by filtering at fetch time; (2) Trim EPSS from 334k entries to only CVEs we reference; (3) Bridge CVE-mentioning news articles into the vuln tab so vulners/vuldb/sploitus CVEs appear in vulnerability intelligence.

**Architecture:** The OSV fetcher already downloads full ecosystem zips — we add a filter inside `_fetch_one_osv_ecosystem` to skip non-malware entries before writing JSON. EPSS gets a post-fetch trim step that keeps only CVE-IDs present in other vuln sources + news. The news→vuln bridge reads CVE-IDs from `news.db` articles (limited to vuln-focused RSS sources) and synthesizes lightweight `Vuln` objects that merge into the existing `all_vulns()` pipeline.

**Tech Stack:** Python, SQLite, FastAPI, existing codebase patterns

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `scripts/fetch_data.py` | Modify | OSV: filter to malware-only at write time; EPSS: add post-fetch trim function |
| `backend/app/data.py` | Modify | Add `_news_cve_to_vulns()` bridge; wire into `all_vulns()` |
| `tests/test_fetch_data_news.py` | Modify | Add tests for OSV slim + EPSS trim |
| `tests/test_vuln_bridge.py` | Create | Tests for news→vuln bridge |

---

### Task 1: OSV Fetcher — Filter to Malware-Only at Write Time

**Files:**
- Modify: `scripts/fetch_data.py:848-870` (`_fetch_one_osv_ecosystem`)

Currently `_fetch_one_osv_ecosystem` normalizes every entry in the zip and writes all of them. We filter to `is_malware=True` entries only, since `_osv_malware_to_vulns()` in data.py already discards non-malware entries anyway.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_fetch_data_news.py — append to existing file

import json
import zipfile
import io


def _make_osv_zip(entries: list[dict]) -> bytes:
    """Build an in-memory zip with one JSON file per entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i, e in enumerate(entries):
            zf.writestr(f"{e.get('id', f'entry-{i}')}.json", json.dumps(e))
    return buf.getvalue()


@pytest.mark.asyncio
async def test_osv_fetcher_only_stores_malware(tmp_path, monkeypatch):
    """OSV fetcher must discard non-malware entries at write time."""
    import scripts.fetch_data as fd

    malware_entry = {
        "id": "MAL-2026-1234",
        "summary": "Malicious npm package",
        "affected": [{"package": {"name": "@evil/pkg", "ecosystem": "npm"}}],
        "database_specific": {"type": "malware"},
        "published": "2026-05-25T00:00:00Z",
        "modified": "2026-05-25T00:00:00Z",
    }
    normal_entry = {
        "id": "GHSA-xxxx-yyyy",
        "summary": "Normal vulnerability",
        "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}}],
        "published": "2026-05-24T00:00:00Z",
        "modified": "2026-05-24T00:00:00Z",
    }
    zip_bytes = _make_osv_zip([malware_entry, normal_entry])

    monkeypatch.setattr(fd, "CACHE", tmp_path)

    class FakeResp:
        status_code = 200
        content = zip_bytes
        def raise_for_status(self): pass

    class FakeClient:
        async def get(self, *a, **kw):
            return FakeResp()

    count = await fd._fetch_one_osv_ecosystem(FakeClient(), "npm")
    written = json.loads((tmp_path / "osv-npm.json").read_text())
    assert count == 1, f"expected 1 malware entry, got {count}"
    assert len(written["items"]) == 1
    assert written["items"][0]["id"] == "MAL-2026-1234"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_fetch_data_news.py::test_osv_fetcher_only_stores_malware -xvs`
Expected: FAIL — currently the fetcher stores both entries (count=2).

- [ ] **Step 3: Implement the malware-only filter**

In `scripts/fetch_data.py`, modify `_fetch_one_osv_ecosystem` (line ~848):

```python
async def _fetch_one_osv_ecosystem(client: httpx.AsyncClient, ecosystem: str) -> int:
    url = _osv_ecosystem_url(ecosystem)
    r = await client.get(url, headers=HEADERS, timeout=180)
    r.raise_for_status()
    items: list[dict] = []
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                raw = json.loads(zf.read(name))
            except (json.JSONDecodeError, OSError):
                continue
            entry = _normalize_osv_entry(raw)
            if entry.get("is_malware"):
                items.append(entry)
    items.sort(key=lambda x: x.get("modified", ""), reverse=True)
    out = {
        "ecosystem": ecosystem,
        "items": items,
        "count": len(items),
        "fetched_at": now_iso(),
    }
    write_json(f"osv-{ecosystem.lower()}.json", out)
    return len(items)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_fetch_data_news.py::test_osv_fetcher_only_stores_malware -xvs`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/fetch_data.py tests/test_fetch_data_news.py
git commit -m "fix(osv): filter to malware-only at fetch time (204MB → <2MB)"
```

---

### Task 2: EPSS — Trim to Referenced CVEs Only

**Files:**
- Modify: `scripts/fetch_data.py:733-789` (`fetch_epss`)

After fetching the full EPSS CSV, cross-reference against CVE-IDs present in KEV, GHSA, PoCs, and news.db. Discard any EPSS entry whose CVE-ID doesn't appear in those sources.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_fetch_data_news.py — append

@pytest.mark.asyncio
async def test_epss_trims_to_referenced_cves(tmp_path, monkeypatch):
    """EPSS post-fetch trim keeps only CVEs referenced elsewhere."""
    import scripts.fetch_data as fd

    monkeypatch.setattr(fd, "CACHE", tmp_path)

    # Fake a KEV file with one CVE
    kev = {"items": [{"cveID": "CVE-2026-1111"}]}
    (tmp_path / "kev.json").write_text(json.dumps(kev))
    # Fake GHSA with one CVE
    ghsa = {"items": [{"cve_id": "CVE-2026-2222"}]}
    (tmp_path / "ghsa.json").write_text(json.dumps(ghsa))
    # Fake PoCs with one CVE
    pocs = {"items": [{"cve_id": "CVE-2026-3333"}]}
    (tmp_path / "pocs.json").write_text(json.dumps(pocs))
    # No news.db in tmp_path → skip news CVEs

    # Write a fat EPSS with 4 CVEs (one referenced, three not)
    epss_data = {
        "score_date": "2026-05-25",
        "model_version": "test",
        "items": {
            "CVE-2026-1111": {"score": 0.9, "percentile": 0.99},
            "CVE-2026-2222": {"score": 0.5, "percentile": 0.50},
            "CVE-2026-9999": {"score": 0.01, "percentile": 0.10},
            "CVE-2026-8888": {"score": 0.02, "percentile": 0.15},
        },
        "count": 4,
        "fetched_at": "2026-05-25T00:00:00Z",
    }
    (tmp_path / "epss.json").write_text(json.dumps(epss_data))

    fd.trim_epss_to_referenced(cache_dir=tmp_path)

    trimmed = json.loads((tmp_path / "epss.json").read_text())
    assert "CVE-2026-1111" in trimmed["items"]
    assert "CVE-2026-2222" in trimmed["items"]
    assert "CVE-2026-9999" not in trimmed["items"]
    assert "CVE-2026-8888" not in trimmed["items"]
    assert trimmed["count"] == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_fetch_data_news.py::test_epss_trims_to_referenced_cves -xvs`
Expected: FAIL — `trim_epss_to_referenced` doesn't exist yet.

- [ ] **Step 3: Implement the EPSS trim function**

Add to `scripts/fetch_data.py` after the `fetch_epss` function:

```python
def trim_epss_to_referenced(*, cache_dir: Path | None = None) -> int:
    """Post-fetch step: discard EPSS entries for CVEs not referenced by any vuln source or news.

    Reads KEV/GHSA/PoCs for CVE-IDs, plus news.db for CVE-mentioning article titles.
    Rewrites epss.json in place with only the intersection.
    Returns the number of retained entries.
    """
    d = cache_dir or CACHE
    epss_path = d / "epss.json"
    if not epss_path.exists():
        return 0

    referenced: set[str] = set()

    # KEV
    kev_path = d / "kev.json"
    if kev_path.exists():
        try:
            kev = json.loads(kev_path.read_text(encoding="utf-8"))
            for item in kev.get("items", []):
                cve = item.get("cveID")
                if cve:
                    referenced.add(cve.upper())
        except (json.JSONDecodeError, OSError):
            pass

    # GHSA
    ghsa_path = d / "ghsa.json"
    if ghsa_path.exists():
        try:
            ghsa = json.loads(ghsa_path.read_text(encoding="utf-8"))
            for item in ghsa.get("items", []):
                cve = item.get("cve_id")
                if cve:
                    referenced.add(cve.upper())
        except (json.JSONDecodeError, OSError):
            pass

    # PoCs
    pocs_path = d / "pocs.json"
    if pocs_path.exists():
        try:
            pocs = json.loads(pocs_path.read_text(encoding="utf-8"))
            for item in pocs.get("items", []):
                cve = item.get("cve_id")
                if cve:
                    referenced.add(cve.upper())
        except (json.JSONDecodeError, OSError):
            pass

    # News DB — extract CVE-IDs from article titles
    news_db = d / "news.db"
    if news_db.exists():
        try:
            import sqlite3
            conn = sqlite3.connect(str(news_db))
            cve_re = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
            for (title,) in conn.execute("SELECT title FROM articles WHERE title LIKE '%CVE-%'"):
                for m in cve_re.findall(title or ""):
                    referenced.add(m.upper())
            conn.close()
        except Exception:
            pass

    # Trim
    epss = json.loads(epss_path.read_text(encoding="utf-8"))
    old_items = epss.get("items", {})
    new_items = {k: v for k, v in old_items.items() if k.upper() in referenced}
    epss["items"] = new_items
    epss["count"] = len(new_items)
    epss["trimmed_from"] = len(old_items)
    epss_path.write_text(json.dumps(epss, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(new_items)
```

Then wire it into `run()` — add after the existing EPSS fetch completes. In the `run` function (line ~1262), after the manifest is written and before the snapshot step, add:

```python
    # Post-fetch: trim EPSS to only CVEs referenced by other sources
    if "epss" in selected:
        try:
            kept = trim_epss_to_referenced()
            print(f"[trim] epss: kept {kept} CVEs (from full EPSS dump)", file=sys.stderr)
        except Exception as exc:
            print(f"[trim] epss failed: {exc}", file=sys.stderr)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_fetch_data_news.py::test_epss_trims_to_referenced_cves -xvs`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/fetch_data.py tests/test_fetch_data_news.py
git commit -m "fix(epss): trim to referenced CVEs only (27MB → <1MB)"
```

---

### Task 3: News→Vuln Bridge — Extract CVEs from News Articles

**Files:**
- Modify: `backend/app/data.py:461` (wire into `all_vulns()`)
- Create: `tests/test_vuln_bridge.py`

News articles from vuln-focused sources (vulners_com, vuldb_com, sploitus_com, blog_nsfocus_net, securityonline_info) often have CVE-IDs in their titles. We extract those, create lightweight Vuln objects, and merge them into the existing pipeline where they get EPSS/nuclei/HN signals and heat scoring like any other vuln.

- [ ] **Step 1: Write the failing test**

Create `tests/test_vuln_bridge.py`:

```python
"""Tests for news→vuln bridge: extracting CVE entries from news.db."""
import json
import sqlite3
import pytest
from unittest.mock import patch
from pathlib import Path


def _seed_db(db_path: Path) -> None:
    """Create a minimal news.db with articles containing CVE-IDs."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE IF NOT EXISTS articles (
        id INTEGER PRIMARY KEY,
        canonical_url TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        summary TEXT,
        source_slug TEXT NOT NULL,
        source_title TEXT,
        lang TEXT,
        rss_category TEXT,
        published TEXT,
        fetched_at TEXT NOT NULL,
        first_seen_date TEXT,
        llm_score INTEGER,
        llm_category TEXT,
        llm_reason TEXT,
        is_relevant BOOLEAN,
        llm_scored_at TEXT,
        llm_summary_zh TEXT,
        llm_summarized_at TEXT,
        cluster_id INTEGER,
        is_cluster_primary BOOLEAN DEFAULT 0
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sources (
        slug TEXT PRIMARY KEY,
        title TEXT, url TEXT, lang TEXT, tier TEXT,
        interval_minutes INTEGER DEFAULT 240,
        last_fetched TEXT, last_etag TEXT, last_modified TEXT,
        ok BOOLEAN DEFAULT 1, error TEXT
    )""")
    articles = [
        ("https://vuldb.com/1", "CVE-2026-1111 | Apache HTTP Server path traversal",
         "A path traversal vulnerability...", "vuldb_com", "VulDB", "en",
         "2026-05-25T10:00:00Z", "2026-05-25T10:00:00Z"),
        ("https://vulners.com/1", "CVE-2026-1111",
         "Apache HTTP Server vuln", "vulners_com", "Vulners", "en",
         "2026-05-25T09:00:00Z", "2026-05-25T09:00:00Z"),
        ("https://vulners.com/2", "CVE-2026-2222",
         "Chrome RCE", "vulners_com", "Vulners", "en",
         "2026-05-25T11:00:00Z", "2026-05-25T11:00:00Z"),
        ("https://sploitus.com/1", "Exploit for CVE-2026-2222",
         "PoC exploit for Chrome", "sploitus_com", "Sploitus", "en",
         "2026-05-25T11:30:00Z", "2026-05-25T11:30:00Z"),
        # Non-vuln source — should NOT be bridged
        ("https://bleeping.com/1", "CVE-2026-9999 exploited in wild",
         "Article about CVE", "bleeping_com", "BleepingComputer", "en",
         "2026-05-25T12:00:00Z", "2026-05-25T12:00:00Z"),
    ]
    for url, title, summary, slug, stitle, lang, pub, fetched in articles:
        conn.execute(
            "INSERT OR IGNORE INTO articles (canonical_url, title, summary, source_slug, source_title, lang, published, fetched_at) VALUES (?,?,?,?,?,?,?,?)",
            [url, title, summary, slug, stitle, lang, pub, fetched],
        )
    conn.commit()
    conn.close()


def test_news_cve_bridge_extracts_cves(tmp_path):
    db_path = tmp_path / "news.db"
    _seed_db(db_path)

    from backend.app.data import _news_cve_to_vulns
    vulns = _news_cve_to_vulns(db_path=db_path)

    cve_ids = {v.cve_id for v in vulns}
    # CVE-2026-1111 from vuldb + vulners (2 sources) → merged
    assert "CVE-2026-1111" in cve_ids
    # CVE-2026-2222 from vulners + sploitus (2 sources)
    assert "CVE-2026-2222" in cve_ids
    # CVE-2026-9999 from bleeping_com should NOT be included (not a vuln-focused source)
    assert "CVE-2026-9999" not in cve_ids


def test_news_cve_bridge_multi_source_tags(tmp_path):
    db_path = tmp_path / "news.db"
    _seed_db(db_path)

    from backend.app.data import _news_cve_to_vulns
    vulns = _news_cve_to_vulns(db_path=db_path)

    by_cve = {v.cve_id: v for v in vulns}
    v1111 = by_cve["CVE-2026-1111"]
    # Title should come from the longest/richest article
    assert "Apache" in v1111.title or "path traversal" in v1111.title
    # Should have news_mention_count reflecting 2 sources
    assert v1111.hn_mentions == 0  # not HN mentions — those come from signals
    assert len(v1111.references) >= 2  # at least the 2 article URLs
    assert v1111.source == "news-bridge"


def test_news_cve_bridge_empty_db(tmp_path):
    db_path = tmp_path / "news.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE IF NOT EXISTS articles (
        id INTEGER PRIMARY KEY, canonical_url TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL, summary TEXT, source_slug TEXT NOT NULL,
        source_title TEXT, lang TEXT, rss_category TEXT, published TEXT,
        fetched_at TEXT NOT NULL, first_seen_date TEXT,
        llm_score INTEGER, llm_category TEXT, llm_reason TEXT,
        is_relevant BOOLEAN, llm_scored_at TEXT, llm_summary_zh TEXT,
        llm_summarized_at TEXT, cluster_id INTEGER,
        is_cluster_primary BOOLEAN DEFAULT 0
    )""")
    conn.commit()
    conn.close()

    from backend.app.data import _news_cve_to_vulns
    vulns = _news_cve_to_vulns(db_path=db_path)
    assert vulns == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_vuln_bridge.py -xvs`
Expected: FAIL — `_news_cve_to_vulns` doesn't exist yet.

- [ ] **Step 3: Implement `_news_cve_to_vulns` in data.py**

Add to `backend/app/data.py`, before the `all_vulns()` function:

```python
# Sources whose RSS feeds are essentially CVE databases — their titles
# reliably contain CVE-IDs as the primary subject.  General news sites
# (BleepingComputer, Krebs, etc.) mention CVEs in *stories about* CVEs,
# but the article's value is the narrative, not the vuln record itself.
_VULN_RSS_SOURCES = frozenset({
    "vulners_com", "vuldb_com", "sploitus_com",
    "blog_nsfocus_net", "securityonline_info",
})


def _news_cve_to_vulns(*, db_path: Path | None = None) -> list[Vuln]:
    """Bridge: extract CVE-IDs from vuln-focused news RSS and synthesize Vuln objects.

    Only pulls from sources in _VULN_RSS_SOURCES whose titles reliably
    contain CVE-IDs as primary subjects. Groups by CVE-ID, picks the
    richest title, and creates references back to original articles.
    Limited to articles published in the last 7 days.
    """
    db = db_path or _NEWS_DB
    if not db.exists():
        return []
    import sqlite3 as _sq
    conn = _sq.connect(str(db))
    conn.row_factory = _sq.Row
    placeholders = ",".join("?" for _ in _VULN_RSS_SOURCES)
    rows = list(conn.execute(f"""
        SELECT title, summary, canonical_url, source_slug, source_title, published
        FROM articles
        WHERE source_slug IN ({placeholders})
          AND title LIKE '%CVE-%'
          AND published >= date('now', '-7 days')
        ORDER BY published DESC
    """, list(_VULN_RSS_SOURCES)))
    conn.close()

    grouped: dict[str, list[dict]] = {}
    for row in rows:
        title = row["title"] or ""
        for m in CVE_RE.findall(title):
            cve = m.upper()
            grouped.setdefault(cve, []).append(dict(row))

    out: list[Vuln] = []
    for cve, articles in grouped.items():
        best = max(articles, key=lambda a: len(a.get("title") or ""))
        title_raw = best.get("title") or cve
        summary_raw = best.get("summary") or ""
        sources_seen = list(dict.fromkeys(a.get("source_slug", "") for a in articles))
        refs = [
            Reference(url=a["canonical_url"], label=a.get("source_title") or a.get("source_slug") or "")
            for a in articles if a.get("canonical_url")
        ][:6]
        tags = ["NEWS-CVE"]
        if len(sources_seen) > 1:
            tags.append(f"{len(sources_seen)} sources")
        out.append(Vuln(
            id=cve,
            kind="cve",
            cve_id=cve,
            title=title_raw.strip()[:200],
            summary=summary_raw.strip()[:500],
            severity="unknown",
            references=refs,
            tags=tags,
            source="news-bridge",
            published=best.get("published"),
        ))
    out.sort(key=lambda v: v.published or "", reverse=True)
    return out
```

- [ ] **Step 4: Wire `_news_cve_to_vulns` into `all_vulns()`**

In `backend/app/data.py`, modify the `all_vulns()` function (line 462):

Change:
```python
def all_vulns() -> list[Vuln]:
    vulns = _kev_to_vulns() + _ghsa_to_vulns() + _pocs_to_vulns() + _osv_malware_to_vulns()
```

To:
```python
def all_vulns() -> list[Vuln]:
    vulns = _kev_to_vulns() + _ghsa_to_vulns() + _pocs_to_vulns() + _osv_malware_to_vulns() + _news_cve_to_vulns()
```

- [ ] **Step 5: Run tests to verify everything passes**

Run: `uv run pytest tests/test_vuln_bridge.py -xvs`
Expected: All 3 tests PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/data.py tests/test_vuln_bridge.py
git commit -m "feat(vuln): bridge news CVEs into vulnerability tab

CVE-IDs from vulners/vuldb/sploitus/nsfocus RSS now appear in the
vuln tab. Multi-source mentions merge and get EPSS/heat scoring."
```

---

### Task 4: Integration Verification

**Files:** No new files — verify the pipeline end-to-end.

- [ ] **Step 1: Run the full test suite**

Run: `uv run pytest tests/ -x --tb=short`
Expected: All tests pass (existing + new).

- [ ] **Step 2: Start the dev server and verify the API**

Run: `uv run uvicorn backend.app.main:app --reload --port 8000`

Verify in another terminal:
```bash
# Vuln API should now include news-bridge CVEs
curl -s 'http://127.0.0.1:8000/api/vuln?limit=5' | python3 -m json.tool | head -40

# Check that news-bridge CVEs appear
curl -s 'http://127.0.0.1:8000/api/vuln?q=CVE-2026' | python3 -c "
import json,sys
vulns = json.load(sys.stdin)
bridge = [v for v in vulns if v['source'] == 'news-bridge']
print(f'news-bridge CVEs: {len(bridge)}')
for v in bridge[:5]:
    print(f'  {v[\"cve_id\"]} heat={v[\"heat\"]} tags={v[\"tags\"]}')"

# Today summary should reflect increased vuln count
curl -s 'http://127.0.0.1:8000/api/today' | python3 -m json.tool
```

- [ ] **Step 3: Verify OSV/EPSS data sizes (after re-fetching)**

This step validates the data reduction. Only run if you have time to re-fetch:
```bash
# Re-fetch OSV (will now be malware-only)
uv run python scripts/fetch_data.py --only osv
ls -lh backend/cache/osv-*.json
# Expected: osv-npm.json < 5MB, osv-pypi.json < 1MB

# Re-fetch EPSS (will auto-trim)
uv run python scripts/fetch_data.py --only epss
ls -lh backend/cache/epss.json
# Expected: epss.json < 2MB
```

- [ ] **Step 4: Final commit with any integration fixes**

```bash
git add -A
git commit -m "chore: integration fixes from vuln-slim-and-bridge"
```
