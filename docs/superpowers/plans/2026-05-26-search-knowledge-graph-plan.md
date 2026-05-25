# Search Knowledge Graph — Implementation Plan

**Spec:** `docs/superpowers/specs/2026-05-26-search-knowledge-graph-design.md`
**Date:** 2026-05-26

## Steps

### Step 1: Backend — Add SearchResult model + /api/search endpoint

**Files:** `backend/app/models.py`, `backend/app/main.py`, `backend/app/data.py`

1. In `models.py`, add:
   ```python
   class SearchLink(BaseModel):
       cve_id: str
       vuln_ids: list[str] = Field(default_factory=list)
       news_ids: list[int] = Field(default_factory=list)

   class SearchResult(BaseModel):
       query: str
       vulns: list[Vuln] = Field(default_factory=list)
       news: list[Article] = Field(default_factory=list)
       links: list[SearchLink] = Field(default_factory=list)
   ```

2. In `data.py`, add a helper `search_aggregated(q: str, limit: int) -> SearchResult` that:
   - Calls existing `search_articles(q)` for news (filter out uncategorized, sort by llm_score desc, take top `limit`)
   - Calls `all_vulns()` and filters with `_contains(q, ...)` (reusing the existing vuln search logic), sort by heat desc, take top `limit`
   - Extracts CVE-IDs from news titles/summaries via regex
   - Cross-references with vuln CVE-IDs to build the `links` array
   - Returns `SearchResult`

3. In `main.py`, add:
   ```python
   @app.get("/api/search", response_model=SearchResult, tags=["search"])
   def api_search(q: str = Query(..., min_length=2), limit: int = Query(default=10, ge=1, le=30)) -> SearchResult:
       return search_aggregated(q, limit)
   ```

**Verify:** `uv run pytest tests/ -x` + manual curl test.

### Step 2: Backend tests

**Files:** `tests/test_search_api.py` (new)

Add pytest tests:
- `test_search_returns_shape` — verify response has query/vulns/news/links fields
- `test_search_links_generation` — mock data with shared CVE, verify links array
- `test_search_min_length` — query with 1 char returns 422
- `test_search_limit` — verify limit caps results

**Verify:** `uv run pytest tests/test_search_api.py -v`

### Step 3: Frontend — Search Graph Modal (CSS + HTML structure)

**Files:** `web/index.html`

1. Add CSS for the modal: `.search-graph-backdrop`, `.search-graph-modal`, `.sg-search-bar`, `.sg-graph-panel`, `.sg-node`, `.sg-detail-panel`, `.sg-stat-bar`, etc. Follow existing design tokens.

2. Add modal HTML structure right before `</body>`:
   ```html
   <div id="search-graph-backdrop" class="search-graph-backdrop hidden">
     <div class="search-graph-modal">
       <div class="sg-search-bar">...</div>
       <div class="sg-main-area">
         <div class="sg-graph-panel"><canvas id="sg-canvas"></canvas></div>
         <div class="sg-detail-panel"></div>
       </div>
       <div class="sg-stat-bar">...</div>
     </div>
   </div>
   ```

3. Add i18n keys to the `I18N` dictionary.

4. Modify the existing ⌘K handler and search input handler to open the modal instead of performing inline search. Remove the old `performGlobalSearch` function, `searchTimer`, and `state._searchResults`. Remove the search banner rendering from `renderNewsList`.

### Step 4: Frontend — Graph rendering + Canvas lines

**Files:** `web/index.html`

1. Implement `renderSearchGraph(data)`:
   - Clear graph panel
   - Place center node at (50%, 50%)
   - Distribute vuln nodes on right semicircle, news nodes on left semicircle
   - Place shared CVE bridge nodes at bottom-center
   - Each node is a positioned `<div>` with click handler

2. Implement `drawSearchLines()`:
   - Canvas fills graph panel
   - Solid curves from center to each vuln/news node
   - Dashed purple lines between shared CVE nodes and their linked items
   - Called on render, resize, and detail panel toggle

3. Implement debounced search: input → 300ms debounce → `fetch('/api/search?q=...')` → `renderSearchGraph(data)`

### Step 5: Frontend — Detail panel + interactions

**Files:** `web/index.html`

1. Implement `showSearchDetail(type, item, relatedItems)`:
   - Populate detail panel HTML
   - Add `.open` class to panel, `.shrunk` class to graph
   - Redraw canvas lines after transition

2. Implement ESC handling:
   - If detail open → close detail
   - If detail closed → close modal

3. Implement "related item" click → switch detail to clicked item, highlight node

4. Wire up "open original" link

### Step 6: Cleanup + integration test

1. Remove old search-related code: `performGlobalSearch`, `searchTimer`, `state._searchResults`, search banner in `renderNewsList`, `renderVulnList` search integration.
2. Ensure the existing search bar HTML is replaced/repurposed to trigger the modal.
3. Manual integration test: start server, test full flow.

## Parallelization

- **Step 1 + Step 3** can run in parallel (backend API vs frontend CSS/HTML structure)
- **Step 2** depends on Step 1
- **Step 4 + Step 5** depend on Step 3
- **Step 6** depends on all previous steps
