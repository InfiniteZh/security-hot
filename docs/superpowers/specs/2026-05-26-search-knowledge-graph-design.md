# Search Knowledge Graph Modal — Design Spec

**Date:** 2026-05-26
**Status:** Approved

## Overview

Replace the current inline ⌘K search (text filter + banner) with a full-screen knowledge-graph modal. The user types a query and sees a force-directed graph: the keyword at the center, vulnerability nodes (red) and news nodes (blue) radiating outward with connecting lines. Shared CVE-IDs appear as purple bridge nodes. Clicking any node opens a detail panel on the right.

## User Flow

1. User presses **⌘K** (or clicks the search bar) → full-screen modal opens with backdrop blur.
2. User types a query (≥2 chars) → debounce 300ms → `GET /api/search?q=<query>&limit=20`.
3. Graph renders: center keyword node, vuln nodes on the right half, news nodes on the left half.
4. User clicks a node → right detail panel slides in (graph shrinks to ~60% width).
5. Detail panel shows: type badge, title, AI summary, key metadata, related items (cross-links), and an "open original" link.
6. User presses **ESC** or clicks backdrop → modal closes, search state clears.

## Backend: `GET /api/search`

New endpoint in `main.py`.

### Request

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `q` | string | required | Search query (min 2 chars) |
| `limit` | int | 20 | Max nodes per category (vulns + news each capped) |

### Response

```json
{
  "query": "RCE",
  "vulns": [ /* Vuln objects, sorted by heat desc, max `limit` */ ],
  "news":  [ /* Article objects, sorted by llm_score desc, max `limit` */ ],
  "links": [
    {
      "cve_id": "CVE-2026-5426",
      "vuln_ids": ["CVE-2026-5426"],
      "news_ids": [539]
    }
  ]
}
```

### Link Generation Logic

1. Collect all `cve_id` values from the returned vulns.
2. For each returned news article, extract CVE-IDs from `title`, `summary`, and `llm_summary_zh` using regex `CVE-\d{4}-\d{4,}`.
3. A link exists when a news article references a CVE-ID that also appears in the vuln results.
4. Group by CVE-ID → produce the `links` array.

## Frontend: Knowledge Graph Modal

### Component Structure

```
SearchGraphModal (overlay)
├── SearchBar (input + stats + ESC hint)
├── MainArea (flex)
│   ├── GraphPanel (canvas + positioned nodes)
│   │   ├── CenterNode (keyword)
│   │   ├── VulnNodes[] (right half, red border-left)
│   │   ├── NewsNodes[] (left half, blue border-left)
│   │   ├── SharedCVENodes[] (purple, bridge)
│   │   ├── Canvas (connecting lines)
│   │   └── Legend
│   └── DetailPanel (slide-in, 380px)
│       ├── TypeBadge + Title
│       ├── Badges (KEV/severity/EPSS/AI score)
│       ├── AI Summary
│       ├── Key Info Grid
│       ├── Related Items (cross-links)
│       └── "Open Original" link
└── StatBar (bottom: stats + hint)
```

### Node Layout

Use a simple force-directed-like layout (no physics library needed):

1. Center node at `(50%, 50%)`.
2. Vuln nodes distributed on the right semicircle (angles 270°→90° clockwise), spaced evenly.
3. News nodes distributed on the left semicircle (angles 90°→270° clockwise), spaced evenly.
4. Shared CVE nodes placed at the bottom-center area.
5. Node size scales with heat (vuln) or llm_score (news): larger badge area for higher scores.

### Canvas Lines

- Solid lines from center to each vuln/news node.
- Dashed purple lines from shared CVE nodes to their linked vuln and news nodes.
- Line color: red-tinted for vulns, blue-tinted for news, purple for shared.
- Redraw on window resize and on detail panel open/close (graph width changes).

### Node Appearance

| Type | Border-left | Badges | Sort key |
|------|-------------|--------|----------|
| Vuln | 3px #EF4444 | KEV, severity, CVSS, EPSS, PoC | heat desc |
| News | 3px #3B82F6 | AI score, category | llm_score desc |
| Shared CVE | 3px #8B5CF6 | "LINK" | — |

Each node shows: badges row, title (truncated to 2 lines), meta line (CVE-ID or source+category), and a tiny heat bar.

### Detail Panel

- Width: 380px, slides in from the right.
- When open, graph panel shrinks with CSS `flex: 0.6` transition.
- Content sections: type label, title, badge row, "AI Summary" section, key-info 2-column grid, "Related Items" list (clickable, highlights the linked node), "Open Original →" link at the bottom.
- Close button (✕) top-right.

### Interaction

- **⌘K / Ctrl+K**: open modal, focus input.
- **ESC**: if detail panel is open → close detail; if detail closed → close modal.
- **Click node**: open detail panel for that node.
- **Click related item in detail**: switch detail to that node, highlight it in graph.
- **Click backdrop**: close modal.
- Input debounce: 300ms after last keystroke.
- Empty/short query (<2 chars): show a placeholder state ("Type to search across vulns & news").

### i18n

All visible text goes through the existing `I18N` dictionary. New keys:

```javascript
"search.placeholder": { zh: "搜索漏洞与资讯…", en: "Search vulns & news…" },
"search.stats": { zh: "{v} 漏洞 · {n} 资讯 · {l} 关联", en: "{v} vulns · {n} news · {l} links" },
"search.hint_close": { zh: "ESC 关闭", en: "ESC to close" },
"search.detail_open": { zh: "打开原文 →", en: "Open original →" },
"search.detail_related": { zh: "关联条目", en: "Related items" },
"search.detail_summary": { zh: "AI 概述", en: "AI Summary" },
"search.detail_info": { zh: "关键信息", en: "Key Info" },
"search.legend_vuln": { zh: "漏洞情报", en: "Vulnerabilities" },
"search.legend_news": { zh: "行业资讯", en: "News" },
"search.legend_shared": { zh: "共同 CVE", en: "Shared CVE" },
"search.empty": { zh: "输入关键词搜索漏洞与资讯", en: "Type to search vulns & news" },
"search.no_results": { zh: "未找到相关结果", en: "No results found" },
"search.data_range": { zh: "数据范围: 30天", en: "Data range: 30 days" },
```

### Responsive

- Below 768px: graph nodes stack vertically (vulns on top, news below), detail panel becomes a bottom sheet instead of right panel.
- Modal width: `min(1060px, 95vw)`, height: `min(640px, 88vh)`.

## Styling

Follow the existing OpenAI-style design system:
- Background: `#FAFAF7` (modal body), `#fff` (search bar, detail panel)
- Border: `1px solid #E8E5DD`
- Border-radius: `20px` (modal), `12px` (nodes)
- Font: Geist for body, Geist Mono for CVE-IDs / scores / dates
- Backdrop: `rgba(10,10,10,.55)` with `backdrop-filter: blur(6px)`
- Accent: `#10A37F` for selected node outline and links

## Scope

### In scope
- New `GET /api/search` endpoint
- Full-screen search graph modal (replaces current ⌘K)
- Detail panel with slide-in animation
- Canvas-based connecting lines
- i18n support (zh/en)
- Node layout algorithm (semicircle distribution)

### Out of scope
- Physics-based force simulation (keep it simple CSS positioning)
- Drag-to-rearrange nodes
- Persisted search history
- Full-text search improvements to the existing FTS5 index
- Mobile-first design (basic responsive is enough)

## Files to Modify

| File | Change |
|------|--------|
| `backend/app/main.py` | Add `GET /api/search` endpoint |
| `backend/app/models.py` | Add `SearchResult` response model |
| `backend/app/data.py` | Add search aggregation helper if needed |
| `web/index.html` | Replace search UI: remove inline search, add graph modal + detail panel + canvas logic + i18n keys |

## Testing

- Backend: pytest for `/api/search` — verify response shape, link generation, empty query handling, limit capping.
- Frontend: manual — verify ⌘K opens modal, typing triggers search, nodes render, clicking opens detail, ESC closes, i18n toggles.
