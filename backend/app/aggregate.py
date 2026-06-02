"""API-facing aggregate views: heat boards, today summary, fetch manifest,
and cross-domain search."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .cache_io import _load_json, parse_iso_date
from .models import (
    Article,
    FetcherStatus,
    HeatEntry,
    Manifest,
    SearchLink,
    SearchResult,
    TodaySummary,
)
from .news.query import all_articles, all_sources, search_articles
from .vuln.aggregate import all_vulns


def manifest() -> Manifest:
    raw = _load_json("manifest.json", {"fetched_at": "", "results": []})
    results = []
    for r in raw.get("results", []):
        results.append(FetcherStatus(
            name=r.get("name", ""),
            ok=bool(r.get("ok")),
            status=r.get("status"),
            count=int(r.get("count", 0)),
            elapsed_s=float(r.get("elapsed_s", 0)),
            finished_at=r.get("finished_at"),
            error=r.get("error"),
            diagnostic=r.get("diagnostic"),
            partial_errors=r.get("partial_errors"),
            by_ecosystem=r.get("by_ecosystem"),
        ))
    return Manifest(fetched_at=raw.get("fetched_at", ""), results=results)


def heat_board(limit: int = 10, date: str | None = None) -> list[HeatEntry]:
    vulns = all_vulns()
    if date:
        vulns = [v for v in vulns if (v.published or "")[:10] == date]
    out: list[HeatEntry] = []
    for i, v in enumerate(vulns[:limit], start=1):
        kind_color = {
            "itw": "itw",
            "supply": "itw",
            "poc": "poc",
            "cve": "crit" if v.severity == "critical" else "high",
        }.get(v.kind, "muted")
        out.append(HeatEntry(
            rank=i,
            label=v.cve_id or v.id,
            cve_id=v.cve_id,
            score=v.heat,
            category=v.kind,
            kind_color=kind_color,
        ))
    return out


_CAT_COLOR = {
    "incident": "itw",
    "vuln": "crit",
    "supply-chain": "itw",
    "research": "poc",
    "industry": "muted",
}


def _news_heat_score(a: "Article", now_utc: datetime) -> int:
    """Composite score that pulls apart the clumping at LLM score 9.

    base       = llm_score × 10               (0-100, but in practice most live
                                               at 80-90 due to LLM bias)
    recency    = max(0, 24 - age_hours)       (0-24, favors today's stories)
    cluster_bonus = mirror_count × 3          (0-30, multi-source events rise)
    """
    base = (a.llm_score or 0) * 10
    age_h = 0.0
    pub = a.published or ""
    if pub:
        try:
            dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
            age_h = max(0.0, (now_utc - dt).total_seconds() / 3600)
        except (ValueError, TypeError):
            pass
    recency = max(0, int(24 - age_h)) if age_h <= 24 else 0
    cluster_bonus = (a.mirror_count or 0) * 3
    return base + recency + cluster_bonus


def news_heat_board(limit: int = 10, date: str | None = None) -> list[HeatEntry]:
    """Top news articles for the 行业资讯 tab right rail.

    Composite score combines LLM rank + recency + mirror count to differentiate
    items the LLM clumped at the same score. If `date` is given, restricts to
    articles published (or first-seen) on that date — gives a per-day heat view
    that tracks the date strip; otherwise returns the global top.
    """
    articles = all_articles()
    if date:
        # Strict publish-date match. The previous code accepted *all* undated
        # articles for *any* selected date, which flooded every day's heat
        # board with the freshest fetch batch (e.g. a NULL-dated curl batch
        # appearing on 05.22's board even though it was fetched on 05.25).
        # Articles without a published date simply don't appear in any
        # specific day's heat — same rule as /api/news and the daily brief.
        articles = [a for a in articles if (a.published or "")[:10] == date]
    now_utc = datetime.now(timezone.utc)
    scored = sorted(
        ((_news_heat_score(a, now_utc), a) for a in articles),
        key=lambda t: -t[0],
    )
    out: list[HeatEntry] = []
    for i, (score, a) in enumerate(scored[:limit], start=1):
        out.append(HeatEntry(
            rank=i,
            label=a.title[:48] + ("…" if len(a.title) > 48 else ""),
            cve_id=None,
            score=score,
            category=a.llm_category,
            kind_color=_CAT_COLOR.get(a.llm_category or "", "muted"),
            link=a.link,
        ))
    return out


def today_summary() -> TodaySummary:
    vulns = all_vulns()
    articles = all_articles()
    sources = all_sources()
    now = datetime.now(timezone.utc)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)

    def is_recent(s: str | None) -> bool:
        d = parse_iso_date(s)
        return bool(d and d >= midnight)

    news_today = sum(1 for a in articles if is_recent(a.published))
    vuln_today = sum(1 for v in vulns if is_recent(v.published))
    itw_today = sum(1 for v in vulns if v.is_itw and is_recent(v.published))
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for v in vulns:
        sev[v.severity] = sev.get(v.severity, 0) + 1
    heats = heat_board(1)
    return TodaySummary(
        date=now.strftime("%Y-%m-%d"),
        news_today=news_today,
        vuln_today=vuln_today,
        itw_today=itw_today,
        sources_alive=sum(1 for s in sources if s.ok),
        sources_total=len(sources),
        top_heat=heats[0] if heats else None,
        sev_breakdown=sev,
        last_fetch=manifest().fetched_at,
    )


_CVE_SEARCH_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def search_aggregated(q: str, limit: int = 10) -> SearchResult:
    """Cross-domain search: news + vulns + CVE-based links between them."""
    # --- News ---
    raw_news = search_articles(q, limit=max(limit * 3, 300))
    # Filter out uncategorized articles (same rule as /api/news)
    filtered_news = [
        a for a in raw_news
        if a.llm_category not in (None, "", "uncategorized")
    ]
    filtered_news.sort(key=lambda a: a.llm_score if a.llm_score is not None else -1, reverse=True)
    news = filtered_news[:limit]

    # --- Vulns ---
    ql = q.lower()
    matched_vulns = [
        v for v in all_vulns()
        if any(
            ql in (f or "").lower()
            for f in (v.title, v.summary, v.cve_id, v.ghsa_id, v.package, v.vendor, v.product)
        )
    ]
    matched_vulns.sort(key=lambda v: -v.heat)
    vulns = matched_vulns[:limit]

    # --- CVE links ---
    cve_to_news: dict[str, list[int]] = {}
    for a in news:
        text = (a.title or "") + " " + (a.summary or "") + " " + (a.llm_summary_zh or "")
        for m in _CVE_SEARCH_RE.findall(text):
            cve = m.upper()
            cve_to_news.setdefault(cve, [])
            if a.id is not None and a.id not in cve_to_news[cve]:
                cve_to_news[cve].append(a.id)

    cve_to_vuln: dict[str, list[str]] = {}
    for v in vulns:
        if v.cve_id:
            cve_to_vuln.setdefault(v.cve_id, [])
            if v.id not in cve_to_vuln[v.cve_id]:
                cve_to_vuln[v.cve_id].append(v.id)

    links = [
        SearchLink(cve_id=cve, vuln_ids=cve_to_vuln[cve], news_ids=cve_to_news[cve])
        for cve in cve_to_news
        if cve in cve_to_vuln
    ]

    return SearchResult(query=q, vulns=vulns, news=news, links=links)
