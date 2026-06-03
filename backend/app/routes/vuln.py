"""Vulnerability + heat board routes."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Response

from ..data import all_vulns, heat_board
from ..models import HeatEntry, Vuln
from .news import _contains
from .ops import _matches_date, _today_utc_str, _validate_date, _within_window

router = APIRouter()


@router.get("/api/vuln", response_model=list[Vuln], tags=["vulnerability"])
def api_vuln(
    response: Response,
    kind: Literal["all", "cve", "supply", "poc", "itw"] = "all",
    q: str = "",
    severity: Literal["any", "critical", "high", "medium", "low"] = "any",
    date: str | None = Query(default=None, description="window end date (YYYY-MM-DD); default today. Matches CISA dateAdded for KEV, published_at for GHSA/OSV"),
    days: int = Query(default=1, ge=1, le=90, description="rolling window size in days ending at `date`/today. days=1 = single day (drill-down); the UI defaults to a multi-day window because vuln publish dates are sparse"),
    limit: int = Query(default=60, ge=1, le=2000),
    sort: Literal["heat", "time"] = "heat",
) -> list[Vuln]:
    target_date = _validate_date(date)
    items = all_vulns()
    if kind != "all":
        items = [v for v in items if v.kind == kind]
    if severity != "any":
        items = [v for v in items if v.severity == severity]
    if q:
        items = [v for v in items if _contains(q, v.title, v.summary, v.cve_id, v.ghsa_id, v.package, v.vendor, v.product)]
    # Date filtering uses the source-of-truth publish date. `first_seen` is
    # intentionally excluded — it tracks when *our* cache first observed the
    # row, so on cold-start days it stamps the whole backlog with today.
    # days>1 → rolling window ending at target/today; days<=1 → single day.
    if days > 1:
        end = target_date or _today_utc_str()
        items = [v for v in items if _within_window(v.published, end, days)]
    elif target_date:
        items = [v for v in items if _matches_date(v.published, target_date)]
    if sort == "heat":
        items.sort(key=lambda x: -x.heat)
    else:
        items.sort(key=lambda x: x.published or "", reverse=True)
    # Expose the full filtered count so the client can show a "showing N of M"
    # overflow hint when the result is truncated by `limit`.
    response.headers["X-Total-Count"] = str(len(items))
    return items[:limit]


@router.get("/api/vuln/{vuln_id}", response_model=Vuln, tags=["vulnerability"])
def api_vuln_detail(vuln_id: str) -> Vuln:
    """Return a single vulnerability by CVE-ID, GHSA-ID, or internal id.

    Lookup is case-insensitive on CVE/GHSA prefixes.
    """
    needle = vuln_id.strip().upper()
    for v in all_vulns():
        if v.cve_id and v.cve_id.upper() == needle:
            return v
        if v.ghsa_id and v.ghsa_id.upper() == needle:
            return v
        if v.id.upper() == needle:
            return v
    raise HTTPException(status_code=404, detail=f"vuln '{vuln_id}' not found")


@router.get("/api/heat", response_model=list[HeatEntry], tags=["overview"])
def api_heat(
    limit: int = Query(default=10, ge=1, le=50),
    kind: Literal["vuln", "news"] = Query(default="vuln", description="vuln=CVE heat (default, back-compat); news=top AI-scored articles"),
    date: str | None = Query(default=None, description="YYYY-MM-DD; filters both vuln and news heat boards"),
) -> list[HeatEntry]:
    target = _validate_date(date)
    if kind == "news":
        from ..data import news_heat_board
        return news_heat_board(limit, date=target)
    return heat_board(limit, date=target)
