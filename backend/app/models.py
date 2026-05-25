"""Pydantic schemas for the security-hot public API."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Lang = Literal["zh", "en"]
Severity = Literal["critical", "high", "medium", "low", "unknown"]
VulnKind = Literal["cve", "supply", "poc", "itw"]
NewsCategory = Literal["incident", "vuln", "supply-chain", "research", "industry"]
SortBy = Literal["heat", "time"]


class Article(BaseModel):
    id: int | None = None
    title: str
    link: str
    published: str = ""
    summary: str = ""
    source_slug: str
    source_title: str
    lang: Lang
    category: str | None = None
    llm_score: int | None = None
    llm_reason: str | None = None
    llm_category: NewsCategory | None = None
    llm_summary_zh: str | None = None
    tags: list[str] = Field(default_factory=list)
    is_relevant: bool | None = None
    mirror_count: int = 0
    mirror_source_titles: list[str] = Field(default_factory=list)


class PocLink(BaseModel):
    url: str
    title: str = ""
    stars: int = 0


class Reference(BaseModel):
    url: str
    label: str = ""


class Vuln(BaseModel):
    id: str
    kind: VulnKind
    title: str
    summary: str = ""
    severity: Severity = "unknown"
    cvss: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    cve_id: str | None = None
    ghsa_id: str | None = None
    is_kev: bool = False
    is_itw: bool = False
    is_ransomware: bool = False
    is_supply_chain: bool = False
    vendor: str | None = None
    product: str | None = None
    ecosystem: str | None = None
    package: str | None = None
    pocs: list[PocLink] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    source: str
    published: str | None = None
    updated: str | None = None
    first_seen: str | None = None
    nuclei_template_url: str | None = None
    hn_mentions: int = 0
    masto_mentions: int = 0
    heat: int = 0
    ai_severity: Severity | None = None
    ai_summary: str | None = None


class HeatEntry(BaseModel):
    rank: int
    label: str
    cve_id: str | None = None
    score: int
    category: VulnKind | NewsCategory | Literal["news"] | None = None
    kind_color: str | None = None
    link: str | None = None  # for news heat: clicking opens the article URL


class SourceStatus(BaseModel):
    slug: str
    title: str
    url: str
    lang: Lang | Literal["mixed"]
    category: str | None = None
    ok: bool
    count: int = 0
    error: str | None = None


class FetcherStatus(BaseModel):
    name: str
    ok: bool
    status: Literal["ok", "no_data", "error"] | None = None
    count: int = 0
    elapsed_s: float = 0
    finished_at: str | None = None
    error: str | None = None
    diagnostic: dict | None = None
    partial_errors: int | None = None
    by_ecosystem: dict[str, int] | None = None


class TodaySummary(BaseModel):
    date: str
    news_today: int
    vuln_today: int
    itw_today: int
    sources_alive: int
    sources_total: int
    top_heat: HeatEntry | None = None
    sev_breakdown: dict[Severity, int] = Field(default_factory=dict)
    last_fetch: str | None = None


class Manifest(BaseModel):
    fetched_at: str
    results: list[FetcherStatus] = Field(default_factory=list)
