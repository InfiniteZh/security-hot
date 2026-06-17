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
    is_relevant: bool | None = None


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
    iocs: list[str] = Field(default_factory=list)
    fix_versions: list[str] = Field(default_factory=list)
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
    sources: list[str] = Field(default_factory=list)

    def model_post_init(self, __context) -> None:
        # Normalize `sources` to a deduped list that always leads with `source`,
        # so a freshly-built Vuln already carries its origin before any cross-CVE
        # merge in all_vulns() accumulates additional sources.
        seen: set[str] = set()
        normalized: list[str] = []
        for src in [self.source, *self.sources]:
            src = str(src or "").strip()
            if src and src not in seen:
                normalized.append(src)
                seen.add(src)
        self.sources = normalized


class HeatEntry(BaseModel):
    rank: int
    label: str
    cve_id: str | None = None
    score: int
    category: VulnKind | NewsCategory | Literal["news"] | None = None
    kind_color: str | None = None
    link: str | None = None  # for news heat: clicking opens the article URL


class DispatchEntry(BaseModel):
    ref_id: str
    origin: Literal["vuln", "news"]
    package: str | None = None       # derived: first package's name (back-compat / 摘要行)
    ecosystem: str | None = None     # derived: first package's ecosystem
    packages: list[dict] = Field(default_factory=list)  # v3: 多包数组 [{ecosystem,package,versions...}]
    iocs: list[dict] = Field(default_factory=list)
    title: str | None = None
    severity: str | None = None
    cve_id: str | None = None
    summary_zh: str | None = None
    references: list[dict] = Field(default_factory=list)
    related_news: list[dict] = Field(default_factory=list)
    dispatched_at: str
    topic: str | None = None
    message: dict | None = None       # 完整 Kafka 投递报文（抽屉里展示原文）


class SourceStatus(BaseModel):
    slug: str
    title: str
    url: str
    lang: Lang | Literal["mixed"]
    ok: bool
    count: int = 0
    error: str | None = None
    consecutive_failures: int = 0
    tier: str = "tail"
    last_fetched: str | None = None


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


class SearchLink(BaseModel):
    cve_id: str
    vuln_ids: list[str] = Field(default_factory=list)
    news_ids: list[int] = Field(default_factory=list)


class SearchResult(BaseModel):
    query: str
    vulns: list[Vuln] = Field(default_factory=list)
    news: list[Article] = Field(default_factory=list)
    links: list[SearchLink] = Field(default_factory=list)
