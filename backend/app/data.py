"""Load cached JSON snapshots and normalize them into API-ready models."""
from __future__ import annotations

import json
import re
import sqlite3 as _sqlite3
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from .models import (
    Article,
    FetcherStatus,
    HeatEntry,
    Manifest,
    NewsCategory,
    PocLink,
    Reference,
    SourceStatus,
    Severity,
    TodaySummary,
    Vuln,
)

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / "backend" / "cache"

_NEWS_DB = ROOT / "backend" / "cache" / "news.db"

_RELOAD_TTL = 30  # seconds
_VALID_CATEGORIES: set[str] = {"incident", "vuln", "supply-chain", "research", "industry"}


# ─────────── SQLite helpers ───────────

def _news_conn() -> _sqlite3.Connection:
    c = _sqlite3.connect(str(_NEWS_DB))
    c.row_factory = _sqlite3.Row
    # foreign_keys is session-scoped; explicit set is required even on WAL-init'd file.
    # WAL mode is already sticky in the file header but re-stating it is harmless.
    c.execute("PRAGMA journal_mode = WAL")
    c.execute("PRAGMA foreign_keys = ON")
    c.execute("PRAGMA synchronous = NORMAL")
    return c


def _row_to_article(row, mirror_titles_by_cluster: dict) -> Article:
    cluster_id = row["cluster_id"]
    mirror_titles = mirror_titles_by_cluster.get(cluster_id, []) if cluster_id else []
    raw_cat = row["llm_category"]
    llm_cat: NewsCategory | None = raw_cat if raw_cat in _VALID_CATEGORIES else None
    return Article(
        id=row["id"],
        title=row["title"] or "",
        link=row["canonical_url"] or "",
        published=row["published"] or "",
        summary=row["summary"] or "",
        source_slug=row["source_slug"] or "",
        source_title=row["source_title"] or "",
        lang=row["lang"] if row["lang"] in ("zh", "en") else "en",
        category=row["rss_category"],
        llm_score=int(row["llm_score"]) if row["llm_score"] is not None else None,
        llm_reason=row["llm_reason"],
        llm_category=llm_cat,
        llm_summary_zh=row["llm_summary_zh"],
        is_relevant=bool(row["is_relevant"]) if row["is_relevant"] is not None else None,
        mirror_count=len(mirror_titles),
        mirror_source_titles=mirror_titles[:6],
    )


_state: dict[str, tuple[float, Any]] = {}


# ─────────── cache loaders ───────────

def _load_json(name: str, default):
    path = CACHE / name
    if not path.exists():
        return default
    cached = _state.get(name)
    mtime = path.stat().st_mtime
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        data = default
    _state[name] = (mtime, data)
    return data


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


# ─────────── helpers ───────────

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def severity_from_cvss(cvss: float | None) -> Severity:
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "unknown"


def parse_iso_date(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    # try a few formats
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # ISO with +/- offset
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ─────────── source normalization ───────────

def _kev_to_vulns() -> list[Vuln]:
    raw = _load_json("kev.json", {"items": []})
    out: list[Vuln] = []
    for v in raw.get("items", []):
        cve = v.get("cveID", "")
        vendor = v.get("vendorProject")
        product = v.get("product")
        ransom = (v.get("knownRansomwareCampaignUse") or "").lower() == "known"
        date_added = v.get("dateAdded")
        title = v.get("vulnerabilityName") or (f"{vendor} {product}" if vendor else cve)
        out.append(Vuln(
            id=cve,
            kind="itw",
            cve_id=cve,
            title=title,
            summary=(v.get("shortDescription") or "").strip(),
            severity="unknown",  # KEV doesn't carry CVSS; derive_severity will escalate to ≥high
            is_kev=True,
            is_itw=True,
            is_ransomware=ransom,
            vendor=vendor,
            product=product,
            references=[Reference(url=f"https://nvd.nist.gov/vuln/detail/{cve}", label="NVD")],
            tags=[t for t in ["KEV", "ITW", "Ransomware" if ransom else None] if t],
            source="cisa-kev",
            published=date_added,
            updated=date_added,
            first_seen=v.get("first_seen"),
        ))
    return out


def _ghsa_to_vulns() -> list[Vuln]:
    raw = _load_json("ghsa.json", {"items": []})
    out: list[Vuln] = []
    for a in raw.get("items", []):
        cvss_obj = a.get("cvss") or {}
        cvss = cvss_obj.get("score")
        sev_raw = (a.get("severity") or "").lower()
        severity: Severity = sev_raw if sev_raw in ("critical", "high", "medium", "low") else severity_from_cvss(cvss)  # type: ignore
        is_malware = (a.get("type") or "").lower() == "malware"
        vulns = a.get("vulnerabilities") or []
        ecosystem = None
        package = None
        if vulns:
            pkg = (vulns[0].get("package") or {})
            ecosystem = pkg.get("ecosystem")
            package = pkg.get("name")
        refs = []
        for ref in (a.get("references") or [])[:6]:
            if isinstance(ref, dict):
                url = ref.get("url")
            else:
                url = ref
            if url:
                refs.append(Reference(url=url, label=""))
        out.append(Vuln(
            id=a.get("ghsa_id") or a.get("cve_id") or "GHSA-unknown",
            kind="supply" if is_malware else "cve",
            cve_id=a.get("cve_id"),
            ghsa_id=a.get("ghsa_id"),
            title=a.get("summary") or "GHSA advisory",
            summary=(a.get("description") or "").strip()[:600],
            severity=severity,
            cvss=cvss,
            is_supply_chain=is_malware,
            ecosystem=ecosystem,
            package=package,
            references=refs,
            tags=[t for t in [
                (ecosystem or "").upper() if ecosystem else None,
                "MALWARE" if is_malware else None,
            ] if t],
            source="github-advisory",
            published=a.get("published_at"),
            updated=a.get("updated_at"),
            first_seen=a.get("first_seen"),
        ))
    return out


def _pocs_to_vulns() -> list[Vuln]:
    raw = _load_json("pocs.json", {"items": []})
    grouped: dict[str, list[dict]] = {}
    for p in raw.get("items", []):
        cve = p.get("cve_id", "")
        if not cve:
            continue
        grouped.setdefault(cve, []).append(p)
    out: list[Vuln] = []
    for cve, items in grouped.items():
        first = items[0]
        pocs = [
            PocLink(
                url=p.get("html_url") or "",
                title=p.get("full_name") or p.get("name") or "",
                stars=int(p.get("stargazers_count") or 0),
            ) for p in items if p.get("html_url")
        ]
        pocs.sort(key=lambda x: -x.stars)
        cvss = None
        try:
            cvss = float(first.get("cvss_score") or 0) or None
        except (TypeError, ValueError):
            cvss = None
        desc = first.get("vuln_description") or first.get("description") or ""
        out.append(Vuln(
            id=cve,
            kind="poc",
            cve_id=cve,
            title=desc[:160].strip() or cve,
            summary=desc[:500].strip(),
            severity=severity_from_cvss(cvss) if cvss else "unknown",
            cvss=cvss,
            pocs=pocs,
            references=[Reference(url=f"https://nvd.nist.gov/vuln/detail/{cve}", label="NVD")],
            tags=["POC", f"{len(pocs)} repos"],
            source="nomi-sec",
            published=first.get("created_at") or first.get("updated_at"),
            updated=first.get("updated_at"),
            first_seen=first.get("first_seen"),
        ))
    return out


def _pkg_scope(name: str | None) -> str | None:
    """Scope key for grouping a typosquat campaign — returns None for
    unscoped packages (so they stay as their own card).

    Real-world typosquat campaigns almost always cluster under a single
    `@org/*` scope (e.g. `@uipath/*`, `@chamilo/*`); unscoped packages
    legitimately have unrelated owners even when names start with the
    same word, so grouping `lodash-utils` with `lodash-helpers` would
    over-merge. Return None there.
    """
    if not name:
        return None
    if name.startswith("@") and "/" in name:
        return name.split("/", 1)[0]
    return None


def _osv_malware_to_vulns() -> list[Vuln]:
    """Pull malicious-package entries straight from OSV (npm + PyPI dumps).

    Replaces the previous `_malpkgs_to_vulns` which listed every commit to
    `ossf/malicious-packages` — the bulk of those commits are infrastructure
    work ("Assign IDs", "Ingest OSV - Cloud Storage"), not actual malware
    reports. OSV-MAL records carry structured package + summary + dates.

    Pipeline:
      1. read both ecosystem dumps, keep is_malware = True
      2. take top-N most recent per ecosystem (npm 300 / pypi 100) — npm
         has 200k MAL records but most are historical; we only care about
         the recent window.
      3. fold near-identical campaigns: same ecosystem + same package scope
         (`@uipath/*` or `requests*`) + same publish-MINUTE collapse to one
         "<scope>/* typosquat (N variants)" card. Reduces top-10 redundancy
         when one attacker registers dozens of variants in seconds.
    """
    per_eco: dict[str, list[dict]] = {"npm": [], "pypi": []}
    for filename, ecosystem in (("osv-npm.json", "npm"), ("osv-pypi.json", "pypi")):
        raw = _load_json(filename, {"items": []})
        for entry in raw.get("items", []):
            if entry.get("is_malware") and entry.get("id"):
                per_eco[ecosystem].append(entry)
    per_eco["npm"].sort(key=lambda e: e.get("published", ""), reverse=True)
    per_eco["pypi"].sort(key=lambda e: e.get("published", ""), reverse=True)
    candidates: list[tuple[dict, str]] = (
        [(e, "npm") for e in per_eco["npm"][:300]]
        + [(e, "pypi") for e in per_eco["pypi"][:100]]
    )

    # Group: scoped `@org/*` packages collapse across all timestamps (single
    # campaign). Unscoped packages get a per-entry key (each is its own card).
    groups: dict[tuple, list[dict]] = {}
    for entry, ecosystem in candidates:
        pkgs = entry.get("packages") or []
        primary_pkg = pkgs[0] if pkgs else ""
        scope = _pkg_scope(primary_pkg)
        if scope:
            key = (ecosystem, scope)
        else:
            # Unscoped → unique key so it doesn't merge with anything else.
            key = (ecosystem, "_solo", entry.get("id", ""))
        groups.setdefault(key, []).append(entry)

    out: list[Vuln] = []
    for group_key, entries in groups.items():
        ecosystem = group_key[0]
        scope = group_key[1] if group_key[1] != "_solo" else None
        head = entries[0]
        variants = len(entries)
        pkgs = [(e.get("packages") or [None])[0] for e in entries]
        pkgs = [p for p in pkgs if p]
        primary_pkg = pkgs[0] if pkgs else None

        # Collect affected versions for the head package(s). For a campaign
        # collapse, we just surface the head entry's versions — listing every
        # variant's versions would explode card height.
        versions: list[str] = []
        head_versions = head.get("versions") or []
        if head_versions and isinstance(head_versions[0], list):
            versions = list(head_versions[0])[:8]
        # OSV `details` often carries campaign attribution (e.g. "Mini Shai-Hulud
        # is back worm by the TeamPCP threat actor"). Prefer it over summary when
        # present because it gives the reader actual context.
        narrative = (head.get("details") or "").strip()
        summary_short = (head.get("summary") or "").strip()

        if variants > 1 and scope:
            title = f"{scope}/* typosquat · {variants} variants ({ecosystem})"
            parts: list[str] = []
            if narrative:
                parts.append(narrative)
            elif summary_short:
                parts.append(summary_short)
            if pkgs:
                parts.append("variants: " + ", ".join(sorted(pkgs)[:6]))
            summary = " | ".join(parts)[:700]
        else:
            title = summary_short or f"Malicious {ecosystem} package {primary_pkg or ''}".strip()
            summary = narrative or summary_short

        refs: list[Reference] = []
        seen_urls: set[str] = set()
        for e in entries[:3]:
            for r in (e.get("references") or [])[:3]:
                if isinstance(r, dict) and r.get("url") and r["url"] not in seen_urls:
                    seen_urls.add(r["url"])
                    refs.append(Reference(url=r["url"], label=r.get("type") or ""))
        fs_values = [e.get("first_seen") for e in entries if e.get("first_seen")]
        first_seen = max(fs_values) if fs_values else None
        tags = [ecosystem.upper(), "MALWARE"]
        if variants > 1:
            tags.append(f"×{variants}")
        # Surface threat-actor / campaign attribution as a tag when OSV's details
        # mention well-known campaign names. Cheap heuristic; precision > recall.
        narrative_lower = (narrative or "").lower()
        for campaign in ("shai-hulud", "teampcp", "north korea", "lazarus", "dprk"):
            if campaign in narrative_lower:
                tags.append(campaign.upper())
                break
        out.append(Vuln(
            id=head.get("id", ""),
            kind="supply",
            title=title,
            summary=summary,
            severity="high",
            is_supply_chain=True,
            ecosystem=ecosystem,
            package=primary_pkg,
            references=refs,
            affected_versions=versions,
            tags=tags,
            source="osv-malware",
            published=head.get("published"),
            updated=head.get("modified"),
            first_seen=first_seen,
        ))
    out.sort(key=lambda v: v.published or "", reverse=True)
    return out[:200]


def _cve_signals() -> dict[str, dict]:
    """Pre-compute per-CVE signals: EPSS, HN mentions, Mastodon mentions, Nuclei.

    Returned shape:  {cve_id: {epss, epss_p, hn_mentions, masto_mentions, nuclei_url}}
    All sub-keys may be missing if the source had no entry for that CVE.
    """
    epss = _load_json("epss.json", {"items": {}})
    hn = _load_json("hn.json", {"items": []})
    masto = _load_json("masto.json", {"items": []})
    nuclei = _load_json("nuclei.json", {"items": {}})

    signals: dict[str, dict] = {}

    for cve, scores in (epss.get("items") or {}).items():
        if not isinstance(scores, dict):
            continue
        slot = signals.setdefault(cve, {})
        slot["epss"] = scores.get("score")
        slot["epss_p"] = scores.get("percentile")

    for h in hn.get("items", []) or []:
        for cve in (h.get("cve_mentions") or []):
            slot = signals.setdefault(cve, {})
            slot["hn_mentions"] = slot.get("hn_mentions", 0) + 1

    for s in masto.get("items", []) or []:
        for cve in (s.get("cve_mentions") or []):
            slot = signals.setdefault(cve, {})
            slot["masto_mentions"] = slot.get("masto_mentions", 0) + 1
            slot["masto_engagement"] = slot.get("masto_engagement", 0) + int(s.get("favourites", 0)) + 2 * int(s.get("reblogs", 0))

    for cve, info in (nuclei.get("items") or {}).items():
        if not isinstance(info, dict):
            continue
        slot = signals.setdefault(cve, {})
        slot["nuclei_url"] = info.get("url")

    return signals


# ─────────── public loaders ───────────

def all_vulns() -> list[Vuln]:
    vulns = _kev_to_vulns() + _ghsa_to_vulns() + _pocs_to_vulns() + _osv_malware_to_vulns()
    # cross-link: if a CVE appears in multiple sources, merge KEV/ITW flags & PoCs
    by_cve: dict[str, Vuln] = {}
    extra: list[Vuln] = []
    for v in vulns:
        key = v.cve_id or v.id
        if not key:
            extra.append(v)
            continue
        if key in by_cve:
            existing = by_cve[key]
            existing.is_kev = existing.is_kev or v.is_kev
            existing.is_itw = existing.is_itw or v.is_itw
            existing.is_ransomware = existing.is_ransomware or v.is_ransomware
            existing.is_supply_chain = existing.is_supply_chain or v.is_supply_chain
            # PoC merge: dedupe by URL, keep top-12 by stars (no longer
            # silently dropped if the first source's list is already full).
            # When same URL appears in both lists, take the higher star count
            # but preserve a non-empty title from either copy.
            combined: dict[str, PocLink] = {}
            for p in existing.pocs + v.pocs:
                if not p.url:
                    continue
                prev = combined.get(p.url)
                if prev is None:
                    combined[p.url] = p
                else:
                    combined[p.url] = PocLink(
                        url=p.url,
                        title=prev.title or p.title,
                        stars=max(prev.stars, p.stars),
                    )
            existing.pocs = sorted(combined.values(), key=lambda x: -x.stars)[:12]
            if not existing.cvss and v.cvss:
                existing.cvss = v.cvss
            # Reference merge: set-based dedupe by URL (was O(n²)).
            seen_urls = {x.url for x in existing.references if x.url}
            for r in v.references:
                if r.url and r.url not in seen_urls:
                    existing.references.append(r)
                    seen_urls.add(r.url)
            for t in v.tags:
                if t and t not in existing.tags:
                    existing.tags.append(t)
        else:
            by_cve[key] = v
    merged = list(by_cve.values()) + extra
    # join CVE-level external signals (EPSS / HN / Mastodon / Nuclei)
    signals = _cve_signals()
    # AI assessments (written by llm_rank.py --task vuln_assess)
    ai_data = _load_json("vuln_ai.json", {})
    for v in merged:
        s = signals.get(v.cve_id) if v.cve_id else None
        if s:
            v.epss_score = s.get("epss")
            v.epss_percentile = s.get("epss_p")
            v.hn_mentions = int(s.get("hn_mentions", 0))
            v.masto_mentions = int(s.get("masto_mentions", 0))
            v.nuclei_template_url = s.get("nuclei_url")
        ai = ai_data.get(v.cve_id or v.id)
        if isinstance(ai, dict):
            raw_sev = ai.get("ai_severity")
            if raw_sev in ("critical", "high", "medium", "low"):
                v.ai_severity = raw_sev
            v.ai_summary = ai.get("ai_summary")
        v.kind = classify_kind(v)
        v.severity = derive_severity(v)
        v.heat = compute_heat(v)
    merged.sort(key=lambda x: (-x.heat, x.cve_id or x.id))
    return merged


_SEV_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def classify_kind(v: Vuln) -> "VulnKind":  # type: ignore[name-defined]
    """Pick the most informative kind for UI categorization.

    Precedence (most-actionable first):
      itw    – CISA KEV listing or analyst-confirmed in-the-wild exploitation
      supply – malicious package / typosquat / dependency confusion
      poc    – public exploit code exists
      cve    – fallback (CVSS-rated advisory, no PoC yet, not ITW)
    """
    if v.is_itw or v.is_kev:
        return "itw"
    if v.is_supply_chain:
        return "supply"
    if v.pocs:
        return "poc"
    return "cve"


def derive_severity(v: Vuln) -> "Severity":  # type: ignore[name-defined]
    """Pick the highest justified severity for this vuln.

    Precedence:
      1. CVSS-derived severity (when v.cvss is set).
      2. Upstream-provided severity string (e.g. GHSA's "severity" field).
      3. Escalation: KEV / ITW listings lift severity to at least 'high'
         (but never force 'critical' — that remains a CVSS 9.0+ judgement).
    """
    base = v.severity or "unknown"
    if v.cvss is not None:
        cvss_sev = severity_from_cvss(v.cvss)
        if _SEV_RANK.get(cvss_sev, 0) > _SEV_RANK.get(base, 0):
            base = cvss_sev
    if (v.is_kev or v.is_itw) and _SEV_RANK.get(base, 0) < _SEV_RANK["high"]:
        return "high"
    return base


def compute_heat(v: Vuln) -> int:
    """Normalized 0-100 threat score.

    Components:
      KEV (+20) + ITW (+15) — additive, dual confirmation outranks single
      Ransomware (+8)
      EPSS (×30, age-dampened)
      PoC availability (0-10)  — count + stars
      Nuclei template (+8)
      Freshness (0-15, 168h/7d linear decay)
      Social (HN+Masto, cap 8)
      Supply-chain (0-12, 168h linear decay)
      Severity tiebreaker (0-4)
    """
    h = 0

    if v.is_kev:
        h += 20
    if v.is_itw:
        h += 15
    if v.is_ransomware:
        h += 8

    if v.epss_score is not None:
        epss_boost = v.epss_score * 30
        pub = parse_iso_date(v.published)
        if pub is not None:
            age_y = (datetime.now(timezone.utc) - pub).days / 365
            if age_y > 1:
                epss_boost *= max(0.4, 1 - 0.15 * (age_y - 1))
        h += int(round(epss_boost))

    if v.pocs:
        poc_score = min(len(v.pocs), 5) * 1.2
        star_score = min(sum(p.stars for p in v.pocs[:5]), 100) / 20
        h += int(round(min(poc_score + star_score, 10)))

    if v.nuclei_template_url:
        h += 8

    fs = parse_iso_date(v.first_seen) or parse_iso_date(v.published)
    now = datetime.now(timezone.utc)
    if fs is not None:
        age_h = (now - fs).total_seconds() / 3600
        if age_h < 0:
            h += 15
        elif age_h <= 168:
            h += int(round(15 * (1 - age_h / 168)))

    social = min(v.hn_mentions * 1.5 + v.masto_mentions, 8)
    h += int(round(social))

    if v.is_supply_chain and fs is not None:
        age_h_sc = (now - fs).total_seconds() / 3600
        if age_h_sc < 0:
            h += 12
        elif age_h_sc <= 168:
            h += int(round(12 * (1 - age_h_sc / 168)))

    h += {"critical": 4, "high": 3, "medium": 1, "low": 0, "unknown": 0}.get(v.severity, 0)
    return min(h, 100)


def all_articles() -> list[Article]:
    """SQLite-backed: primary articles (or unclustered) where is_relevant != 0,
    with mirror_source_titles attached for the cluster.

    Cached against news.db mtime — every request was rebuilding ~10k Pydantic
    models, dominating hot-path latency. Invalidates on any DB write."""
    if not _NEWS_DB.exists():
        return []
    mtime = _NEWS_DB.stat().st_mtime
    cached = _state.get("__articles_sqlite__")
    if cached and cached[0] == mtime:
        return cached[1]

    conn = _news_conn()
    # Pre-fetch mirror source titles, grouped by cluster
    mirror_titles: dict = {}
    for r in conn.execute("""
        SELECT cluster_id, source_title
        FROM articles
        WHERE cluster_id IS NOT NULL AND is_cluster_primary = 0
        ORDER BY fetched_at ASC
    """):
        mirror_titles.setdefault(r["cluster_id"], []).append(r["source_title"] or "")

    rows = list(conn.execute("""
        SELECT * FROM articles
        WHERE (is_relevant = 1 OR is_relevant IS NULL)
          AND (cluster_id IS NULL OR is_cluster_primary = 1)
        ORDER BY COALESCE(llm_score, -1) DESC, COALESCE(published, fetched_at) DESC
    """))
    conn.close()
    items = [_row_to_article(r, mirror_titles) for r in rows]
    _state["__articles_sqlite__"] = (mtime, items)
    return items


def all_sources() -> list[SourceStatus]:
    """News sources from SQLite sources table."""
    if not _NEWS_DB.exists():
        return []
    out: list[SourceStatus] = []
    conn = _news_conn()
    for r in conn.execute("""
        SELECT slug, title, url, lang, ok, error,
               (SELECT COUNT(*) FROM articles WHERE source_slug = sources.slug) AS count
        FROM sources
    """):
        lang_raw = r["lang"]
        lang_val = lang_raw if lang_raw in ("zh", "en") else "mixed"
        out.append(SourceStatus(
            slug=r["slug"], title=r["title"] or r["slug"], url=r["url"] or "",
            lang=lang_val,
            ok=bool(r["ok"]), count=int(r["count"] or 0),
            error=r["error"],
        ))
    conn.close()
    return out


def heat_board(limit: int = 10) -> list[HeatEntry]:
    vulns = all_vulns()
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
        articles = [a for a in articles
                    if (a.published or "")[:10] == date or
                       (not a.published and date)]  # accept undated for today
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
