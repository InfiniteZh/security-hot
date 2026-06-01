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
    SearchLink,
    SearchResult,
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


def _first_text(item: dict, *keys: str) -> str | None:
    for key in keys:
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _first_float(item: dict, *keys: str) -> float | None:
    for key in keys:
        value = item.get(key)
        if value is None or value == "":
            continue
        try:
            score = float(value)
        except (TypeError, ValueError):
            continue
        if 0 < score <= 10:
            return score
    return None


def _first_cve(item: dict) -> str | None:
    for key in ("cve_id", "cveId", "cve", "cve_no", "cveNo"):
        value = item.get(key)
        if value:
            m = CVE_RE.search(str(value))
            if m:
                return m.group(0).upper()
    for value in item.values():
        if isinstance(value, str):
            m = CVE_RE.search(value)
            if m:
                return m.group(0).upper()
    return None


def _first_ghsa(item: dict) -> str | None:
    ghsa_re = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)
    for key in ("ghsa_id", "ghsaId", "ghsa", "id"):
        value = item.get(key)
        if value:
            m = ghsa_re.search(str(value))
            if m:
                return m.group(0).upper()
    return None


def _normalize_murphy_severity(item: dict, cvss: float | None) -> Severity:
    raw = _first_text(
        item,
        "severity", "level", "risk_level", "riskLevel", "vuln_level", "vulnLevel",
        "cvss_level", "cvssLevel", "hazard_level", "hazardLevel",
    )
    text = (raw or "").strip().lower()
    if any(x in text for x in ("critical", "严重", "超危", "紧急", "危急")):
        return "critical"
    if any(x in text for x in ("high", "高危", "高")):
        return "high"
    if any(x in text for x in ("medium", "moderate", "中危", "中")):
        return "medium"
    if any(x in text for x in ("low", "低危", "低")):
        return "low"
    return severity_from_cvss(cvss)


def _normalize_murphy_time(item: dict, *keys: str) -> str | None:
    value = _first_text(item, *keys)
    if not value:
        return None
    parsed = parse_iso_date(value)
    if parsed is None:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
    if parsed is None:
        return value
    # MurphySec timestamps carry +08:00 (Beijing). Normalize to UTC so date
    # filtering (which compares the YYYY-MM-DD prefix against UTC dates) stays
    # consistent with KEV/GHSA and avoids a ±1-day skew near the day boundary.
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _murphy_bool(item: dict, *keys: str) -> bool:
    markers = ("投毒", "恶意", "后门", "木马", "malicious", "malware", "backdoor", "trojan")
    for key in keys:
        value = item.get(key)
        if isinstance(value, bool):
            return value
        if value is None:
            continue
        text = str(value).strip().lower()
        if text in {"1", "true", "yes", "y"}:
            return True
        if any(marker in text for marker in markers):
            return True
    problem = item.get("problem_type") or item.get("problemType") or {}
    if isinstance(problem, dict):
        cwe = str(problem.get("cwe") or "").strip().lower()
        if cwe == "cwe-506":
            return True
        problem_text = str(problem.get("meaning") or "")
    else:
        problem_text = str(problem)
    if "cwe-506" in problem_text.lower():
        return True
    raw_tags = item.get("tags") or []
    if isinstance(raw_tags, list):
        tag_text = " ".join(str(tag) for tag in raw_tags)
    else:
        tag_text = str(raw_tags)
    combined = f"{problem_text} {tag_text}".lower()
    return any(marker in combined for marker in markers)


def _murphy_title_package(title: str | None) -> tuple[str | None, str | None]:
    if not title:
        return None, None
    m = re.search(r"(PyPI|PIP|NPM|Maven|Go|NuGet|RubyGems|Cargo)仓库\s*(.+?)等(?:包|组件)", title, re.IGNORECASE)
    if not m:
        return None, None
    ecosystem_raw = m.group(1).lower()
    ecosystem_map = {
        "pip": "pypi",
        "pypi": "pypi",
        "npm": "npm",
        "maven": "maven",
        "go": "go",
        "nuget": "nuget",
        "rubygems": "rubygems",
        "cargo": "cargo",
    }
    return ecosystem_map.get(ecosystem_raw, ecosystem_raw), m.group(2).strip()


def _normalize_murphy_ecosystem(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip().lower()
    aliases = {
        "pip": "pypi",
        "python": "pypi",
        "node": "npm",
        "nodejs": "npm",
        "javascript": "npm",
    }
    return aliases.get(text, text)


def _murphy_language_ecosystem(item: dict) -> str | None:
    raw = item.get("language")
    if isinstance(raw, list):
        text = " ".join(str(x) for x in raw)
    elif raw is not None:
        text = str(raw)
    else:
        return None
    text = text.lower()
    if "python" in text:
        return "pypi"
    if any(x in text for x in ("javascript", "node", "npm")):
        return "npm"
    if "java" in text:
        return "maven"
    if "golang" in text or re.search(r"\bgo\b", text):
        return "go"
    return None


def _murphy_references(item: dict) -> list[Reference]:
    refs: list[Reference] = []
    seen: set[str] = set()

    def add(url: str | None, label: str = "") -> None:
        if not url:
            return
        url = str(url).strip()
        if not url.startswith(("http://", "https://")) or url in seen:
            return
        refs.append(Reference(url=url, label=label))
        seen.add(url)

    for key in ("url", "link", "detail_url", "detailUrl", "vuln_url", "vulnUrl"):
        add(item.get(key), "MurphySec")
    raw_refs = item.get("references") or item.get("refs") or item.get("reference")
    if isinstance(raw_refs, str):
        for url in re.findall(r"https?://[^\s,;]+", raw_refs):
            add(url)
    elif isinstance(raw_refs, list):
        for ref in raw_refs[:8]:
            if isinstance(ref, dict):
                add(ref.get("url") or ref.get("link"), ref.get("name") or ref.get("label") or ref.get("type") or "")
            else:
                add(str(ref))
    return refs[:8]


def _murphy_affected_entries(item: dict) -> list[dict]:
    raw = item.get("affected_version") or item.get("affectedVersion") or []
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def _dedupe_nonempty(values) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text or text in seen:
            continue
        out.append(text)
        seen.add(text)
    return out


def _murphy_packages(entries: list[dict]) -> str | None:
    names = _dedupe_nonempty(entry.get("name") for entry in entries)
    if not names:
        return None
    return ", ".join(names[:4])


def _murphy_affected_versions(item: dict, entries: list[dict]) -> list[str]:
    ranges = _dedupe_nonempty(
        (entry.get("affected") or {}).get("version_range")
        for entry in entries
        if isinstance(entry.get("affected") or {}, dict)
    )
    if ranges:
        return ranges[:12]
    versions = item.get("affected_versions") or item.get("affectedVersions") or item.get("versions") or []
    if isinstance(versions, str):
        return [v.strip() for v in re.split(r"[,;\n]", versions) if v.strip()][:12]
    if isinstance(versions, list):
        return [str(v) for v in versions[:12] if v]
    return []


def _murphy_to_vulns() -> list[Vuln]:
    raw = _load_json("murphy.json", {"items": []})
    out: list[Vuln] = []
    for item in raw.get("items", []):
        if not isinstance(item, dict):
            continue
        cve = _first_cve(item)
        ghsa = _first_ghsa(item)
        key = _first_text(item, "_murphy_key", "id", "vuln_id", "vulnId", "mps_id", "mpsId") or cve or ghsa
        if not key:
            continue
        title = _first_text(
            item,
            "title", "vuln_name", "vulnName", "vuln_title", "vulnTitle", "name",
        ) or cve or ghsa or str(key)
        affected_entries = _murphy_affected_entries(item)
        title_ecosystem, title_package = _murphy_title_package(title)
        summary_parts = [
            _first_text(item, "summary", "description", "desc", "vuln_desc", "vulnDesc", "detail", "details"),
            _first_text(item, "solution", "fix", "remediation", "repair_suggestion", "repairSuggestion"),
        ]
        summary = " | ".join(p for p in summary_parts if p)[:800]
        cvss = _first_float(item, "cvss_score", "cvssScore", "cvss", "cvss_v3_score", "cvssV3Score")
        severity = _normalize_murphy_severity(item, cvss)
        package = (
            _murphy_packages(affected_entries)
            or _first_text(
                item,
                "package_name", "packageName", "package", "pkg_name", "pkgName",
                "component_name", "componentName", "artifact_id", "artifactId",
            )
            or title_package
        )
        ecosystem = (
            _normalize_murphy_ecosystem(_first_text(item, "ecosystem", "package_type", "packageType", "repository"))
            or _normalize_murphy_ecosystem(next((str(entry.get("repository")) for entry in affected_entries if entry.get("repository")), None))
            or _normalize_murphy_ecosystem(title_ecosystem)
            or _normalize_murphy_ecosystem(_murphy_language_ecosystem(item))
        )
        vendor = _first_text(item, "vendor", "vendor_name", "vendorName")
        product = _first_text(item, "product", "product_name", "productName", "component_name", "componentName")
        malicious = _murphy_bool(
            item,
            "is_malicious", "isMalicious", "malicious", "malicious_code",
            "maliciousCode", "threat_type", "threatType", "type",
        )
        tags = ["MURPHY"]
        if malicious:
            tags.append("MALWARE")
        if ecosystem:
            tags.append(ecosystem.upper())
        published = _normalize_murphy_time(
            item,
            "publish_time", "publishTime", "public_time", "publicTime",
            "published", "published_at", "published_date", "publishedDate",
            "created_at", "create_time", "createTime",
        )
        updated = _normalize_murphy_time(
            item,
            "last_modify_time", "lastModifyTime", "modify_time", "modified_at",
            "last_updated_time", "lastUpdatedTime", "updated_at", "updated",
        )
        affected_versions = _murphy_affected_versions(item, affected_entries)
        out.append(Vuln(
            id=cve or ghsa or f"MURPHY-{key}",
            # MurphySec is a software-composition / dependency source → always
            # categorize as supply-chain risk (final kind is recomputed by
            # classify_kind, where KEV/ITW still outranks supply for overlaps).
            kind="supply",
            cve_id=cve,
            ghsa_id=ghsa,
            title=title[:220],
            summary=summary,
            severity=severity,
            cvss=cvss,
            is_supply_chain=True,
            ecosystem=ecosystem,
            package=package,
            vendor=vendor,
            product=product,
            references=_murphy_references(item),
            affected_versions=affected_versions,
            tags=tags,
            source="murphysec",
            published=published or updated,
            updated=updated,
            first_seen=item.get("first_seen"),
        ))
    out.sort(key=lambda v: v.updated or v.published or "", reverse=True)
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


_VULN_RSS_SOURCES = frozenset({
    "vulners", "vuldb", "sploitus",
    "vulners_com", "vuldb_com", "sploitus_com",
    "blog_nsfocus_net", "securityonline_info",
})


def _news_cve_to_vulns(*, db_path: Path | None = None) -> list[Vuln]:
    """Bridge: extract CVE-IDs from vuln-focused news RSS and synthesize Vuln objects."""
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


# ─────────── public loaders ───────────

def all_vulns() -> list[Vuln]:
    vulns = (
        _kev_to_vulns()
        + _ghsa_to_vulns()
        + _pocs_to_vulns()
        + _murphy_to_vulns()
        + _osv_malware_to_vulns()
        + _news_cve_to_vulns()
    )
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


_CJK_RE = re.compile(r"[一-鿿　-ヿ＀-￯]")


def search_articles(q: str, limit: int = 200) -> list[Article]:
    """Full-text article search across title + summary + llm_summary_zh + source_title.

    Two paths, chosen by query character set:

    * Pure ASCII (vendors, CVE-IDs, English keywords) → FTS5 MATCH on
      `articles_fts` (unicode61 tokenizer). CVE-IDs and other hyphenated
      tokens are quoted as phrases; short ASCII words get a trailing `*`
      for prefix search.
    * Anything containing CJK characters → LIKE %q% scan across all four
      columns. FTS5 unicode61 doesn't segment Chinese (it lumps each
      no-space run into one token), so MATCH would return nothing useful
      for queries like "备份" or "微软". The LIKE scan is slower but works
      directly on the indexed string and gives substring semantics users
      expect.

    Source-name hits (e.g. "BleepingComputer") work in either path: ASCII
    path adds a source_title LIKE union; CJK path already covers source_title.
    Restricts to primary cluster articles where is_relevant != 0.
    """
    q = (q or "").strip()
    if not q or len(q) < 2:
        return []
    if not _NEWS_DB.exists():
        return []

    conn = _news_conn()
    try:
        mirror_titles: dict = {}
        for r in conn.execute(
            "SELECT cluster_id, source_title FROM articles "
            "WHERE cluster_id IS NOT NULL AND is_cluster_primary = 0 "
            "ORDER BY fetched_at ASC"
        ):
            mirror_titles.setdefault(r["cluster_id"], []).append(r["source_title"] or "")

        rows_by_id: dict[int, tuple[float, dict]] = {}
        has_cjk = bool(_CJK_RE.search(q))

        if not has_cjk:
            # FTS5 path. Build a syntactically-safe query string.
            tokens = [t for t in re.split(r"\s+", q) if t]
            fts_terms: list[str] = []
            for t in tokens:
                if re.search(r"[^A-Za-z0-9]", t):
                    fts_terms.append('"' + t.replace('"', '""') + '"')
                else:
                    fts_terms.append(t + "*")
            fts_query = " ".join(fts_terms)
            try:
                for r in conn.execute(
                    """
                    SELECT a.*, fts.rank AS fts_rank
                    FROM articles a
                    JOIN articles_fts fts ON fts.rowid = a.id
                    WHERE articles_fts MATCH ?
                      AND (a.is_relevant = 1 OR a.is_relevant IS NULL)
                      AND (a.cluster_id IS NULL OR a.is_cluster_primary = 1)
                    ORDER BY fts.rank
                    LIMIT ?
                    """,
                    [fts_query, limit],
                ):
                    rows_by_id[r["id"]] = (r["fts_rank"] or 0.0, dict(r))
            except _sqlite3.OperationalError:
                pass  # bad FTS5 syntax; LIKE fallback below still runs

        # LIKE path. For CJK (and mixed ASCII+CJK) queries, FTS5 is skipped
        # above so this path covers title/summary/llm_summary_zh/source_title.
        # For pure-ASCII queries, this only adds source_title (FTS5 doesn't
        # index source name).
        #
        # Multi-token queries combine with AND across columns: every
        # whitespace-separated token must appear in at least one of the
        # searched columns. This makes "Kopia 备份" match an article whose
        # title contains "Kopia" and whose Chinese summary contains "备份".
        tokens = [t.lower() for t in re.split(r"\s+", q) if t]
        if has_cjk:
            per_token = (
                "(lower(title) LIKE ? OR lower(summary) LIKE ? "
                "OR lower(llm_summary_zh) LIKE ? OR lower(source_title) LIKE ?)"
            )
            where_clauses = [per_token] * len(tokens)
            params: list = []
            for t in tokens:
                pat = f"%{t}%"
                params.extend([pat, pat, pat, pat])
            params.append(limit)
            sql = f"""
                SELECT * FROM articles
                WHERE {' AND '.join(where_clauses)}
                  AND (is_relevant = 1 OR is_relevant IS NULL)
                  AND (cluster_id IS NULL OR is_cluster_primary = 1)
                ORDER BY COALESCE(llm_score, -1) DESC,
                         COALESCE(published, fetched_at) DESC
                LIMIT ?
            """
        else:
            sql = """
                SELECT * FROM articles
                WHERE lower(source_title) LIKE ?
                  AND (is_relevant = 1 OR is_relevant IS NULL)
                  AND (cluster_id IS NULL OR is_cluster_primary = 1)
                LIMIT ?
            """
            params = [f"%{q.lower()}%", limit]
        for i, r in enumerate(conn.execute(sql, params)):
            if r["id"] not in rows_by_id:
                # Stable rank-after-FTS for LIKE-only hits.
                rows_by_id[r["id"]] = (1e9 + i, dict(r))

        sorted_rows = sorted(rows_by_id.values(), key=lambda t: t[0])[:limit]
        return [_row_to_article(r[1], mirror_titles) for r in sorted_rows]
    finally:
        conn.close()


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
