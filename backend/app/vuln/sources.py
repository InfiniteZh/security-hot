"""KEV / GHSA / nomi-sec PoC / OSV-malware / news-bridge → Vuln normalization,
plus per-CVE external signal precomputation (EPSS / HN / Mastodon / Nuclei)."""
from __future__ import annotations

from pathlib import Path

from .. import cache_io
from ..cache_io import CVE_RE, _load_json, severity_from_cvss
from ..models import PocLink, Reference, Severity, Vuln


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


_SIGNAL_FILES = ("epss.json", "hn.json", "masto.json", "nuclei.json")
_signals_cache: tuple[tuple, dict[str, dict]] | None = None


def _signal_files_key() -> tuple:
    """mtime fingerprint of the 4 signal source files (None when absent)."""
    out = []
    for name in _SIGNAL_FILES:
        p = cache_io.CACHE / name
        out.append(p.stat().st_mtime if p.exists() else None)
    return tuple(out)


def _cve_signals() -> dict[str, dict]:
    """Pre-compute per-CVE signals: EPSS, HN mentions, Mastodon mentions, Nuclei.

    Returned shape:  {cve_id: {epss, epss_p, hn_mentions, masto_mentions, nuclei_url}}
    All sub-keys may be missing if the source had no entry for that CVE.

    Memoized by source-file mtimes: EPSS alone is 300k+ entries, and this dict
    was previously rebuilt on every /api/vuln request. The cache is invalidated
    automatically when any of the 4 files is re-fetched (mtime changes).
    """
    global _signals_cache
    key = _signal_files_key()
    if _signals_cache is not None and _signals_cache[0] == key:
        return _signals_cache[1]

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

    _signals_cache = (key, signals)
    return signals


_VULN_RSS_SOURCES = frozenset({
    "vulners", "vuldb", "sploitus",
    "vulners_com", "vuldb_com", "sploitus_com",
    "blog_nsfocus_net", "securityonline_info",
})


def _news_cve_to_vulns(*, db_path: Path | None = None) -> list[Vuln]:
    """Bridge: extract CVE-IDs from vuln-focused news RSS and synthesize Vuln objects."""
    db = db_path or cache_io._NEWS_DB
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
