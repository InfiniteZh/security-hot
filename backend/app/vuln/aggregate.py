"""Cross-source Vuln merge + external-signal join + AI assessment injection."""
from __future__ import annotations

from ..cache_io import _load_json
from ..models import PocLink, Vuln
from ..scoring import classify_kind, compute_heat, derive_severity
from .murphy import _murphy_to_vulns
from .sources import (
    _cve_signals,
    _ghsa_to_vulns,
    _kev_to_vulns,
    _news_cve_to_vulns,
    _osv_malware_to_vulns,
    _pocs_to_vulns,
)


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
        if v.source and v.source not in v.sources:
            v.sources.append(v.source)
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
            seen_iocs = set(existing.iocs)
            for ioc in v.iocs:
                if ioc and ioc not in seen_iocs:
                    existing.iocs.append(ioc)
                    seen_iocs.add(ioc)
            seen_fix = set(existing.fix_versions)
            for fix_version in v.fix_versions:
                if fix_version and fix_version not in seen_fix:
                    existing.fix_versions.append(fix_version)
                    seen_fix.add(fix_version)
            # Reference merge: set-based dedupe by URL (was O(n²)).
            seen_urls = {x.url for x in existing.references if x.url}
            for r in v.references:
                if r.url and r.url not in seen_urls:
                    existing.references.append(r)
                    seen_urls.add(r.url)
            for t in v.tags:
                if t and t not in existing.tags:
                    existing.tags.append(t)
            for source in v.sources or [v.source]:
                if source and source not in existing.sources:
                    existing.sources.append(source)
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
