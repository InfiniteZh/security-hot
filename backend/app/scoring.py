"""Pure scoring / classification for Vuln objects (no I/O)."""
from __future__ import annotations

from datetime import datetime, timezone

from .cache_io import parse_iso_date, severity_from_cvss
from .models import Severity, Vuln

_SEV_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def classify_kind(v: Vuln) -> str:
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
