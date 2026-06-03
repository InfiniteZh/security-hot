"""MurphySec vuln_warn → Vuln normalization (the largest single source parser)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..cache_io import CVE_RE, _load_json, parse_iso_date, severity_from_cvss
from ..models import Reference, Severity, Vuln


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


def _murphy_fix_versions(entries: list[dict]) -> list[str]:
    values: list[str | None] = []
    for entry in entries:
        affected = entry.get("affected") or {}
        if not isinstance(affected, dict):
            continue
        expression = affected.get("expression") or {}
        if isinstance(expression, dict):
            values.append(expression.get("fix_version"))
        values.append(affected.get("upstream_fix_version"))
    return _dedupe_nonempty(values)[:12]


def _murphy_iocs(item: dict) -> list[str]:
    raw = item.get("ioc") or item.get("iocs") or []
    if isinstance(raw, str):
        values = re.split(r"[,;\n]", raw)
    elif isinstance(raw, list):
        values = raw
    else:
        values = []
    return _dedupe_nonempty(values)


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
        fix_versions = _murphy_fix_versions(affected_entries)
        iocs = _murphy_iocs(item)
        out.append(Vuln(
            id=cve or ghsa or f"MURPHY-{key}",
            # MurphySec is a software-composition / dependency source that reports
            # BOTH ordinary vulnerabilities in legit packages AND genuinely poisoned
            # (malicious) packages. Only the latter is supply-chain *poisoning* — gate
            # is_supply_chain on the malicious flag so plain dependency CVEs stay 'cve'.
            # Final kind is recomputed by classify_kind (KEV/ITW still outrank supply).
            kind="supply" if malicious else "cve",
            cve_id=cve,
            ghsa_id=ghsa,
            title=title[:220],
            summary=summary,
            severity=severity,
            cvss=cvss,
            is_supply_chain=malicious,
            ecosystem=ecosystem,
            package=package,
            vendor=vendor,
            product=product,
            references=_murphy_references(item),
            affected_versions=affected_versions,
            iocs=iocs,
            fix_versions=fix_versions,
            tags=tags,
            source="murphysec",
            published=published or updated,
            updated=updated,
            first_seen=item.get("first_seen"),
        ))
    out.sort(key=lambda v: v.updated or v.published or "", reverse=True)
    return out
