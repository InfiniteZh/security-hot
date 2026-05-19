"""Merge security RSS feeds from multiple OPML sources, dedupe, and probe liveness.

Sources:
  - rss/awesome-security-feed/security_feeds.opml
  - rss/CyberSecurityRSS/CyberSecurityRSS.opml
  - rss/Chinese-Security-RSS/Chinese-Security-RSS.opml
  - rss/wechat2rss/sec.opml (cached from https://wechat2rss.xlab.app/opml/sec.opml)

Outputs:
  - rss/merged.opml                (alive feeds by default; --include-dead keeps all)
  - scripts/output/health.csv      (per-feed probe result)
  - scripts/output/health.md       (summary + list of dead/stale feeds)

Usage:
  python scripts/merge_rss.py
  python scripts/merge_rss.py --refresh                    # re-fetch wechat2rss OPML
  python scripts/merge_rss.py --days 90                    # 90-day freshness window
  python scripts/merge_rss.py --concurrency 16 --per-host 2
  python scripts/merge_rss.py --no-probe                   # just merge + dedupe, skip probing
  python scripts/merge_rss.py --include-dead               # write dead feeds to merged.opml too
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

try:
    import httpx
except ImportError:
    sys.exit("missing dependency: httpx (pip install -r scripts/requirements.txt)")

try:
    import feedparser
except ImportError:
    sys.exit("missing dependency: feedparser (pip install -r scripts/requirements.txt)")


REPO_ROOT = Path(__file__).resolve().parent.parent
RSS_DIR = REPO_ROOT / "rss"
SCRIPTS_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = SCRIPTS_DIR / "output"

WECHAT2RSS_URL = "https://wechat2rss.xlab.app/opml/sec.opml"
WECHAT2RSS_LOCAL = RSS_DIR / "wechat2rss" / "sec.opml"

SOURCES: list[tuple[Path, str]] = [
    (RSS_DIR / "awesome-security-feed" / "security_feeds.opml", "awesome-security-feed"),
    (RSS_DIR / "CyberSecurityRSS" / "CyberSecurityRSS.opml", "CyberSecurityRSS"),
    (RSS_DIR / "Chinese-Security-RSS" / "Chinese-Security-RSS.opml", "Chinese-Security-RSS"),
    (WECHAT2RSS_LOCAL, "wechat2rss"),
]

USER_AGENT = (
    "Mozilla/5.0 (compatible; security-hot-rss-merger/1.0; "
    "+https://github.com/) feedparser/python-httpx"
)
ACCEPT_HEADER = (
    "application/rss+xml, application/atom+xml, application/xml;q=0.9, "
    "text/xml;q=0.8, */*;q=0.5"
)


@dataclass
class Feed:
    title: str
    xml_url: str
    html_url: str = ""
    category: str = ""
    sources: list[str] = field(default_factory=list)


@dataclass
class ProbeResult:
    feed: Feed
    status_code: int | None = None
    parsed_ok: bool = False
    recent: bool = False
    alive: bool = False
    entries: int = 0
    last_update: datetime | None = None
    final_url: str = ""
    error: str = ""
    elapsed_ms: int = 0


def normalize_url(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    if url.lower().startswith("feed://"):
        url = "http://" + url[7:]
    try:
        p = urlparse(url)
        if not p.netloc:
            return url.lower().rstrip("/")
        scheme = p.scheme.lower() or "http"
        host = p.netloc.lower()
        if host.endswith(":80") and scheme == "http":
            host = host[:-3]
        if host.endswith(":443") and scheme == "https":
            host = host[:-4]
        path = p.path or "/"
        if len(path) > 1:
            path = path.rstrip("/")
        suffix = f"?{p.query}" if p.query else ""
        return f"{scheme}://{host}{path}{suffix}"
    except Exception:
        return url.lower()


def parse_opml(path: Path, source_name: str) -> list[Feed]:
    feeds: list[Feed] = []
    if not path.exists():
        print(f"[warn] OPML not found: {path}", file=sys.stderr)
        return feeds
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        print(f"[error] parse {path}: {exc}", file=sys.stderr)
        return feeds

    def walk(node: ET.Element, category: str) -> None:
        for child in node:
            if child.tag.split("}")[-1] != "outline":
                continue
            xml_url = (child.attrib.get("xmlUrl") or "").strip()
            title = (child.attrib.get("title") or child.attrib.get("text") or "").strip()
            if xml_url:
                feeds.append(
                    Feed(
                        title=title,
                        xml_url=xml_url,
                        html_url=(child.attrib.get("htmlUrl") or "").strip(),
                        category=category,
                        sources=[source_name],
                    )
                )
            else:
                walk(child, title or category)

    body = tree.getroot().find("body")
    if body is None:
        body = tree.getroot()
    walk(body, "")
    return feeds


def dedupe(feeds: list[Feed]) -> list[Feed]:
    seen: dict[str, Feed] = {}
    for feed in feeds:
        key = normalize_url(feed.xml_url)
        if not key:
            continue
        if key in seen:
            existing = seen[key]
            for source in feed.sources:
                if source not in existing.sources:
                    existing.sources.append(source)
            if not existing.title and feed.title:
                existing.title = feed.title
            if not existing.html_url and feed.html_url:
                existing.html_url = feed.html_url
            if not existing.category and feed.category:
                existing.category = feed.category
        else:
            seen[key] = Feed(
                title=feed.title,
                xml_url=feed.xml_url,
                html_url=feed.html_url,
                category=feed.category,
                sources=list(feed.sources),
            )
    return list(seen.values())


async def fetch_wechat2rss(refresh: bool, timeout: float) -> None:
    if WECHAT2RSS_LOCAL.exists() and not refresh:
        return
    WECHAT2RSS_LOCAL.parent.mkdir(parents=True, exist_ok=True)
    headers = {"User-Agent": USER_AGENT, "Accept": ACCEPT_HEADER}
    async with httpx.AsyncClient(
        timeout=timeout, headers=headers, follow_redirects=True
    ) as client:
        resp = await client.get(WECHAT2RSS_URL)
        resp.raise_for_status()
        WECHAT2RSS_LOCAL.write_bytes(resp.content)
    print(f"[info] fetched {WECHAT2RSS_URL} -> {WECHAT2RSS_LOCAL}", file=sys.stderr)


class HostLimiter:
    """Per-host concurrency cap to be polite to individual servers."""

    def __init__(self, per_host: int) -> None:
        self.per_host = max(1, per_host)
        self._sems: dict[str, asyncio.Semaphore] = {}

    def get(self, host: str) -> asyncio.Semaphore:
        sem = self._sems.get(host)
        if sem is None:
            sem = asyncio.Semaphore(self.per_host)
            self._sems[host] = sem
        return sem


def _latest_entry_date(parsed) -> datetime | None:
    latest: datetime | None = None
    for entry in parsed.entries:
        for key in ("published_parsed", "updated_parsed", "created_parsed"):
            value = entry.get(key)
            if not value:
                continue
            try:
                dt = datetime(*value[:6], tzinfo=timezone.utc)
            except (TypeError, ValueError):
                continue
            if latest is None or dt > latest:
                latest = dt
            break
    return latest


async def probe_feed(
    feed: Feed,
    client: httpx.AsyncClient,
    global_sem: asyncio.Semaphore,
    host_limiter: HostLimiter,
    days: int,
    timeout: float,
    per_host_delay: float,
) -> ProbeResult:
    result = ProbeResult(feed=feed)
    host = (urlparse(feed.xml_url).netloc or "").lower()
    host_sem = host_limiter.get(host)
    started = time.monotonic()
    try:
        async with global_sem:
            async with host_sem:
                try:
                    resp = await client.get(feed.xml_url, timeout=timeout)
                    result.status_code = resp.status_code
                    result.final_url = str(resp.url)
                    if 200 <= resp.status_code < 300:
                        parsed = feedparser.parse(resp.content)
                        result.entries = len(parsed.entries)
                        result.parsed_ok = bool(parsed.entries) or bool(
                            parsed.feed.get("title")
                        )
                        latest = _latest_entry_date(parsed)
                        result.last_update = latest
                        if not result.parsed_ok:
                            result.recent = False
                            result.error = "not a recognizable feed"
                        elif latest is not None:
                            result.recent = (
                                datetime.now(timezone.utc) - latest
                            ) <= timedelta(days=days)
                        else:
                            # Parsed OK but no parseable dates; assume recent.
                            result.recent = True
                        result.alive = result.parsed_ok and result.recent
                    else:
                        result.error = f"HTTP {resp.status_code}"
                except httpx.TimeoutException:
                    result.error = "timeout"
                except httpx.HTTPError as exc:
                    result.error = f"{type(exc).__name__}: {exc}"[:200]
                except Exception as exc:  # noqa: BLE001
                    result.error = f"{type(exc).__name__}: {exc}"[:200]
                finally:
                    if per_host_delay > 0:
                        await asyncio.sleep(per_host_delay)
    finally:
        result.elapsed_ms = int((time.monotonic() - started) * 1000)
    return result


async def probe_all(
    feeds: list[Feed],
    concurrency: int,
    per_host: int,
    timeout: float,
    days: int,
    per_host_delay: float,
) -> list[ProbeResult]:
    global_sem = asyncio.Semaphore(max(1, concurrency))
    host_limiter = HostLimiter(per_host)
    headers = {"User-Agent": USER_AGENT, "Accept": ACCEPT_HEADER}
    timeout_obj = httpx.Timeout(timeout, connect=min(10.0, timeout))
    limits = httpx.Limits(
        max_connections=concurrency * 2,
        max_keepalive_connections=concurrency,
    )
    results: list[ProbeResult] = []
    total = len(feeds)
    async with httpx.AsyncClient(
        headers=headers, timeout=timeout_obj, limits=limits, follow_redirects=True
    ) as client:
        coros = [
            probe_feed(
                feed, client, global_sem, host_limiter, days, timeout, per_host_delay
            )
            for feed in feeds
        ]
        done = 0
        for coro in asyncio.as_completed(coros):
            res = await coro
            done += 1
            tag = (
                "OK"
                if res.alive
                else (f"HTTP {res.status_code}" if res.status_code else res.error or "FAIL")
            )
            print(
                f"[{done:>4}/{total}] {tag:<22} {res.feed.xml_url}",
                file=sys.stderr,
            )
            results.append(res)
    return results


def write_merged_opml(
    feeds: list[Feed], path: Path, alive_keys: set[str] | None
) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    opml = ET.Element("opml", attrib={"version": "2.0"})
    head = ET.SubElement(opml, "head")
    ET.SubElement(head, "title").text = "security-hot merged feeds"
    ET.SubElement(head, "dateCreated").text = datetime.now(timezone.utc).strftime(
        "%a, %d %b %Y %H:%M:%S +0000"
    )
    body = ET.SubElement(opml, "body")

    by_category: dict[str, list[Feed]] = {}
    written = 0
    for feed in feeds:
        if alive_keys is not None and normalize_url(feed.xml_url) not in alive_keys:
            continue
        by_category.setdefault(feed.category or "Uncategorized", []).append(feed)

    for cat in sorted(by_category, key=str.lower):
        cat_node = ET.SubElement(body, "outline", attrib={"text": cat, "title": cat})
        for feed in sorted(by_category[cat], key=lambda f: f.title.lower()):
            attrib = {
                "type": "rss",
                "text": feed.title or feed.xml_url,
                "title": feed.title or feed.xml_url,
                "xmlUrl": feed.xml_url,
            }
            if feed.html_url:
                attrib["htmlUrl"] = feed.html_url
            if feed.sources:
                attrib["category"] = ",".join(feed.sources)
            ET.SubElement(cat_node, "outline", attrib=attrib)
            written += 1

    tree = ET.ElementTree(opml)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)
    print(f"[info] wrote {path} ({written} feeds)", file=sys.stderr)
    return written


def write_health_csv(results: list[ProbeResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "title",
                "xml_url",
                "sources",
                "status_code",
                "alive",
                "parsed_ok",
                "recent",
                "entries",
                "last_update",
                "final_url",
                "error",
                "elapsed_ms",
            ]
        )
        for r in sorted(results, key=lambda x: (not x.alive, x.feed.title.lower())):
            writer.writerow(
                [
                    r.feed.title,
                    r.feed.xml_url,
                    ";".join(r.feed.sources),
                    r.status_code or "",
                    r.alive,
                    r.parsed_ok,
                    r.recent,
                    r.entries,
                    r.last_update.isoformat() if r.last_update else "",
                    r.final_url,
                    r.error,
                    r.elapsed_ms,
                ]
            )
    print(f"[info] wrote {path}", file=sys.stderr)


def classify(r: ProbeResult) -> tuple[str, str]:
    """Return (category, detail) for a probe result.

    Categories:
      alive         — HTTP 2xx + parses + recent
      http_4xx      — server reachable, refused or gone (404, 403, 410, 401, 4xx)
      http_5xx      — server error (500, 502, 521, 530…)
      network       — connect refused / DNS / SSL / remote protocol / timeout
      parse_failed  — HTTP 200 but body is not a recognizable feed
      stale         — HTTP 200, parses fine, but no entries within the window
      unknown       — fallthrough
    """
    if r.alive:
        return "alive", ""
    if r.status_code is not None and not (200 <= r.status_code < 300):
        bucket = "http_4xx" if 400 <= r.status_code < 500 else "http_5xx"
        return bucket, f"HTTP {r.status_code}"
    if r.status_code is None:
        err = r.error or "network error"
        low = err.lower()
        if "timeout" in low:
            detail = "timeout"
        elif "ssl" in low or "certificate" in low:
            detail = "SSL"
        elif "remoteprotocolerror" in low or "protocol" in low:
            detail = "protocol"
        elif "connect" in low or "dns" in low or "name or service" in low:
            detail = "connect"
        elif "redirect" in low:
            detail = "redirect"
        else:
            detail = err
        return "network", detail
    if not r.parsed_ok:
        return "parse_failed", "not a feed"
    if not r.recent:
        return "stale", "no recent entries"
    return "unknown", r.error or ""


def write_health_md(results: list[ProbeResult], path: Path, days: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    total = len(results)
    buckets: dict[str, list[tuple[ProbeResult, str]]] = {}
    detail_counts: dict[str, "Counter[str]"] = {}
    for r in results:
        cat, detail = classify(r)
        buckets.setdefault(cat, []).append((r, detail))
        detail_counts.setdefault(cat, Counter())[detail] += 1

    def n(cat: str) -> int:
        return len(buckets.get(cat, []))

    lines = [
        "# RSS Feed Health Report",
        "",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        f"- Freshness threshold: {days} days",
        f"- Total feeds: {total}",
        "",
        "## Summary by category",
        "",
        "| Category | Count | Notes |",
        "| --- | ---: | --- |",
        f"| alive | {n('alive')} | HTTP 2xx + parses + entry within {days} days |",
        f"| stale | {n('stale')} | reachable + parses, but no entries within {days} days |",
        f"| http_4xx | {n('http_4xx')} | client errors (404/403/410/...) — likely retired |",
        f"| http_5xx | {n('http_5xx')} | server errors (500/521/530/...) — likely temporary |",
        f"| network | {n('network')} | timeout / connect refused / SSL / DNS / protocol |",
        f"| parse_failed | {n('parse_failed')} | HTTP 200 but body is not RSS/Atom |",
        f"| unknown | {n('unknown')} | uncategorized |",
        "",
    ]

    for cat in ("http_4xx", "http_5xx", "network", "parse_failed"):
        breakdown = detail_counts.get(cat)
        if breakdown:
            tops = ", ".join(f"{d}={c}" for d, c in breakdown.most_common(8))
            lines.append(f"- **{cat}** top detail: {tops}")
    lines.append("")

    section_order = [
        ("http_4xx", "HTTP 4xx (likely retired)"),
        ("http_5xx", "HTTP 5xx (server errors)"),
        ("network", "Network errors (timeout / connect / SSL / protocol)"),
        ("parse_failed", "Parse failed (HTTP 200 but body is not a feed)"),
        ("stale", f"Stale (parses fine, no entry within {days} days)"),
        ("unknown", "Uncategorized"),
    ]
    for cat, title in section_order:
        items = buckets.get(cat) or []
        if not items:
            continue
        lines.append(f"## {title} — {len(items)}")
        lines.append("")
        lines.append("| Title | URL | Status | Last update | Sources | Detail |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        items.sort(key=lambda pair: pair[0].feed.title.lower())
        for r, detail in items:
            last = r.last_update.date().isoformat() if r.last_update else ""
            t = (r.feed.title or "(no title)").replace("|", "\\|")
            url = r.feed.xml_url.replace("|", "\\|")
            lines.append(
                f"| {t} | {url} | {r.status_code or 'N/A'} | {last} | "
                f"{';'.join(r.feed.sources)} | {detail} |"
            )
        lines.append("")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[info] wrote {path}", file=sys.stderr)


async def main_async(args: argparse.Namespace) -> int:
    try:
        await fetch_wechat2rss(refresh=args.refresh, timeout=args.timeout)
    except Exception as exc:  # noqa: BLE001
        print(
            f"[warn] failed to fetch wechat2rss OPML ({exc}); "
            "continuing with cached/other sources",
            file=sys.stderr,
        )

    raw: list[Feed] = []
    for path, name in SOURCES:
        items = parse_opml(path, name)
        print(f"[info] {name}: {len(items)} feeds", file=sys.stderr)
        raw.extend(items)

    deduped = dedupe(raw)
    overlap = len(raw) - len(deduped)
    print(
        f"[info] total feeds: raw={len(raw)} unique={len(deduped)} "
        f"duplicates_merged={overlap}",
        file=sys.stderr,
    )

    output_dir = Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_DIR
    merged_path = RSS_DIR / "merged.opml"

    if args.no_probe:
        write_merged_opml(deduped, merged_path, alive_keys=None)
        return 0

    results = await probe_all(
        deduped,
        concurrency=args.concurrency,
        per_host=args.per_host,
        timeout=args.timeout,
        days=args.days,
        per_host_delay=args.per_host_delay,
    )
    alive_keys = {normalize_url(r.feed.xml_url) for r in results if r.alive}
    write_merged_opml(
        deduped,
        merged_path,
        alive_keys=None if args.include_dead else alive_keys,
    )
    write_health_csv(results, output_dir / "health.csv")
    write_health_md(results, output_dir / "health.md", days=args.days)

    alive = len(alive_keys)
    print(
        f"\nsummary: {alive}/{len(results)} alive, "
        f"{len(results) - alive} dead/stale",
        file=sys.stderr,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Merge security RSS OPML sources, dedupe, and probe liveness.",
    )
    p.add_argument(
        "--refresh",
        action="store_true",
        help="Re-fetch the wechat2rss OPML even if a local copy exists.",
    )
    p.add_argument(
        "--days",
        type=int,
        default=180,
        help="Freshness threshold in days for the 'recent' check (default: 180).",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=24,
        help="Global concurrent request limit (default: 24).",
    )
    p.add_argument(
        "--per-host",
        type=int,
        default=2,
        help="Per-host concurrent request limit to avoid rate limits (default: 2).",
    )
    p.add_argument(
        "--per-host-delay",
        type=float,
        default=0.0,
        help="Sleep this many seconds after each per-host request (default: 0).",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP timeout per request in seconds (default: 15).",
    )
    p.add_argument(
        "--include-dead",
        action="store_true",
        help="Include dead/stale feeds in merged.opml (default: only alive).",
    )
    p.add_argument(
        "--no-probe",
        action="store_true",
        help="Skip liveness probe; just merge + dedupe and write merged.opml.",
    )
    p.add_argument(
        "--output-dir",
        help="Directory for health reports (default: scripts/output).",
    )
    return p


def main() -> int:
    args = build_parser().parse_args()
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[info] interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
