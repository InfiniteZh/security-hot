"""RSS source catalog and resolution.

Owns the curated NEWS_SOURCES list, language detection heuristics, and the
merge logic that overlays the curated entries on top of the OPML feed catalog
produced by merge_rss.py.
"""
from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree as ET

from .._util import ROOT


# ─── curated RSS sources ───
NEWS_SOURCES: list[dict] = [
    # Chinese
    {"slug": "freebuf", "title": "FreeBuf", "url": "https://www.freebuf.com/feed", "lang": "zh"},
    {"slug": "anquanke", "title": "安全客", "url": "https://api.anquanke.com/data/v1/rss", "lang": "zh"},
    {"slug": "4hou", "title": "嘶吼", "url": "https://www.4hou.com/feed", "lang": "zh"},
    {"slug": "secwiki", "title": "SecWiki News", "url": "https://www.sec-wiki.com/news/rss", "lang": "zh"},
    {"slug": "vipread", "title": "信息安全知识库", "url": "https://vipread.com/feed", "lang": "zh"},
    {"slug": "xuanwu", "title": "腾讯玄武实验室", "url": "https://xlab.tencent.com/cn/atom.xml", "lang": "zh"},
    {"slug": "keenlab", "title": "腾讯科恩实验室", "url": "https://keenlab.tencent.com/zh/atom.xml", "lang": "zh"},
    {"slug": "seebug", "title": "Seebug Paper", "url": "https://paper.seebug.org/rss", "lang": "zh"},
    {"slug": "netlab360", "title": "360 Netlab", "url": "https://blog.netlab.360.com/rss", "lang": "zh"},
    {"slug": "meituan", "title": "美团技术团队", "url": "https://tech.meituan.com/feed", "lang": "zh"},
    # English
    {"slug": "thn", "title": "The Hacker News", "url": "https://thehackernews.com/feeds/posts/default", "lang": "en"},
    {"slug": "bleeping", "title": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "lang": "en"},
    {"slug": "krebs", "title": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "lang": "en"},
    {"slug": "schneier", "title": "Schneier on Security", "url": "https://www.schneier.com/feed/atom/", "lang": "en"},
    {"slug": "talos", "title": "Talos Intelligence", "url": "https://blog.talosintelligence.com/feeds/posts/default", "lang": "en"},
    {"slug": "unit42", "title": "Palo Alto Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "lang": "en"},
    {"slug": "msrc", "title": "Microsoft MSRC", "url": "https://msrc.microsoft.com/blog/feed/", "lang": "en"},
    {"slug": "datadog", "title": "Datadog Security Labs", "url": "https://securitylabs.datadoghq.com/rss/feed.xml", "lang": "en"},
    {"slug": "googlep0", "title": "Project Zero", "url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "lang": "en"},
    {"slug": "mandiant", "title": "Mandiant", "url": "https://www.mandiant.com/resources/blog/rss.xml", "lang": "en"},
    {"slug": "checkmarx", "title": "Checkmarx", "url": "https://checkmarx.com/blog/feed/", "lang": "en"},
    # Supply-chain-focused blogs — most useful early-warning signal for npm/PyPI/Go/Rust
    # poisoning. `category: "supply-intel"` lets the frontend pull them into the
    # supply-chain view independently of language filters.
    # Socket: their /blog/rss.xml is Cloudflare-gated, but /api/blog/feed.atom serves
    # cleanly without the bot challenge.
    {"slug": "socket", "title": "Socket", "url": "https://socket.dev/api/blog/feed.atom", "lang": "en", "category": "supply-intel"},
    {"slug": "safedep", "title": "SafeDep", "url": "https://safedep.io/rss.xml", "lang": "en", "category": "supply-intel"},
    {"slug": "aikido", "title": "Aikido", "url": "https://www.aikido.dev/blog/rss.xml", "lang": "en", "category": "supply-intel"},
    {"slug": "stepsec", "title": "StepSecurity", "url": "https://www.stepsecurity.io/blog/rss.xml", "lang": "en", "category": "supply-intel"},
    {"slug": "endor", "title": "Endor Labs", "url": "https://www.endorlabs.com/blog/rss.xml", "lang": "en", "category": "supply-intel"},
]


# Hosts that almost certainly serve Chinese content. Anything matching here
# (substring) is tagged lang=zh regardless of OPML metadata.
_ZH_HOST_HINTS = (
    "freebuf.com", "anquanke.com", "4hou.com", "secrss.com", "sec-wiki",
    "secwiki", "seebug.org", "vipread.com", "360.cn", "tencent.com",
    "alibaba.com", "weibo.com", "qq.com", "ke.qq", "huawei.com",
    "uedbox.com", "secquan.org", "secepo.com", "feishu", "csdn.net",
    "sec-in.com", "sec-news.com", "zhihu.com", "jianshu.com",
    "xianzhi.aliyun", "bilibili.com", "cnblogs.com",
    ".com.cn", ".org.cn", ".cn/",
)


def _slug_from_url(url: str) -> str:
    """Derive a stable slug from a feed URL — host segment with non-alnum
    collapsed to '_'. Used for de-duplication and as a stable id across
    runs even when the OPML title changes."""
    try:
        host = re.sub(r"^https?://", "", url).split("/")[0].lower()
        host = re.sub(r"^www\.", "", host)
        slug = re.sub(r"[^a-z0-9]+", "_", host).strip("_")
        return slug[:48] or "unknown"
    except Exception:
        return "unknown"


def _detect_lang(title: str, url: str, category_label: str) -> str:
    """Heuristic: any CJK char in title, or known-CN host, or 公众号 category
    ⇒ zh. Otherwise en. Mis-tagged Italian / French feeds default to en,
    which is fine for the news lang toggle."""
    if any("一" <= ch <= "鿿" for ch in (title or "")):
        return "zh"
    lower_url = (url or "").lower()
    if any(hint in lower_url for hint in _ZH_HOST_HINTS):
        return "zh"
    if "公众号" in (category_label or ""):
        return "zh"
    return "en"


def _load_alive_sources_from_opml(opml_path: Path) -> list[dict]:
    """Parse rss/merged.opml (output of merge_rss.py) into the
    NEWS_SOURCES dict shape. Returns empty list if file missing/invalid
    so the caller can fall back to the curated list.

    Slugs are URL-derived to stay stable across re-merges; falls back to
    feed title when host hashing collides.
    """
    if not opml_path.exists():
        return []
    try:
        tree = ET.parse(opml_path)
    except ET.ParseError:
        return []
    body = tree.getroot().find("body")
    if body is None:
        return []
    sources: list[dict] = []
    seen_slugs: dict[str, int] = {}

    def walk(node: ET.Element, parent_category: str) -> None:
        for child in node:
            if child.tag.split("}")[-1] != "outline":
                continue
            xml_url = (child.attrib.get("xmlUrl") or "").strip()
            title = (child.attrib.get("title") or child.attrib.get("text") or "").strip()
            if not xml_url:
                # Topical category container (e.g. "Pentest", "Companies").
                walk(child, title or parent_category)
                continue
            slug = _slug_from_url(xml_url)
            # Disambiguate when two feeds share a host (rare but happens).
            if slug in seen_slugs:
                seen_slugs[slug] += 1
                slug = f"{slug}_{seen_slugs[slug]}"
            else:
                seen_slugs[slug] = 1
            sources.append({
                "slug": slug,
                "title": title or xml_url,
                "url": xml_url,
                "lang": _detect_lang(title, xml_url, parent_category),
                "category": parent_category or "Uncategorized",
            })

    walk(body, "")
    return sources


def _news_sources_to_use() -> list[dict]:
    """Resolve the news source list at fetch time.

    Strategy:
      1. read rss/merged.opml — that's the full ~695 alive feed catalog
         produced by merge_rss.py
      2. merge the curated NEWS_SOURCES on top (their hand-tuned title,
         lang, and supply-intel category override the OPML defaults)
      3. fall back to NEWS_SOURCES alone if merged.opml doesn't exist

    Curated sources keep their original slug so cross-run continuity
    holds; new OPML sources get URL-derived slugs.
    """
    opml = ROOT / "rss" / "merged.opml"
    bulk = _load_alive_sources_from_opml(opml)
    if not bulk:
        return list(NEWS_SOURCES)
    # Overlay curated entries by URL match.
    curated_by_url = {s["url"]: s for s in NEWS_SOURCES}
    out: list[dict] = []
    consumed_curated_urls: set[str] = set()
    for s in bulk:
        if s["url"] in curated_by_url:
            override = curated_by_url[s["url"]]
            consumed_curated_urls.add(s["url"])
            out.append({**s, **override, "category": override.get("category") or s["category"]})
        else:
            out.append(s)
    # Any curated source not present in OPML (e.g. supply-intel vendors
    # we added by hand and never ran through merge_rss) still gets in.
    for s in NEWS_SOURCES:
        if s["url"] not in consumed_curated_urls:
            out.append(s)
    return out
