"""Stateless utilities shared across ingest fetcher modules.

Holds the common HTTP constants, time/JSON/HTML helpers, URL canonicalization
and the keyword blocklist used by the news pipeline. Depends on nothing inside
the ingest package (no source modules), so every source module can import from
here without risking a circular import.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
CACHE = ROOT / "backend" / "cache"
CACHE.mkdir(parents=True, exist_ok=True)
ARCHIVE_DIR = ROOT / "backend" / "archive" / "news"

USER_AGENT = (
    "Mozilla/5.0 (compatible; security-hot/1.0; +https://github.com/) "
    "feedparser/python-httpx"
)
HEADERS = {"User-Agent": USER_AGENT}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(name: str, data) -> Path:
    path = CACHE / name
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def strip_html(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&\w+;", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def clean_summary(text: str, limit: int = 320) -> str:
    text = strip_html(text)
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def _iso_from_feedparser(entry) -> str:
    """Normalize RSS/Atom dates to ISO 8601 UTC.

    feedparser parses every common date format into a `time.struct_time`
    under `published_parsed` (or `updated_parsed` / `created_parsed`).
    Falling back to the raw string risks lexicographic sort breaking when
    sources mix RFC 2822 ("Wed, 26 Nov 2025 …") with ISO ("2026-05-12 …").
    """
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        parsed = entry.get(key)
        if parsed:
            try:
                return time.strftime("%Y-%m-%dT%H:%M:%SZ", parsed)
            except (TypeError, ValueError):
                continue
    # No machine-readable date; return raw string (rare, but keep something).
    return (entry.get("published") or entry.get("updated") or "").strip()


def _entry_published_iso(entry) -> str | None:
    """Normalize feedparser entry published time to ISO 8601 UTC string."""
    from time import struct_time
    pt = entry.get("published_parsed") or entry.get("updated_parsed")
    if not pt or not isinstance(pt, struct_time):
        return None
    try:
        return datetime(*pt[:6], tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError):
        return None


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(text, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ────────── Layer 1: URL + title dedupe ──────────
# Prefix-based instead of a named whitelist: tracking params multiply faster
# than we can enumerate. Anything starting with these prefixes (case-insensitive)
# is dropped from the canonical URL. Covers utm_*, ref/ref_*, scene/scene_*,
# spm (taobao/aliyun), mpshare/chksm/srcid (wechat), igshid (instagram),
# mc_eid/mkt_tok (mailchimp / marketo), s_cid/cmpid (mainstream news), etc.
_TRACKING_PREFIXES = (
    "utm_", "utm", "ref", "ref_", "from_", "_from", "from",
    "source", "spm", "scene", "share", "sharer", "shareid",
    "mpshare", "chksm", "srcid", "wt_mc", "wt_zmc",
    "mc_eid", "mc_cid", "mkt_tok",
    "s_cid", "cmpid", "cmp",
    "fbclid", "gclid", "igshid", "__twitter_impression",
)


def _is_tracking_param(key: str) -> bool:
    k = (key or "").lower()
    for prefix in _TRACKING_PREFIXES:
        if k == prefix or k.startswith(prefix):
            return True
    return False


def _canonical_url(url: str) -> str:
    """Strip tracking params and normalize host/path so the same article
    on two aggregators (or shared with different `?utm_*` tails) is one
    URL key for dedupe.

    Security: rejects any URL whose scheme is not http(s). RSS publishers
    can inject `javascript:` or `data:` URIs in <link> tags; if those reach
    the frontend they become stored XSS via clickable href attributes.
    """
    if not url:
        return ""
    try:
        p = urlparse(url.strip())
    except Exception:
        return ""
    if p.scheme.lower() not in ("http", "https"):
        return ""
    if not p.netloc:
        return ""
    qs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=False)
          if not _is_tracking_param(k)]
    query = urlencode(qs)
    path = p.path.rstrip("/") or "/"
    host = p.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return f"{p.scheme.lower()}://{host}{path}" + (f"?{query}" if query else "")


# ────────── Layer 2: keyword blocklist ──────────
# Default blocklist covers recruitment, promo / lottery, conference solicitation,
# personal housekeeping posts. Override via NEWS_BLOCK_KEYWORDS env (comma list)
# if you want stricter / looser filtering without redeploying.
_DEFAULT_BLOCK_KEYWORDS = [
    # ─── Recruitment ────────────────────────────────────────────
    "招聘", "招人", "招募", "诚聘", "实习生招", "校招", "社招",
    "求职", "投简历", "招贤纳士", "内推",
    "we're hiring", "we are hiring",

    # ─── Promotion / giveaway / sales ───────────────────────────
    "限免", "限时免费", "优惠码", "抽奖", "免费领取",
    "福利来了", "限时优惠", "购买链接",
    "加群", "加微信", "扫码加", "知识星球",

    # ─── Conference solicitation ────────────────────────────────
    # Use specific compound phrases (not bare 议程/报名) to avoid killing
    # BlackHat/DEFCON/USENIX agenda announcements which carry research signal.
    "议程公布", "嘉宾揭晓", "报名截止", "报名开启", "开启报名",
    "限时报名", "招商赞助", "赞助合作",

    # ─── Periodic digests (no information density) ──────────────
    # All catch retrospective compilations like "CNVD漏洞周报" / "Weekly Update".
    # We don't kill `年度` alone (kills "2025 年度十大漏洞盘点"), only compound.
    "周报", "月报", "全球网络安全日报",
    "Weekly Update", "Weekly Briefing", "Newsletter", "Digest",
    "年终总结", "年度总结", "年度盘点", "年度大事记",
    "年度荣耀", "年度颁奖",

    # ─── Personal / housekeeping ────────────────────────────────
    "新年快乐", "中秋快乐", "国庆快乐", "感谢支持",
    "公众号回顾", "年终总结征集",
    "随笔", "深夜随笔", "年中随笔", "心得体会",
    "我们的故事", "团队介绍", "加入我们",
    "产品发布会",  # marketing event vs. genuine product launch story

    # ─── Audio-only content (RSS gives us titles but not transcripts) ─
    "Podcast:", "播客:", "播客：",
]


def _articles_keyword_filter(articles: list[dict]) -> tuple[list[dict], list[dict]]:
    raw_extra = os.environ.get("NEWS_BLOCK_KEYWORDS") or ""
    extras = [k.strip() for k in raw_extra.split(",") if k.strip()]
    keywords = _DEFAULT_BLOCK_KEYWORDS + extras
    if not keywords:
        return articles, []
    # ASCII keywords get \b word boundaries to avoid substring traps like
    # "Digest" matching "Digestion". CJK keywords have no real word-boundary
    # concept in regex; just leave them as substring matches (which is what
    # we want anyway — Chinese text has no inter-word space).
    parts: list[str] = []
    for kw in keywords:
        if re.search(r"[一-鿿]", kw):  # CJK present → substring match
            parts.append(re.escape(kw))
        else:                                 # ASCII → word-bounded match
            parts.append(rf"\b{re.escape(kw)}\b")
    pattern = re.compile("|".join(parts), re.IGNORECASE)
    kept: list[dict] = []
    dropped: list[dict] = []
    for a in articles:
        blob = f"{a.get('title','')} {a.get('summary','')}"
        m = pattern.search(blob)
        if m:
            dropped.append({**a, "drop_reason": f"keyword:{m.group(0)}"})
        else:
            kept.append(a)
    return kept, dropped
