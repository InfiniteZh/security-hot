"""Shared helpers for security-hot Kafka dispatchers."""
from __future__ import annotations

import json
import re
import sys

KAFKA_BOOTSTRAP = (
    "kafka01-devsecops-cnhbnp01-test.chj.cloud:9092,"
    "kafka02-devsecops-cnhbnp01-test.chj.cloud:9092,"
    "kafka03-devsecops-cnhbnp01-test.chj.cloud:9092"
)
KAFKA_TOPIC = "schedule_task_normal"

TIER1_SUPPLY_SOURCES = {
    "Socket", "SafeDep", "StepSecurity", "Endor Labs", "Aikido", "defend.network",
}
TIER2_SUPPLY_SOURCES = {
    "The Hacker News", "SecurityWeek » Feed", "Cybersecurity News",
    "SANS Internet Storm Center, InfoCON: green",
}

_BLOCK_RE = re.compile(
    r"<(script|style|head|nav|footer)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL
)
_TAG_RE = re.compile(r"<[^>]+>")
_ENTITY_RE = re.compile(r"&\w+;")
_WS_RE = re.compile(r"\s+")

_URL_RE = re.compile(r"\b(?:https?|hxxps?)://[^\s<>'\"，。；;,]+", re.IGNORECASE)
_SHA256_RE = re.compile(r"(?<![@:/.\w])[a-fA-F0-9]{64}(?![@:/.\w])")
_MD5_RE = re.compile(r"(?<![@:/.\w])[a-fA-F0-9]{32}(?![@:/.\w])")
_IPV4_RE = re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}(?![\w:])")
_DOMAIN_RE = re.compile(
    r"(?<![@\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,63})(?![\w.-])"
)
_DSN_DOMAIN_RE = re.compile(
    r"(?<=@)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,63})(?=[/:]|$)"
)


def make_producer(bootstrap: str):
    from aiokafka import AIOKafkaProducer
    return AIOKafkaProducer(bootstrap_servers=bootstrap, acks="all")


async def send(producer, topic: str, key: str, msg: dict) -> None:
    await producer.send_and_wait(
        topic,
        key=str(key).encode(),
        value=json.dumps(msg, ensure_ascii=False).encode("utf-8"),
    )


def html_to_text(html: str) -> str:
    text = _BLOCK_RE.sub(" ", html or "")
    text = _TAG_RE.sub(" ", text)
    text = _ENTITY_RE.sub(" ", text)
    return _WS_RE.sub(" ", text).strip()


async def fetch_body(client, url: str, max_len: int = 20000) -> str:
    if not url:
        return ""
    try:
        r = await client.get(url, timeout=10.0, follow_redirects=True)
        r.raise_for_status()
        return html_to_text(r.text)[:max_len]
    except Exception as e:
        print(f"[dispatch] 拉取全文失败 {url}: {e}", file=sys.stderr)
        return ""


def _refang(text: str) -> str:
    return (
        (text or "")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[:]", ":")
    )


def _clean_ioc(value: str) -> str:
    return value.strip().strip(".,;:!?()[]{}<>\"'")


def extract_iocs(text: str, exclude: set[str] | None = None) -> list[dict]:
    normalized = _refang(text)
    exclude = exclude or set()
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    url_spans: list[tuple[int, int]] = []

    def in_url_span(start: int, end: int) -> bool:
        return any(start >= u_start and end <= u_end for u_start, u_end in url_spans)

    def add(value: str, typ: str) -> None:
        value = _clean_ioc(value)
        if not value:
            return
        if value.lower() in exclude:
            return
        key = (typ, value.lower())
        if key in seen:
            return
        seen.add(key)
        out.append({"value": value, "type": typ})

    for m in _URL_RE.finditer(normalized):
        url_spans.append(m.span())
        add(m.group(0), "url")
    for m in _SHA256_RE.finditer(normalized):
        add(m.group(0).lower(), "sha256")
    for m in _MD5_RE.finditer(normalized):
        add(m.group(0).lower(), "md5")
    for m in _IPV4_RE.finditer(normalized):
        add(m.group(0), "ipv4")
    for m in _IPV6_RE.finditer(normalized):
        add(m.group(0).lower(), "ipv6")
    for m in _DSN_DOMAIN_RE.finditer(normalized):
        add(m.group(0).lower(), "domain")
    for m in _DOMAIN_RE.finditer(normalized):
        if in_url_span(m.start(), m.end()):
            continue
        value = m.group(0)
        if _IPV4_RE.fullmatch(value):
            continue
        add(value.lower(), "domain")
    return out
