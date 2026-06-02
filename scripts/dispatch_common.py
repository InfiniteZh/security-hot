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

# 代码/资源文件后缀——这些"伪 TLD"会让 index.js / setup.py 之类文件名被误判成域名。
# 域名识别时若末段落在此集合内，直接丢弃（散文里的文件名不是失陷指标）。
_CODE_FILE_EXT = {
    "js", "mjs", "cjs", "jsx", "ts", "tsx", "py", "pyc", "pyi", "go", "rs",
    "rb", "php", "java", "kt", "kts", "scala", "swift", "json", "md", "txt",
    "sh", "bash", "zsh", "yml", "yaml", "lock", "toml", "cfg", "ini", "env",
    "xml", "html", "htm", "css", "scss", "sass", "less", "png", "jpg", "jpeg",
    "gif", "svg", "webp", "ico", "exe", "dll", "so", "dylib", "bin", "sql",
    "c", "cpp", "cc", "h", "hpp", "log", "csv", "tsv", "pdf", "zip", "gz",
    "tar", "tgz", "whl", "jar", "war", "class", "map", "ipynb", "md5", "sha256",
}

# 合法包名：可选 @scope/，允许 . _ - / : @ * 等生态分隔符；禁止空格/括号/散文。
_PKG_RE = re.compile(r"^[@A-Za-z0-9][\w.@/:*\-]{0,119}$")
# 合法版本号：纯版本串，禁止空格与中文（'95 versions' / '多个版本受影响' 一律判空）。
_VER_RE = re.compile(r"^[vV0-9~^<>=]?[\w.\-+*]{0,39}$")


def valid_package(name: str | None) -> str:
    """校验并归一化包名；prose（含空格/括号）或非法字符 → 返回 ''。"""
    name = (name or "").strip()
    if not name or " " in name or "\t" in name or "(" in name or ")" in name:
        return ""
    return name if _PKG_RE.match(name) else ""


def valid_version(ver: str | None) -> str:
    """校验版本号；含空格/中文/说明文字 → 返回 ''。"""
    ver = (ver or "").strip()
    if not ver or " " in ver:
        return ""
    return ver if _VER_RE.match(ver) else ""


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
        value = m.group(0)
        if value.rsplit(".", 1)[-1].lower() in _CODE_FILE_EXT:
            continue
        add(value.lower(), "domain")
    for m in _DOMAIN_RE.finditer(normalized):
        if in_url_span(m.start(), m.end()):
            continue
        value = m.group(0)
        if _IPV4_RE.fullmatch(value):
            continue
        if value.rsplit(".", 1)[-1].lower() in _CODE_FILE_EXT:
            continue  # index.js / setup.py 之类文件名不是域名
        add(value.lower(), "domain")
    return out
