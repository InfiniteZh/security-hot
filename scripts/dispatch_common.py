"""Shared helpers for security-hot Kafka dispatchers."""
from __future__ import annotations

import functools
import json
import os
import re
import sys

KAFKA_BOOTSTRAP = (
    "kafka01-devsecops-cnhbnp01-test.chj.cloud:9092,"
    "kafka02-devsecops-cnhbnp01-test.chj.cloud:9092,"
    "kafka03-devsecops-cnhbnp01-test.chj.cloud:9092"
)
KAFKA_TOPIC = "schedule_task_normal"

# Kafka 投递报文的协议版本号 —— 单一真源。两个 dispatcher（poisoning/vuln）的
# build_message 与 backend 抽屉重建（news.query）共用此常量；下游 security_copilot
# 按它判断报文结构（v3 起顶层单包字段合并为 packages[] 数组）。任何破坏性结构变更
# 都要在此 +1 并同步下游，切勿在各处硬编码（曾导致重建报文 schema_version=null）。
SCHEMA_VERSION = 3

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
# (pattern, ioc_type) ordered longest-first so a 64-char hex string matches sha256, not sha1/md5.
_HASH_RES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?<![@:/.\w])[a-fA-F0-9]{64}(?![@:/.\w])"), "sha256"),
    (re.compile(r"(?<![@:/.\w])[a-fA-F0-9]{40}(?![@:/.\w])"), "sha1"),   # git commit hashes
    (re.compile(r"(?<![@:/.\w])[a-fA-F0-9]{32}(?![@:/.\w])"), "md5"),
]
# Hash IOC types are high-confidence enough for body augmentation; domains/URLs are too noisy.
BODY_AUGMENT_TYPES: frozenset[str] = frozenset(t for _, t in _HASH_RES)
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
    """校验并归一化包名；prose（含空格/括号）/非 ASCII（中文等）/非法字符 → 返回 ''。"""
    name = (name or "").strip()
    if not name or not name.isascii() or " " in name or "\t" in name or "(" in name or ")" in name:
        return ""
    return name if _PKG_RE.match(name) else ""


def valid_version(ver: str | None) -> str:
    """校验单个版本号；含空格/中文（非 ASCII）/说明文字 → 返回 ''。
    注意：正则 \\w 在 Unicode 下会匹配中文，故必须显式挡掉非 ASCII（如"多个版本"）。"""
    ver = (ver or "").strip()
    if not ver or not ver.isascii() or " " in ver:
        return ""
    return ver if _VER_RE.match(ver) else ""


# 多版本分隔符：逗号 / 顿号 / 分号 / 空白 / "and" / "&"。
# 一次投毒常同时命中多个版本（如 redhat "3.6.1,3.6.2,3.6.4"），旧 valid_version
# 对整串校验会因逗号直接清空 → 下游丢失受影响版本。改为逐元素校验后保留有效项。
# 注意：不拆 '/' —— 它出现在 git 分支引用（dev-foo/feature/x）里，拆了会造出假版本；
# 整串带 '/' 的会被 valid_version 直接判非法（'/' 不在合法版本字符集内）。
_VERSION_SPLIT_RE = re.compile(r"[,、;；\s]+|\band\b|&", re.IGNORECASE)


def valid_versions(raw) -> list[str]:
    """把"多版本"输入（逗号串 / 列表 / 单串）拆分并逐个校验，返回去重后的有效版本列表。
    非法/散文元素被剔除；无有效项返回 []。"""
    if isinstance(raw, (list, tuple, set)):
        parts: list[str] = [str(x) for x in raw]
    else:
        parts = _VERSION_SPLIT_RE.split(str(raw or ""))
    out: list[str] = []
    seen: set[str] = set()
    for p in parts:
        v = valid_version(p)
        if v and v.lower() not in seen:
            seen.add(v.lower())
            out.append(v)
    return out


# 知名合法基础设施域名 —— 这些是恶意包"借道"的合法服务（区块链公共 RPC、
# 包注册中心、官方代理），它们本身不是失陷指标。若当 IOC 投给下游自动封禁，
# 会误伤正常业务（如把 api.trongrid.io 封了 → 所有正常 TRON 调用挂掉）。
# 保持"窄"：只列那些"永远不会是真 IOC"的纯基础设施；像 github.com / *.trycloudflare.com
# 这类既能托管合法内容又常被滥用投递 payload 的，绝不列入（否则会漏掉真 IOC）。
# 可用 DISPATCH_INFRA_ALLOWLIST 环境变量追加（逗号分隔）。
_DEFAULT_INFRA_ALLOWLIST = {
    # 区块链公共 RPC / 浏览器 API
    "trongrid.io", "api.trongrid.io",
    "infura.io", "alchemyapi.io", "alchemy.com",
    "etherscan.io", "blockchair.com", "blockcypher.com",
    # 包注册中心 / 官方代理（advisory 里出现的是"包发布在哪"，非 IOC）
    "registry.npmjs.org", "npmjs.com", "npmjs.org",
    "pypi.org", "files.pythonhosted.org",
    "crates.io", "static.crates.io",
    "rubygems.org", "packagist.org", "repo.packagist.org",
    "proxy.golang.org", "sum.golang.org",
    "nuget.org", "api.nuget.org",
}


@functools.lru_cache(maxsize=1)
def _infra_allowlist() -> frozenset[str]:
    extra = os.environ.get("DISPATCH_INFRA_ALLOWLIST", "")
    out = set(_DEFAULT_INFRA_ALLOWLIST)
    for d in extra.split(","):
        d = d.strip().lower().strip(".")
        if d:
            out.add(d)
    return frozenset(out)


def is_legit_infra(domain: str, allowlist: set[str] | None = None) -> bool:
    """域名（或其父域）命中合法基础设施 allowlist → True。
    子域匹配：api.trongrid.io 命中 trongrid.io。"""
    d = (domain or "").lower().strip().strip(".")
    if not d:
        return False
    allow = allowlist if allowlist is not None else _infra_allowlist()
    return any(d == a or d.endswith("." + a) for a in allow)


_URL_HOST_RE = re.compile(r"^[a-zA-Z][\w+.-]*://([^/:?#\s]+)")


def _url_host(url: str) -> str:
    m = _URL_HOST_RE.match(url or "")
    return m.group(1).lower() if m else ""


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
    allowlist = _infra_allowlist()
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
        # 合法基础设施（区块链 RPC / 包注册中心）不是失陷指标：domain 直接命中，
        # url 取 host 命中 → 一律丢弃，避免下游误封正常服务。
        if typ == "domain" and is_legit_infra(value, allowlist):
            return
        if typ == "url" and is_legit_infra(_url_host(value), allowlist):
            return
        key = (typ, value.lower())
        if key in seen:
            return
        seen.add(key)
        out.append({"value": value, "type": typ})

    for m in _URL_RE.finditer(normalized):
        url_spans.append(m.span())
        add(m.group(0), "url")
    for pattern, ioc_type in _HASH_RES:
        for m in pattern.finditer(normalized):
            add(m.group(0).lower(), ioc_type)
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
