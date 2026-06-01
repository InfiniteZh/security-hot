# security-hot

面向安全行业的"每日聚合面板"。三个一级板块：**行业资讯 · 漏洞情报 · 安全论文**（论文待接入）。
后端 FastAPI，前端单文件 HTML（中英 i18n，默认中文），全部由一个 uvicorn 进程同时托管。

## 目录结构

```
.
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI app + 静态挂载 + 3 new endpoints
│   │   ├── data.py            # SQLite news loader + legacy JSON for vuln
│   │   └── models.py          # Pydantic schema (Article 扩 is_relevant/mirror_count)
│   ├── cache/
│   │   ├── news.db            # ← SQLite 主存 (WAL + FTS5) - 行业资讯权威数据
│   │   ├── kev.json           # CISA KEV
│   │   ├── ghsa.json          # GitHub Security Advisories
│   │   ├── pocs.json          # nomi-sec PoC mirror
│   │   ├── murphy.json        # MurphySec vuln_warn 增量缓存
│   │   ├── itw.json           # inthewild.io (目前空)
│   │   ├── heat.json          # cvecrowd (目前空)
│   │   ├── epss.json          # FIRST.org EPSS 每日 CSV
│   │   ├── osv-npm.json       # OSV.dev npm advisories
│   │   ├── osv-pypi.json      # OSV.dev PyPI advisories
│   │   ├── nuclei.json        # nuclei-templates CVE 覆盖
│   │   ├── hn.json            # Hacker News 安全 stories
│   │   ├── masto.json         # Mastodon 标签时间线
│   │   ├── vuln_ai.json       # 漏洞 AI 评估结果 (vuln_assess 写入)
│   │   └── manifest.json      # 各 fetcher 状态
│   └── archive/
│       └── news/              # 每日 NDJSON 派生归档 (YYYY-MM-DD.jsonl)
├── rss/
│   ├── awesome-security-feed/    # submodule
│   ├── CyberSecurityRSS/         # submodule
│   ├── Chinese-Security-RSS/     # submodule
│   ├── wechat2rss/sec.opml       # 远端缓存
│   └── merged.opml               # merge_rss.py 产出
├── scripts/
│   ├── fetch_data.py          # 12 个 fetcher，news 写 SQLite，其他写 JSON
│   ├── llm_rank.py            # SQLite-backed classify/summarize/brief + vuln_assess
│   ├── embed_articles.py      # 计算 multilingual-e5-small 嵌入向量（384-dim）
│   ├── cluster_articles.py    # 余弦相似度镜像聚类（替代原 Jaccard 3-shingle）
│   ├── db.py                  # SQLite 连接 + schema + CRUD helpers
│   ├── migrate_to_sqlite.py   # 一次性 news.json → news.db 迁移
│   ├── merge_rss.py           # OPML 合并 + 去重 + 探活
│   ├── requirements.txt       # 仅 merge_rss.py 用
│   └── output/                # health.csv / health.md
├── tests/                     # pytest (42+ 测试)
├── web/
│   └── index.html             # 单文件前端，OpenAI 风格，i18n
├── docs/
│   ├── cron-template.txt      # cron 部署模板
│   └── superpowers/{specs,plans}/  # 设计文档与实施计划
├── pyproject.toml             # uv 管理的项目依赖
└── CLAUDE.md
```

## 环境：使用 uv（不要用裸 python3 / pip）

```bash
uv sync                                       # 创建/同步 .venv 与所有依赖
uv run python scripts/fetch_data.py           # 抓数据 → backend/cache
uv run uvicorn backend.app.main:app --reload --port 8000
```

打开 <http://127.0.0.1:8000/> 看页面，<http://127.0.0.1:8000/docs> 看 OpenAPI。

`uv run` 会自动锁定到本项目 `.venv`；调用 `pip` 时一律用 `uv pip install`。新增依赖直接编辑 `pyproject.toml` 的 `dependencies`，再 `uv sync`。

## 后端

### 数据流

1. `scripts/fetch_data.py` 异步并发抓取各源，按 schema 落到 `backend/cache/*.json`
2. FastAPI 启动时**不**预加载——每次请求按文件 mtime 做内存缓存（30s TTL）
3. `data.py` 把缓存归一化成 `Vuln` / `Article` / `HeatEntry` / `SourceStatus` 等模型
4. `main.py` 暴露 6 个 GET 接口
5. `web/` 作为静态目录挂载到 `/`，浏览器并发请求 6 个 `/api/*` 渲染

### API 接口

| 路径 | 描述 | 典型参数 |
| --- | --- | --- |
| `GET /api/today` | 顶部统计：今日资讯数、新增漏洞、ITW、热点 CVE | — |
| `GET /api/news` | 资讯列表 | `lang=zh\|en\|all` `q=` `source=` `sort=heat\|time` `limit=` |
| `GET /api/vuln` | 漏洞列表（CVE/Supply/PoC/ITW 合一） | `kind=all\|cve\|supply\|poc\|itw` `severity=` `q=` `sort=` `limit=` |
| `GET /api/heat` | 热度榜（按 heat 排序） | `limit=` |
| `GET /api/sources` | 数据源健康度 | — |
| `GET /api/manifest` | 最近一次 fetch 各 fetcher 的状态 | — |
| `GET /api/healthz` | 存活检查 | — |

### Vuln 归一化与热度

CISA KEV、GHSA、nomi-sec PoC、MurphySec、OSSF malicious-packages 共五个源会跨 CVE-ID 合并：合并后保留所有 PoC 链接、KEV/ITW 标记、所有引用。`kind` 字段按优先级判定 `itw > supply > poc > cve`。

`heat` 是后端计算的整数：
- severity (critical 60 / high 35 / medium 15 / low 5)
- + KEV(50) + ITW(40)
- + min(pocs, 10) × 6 + 前 5 个 PoC 的 stars 累加
- + max(0, 20 - age_days)

## Fetcher

```bash
uv run python scripts/fetch_data.py                  # 全部
uv run python scripts/fetch_data.py --only kev,news  # 子集
uv run python scripts/fetch_data.py --concurrency 12 # 提升 news RSS 并发
```

各 fetcher（在 `scripts/fetch_data.py` 的 `FETCHERS` 字典注册，共 12 个）：

| 名称 | 源 | 说明 |
| --- | --- | --- |
| kev | `cisa.gov/.../known_exploited_vulnerabilities.json` | 全量 KEV，按 dateAdded 倒序取 200 |
| ghsa | `api.github.com/advisories` | 最新 100 条公开 advisory（匿名 60/h，带 GITHUB_TOKEN 提到 5000/h） |
| pocs | `poc-in-github.motikan2010.net/api/v1` | 最近 100 个 PoC 仓库 |
| murphy | `murphysec.com/platform/v2/vuln_warn/list` | MurphySec 漏洞预警，始终 `scope=default` + `last_modify_time` 时间窗口；无缓存时默认回看 4 小时 |
| itw | `inthewild.io/feed` | RSS（feed 当前可能为空） |
| heat | `cvecrowd.com/api/cves` | 端点格式可能变了，目前 fallback 到 0 |
| news | 713 个聚合源（merged.opml + curated） | **写 SQLite (`news.db`)**，按 `sources.interval_minutes` 智能挑源；带 Conditional GET |
| epss | `epss.empiricalsecurity.com/.../v202X.csv.gz` | FIRST.org EPSS 每日全量 CSV，>30 万条 CVE→exploit 概率 |
| osv | `osv-vulnerabilities.storage.googleapis.com` | OSV.dev 全量 ecosystem dump（npm + PyPI），>20 万条 |
| nuclei | `api.github.com/repos/projectdiscovery/nuclei-templates/git/trees` | 列出所有 CVE 模板（用于 vuln 详情外链） |
| hn | `hn.algolia.com/api/v1/search_by_date` | Hacker News 安全相关近期 stories（多查询并发） |
| masto | 多个 Mastodon 实例 public timeline | 标签订阅 + CVE 抽取（联邦去重） |

后四个（epss / hn / masto / nuclei）不直接出现在前端列表里，而是在 `data.py:_cve_signals()` 里按 CVE-ID 旁路注入到 vuln 卡片上（EPSS 分数、HN/Masto mentions、Nuclei 模板链接）。

跑完 stderr 会有 `[ok] kev count=200 elapsed=1.8s` 这类日志，`manifest.json` 落详细状态。

## LLM 管道（两阶段）

```bash
uv run python scripts/llm_rank.py                              # 全流程（30天内文章）
uv run python scripts/llm_rank.py --task news_classify          # Phase 1: 快速分类打分
uv run python scripts/llm_rank.py --task news_summarize         # Phase 2: 高分英文生成中文摘要
uv run python scripts/llm_rank.py --task vuln_assess            # 漏洞 AI 评估
uv run python scripts/llm_rank.py --task daily_brief            # 每日分类日报
uv run python scripts/llm_rank.py --days 0 --rescore            # 处理所有文章（不限30天）
uv run python scripts/llm_rank.py --min-score 7                 # 仅 >=7 分的文章生成摘要
```

- **Phase 1**（分类+打分）：batch=80，并发 4 路，仅输出 score+cat+reason，极快
- **Phase 2**（摘要）：仅处理 `llm_score >= min_score` 的英文文章，节省 ~60% token
- **30 天限制**：默认只处理 30 天内文章，`--days 0` 解除限制
- 新闻分类为 5 类：`incident / vuln / supply-chain / research / industry`
- 漏洞 AI 评估产出 `ai_severity`（独立于 CVSS 判断）和中文概述
- 日报按分类生成当日摘要，存入 SQLite `daily_briefs` 表（`GET /api/brief` 读取）

## 行业资讯链路（SQLite 重构后）

**数据底座**：`backend/cache/news.db` (SQLite + FTS5)

**首次部署**：
```bash
uv run python scripts/migrate_to_sqlite.py            # 一次性迁移 news.json → news.db
```

**日常操作**：
```bash
uv run python scripts/fetch_data.py --only news --incremental    # 智能挑源（按 last_fetched + interval_minutes）
uv run python scripts/embed_articles.py                           # 计算嵌入（multilingual-e5-small，首次下载 ~470MB）
uv run python scripts/embed_articles.py --window 168              # 扩大窗口（如补跑过去 7 天）
uv run python scripts/cluster_articles.py                         # 镜像聚类（余弦相似度 ≥0.85，支持跨语言）
uv run python scripts/llm_rank.py --task news_classify            # 仅给未打分的 articles 打分
uv run python scripts/llm_rank.py --task news_summarize           # 高分英文文章 → 中文摘要
uv run python scripts/llm_rank.py --task daily_brief              # 5 类日报，写入 daily_briefs 表
uv run python scripts/llm_rank.py --task daily_brief --date 2026-05-25  # 指定日期重跑
```

**嵌入管道说明**：
- `embed_articles.py` 使用 `intfloat/multilingual-e5-small`（118M 参数，MIT 协议，Apple Silicon MPS 加速）
- 将标题编码为 384 维 L2-归一化向量，存入 `article_embeddings` 表（独立于 `articles`）
- `cluster_articles.py` 读取已有嵌入，构建 n×n 余弦相似度矩阵，用 Union-Find 合并 ≥0.85 的对
- 跨语言镜像（"微软修补 Outlook RCE" ↔ "Microsoft patches Outlook RCE"）可被正确检出
- 依赖：`sentence-transformers>=3.0`（含 torch，约 700MB，`uv sync` 一次性下载）

**fetch_data 与 LLM 完全解耦**：fetch 写 articles (LLM 字段 NULL)；llm_rank 独立扫 `WHERE llm_score IS NULL` 并填上。
两个进程通过 SQLite WAL 模式并发，0 import 关系。

**Agent / Claude 查询**：
- 直接读 SQLite：`sqlite3 backend/cache/news.db "SELECT * FROM articles WHERE date(published)='2026-05-25' AND llm_score >= 7"`
- FTS5 全文搜：`sqlite3 backend/cache/news.db "SELECT title FROM articles_fts WHERE articles_fts MATCH 'CVE-2025'"`
- 当天 NDJSON 归档：`Read backend/archive/news/2026-05-25.jsonl`

**Cron 部署**：参考 `docs/cron-template.txt`。

## 前端

`web/index.html`：

- 默认中文，右上 `中 / EN` 切换；语言写到 `localStorage` 持久化
- OpenAI 风格：暖白 `#FAFAF7` 画布、纯白卡片、黑墨主文、Geist + Geist Mono、12px 圆角、温和 hairline
- Sticky 顶导栏 + Hero 统计 + 日期 strip + Tab + 主体（卡片流）+ 右栏（热度榜 / 趋势关键词 / 流水线）
- 三个 tab：行业资讯（带 5 类分类子过滤 + zh/en/all）、漏洞情报（带 5 种 kind 子过滤 + AI 评估区块）、安全论文（占位）
- 行业资讯支持每日分类简报（daily brief）、新闻双列网格布局
- 英文文章自动展示 AI 中文摘要；低质量文章（llm_score<=2）自动过滤
- 搜索框 200ms 防抖，`⌘K` 聚焦
- 服务端 503 / 接口失败不会整体崩——`Promise.allSettled` 各 panel 独立渲染

### 给后续 Claude 会话的说明

- 改前端文本一律走 `I18N` 字典，不要在 HTML 里写死中文
- 新加 API 字段：先动 `models.py`，再改 `data.py` 的归一化，最后改前端渲染器
- 新增 fetcher：在 `scripts/fetch_data.py` 的 `FETCHERS` 注册，并约定写出 `backend/cache/<name>.json`
- 跑命令永远是 `uv run …`；裸 `python` 会找不到包
- 子模块 OPML 来自上游，**不要手改**；新增源走 `NEWS_SOURCES` 列表或独立 fetcher
- 服务起在 8000 端口；改端口同步改 `web/` 里没硬编码（都用相对路径）
