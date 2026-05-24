# security-hot

面向安全行业的"每日聚合面板"。三个一级板块：**行业资讯 · 漏洞情报 · 安全论文**（论文待接入）。
后端 FastAPI，前端单文件 HTML（中英 i18n，默认中文），全部由一个 uvicorn 进程同时托管。

## 目录结构

```
.
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI app + 静态挂载
│   │   ├── data.py            # 缓存读取 + 归一化
│   │   └── models.py          # Pydantic schema
│   └── cache/                 # fetcher 落地的 JSON 快照
│       ├── kev.json           # CISA KEV
│       ├── ghsa.json          # GitHub Security Advisories
│       ├── pocs.json          # nomi-sec PoC mirror
│       ├── itw.json           # inthewild.io (目前空)
│       ├── malpkgs.json       # ossf/malicious-packages commits
│       ├── heat.json          # cvecrowd (目前空)
│       ├── news.json          # 22 个精选 RSS 源
│       ├── vuln_ai.json       # 漏洞 AI 评估结果
│       ├── daily_brief.json   # 每日分类日报
│       └── manifest.json      # 各 fetcher 状态
├── rss/
│   ├── awesome-security-feed/    # submodule
│   ├── CyberSecurityRSS/         # submodule
│   ├── Chinese-Security-RSS/     # submodule
│   ├── wechat2rss/sec.opml       # 远端缓存
│   └── merged.opml               # merge_rss.py 产出
├── scripts/
│   ├── fetch_data.py          # 漏洞/PoC/资讯 → backend/cache（支持 --incremental）
│   ├── llm_rank.py            # 两阶段 LLM 管道 + 漏洞评估 + 日报生成
│   ├── merge_rss.py           # OPML 合并 + 去重 + 探活
│   ├── requirements.txt       # 仅 merge_rss.py 用
│   └── output/                # health.csv / health.md
├── web/
│   └── index.html             # 单文件前端，OpenAI 风格，i18n
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

CISA KEV、GHSA、nomi-sec PoC、OSSF malicious-packages 共四个源会跨 CVE-ID 合并：合并后保留所有 PoC 链接、KEV/ITW 标记、所有引用。`kind` 字段按优先级判定 `itw > supply > poc > cve`。

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

各 fetcher：

| 名称 | 源 | 说明 |
| --- | --- | --- |
| kev | `cisa.gov/.../known_exploited_vulnerabilities.json` | 全量 KEV，按 dateAdded 倒序取 200 |
| ghsa | `api.github.com/advisories` | 最新 100 条公开 advisory（匿名，60/h 限速） |
| pocs | `poc-in-github.motikan2010.net/api/v1` | 最近 100 个 PoC 仓库 |
| itw | `inthewild.io/feed` | RSS（feed 当前可能为空） |
| malpkgs | `api.github.com/repos/ossf/malicious-packages/commits` | 最近 80 个 commit 当作恶意包通报 |
| heat | `cvecrowd.com/api/cves` | 端点格式可能变了，目前 fallback 到 0 |
| news | 22 个精选 RSS（中 10 + 英 12） | 每个源取最新 8 条 |

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
- 日报按分类生成当日摘要，存入 `daily_brief.json`

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
