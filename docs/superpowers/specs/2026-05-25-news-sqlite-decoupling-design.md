# 行业资讯链路重构：SQLite 主存 + Fetch/LLM 解耦

**日期**：2026-05-25
**范围**：仅"行业资讯"（news）链路；漏洞情报（vuln）本轮不动
**驱动目标**：
1. 把 `fetch_data.py`（数据拉取）与 `llm_rank.py`（LLM 打分/摘要/日报）从代码层解耦，通过 SQLite 隔空通信
2. 用 SQLite + FTS5 替代 `news.json` 单文件做主存，兼顾 Agent 检索与查询性能
3. 引入按源差异化的智能拉取调度 + Conditional GET 降低浪费
4. 镜像聚类（同 URL 转发 + 高相似标题）压缩重复信号 + 节省 LLM token
5. 自动生成 5 类全覆盖日报 + 用户手动刷新按钮
6. 显式过滤"非安全主题"文章（LLM 判断 `is_relevant`）

---

## 1. 整体架构

```
┌──────────────────────┐         ┌──────────────────────┐
│  fetch_data.py       │         │   llm_rank.py        │
│  （纯 IO）            │         │   （纯 LLM）          │
│                      │         │                      │
│  pull RSS            │         │  read articles       │
│  dedupe/keyword 过滤  │         │     WHERE llm_score  │
│  upsert articles     │  ──→    │           IS NULL    │
│     llm_* = NULL     │  news.db│  call MiniMax/OpenAI │
│                      │  ←──    │  UPDATE articles SET │
│  不再 import llm_rank │  WAL    │     llm_score=...    │
└──────────────────────┘         └──────────────────────┘
            ↑                                 ↑
   cron 每 15min（智能挑源）         cron 每 2h
                              ↓
              ┌──────────────────────┐
              │ cluster_articles.py  │ ← fetch 后、LLM 前跑
              │ （Jaccard 聚镜像）    │   deterministic, 无 LLM
              └──────────────────────┘
```

**关键属性**：
- 两个核心进程（fetch / LLM）0 import 关系
- 通过 SQLite WAL 模式并发写入（同一行不同列，无冲突）
- 任一进程挂了，另一个继续跑
- 漏洞情报链路（kev/ghsa/pocs/itw/osv/epss/nuclei/hn/masto/heat）保持现有 JSON 文件流，零侵入

---

## 2. 数据底座：SQLite Schema

主存文件：`backend/cache/news.db`（启用 WAL 模式）

### 2.1 articles 表

```sql
CREATE TABLE articles (
    id              INTEGER PRIMARY KEY,
    canonical_url   TEXT    UNIQUE NOT NULL,
    title           TEXT    NOT NULL,
    summary         TEXT,
    source_slug     TEXT    NOT NULL,
    source_title    TEXT,
    lang            TEXT,                          -- 'zh' / 'en'
    rss_category    TEXT,
    published       TEXT,                          -- ISO 8601 UTC, 可空
    fetched_at      TEXT    NOT NULL,              -- ISO 8601 UTC
    first_seen_date TEXT,                          -- 'YYYY-MM-DD'

    -- LLM 增强字段（fetch 时全 NULL）
    llm_score          INTEGER,                    -- 0-10
    llm_category       TEXT,                       -- incident|vuln|supply-chain|research|industry
    llm_reason         TEXT,
    is_relevant        BOOLEAN,                    -- 1=安全相关 / 0=离题 / NULL=未判断
    llm_scored_at      TEXT,
    llm_summary_zh     TEXT,                       -- phase 2 中文摘要（仅高分英文）
    llm_summarized_at  TEXT,

    -- 镜像聚类
    cluster_id          INTEGER,                   -- NULL=未聚类
    is_cluster_primary  BOOLEAN DEFAULT 0,

    FOREIGN KEY (cluster_id) REFERENCES clusters(id)
);

CREATE INDEX idx_published     ON articles(published DESC);
CREATE INDEX idx_score         ON articles(llm_score DESC, published DESC);
CREATE INDEX idx_category      ON articles(llm_category);
CREATE INDEX idx_cluster       ON articles(cluster_id);
CREATE INDEX idx_first_seen    ON articles(first_seen_date);
CREATE INDEX idx_is_relevant   ON articles(is_relevant);
```

### 2.2 FTS5 全文索引

```sql
CREATE VIRTUAL TABLE articles_fts USING fts5(
    title, summary, llm_summary_zh,
    content='articles', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);

-- 标准同步触发器（articles INSERT/UPDATE/DELETE → articles_fts）
CREATE TRIGGER articles_ai AFTER INSERT ON articles BEGIN
  INSERT INTO articles_fts(rowid, title, summary, llm_summary_zh)
  VALUES (new.id, new.title, new.summary, new.llm_summary_zh);
END;
CREATE TRIGGER articles_ad AFTER DELETE ON articles BEGIN
  INSERT INTO articles_fts(articles_fts, rowid, title, summary, llm_summary_zh)
  VALUES('delete', old.id, old.title, old.summary, old.llm_summary_zh);
END;
CREATE TRIGGER articles_au AFTER UPDATE ON articles BEGIN
  INSERT INTO articles_fts(articles_fts, rowid, title, summary, llm_summary_zh)
  VALUES('delete', old.id, old.title, old.summary, old.llm_summary_zh);
  INSERT INTO articles_fts(rowid, title, summary, llm_summary_zh)
  VALUES (new.id, new.title, new.summary, new.llm_summary_zh);
END;
```

### 2.3 sources 表（Conditional GET 状态）

```sql
CREATE TABLE sources (
    slug             TEXT PRIMARY KEY,
    title            TEXT,
    url              TEXT NOT NULL,
    lang             TEXT,                            -- 'zh' / 'en'
    tier             TEXT NOT NULL DEFAULT 'tail',    -- 'top' / 'tail'
    interval_minutes INTEGER NOT NULL,                -- top=30, tail=240, 可 override
    last_fetched     TEXT,
    last_etag        TEXT,                            -- Conditional GET
    last_modified    TEXT,
    ok               BOOLEAN DEFAULT 1,
    error            TEXT,
    consecutive_failures INTEGER DEFAULT 0
);
```

### 2.4 clusters 表（镜像组元信息）

```sql
CREATE TABLE clusters (
    id                  INTEGER PRIMARY KEY,
    primary_article_id  INTEGER NOT NULL REFERENCES articles(id),
    member_count        INTEGER NOT NULL,
    created_at          TEXT NOT NULL
);
```

**循环外键说明**：`articles.cluster_id → clusters.id` 与 `clusters.primary_article_id → articles.id` 形成循环引用。SQLite 允许这种结构，但 `cluster_articles.py` 写入时需要按以下顺序：

```python
# 单事务内：
# 1. INSERT INTO clusters (primary_article_id=tentative, member_count, created_at) → 拿到 cluster_id
# 2. UPDATE articles SET cluster_id=?, is_cluster_primary=1 WHERE id=primary
# 3. UPDATE articles SET cluster_id=? WHERE id IN (mirrors)
# 用 PRAGMA defer_foreign_keys = ON 解开循环
```

### 2.5 daily_briefs 表（按 date + category 唯一）

```sql
CREATE TABLE daily_briefs (
    date           TEXT NOT NULL,                 -- 'YYYY-MM-DD'
    category       TEXT NOT NULL,                 -- 5 类: incident|vuln|supply-chain|research|industry
    text           TEXT NOT NULL,
    article_count  INTEGER NOT NULL,
    generated_at   TEXT NOT NULL,
    PRIMARY KEY (date, category)
);
```

---

## 3. 派生数据：按天 NDJSON 归档

路径：`backend/archive/news/YYYY-MM-DD.jsonl`

每天一个文件，每行一篇文章的完整 JSON 序列化。由 `fetch_data` 收尾时从 SQLite dump。

**用途**：
- Agent / Claude 一次性吃下当天全集（`Read backend/archive/news/2026-05-25.jsonl`，~1MB）
- 离线分析、归档审计
- 删了能从 SQLite 重建

**包含**：所有当天文章，含 `is_relevant=false` 的（便于审查 LLM 误判）

---

## 4. fetch_data.py 改造

### 4.1 CLI 契约

```
uv run python scripts/fetch_data.py --only news [--full | --incremental]
```

| flag | 行为 |
|---|---|
| `--incremental`（默认） | 智能挑源：仅拉取 `last_fetched + interval_minutes <= now` 的源；带 ETag/If-Modified-Since |
| `--full` | 全部源都拉，不带 Conditional GET 头 |

**其他 fetcher（kev/ghsa/...）不变**：继续写 `backend/cache/*.json`。

### 4.2 News 子流程

```python
# 伪代码
def fetch_news_incremental():
    now = utc_now_iso()
    due_sources = db.query("""
        SELECT * FROM sources
        WHERE ok = 1 AND consecutive_failures < 5
          AND (last_fetched IS NULL
               OR datetime(last_fetched, '+' || interval_minutes || ' minutes') <= ?)
    """, [now])

    for src in due_sources:
        headers = {}
        if src.last_etag:     headers["If-None-Match"] = src.last_etag
        if src.last_modified: headers["If-Modified-Since"] = src.last_modified
        r = await client.get(src.url, headers=headers)

        if r.status_code == 304:
            db.update_source(slug, last_fetched=now)   # 触达但无变化
            continue
        # 200 → 解析 RSS → upsert articles (llm_* 全 NULL) → 更新 ETag/Last-Modified
        for entry in parse_feed(r.content):
            db.upsert_article(canonical_url=canonical(entry.link), ...)
        db.update_source(slug, last_fetched=now, last_etag=r.headers.get("ETag"),
                         last_modified=r.headers.get("Last-Modified"))

    # 收尾：dump 当天 NDJSON 归档
    dump_archive(today)
```

### 4.3 砍掉的代码

`fetch_data.py:488-497` 整个 LLM 自动触发代码块删除。

### 4.4 保留的现有逻辑

- **Layer 1 URL 去重**：现在变成两层防御 —— Python 端 `_canonical_url()` 仍跑（剥追踪参数），最终幂等性靠 SQLite `canonical_url UNIQUE` 约束兜底（`INSERT OR IGNORE`）
- **Layer 1 标题去重**：仍在 Python 端 batch 内做（同一批拉取里同标题不同 URL 视为重复，保留 fetched_at 最早的）
- **Layer 2 关键词黑名单**：仍在 upsert 前过滤，被 drop 的文章**不入库**（因为关键词命中是确定性的操作噪音，不需要审计）
- **snapshot_today / first_seen 注解**：非 news 的 fetcher（kev/ghsa/...）仍按现有逻辑跑；news 的 first_seen 改由 SQLite `first_seen_date` 字段直接承担（UPSERT 时若是新行则填今天）

---

## 5. llm_rank.py 改造

### 5.1 CLI 契约

```
uv run python scripts/llm_rank.py --task TASK [--rescore] [--days N] [--date YYYY-MM-DD]
```

| task | 数据契约 |
|---|---|
| `classify` | `SELECT * WHERE llm_score IS NULL AND published >= now-30d`；调 LLM；UPDATE articles SET `llm_score / llm_category / llm_reason / is_relevant / llm_scored_at` |
| `summarize` | `SELECT * WHERE llm_summary_zh IS NULL AND llm_score >= 5 AND lang='en' AND is_relevant = 1 AND published >= now-30d`；UPDATE articles SET `llm_summary_zh / llm_summarized_at` |
| `brief` | 对 `--date`（默认今天）查询 `WHERE first_seen_date = ? AND is_relevant = 1`，按 5 类各跑一次 LLM 总结；INSERT OR REPLACE INTO daily_briefs |
| `all` | classify → summarize → brief 顺序 |
| `vuln_assess` | **不变**，继续读 JSON 写 `vuln_ai.json`（本轮 vuln 不动） |

### 5.2 classify 提示词扩展

输出 JSON 增加 `is_relevant` 字段：

```json
{
  "score": 7,
  "category": "vuln",
  "is_relevant": true,
  "reason": "讨论 React Server Components RCE"
}

// 离题示例
{
  "score": 0,
  "category": null,
  "is_relevant": false,
  "reason": "AI 大模型行业评论，与安全无关"
}
```

提示词补充原则：明确"is_relevant" 仅判断"是否属于网络安全/信息安全/软件安全主题"，与文章质量、严重程度无关。

### 5.3 标志位

- `--rescore`：解除 `IS NULL` 限制，强制重打
- `--days N`：覆盖默认 30 天回看窗口（`--days 0` 不限）
- `--date YYYY-MM-DD`：brief 任务指定日期

---

## 6. cluster_articles.py（新增）

### 6.1 CLI

```
uv run python scripts/cluster_articles.py [--window 72]
```

`--window`：回看小时数，默认 72h

### 6.2 算法

```python
def shingles(title: str) -> set[str]:
    normalized = re.sub(r'\W', '', title.lower())
    return {normalized[i:i+3] for i in range(len(normalized) - 2)}

def jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if (a or b) else 0

# 1. SELECT id, title FROM articles WHERE fetched_at >= now - window AND cluster_id IS NULL
# 2. 按 title 首字索引分桶（同首字才两两比较，10x 加速）
# 3. 桶内两两 Jaccard，阈值 >= 0.7 视为镜像
# 4. 用 Union-Find 把连通组聚成 cluster
# 5. 每个 cluster 选 primary（zh 优先 → fetched_at 最早）
# 6. INSERT INTO clusters; UPDATE articles SET cluster_id, is_cluster_primary
```

### 6.3 触发时机

```
fetch_data → cluster_articles → llm_rank classify (only WHERE cluster_id IS NULL OR is_cluster_primary=1)
```

**LLM token 节省**：只对 primary 打分，镜像 SELECT 时 JOIN 继承 primary 的 score。

---

## 7. 拉取调度

**Tier 规则**：
- `top`（~50 源，硬编码白名单）：FreeBuf / 安全客 / 嘶吼 / 看雪 / Krebs / BleepingComputer / SecurityWeek / TheHackerNews / DarkReading / 阿里云安全 / 腾讯安全 …
- `tail`（其余 ~660 源）：默认

**Interval**：
- top → 30 min
- tail → 240 min（4h）
- `sources.interval_minutes` 可手工 override

**Cron**：

```cron
*/15 * * * *   cd /path && set -a && source .env && set +a && uv run python scripts/fetch_data.py --only news --incremental
0    */2 * * * cd /path && set -a && source .env && set +a && uv run python scripts/cluster_articles.py
30   */2 * * * cd /path && set -a && source .env && set +a && uv run python scripts/llm_rank.py --task classify
45   */2 * * * cd /path && set -a && source .env && set +a && uv run python scripts/llm_rank.py --task summarize
0    23  * * * cd /path && set -a && source .env && set +a && uv run python scripts/llm_rank.py --task brief
```

- `*/15` 唤醒 fetcher，内部按 due 挑源 → top 实际 30min 一次，tail 4h 一次
- cluster / classify / summarize 错峰，避免在同一秒抢 SQLite 写锁
- brief 每晚 23:00 跑一次覆盖当天

---

## 8. 一次性迁移：`scripts/migrate_to_sqlite.py`

```
uv run python scripts/migrate_to_sqlite.py            # 默认：news.json + daily_brief.json → news.db
uv run python scripts/migrate_to_sqlite.py --force    # 覆盖已存在的 news.db
```

**步骤**：
1. 若 `news.db` 已存在且无 `--force` → 报错退出
2. 创建 `news.db`，按 §2 schema 建表 + FTS5 + 触发器
3. 把 `NEWS_SOURCES`（fetch_data.py 顶部硬编码列表）+ `merged.opml` 合并导入 `sources` 表
   - 应用 tier 白名单（白名单内 → `tier='top'`，其余 → `tier='tail'`）
4. 读 `backend/cache/news.json`，批量 INSERT 到 `articles`，保留所有 LLM 字段
   - `is_relevant`：暂留 NULL（下一次 classify 会判断）
5. 读 `backend/cache/daily_brief.json`，每个分类拆一行 INSERT 到 `daily_briefs`
6. 验证：`SELECT COUNT(*) FROM articles` 等于 `news.json.articles` 长度
7. 把 `news.json` 改名为 `news.json.bak`（保留备份不删）
8. 把 `daily_brief.json` 改名为 `daily_brief.json.bak`

---

## 9. API 层改造

### 9.1 backend/app/data.py

`all_articles()` 从读 `news.json` 改为 SQLite 查询：

```python
def all_articles() -> list[Article]:
    rows = db.query("""
        SELECT a.*, c.member_count
        FROM articles a
        LEFT JOIN clusters c ON c.id = a.cluster_id
        WHERE (a.is_relevant = 1 OR a.is_relevant IS NULL)
          AND (a.cluster_id IS NULL OR a.is_cluster_primary = 1)
    """)
    return [Article(**row) for row in rows]
```

**前端 API 契约**：`Article` Pydantic 模型在原基础上增加：
- `is_relevant: bool | None`（透传 SQLite 字段）
- `mirror_count: int = 0`（= `clusters.member_count - 1`，不含 primary）
- `mirror_source_titles: list[str] = []`（**在 `/api/news` 响应里一次性带上**，仅含 source_title 字符串，最多前 6 个；用于卡片底部 "+N 镜像源 · 安全客 / 嘶吼 …" 展示，避免每张卡片再发一次请求）

完整镜像内容（含标题/链接）走单独 endpoint，懒加载（见 §9.3）。

### 9.2 backend/app/main.py 新增 endpoint

```python
@app.post("/api/brief/regenerate", tags=["news"])
async def regenerate_brief(
    background: BackgroundTasks,
    date: str | None = Query(default=None, description="YYYY-MM-DD"),
    x_refresh_token: str = Header(alias="X-Refresh-Token"),
):
    expected = os.environ.get("SECURITY_HOT_REFRESH_TOKEN")
    if not expected or x_refresh_token != expected:
        raise HTTPException(401, "invalid refresh token")
    target = date or today_str()
    background.add_task(
        _run_llm_rank_brief, target
    )
    return {"status": "accepted", "date": target}
```

```python
@app.get("/api/news/hidden", response_model=list[Article], tags=["news"])
def api_news_hidden(
    date: str | None = Query(default=None, description="YYYY-MM-DD; default=today"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[Article]:
    """Show articles judged is_relevant=0 — for human audit of LLM filter.

    Returns articles with their llm_reason so users can see *why* the LLM
    flagged them as off-topic.
    """
    target = date or today_str()
    rows = db.query("""
        SELECT * FROM articles
        WHERE is_relevant = 0 AND first_seen_date = ?
        ORDER BY fetched_at DESC LIMIT ?
    """, [target, limit])
    return [Article(**row) for row in rows]
```

### 9.3 新增 endpoint for cluster mirrors

```python
@app.get("/api/news/{article_id}/mirrors", response_model=list[Article], tags=["news"])
def api_article_mirrors(article_id: int) -> list[Article]:
    """Return all mirror articles in the same cluster (excludes the primary itself).

    404 if article_id not found or has no cluster_id.
    """
    primary = db.query_one("SELECT cluster_id FROM articles WHERE id = ?", [article_id])
    if not primary or not primary["cluster_id"]:
        raise HTTPException(404, "no cluster for this article")
    rows = db.query("""
        SELECT * FROM articles
        WHERE cluster_id = ? AND id != ?
        ORDER BY fetched_at ASC
    """, [primary["cluster_id"], article_id])
    return [Article(**row) for row in rows]
```

---

## 10. 前端改造（`web/index.html`）

### 10.1 聚类卡片样式 A（Stacked Badge）

在现有 article card 底部加：

```html
<div class="mirror-strip" v-if="article.mirror_count > 0" @click="expandMirrors()">
  <div class="mirror-dot"></div>
  <div class="mirror-dot"></div>
  <span class="mirror-count">+{{ article.mirror_count }} 镜像源</span>
  <span class="mirror-srcs">· {{ article.mirror_source_titles.join(' / ') }}</span>
  <span class="mirror-chevron">▾</span>
</div>
```

点击 → 调 `/api/news/{id}/mirrors` → 内联展开。

### 10.2 日报刷新按钮

日报区块右上角加 ⟳ 图标。点击时：

```js
async function regenerateBrief() {
  let token = localStorage.getItem('refreshToken');
  if (!token) {
    token = prompt('Enter refresh token (set in .env as SECURITY_HOT_REFRESH_TOKEN):');
    if (!token) return;
    localStorage.setItem('refreshToken', token);
  }
  try {
    const r = await fetch('/api/brief/regenerate', {
      method: 'POST',
      headers: {'X-Refresh-Token': token}
    });
    if (r.status === 401) {
      localStorage.removeItem('refreshToken');
      showToast('Token 无效，请重试');
      return;
    }
    showToast('简报生成中，10s 后自动刷新');
    setTimeout(() => fetchOne('daily_brief'), 10000);
  } catch (e) {
    showToast('刷新失败：' + e.message);
  }
}
```

**Token 来源**：首次点击时 `prompt()` 让用户粘贴 `.env` 里的 `SECURITY_HOT_REFRESH_TOKEN` 值，存 localStorage。Token 无效时自动清掉重新提示。这是开发者/管理员功能，不是普通访客功能，UX 简陋可以接受。

### 10.3 "查看已隐藏"透明度开关

在分类过滤器右侧加：

```html
<button onclick="toggleHidden()">
  ⊘ 已隐藏 {{ hiddenCount }} 篇离题
</button>
```

点击 → 调 `/api/news/hidden?date=current` → 弹层展示 LLM 判 `is_relevant=false` 的文章 + 理由。

---

## 11. 受影响 / 不受影响清单

| 文件 | 状态 |
|---|---|
| `scripts/fetch_data.py` | 改造：news 走 SQLite，砍 LLM 触发；其他 10 个 fetcher 不变 |
| `scripts/llm_rank.py` | 改造：news 相关读写 SQLite；`vuln_assess` 不变 |
| `scripts/cluster_articles.py` | **新增** |
| `scripts/migrate_to_sqlite.py` | **新增** |
| `scripts/db.py` | **新增**：SQLite 连接管理 + schema 初始化 + 公共 query helper |
| `backend/cache/news.db` | **新增** |
| `backend/cache/news.json` | 迁移后 → `.bak`，不再写 |
| `backend/cache/daily_brief.json` | 迁移后 → `.bak`，不再写 |
| `backend/cache/{kev,ghsa,pocs,itw,osv-*,epss,nuclei,hn,masto,heat}.json` | **完全不变** |
| `backend/archive/news/*.jsonl` | **新增**：每天 dump |
| `backend/app/data.py` | 改造：news 部分查 SQLite，vuln 部分不变 |
| `backend/app/main.py` | 改造：加 `POST /api/brief/regenerate`、`GET /api/news/{id}/mirrors`、`GET /api/news/hidden` |
| `backend/app/models.py` | 改造：`Article` 加 `mirror_count`、`mirror_source_titles`、`is_relevant` |
| `web/index.html` | 小改：聚类卡片、刷新按钮、已隐藏开关 |
| `CLAUDE.md` | 更新：新文件布局、新命令、新 cron 示例 |

---

## 12. 验收标准

实施完成后必须满足：

1. ✅ `uv run python scripts/migrate_to_sqlite.py` 成功，`news.db` 记录数 == 原 `news.json.articles` 长度
2. ✅ `uv run python scripts/fetch_data.py --only news --incremental` 不再 import llm_rank，能跑通；多次重跑无重复 article（UPSERT 幂等）
3. ✅ 命中 304 时 stderr 显示 `[news] <slug>: 304 not-modified`，articles 表不变
4. ✅ `uv run python scripts/llm_rank.py --task classify` 仅处理 `llm_score IS NULL` 行；输出含 `is_relevant`
5. ✅ `uv run python scripts/cluster_articles.py` 找出 >0 个 cluster，UPDATE articles 设 `cluster_id`
6. ✅ `uv run python scripts/llm_rank.py --task brief` 生成 5 行 `daily_briefs`（5 分类全覆盖）
7. ✅ `GET /api/news` 返回的列表中**不**包含 `is_relevant=0` 的文章，**不**包含非 primary 镜像
8. ✅ 前端：聚类徽章显示并能展开；日报"刷新"按钮可触发；"已隐藏"开关显示数量
9. ✅ Archive: `backend/archive/news/2026-05-25.jsonl` 存在且行数 == 当天 articles 总数（含 is_relevant=0）
10. ✅ 漏洞情报链路 `/api/vuln`、`/api/today`、`/api/sources`、`/api/manifest` 行为完全不变

---

## 13. 范围排除（这轮不做，留 backlog）

- 漏洞情报（vuln）的 SQLite 化 —— 下一轮设计
- 自动源降级（连续 30 天 90%+ 离题 → tier 降级或冷藏）
- 跨源 embedding 聚类（"同事件不同视角"折叠）—— 明确决定不做
- LLM 厂商抽象层（当前直接 MiniMax/OpenAI 二选一已够用）
- 历史归档的 Git 化（`backend/archive/` 入库）—— 等数据稳定后再考虑

---

## 14. 失败模式与降级

| 情况 | 表现 | 处理 |
|---|---|---|
| SQLite 文件损坏 | 启动报错 | 从最近 NDJSON 归档手动重建 |
| LLM API 全挂 | classify 任务失败但 articles 仍写入 | 前端展示 articles 但无 score；日报 fallback 显示"暂无"|
| 某源连续 5 次失败 | `consecutive_failures >= 5` | 自动跳过该源，需要人工 reset |
| Cron 错过一次 | 下次正常跑 | 智能挑源会自动补抓（基于 last_fetched）|
| 同时跑两个 fetch_data 实例 | SQLite 行锁等待 | WAL 模式下读不阻塞，写串行；可接受 |
| 聚类误判（中英对照被错误聚合） | 不会，Jaccard 0 不会过阈值 | — |
| LLM 错判 is_relevant | 文章被隐藏 | "查看已隐藏"接口暴露给人工审计 |

---

## 15. 时间估算（信息性）

- Phase 1（数据底座）：SQLite schema + db.py + migrate_to_sqlite.py + 验收点 1
- Phase 2（fetch 解耦）：fetch_data.py 改造 + Conditional GET + 验收点 2-3
- Phase 3（LLM 解耦）：llm_rank.py 改造 + is_relevant + 验收点 4
- Phase 4（聚类）：cluster_articles.py + 验收点 5
- Phase 5（日报扩展）：5 类 brief + endpoint + 验收点 6
- Phase 6（API 适配 + 前端）：data.py + main.py + index.html + 验收点 7-9
- Phase 7（部署）：cron 模板 + CLAUDE.md 更新 + 端到端验证

具体工时由 `writing-plans` 阶段分解。
