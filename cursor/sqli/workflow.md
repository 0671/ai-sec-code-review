# SQL 注入静态审计工作流 v2.0

> 一套模块化、按需加载的 Cursor AI 审计系统，覆盖 **7 种语言 × 12 个 ORM 框架 × 5 种数据库引擎**。

---

## 知识资产一览

| 类别 | 数量 | 内容 |
|------|------|------|
| 核心引擎 | 1 | 污点判定树 · 严重性矩阵 · 二阶方法论 · 误报指南 · 报告模板 |
| 语言模块 | 7 | Node.js · Python · Java · Go · PHP · C# · Ruby |
| 框架模块 | 12 | Sequelize · TypeORM · Prisma · Knex · MyBatis · Hibernate · Django ORM · SQLAlchemy · GORM · Laravel · ActiveRecord · Entity Framework |
| 数据库模块 | 5 | PostgreSQL · MySQL · MSSQL · SQLite · Oracle |
| 被动规则 | 7 | 按语言独立配置的实时编码拦截 |
| **合计** | **32 文件** | **约 170 KB 结构化安全知识** |

---

## 架构

```
.cursor/
│
├── commands/
│   └── sqli-audit.md ·················· 审计流程编排（/sqli-audit 触发）
│
├── skills/
│   └── sqli-hunt/
│       ├── SKILL.md ··················· 核心引擎（语言无关）
│       │                                ├ 动态加载协议
│       │                                ├ 污点判定树
│       │                                ├ 严重性矩阵
│       │                                ├ 二阶注入方法论
│       │                                ├ 通用回退模式库
│       │                                ├ 误报识别指南
│       │                                ├ 合规边界
│       │                                └ 报告输出格式
│       │
│       ├── lang/ ······················ 语言层
│       │   ├── nodejs.md               Express / Koa / Fastify / GraphQL / Serverless
│       │   ├── python.md              Django / Flask / FastAPI / Celery
│       │   ├── java.md               Spring MVC / JAX-RS / gRPC / MQ
│       │   ├── go.md                 net/http / Gin / Echo / Fiber
│       │   ├── php.md               $_GET/$_POST / Laravel / Symfony / WordPress
│       │   ├── csharp.md            ASP.NET Core / Minimal API / SignalR
│       │   └── ruby.md              Rails / Sinatra / Grape
│       │
│       ├── framework/ ················ 框架层
│       │   ├── sequelize.md           12 模式 · 5 CVE · 5 修复模板
│       │   ├── typeorm.md            10 模式 · 1 CVE
│       │   ├── prisma.md             5 模式 · Prisma.sql 标签陷阱
│       │   ├── knex.md              11 模式 · raw 绑定参数
│       │   ├── mybatis.md           14 模式 · ${} vs #{} 核心原理
│       │   ├── hibernate.md         12 模式 · HQL/JPQL/JDBC/Criteria
│       │   ├── django-orm.md        13 模式 · 4 CVE · extra/RawSQL
│       │   ├── sqlalchemy.md        12 模式 · text() f-string 陷阱
│       │   ├── gorm.md             14 模式 · Order() 无过滤问题
│       │   ├── laravel-eloquent.md  13 模式 · Raw 方法绑定
│       │   ├── activerecord.md      15 模式 · Arel.sql 滥用
│       │   └── entity-framework.md  12 模式 · FormattableString 陷阱
│       │
│       └── database/ ················· 数据库层
│           ├── postgresql.md          $$ 美元引用 · COPY TO PROGRAM → RCE
│           ├── mysql.md              版本注释绕过 · LOAD_FILE · 多字节编码
│           ├── mssql.md             stacked queries · xp_cmdshell → RCE
│           ├── sqlite.md            ATTACH DATABASE → WebShell · load_extension
│           └── oracle.md            UTL_HTTP → SSRF · Java 存储过程 → RCE
│
└── rules/ ····························· 被动拦截（日常开发自动生效）
    ├── sqli-guard-nodejs.mdc          *.ts / *.js — 20 globs
    ├── sqli-guard-python.mdc         *.py — 17 globs
    ├── sqli-guard-java.mdc          *.java / *.kt / *Mapper.xml — 10 globs
    ├── sqli-guard-go.mdc            *.go — 17 globs
    ├── sqli-guard-php.mdc           *.php — 15 globs
    ├── sqli-guard-csharp.mdc        *.cs — 14 globs
    └── sqli-guard-ruby.mdc          *.rb — 9 globs
```

---

## 设计原则

### 三层知识分离 + 按需加载

```
                    ┌────────────────────────────┐
                    │       SKILL.md 核心引擎       │  ← 每次必加载
                    │  判定树 · 矩阵 · 方法论 · 报告  │
                    └─────────────┬──────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
    ┌─────────▼─────────┐ ┌──────▼──────────┐ ┌──────▼──────────┐
    │   lang/*.md        │ │ framework/*.md   │ │ database/*.md   │
    │   语言 Source/Sink  │ │ 模式库+CVE+修复   │ │ 引擎攻击面+修正  │
    │                    │ │                  │ │                 │
    │ Phase 0 识别语言    │ │ Phase 0 识别依赖  │ │ Phase 0 识别 DB  │
    │ 后按需 Read         │ │ 后按需 Read       │ │ 后按需 Read      │
    └────────────────────┘ └──────────────────┘ └─────────────────┘
```

**为什么这样设计？**

1. **节省 Context Window**：审计 Spring Boot + MyBatis + MySQL 项目时，只加载 `java.md` + `mybatis.md` + `mysql.md`，不浪费 token 在 Sequelize / Django / Ruby 等无关知识上
2. **独立可维护**：新增一个框架只需加一个 `.md` 文件，不影响其他任何模块
3. **组合爆炸可控**：7 语言 × 12 框架 × 5 数据库 = 420 种组合，模块化让每种组合都自动覆盖

### 职责划分

| 组件 | 管什么 | 不管什么 |
|------|--------|---------|
| **Command** (`sqli-audit.md`) | 做什么、按什么顺序、何时加载知识 | 具体判定逻辑 |
| **Skill 核心** (`SKILL.md`) | 怎么判断、用什么决策树 | 具体框架的 API 细节 |
| **Skill 语言插件** (`lang/*.md`) | Source/Sink 模型、目录约定 | 严重性评分 |
| **Skill 框架插件** (`framework/*.md`) | grep 正则、CVE、修复代码 | 数据库特性 |
| **Skill 数据库插件** (`database/*.md`) | 引擎攻击面、严重性修正 | 框架 API |
| **Rule** (`rules/*.mdc`) | 日常编码被动提醒 | 完整审计流程 |

---

## 使用方式

### 模式一：日常开发（被动拦截）

Rule 文件按语言 globs 自动激活。**无需任何操作**。

当你在 `services/`、`controllers/`、`mapper/` 等目录编写数据库查询时，Agent 会自动检测并提醒：
- 模板字符串/f-string 内出现 SQL 关键字 + 动态插值
- `*Raw()` / `literal()` / `$queryRawUnsafe` 等危险 API 调用
- ORDER BY / 表名 / 列名使用未校验的动态值

每种语言有独立的规则文件，互不干扰。只需将对应语言的 `.mdc` 文件放入 `.cursor/rules/` 目录。

### 模式二：按需审计（主动触发）

在 Cursor 聊天框输入 **`/sqli-audit`**，Agent 自动执行完整审计流程：

```
/sqli-audit
    │
    │  ┌─ Phase 0 ─────────────────────────────────────────────────┐
    ├──┤ 技术画像                                                    │
    │  │ 扫描 package.json / requirements.txt / go.mod / pom.xml   │
    │  │ / *.csproj / Gemfile → 识别语言 + ORM + 数据库              │
    │  └────────────────────────────────────────────────────────────┘
    │
    │  ┌─ Phase 0.5 ───────────────────────────────────────────────┐
    ├──┤ 知识按需加载                                                │
    │  │ Read lang/{language}.md      → Source/Sink 模型            │
    │  │ Read framework/{orm}.md      → grep 模式库 + CVE + 修复    │
    │  │ Read database/{engine}.md    → 引擎攻击面 + 严重性修正      │
    │  └────────────────────────────────────────────────────────────┘
    │
    │  ┌─ Phase 1 ─────────────────────────────────────────────────┐
    ├──┤ 危险 API 表面搜索                                           │
    │  │ 用框架模式库的 grep 正则扫描全部业务代码 → 候选清单           │
    │  │ 同时检查依赖版本是否命中已知 CVE                             │
    │  └────────────────────────────────────────────────────────────┘
    │
    │  ┌─ Phase 2 ─────────────────────────────────────────────────┐
    ├──┤ 污点追踪                                                    │
    │  │ 对每个候选点：向上追踪 Source → 向下确认 Sink → 检查净化    │
    │  │ 严格按 SKILL.md 判定树的 Q1→Q4 分支执行                    │
    │  └────────────────────────────────────────────────────────────┘
    │
    │  ┌─ Phase 3 ─────────────────────────────────────────────────┐
    ├──┤ 风险分级                                                    │
    │  │ 基础等级 = SKILL.md 严重性矩阵（Source×Sink×净化）          │
    │  │ 最终等级 = 基础等级 + database/*.md 修正因子                │
    │  └────────────────────────────────────────────────────────────┘
    │
    │  ┌─ Phase 4 ─────────────────────────────────────────────────┐
    ├──┤ 二阶注入专项                                                │
    │  │ 搜索 INSERT/UPDATE 含用户输入的字段                         │
    │  │ → 追踪同表字段的读取 → 是否拼入 SQL                        │
    │  └────────────────────────────────────────────────────────────┘
    │
    │  ┌─ Phase 5 ─────────────────────────────────────────────────┐
    ├──┤ 修复方案生成                                                │
    │  │ 从 framework/*.md 提取对应修复模板                          │
    │  │ 基于实际代码上下文生成具体修复代码                           │
    │  └────────────────────────────────────────────────────────────┘
    │
    │  ┌─ Phase 6 ─────────────────────────────────────────────────┐
    └──┤ 输出报告                                                    │
       │ 总览 → CVE 命中 → 发现明细（高→低）→ 二阶发现              │
       │ → 修复建议汇总 → 技术债清单 → 审计覆盖率                   │
       └────────────────────────────────────────────────────────────┘
```

---

## 加载示例

### 示例 1：Spring Boot + MyBatis + MySQL

```
Phase 0 检测到 → pom.xml 含 mybatis-spring-boot-starter + mysql-connector-java
Phase 0.5 加载 → SKILL.md + lang/java.md + framework/mybatis.md + database/mysql.md
Phase 1 使用  → mybatis.md 的 14 条模式（重点搜 Mapper XML 中的 ${}）
Phase 3 修正  → mysql.md 的引擎修正因子
```

### 示例 2：Express + Sequelize + PostgreSQL

```
Phase 0 检测到 → package.json 含 sequelize + pg
Phase 0.5 加载 → SKILL.md + lang/nodejs.md + framework/sequelize.md + database/postgresql.md
Phase 1 使用  → sequelize.md 的 12 条模式（重点搜 query/literal/fn）
Phase 3 修正  → postgresql.md 的引擎修正因子（COPY TO PROGRAM 提权）
```

### 示例 3：Django + PostgreSQL

```
Phase 0 检测到 → requirements.txt 含 django + psycopg2
Phase 0.5 加载 → SKILL.md + lang/python.md + framework/django-orm.md + database/postgresql.md
Phase 1 使用  → django-orm.md 的 13 条模式（重点搜 raw/extra/RawSQL/cursor.execute）
Phase 1 同时  → 检查 Django 版本是否命中 CVE-2022-34265 / CVE-2021-35042 等
```

### 示例 4：ASP.NET Core + EF Core + Dapper + MSSQL（多框架）

```
Phase 0 检测到 → *.csproj 含 Microsoft.EntityFrameworkCore.SqlServer + Dapper
Phase 0.5 加载 → SKILL.md + lang/csharp.md + framework/entity-framework.md + database/mssql.md
Phase 1 使用  → entity-framework.md 的 12 条模式（EF Core + Dapper + ADO.NET 全覆盖）
Phase 3 修正  → mssql.md 修正因子（默认 stacked queries → 所有注入点自动上调严重性）
```

### 示例 5：Go + GORM + SQLite（嵌入式）

```
Phase 0 检测到 → go.mod 含 gorm.io/gorm + gorm.io/driver/sqlite
Phase 0.5 加载 → SKILL.md + lang/go.md + framework/gorm.md + database/sqlite.md
Phase 1 使用  → gorm.md 的 14 条模式（重点搜 fmt.Sprintf 构建 SQL）
Phase 3 修正  → sqlite.md 修正因子（ATTACH DATABASE 写 WebShell 风险）
```

---

## 扩展指南

### 新增语言

1. 在 `lang/` 下新建 `{language}.md`
   - 定义所有 Web 框架的 **Source 模式**（HTTP 请求参数获取方式）
   - 定义所有 DB 驱动/ORM 的 **Sink 入口**（执行 SQL 的 API 列表）
   - 定义 **净化器模式**（白名单/类型转换/escape 的代码模式）
   - 定义 **目录约定**（搜索范围/排除目录/单独标记目录）
   - 定义 **依赖文件解析**（如何从 manifest 文件触发框架加载）

2. 在 `rules/` 下新建 `sqli-guard-{language}.mdc`
   - 配置 globs（匹配该语言的业务代码目录/文件后缀）
   - 编写「绝对禁止」「必须遵循」「审查触发模式」三部分规则

3. 在 `framework/` 下为该语言的主流 ORM/驱动各建一个文件

4. 在 `SKILL.md` §1.1 加载决策矩阵中添加检测信号

### 新增框架

1. 在 `framework/` 下新建 `{framework}.md`，必须包含：
   - **模式库表格**：ID + Grep 正则 + 危险等级 + 说明
   - **安全 vs 危险 API 对照**：同一操作的安全写法和危险写法对比
   - **已知 CVE 清单**：CVE 编号 + 受影响版本 + 漏洞类型 + CVSS
   - **修复模板**：每种常见漏洞模式的 before/after 代码

2. 在对应 `lang/*.md` 的「支持框架列表」中添加引用

### 新增数据库

1. 在 `database/` 下新建 `{database}.md`，必须包含：
   - **引擎特有注入技法**：该数据库独有的攻击方式（如 MSSQL xp_cmdshell）
   - **严重性修正因子表**：哪些条件导致等级上调/下调
   - **数据外带方法**：DNS/HTTP/文件等 OOB 途径
   - **各语言驱动的参数化方式**：占位符风格差异

2. 在 `SKILL.md` §1.3 数据库检测与加载中添加检测信号

---

## 快速导入

将本工作流导入到任意 Cursor 项目的 `.cursor/` 目录下，即可立即使用。

### 方式一：一行命令（推荐）

确保已安装 Node.js，在项目根目录终端执行：

```bash
npx degit 0671/ai-sec-code-review/cursor/sqli .cursor --force
```

`degit` 会从 GitHub 下载 `cursor/sqli/` 子目录的全部内容，直接释放到 `.cursor/` 下，无需 clone 整个仓库。

### 方式二：git sparse checkout

无需 Node.js，仅依赖 git：

```bash
# Linux / macOS
git clone --depth 1 --sparse https://github.com/0671/ai-sec-code-review.git /tmp/_sqli_import \
  && cd /tmp/_sqli_import \
  && git sparse-checkout set cursor/sqli \
  && mkdir -p "$OLDPWD/.cursor" \
  && cp -r cursor/sqli/* "$OLDPWD/.cursor/" \
  && cd "$OLDPWD" \
  && rm -rf /tmp/_sqli_import
```

```powershell
# Windows PowerShell
git clone --depth 1 --sparse https://github.com/0671/ai-sec-code-review.git _tmp_sqli
cd _tmp_sqli; git sparse-checkout set cursor/sqli; cd ..
if (!(Test-Path .cursor)) { New-Item -ItemType Directory .cursor }
Copy-Item -Recurse -Force _tmp_sqli\cursor\sqli\* .cursor\
Remove-Item -Recurse -Force _tmp_sqli
```

### 方式三：Cursor Agent 对话导入

切换到 **Agent 模式**，在聊天框输入：

```
请从 https://github.com/0671/ai-sec-code-review 仓库的 cursor/sqli/ 目录下载全部文件（commands/、skills/、rules/），放到当前项目的 .cursor/ 目录下，保持子目录结构。
注意：不要出现 sqli 目录名称。
```

Agent 会自动执行 shell 命令或逐文件 fetch 完成导入。

### 导入后验证

导入成功后 `.cursor/` 下应出现以下结构：

```
.cursor/
├── commands/
│   └── sqli-audit.md           ← 输入 /sqli-audit 即可触发审计
├── skills/
│   └── sqli-hunt/
│       ├── SKILL.md            ← 核心引擎（自动加载）
│       ├── lang/               ← 7 个语言模块（按需加载）
│       ├── framework/          ← 12 个框架模块（按需加载）
│       └── database/           ← 5 个数据库模块（按需加载）
├── rules/
│   ├── sqli-guard-nodejs.mdc   ← 被动拦截（自动按 globs 匹配生效）
│   ├── sqli-guard-python.mdc
│   ├── sqli-guard-java.mdc
│   ├── sqli-guard-go.mdc
│   ├── sqli-guard-php.mdc
│   ├── sqli-guard-csharp.mdc
│   └── sqli-guard-ruby.mdc
└── workflow.md                 ← 本文件（架构文档，人读用）
```

**验证方法**：在 Cursor 聊天框输入 `/sqli-audit`，如果 Agent 开始执行 Phase 0 技术画像，说明导入成功。

### 按需裁剪

如果项目只使用特定语言，可以只保留需要的模块以减少文件数量：

| 项目类型 | 保留的文件 |
|---------|-----------|
| Node.js + Sequelize + PostgreSQL | `lang/nodejs.md` + `framework/sequelize.md` + `database/postgresql.md` + `rules/sqli-guard-nodejs.mdc` |
| Spring Boot + MyBatis + MySQL | `lang/java.md` + `framework/mybatis.md` + `database/mysql.md` + `rules/sqli-guard-java.mdc` |
| Django + PostgreSQL | `lang/python.md` + `framework/django-orm.md` + `database/postgresql.md` + `rules/sqli-guard-python.mdc` |
| Go + GORM + PostgreSQL | `lang/go.md` + `framework/gorm.md` + `database/postgresql.md` + `rules/sqli-guard-go.mdc` |

> `SKILL.md`（核心引擎）和 `commands/sqli-audit.md`（审计命令）始终保留，它们是必需的。
