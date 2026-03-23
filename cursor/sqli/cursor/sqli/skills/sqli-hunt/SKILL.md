---
name: sqli-hunt
description: >
  SQL 注入漏洞狩猎核心引擎。提供语言无关的污点判定树、严重性矩阵、
  二阶注入方法论、误报识别指南和合规边界。具体技术栈的模式库、CVE、
  修复模板由 lang/、framework/、database/ 子模块按需提供。
metadata:
  author: security-team
  version: "2.0"
  tags: security, sql-injection, code-review, audit
---

# SQL 注入漏洞狩猎 · 核心引擎

> 本文件为语言无关的审计决策内核。具体技术栈知识由子模块按需加载。

---

## 1. 动态知识加载协议

当 `/sqli-audit` 命令触发本 Skill 时，Agent 必须在执行审计前完成知识加载：

### 1.1 加载决策矩阵

| 检测信号 | 加载文件 |
|---|---|
| `package.json` 存在 | `lang/nodejs.md` |
| `requirements.txt` / `pyproject.toml` / `Pipfile` 存在 | `lang/python.md` |
| `pom.xml` / `build.gradle` / `build.gradle.kts` 存在 | `lang/java.md` |
| `go.mod` 存在 | `lang/go.md` |
| `composer.json` 存在 | `lang/php.md` |
| `*.csproj` / `*.sln` 存在 | `lang/csharp.md` |
| `Gemfile` 存在 | `lang/ruby.md` |

### 1.2 框架检测与加载

在依赖文件中搜索以下关键字，命中则加载对应框架模块：

| 依赖关键字 | 加载文件 |
|---|---|
| `sequelize` | `framework/sequelize.md` |
| `typeorm` | `framework/typeorm.md` |
| `prisma`, `@prisma/client` | `framework/prisma.md` |
| `knex` | `framework/knex.md` |
| `mybatis`, `mybatis-spring`, `mybatis-plus` | `framework/mybatis.md` |
| `hibernate`, `spring-boot-starter-data-jpa` | `framework/hibernate.md` |
| `django`, `Django` | `framework/django-orm.md` |
| `sqlalchemy`, `SQLAlchemy`, `flask-sqlalchemy` | `framework/sqlalchemy.md` |
| `gorm.io/gorm`, `jinzhu/gorm` | `framework/gorm.md` |
| `laravel/framework`, `illuminate/database` | `framework/laravel-eloquent.md` |
| `activerecord`, `rails` | `framework/activerecord.md` |
| `Microsoft.EntityFrameworkCore`, `Dapper` | `framework/entity-framework.md` |

### 1.3 数据库检测与加载

优先从连接字符串、依赖名、配置文件推断数据库类型：

| 检测信号 | 加载文件 |
|---|---|
| `pg`, `postgres`, `postgresql`, `psycopg2`, `asyncpg`, `pgx` | `database/postgresql.md` |
| `mysql`, `mysql2`, `pymysql`, `mysqlclient`, `go-sql-driver` | `database/mysql.md` |
| `mssql`, `tedious`, `pyodbc`, `sqlserver`, `System.Data.SqlClient` | `database/mssql.md` |
| `sqlite`, `sqlite3`, `better-sqlite3`, `mattn/go-sqlite3` | `database/sqlite.md` |
| `oracledb`, `cx_Oracle`, `ojdbc`, `godror` | `database/oracle.md` |

### 1.4 多技术栈项目

若检测到多种语言或框架（如 Node.js + Python 微服务），加载所有匹配的模块。审计时按语言分组执行 Phase 1-4，最后合并为统一报告。

### 1.5 未匹配回退

若项目使用的框架/数据库不在上述列表中：
1. 加载对应语言模块获取 Source 模型
2. 使用本文件 §3「通用跨技术栈模式」作为 grep 正则
3. 在报告中标注「⚠️ 框架 {name} 暂无专用模式库，已使用通用模式，建议人工复核」

---

## 2. 污点判定树（Taint Decision Tree）

对于每一个模式命中点，严格按以下决策路径判定。不得跳过任何分支。

```
命中点（Grep 匹配到的代码行）
 │
 ├─ Q1: 该行是否位于测试文件 / migration / seed / 文档？
 │   └─ 是 → ⚪ 排除（不计入正式发现，可附录记录）
 │
 ├─ Q2: 数据来源（Source）是否可被外部用户控制？
 │   │
 │   ├─ 直接可控（HTTP 请求参数/头/体/Cookie/路径）
 │   │   └─ 标记 Source = "HTTP_DIRECT"，继续 Q3
 │   │
 │   ├─ 间接可控（函数参数，且调用链上游来自 HTTP 请求）
 │   │   └─ 标记 Source = "HTTP_INDIRECT"，继续 Q3
 │   │
 │   ├─ 数据库存储值（该值的写入链路含用户输入）
 │   │   └─ 标记 Source = "STORED"，跳转 §4 二阶注入流程
 │   │
 │   ├─ 管理后台输入（需管理员权限才能控制）
 │   │   └─ 标记 Source = "ADMIN_INPUT"，继续 Q3（严重性降级）
 │   │
 │   ├─ 内部服务调用（gRPC/消息队列/内部 HTTP）
 │   │   └─ 标记 Source = "INTERNAL_SERVICE"，继续 Q3（需确认上游是否可控）
 │   │
 │   ├─ 环境变量 / 硬编码常量 / 配置文件
 │   │   └─ ⚪ 信息（技术债记录，非漏洞）
 │   │
 │   └─ 无法确定
 │       └─ ⚠️ 标记为「需人工确认」，列出需要追踪的调用链
 │
 ├─ Q3: 数据进入 SQL 的方式（Sink 分类）？
 │   │
 │   ├─ A. 作为参数绑定值
 │   │   └─ replacements / bind / $1 / ? / :name → ✅ 安全（参数化查询）
 │   │
 │   ├─ B. 进入 ORM 安全 API 的值位置
 │   │   └─ where: { col: value } / .eq() / .filter() → ✅ 通常安全
 │   │   └─ ⚠️ 但需检查 ORM 版本是否有已知 CVE（对照框架模块 CVE 清单）
 │   │
 │   ├─ C. 进入 SQL 语法结构（字符串拼接/模板插值）
 │   │   │
 │   │   ├─ C1. 进入 WHERE / HAVING 条件
 │   │   │   └─ 继续 Q4（净化检查）
 │   │   │
 │   │   ├─ C2. 进入 ORDER BY / GROUP BY
 │   │   │   └─ 继续 Q4（注意：escape 对标识符无效）
 │   │   │
 │   │   ├─ C3. 进入子查询 / UNION
 │   │   │   └─ 继续 Q4（最高危场景之一）
 │   │   │
 │   │   ├─ C4. 进入 INSERT VALUES / UPDATE SET
 │   │   │   └─ 继续 Q4
 │   │   │
 │   │   └─ C5. 进入函数参数 (literal/fn/raw)
 │   │       └─ 继续 Q4
 │   │
 │   ├─ D. 进入标识符位置
 │   │   │
 │   │   ├─ D1. 列名 / 表名
 │   │   │   ├─ 有白名单校验 → ✅ 安全
 │   │   │   └─ 无白名单 → 🔴 确认漏洞（escape 对标识符无效）
 │   │   │
 │   │   └─ D2. 排序方向 (ASC/DESC)
 │   │       ├─ 白名单 ['ASC','DESC'] → ✅ 安全
 │   │       └─ 无校验 → 🟡 中危
 │   │
 │   ├─ E. 进入 LIKE 模式
 │   │   ├─ 用户值作为绑定参数 + 通配符服务端固定 → ✅ 安全
 │   │   ├─ 用户值绑定但未转义 %_\ → 🔵 低危（通配符注入/DoS）
 │   │   └─ 用户值直接拼入 LIKE 字符串 → 🟡 中危
 │   │
 │   └─ F. 进入 LIMIT / OFFSET
 │       ├─ 参数绑定或 parseInt → ✅ 安全
 │       └─ 直接拼接 → 🔵 低危（数值型但仍应参数化）
 │
 └─ Q4: Source → Sink 路径上是否存在有效净化（Sanitizer）？
     │
     ├─ 白名单枚举比对（allowedFields.includes(input)）
     │   └─ ✅ 有效净化 → 安全
     │
     ├─ parseInt() / Number() / parseFloat()（且场景为纯数字）
     │   └─ ✅ 有效净化 → 安全
     │
     ├─ 类型系统约束（TypeScript enum / Java enum / Go iota）
     │   └─ ✅ 有效净化 → 安全（前提：枚举值不来自外部）
     │
     ├─ 正则替换（如 /[^a-zA-Z0-9_]/g）
     │   └─ ⚠️ 需检查正则完备性：
     │       - 是否覆盖所有 SQL 元字符？
     │       - 是否考虑 Unicode 绕过？
     │       - 是否为 deny-list（不推荐）还是 allow-list（推荐）？
     │
     ├─ escape 函数（mysql_escape_string / sequelize.escape / pg.escapeLiteral）
     │   └─ ⚠️ 仅对 SQL 值部分有效，对标识符（列名/表名）无效
     │
     ├─ ORM 提供的引用函数（quoteIdentifier / escapeId）
     │   └─ ⚠️ 对标识符部分有效，但需确认没有已知绕过
     │
     └─ 无任何净化
         └─ 🔴 确认漏洞（结合 Sink 类型和 Source 类型评定最终等级）
```

---

## 3. 通用跨技术栈模式（回退模式库）

当项目使用的框架不在已有框架模块中时，使用以下通用正则作为 Phase 1 的搜索模式：

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `GEN-SQL-TMPL` | `` `\s*(SELECT\|INSERT\|UPDATE\|DELETE\|ALTER\|DROP\|CREATE\|TRUNCATE) `` | 高 | 模板字符串含 SQL 关键字 |
| `GEN-SQL-CONCAT` | `(SELECT\|INSERT\|UPDATE\|DELETE).*["']\s*\+` | 高 | 字符串拼接含 SQL 关键字 |
| `GEN-SQL-FSTR` | `f["'](SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | f-string 含 SQL 关键字（Python） |
| `GEN-SQL-FORMAT` | `(SELECT\|INSERT\|UPDATE\|DELETE).*\.format\(` | 高 | str.format() 含 SQL 关键字 |
| `GEN-SQL-SPRINTF` | `(Sprintf\|sprintf\|fmt\.Sprintf)\s*\(\s*["'](SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | sprintf 系列含 SQL 关键字 |
| `GEN-SQL-PERCENT` | `(SELECT\|INSERT\|UPDATE\|DELETE).*%[^s]` | 中 | % 格式化（非 %s 占位）含 SQL |
| `GEN-ORDERBY-DYN` | `ORDER\s+BY\s*.*\$\{` | 高 | 动态 ORDER BY（模板字符串） |
| `GEN-ORDERBY-CONCAT` | `ORDER\s+BY\s+['"]?\s*\+` | 高 | 动态 ORDER BY（字符串拼接） |
| `GEN-LIKE-DYN` | `LIKE\s*.*(\$\{\|%s\|%v\|\+)` | 中 | LIKE 含动态值 |
| `GEN-IN-JOIN` | `IN\s*\(\s*.*\.join\s*\(` | 中 | IN 子句通过数组 join |
| `GEN-IN-FORMAT` | `IN\s*\(\s*.*(%s\|%v\|\$\{)` | 中 | IN 子句通过格式化 |
| `GEN-TABLE-DYN` | `(FROM\|JOIN\|INTO\|UPDATE)\s+.*(\$\{\|%s\|\+\s*[a-zA-Z])` | 高 | 动态表名 |
| `GEN-LIMIT-DYN` | `(LIMIT\|OFFSET)\s+(\$\{\|%s\|%v\|\+)` | 低 | 动态 LIMIT/OFFSET |
| `GEN-EXEC-CALL` | `\.(execute\|exec\|query\|raw)\s*\(` | 信息 | 通用原生查询入口（需进一步分析） |

---

## 4. 二阶注入检测方法

二阶 SQL 注入的核心特征：**注入点（写入）与触发点（查询）在时间和代码空间上分离**。

### 4.1 检测步骤

```
步骤 1: 标记存储点（Sink → DB）
  搜索所有 INSERT/UPDATE 操作，识别其中包含用户输入的字段。
  记录：{表名, 字段名, Source 类型, 写入位置}

步骤 2: 标记读取点（DB → Source → SQL Sink）
  搜索所有从步骤 1 标记的 {表名.字段名} 读取后，
  被用于构建 SQL 语句的位置（非参数化方式）。
  记录：{读取位置, 使用方式, 目标 SQL 结构}

步骤 3: 链路验证
  对每个 {写入位置 → 存储 → 读取位置 → SQL Sink} 链路：
  ├─ 写入时是否经过净化/转义？
  │   ├─ 是 → 但净化可能被数据库解码还原（如 HTML 实体存入后原样取出）
  │   └─ 否 → 恶意载荷原样存入
  ├─ 读取后是否使用参数化？
  │   ├─ 是 → ✅ 安全
  │   └─ 否 → 🔴 二阶注入确认
  └─ 存储到触发的时间跨度？
      └─ 跨度越大越难发现，应标注为高优审查项
```

### 4.2 高危场景清单

| 存储操作 | 触发操作 | 典型案例 |
|---|---|---|
| 用户注册/更新个人资料 | 后台管理报表 / 搜索 / 导出 | 用户名含 SQL 载荷，管理员查看用户列表时拼接 |
| 评论/帖子发布 | 全文搜索 / 内容聚合 | 评论内容含载荷，搜索功能 LIKE 拼接 |
| 文件名/标签上传 | 文件管理/标签统计 | 文件名含载荷，统计查询拼接文件名 |
| API 参数存入日志表 | 日志分析/审计查询 | 请求参数含载荷，日志查询拼接 |
| 配置项（管理员设置） | 定时任务 / 报表生成 | 配置值含载荷，定时任务读取后拼接 SQL |
| Webhook URL / 回调地址 | URL 解析后拼入查询 | URL 路径参数含载荷 |

### 4.3 搜索策略

```
# 步骤 1：搜索写入操作中可能包含用户输入的字段
grep -rn "INSERT INTO\|\.create(\|\.bulkCreate(\|\.insert(\|\.save(" --include="*.{ts,js,py,java,go,php,rb}"
grep -rn "UPDATE.*SET\|\.update(\|\.updateMany(" --include="*.{ts,js,py,java,go,php,rb}"

# 步骤 2：搜索同表字段被读取后用于构建 SQL 的位置
# 需要根据步骤 1 的结果，针对性搜索
# 重点关注：报表、搜索、导出、聚合、定时任务相关代码
```

---

## 5. 严重性矩阵

### 5.1 基础矩阵

| Source × Sink | 无净化 | 部分净化（不充分） | 有效净化 |
|---|---|---|---|
| **HTTP 直接输入 → SQL 值位置（WHERE/HAVING/INSERT/UPDATE）** | 🔴 高危 | 🟡 中危 | ✅ 安全 |
| **HTTP 直接输入 → SQL 标识符（列名/表名）** | 🔴 高危 | 🔴 高危（escape 无效） | ✅ 白名单=安全 |
| **HTTP 直接输入 → ORDER BY 字段** | 🔴 高危 | 🟡 中危 | ✅ 白名单=安全 |
| **HTTP 直接输入 → LIKE 模式** | 🟡 中危 | 🔵 低危 | ✅ 安全 |
| **HTTP 直接输入 → LIMIT / OFFSET** | 🔵 低危 | ⚪ 信息 | ✅ 安全 |
| **HTTP 直接输入 → 子查询 / UNION** | 🔴 高危 | 🔴 高危 | ✅ 参数化=安全 |
| **HTTP 间接输入 → SQL 结构** | 🔴 高危 | 🟡 中危 | ✅ 安全 |
| **管理后台输入 → SQL 结构** | 🟡 中危 | 🔵 低危 | ⚪ 信息 |
| **内部服务输入 → SQL 结构** | 🟡 中危 | 🔵 低危 | ⚪ 信息 |
| **二阶（DB 存储值）→ SQL 结构** | 🔴 高危 | 🟡 中危 | ⚪ 信息 |
| **环境变量/常量 → SQL 结构** | ⚪ 信息 | — | — |

### 5.2 数据库修正因子

基础等级确定后，根据数据库引擎特性调整（详见 `database/*.md`）：

| 条件 | 修正 |
|---|---|
| 目标 DB 支持 stacked queries（MSSQL 默认支持）| 上调一级 |
| 目标 DB 可通过注入执行系统命令（xp_cmdshell / COPY TO PROGRAM）| 上调至 🔴 高危 |
| 目标 DB 支持文件读写（LOAD_FILE / INTO OUTFILE / ATTACH DATABASE）| 上调一级 |
| 注入点位于预编译语句但使用了不安全的 API（如 $queryRawUnsafe）| 不变（API 本身已绕过参数化）|
| 应用使用了最低权限数据库账户（只读/限定表）| 下调一级（影响范围受限）|
| 存在 WAF / SQL 防火墙 | 不下调（WAF 可绕过，不改变漏洞本身等级）|

### 5.3 CVSS 3.1 评分参考

| 等级 | CVSS 范围 | 典型场景 |
|---|---|---|
| 🔴 高危 | 8.0 - 10.0 | 未认证攻击者可通过 HTTP 参数注入任意 SQL；可导致数据库完全泄露或 RCE |
| 🟡 中危 | 5.0 - 7.9 | 需认证/管理权限才可触发；或注入点受部分净化限制；或仅影响 LIKE/LIMIT |
| 🔵 低危 | 2.0 - 4.9 | 通配符注入导致信息泄露/DoS；数值型 LIMIT 拼接 |
| ⚪ 信息 | 0.0 - 1.9 | 技术债（raw SQL 用了常量但未参数化）；迁移文件中的拼接 |

---

## 6. 误报识别指南

### 6.1 常见误报场景

| 场景 | 为什么通常安全 | 仍需确认 |
|------|---------------|----------|
| ORM 链式调用 `.where({ col: value })` | ORM 自动参数化 | ORM 版本是否有已知 CVE |
| 参数化查询但用模板字符串包裹静态 SQL | 插值的是结构而非数据 | 确认 `${}` 内确实是常量 |
| Migration / Seed 文件中的 raw SQL | 运行一次且无用户输入 | 确认不在生产运行 |
| 测试文件中的 SQL 拼接 | 测试数据受控 | 确认不在生产代码路径 |
| SQL 模板文件（`.sql`）中的占位符 | 框架会替换为参数化 | 确认调用方使用参数化替换 |
| 日志/注释中的 SQL 示例 | 不会执行 | 确认不在可达代码路径 |
| `Prisma.$queryRaw` + `` Prisma.sql`...` `` 标签模板 | Prisma 标签模板自动参数化 | 确认使用的是 `Prisma.sql` 标签而非普通模板 |
| MyBatis `#{}` 占位符 | 预编译参数 | 确认不是 `${}` |

### 6.2 需要额外警惕的"看起来安全"场景

| 场景 | 风险 |
|---|---|
| `escape()` 函数处理后拼入标识符位置 | escape 对标识符无效 |
| 前端做了输入校验但后端未校验 | 前端校验可绕过 |
| TypeScript 类型标注为 `number` 但运行时传入 `string` | TS 类型仅编译时检查 |
| GraphQL 参数经过 schema 类型校验 | schema 校验 `String` 类型仍可含 SQL 载荷 |
| Request DTO 使用了 `class-validator` | 需确认具体装饰器是否限制 SQL 元字符 |

---

## 7. 合规与安全边界

### 7.1 审计行为约束

- **禁止**对任何 URL 发起实际 HTTP 请求或注入测试
- **禁止**在审计报告中包含可直接利用的完整 exploit payload
- **禁止**修改任何项目文件（仅读取和搜索）
- 攻击向量描述应足够说明风险但不构成武器化 payload

### 7.2 报告标注要求

- 所有发现必须标注 **CWE-89**（Improper Neutralization of Special Elements used in an SQL Command）
- 二阶注入同时标注 **CWE-89** + **CWE-564**（SQL Injection: Hibernate）或对应框架的 CWE
- LIKE 通配符注入标注 **CWE-943**（Improper Neutralization of Special Elements in Data Query Logic）
- 动态标识符注入标注 **CWE-89** + 备注「标识符注入」

### 7.3 容量管理

- 若候选清单超过 50 个命中点，先输出统计概览再按风险等级从高到低逐个分析
- 若项目超过 10 万行代码，建议分模块审计并在报告中标注审计覆盖率
- 对于无法确定的情况，一律标记「⚠️ 需人工确认」并说明原因

---

## 8. 报告输出格式

### 8.1 总览模板

```markdown
## SQL 注入审计报告

### 技术画像
- **语言**：{language}
- **框架**：{framework}
- **ORM/查询层**：{orm}
- **数据库**：{database}
- **已加载知识模块**：{loaded_modules}

### 统计
- 扫描文件数：{n}
- 候选命中数：{n}
- 确认漏洞数：🔴 {n} / 🟡 {n} / 🔵 {n}
- 信息/技术债：{n}
- 需人工确认：{n}
- 已知 CVE 命中：{n}
```

### 8.2 发现明细模板

```markdown
### [🔴 高危] {发现标题}

- **CWE**：CWE-89
- **模式**：`{PATTERN_ID}`（来自 {framework} 模式库）
- **位置**：`{file_path}:{line_number}`
- **Source**：`{source_expression}`（{source_type}）
- **Sink**：`{sink_expression}`
- **Sink 类型**：{WHERE/ORDER BY/LIKE/标识符/...}
- **净化**：{无 / 部分（描述）/ 有效}
- **调用链**：
  1. `{caller_file}:{line}` → `{function}()`
  2. `{service_file}:{line}` → `{method}()`
  3. `{sink_file}:{line}` → SQL 执行
- **攻击向量**：{描述攻击路径，不含实际 payload}
- **影响**：{数据泄露/数据篡改/RCE/...}
- **数据库修正**：{是否因数据库特性上调等级}
- **修复建议**：{具体方案}
- **修复代码**：{参考框架模块中的修复模板}
```

### 8.3 二阶注入发现模板

```markdown
### [🔴 高危] 二阶注入：{描述}

- **CWE**：CWE-89 + CWE-564
- **注入点（写入）**：`{write_file}:{line}` — {INSERT/UPDATE 描述}
- **存储位置**：表 `{table}` 字段 `{column}`
- **触发点（读取+执行）**：`{read_file}:{line}` — {SQL 构建描述}
- **时间跨度**：{实时/延迟/定时任务}
- **攻击向量**：{描述存储→触发的完整链路}
- **修复建议**：{读取点使用参数化 / 写入点增加净化}
```
