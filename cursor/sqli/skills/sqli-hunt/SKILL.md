---
name: sqli-hunt
description: >
  SQL 注入漏洞狩猎知识库。当用户要求进行 SQL 注入审计、检查数据库查询安全性、
  review raw SQL 代码、或使用 /sqli-audit 命令时激活。提供多技术栈的危险模式库、
  污点分析判定树、严重性矩阵和修复模板。
metadata:
  author: security-team
  version: "1.0"
  tags: security, sql-injection, code-review, audit
---

# SQL 注入漏洞狩猎 Skill

## 1. 模式库（Pattern Library）

以下模式按技术栈分组。每个模式包含：ID、grep 正则、危险等级、说明。
审计时根据项目使用的技术栈选取对应分组。

---

### 1.1 Sequelize

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `SEQ-RAW-TMPL` | `` sequelize\.query\s*\(\s*` `` | 高 | `sequelize.query()` 使用模板字符串，可能存在插值拼接 |
| `SEQ-RAW-CONCAT` | `sequelize\.query\s*\(\s*[^`].*\+` | 高 | `sequelize.query()` 使用字符串拼接 |
| `SEQ-LITERAL-TMPL` | `` (Sequelize\.literal\|literal)\s*\(\s*` `` | 高 | `Sequelize.literal()` 内使用模板字符串 |
| `SEQ-LITERAL-CONCAT` | `(Sequelize\.literal\|literal)\s*\(\s*[^`].*\+` | 高 | `Sequelize.literal()` 内使用字符串拼接 |
| `SEQ-LITERAL-VAR` | `(Sequelize\.literal\|literal)\s*\(\s*[a-zA-Z_]\w*\s*\)` | 中 | `Sequelize.literal()` 传入变量（需追踪来源） |
| `SEQ-FN-DYNAMIC` | `Sequelize\.fn\s*\(.*\$\{` | 中 | `Sequelize.fn()` 中含动态插值 |
| `SEQ-WHERE-RAW` | `Sequelize\.where\s*\(.*\+` | 中 | `Sequelize.where()` 中使用拼接 |
| `SEQ-COL-DYNAMIC` | `Sequelize\.col\s*\(\s*[a-zA-Z_]` | 中 | `Sequelize.col()` 传入变量（动态列名） |
| `SEQ-JSON-PATH` | `\$\w+\.\.\$` | 中 | JSON 路径表达式中可能存在 CVE-2026-30951 风险 |
| `SEQ-QUERY-NO-BIND` | `sequelize\.query\s*\([^,]+\)\s*;` | 低 | `sequelize.query()` 调用缺少第二个参数（无 replacements/bind） |

### 1.2 TypeORM

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `TORM-QB-WHERE-CONCAT` | `\.where\s*\(\s*[`'"].*\+` | 高 | QueryBuilder `.where()` 使用字符串拼接 |
| `TORM-QB-WHERE-TMPL` | `` \.where\s*\(\s*` `` | 高 | QueryBuilder `.where()` 使用模板字符串 |
| `TORM-RAW-QUERY` | `(getRepository\|manager\|dataSource\|connection).*\.query\s*\(` | 中 | 原生查询入口（需检查参数化） |
| `TORM-ORDER-DYNAMIC` | `\.addOrderBy\s*\(\s*[a-zA-Z_]` | 高 | 动态 ORDER BY 列名 |
| `TORM-SELECT-DYNAMIC` | `\.addSelect\s*\(\s*[a-zA-Z_]` | 中 | 动态 SELECT 列 |
| `TORM-NESTED-JSON` | `\.save\s*\(\s*\{.*\[` | 中 | CVE-2025-60542 相关：嵌套 JSON 对象 |

### 1.3 Knex

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `KNEX-RAW-TMPL` | `` (knex\|db)\.raw\s*\(\s*` `` | 高 | `knex.raw()` 使用模板字符串 |
| `KNEX-RAW-CONCAT` | `(knex\|db)\.raw\s*\(\s*[^`].*\+` | 高 | `knex.raw()` 使用字符串拼接 |
| `KNEX-WHERE-RAW` | `\.whereRaw\s*\(` | 中 | `.whereRaw()` 调用（需检查参数化） |
| `KNEX-ORDER-RAW` | `\.orderByRaw\s*\(` | 中 | `.orderByRaw()` 动态排序 |
| `KNEX-HAVING-RAW` | `\.havingRaw\s*\(` | 中 | `.havingRaw()` 动态分组条件 |
| `KNEX-JOIN-RAW` | `\.joinRaw\s*\(` | 中 | `.joinRaw()` 动态 JOIN |

### 1.4 Prisma

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `PRISMA-UNSAFE-RAW` | `\$queryRawUnsafe\s*\(` | 高 | 明确标记为 Unsafe 的原生查询 |
| `PRISMA-EXEC-UNSAFE` | `\$executeRawUnsafe\s*\(` | 高 | 明确标记为 Unsafe 的原生执行 |
| `PRISMA-RAW-TMPL` | `` \$(queryRaw\|executeRaw)\s*\(\s*` `` | 中 | 原生查询使用模板字符串（需确认是否用了 Prisma.sql 标签） |
| `PRISMA-RAW-CONCAT` | `\$(queryRaw\|executeRaw)\s*\(\s*[^`].*\+` | 高 | 原生查询使用字符串拼接 |

### 1.5 原生驱动（pg / mysql2 / sqlite3 / better-sqlite3）

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `NATIVE-QUERY-TMPL` | `` (pool\|client\|connection\|db)\.(query\|execute\|run\|all\|get\|prepare)\s*\(\s*` `` | 高 | 原生查询使用模板字符串 |
| `NATIVE-QUERY-CONCAT` | `(pool\|client\|connection\|db)\.(query\|execute\|run\|all\|get\|prepare)\s*\(\s*[^`].*\+` | 高 | 原生查询使用字符串拼接 |
| `NATIVE-QUERY-VAR` | `(pool\|client\|connection\|db)\.(query\|execute\|run\|all)\s*\(\s*[a-zA-Z_]\w*\s*[,\)]` | 中 | 原生查询传入变量（需追踪来源） |

### 1.6 通用跨技术栈模式

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `GEN-SQL-TMPL` | `` `\s*(SELECT\|INSERT\|UPDATE\|DELETE\|ALTER\|DROP\|CREATE\|TRUNCATE) `` | 高 | 模板字符串中含 SQL 关键字（不区分大小写搜索） |
| `GEN-SQL-CONCAT` | `(SELECT\|INSERT\|UPDATE\|DELETE).*["']\s*\+` | 高 | 字符串拼接含 SQL 关键字 |
| `GEN-ORDERBY-DYN` | `ORDER\s+BY\s*.*\$\{` | 高 | 动态 ORDER BY（模板字符串） |
| `GEN-ORDERBY-VAR` | `ORDER\s+BY\s+['"]?\s*\+` | 高 | 动态 ORDER BY（字符串拼接） |
| `GEN-LIKE-TMPL` | `` LIKE\s*.*\$\{ `` | 中 | LIKE 子句含插值 |
| `GEN-IN-JOIN` | `IN\s*\(\s*.*\.join\s*\(` | 中 | IN 子句通过数组 join 构建 |
| `GEN-TABLE-DYN` | `` (FROM\|JOIN\|INTO\|UPDATE)\s+.*\$\{ `` | 高 | 动态表名 |
| `GEN-LIMIT-DYN` | `` (LIMIT\|OFFSET)\s+\$\{ `` | 低 | 动态 LIMIT/OFFSET（数值型但仍应参数化） |

### 1.7 Python 生态（Django / SQLAlchemy / psycopg2）

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `PY-RAW-SQL` | `(\.raw\|\.extra\|RawSQL)\s*\(.*%s` 且无参数列表 | 高 | Django 原生查询未参数化 |
| `PY-SQLA-TEXT-FSTR` | `text\s*\(\s*f["']` | 高 | SQLAlchemy `text()` 使用 f-string |
| `PY-SQLA-EXEC-FSTR` | `(execute\|exec)\s*\(\s*f["']` | 高 | 原生执行使用 f-string |
| `PY-CURSOR-FORMAT` | `cursor\.execute\s*\(.*\.format\(` | 高 | `str.format()` 拼接 SQL |
| `PY-CURSOR-PERCENT` | `cursor\.execute\s*\(.*%\s` 且非 `%s` 占位 | 高 | `%` 字符串格式化拼接 SQL |

---

## 2. 污点判定树（Taint Decision Tree）

对于每一个模式命中点，按以下决策路径判定：

```
命中点
 │
 ├─ 数据来源是否可被用户控制？
 │   ├─ 否 → 硬编码/环境变量/常量 → ⚪ 信息（记录为技术债）
 │   └─ 是 → 继续 ↓
 │
 ├─ 数据进入 SQL 的位置？
 │   ├─ 仅作为参数绑定值（replacements / bind / $1 / ?）
 │   │   └─ ✅ 安全（参数化查询）
 │   │
 │   ├─ 进入 WHERE 条件的值部分（通过 ORM where 对象）
 │   │   └─ ✅ 通常安全（但需检查 ORM 版本是否存在已知 CVE）
 │   │
 │   ├─ 进入 SQL 语法结构（字符串拼接/模板插值到 SELECT/WHERE/ORDER BY...）
 │   │   ├─ 路径上是否存在有效净化？
 │   │   │   ├─ 白名单枚举比对 → ✅ 安全
 │   │   │   ├─ parseInt/Number() 且场景为纯数字 → ✅ 安全
 │   │   │   ├─ 正则过滤 → ⚠️ 需检查正则是否完备
 │   │   │   ├─ escape 函数 → ⚠️ 对标识符无效，对值部分可能有效
 │   │   │   └─ 无任何净化 → 🔴 确认漏洞
 │   │   └─ 无净化 → 🔴 确认漏洞
 │   │
 │   ├─ 进入标识符位置（列名/表名/排序字段）
 │   │   ├─ 有白名单校验 → ✅ 安全
 │   │   └─ 无白名单 → 🔴 确认漏洞（escape 对标识符无效）
 │   │
 │   └─ 进入 LIKE 模式
 │       ├─ 通配符 % _ 由服务端固定添加，用户值作为绑定参数 → ✅ 安全
 │       └─ 用户值直接拼入 LIKE 字符串 → 🟡 中危（信息泄露/DoS）
 │
 └─ 数据来源为数据库存储值？
     ├─ 该存储值的写入路径包含用户输入 → ⚠️ 二阶注入候选
     └─ 该存储值为系统内部生成 → ⚪ 信息
```

---

## 3. 二阶注入检测方法

二阶 SQL 注入的特征是注入点（写入）与触发点（查询）分离。检测步骤：

1. **标记存储点**：搜索所有 INSERT/UPDATE 操作中包含用户输入字段的位置。
2. **标记读取点**：搜索所有从同表读取该字段后用于构建 SQL 的位置。
3. **判定**：
   - 写入时是否经过净化/编码？（净化了写入但读取时假设安全 → 仍可能漏洞）
   - 读取后是否再次使用参数化？（是 → 安全；否 → 确认二阶）
4. **高危场景**：
   - 用户名/昵称存入 DB → 后台管理报表拼接 SQL 显示
   - 评论/帖子内容存入 DB → 搜索功能用 LIKE + 拼接
   - 配置项由管理员设置 → 后台定时任务拼接 SQL 执行

---

## 4. 严重性矩阵

| | 无净化 | 部分净化 | 有效净化 |
|---|---|---|---|
| **HTTP 直接输入 → SQL 结构** | 🔴 高危 | 🟡 中危 | ⚪ 信息 |
| **HTTP 直接输入 → 标识符** | 🔴 高危 | 🔴 高危（escape 对标识符无效） | ✅ 白名单=安全 |
| **HTTP 直接输入 → LIKE** | 🟡 中危 | 🔵 低危 | ✅ 安全 |
| **HTTP 直接输入 → LIMIT/OFFSET** | 🔵 低危 | ⚪ 信息 | ✅ 安全 |
| **管理后台输入 → SQL 结构** | 🟡 中危 | 🔵 低危 | ⚪ 信息 |
| **二阶（DB 存储值）→ SQL 结构** | 🔴 高危 | 🟡 中危 | ⚪ 信息 |
| **环境变量/常量 → SQL 结构** | ⚪ 信息 | — | — |

---

## 5. 已知 CVE 速查

审计时应检查项目依赖版本是否受以下漏洞影响：

| CVE | 库 | 受影响版本 | 漏洞类型 | 要点 |
|-----|-----|-----------|----------|------|
| CVE-2026-30951 | Sequelize | <6.37.8 | JSON path `::` 类型转换注入 | `_traverseJSON()` 未转义 `::` 后的 cast 类型 |
| CVE-2025-60542 | TypeORM | <0.3.26 | 嵌套 JSON 绕过 `.save()`/`.update()` | `stringifyObjects: false` 导致字段级限制被绕过 |
| CVE-2023-22578 | Sequelize | <6.28.1 | `replacements` 中的转义绕过 | 特定字符组合可逃逸占位符 |
| CVE-2023-25813 | Sequelize | <6.29.0 | `literal()` SQL 注入 | 通过 `literal()` 绕过 |
| CVE-2019-10748 | Sequelize | <5.15.1 | `JSON` 条件注入 | JSON 操作符处理不当 |

---

## 6. 修复模板

### 6.1 参数化替代拼接

**问题**：
```typescript
const rows = await sequelize.query(
  `SELECT * FROM users WHERE name = '${name}'`
);
```

**修复**：
```typescript
const rows = await sequelize.query(
  `SELECT * FROM users WHERE name = :name`,
  { replacements: { name }, type: QueryTypes.SELECT }
);
```

### 6.2 白名单替代动态标识符

**问题**：
```typescript
const rows = await sequelize.query(
  `SELECT * FROM users ORDER BY ${sortField} ${sortOrder}`
);
```

**修复**：
```typescript
const ALLOWED_SORT_FIELDS = ['name', 'created_at', 'email'] as const;
const ALLOWED_SORT_ORDERS = ['ASC', 'DESC'] as const;

const safeSortField = ALLOWED_SORT_FIELDS.includes(sortField)
  ? sortField : 'created_at';
const safeSortOrder = ALLOWED_SORT_ORDERS.includes(sortOrder?.toUpperCase())
  ? sortOrder.toUpperCase() : 'ASC';

const rows = await sequelize.query(
  `SELECT * FROM users ORDER BY ${safeSortField} ${safeSortOrder}`,
  { type: QueryTypes.SELECT }
);
```

### 6.3 LIKE 安全处理

**问题**：
```typescript
await sequelize.query(
  `SELECT * FROM posts WHERE title LIKE '%${keyword}%'`
);
```

**修复**：
```typescript
function escapeLike(str: string): string {
  return str.replace(/[%_\\]/g, '\\$&');
}
const rows = await sequelize.query(
  `SELECT * FROM posts WHERE title LIKE :pattern ESCAPE '\\'`,
  { replacements: { pattern: `%${escapeLike(keyword)}%` }, type: QueryTypes.SELECT }
);
```

### 6.4 IN 子句安全处理

**问题**：
```typescript
const ids = userInput.split(',');
await db.query(`SELECT * FROM items WHERE id IN (${ids.join(',')})`);
```

**修复**：
```typescript
const ids = userInput.split(',').map(Number).filter(Number.isFinite);
await db.query(
  `SELECT * FROM items WHERE id = ANY(:ids)`,
  { replacements: { ids }, type: QueryTypes.SELECT }
);
```

### 6.5 Prisma 安全原生查询

**问题**：
```typescript
const result = await prisma.$queryRawUnsafe(
  `SELECT * FROM users WHERE email = '${email}'`
);
```

**修复**：
```typescript
import { Prisma } from '@prisma/client';
const result = await prisma.$queryRaw(
  Prisma.sql`SELECT * FROM users WHERE email = ${email}`
);
```

---

## 7. 误报识别指南

以下情况通常为误报，但仍需人工确认：

| 场景 | 为什么通常安全 | 仍需确认 |
|------|---------------|----------|
| `sequelize.query()` + 模板字符串但插值仅含表名常量 | 无用户输入 | 确认变量确实不可控 |
| ORM `where: { col: value }` | ORM 自动参数化 | 检查 ORM 版本是否有已知 CVE |
| `knex('table').where({ col: value })` | Knex 链式调用自动参数化 | 确认无 `.raw()` 混入 |
| `Prisma.$queryRaw` + 标签模板 ``Prisma.sql`...` `` | Prisma 标签模板自动参数化 | 确认使用的是 `Prisma.sql` 而非普通模板 |
| Migration 文件中的 raw SQL | 运行一次且非用户输入 | 确认无动态内容 |
| Seed 文件中的硬编码 SQL | 开发数据 | 确认不在生产运行 |

---

## 8. 合规与安全边界

- **禁止**对未授权目标发起实际注入测试。
- **禁止**在审计报告中包含可直接利用的完整 exploit。
- 攻击向量描述应足够说明风险但不构成武器化 payload。
- 审计输出应标注 CWE-89（SQL Injection）以便对接漏洞管理平台。
- 二阶注入需明确标注注入点和触发点的双重位置。
```
