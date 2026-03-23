# Prisma — SQL 注入模式库

---

## 1. 模式库（Pattern Library）

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `PRISMA-UNSAFE-RAW` | `\$queryRawUnsafe\s*\(` | 高 | 明确标记为 Unsafe 的原生查询 |
| `PRISMA-EXEC-UNSAFE` | `\$executeRawUnsafe\s*\(` | 高 | 明确标记为 Unsafe 的原生执行 |
| `PRISMA-RAW-CONCAT` | `\$(queryRaw\|executeRaw)\s*\(\s*[^`].*\+` | 高 | 原生查询使用字符串拼接 |
| `PRISMA-RAW-NONTAG` | `` \$(queryRaw\|executeRaw)\s*\(\s*` `` | 中 | 原生查询使用模板字符串（需确认是否为 Prisma.sql 标签） |
| `PRISMA-RAW-VAR` | `\$(queryRaw\|executeRaw)\s*\(\s*[a-zA-Z_]\w*\s*[,\)]` | 中 | 原生查询传入变量（需追踪来源） |

---

## 2. 安全 vs 危险 API 对照

### 2.1 核心原则：Prisma.sql 标签模板 vs 普通字符串

```typescript
import { Prisma } from '@prisma/client';

// ✅ 安全：Prisma.sql 标签模板 — 自动参数化
const users = await prisma.$queryRaw(
  Prisma.sql`SELECT * FROM users WHERE name = ${name}`
);
// Prisma 会将 ${name} 转为 $1 占位符

// ✅ 安全：$queryRaw + 直接模板字符串（Prisma 5+ 自动识别为标签模板）
const users = await prisma.$queryRaw`SELECT * FROM users WHERE name = ${name}`;

// 🔴 危险：$queryRawUnsafe — 不做任何参数化
const users = await prisma.$queryRawUnsafe(
  `SELECT * FROM users WHERE name = '${name}'`
);

// 🔴 危险：先构建字符串再传入 $queryRawUnsafe
const sql = `SELECT * FROM users WHERE name = '${name}'`;
const users = await prisma.$queryRawUnsafe(sql);

// 🔴 危险：字符串拼接 + $queryRawUnsafe
const users = await prisma.$queryRawUnsafe(
  "SELECT * FROM users WHERE name = '" + name + "'"
);
```

### 2.2 $executeRaw 系列

```typescript
// ✅ 安全：标签模板
await prisma.$executeRaw`UPDATE users SET name = ${newName} WHERE id = ${id}`;

// 🔴 危险：Unsafe 版本
await prisma.$executeRawUnsafe(`UPDATE users SET name = '${newName}' WHERE id = ${id}`);
```

### 2.3 Prisma ORM 方法（通常安全）

```typescript
// ✅ 安全：Prisma Client 方法自动参数化
await prisma.user.findMany({ where: { name: userInput } });
await prisma.user.findFirst({ where: { email: { contains: userInput } } });
await prisma.user.create({ data: { name: userInput } });
await prisma.user.update({ where: { id }, data: { name: userInput } });

// ⚠️ 注意：contains/startsWith/endsWith 不转义通配符 %_
// 但在 Prisma 中这不是 SQL 注入，而是逻辑层通配符问题
```

---

## 3. 已知 CVE

Prisma 的安全模型相对较好（Unsafe API 命名明确），但需关注：

| 问题 | 版本 | 要点 |
|------|------|------|
| `$queryRawUnsafe` 误用 | 所有版本 | API 名称中的 "Unsafe" 是唯一提示；新手可能忽略 |
| 标签模板识别 | < 5.0 | 旧版本中 `$queryRaw(sql)` 如果 sql 是普通字符串变量则不会参数化 |

---

## 4. 修复模板

### 4.1 Unsafe → 标签模板

```typescript
// ❌ 修复前
const result = await prisma.$queryRawUnsafe(
  `SELECT * FROM users WHERE email = '${email}'`
);

// ✅ 修复后
const result = await prisma.$queryRaw(
  Prisma.sql`SELECT * FROM users WHERE email = ${email}`
);
```

### 4.2 动态 ORDER BY

```typescript
// ❌ 修复前
const result = await prisma.$queryRawUnsafe(
  `SELECT * FROM users ORDER BY ${sortField} ${sortOrder}`
);

// ✅ 修复后（使用 Prisma Client + 白名单）
const ALLOWED_SORT: Record<string, Prisma.UserOrderByWithRelationInput> = {
  name: { name: 'asc' },
  email: { email: 'asc' },
  createdAt: { createdAt: 'desc' },
};
const orderBy = ALLOWED_SORT[sortField] ?? { createdAt: 'desc' };
const result = await prisma.user.findMany({ orderBy });
```

### 4.3 动态 WHERE 条件

```typescript
// ❌ 修复前
let sql = "SELECT * FROM users WHERE 1=1";
if (name) sql += ` AND name = '${name}'`;
if (email) sql += ` AND email = '${email}'`;
const result = await prisma.$queryRawUnsafe(sql);

// ✅ 修复后（使用 Prisma Client 动态条件）
const where: Prisma.UserWhereInput = {};
if (name) where.name = name;
if (email) where.email = email;
const result = await prisma.user.findMany({ where });
```

### 4.4 IN 子句

```typescript
// ❌ 修复前
const result = await prisma.$queryRawUnsafe(
  `SELECT * FROM users WHERE id IN (${ids.join(',')})`
);

// ✅ 修复后
const result = await prisma.$queryRaw(
  Prisma.sql`SELECT * FROM users WHERE id IN (${Prisma.join(ids)})`
);
```
