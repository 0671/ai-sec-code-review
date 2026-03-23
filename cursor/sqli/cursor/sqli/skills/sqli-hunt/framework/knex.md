# Knex.js — SQL 注入模式库

---

## 1. 模式库（Pattern Library）

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `KNEX-RAW-TMPL` | `` (knex\|db)\.raw\s*\(\s*` `` | 高 | `knex.raw()` 使用模板字符串 |
| `KNEX-RAW-CONCAT` | `(knex\|db)\.raw\s*\(\s*[^`].*\+` | 高 | `knex.raw()` 使用字符串拼接 |
| `KNEX-WHERE-RAW-TMPL` | `` \.whereRaw\s*\(\s*` `` | 高 | `.whereRaw()` 使用模板字符串 |
| `KNEX-WHERE-RAW-CONCAT` | `\.whereRaw\s*\(\s*[^`].*\+` | 高 | `.whereRaw()` 使用字符串拼接 |
| `KNEX-ORDER-RAW` | `\.orderByRaw\s*\(` | 中 | `.orderByRaw()` 需检查参数化 |
| `KNEX-HAVING-RAW` | `\.havingRaw\s*\(` | 中 | `.havingRaw()` 需检查参数化 |
| `KNEX-JOIN-RAW` | `\.joinRaw\s*\(` | 中 | `.joinRaw()` 需检查参数化 |
| `KNEX-SELECT-RAW` | `\.selectRaw\s*\(` | 中 | `.selectRaw()` 需检查参数化 |
| `KNEX-GROUP-RAW` | `\.groupByRaw\s*\(` | 中 | `.groupByRaw()` 需检查参数化 |
| `KNEX-COLUMN-DYN` | `\.column\s*\(\s*[a-zA-Z_]` | 中 | 动态列名 |
| `KNEX-TABLE-DYN` | `knex\s*\(\s*[a-zA-Z_]\w*\s*\)` | 中 | 动态表名（knex 函数的第一个参数） |

---

## 2. 安全 vs 危险 API 对照

### 2.1 knex.raw()

```typescript
// 🔴 危险：模板字符串插值
const rows = await knex.raw(`SELECT * FROM users WHERE name = '${name}'`);

// 🔴 危险：字符串拼接
const rows = await knex.raw("SELECT * FROM users WHERE name = '" + name + "'");

// ✅ 安全：绑定参数（位置参数 ?）
const rows = await knex.raw("SELECT * FROM users WHERE name = ?", [name]);

// ✅ 安全：绑定参数（命名参数 :name）
const rows = await knex.raw("SELECT * FROM users WHERE name = :name", { name });
```

### 2.2 链式查询（通常安全）

```typescript
// ✅ 安全：Knex 链式 API 自动参数化
const rows = await knex('users').where({ name: userInput }).select('*');
const rows = await knex('users').where('name', '=', userInput);
const rows = await knex('users').where('name', 'like', `%${userInput}%`);
// ⚠️ 注意：LIKE 中 % 未转义，可能存在通配符注入
```

### 2.3 *Raw 方法

```typescript
// 🔴 危险：无参数化的 whereRaw
await knex('users').whereRaw(`name = '${name}'`);

// ✅ 安全：whereRaw + 绑定
await knex('users').whereRaw("name = ?", [name]);
await knex('users').whereRaw("name = :name", { name });

// 同理适用于 orderByRaw / havingRaw / joinRaw 等
```

### 2.4 动态表名和列名

```typescript
// ⚠️ 需警惕：knex() 的第一个参数为表名
const rows = await knex(tableName).select('*');
// 若 tableName 来自用户输入，需白名单校验

// ⚠️ 需警惕：.column() / .select() 中的动态列名
const rows = await knex('users').select(columns);
// 若 columns 来自用户输入，需白名单校验
```

---

## 3. 已知 CVE

| 问题 | 要点 |
|------|------|
| knex.raw 误用 | 与 ORM 安全方法混用时容易被忽略 |
| 对象原型污染 | 若使用旧版本 Knex，需检查原型污染漏洞 |

---

## 4. 修复模板

### 4.1 raw → 绑定参数

```typescript
// ❌ 修复前
const result = await knex.raw(
  `SELECT * FROM ${table} WHERE status = '${status}' ORDER BY ${sortField}`
);

// ✅ 修复后
const ALLOWED_TABLES = ['users', 'posts', 'comments'];
const ALLOWED_SORT = ['created_at', 'name', 'id'];

const safeTable = ALLOWED_TABLES.includes(table) ? table : 'users';
const safeSort = ALLOWED_SORT.includes(sortField) ? sortField : 'created_at';

const result = await knex.raw(
  `SELECT * FROM ${safeTable} WHERE status = ? ORDER BY ${safeSort}`,
  [status]
);
```

### 4.2 whereRaw → where 链式

```typescript
// ❌ 修复前
await knex('users').whereRaw(`age > ${minAge} AND age < ${maxAge}`);

// ✅ 修复后
await knex('users')
  .where('age', '>', minAge)
  .andWhere('age', '<', maxAge);
```

### 4.3 orderByRaw → orderBy

```typescript
// ❌ 修复前
await knex('users').orderByRaw(`${sortField} ${sortOrder}`);

// ✅ 修复后
const ALLOWED_SORT = { name: 'name', date: 'created_at', email: 'email' };
const ALLOWED_ORDER = ['asc', 'desc'];

const column = ALLOWED_SORT[sortField] || 'created_at';
const order = ALLOWED_ORDER.includes(sortOrder?.toLowerCase()) ? sortOrder : 'asc';

await knex('users').orderBy(column, order);
```
