# TypeORM — SQL 注入模式库

---

## 1. 模式库（Pattern Library）

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `TORM-QB-WHERE-CONCAT` | `\.where\s*\(\s*[`'"].*\+` | 高 | QueryBuilder `.where()` 使用字符串拼接 |
| `TORM-QB-WHERE-TMPL` | `` \.where\s*\(\s*` `` | 高 | QueryBuilder `.where()` 使用模板字符串 |
| `TORM-RAW-QUERY` | `(getRepository\|manager\|dataSource\|connection).*\.query\s*\(` | 中 | 原生查询入口（需检查参数化） |
| `TORM-ORDER-DYNAMIC` | `\.addOrderBy\s*\(\s*[a-zA-Z_]` | 高 | 动态 ORDER BY 列名 |
| `TORM-ORDER-STR` | `\.orderBy\s*\(\s*[`'"].*\$\{` | 高 | orderBy 模板字符串 |
| `TORM-SELECT-DYNAMIC` | `\.addSelect\s*\(\s*[a-zA-Z_]` | 中 | 动态 SELECT 列 |
| `TORM-HAVING-DYN` | `\.having\s*\(\s*[`'"].*(\+\|\$\{)` | 高 | 动态 HAVING |
| `TORM-NESTED-JSON` | `\.save\s*\(\s*\{.*\[` | 中 | CVE-2025-60542 相关：嵌套 JSON 对象 |
| `TORM-RAW-EXPR` | `Raw\s*\(\s*[`'"].*(\+\|\$\{)` | 高 | `Raw()` 表达式拼接 |
| `TORM-FIND-WHERE-STR` | `\.find\s*\(\s*\{.*where:.*Brackets` | 中 | Brackets 中可能含拼接 |

---

## 2. 安全 vs 危险 API 对照

### 2.1 QueryBuilder

```typescript
// 🔴 危险：字符串拼接
queryBuilder
  .where(`user.name = '${name}'`)
  .orderBy(`user.${sortField}`, 'ASC');

// ✅ 安全：参数绑定
queryBuilder
  .where("user.name = :name", { name })
  .orderBy("user.created_at", "ASC");
```

### 2.2 原生查询

```typescript
// 🔴 危险：无参数化
await dataSource.query(`SELECT * FROM users WHERE id = ${id}`);

// ✅ 安全：参数化
await dataSource.query("SELECT * FROM users WHERE id = $1", [id]);
```

### 2.3 Find 方法

```typescript
// ✅ 安全：ORM 对象条件
await userRepo.find({ where: { name: userInput } });

// 🔴 危险：Raw 表达式
await userRepo.find({
  where: { name: Raw(`= '${userInput}'`) }
});

// ✅ 安全：Raw + 参数化
await userRepo.find({
  where: { name: Raw(alias => `${alias} = :name`, { name: userInput }) }
});
```

---

## 3. 已知 CVE

| CVE | 受影响版本 | 漏洞类型 | 要点 | CVSS |
|-----|-----------|----------|------|------|
| CVE-2025-60542 | < 0.3.26 | 嵌套 JSON 对象绕过 | `stringifyObjects: false` 导致 `.save()` / `.update()` 字段级限制被绕过，攻击者可通过嵌套 JSON 对象注入 SQL | 7.5 |

---

## 4. 修复模板

### 4.1 QueryBuilder 参数化

```typescript
// ❌ 修复前
const users = await dataSource
  .getRepository(User)
  .createQueryBuilder("user")
  .where(`user.name LIKE '%${search}%'`)
  .orderBy(`user.${sortField}`, sortOrder)
  .getMany();

// ✅ 修复后
const ALLOWED_SORT = ['name', 'email', 'createdAt'] as const;
const ALLOWED_ORDER = ['ASC', 'DESC'] as const;

const safeSort = ALLOWED_SORT.includes(sortField as any) ? sortField : 'createdAt';
const safeOrder = ALLOWED_ORDER.includes(sortOrder?.toUpperCase() as any) ? sortOrder.toUpperCase() : 'ASC';

const users = await dataSource
  .getRepository(User)
  .createQueryBuilder("user")
  .where("user.name LIKE :search", { search: `%${search}%` })
  .orderBy(`user.${safeSort}`, safeOrder as 'ASC' | 'DESC')
  .getMany();
```

### 4.2 原生查询参数化

```typescript
// ❌ 修复前
const result = await dataSource.query(
  `SELECT * FROM users WHERE email = '${email}' LIMIT ${limit}`
);

// ✅ 修复后
const result = await dataSource.query(
  "SELECT * FROM users WHERE email = $1 LIMIT $2",
  [email, parseInt(String(limit), 10) || 10]
);
```
