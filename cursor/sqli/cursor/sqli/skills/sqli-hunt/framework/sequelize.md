# Sequelize — SQL 注入模式库

---

## 1. 模式库（Pattern Library）

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
| `SEQ-ORDER-DYN` | `order:\s*\[\s*\[.*\$\{` | 信息 | 动态 ORDER BY 通过 ORM 数组构建。**注意**：Sequelize `findAll({ order })` 对字符串自动 `quoteIdentifier` + 方向白名单，通常安全；但若经 `literal()` 进入则无保护，需按 `SEQ-LITERAL-TMPL` 处理。建议添加白名单作纵深防御 |
| `SEQ-ATTR-DYN` | `attributes:\s*\[.*\$\{` | 中 | 动态 attributes 选择 |

---

## 2. 安全 vs 危险 API 对照

### 2.1 sequelize.query()

```typescript
// 🔴 危险：模板字符串插值
await sequelize.query(`SELECT * FROM users WHERE name = '${name}'`);

// 🔴 危险：字符串拼接
await sequelize.query("SELECT * FROM users WHERE name = '" + name + "'");

// ✅ 安全：replacements（命名参数）
await sequelize.query(
  "SELECT * FROM users WHERE name = :name",
  { replacements: { name }, type: QueryTypes.SELECT }
);

// ✅ 安全：replacements（位置参数）
await sequelize.query(
  "SELECT * FROM users WHERE name = ?",
  { replacements: [name], type: QueryTypes.SELECT }
);

// ✅ 安全：bind
await sequelize.query(
  "SELECT * FROM users WHERE name = $1",
  { bind: [name], type: QueryTypes.SELECT }
);
```

### 2.2 Sequelize.literal()

```typescript
// 🔴 危险：用户输入进入 literal
const result = await User.findAll({
  where: Sequelize.literal(`name = '${userInput}'`)
});

// 🔴 危险：变量传入 literal（需追踪变量来源）
const condition = buildCondition(userInput);
const result = await User.findAll({
  where: Sequelize.literal(condition)
});

// ✅ 安全：literal 内为纯常量
const result = await User.findAll({
  where: Sequelize.literal("name IS NOT NULL")
});
```

### 2.3 ORM Where 对象

```typescript
// ✅ 安全：ORM where 对象自动参数化
await User.findAll({ where: { name: userInput } });
await User.findAll({ where: { name: { [Op.like]: `%${userInput}%` } } });
// ⚠️ 注意：Op.like 的值会被参数化，但 % 通配符不会被转义
// 用户可输入 % 进行通配符注入（信息泄露级别）
```

### 2.4 动态 ORDER BY

```typescript
// ✅ 实际安全（但不推荐）：用户输入进入 findAll order 字符串数组
// Sequelize 内部 quote() 方法会：
//   1. 对列名调用 quoteIdentifier() → "userInput"（双引号包裹，内部 " 转义为 ""）
//   2. 对方向值与 validOrderOptions 白名单比对（仅允许 ASC/DESC 等 8 个值）
// 因此不构成 SQL 注入，但会暴露内部列名信息，建议仍添加白名单
await User.findAll({ order: [[userInput, 'ASC']] });
// 生成: ORDER BY "userInput" ASC — 注入尝试被引号转义

// 🔴 危险：用户输入经 literal() 进入 order — literal 绕过 quoteIdentifier
await User.findAll({ order: [[literal(`${userInput}`), 'ASC']] });
// literal() 输出直接嵌入 SQL，不做任何转义

// 🔴 危险：用户输入拼入 sequelize.query() 的 ORDER BY — 原生 SQL 无保护
await sequelize.query(`SELECT * FROM users ORDER BY ${userInput}`);
// 模板字符串直接拼接，无 quote 无 validate

// ✅ 安全（推荐）：白名单校验
const ALLOWED = ['name', 'created_at', 'email'];
const field = ALLOWED.includes(userInput) ? userInput : 'created_at';
await User.findAll({ order: [[field, 'ASC']] });
```

> **Sequelize v6 内部保护机制参考**（源码 `query-generator.js` 的 `quote()` 方法）：
> ```javascript
> const validOrderOptions = [
>   'ASC', 'DESC', 'ASC NULLS LAST', 'DESC NULLS LAST',
>   'ASC NULLS FIRST', 'DESC NULLS FIRST', 'NULLS FIRST', 'NULLS LAST'
> ];
> // 字符串列名 → quoteIdentifiers() → "col_name"
> // 字符串方向 → validOrderOptions.indexOf(item.toUpperCase()) → 匹配则 literal，不匹配则 quoteIdentifier
> ```

---

## 3. 已知 CVE

| CVE | 受影响版本 | 漏洞类型 | 要点 | CVSS |
|-----|-----------|----------|------|------|
| CVE-2026-30951 | < 6.37.8 | JSON 路径注入 | `_traverseJSON()` 未转义 `::` 后的 cast 类型，攻击者可通过 JSON 查询路径注入 SQL | 8.1 |
| CVE-2023-25813 | < 6.29.0 | `literal()` SQL 注入 | 特定场景下 `literal()` 的值未正确转义 | 9.8 |
| CVE-2023-22578 | < 6.28.1 | `replacements` 转义绕过 | 特定字符组合可逃逸 replacements 占位符 | 10.0 |
| CVE-2019-10748 | < 5.15.1 | JSON 条件注入 | JSON 操作符处理不当导致 SQL 注入 | 9.8 |
| CVE-2019-10749 | < 5.15.1 | toString 注入 | 对象的 `toString()` 被调用时可注入 | 9.8 |

### CVE 版本检查脚本

```bash
# 从 package.json 检查 Sequelize 版本
grep -o '"sequelize":\s*"[^"]*"' package.json
# 或从 lock 文件
grep '"sequelize"' package-lock.json | head -5
```

---

## 4. 修复模板

### 4.1 参数化替代拼接

```typescript
// ❌ 修复前
const rows = await sequelize.query(
  `SELECT * FROM users WHERE name = '${name}' AND age > ${age}`
);

// ✅ 修复后
const rows = await sequelize.query(
  `SELECT * FROM users WHERE name = :name AND age > :age`,
  { replacements: { name, age }, type: QueryTypes.SELECT }
);
```

### 4.2 白名单替代动态标识符

```typescript
// ❌ 修复前
const rows = await sequelize.query(
  `SELECT * FROM users ORDER BY ${sortField} ${sortOrder}`
);

// ✅ 修复后
const ALLOWED_SORT_FIELDS = ['name', 'created_at', 'email'] as const;
const ALLOWED_SORT_ORDERS = ['ASC', 'DESC'] as const;

type SortField = typeof ALLOWED_SORT_FIELDS[number];
type SortOrder = typeof ALLOWED_SORT_ORDERS[number];

const safeSortField: SortField = ALLOWED_SORT_FIELDS.includes(sortField as SortField)
  ? (sortField as SortField) : 'created_at';
const safeSortOrder: SortOrder = ALLOWED_SORT_ORDERS.includes(sortOrder?.toUpperCase() as SortOrder)
  ? (sortOrder.toUpperCase() as SortOrder) : 'ASC';

const rows = await sequelize.query(
  `SELECT * FROM users ORDER BY ${safeSortField} ${safeSortOrder}`,
  { type: QueryTypes.SELECT }
);
```

### 4.3 LIKE 安全处理

```typescript
// ❌ 修复前
await sequelize.query(
  `SELECT * FROM posts WHERE title LIKE '%${keyword}%'`
);

// ✅ 修复后
function escapeLike(str: string): string {
  return str.replace(/[%_\\]/g, '\\$&');
}

const rows = await sequelize.query(
  `SELECT * FROM posts WHERE title LIKE :pattern ESCAPE '\\'`,
  { replacements: { pattern: `%${escapeLike(keyword)}%` }, type: QueryTypes.SELECT }
);
```

### 4.4 IN 子句安全处理

```typescript
// ❌ 修复前
const ids = userInput.split(',');
await sequelize.query(`SELECT * FROM items WHERE id IN (${ids.join(',')})`);

// ✅ 修复后
const ids = userInput.split(',').map(Number).filter(Number.isFinite);
await sequelize.query(
  `SELECT * FROM items WHERE id IN (:ids)`,
  { replacements: { ids }, type: QueryTypes.SELECT }
);
```

### 4.5 literal() 安全替代

```typescript
// ❌ 修复前
await User.findAll({
  where: Sequelize.literal(`balance > ${threshold}`)
});

// ✅ 修复后（使用 ORM 操作符）
await User.findAll({
  where: { balance: { [Op.gt]: threshold } }
});

// 若必须用 literal（复杂表达式），确保参数化
await User.findAll({
  where: Sequelize.literal('balance > :threshold'),
  replacements: { threshold }
});
```
