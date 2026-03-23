# MyBatis — SQL 注入模式库

> MyBatis 是 Java 生态中 SQL 注入发生率最高的 ORM 框架。`${}` 与 `#{}` 的区别是审计核心。

---

## 1. 模式库（Pattern Library）

### 1.1 XML Mapper 模式（搜索 *.xml 文件）

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `MBTS-DOLLAR` | `\$\{[^}]+\}` | 高 | `${}` 字符串替换（最核心的危险模式） |
| `MBTS-LIKE-DOLLAR` | `LIKE.*\$\{` | 高 | LIKE + `${}` 拼接 |
| `MBTS-ORDERBY-DOLLAR` | `ORDER\s+BY.*\$\{` | 高 | ORDER BY + `${}` |
| `MBTS-IN-DOLLAR` | `IN\s*\(.*\$\{` | 高 | IN 子句 + `${}` |
| `MBTS-TABLE-DOLLAR` | `(FROM\|JOIN\|INTO\|UPDATE)\s+\$\{` | 高 | 动态表名 |
| `MBTS-COLUMN-DOLLAR` | `(SELECT\|GROUP BY)\s+.*\$\{` | 高 | 动态列名/分组 |
| `MBTS-WHERE-DOLLAR` | `WHERE.*\$\{` | 高 | WHERE 条件 + `${}` |
| `MBTS-SET-DOLLAR` | `SET\s+.*\$\{` | 中 | UPDATE SET + `${}` |
| `MBTS-LIMIT-DOLLAR` | `(LIMIT\|OFFSET)\s+\$\{` | 低 | 动态分页 |

### 1.2 注解模式（搜索 *.java 文件）

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `MBTS-ANNO-DOLLAR` | `@(Select\|Insert\|Update\|Delete)\s*\(.*\$\{` | 高 | 注解 SQL + `${}` |
| `MBTS-PROVIDER-CONCAT` | `"(SELECT\|INSERT\|UPDATE\|DELETE).*"\s*\+` | 高 | SQLProvider 字符串拼接 |
| `MBTS-PROVIDER-FORMAT` | `String\.format.*"(SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | SQLProvider String.format |
| `MBTS-PROVIDER-SB` | `StringBuilder.*append.*"(SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | SQLProvider StringBuilder |

### 1.3 MyBatis-Plus 模式

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `MBTP-APPLY` | `\.apply\s*\(\s*"` | 高 | `.apply()` 自定义 SQL 片段（需检查参数化） |
| `MBTP-LAST` | `\.last\s*\(` | 高 | `.last()` 追加 SQL 片段（绕过任何安全限制） |
| `MBTP-ORDER-COL` | `\.orderByAsc\s*\(\s*[a-zA-Z_]` | 中 | 动态排序列（需追踪来源） |
| `MBTP-ORDER-DESC` | `\.orderByDesc\s*\(\s*[a-zA-Z_]` | 中 | 动态排序列 |
| `MBTP-INJECTPARAM` | `\.apply\s*\(.*\+` | 高 | apply 中使用拼接 |

---

## 2. `${}` vs `#{}` 核心原理

### 2.1 `#{param}` — 预编译参数（安全）

```xml
<!-- MyBatis 将 #{name} 替换为 ? 占位符，值通过 PreparedStatement 绑定 -->
<select id="findByName" resultType="User">
  SELECT * FROM users WHERE name = #{name}
</select>
<!-- 生成的 SQL: SELECT * FROM users WHERE name = ? -->
```

### 2.2 `${param}` — 字符串替换（危险）

```xml
<!-- MyBatis 将 ${name} 直接替换为参数值的字符串形式，无任何转义 -->
<select id="findByName" resultType="User">
  SELECT * FROM users WHERE name = '${name}'
</select>
<!-- 若 name = "' OR '1'='1"，生成: SELECT * FROM users WHERE name = '' OR '1'='1' -->
```

### 2.3 开发者被迫使用 `${}` 的常见场景

| 场景 | 原因 | 安全替代方案 |
|------|------|-------------|
| ORDER BY | `#{}` 会给列名加引号导致语法错误 | 白名单映射 |
| 动态表名 | 表名不能参数化 | 白名单映射 |
| IN 子句 | 传统方式无法动态生成多个 `?` | `<foreach>` 标签 |
| LIKE | `#{}` 需要特殊处理 | `CONCAT('%', #{keyword}, '%')` |
| GROUP BY / DISTINCT | 列名不能参数化 | 白名单映射 |

---

## 3. 已知 CVE

| CVE | 受影响范围 | 要点 |
|-----|-----------|------|
| 框架设计 | 所有版本 | `${}` 是 MyBatis 设计中的已知"特性"而非 bug，由开发者负责安全使用 |
| MyBatis-Plus injection | < 3.5.3.1 | 部分 Wrapper 方法未正确处理特殊字符 |

---

## 4. 修复模板

### 4.1 ORDER BY 安全处理

```xml
<!-- ❌ 修复前 -->
<select id="listUsers" resultType="User">
  SELECT * FROM users ORDER BY ${sortField} ${sortOrder}
</select>
```

```java
// ✅ 修复后（Java 端白名单）
private static final Map<String, String> SORT_FIELD_MAP = Map.of(
    "name", "name",
    "email", "email",
    "date", "created_at"
);
private static final Set<String> SORT_ORDERS = Set.of("ASC", "DESC");

public List<User> listUsers(String sortField, String sortOrder) {
    String safeField = SORT_FIELD_MAP.getOrDefault(sortField, "created_at");
    String safeOrder = SORT_ORDERS.contains(sortOrder.toUpperCase()) ? sortOrder.toUpperCase() : "ASC";
    return mapper.listUsers(safeField, safeOrder);
}
```

### 4.2 LIKE 安全处理

```xml
<!-- ❌ 修复前 -->
<select id="search" resultType="User">
  SELECT * FROM users WHERE name LIKE '%${keyword}%'
</select>

<!-- ✅ 修复后方案 1：使用 CONCAT + #{} -->
<select id="search" resultType="User">
  SELECT * FROM users WHERE name LIKE CONCAT('%', #{keyword}, '%')
</select>

<!-- ✅ 修复后方案 2：使用 bind 标签 -->
<select id="search" resultType="User">
  <bind name="pattern" value="'%' + keyword + '%'" />
  SELECT * FROM users WHERE name LIKE #{pattern}
</select>
```

### 4.3 IN 子句安全处理

```xml
<!-- ❌ 修复前 -->
<select id="findByIds" resultType="User">
  SELECT * FROM users WHERE id IN (${ids})
</select>

<!-- ✅ 修复后：使用 foreach -->
<select id="findByIds" resultType="User">
  SELECT * FROM users WHERE id IN
  <foreach item="id" collection="ids" open="(" separator="," close=")">
    #{id}
  </foreach>
</select>
```

### 4.4 动态表名安全处理

```java
// ❌ 修复前：XML 中 FROM ${tableName}

// ✅ 修复后：Java 端白名单
private static final Set<String> ALLOWED_TABLES = Set.of(
    "users", "orders", "products"
);

public List<Map<String, Object>> queryTable(String tableName) {
    if (!ALLOWED_TABLES.contains(tableName)) {
        throw new IllegalArgumentException("Invalid table name: " + tableName);
    }
    return mapper.queryTable(tableName);
}
```

### 4.5 MyBatis-Plus apply/last 安全处理

```java
// ❌ 修复前
queryWrapper.apply("name = '" + name + "'");
queryWrapper.last("ORDER BY " + sortField);

// ✅ 修复后
queryWrapper.apply("name = {0}", name);  // 使用占位符
// 对于 last()，尽量避免使用；若必须，白名单校验参数
```

---

## 5. MyBatis XML 审计检查清单

审计时按以下顺序检查所有 `*Mapper.xml` 文件：

1. **全局搜索 `${`**：每一个 `${` 都是潜在注入点
2. **检查 `${}` 的参数来源**：追踪到 Mapper 接口的方法参数，再到 Controller/Service
3. **检查 `<if>` / `<choose>` / `<when>` 内的 `${}`**：动态 SQL 中的隐蔽注入
4. **检查 `@SelectProvider` / `@UpdateProvider` 类**：SQL Provider 中的字符串拼接
5. **检查 `.apply()` 和 `.last()` 调用**：MyBatis-Plus 的高危方法
