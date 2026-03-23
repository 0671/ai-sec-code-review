# Hibernate / JPA / Spring Data JPA — SQL 注入模式库

---

## 1. 模式库（Pattern Library）

### 1.1 原生 SQL 查询

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `HIB-NATIVE-TMPL` | `createNativeQuery\s*\(.*\+` | 高 | 原生查询使用字符串拼接 |
| `HIB-NATIVE-FORMAT` | `createNativeQuery\s*\(\s*String\.format` | 高 | 原生查询使用 String.format |
| `HIB-NATIVE-SB` | `createNativeQuery\s*\(\s*(sb\|builder\|sql)` | 中 | 原生查询传入变量（需追踪） |

### 1.2 HQL / JPQL 查询

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `HIB-HQL-CONCAT` | `createQuery\s*\(\s*"(SELECT\|FROM\|UPDATE\|DELETE).*\+` | 高 | HQL/JPQL 字符串拼接 |
| `HIB-HQL-FORMAT` | `createQuery\s*\(\s*String\.format.*"(SELECT\|FROM)` | 高 | HQL/JPQL String.format |
| `HIB-HQL-SB` | `createQuery\s*\(\s*(sb\|builder\|hql\|jpql\|query)` | 中 | HQL/JPQL 传入变量 |

### 1.3 Criteria API（通常安全，但有例外）

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `HIB-CRIT-FUNCTION` | `criteriaBuilder\.function\s*\(` | 中 | 自定义数据库函数调用 |
| `HIB-CRIT-LITERAL` | `criteriaBuilder\.literal\s*\(\s*[a-zA-Z]` | 低 | literal 传入变量 |

### 1.4 Spring Data JPA @Query

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `SJD-QUERY-NATIVE-CONCAT` | `@Query\s*\(.*nativeQuery.*value.*\+` | 高 | 原生查询注解 + 拼接（罕见但可能） |
| `SJD-QUERY-SPEL` | `@Query.*#\{` | 中 | SpEL 表达式（需检查） |
| `SJD-SPEC-RAW` | `toPredicate.*criteriaBuilder` | 低 | Specification 实现（需检查拼接） |

### 1.5 Spring JDBC Template

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `JDBC-TMPL-CONCAT` | `jdbcTemplate\.(query\|update\|execute)\s*\(.*\+` | 高 | JdbcTemplate + 字符串拼接 |
| `JDBC-TMPL-FORMAT` | `jdbcTemplate\.(query\|update\|execute)\s*\(\s*String\.format` | 高 | JdbcTemplate + String.format |
| `JDBC-TMPL-VAR` | `jdbcTemplate\.(query\|update\|execute)\s*\(\s*[a-zA-Z_]\w*\s*[,\)]` | 中 | JdbcTemplate 传入变量 |
| `JDBC-STMT-EXEC` | `(statement\|stmt)\.(execute\|executeQuery\|executeUpdate)\s*\(` | 高 | Statement 直接执行（非 PreparedStatement） |

---

## 2. 安全 vs 危险 API 对照

### 2.1 原生 SQL

```java
// 🔴 危险：字符串拼接
entityManager.createNativeQuery(
    "SELECT * FROM users WHERE name = '" + name + "'"
).getResultList();

// ✅ 安全：位置参数
entityManager.createNativeQuery(
    "SELECT * FROM users WHERE name = ?1"
).setParameter(1, name).getResultList();

// ✅ 安全：命名参数
entityManager.createNativeQuery(
    "SELECT * FROM users WHERE name = :name"
).setParameter("name", name).getResultList();
```

### 2.2 HQL / JPQL

```java
// 🔴 危险：HQL 拼接（HQL 注入）
session.createQuery(
    "FROM User WHERE name = '" + name + "'"
).list();

// ✅ 安全：HQL + 参数绑定
session.createQuery(
    "FROM User WHERE name = :name"
).setParameter("name", name).list();
```

### 2.3 Spring Data JPA

```java
// ✅ 安全：Spring Data 方法名查询（自动参数化）
List<User> findByName(String name);
List<User> findByNameContaining(String keyword);

// ✅ 安全：@Query + 参数绑定
@Query("SELECT u FROM User u WHERE u.name = :name")
List<User> findByName(@Param("name") String name);

// ✅ 安全：原生查询 + 参数绑定
@Query(value = "SELECT * FROM users WHERE name = :name", nativeQuery = true)
List<User> findByNameNative(@Param("name") String name);
```

### 2.4 JdbcTemplate

```java
// 🔴 危险：字符串拼接
jdbcTemplate.query(
    "SELECT * FROM users WHERE name = '" + name + "'",
    new UserRowMapper()
);

// ✅ 安全：位置参数
jdbcTemplate.query(
    "SELECT * FROM users WHERE name = ?",
    new UserRowMapper(),
    name
);

// ✅ 安全：NamedParameterJdbcTemplate
namedParameterJdbcTemplate.query(
    "SELECT * FROM users WHERE name = :name",
    Map.of("name", name),
    new UserRowMapper()
);
```

---

## 3. 已知 CVE

| CVE | 受影响版本 | 漏洞类型 | 要点 |
|-----|-----------|----------|------|
| CVE-2020-25638 | Hibernate < 5.4.24 | HQL 注入绕过 | `hibernate.use_sql_comments=true` 时可通过注释注入 |
| CVE-2019-14900 | Hibernate < 5.4.18 | SQL 注入（literal 注入） | `literal()` 处理不当 |
| Spring Data JPA SpEL | 需检查 | SpEL 注入 | `@Query` 中使用 `#{}` SpEL 表达式时可能被注入 |

---

## 4. 修复模板

### 4.1 原生查询参数化

```java
// ❌ 修复前
String sql = "SELECT * FROM users WHERE department = '" + dept + "' ORDER BY " + sortField;
List<Object[]> results = entityManager.createNativeQuery(sql).getResultList();

// ✅ 修复后
Set<String> ALLOWED_SORT = Set.of("name", "email", "created_at");
String safeSort = ALLOWED_SORT.contains(sortField) ? sortField : "created_at";

String sql = "SELECT * FROM users WHERE department = :dept ORDER BY " + safeSort;
List<Object[]> results = entityManager.createNativeQuery(sql)
    .setParameter("dept", dept)
    .getResultList();
```

### 4.2 HQL 动态条件

```java
// ❌ 修复前
StringBuilder hql = new StringBuilder("FROM User WHERE 1=1");
if (name != null) hql.append(" AND name = '").append(name).append("'");
if (email != null) hql.append(" AND email = '").append(email).append("'");
session.createQuery(hql.toString()).list();

// ✅ 修复后
StringBuilder hql = new StringBuilder("FROM User WHERE 1=1");
Map<String, Object> params = new HashMap<>();
if (name != null) { hql.append(" AND name = :name"); params.put("name", name); }
if (email != null) { hql.append(" AND email = :email"); params.put("email", email); }
Query query = session.createQuery(hql.toString());
params.forEach(query::setParameter);
query.list();
```

### 4.3 JdbcTemplate 动态 IN 子句

```java
// ❌ 修复前
String ids = String.join(",", idList);
jdbcTemplate.query("SELECT * FROM users WHERE id IN (" + ids + ")", mapper);

// ✅ 修复后
NamedParameterJdbcTemplate namedTemplate = new NamedParameterJdbcTemplate(jdbcTemplate);
MapSqlParameterSource params = new MapSqlParameterSource("ids", idList);
namedTemplate.query("SELECT * FROM users WHERE id IN (:ids)", params, mapper);
```

### 4.4 Criteria API 替代 HQL 拼接

```java
// ✅ 使用 Criteria API（类型安全）
CriteriaBuilder cb = entityManager.getCriteriaBuilder();
CriteriaQuery<User> cq = cb.createQuery(User.class);
Root<User> root = cq.from(User.class);

List<Predicate> predicates = new ArrayList<>();
if (name != null) predicates.add(cb.equal(root.get("name"), name));
if (email != null) predicates.add(cb.like(root.get("email"), "%" + email + "%"));

cq.where(predicates.toArray(new Predicate[0]));
entityManager.createQuery(cq).getResultList();
```
