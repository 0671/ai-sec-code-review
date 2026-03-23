# Java — SQL 注入 Source/Sink 模型

---

## 1. Source 模式（用户可控输入入口）

### 1.1 Spring MVC / Spring Boot

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `@RequestParam String name` | GET/POST 参数 | 自动绑定 |
| `@RequestParam("key") String val` | 指定参数名 | |
| `@PathVariable String id` | 路径参数 | `/user/{id}` |
| `@RequestBody SomeDto dto` | JSON 请求体 | 反序列化为对象，字段均可控 |
| `@RequestHeader("X-Custom") String h` | 请求头 | |
| `@CookieValue("name") String c` | Cookie | |
| `@ModelAttribute SomeForm form` | 表单绑定 | 字段均可控 |
| `HttpServletRequest request` → `.getParameter("...")` | GET/POST 参数 | Servlet 原生 API |
| `request.getParameterValues("...")` | 多值参数 | |
| `request.getHeader("...")` | 请求头 | |
| `request.getCookies()` | Cookie 数组 | |
| `request.getInputStream()` / `request.getReader()` | 原始请求体 | |
| `MultipartFile file` → `file.getOriginalFilename()` | 上传文件名 | 客户端可控 |

### 1.2 JAX-RS (Jersey / RESTEasy)

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `@QueryParam("key") String val` | GET 参数 | |
| `@PathParam("key") String val` | 路径参数 | |
| `@FormParam("key") String val` | 表单参数 | |
| `@HeaderParam("key") String val` | 请求头 | |
| `@CookieParam("key") String val` | Cookie | |

### 1.3 gRPC

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `request.getFieldName()` | gRPC 请求字段 | 间接可控（取决于调用方） |
| `request.getFieldNameList()` | 重复字段 | |

### 1.4 消息队列

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `@KafkaListener` 方法参数 | Kafka 消息 | 间接可控 |
| `@RabbitListener` 方法参数 | RabbitMQ 消息 | 间接可控 |
| `@JmsListener` 方法参数 | JMS 消息 | 间接可控 |

---

## 2. Sink 入口（危险 API 搜索起点）

### 2.1 MyBatis

```java
// MyBatis XML Mapper — 最关键的审计目标
${...}                     // 字符串替换（危险）
#{...}                     // 预编译参数（安全）

// MyBatis 注解
@Select("SELECT * FROM users WHERE name = ${name}")    // 危险
@Select("SELECT * FROM users WHERE name = #{name}")    // 安全

// MyBatis-Plus
.apply("name = " + name)          // 危险
.last("ORDER BY " + sortField)    // 危险
.orderByAsc(columns)              // 需检查 columns 来源
```

### 2.2 Hibernate / JPA

```java
// 原生 SQL（高危搜索目标）
entityManager.createNativeQuery(
session.createNativeQuery(
session.createSQLQuery(            // Hibernate 5 已废弃但仍可用

// HQL / JPQL（需检查拼接）
entityManager.createQuery("SELECT ... WHERE " + condition)
session.createQuery("FROM User WHERE " + condition)

// Criteria API — 通常安全，但有例外
CriteriaBuilder.function(          // 自定义函数可能含危险参数
```

### 2.3 Spring JDBC Template

```java
// 需检查参数化方式
jdbcTemplate.query(sql, ...)
jdbcTemplate.queryForObject(sql, ...)
jdbcTemplate.queryForList(sql, ...)
jdbcTemplate.update(sql, ...)
jdbcTemplate.execute(sql)
jdbcTemplate.batchUpdate(sql, ...)

// NamedParameterJdbcTemplate — 通常更安全
namedParameterJdbcTemplate.query(sql, params, ...)
```

### 2.4 JOOQ

```java
// 原生 SQL 入口
DSL.sql(                          // 原生 SQL 片段
DSL.field(                        // 动态字段名
DSL.table(                        // 动态表名
DSL.condition(                    // 动态条件
dsl.resultQuery(                  // 原生查询
.plain(                           // 非参数化 SQL
```

### 2.5 原生 JDBC

```java
// Statement（从不参数化，必须搜索）
statement.execute(sql)
statement.executeQuery(sql)
statement.executeUpdate(sql)

// PreparedStatement 构建过程（检查 SQL 是否拼接）
connection.prepareStatement(sql)   // sql 变量是否含拼接？
```

---

## 3. 危险拼接模式

| 模式 | Grep 正则 | 危险等级 | 说明 |
|---|---|---|---|
| + 拼接 SQL | `"(SELECT\|INSERT\|UPDATE\|DELETE).*"\s*\+` | 高 | 字符串拼接含 SQL 关键字 |
| StringBuilder | `(StringBuilder\|StringBuffer).*append.*"(SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | StringBuilder 构建 SQL |
| String.format | `String\.format\s*\(\s*"(SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | String.format 格式化 SQL |
| MessageFormat | `MessageFormat\.format.*"(SELECT\|INSERT\|UPDATE\|DELETE)` | 中 | MessageFormat 格式化 |
| MyBatis ${} | `\$\{[^}]+\}` (在 .xml Mapper 中) | 高 | MyBatis 字符串替换 |
| concat() | `"(SELECT\|INSERT\|UPDATE\|DELETE).*\.concat\(` | 高 | String.concat() |

---

## 4. 净化器模式

| 净化方式 | 代码模式 | 对值有效 | 对标识符有效 |
|---|---|---|---|
| 白名单 | `allowedFields.contains(input)` / `Arrays.asList(...).contains(input)` | ✅ | ✅ |
| Integer.parseInt | `Integer.parseInt(input)` / `Long.parseLong(input)` | ✅ | ❌ |
| Java enum | `SortField.valueOf(input)` | ✅ | ✅ |
| PreparedStatement | `connection.prepareStatement(sql)` + `setString/setInt` | ✅ | ❌ |
| Spring Validation | `@Pattern(regexp="...")` / `@Size` / `@NotBlank` | ⚠️ | ⚠️ |
| Apache Commons | `StringEscapeUtils.escapeSql(input)` | ⚠️ 已废弃 | ❌ |
| OWASP ESAPI | `ESAPI.encoder().encodeForSQL(...)` | ✅ | ❌ |

---

## 5. 目录约定与搜索范围

### 5.1 应搜索的目录/文件

```
**/src/main/java/**/*.java
**/src/main/resources/**/*.xml       # MyBatis Mapper XML
**/src/main/kotlin/**/*.kt           # Kotlin 代码
**/mapper/**/*.java
**/mapper/**/*.xml
**/repository/**/*.java
**/dao/**/*.java
**/service/**/*.java
**/controller/**/*.java
**/resource/**/*.java                # JAX-RS resources
**/api/**/*.java
**/provider/**/*.java                # MyBatis SQL Provider
```

### 5.2 应排除的目录

```
**/target/**
**/build/**
**/.gradle/**
**/out/**
**/generated/**
**/generated-sources/**
```

### 5.3 应单独标记的目录

```
**/src/test/**
**/src/main/resources/db/migration/**    # Flyway
**/src/main/resources/db/changelog/**    # Liquibase
```

---

## 6. 依赖文件解析

### 6.1 pom.xml 关键依赖

```xml
mybatis / mybatis-spring-boot-starter     → framework/mybatis.md
mybatis-plus-boot-starter                 → framework/mybatis.md
hibernate-core / spring-boot-starter-data-jpa → framework/hibernate.md
spring-jdbc / spring-boot-starter-jdbc    → (Spring JDBC Template, 含在 hibernate.md)
jooq                                       → (JOOQ 模式在本文件 §2.4)
postgresql / org.postgresql:postgresql    → database/postgresql.md
mysql-connector-java / mysql:mysql-connector-java → database/mysql.md
com.microsoft.sqlserver:mssql-jdbc        → database/mssql.md
com.oracle.database.jdbc:ojdbc8           → database/oracle.md
org.xerial:sqlite-jdbc                    → database/sqlite.md
```

### 6.2 build.gradle 关键依赖

```groovy
implementation 'org.mybatis.spring.boot:mybatis-spring-boot-starter'
implementation 'com.baomidou:mybatis-plus-boot-starter'
implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
runtimeOnly 'org.postgresql:postgresql'
runtimeOnly 'mysql:mysql-connector-java'
```

---

## 7. Java 特有审计要点

### 7.1 MyBatis XML Mapper 审计要点

MyBatis 是 Java 生态中 SQL 注入最高发的框架。审计重点：

1. **全量搜索 `${}`**：在所有 `.xml` Mapper 文件中搜索 `${`，每一个都是潜在注入点
2. **`${}` vs `#{}`**：`#{}` 是参数化（安全），`${}` 是字符串替换（危险）
3. **动态 SQL 中的 `${}`**：`<if>` / `<choose>` / `<foreach>` 内的 `${}` 更隐蔽
4. **ORDER BY**：MyBatis 的 `#{}` 在 ORDER BY 位置会加引号导致语法错误，开发者常被迫用 `${}`
5. **`@SelectProvider` / `@UpdateProvider`**：SQL Provider 类中的字符串拼接

### 7.2 Hibernate 二级缓存与 SQL 注入

注入通过 HQL 发生时，若启用了二级缓存，可能导致缓存投毒。

### 7.3 Spring Data JPA 的 `@Query`

```java
// 安全：使用位置参数或命名参数
@Query("SELECT u FROM User u WHERE u.name = :name")
@Query("SELECT u FROM User u WHERE u.name = ?1")

// 危险：SpEL 表达式注入（罕见但存在）
@Query("SELECT u FROM User u WHERE u.name = :#{#name}")  // SpEL
```

---

## 8. 支持的框架模块

- `framework/mybatis.md`
- `framework/hibernate.md`
