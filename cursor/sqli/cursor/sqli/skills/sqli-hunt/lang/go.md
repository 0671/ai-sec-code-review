# Go — SQL 注入 Source/Sink 模型

---

## 1. Source 模式（用户可控输入入口）

### 1.1 net/http (标准库)

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `r.URL.Query().Get("...")` | GET 参数 | 标准库 |
| `r.URL.Query()["..."]` | GET 参数（多值） | |
| `r.FormValue("...")` | GET/POST 参数 | 自动解析表单 |
| `r.PostFormValue("...")` | POST 参数 | 仅 POST 表单 |
| `r.Header.Get("...")` | 请求头 | |
| `r.PathValue("...")` | 路径参数 | Go 1.22+ |
| `r.Body` | 原始请求体 | 需 `json.Decode` 后检查字段 |
| `r.Cookie("...")` | Cookie | |

### 1.2 Gin

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `c.Query("...")` / `c.DefaultQuery("...", "...")` | GET 参数 | |
| `c.Param("...")` | 路径参数 | `/:id` |
| `c.PostForm("...")` | POST 表单 | |
| `c.GetHeader("...")` | 请求头 | |
| `c.Cookie("...")` | Cookie | |
| `c.ShouldBindJSON(&obj)` / `c.BindJSON(&obj)` | JSON 请求体 | 绑定后 obj 字段均可控 |
| `c.ShouldBindQuery(&obj)` | GET 参数绑定 | |

### 1.3 Echo

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `c.QueryParam("...")` | GET 参数 | |
| `c.Param("...")` | 路径参数 | |
| `c.FormValue("...")` | POST 表单 | |
| `c.Request().Header.Get("...")` | 请求头 | |
| `c.Bind(&obj)` | 请求体绑定 | |

### 1.4 Fiber

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `c.Query("...")` | GET 参数 | |
| `c.Params("...")` | 路径参数 | |
| `c.FormValue("...")` | POST 表单 | |
| `c.Get("...")` | 请求头 | |
| `c.BodyParser(&obj)` | 请求体绑定 | |

### 1.5 gRPC

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `req.GetFieldName()` / `req.FieldName` | gRPC 请求字段 | protobuf 生成的 getter |

---

## 2. Sink 入口（危险 API 搜索起点）

### 2.1 database/sql（标准库）

```go
// 最核心的审计目标 — 几乎所有 Go SQL 操作的底层
db.Query(sql, args...)
db.QueryRow(sql, args...)
db.Exec(sql, args...)
db.QueryContext(ctx, sql, args...)
db.ExecContext(ctx, sql, args...)
db.Prepare(sql)
db.PrepareContext(ctx, sql)

tx.Query(sql, args...)
tx.QueryRow(sql, args...)
tx.Exec(sql, args...)

stmt.Query(args...)
stmt.QueryRow(args...)
stmt.Exec(args...)
```

### 2.2 GORM

```go
// 危险 API（需检查参数化）
db.Raw(sql, args...).Scan(&result)
db.Exec(sql, args...)
db.Where(condition, args...)       // condition 为字符串时需检查
db.Order(value)                    // 动态排序
db.Select(fields)                  // 动态字段选择
db.Group(column)                   // 动态分组
db.Having(condition, args...)      // 动态 HAVING
db.Table(name)                     // 动态表名
db.Joins(joinStr, args...)         // 动态 JOIN

// GORM v2 Clause（通常安全但需确认）
clause.Expr{SQL: sql, Vars: vars}
```

### 2.3 sqlx

```go
// sqlx 扩展了 database/sql，以下 API 需检查
sqlx.Get(db, &dest, sql, args...)
sqlx.Select(db, &dest, sql, args...)
db.NamedExec(sql, arg)
db.NamedQuery(sql, arg)
db.Rebind(sql)                     // 占位符转换
```

### 2.4 ent (Facebook)

```go
// ent 通常类型安全，但以下需检查
client.Debug().Query()             // Debug 模式
.Where(predicate.Func(...))        // 自定义谓词函数
```

---

## 3. 危险拼接模式

Go 中最常见的 SQL 注入模式是 `fmt.Sprintf` 构建 SQL：

| 模式 | Grep 正则 | 危险等级 | 说明 |
|---|---|---|---|
| fmt.Sprintf SQL | `fmt\.Sprintf\s*\(\s*["'` + `](SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | 最常见的 Go SQL 注入模式 |
| + 拼接 SQL | `"(SELECT\|INSERT\|UPDATE\|DELETE).*"\s*\+` | 高 | 字符串拼接 |
| fmt.Fprintf | `fmt\.Fprintf.*"(SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | 写入 buffer |
| strings.Replace | `strings\.Replace.*"(SELECT\|INSERT\|UPDATE\|DELETE)` | 中 | 字符串替换构建 SQL |
| strings.Join IN | `IN\s*\(\s*.*strings\.Join` | 中 | 数组 Join 构建 IN 子句 |
| %v 占位 | `(SELECT\|INSERT\|UPDATE\|DELETE).*%v` | 高 | `%v` 不会转义 |
| %s 占位 | `(SELECT\|INSERT\|UPDATE\|DELETE).*%s` | 高 | `%s` 不会转义 |

### Go 特有陷阱：`%v` 与 `%s`

```go
// 危险：%v 和 %s 只是格式化，不做 SQL 转义
query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
query := fmt.Sprintf("SELECT * FROM users WHERE id = %v", id)

// 安全：使用占位符 $1 / ?
db.Query("SELECT * FROM users WHERE name = $1", name)
db.Query("SELECT * FROM users WHERE name = ?", name)
```

---

## 4. 净化器模式

| 净化方式 | 代码模式 | 对值有效 | 对标识符有效 |
|---|---|---|---|
| 参数化占位符 | `$1` / `$2` / `?` (database/sql) | ✅ | ❌ |
| 白名单 map | `allowedFields[input]` | ✅ | ✅ |
| strconv.Atoi | `strconv.Atoi(input)` / `strconv.ParseInt(input, ...)` | ✅ | ❌ |
| Go 枚举 (iota) | 自定义类型 + iota 常量 | ✅ | ✅（前提：值不来自外部） |
| pq.QuoteLiteral | `pq.QuoteLiteral(input)` | ✅ | ❌ |
| pq.QuoteIdentifier | `pq.QuoteIdentifier(input)` | ❌ | ✅ |
| pgx.Identifier | `pgx.Identifier{input}.Sanitize()` | ❌ | ✅ |
| regexp.MustCompile | `regexp.MustCompile("^[a-zA-Z0-9_]+$").MatchString(input)` | ⚠️ | ⚠️ |

---

## 5. 目录约定与搜索范围

### 5.1 应搜索的目录/文件

```
**/*.go
**/internal/**/*.go
**/pkg/**/*.go
**/cmd/**/*.go
**/handler/**/*.go
**/handlers/**/*.go
**/controller/**/*.go
**/controllers/**/*.go
**/service/**/*.go
**/services/**/*.go
**/repository/**/*.go
**/repositories/**/*.go
**/store/**/*.go
**/dao/**/*.go
**/model/**/*.go
**/models/**/*.go
**/api/**/*.go
**/server/**/*.go
```

### 5.2 应排除的目录

```
**/vendor/**
**/*_test.go
**/testdata/**
**/mock_*.go
**/mocks/**
```

### 5.3 应单独标记的文件

```
**/migrations/**/*.go
**/migrate/**/*.go
**/*.sql                  # SQL 迁移文件
```

---

## 6. 依赖文件解析

### 6.1 go.mod 关键依赖

```
gorm.io/gorm                       → framework/gorm.md
gorm.io/driver/postgres             → database/postgresql.md
gorm.io/driver/mysql                → database/mysql.md
gorm.io/driver/sqlite               → database/sqlite.md
gorm.io/driver/sqlserver             → database/mssql.md
github.com/jmoiron/sqlx             → (sqlx 模式在本文件 §2.3)
github.com/lib/pq                   → database/postgresql.md
github.com/jackc/pgx                → database/postgresql.md
github.com/go-sql-driver/mysql      → database/mysql.md
github.com/mattn/go-sqlite3         → database/sqlite.md
github.com/denisenkom/go-mssqldb    → database/mssql.md
entgo.io/ent                        → (ent 模式在本文件 §2.4)
```

---

## 7. Go 特有审计要点

### 7.1 `database/sql` 的占位符差异

不同数据库驱动使用不同占位符：

| 驱动 | 占位符 | 示例 |
|---|---|---|
| `lib/pq` (PostgreSQL) | `$1, $2, $3` | `WHERE id = $1` |
| `go-sql-driver/mysql` | `?` | `WHERE id = ?` |
| `mattn/go-sqlite3` | `?` 或 `$1` | |
| `go-mssqldb` | `@p1, @p2` | `WHERE id = @p1` |

**审计要点**：检查 `db.Query()` 的第一个参数中是否使用了正确的占位符而非 `fmt.Sprintf` 拼接。

### 7.2 GORM `.Where()` 的安全与危险用法

```go
// 安全：结构体条件
db.Where(&User{Name: name}).Find(&users)

// 安全：Map 条件
db.Where(map[string]interface{}{"name": name}).Find(&users)

// 安全：字符串条件 + 参数化
db.Where("name = ?", name).Find(&users)

// 危险：字符串条件 + 拼接
db.Where("name = '" + name + "'").Find(&users)
db.Where(fmt.Sprintf("name = '%s'", name)).Find(&users)
```

### 7.3 Go 的 `interface{}` 类型安全陷阱

Go 的类型系统在运行时可能被 `interface{}` 绕过。即使函数签名期望 `int`，若通过 `interface{}` 传递，实际可能是 `string`。

---

## 8. 支持的框架模块

- `framework/gorm.md`
