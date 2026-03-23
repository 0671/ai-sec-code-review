# C# / .NET — SQL 注入 Source/Sink 模型

---

## 1. Source 模式（用户可控输入入口）

### 1.1 ASP.NET Core MVC / Web API

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `[FromQuery] string name` | GET 参数 | 模型绑定 |
| `[FromRoute] int id` | 路由参数 | |
| `[FromBody] SomeDto dto` | JSON 请求体 | 对象字段均可控 |
| `[FromHeader] string h` | 请求头 | |
| `[FromForm] string f` | 表单参数 | |
| `Request.Query["..."]` | GET 参数 | 直接访问 |
| `Request.Form["..."]` | POST 表单 | |
| `Request.Headers["..."]` | 请求头 | |
| `Request.Cookies["..."]` | Cookie | |
| `Request.RouteValues["..."]` | 路由参数 | |
| `HttpContext.Request.Body` | 原始请求体 | |

### 1.2 ASP.NET (经典)

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `Request.QueryString["..."]` | GET 参数 | |
| `Request.Form["..."]` | POST 参数 | |
| `Request["..."]` | GET/POST/Cookie 合并 | |
| `Request.Headers["..."]` | 请求头 | |
| `Request.Cookies["..."]` | Cookie | |
| `Request.Params["..."]` | 所有参数合并 | |

### 1.3 Minimal API (.NET 6+)

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| Lambda 参数直接绑定 | 自动绑定 | `app.MapGet("/", (string q) => ...)` |
| `[AsParameters] SomeRecord r` | 复合绑定 | |

### 1.4 SignalR

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| Hub 方法参数 | 客户端消息 | `public async Task Send(string message)` |

---

## 2. Sink 入口（危险 API 搜索起点）

### 2.1 ADO.NET (System.Data)

```csharp
// 最底层 — 必须全量搜索
SqlCommand cmd = new SqlCommand(sql, connection);
cmd.ExecuteReader();
cmd.ExecuteNonQuery();
cmd.ExecuteScalar();

// 其他数据库提供程序
NpgsqlCommand / MySqlCommand / OracleCommand / SqliteCommand

// 通用接口
IDbCommand.CommandText = sql;
IDbCommand.ExecuteReader();
```

### 2.2 Dapper

```csharp
// Dapper 扩展方法 — 第一个参数为 SQL 字符串
connection.Query<T>(sql, param)
connection.QueryFirst<T>(sql, param)
connection.QueryFirstOrDefault<T>(sql, param)
connection.QuerySingle<T>(sql, param)
connection.Execute(sql, param)
connection.ExecuteScalar<T>(sql, param)
connection.QueryMultiple(sql, param)

// 异步版本
connection.QueryAsync<T>(sql, param)
connection.ExecuteAsync(sql, param)
```

### 2.3 Entity Framework Core

```csharp
// 原生 SQL API — 主要审计目标
context.Database.ExecuteSqlRaw(sql, params)
context.Database.ExecuteSqlRawAsync(sql, params)
context.Database.SqlQuery<T>(sql)            // EF 8+
context.Database.SqlQueryRaw<T>(sql, params) // EF 8+
dbSet.FromSqlRaw(sql, params)
dbSet.FromSqlInterpolated($"...")            // 安全（插值参数化）

// 已废弃但可能仍存在
context.Database.ExecuteSqlCommand(sql)      // EF Core < 3.0
dbSet.FromSql(sql)                           // EF Core < 3.0
```

### 2.4 NHibernate

```csharp
session.CreateSQLQuery(sql)
session.CreateQuery(hql)       // HQL 拼接同样危险
session.GetNamedQuery("...")
```

---

## 3. 危险拼接模式

| 模式 | Grep 正则 | 危险等级 | 说明 |
|---|---|---|---|
| 字符串插值 | `\$"(SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | C# 6+ 字符串插值 |
| + 拼接 | `"(SELECT\|INSERT\|UPDATE\|DELETE).*"\s*\+` | 高 | 字符串拼接 |
| String.Format | `String\.Format\s*\(\s*"(SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | 格式化 |
| StringBuilder | `(StringBuilder).*Append.*"(SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | |
| string.Concat | `string\.Concat.*"(SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | |
| $@ 逐字插值 | `\$@"(SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | 逐字字符串 + 插值 |

### C# 特有陷阱：`$"..."` 与 `FromSqlInterpolated`

```csharp
// 危险：普通字符串插值 + ExecuteSqlRaw
var sql = $"SELECT * FROM Users WHERE Name = '{name}'";
context.Database.ExecuteSqlRaw(sql);

// 安全：直接传入插值字符串给 FromSqlInterpolated
// EF Core 会将 {name} 转为参数化
context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}");

// 危险：先赋值给 string 变量再传入（丢失 FormattableString 类型信息）
string sql = $"SELECT * FROM Users WHERE Name = {name}";
context.Users.FromSqlRaw(sql); // 此时已经是拼接后的字符串！
```

---

## 4. 净化器模式

| 净化方式 | 代码模式 | 对值有效 | 对标识符有效 |
|---|---|---|---|
| SqlParameter | `new SqlParameter("@name", value)` | ✅ | ❌ |
| Dapper 匿名对象 | `new { name = value }` | ✅ | ❌ |
| int.TryParse | `int.TryParse(input, out var id)` | ✅ | ❌ |
| 白名单 | `allowedColumns.Contains(input)` | ✅ | ✅ |
| C# enum | `Enum.TryParse<SortField>(input, out var field)` | ✅ | ✅ |
| EF FromSqlInterpolated | `FromSqlInterpolated($"...{val}...")` | ✅ | ❌ |
| Data Annotations | `[RegularExpression("...")]` | ⚠️ | ⚠️ |

---

## 5. 目录约定与搜索范围

### 5.1 应搜索的目录/文件

```
**/*.cs
**/Controllers/**/*.cs
**/Services/**/*.cs
**/Repositories/**/*.cs
**/Data/**/*.cs
**/Models/**/*.cs
**/Handlers/**/*.cs
**/Queries/**/*.cs         # CQRS Query Handlers
**/Commands/**/*.cs        # CQRS Command Handlers
**/Infrastructure/**/*.cs
**/Persistence/**/*.cs
**/Dal/**/*.cs
**/Hubs/**/*.cs            # SignalR Hubs
**/Pages/**/*.cs           # Razor Pages
**/Areas/**/*.cs
```

### 5.2 应排除的目录

```
**/bin/**
**/obj/**
**/TestResults/**
**/packages/**
**/.vs/**
```

### 5.3 应单独标记的目录

```
**/Migrations/**
**/Tests/**
**/*.Tests/**
**/*.UnitTests/**
**/*.IntegrationTests/**
```

---

## 6. 依赖文件解析

### 6.1 *.csproj 关键依赖

```xml
Microsoft.EntityFrameworkCore            → framework/entity-framework.md
Microsoft.EntityFrameworkCore.SqlServer  → database/mssql.md
Npgsql.EntityFrameworkCore.PostgreSQL    → database/postgresql.md
Pomelo.EntityFrameworkCore.MySql         → database/mysql.md
Microsoft.EntityFrameworkCore.Sqlite     → database/sqlite.md
Dapper                                   → (Dapper 模式在本文件 §2.2)
NHibernate                               → (NHibernate 模式在本文件 §2.4)
System.Data.SqlClient                    → database/mssql.md
Npgsql                                   → database/postgresql.md
MySqlConnector / MySql.Data              → database/mysql.md
Oracle.ManagedDataAccess                 → database/oracle.md
```

---

## 7. C# 特有审计要点

### 7.1 Stored Procedures 的隐蔽风险

```csharp
// 看似安全（调用存储过程）但存储过程内部可能拼接
cmd.CommandType = CommandType.StoredProcedure;
cmd.CommandText = "sp_SearchUsers";
cmd.Parameters.AddWithValue("@search", userInput);
// 需要审查存储过程 sp_SearchUsers 的定义！
```

### 7.2 Dynamic LINQ (System.Linq.Dynamic.Core)

```csharp
// 动态 LINQ 可能引入注入
users.Where(userInput);      // 动态 WHERE 表达式
users.OrderBy(userInput);    // 动态 ORDER BY
```

### 7.3 `FormattableString` vs `string` 的类型陷阱

EF Core 的 `FromSqlInterpolated` 接受 `FormattableString` 类型参数，自动参数化。但如果先赋值给 `string` 变量，插值会提前求值，安全性丧失。这是 C# 中最隐蔽的 SQL 注入陷阱之一。

---

## 8. 支持的框架模块

- `framework/entity-framework.md`
