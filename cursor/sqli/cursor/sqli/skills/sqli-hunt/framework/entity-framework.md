# Entity Framework Core / Dapper — SQL 注入模式库

---

## 1. 模式库（Pattern Library）

### 1.1 Entity Framework Core

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `EF-SQLRAW-INTERP` | `(ExecuteSqlRaw\|FromSqlRaw)\s*\(\s*\$"` | 高 | SqlRaw + 字符串插值（先求值再传入） |
| `EF-SQLRAW-CONCAT` | `(ExecuteSqlRaw\|FromSqlRaw)\s*\(\s*".*\+` | 高 | SqlRaw + 字符串拼接 |
| `EF-SQLRAW-FORMAT` | `(ExecuteSqlRaw\|FromSqlRaw)\s*\(\s*String\.Format` | 高 | SqlRaw + String.Format |
| `EF-SQLRAW-VAR` | `(ExecuteSqlRaw\|FromSqlRaw)\s*\(\s*[a-zA-Z_]\w*\s*[,\)]` | 中 | SqlRaw 传入变量（需追踪） |
| `EF-SQLQUERY-RAW` | `SqlQueryRaw\s*<` | 中 | EF 8+ SqlQueryRaw（需检查参数化） |
| `EF-DEPRECATED` | `(ExecuteSqlCommand\|FromSql)\s*\(` | 中 | 已废弃 API（EF Core < 3.0） |

### 1.2 Dapper

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `DAP-QUERY-INTERP` | `\.(Query\|Execute)\s*(<[^>]+>)?\s*\(\s*\$"` | 高 | Dapper Query/Execute + 插值 |
| `DAP-QUERY-CONCAT` | `\.(Query\|Execute)\s*(<[^>]+>)?\s*\(\s*".*\+` | 高 | Dapper + 字符串拼接 |
| `DAP-QUERY-FORMAT` | `\.(Query\|Execute)\s*(<[^>]+>)?\s*\(\s*String\.Format` | 高 | Dapper + String.Format |
| `DAP-QUERY-VAR` | `\.(Query\|Execute)\s*(<[^>]+>)?\s*\(\s*[a-zA-Z_]\w*\s*,` | 中 | Dapper 传入变量 |

### 1.3 ADO.NET

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `ADO-CMD-INTERP` | `CommandText\s*=\s*\$"` | 高 | CommandText 字符串插值 |
| `ADO-CMD-CONCAT` | `CommandText\s*=\s*".*\+` | 高 | CommandText 字符串拼接 |
| `ADO-CMD-FORMAT` | `CommandText\s*=\s*String\.Format` | 高 | CommandText String.Format |
| `ADO-EXEC-NOPARAM` | `new\s+SqlCommand\s*\(\s*\$"` | 高 | SqlCommand 构造 + 插值 |

---

## 2. 安全 vs 危险 API 对照

### 2.1 EF Core FromSqlRaw vs FromSqlInterpolated

```csharp
// 🔴 危险：FromSqlRaw + 字符串插值（先求值为 string）
string sql = $"SELECT * FROM Users WHERE Name = '{name}'";
var users = context.Users.FromSqlRaw(sql).ToList();

// 🔴 危险：$"" 先赋值给 string 变量（丢失 FormattableString 类型信息）
string sql = $"SELECT * FROM Users WHERE Name = {name}";
context.Users.FromSqlRaw(sql);  // name 已被嵌入字符串

// ✅ 安全：FromSqlInterpolated（直接传入 FormattableString）
var users = context.Users
    .FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}")
    .ToList();

// ✅ 安全：FromSqlRaw + 参数
var users = context.Users
    .FromSqlRaw("SELECT * FROM Users WHERE Name = {0}", name)
    .ToList();
```

### 2.2 Dapper

```csharp
// 🔴 危险：字符串插值
var users = connection.Query<User>($"SELECT * FROM Users WHERE Name = '{name}'");

// 🔴 危险：字符串拼接
var users = connection.Query<User>("SELECT * FROM Users WHERE Name = '" + name + "'");

// ✅ 安全：匿名对象参数
var users = connection.Query<User>(
    "SELECT * FROM Users WHERE Name = @Name",
    new { Name = name }
);

// ✅ 安全：DynamicParameters
var parameters = new DynamicParameters();
parameters.Add("Name", name);
var users = connection.Query<User>("SELECT * FROM Users WHERE Name = @Name", parameters);
```

### 2.3 ADO.NET

```csharp
// 🔴 危险
var cmd = new SqlCommand($"SELECT * FROM Users WHERE Id = {id}", connection);

// ✅ 安全
var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @Id", connection);
cmd.Parameters.AddWithValue("@Id", id);

// ✅ 更佳：明确类型
cmd.Parameters.Add("@Id", SqlDbType.Int).Value = id;
```

---

## 3. 关键陷阱：FormattableString vs string

这是 C# + EF Core 中最隐蔽也最重要的 SQL 注入陷阱：

```csharp
// EF Core 方法签名对比
FromSqlRaw(string sql, params object[] parameters)           // 接受 string
FromSqlInterpolated(FormattableString sql)                    // 接受 FormattableString

// 问题：$"" 在赋值给 string 时自动求值
FormattableString safe = $"SELECT * FROM Users WHERE Name = {name}";  // 保持为 FormattableString
string dangerous = $"SELECT * FROM Users WHERE Name = {name}";        // 自动求值为 string

// 以下代码看起来安全但实际危险：
var sql = $"SELECT * FROM Users WHERE Id = {id}";
context.Users.FromSqlRaw(sql);  // var 推导为 string → 注入！

// 安全写法：
context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Id = {id}");
```

**审计规则**：搜索所有 `FromSqlRaw` 调用，检查传入的 SQL 是否来自 `$"..."` 插值字符串变量。

---

## 4. 修复模板

### 4.1 EF Core 参数化

```csharp
// ❌ 修复前
var sql = $"SELECT * FROM Users WHERE Department = '{dept}' ORDER BY {sortField}";
var users = context.Users.FromSqlRaw(sql).ToList();

// ✅ 修复后
var allowedSort = new HashSet<string> { "Name", "Email", "CreatedAt" };
var safeSort = allowedSort.Contains(sortField) ? sortField : "CreatedAt";

var users = context.Users
    .FromSqlRaw($"SELECT * FROM Users WHERE Department = {{0}} ORDER BY {safeSort}", dept)
    .ToList();
// 注意：{0} 在 FromSqlRaw 中是参数占位符
```

### 4.2 Dapper 动态条件

```csharp
// ❌ 修复前
var sql = "SELECT * FROM Users WHERE 1=1";
if (!string.IsNullOrEmpty(name)) sql += $" AND Name = '{name}'";
if (!string.IsNullOrEmpty(email)) sql += $" AND Email = '{email}'";
var users = connection.Query<User>(sql);

// ✅ 修复后
var sql = new StringBuilder("SELECT * FROM Users WHERE 1=1");
var parameters = new DynamicParameters();

if (!string.IsNullOrEmpty(name)) {
    sql.Append(" AND Name = @Name");
    parameters.Add("Name", name);
}
if (!string.IsNullOrEmpty(email)) {
    sql.Append(" AND Email = @Email");
    parameters.Add("Email", email);
}

var users = connection.Query<User>(sql.ToString(), parameters);
```

### 4.3 动态排序白名单

```csharp
// ✅ 修复后
private static readonly Dictionary<string, string> AllowedSortColumns = new()
{
    ["name"] = "Name",
    ["email"] = "Email",
    ["date"] = "CreatedAt"
};

public IQueryable<User> GetSorted(string sortField, string sortDir)
{
    var column = AllowedSortColumns.GetValueOrDefault(sortField?.ToLower(), "CreatedAt");
    var ascending = !string.Equals(sortDir, "desc", StringComparison.OrdinalIgnoreCase);

    return ascending
        ? context.Users.OrderBy(u => EF.Property<object>(u, column))
        : context.Users.OrderByDescending(u => EF.Property<object>(u, column));
}
```
