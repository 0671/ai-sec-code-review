# PHP — SQL 注入 Source/Sink 模型

---

## 1. Source 模式（用户可控输入入口）

### 1.1 全局超级变量

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `$_GET['...']` | GET 参数 | 最直接的用户输入 |
| `$_POST['...']` | POST 参数 | |
| `$_REQUEST['...']` | GET/POST/Cookie 合并 | |
| `$_COOKIE['...']` | Cookie | |
| `$_SERVER['HTTP_...']` | 请求头 | `HTTP_X_CUSTOM` 等 |
| `$_SERVER['QUERY_STRING']` | 原始查询字符串 | |
| `$_SERVER['REQUEST_URI']` | 请求 URI | 含路径和查询 |
| `$_FILES['...']['name']` | 上传文件名 | 客户端可控 |
| `file_get_contents('php://input')` | 原始请求体 | |

### 1.2 Laravel

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `$request->input('...')` | 通用输入 | GET/POST 合并 |
| `$request->query('...')` | GET 参数 | |
| `$request->post('...')` | POST 参数 | |
| `$request->get('...')` | 通用获取 | |
| `$request->header('...')` | 请求头 | |
| `$request->cookie('...')` | Cookie | |
| `$request->file('...')` | 上传文件 | |
| `$request->all()` | 所有输入 | 数组形式 |
| `$request->only([...])` | 指定字段 | |
| `$request->route('...')` | 路由参数 | |
| `Request::input('...')` | Facade 风格 | |

### 1.3 Symfony

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `$request->query->get('...')` | GET 参数 | ParameterBag |
| `$request->request->get('...')` | POST 参数 | |
| `$request->headers->get('...')` | 请求头 | |
| `$request->cookies->get('...')` | Cookie | |
| `$request->getContent()` | 原始请求体 | |
| `$request->attributes->get('...')` | 路由参数 | |

### 1.4 WordPress

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `$_GET` / `$_POST` / `$_REQUEST` | 超级变量 | WP 环境下同样可用 |
| `get_query_var('...')` | WP 查询变量 | |
| `sanitize_text_field($_POST['...'])` | 净化后输入 | ⚠️ 不足以防 SQL 注入 |

---

## 2. Sink 入口（危险 API 搜索起点）

### 2.1 PDO（推荐的安全方式，但仍可被误用）

```php
// 需检查是否参数化
$pdo->query($sql)                  // 直接执行（不支持参数化）
$pdo->exec($sql)                   // 直接执行
$stmt = $pdo->prepare($sql)        // 准备语句（$sql 本身是否拼接？）
```

### 2.2 MySQLi

```php
// 过程式
mysqli_query($conn, $sql)
mysqli_real_query($conn, $sql)
mysqli_multi_query($conn, $sql)    // 危险：支持多语句执行
mysqli_prepare($conn, $sql)

// 面向对象
$mysqli->query($sql)
$mysqli->real_query($sql)
$mysqli->multi_query($sql)        // 危险
$mysqli->prepare($sql)
```

### 2.3 WordPress $wpdb

```php
// WordPress 数据库抽象层
$wpdb->query($sql)
$wpdb->get_results($sql)
$wpdb->get_row($sql)
$wpdb->get_var($sql)
$wpdb->get_col($sql)
// 安全：$wpdb->prepare() 预处理
$wpdb->prepare("SELECT * FROM {$wpdb->prefix}users WHERE id = %d", $id)
```

### 2.4 Laravel Query Builder / Eloquent

```php
// 危险 API（需检查参数化）
DB::raw($sql)
DB::select($sql)
DB::statement($sql)
DB::unprepared($sql)               // 明确不预处理
->whereRaw($sql)
->havingRaw($sql)
->orderByRaw($sql)
->groupByRaw($sql)
->selectRaw($sql)
->joinRaw($sql)

// 通常安全但需确认
->where($column, $operator, $value)  // $column 和 $operator 是否可控？
->orderBy($column, $direction)       // $column 是否可控？
```

### 2.5 Doctrine (Symfony)

```php
// 原生 SQL
$conn->executeQuery($sql, $params)
$conn->executeStatement($sql, $params)
$conn->fetchAllAssociative($sql, $params)

// DQL
$em->createQuery($dql)
$qb->where($dql)                  // DQL 拼接
```

---

## 3. 危险拼接模式

| 模式 | Grep 正则 | 危险等级 | 说明 |
|---|---|---|---|
| 双引号插值 | `"\s*(SELECT\|INSERT\|UPDATE\|DELETE).*\$` | 高 | PHP 双引号字符串变量插值 |
| 点拼接 | `(SELECT\|INSERT\|UPDATE\|DELETE).*["']\s*\.` | 高 | `.` 字符串拼接 |
| sprintf | `sprintf\s*\(\s*["'](SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | sprintf 格式化 |
| heredoc | `<<<(SQL\|QUERY\|EOF)` | 中 | Heredoc 中可能有变量插值 |
| "${var}" 语法 | `\$\{[^}]+\}` (在 SQL 上下文中) | 高 | PHP 复杂变量语法 |

### PHP 特有陷阱：双引号与单引号

```php
// 危险：双引号内变量自动插值
$sql = "SELECT * FROM users WHERE name = '$name'";

// 稍安全：单引号不插值（但通常仍会拼接）
$sql = 'SELECT * FROM users WHERE name = \'' . $name . '\'';

// 安全：PDO 参数化
$stmt = $pdo->prepare('SELECT * FROM users WHERE name = :name');
$stmt->execute(['name' => $name]);
```

---

## 4. 净化器模式

| 净化方式 | 代码模式 | 对值有效 | 对标识符有效 |
|---|---|---|---|
| PDO prepare + execute | `$pdo->prepare($sql)` + `$stmt->execute([$val])` | ✅ | ❌ |
| MySQLi prepare + bind | `$mysqli->prepare($sql)` + `bind_param` | ✅ | ❌ |
| $wpdb->prepare() | `$wpdb->prepare($sql, $val)` | ✅ | ❌ |
| intval() / (int) | `intval($input)` / `(int)$input` | ✅ | ❌ |
| 白名单 | `in_array($input, $allowed)` | ✅ | ✅ |
| mysqli_real_escape_string | `mysqli_real_escape_string($conn, $input)` | ⚠️ | ❌ |
| addslashes | `addslashes($input)` | ❌（可绕过） | ❌ |
| htmlspecialchars | `htmlspecialchars($input)` | ❌（HTML≠SQL） | ❌ |
| filter_var | `filter_var($input, FILTER_SANITIZE_NUMBER_INT)` | ✅（纯数字） | ❌ |

### ⚠️ 常见误用：`addslashes` 和 `mysql_real_escape_string`

- `addslashes()` 对 GBK 等多字节编码可被绕过
- `mysql_real_escape_string()` 已废弃
- `htmlspecialchars()` / `htmlentities()` 是 XSS 防护，对 SQL 注入无效

---

## 5. 目录约定与搜索范围

### 5.1 应搜索的目录/文件

```
**/*.php
**/app/**/*.php
**/src/**/*.php
**/controllers/**/*.php
**/Controllers/**/*.php
**/models/**/*.php
**/Models/**/*.php
**/services/**/*.php
**/Services/**/*.php
**/repositories/**/*.php
**/Repositories/**/*.php
**/Http/**/*.php              # Laravel
**/database/**/*.php          # Laravel migrations/seeds
**/routes/**/*.php
**/includes/**/*.php          # WordPress
**/wp-content/**/*.php        # WordPress plugins/themes
```

### 5.2 应排除的目录

```
**/vendor/**
**/node_modules/**
**/storage/**
**/cache/**
**/compiled/**
```

### 5.3 应单独标记的目录

```
**/database/migrations/**
**/database/seeders/**
**/database/factories/**
**/tests/**
**/Tests/**
```

---

## 6. 依赖文件解析

### 6.1 composer.json 关键依赖

```
laravel/framework / illuminate/database    → framework/laravel-eloquent.md
doctrine/orm / doctrine/dbal               → (Doctrine 模式在本文件 §2.5)
```

### 6.2 PHP 版本注意

- PHP < 7.0：可能使用已废弃的 `mysql_*` 函数族
- PHP < 8.0：`PDO::ERRMODE_SILENT` 可能隐藏错误
- 搜索 `mysql_query` / `mysql_fetch_array` 标记为高危（已废弃且不安全）

---

## 7. PHP 特有审计要点

### 7.1 魔术引号（Magic Quotes）

PHP < 5.4 的 `magic_quotes_gpc` 会自动 addslashes，但：
- 已被废弃并移除
- 提供虚假安全感
- 搜索 `get_magic_quotes_gpc()` 标记为信息

### 7.2 `mysqli_multi_query` 多语句执行

```php
// 极其危险：允许分号分隔多条 SQL
mysqli_multi_query($conn, $sql);
// 攻击者可: '; DROP TABLE users; --
```

### 7.3 WordPress 特殊风险

- 插件/主题代码质量参差不齐
- `$wpdb->query()` 未使用 `$wpdb->prepare()` 是高发漏洞
- 搜索 `$wpdb->query("` 且不含 `$wpdb->prepare` 的行

---

## 8. 支持的框架模块

- `framework/laravel-eloquent.md`
