# Laravel Eloquent / Query Builder — SQL 注入模式库

---

## 1. 模式库（Pattern Library）

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `LAR-DB-RAW` | `DB::raw\s*\(\s*["'].*(\.\|\$)` | 高 | `DB::raw()` 含变量插值或拼接 |
| `LAR-WHERE-RAW-CONCAT` | `->whereRaw\s*\(\s*["'].*(\.\|\$)` | 高 | `whereRaw()` 含拼接 |
| `LAR-WHERE-RAW-NOBIND` | `->whereRaw\s*\(\s*["'][^"']*["']\s*\)` | 中 | `whereRaw()` 无绑定参数 |
| `LAR-HAVING-RAW` | `->havingRaw\s*\(` | 中 | `havingRaw()` 需检查参数化 |
| `LAR-ORDER-RAW` | `->orderByRaw\s*\(` | 中 | `orderByRaw()` 需检查参数化 |
| `LAR-SELECT-RAW` | `->selectRaw\s*\(` | 中 | `selectRaw()` 需检查参数化 |
| `LAR-GROUP-RAW` | `->groupByRaw\s*\(` | 中 | `groupByRaw()` 需检查参数化 |
| `LAR-JOIN-RAW` | `->joinRaw\s*\(` | 中 | `joinRaw()` 需检查参数化 |
| `LAR-UNPREPARED` | `DB::unprepared\s*\(` | 高 | 明确不预处理的执行 |
| `LAR-STATEMENT` | `DB::statement\s*\(` | 中 | 原生语句执行 |
| `LAR-SELECT-SQL` | `DB::select\s*\(\s*["'].*(\.\|\$)` | 高 | DB::select 含拼接 |
| `LAR-WHERE-COL-VAR` | `->where\s*\(\s*\$` | 中 | where 第一个参数（列名）为变量 |
| `LAR-ORDER-VAR` | `->orderBy\s*\(\s*\$` | 中 | orderBy 列名为变量 |

---

## 2. 安全 vs 危险 API 对照

### 2.1 Query Builder（通常安全）

```php
// ✅ 安全：Eloquent/Query Builder 自动参数化
User::where('name', $name)->get();
User::where('name', 'like', "%{$name}%")->get();
DB::table('users')->where('name', '=', $name)->get();

// ⚠️ 注意：where 的第一个参数（列名）不会参数化
// 若列名来自用户输入，可能导致注入
DB::table('users')->where($userInput, '=', $value)->get();  // 🔴 危险
```

### 2.2 *Raw 方法

```php
// 🔴 危险：无绑定的 whereRaw
User::whereRaw("name = '$name'")->get();
User::whereRaw("name = " . $name)->get();

// ✅ 安全：whereRaw + 绑定参数
User::whereRaw("name = ?", [$name])->get();
User::whereRaw("LOWER(name) = LOWER(?)", [$name])->get();
```

### 2.3 DB::raw()

```php
// 🔴 危险：raw 内拼接
User::select(DB::raw("*, (SELECT COUNT(*) FROM orders WHERE user_id = users.id AND status = '$status') as order_count"))->get();

// ✅ 安全：raw + 绑定
User::selectRaw("*, (SELECT COUNT(*) FROM orders WHERE user_id = users.id AND status = ?) as order_count", [$status])->get();
```

### 2.4 DB::unprepared()

```php
// 🔴 高危：明确绕过预处理
DB::unprepared("UPDATE users SET status = 'active' WHERE name = '$name'");
// 这个方法永远不应该包含用户输入
```

---

## 3. 已知 CVE / 安全注意

| 问题 | 要点 |
|------|------|
| 列名注入 | `->where($column, $value)` 的 `$column` 不会被参数化；Laravel 文档未充分警告 |
| `orderBy` 列名 | `->orderBy($column)` 的 `$column` 不会参数化 |
| JSON 列查询 | `->where('data->key', $value)` 在某些数据库驱动中可能存在注入 |

---

## 4. 修复模板

### 4.1 whereRaw → where

```php
// ❌ 修复前
$users = User::whereRaw("name LIKE '%{$keyword}%'")->get();

// ✅ 修复后方案 1：使用 where + LIKE
$users = User::where('name', 'like', "%{$keyword}%")->get();

// ✅ 修复后方案 2：whereRaw + 绑定
$users = User::whereRaw("name LIKE ?", ["%{$keyword}%"])->get();
```

### 4.2 动态排序白名单

```php
// ❌ 修复前
$users = User::orderBy($request->input('sort'))->get();

// ✅ 修复后
$allowedSort = ['name', 'email', 'created_at'];
$allowedDirection = ['asc', 'desc'];

$sort = in_array($request->input('sort'), $allowedSort)
    ? $request->input('sort') : 'created_at';
$direction = in_array(strtolower($request->input('direction')), $allowedDirection)
    ? $request->input('direction') : 'asc';

$users = User::orderBy($sort, $direction)->get();
```

### 4.3 动态列名白名单

```php
// ❌ 修复前
$column = $request->input('filter_field');
$value = $request->input('filter_value');
$users = User::where($column, $value)->get();

// ✅ 修复后
$allowedColumns = ['name', 'email', 'status'];
$column = in_array($request->input('filter_field'), $allowedColumns)
    ? $request->input('filter_field') : null;

if ($column) {
    $users = User::where($column, $request->input('filter_value'))->get();
}
```

### 4.4 DB::raw → selectRaw + 绑定

```php
// ❌ 修复前
$users = DB::table('users')
    ->select(DB::raw("name, (age * $multiplier) as adjusted_age"))
    ->get();

// ✅ 修复后
$users = DB::table('users')
    ->selectRaw("name, (age * ?) as adjusted_age", [(int)$multiplier])
    ->get();
```
