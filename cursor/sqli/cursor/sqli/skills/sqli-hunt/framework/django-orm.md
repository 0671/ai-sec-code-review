# Django ORM — SQL 注入模式库

---

## 1. 模式库（Pattern Library）

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `DJ-RAW-FSTR` | `\.raw\s*\(\s*f["']` | 高 | `Model.objects.raw()` 使用 f-string |
| `DJ-RAW-FORMAT` | `\.raw\s*\(\s*["'].*\.format\(` | 高 | `.raw()` 使用 str.format() |
| `DJ-RAW-PERCENT` | `\.raw\s*\(\s*["'].*%[^s]` | 高 | `.raw()` 使用 % 格式化（非参数化 %s） |
| `DJ-RAW-CONCAT` | `\.raw\s*\(\s*["'].*\+` | 高 | `.raw()` 字符串拼接 |
| `DJ-EXTRA-WHERE` | `\.extra\s*\(\s*where` | 高 | `.extra(where=[...])` 已废弃但仍可用 |
| `DJ-EXTRA-SELECT` | `\.extra\s*\(\s*select` | 中 | `.extra(select={...})` |
| `DJ-RAWSQL` | `RawSQL\s*\(` | 高 | `RawSQL()` 表达式 |
| `DJ-CURSOR-FSTR` | `cursor\.execute\s*\(\s*f["']` | 高 | 原生游标 + f-string |
| `DJ-CURSOR-FORMAT` | `cursor\.execute\s*\(\s*["'].*\.format\(` | 高 | 原生游标 + format() |
| `DJ-CURSOR-PERCENT` | `cursor\.execute\s*\(\s*["'].*%\s` | 中 | 原生游标 + %（需区分参数化） |
| `DJ-ORDER-VAR` | `\.order_by\s*\(\s*[a-zA-Z_]\w*\s*\)` | 中 | 动态排序（需追踪变量来源） |
| `DJ-ANNOTATE-RAW` | `\.annotate\s*\(.*RawSQL` | 高 | annotate 中使用 RawSQL |
| `DJ-FILTER-EXTRA` | `\.filter\s*\(.*__` 后接动态键 | 中 | 动态 ORM lookup（__exact 等） |

---

## 2. 安全 vs 危险 API 对照

### 2.1 raw()

```python
# 🔴 危险：f-string
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")

# 🔴 危险：str.format()
User.objects.raw("SELECT * FROM users WHERE name = '{}'".format(name))

# 🔴 危险：% 格式化拼接
User.objects.raw("SELECT * FROM users WHERE name = '%s'" % name)

# ✅ 安全：参数化（%s 作为占位符 + params 列表）
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])
```

### 2.2 ORM 查询（通常安全）

```python
# ✅ 安全：ORM filter/exclude 自动参数化
User.objects.filter(name=user_input)
User.objects.filter(name__contains=user_input)
User.objects.filter(name__iexact=user_input)
User.objects.exclude(status='inactive')

# ⚠️ 注意：contains/startswith/endswith 的 % 通配符由 Django 控制
# 用户无法注入额外 SQL，但可能影响 LIKE 模式匹配范围
```

### 2.3 动态 ORM lookup

```python
# ⚠️ 需警惕：动态字段名和 lookup 类型
field_name = request.GET.get('field')
lookup_type = request.GET.get('lookup', 'exact')
value = request.GET.get('value')

# 🔴 危险：用户控制字段名
User.objects.filter(**{f"{field_name}__{lookup_type}": value})
# 攻击者可设置 field_name 为 "password" 泄露密码

# ✅ 安全：白名单校验字段名
ALLOWED_FIELDS = {'name', 'email', 'created_at'}
ALLOWED_LOOKUPS = {'exact', 'contains', 'gte', 'lte'}
if field_name in ALLOWED_FIELDS and lookup_type in ALLOWED_LOOKUPS:
    User.objects.filter(**{f"{field_name}__{lookup_type}": value})
```

### 2.4 order_by()

```python
# ⚠️ 需警惕：用户控制排序字段
User.objects.order_by(request.GET.get('sort', 'id'))
# 攻击者可传入 SQL 表达式（Django 4.2+ 有部分防护）

# ✅ 安全：白名单
ALLOWED_SORT = ['name', '-name', 'created_at', '-created_at']
sort_field = request.GET.get('sort', 'id')
if sort_field in ALLOWED_SORT:
    User.objects.order_by(sort_field)
```

---

## 3. 已知 CVE

| CVE | 受影响版本 | 漏洞类型 | 要点 |
|-----|-----------|----------|------|
| CVE-2022-34265 | Django < 4.0.6, < 3.2.14 | SQL 注入 via `Trunc(kind=)` / `Extract(lookup_name=)` | 日期函数的 kind 参数未校验 |
| CVE-2021-35042 | Django < 3.1.13, < 3.2.5 | SQL 注入 via `QuerySet.order_by()` | 传入包含 SQL 注释的列名可注入 |
| CVE-2020-7471 | Django < 2.2.10, < 3.0.3 | SQL 注入 via `StringAgg(delimiter=)` | 分隔符参数未转义 |
| CVE-2019-14234 | Django < 2.1.11, < 2.2.4 | SQL 注入 via JSONField key transform | JSON 键路径注入 |

### Django 版本检查

```bash
pip show django | grep Version
# 或
python -c "import django; print(django.VERSION)"
```

---

## 4. 修复模板

### 4.1 raw() → 参数化

```python
# ❌ 修复前
def search_users(request):
    name = request.GET.get('name')
    return User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")

# ✅ 修复后
def search_users(request):
    name = request.GET.get('name')
    return User.objects.raw("SELECT * FROM users WHERE name = %s", [name])
```

### 4.2 cursor.execute() → 参数化

```python
# ❌ 修复前
from django.db import connection
cursor = connection.cursor()
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

# ✅ 修复后
from django.db import connection
cursor = connection.cursor()
cursor.execute("SELECT * FROM users WHERE email = %s", [email])
```

### 4.3 extra() → annotate / ORM 替代

```python
# ❌ 修复前（extra 已废弃）
User.objects.extra(where=["name = '%s'" % name])

# ✅ 修复后
User.objects.filter(name=name)
# 若需复杂表达式
from django.db.models import Value, CharField
User.objects.annotate(
    custom=Value(name, output_field=CharField())
).filter(custom=name)
```

### 4.4 动态排序白名单

```python
# ✅ 修复后
SORT_MAPPING = {
    'name': 'name',
    'name_desc': '-name',
    'date': 'created_at',
    'date_desc': '-created_at',
}

def list_users(request):
    sort_key = request.GET.get('sort', 'date')
    order_field = SORT_MAPPING.get(sort_key, 'created_at')
    return User.objects.order_by(order_field)
```
