# SQLAlchemy — SQL 注入模式库

---

## 1. 模式库（Pattern Library）

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `SQLA-TEXT-FSTR` | `text\s*\(\s*f["']` | 高 | `text()` 使用 f-string |
| `SQLA-TEXT-FORMAT` | `text\s*\(\s*["'].*\.format\(` | 高 | `text()` 使用 str.format() |
| `SQLA-TEXT-CONCAT` | `text\s*\(\s*["'].*\+` | 高 | `text()` 字符串拼接 |
| `SQLA-TEXT-PERCENT` | `text\s*\(\s*["'].*%\s` | 中 | `text()` % 格式化（需区分） |
| `SQLA-EXEC-FSTR` | `(execute\|exec)\s*\(\s*f["']` | 高 | execute 使用 f-string |
| `SQLA-EXEC-FORMAT` | `(session\|engine\|conn)\.execute\s*\(\s*["'].*\.format` | 高 | execute 使用 format() |
| `SQLA-EXEC-CONCAT` | `(session\|engine\|conn)\.execute\s*\(\s*["'].*\+` | 高 | execute 字符串拼接 |
| `SQLA-FILTER-TEXT` | `\.filter\s*\(\s*text\s*\(` | 中 | filter 中使用 text()（需检查参数化） |
| `SQLA-ORDER-TEXT` | `\.order_by\s*\(\s*text\s*\(` | 中 | order_by 中使用 text() |
| `SQLA-FROM-TEXT` | `\.from_statement\s*\(\s*text\s*\(` | 中 | from_statement 使用 text() |
| `SQLA-LITERAL-COL` | `literal_column\s*\(\s*[a-zA-Z_]` | 中 | literal_column 传入变量 |
| `SQLA-COLUMN-DYN` | `column\s*\(\s*[a-zA-Z_]` | 中 | 动态列名 |

---

## 2. 安全 vs 危险 API 对照

### 2.1 text()

```python
from sqlalchemy import text

# 🔴 危险：f-string 拼入 text()
result = session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))

# 🔴 危险：format() 拼入 text()
result = session.execute(text("SELECT * FROM users WHERE name = '{}'".format(name)))

# ✅ 安全：text() + 命名绑定参数
result = session.execute(
    text("SELECT * FROM users WHERE name = :name"),
    {"name": name}
)

# ✅ 安全：text() + bindparams
stmt = text("SELECT * FROM users WHERE name = :name").bindparams(name=name)
result = session.execute(stmt)
```

### 2.2 ORM 查询（通常安全）

```python
# ✅ 安全：ORM 自动参数化
session.query(User).filter(User.name == user_input).all()
session.query(User).filter_by(name=user_input).all()

# SQLAlchemy 2.0 风格
session.execute(select(User).where(User.name == user_input)).scalars().all()
```

### 2.3 literal_column / column

```python
from sqlalchemy import literal_column, column

# ⚠️ 需警惕：用户输入作为列名
sort_col = request.args.get('sort')
session.query(User).order_by(literal_column(sort_col))  # 🔴 危险

# ✅ 安全：白名单
ALLOWED = {'name': User.name, 'email': User.email}
order_col = ALLOWED.get(sort_col, User.name)
session.query(User).order_by(order_col)
```

---

## 3. 已知 CVE

| CVE | 受影响版本 | 漏洞类型 | 要点 |
|-----|-----------|----------|------|
| CVE-2019-7164 | SQLAlchemy < 1.3.0 | order_by/group_by 注入 | 传入 text() 包裹的用户输入可注入 |
| CVE-2019-7548 | SQLAlchemy < 1.2.18 | SQL 注入 via order_by | 原始字符串传入 order_by 可注入 |

---

## 4. 修复模板

### 4.1 text() 参数化

```python
# ❌ 修复前
def search(keyword, sort_field):
    sql = f"SELECT * FROM articles WHERE title LIKE '%{keyword}%' ORDER BY {sort_field}"
    return session.execute(text(sql)).fetchall()

# ✅ 修复后
ALLOWED_SORT = {'title': 'title', 'date': 'created_at', 'author': 'author_name'}

def search(keyword, sort_field):
    safe_sort = ALLOWED_SORT.get(sort_field, 'created_at')
    sql = text(f"SELECT * FROM articles WHERE title LIKE :pattern ORDER BY {safe_sort}")
    return session.execute(sql, {"pattern": f"%{keyword}%"}).fetchall()
```

### 4.2 ORM 动态条件

```python
# ❌ 修复前
def filter_users(**kwargs):
    conditions = []
    for key, val in kwargs.items():
        conditions.append(f"{key} = '{val}'")
    sql = "SELECT * FROM users WHERE " + " AND ".join(conditions)
    return session.execute(text(sql)).fetchall()

# ✅ 修复后
ALLOWED_FILTERS = {'name', 'email', 'status'}

def filter_users(**kwargs):
    query = session.query(User)
    for key, val in kwargs.items():
        if key in ALLOWED_FILTERS and hasattr(User, key):
            query = query.filter(getattr(User, key) == val)
    return query.all()
```

### 4.3 LIKE 安全处理

```python
# ❌ 修复前
session.execute(text(f"SELECT * FROM posts WHERE title LIKE '%{keyword}%'"))

# ✅ 修复后
from sqlalchemy import text

def escape_like(s: str) -> str:
    return s.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')

result = session.execute(
    text("SELECT * FROM posts WHERE title LIKE :pattern ESCAPE '\\\\'"),
    {"pattern": f"%{escape_like(keyword)}%"}
).fetchall()

# 或使用 ORM
from sqlalchemy import func
session.query(Post).filter(Post.title.contains(keyword)).all()
```
