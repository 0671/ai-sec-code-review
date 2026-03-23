# Python — SQL 注入 Source/Sink 模型

---

## 1. Source 模式（用户可控输入入口）

### 1.1 Django

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `request.GET['...']` / `request.GET.get('...')` | GET 参数 | QueryDict |
| `request.POST['...']` / `request.POST.get('...')` | POST 参数 | QueryDict |
| `request.data` / `request.data['...']` | 请求体 | DRF 解析后数据 |
| `request.query_params['...']` / `request.query_params.get('...')` | GET 参数 | DRF 风格 |
| `request.FILES['...']` | 上传文件 | 文件名可控 |
| `request.META['HTTP_...']` | 请求头 | 自定义头 |
| `request.COOKIES['...']` | Cookie | 客户端可控 |
| `kwargs['...']`（视图函数参数） | URL 路径参数 | URLconf 捕获组 |
| `self.kwargs['...']` | URL 路径参数 | CBV 中的路径参数 |
| `self.request.query_params` | GET 参数 | DRF ViewSet |

### 1.2 Flask

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `request.args.get('...')` / `request.args['...']` | GET 参数 | |
| `request.form.get('...')` / `request.form['...']` | POST 表单 | |
| `request.json` / `request.get_json()` | JSON 请求体 | |
| `request.headers.get('...')` | 请求头 | |
| `request.cookies.get('...')` | Cookie | |
| `request.files['...']` | 上传文件 | 文件名可控 |
| 路由函数参数 | URL 路径参数 | `@app.route('/user/<user_id>')` 的 `user_id` |

### 1.3 FastAPI

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| 路由函数参数（无注解或 `Query()`） | GET 参数 | FastAPI 自动绑定 |
| 路由函数参数 + `Path()` | 路径参数 | |
| 路由函数参数 + `Body()` | 请求体 | |
| 路由函数参数 + `Header()` | 请求头 | |
| 路由函数参数 + `Cookie()` | Cookie | |
| Pydantic Model 字段 | 请求体字段 | `async def create(item: Item)` |

### 1.4 消息队列 / Celery

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| Celery task 参数 | 间接可控 | 若调用方传入用户输入 |
| `message.body` / `message.payload` | MQ 消息 | RabbitMQ/Kafka |

---

## 2. Sink 入口（危险 API 搜索起点）

### 2.1 Django ORM

```python
# 危险 API（需检查参数化）
Model.objects.raw(             # 原生 SQL
Model.objects.extra(           # 已废弃但仍可用
RawSQL(                        # 原生 SQL 表达式
connection.cursor().execute(   # 最底层原生执行
cursor.execute(                # 原生游标执行

# 条件性危险（取决于参数来源）
.annotate(... RawSQL(...))     # 注解中使用 RawSQL
.order_by(user_input)          # 动态排序（若未校验）
.extra(where=[...])            # extra 条件
```

### 2.2 SQLAlchemy

```python
# 危险 API
text(                          # text() 构造 SQL 片段
session.execute(               # 执行原生 SQL
engine.execute(                # 引擎级执行
connection.execute(            # 连接级执行

# 条件性危险
.filter(text(...))             # filter 中使用 text()
.order_by(text(...))           # 动态排序
.from_statement(text(...))     # 完整语句替换
```

### 2.3 原生驱动

```python
# psycopg2 / psycopg3
cursor.execute(                # PostgreSQL
cursor.executemany(

# PyMySQL / mysqlclient
cursor.execute(                # MySQL
cursor.executemany(

# sqlite3
cursor.execute(                # SQLite
cursor.executemany(
conn.execute(
conn.executescript(            # 危险：执行多条语句

# asyncpg
conn.fetch(                    # PostgreSQL async
conn.fetchrow(
conn.execute(
```

---

## 3. 危险拼接模式

Python 有多种字符串格式化方式，每种都可能导致 SQL 注入：

| 模式 | Grep 正则 | 危险等级 | 说明 |
|---|---|---|---|
| f-string | `f["'](SELECT\|INSERT\|UPDATE\|DELETE)` | 高 | Python 3.6+ f-string |
| .format() | `(SELECT\|INSERT\|UPDATE\|DELETE).*\.format\(` | 高 | str.format() |
| % 格式化 | `(SELECT\|INSERT\|UPDATE\|DELETE).*%\s` | 高 | 旧式 % 格式化（非 %s 参数化） |
| + 拼接 | `(SELECT\|INSERT\|UPDATE\|DELETE).*["']\s*\+` | 高 | 字符串拼接 |
| .join() | `IN\s*\(\s*.*\.join\(` | 中 | 数组 join 构建 IN 子句 |

### 区分安全与危险的 %s

```python
# 危险：% 格式化拼入 SQL
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)

# 安全：%s 作为参数化占位符（第二个参数传入值）
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))

# 关键区别：第二种 %s 后面有逗号分隔的参数元组
```

---

## 4. 净化器模式

| 净化方式 | 代码模式 | 对值有效 | 对标识符有效 |
|---|---|---|---|
| 白名单 | `if input in allowed_fields:` | ✅ | ✅ |
| int() | `int(input)` | ✅ | ❌ |
| Django F 表达式 | `F('field_name')` | ✅（ORM 处理） | ✅ |
| psycopg2 sql 模块 | `sql.Identifier(input)` | ❌ | ✅ |
| psycopg2 sql 模块 | `sql.Literal(input)` | ✅ | ❌ |
| bleach / markupsafe | HTML 净化 | ❌（HTML≠SQL） | ❌ |
| re.sub | `re.sub(r'[^a-zA-Z0-9_]', '', input)` | ⚠️ | ⚠️ |

---

## 5. 目录约定与搜索范围

### 5.1 应搜索的目录

```
**/*.py
**/views.py
**/views/**/*.py
**/serializers.py
**/serializers/**/*.py
**/models.py
**/models/**/*.py
**/managers.py
**/services/**/*.py
**/repositories/**/*.py
**/tasks.py                # Celery tasks
**/tasks/**/*.py
**/api/**/*.py
**/endpoints/**/*.py
**/routers/**/*.py         # FastAPI routers
**/crud/**/*.py
**/db/**/*.py
**/queries/**/*.py
```

### 5.2 应排除的目录

```
**/venv/**
**/.venv/**
**/env/**
**/__pycache__/**
**/site-packages/**
**/*.egg-info/**
**/dist/**
**/build/**
```

### 5.3 应单独标记的目录

```
**/migrations/**
**/alembic/**
**/fixtures/**
**/tests/**
**/test_*.py
**/*_test.py
**/conftest.py
```

---

## 6. 依赖文件解析

### 6.1 requirements.txt / pyproject.toml 关键依赖

```
django / Django            → framework/django-orm.md
sqlalchemy / SQLAlchemy    → framework/sqlalchemy.md
flask-sqlalchemy           → framework/sqlalchemy.md
psycopg2 / psycopg2-binary / psycopg → database/postgresql.md
asyncpg                    → database/postgresql.md
pymysql / mysqlclient      → database/mysql.md
aiomysql                   → database/mysql.md
sqlite3（标准库）           → database/sqlite.md
aiosqlite                  → database/sqlite.md
pyodbc / pymssql           → database/mssql.md
cx_Oracle / oracledb       → database/oracle.md
```

### 6.2 连接初始化搜索

```python
# Django
DATABASES = {           # settings.py 中数据库配置

# SQLAlchemy
create_engine(          # 引擎创建
sessionmaker(           # Session 工厂

# psycopg2
psycopg2.connect(

# PyMySQL
pymysql.connect(

# sqlite3
sqlite3.connect(
```

---

## 7. 支持的框架模块

- `framework/django-orm.md`
- `framework/sqlalchemy.md`
