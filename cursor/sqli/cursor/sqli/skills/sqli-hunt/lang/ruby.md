# Ruby — SQL 注入 Source/Sink 模型

---

## 1. Source 模式（用户可控输入入口）

### 1.1 Rails

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `params[:key]` / `params['key']` | 请求参数 | GET/POST 合并 |
| `params.require(:key).permit(:field)` | Strong Parameters | 字段值仍可控 |
| `request.headers['HTTP_...']` | 请求头 | |
| `cookies[:key]` | Cookie | |
| `request.path` / `request.fullpath` | 请求路径 | |
| `request.query_string` | 原始查询字符串 | |
| `request.body.read` | 原始请求体 | |
| `request.remote_ip` | 客户端 IP | 可被 X-Forwarded-For 伪造 |

### 1.2 Sinatra

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `params[:key]` | 请求参数 | |
| `request.env['HTTP_...']` | 请求头 | |
| 路由块参数 | 路径参数 | `get '/user/:id' do ... params[:id]` |

### 1.3 Grape (API 框架)

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `params[:key]` | 请求参数 | Grape 参数 |
| `declared(params)` | 声明参数 | 类型验证后但值仍可控 |
| `headers['...']` | 请求头 | |

---

## 2. Sink 入口（危险 API 搜索起点）

### 2.1 ActiveRecord

```ruby
# 原生 SQL API
ActiveRecord::Base.connection.execute(sql)
ActiveRecord::Base.connection.exec_query(sql)
ActiveRecord::Base.connection.select_all(sql)
ActiveRecord::Base.connection.select_one(sql)
Model.find_by_sql(sql)
Model.count_by_sql(sql)

# 条件性危险（取决于参数来源和格式）
Model.where(condition_string)       # 字符串条件
Model.where(condition_string, val)  # 带占位符则安全
Model.order(sort_string)            # 动态排序
Model.group(group_string)           # 动态分组
Model.having(condition_string)      # 动态 HAVING
Model.joins(join_string)            # 动态 JOIN
Model.select(select_string)         # 动态 SELECT
Model.from(table_string)            # 动态表名
Model.pluck(Arel.sql(string))       # Arel.sql 包裹的原生 SQL

# 计算方法
Model.calculate(:sum, column_string)
Model.sum(column_string)
Model.average(column_string)
```

### 2.2 Sequel

```ruby
# Sequel ORM 危险 API
DB.run(sql)
DB.execute(sql)
DB.fetch(sql)
DB[sql]
dataset.where(Sequel.lit(string))
dataset.order(Sequel.lit(string))
```

---

## 3. 危险拼接模式

| 模式 | Grep 正则 | 危险等级 | 说明 |
|---|---|---|---|
| 字符串插值 | `"(SELECT\|INSERT\|UPDATE\|DELETE).*#\{` | 高 | Ruby `#{}` 字符串插值 |
| + 拼接 | `"(SELECT\|INSERT\|UPDATE\|DELETE).*"\s*\+` | 高 | 字符串拼接 |
| << 追加 | `(SELECT\|INSERT\|UPDATE\|DELETE).*<<` | 中 | 字符串追加 |
| % 格式化 | `"(SELECT\|INSERT\|UPDATE\|DELETE).*%` | 高 | 字符串格式化 |
| .where 字符串 | `\.where\s*\(\s*"[^"]*#\{` | 高 | where 中插值 |
| .order 字符串 | `\.order\s*\(\s*"[^"]*#\{` | 高 | order 中插值 |

### Ruby 特有陷阱：`#{}` 插值

```ruby
# 危险：字符串插值
User.where("name = '#{params[:name]}'")
User.where("name = '" + params[:name] + "'")

# 安全：参数化
User.where("name = ?", params[:name])
User.where(name: params[:name])
User.where("name = :name", name: params[:name])
```

---

## 4. 净化器模式

| 净化方式 | 代码模式 | 对值有效 | 对标识符有效 |
|---|---|---|---|
| 占位符 `?` | `.where("col = ?", val)` | ✅ | ❌ |
| 命名占位符 | `.where("col = :name", name: val)` | ✅ | ❌ |
| Hash 条件 | `.where(col: val)` | ✅ | ✅（键名固定） |
| .to_i / .to_f | `input.to_i` | ✅ | ❌ |
| 白名单 | `%w[name email created_at].include?(input)` | ✅ | ✅ |
| sanitize_sql | `ActiveRecord::Base.sanitize_sql(...)` | ✅ | ❌ |
| connection.quote | `connection.quote(val)` | ✅ | ❌ |
| connection.quote_column_name | `connection.quote_column_name(val)` | ❌ | ✅ |

---

## 5. 目录约定与搜索范围

### 5.1 应搜索的目录/文件

```
**/*.rb
**/app/models/**/*.rb
**/app/controllers/**/*.rb
**/app/services/**/*.rb
**/app/queries/**/*.rb
**/app/jobs/**/*.rb
**/app/workers/**/*.rb
**/lib/**/*.rb
**/app/graphql/**/*.rb
**/app/api/**/*.rb           # Grape API
```

### 5.2 应排除的目录

```
**/vendor/**
**/tmp/**
**/log/**
**/public/**
```

### 5.3 应单独标记的目录

```
**/db/migrate/**
**/db/seeds.rb
**/db/seeds/**
**/spec/**
**/test/**
```

---

## 6. 依赖文件解析

### 6.1 Gemfile 关键依赖

```
rails / activerecord           → framework/activerecord.md
sequel                         → (Sequel 模式在本文件 §2.2)
pg                             → database/postgresql.md
mysql2                         → database/mysql.md
sqlite3                        → database/sqlite.md
tiny_tds / activerecord-sqlserver-adapter → database/mssql.md
ruby-oci8 / activerecord-oracle_enhanced-adapter → database/oracle.md
```

---

## 7. Ruby/Rails 特有审计要点

### 7.1 `Arel.sql()` 的滥用

```ruby
# Arel.sql 将字符串标记为"安全 SQL"，绕过 Rails 的安全检查
User.order(Arel.sql(params[:sort]))              # 极其危险
User.pluck(Arel.sql("count(#{params[:col]})"))   # 极其危险

# Rails 5.2+ 对不安全的 order/pluck 字符串会发出弃用警告
# 开发者可能用 Arel.sql 来消除警告，反而引入注入
```

### 7.2 Scope 中的隐藏拼接

```ruby
# Model 中定义的 scope 可能包含隐藏的拼接
scope :search, ->(term) { where("name LIKE '%#{term}%'") }  # 危险
scope :search, ->(term) { where("name LIKE ?", "%#{term}%") }  # 安全
```

### 7.3 Rails SQL 注入常见位置

Rails 官方文档标注的危险方法列表：
`where` / `order` / `group` / `having` / `joins` / `reorder` / `reverse_order` / `from` / `select` / `pluck` / `find_by` / `calculate` / `sum` / `average` / `minimum` / `maximum` / `count` / `delete_all` / `update_all`

以上方法在接收字符串参数时都可能存在注入风险。

---

## 8. 支持的框架模块

- `framework/activerecord.md`
