# ActiveRecord (Ruby on Rails) — SQL 注入模式库

---

## 1. 模式库（Pattern Library）

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `AR-WHERE-INTERP` | `\.where\s*\(\s*"[^"]*#\{` | 高 | `.where()` 含 Ruby 字符串插值 |
| `AR-WHERE-CONCAT` | `\.where\s*\(\s*["'].*\+` | 高 | `.where()` 字符串拼接 |
| `AR-ORDER-INTERP` | `\.order\s*\(\s*"[^"]*#\{` | 高 | `.order()` 含插值 |
| `AR-ORDER-VAR` | `\.order\s*\(\s*[a-z_]\w*\s*\)` | 中 | `.order()` 传入变量 |
| `AR-AREL-SQL` | `Arel\.sql\s*\(\s*[^"']` | 高 | `Arel.sql()` 传入变量（危险） |
| `AR-AREL-SQL-INTERP` | `Arel\.sql\s*\(\s*"[^"]*#\{` | 高 | `Arel.sql()` 含插值 |
| `AR-FIND-BY-SQL` | `\.find_by_sql\s*\(\s*["'].*#\{` | 高 | `find_by_sql` 含插值 |
| `AR-EXEC-INTERP` | `\.execute\s*\(\s*"[^"]*#\{` | 高 | `connection.execute` 含插值 |
| `AR-JOINS-INTERP` | `\.joins\s*\(\s*"[^"]*#\{` | 高 | `.joins()` 含插值 |
| `AR-SELECT-INTERP` | `\.select\s*\(\s*"[^"]*#\{` | 中 | `.select()` 含插值 |
| `AR-GROUP-INTERP` | `\.group\s*\(\s*"[^"]*#\{` | 中 | `.group()` 含插值 |
| `AR-HAVING-INTERP` | `\.having\s*\(\s*"[^"]*#\{` | 高 | `.having()` 含插值 |
| `AR-PLUCK-AREL` | `\.pluck\s*\(\s*Arel\.sql` | 中 | `.pluck()` 使用 Arel.sql |
| `AR-UPDATE-ALL` | `\.update_all\s*\(\s*"[^"]*#\{` | 高 | `update_all` 含插值 |
| `AR-DELETE-ALL` | `\.delete_all\s*\(\s*"[^"]*#\{` | 高 | `delete_all` 含插值 |

---

## 2. 安全 vs 危险 API 对照

### 2.1 where()

```ruby
# 🔴 危险：字符串插值
User.where("name = '#{params[:name]}'")

# 🔴 危险：字符串拼接
User.where("name = '" + params[:name] + "'")

# ✅ 安全：占位符
User.where("name = ?", params[:name])

# ✅ 安全：命名占位符
User.where("name = :name", name: params[:name])

# ✅ 安全：Hash 条件
User.where(name: params[:name])
```

### 2.2 order()

```ruby
# 🔴 危险：直接传入用户输入
User.order(params[:sort])

# 🔴 危险：插值
User.order("#{params[:sort]} #{params[:dir]}")

# 🔴 危险：用 Arel.sql 消除 Rails 警告但引入注入
User.order(Arel.sql(params[:sort]))

# ✅ 安全：白名单 + 符号
ALLOWED = { 'name' => :name, 'date' => :created_at }
DIRECTIONS = { 'asc' => :asc, 'desc' => :desc }
col = ALLOWED[params[:sort]] || :created_at
dir = DIRECTIONS[params[:dir]] || :asc
User.order(col => dir)
```

### 2.3 find_by_sql / count_by_sql

```ruby
# 🔴 危险
User.find_by_sql("SELECT * FROM users WHERE name = '#{name}'")

# ✅ 安全
User.find_by_sql(["SELECT * FROM users WHERE name = ?", name])
```

---

## 3. Rails 版本安全特性

| 版本 | 安全改进 |
|------|----------|
| Rails 5.2+ | `order()` 传入非属性名字符串时发出弃用警告 |
| Rails 6.0+ | 弃用警告变为错误（但 `Arel.sql` 可绕过） |
| Rails 6.1+ | `where` 条件更严格的类型检查 |
| Rails 7.0+ | 更多方法默认拒绝原始字符串 |

---

## 4. 修复模板

### 4.1 where 插值 → 参数化

```ruby
# ❌ 修复前
def search(keyword)
  User.where("name LIKE '%#{keyword}%'")
end

# ✅ 修复后
def search(keyword)
  User.where("name LIKE ?", "%#{keyword}%")
end
```

### 4.2 scope 安全化

```ruby
# ❌ 修复前
scope :by_status, ->(status) { where("status = '#{status}'") }

# ✅ 修复后
scope :by_status, ->(status) { where(status: status) }
```

### 4.3 动态排序白名单

```ruby
# ✅ 修复后
SORT_FIELDS = %w[name email created_at updated_at].freeze
SORT_DIRS = %w[asc desc].freeze

def self.sorted(field, direction)
  safe_field = SORT_FIELDS.include?(field) ? field : 'created_at'
  safe_dir = SORT_DIRS.include?(direction&.downcase) ? direction.downcase : 'asc'
  order("#{safe_field} #{safe_dir}")
end
```

### 4.4 update_all / delete_all

```ruby
# ❌ 修复前
User.where(active: true).update_all("score = score + #{bonus}")

# ✅ 修复后
User.where(active: true).update_all(["score = score + ?", bonus])
```
