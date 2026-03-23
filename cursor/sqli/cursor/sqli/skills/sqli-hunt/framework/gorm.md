# GORM (Go) — SQL 注入模式库

---

## 1. 模式库（Pattern Library）

| ID | Grep 正则 | 危险等级 | 说明 |
|----|-----------|----------|------|
| `GORM-RAW-SPRINTF` | `\.Raw\s*\(\s*fmt\.Sprintf` | 高 | `db.Raw()` 使用 fmt.Sprintf |
| `GORM-RAW-CONCAT` | `\.Raw\s*\(\s*".*\+` | 高 | `db.Raw()` 字符串拼接 |
| `GORM-RAW-VAR` | `\.Raw\s*\(\s*[a-zA-Z_]\w*\s*[,\)]` | 中 | `db.Raw()` 传入变量（需追踪） |
| `GORM-EXEC-SPRINTF` | `\.Exec\s*\(\s*fmt\.Sprintf` | 高 | `db.Exec()` 使用 fmt.Sprintf |
| `GORM-EXEC-CONCAT` | `\.Exec\s*\(\s*".*\+` | 高 | `db.Exec()` 字符串拼接 |
| `GORM-WHERE-SPRINTF` | `\.Where\s*\(\s*fmt\.Sprintf` | 高 | `db.Where()` 使用 fmt.Sprintf |
| `GORM-WHERE-CONCAT` | `\.Where\s*\(\s*".*\+` | 高 | `db.Where()` 字符串拼接 |
| `GORM-ORDER-VAR` | `\.Order\s*\(\s*[a-zA-Z_]\w*\s*\)` | 高 | `db.Order()` 传入变量（极易注入） |
| `GORM-ORDER-SPRINTF` | `\.Order\s*\(\s*fmt\.Sprintf` | 高 | `db.Order()` 使用 fmt.Sprintf |
| `GORM-SELECT-VAR` | `\.Select\s*\(\s*[a-zA-Z_]\w*\s*[,\)]` | 中 | `db.Select()` 传入变量 |
| `GORM-GROUP-VAR` | `\.Group\s*\(\s*[a-zA-Z_]\w*\s*\)` | 中 | `db.Group()` 传入变量 |
| `GORM-HAVING-CONCAT` | `\.Having\s*\(\s*".*(\+\|Sprintf)` | 高 | `db.Having()` 拼接 |
| `GORM-TABLE-VAR` | `\.Table\s*\(\s*[a-zA-Z_]\w*\s*\)` | 中 | `db.Table()` 动态表名 |
| `GORM-JOINS-CONCAT` | `\.Joins\s*\(\s*".*(\+\|Sprintf)` | 高 | `db.Joins()` 拼接 |

---

## 2. 安全 vs 危险 API 对照

### 2.1 Where()

```go
// 🔴 危险：字符串拼接
db.Where("name = '" + name + "'").Find(&users)

// 🔴 危险：fmt.Sprintf
db.Where(fmt.Sprintf("name = '%s'", name)).Find(&users)

// ✅ 安全：占位符参数化
db.Where("name = ?", name).Find(&users)

// ✅ 安全：结构体条件
db.Where(&User{Name: name}).Find(&users)

// ✅ 安全：Map 条件
db.Where(map[string]interface{}{"name": name}).Find(&users)
```

### 2.2 Order()

```go
// 🔴 危险：直接传入用户输入（GORM v2 不做任何过滤）
db.Order(sortField).Find(&users)

// 🔴 危险：fmt.Sprintf
db.Order(fmt.Sprintf("%s %s", sortField, sortOrder)).Find(&users)

// ✅ 安全：白名单
allowedSort := map[string]string{
    "name": "name", "date": "created_at", "email": "email",
}
allowedOrder := map[string]bool{"asc": true, "desc": true}

col, ok := allowedSort[sortField]
if !ok { col = "created_at" }
ord := "asc"
if allowedOrder[strings.ToLower(sortOrder)] { ord = sortOrder }

db.Order(col + " " + ord).Find(&users)
```

### 2.3 Raw() / Exec()

```go
// 🔴 危险：fmt.Sprintf
db.Raw(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id)).Scan(&users)
// 即使 %d 是数值，攻击者可能通过类型转换绕过

// ✅ 安全：占位符
db.Raw("SELECT * FROM users WHERE id = ?", id).Scan(&users)
```

### 2.4 Select() / Group()

```go
// ⚠️ 需警惕：用户控制 select 字段
db.Select(userInput).Find(&users)   // 🔴 危险
db.Group(userInput).Find(&users)    // 🔴 危险

// ✅ 安全：白名单
allowedFields := []string{"name", "email", "created_at"}
var safeFields []string
for _, f := range requestedFields {
    for _, a := range allowedFields {
        if f == a { safeFields = append(safeFields, f) }
    }
}
db.Select(safeFields).Find(&users)
```

---

## 3. GORM 特有风险

### 3.1 GORM v1 vs v2 差异

| 特性 | GORM v1 (jinzhu/gorm) | GORM v2 (gorm.io/gorm) |
|------|----------------------|------------------------|
| `Order()` 安全性 | 无过滤 | 无过滤 |
| `Where()` 字符串 | 无过滤 | 无过滤 |
| `Clause` API | 不存在 | 存在（更安全的替代） |
| SQL 注入防护 | 依赖开发者 | 依赖开发者 |

### 3.2 GORM 的 `clause.Expr`

```go
// ⚠️ 需检查：clause.Expr 可包含原生 SQL
db.Clauses(clause.Expr{SQL: "name = ?", Vars: []interface{}{name}})  // ✅ 安全
db.Clauses(clause.Expr{SQL: "name = '" + name + "'"})  // 🔴 危险
```

---

## 4. 修复模板

### 4.1 动态查询参数化

```go
// ❌ 修复前
func SearchUsers(db *gorm.DB, name, email, sort string) []User {
    query := db.Model(&User{})
    if name != "" {
        query = query.Where(fmt.Sprintf("name LIKE '%%%s%%'", name))
    }
    if email != "" {
        query = query.Where(fmt.Sprintf("email = '%s'", email))
    }
    query = query.Order(sort)

    var users []User
    query.Find(&users)
    return users
}

// ✅ 修复后
var allowedSortFields = map[string]string{
    "name": "name", "email": "email", "date": "created_at",
}

func SearchUsers(db *gorm.DB, name, email, sort string) []User {
    query := db.Model(&User{})
    if name != "" {
        query = query.Where("name LIKE ?", "%"+name+"%")
    }
    if email != "" {
        query = query.Where("email = ?", email)
    }

    sortCol, ok := allowedSortFields[sort]
    if !ok { sortCol = "created_at" }
    query = query.Order(sortCol + " ASC")

    var users []User
    query.Find(&users)
    return users
}
```

### 4.2 IN 子句

```go
// ❌ 修复前
ids := strings.Join(idStrings, ",")
db.Raw(fmt.Sprintf("SELECT * FROM users WHERE id IN (%s)", ids)).Scan(&users)

// ✅ 修复后
db.Where("id IN ?", idInts).Find(&users)
// 或
db.Raw("SELECT * FROM users WHERE id IN ?", idInts).Scan(&users)
```
