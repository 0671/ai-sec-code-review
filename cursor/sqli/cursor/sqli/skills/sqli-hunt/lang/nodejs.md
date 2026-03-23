# Node.js / TypeScript — SQL 注入 Source/Sink 模型

---

## 1. Source 模式（用户可控输入入口）

### 1.1 Express / Koa / Fastify — HTTP 请求

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `req.query.*` / `req.query['...']` | GET 参数 | Express/Koa 查询字符串 |
| `req.params.*` / `req.params['...']` | 路径参数 | Express 路由参数 `:id` |
| `req.body.*` / `req.body['...']` | 请求体 | POST/PUT/PATCH body |
| `req.headers['...']` / `req.get('...')` | 请求头 | 自定义头 X-Username 等 |
| `req.cookies['...']` | Cookie | 客户端可控 |
| `ctx.query.*` | GET 参数 | Koa 风格 |
| `ctx.params.*` | 路径参数 | Koa 风格 |
| `ctx.request.body.*` | 请求体 | Koa 风格 |
| `request.query.*` | GET 参数 | Fastify 风格 |
| `request.params.*` | 路径参数 | Fastify 风格 |
| `request.body.*` | 请求体 | Fastify 风格 |

### 1.2 GraphQL 解析器

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `args.*`（resolver 第二个参数） | GraphQL 参数 | 客户端可控 |
| `input.*`（mutation input 类型） | GraphQL Input | 客户端可控 |
| `context.req.headers['...']` | 请求头 | 通过 context 透传 |

### 1.3 WebSocket

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `message` / `data`（ws.on('message', ...)） | WS 消息 | 客户端可控 |
| `socket.handshake.query.*` | WS 握手参数 | Socket.IO 风格 |

### 1.4 Serverless / 消息队列

| Source 表达式 | 类型 | 说明 |
|---|---|---|
| `event.queryStringParameters.*` | API Gateway 参数 | AWS Lambda |
| `event.body` | API Gateway Body | AWS Lambda |
| `event.pathParameters.*` | API Gateway 路径 | AWS Lambda |
| `message.value` / `message.body` | MQ 消息 | Kafka/RabbitMQ/SQS（间接可控） |

---

## 2. Sink 入口（危险 API 搜索起点）

以下为 Node.js 生态中所有可能执行 SQL 的 API，搜索时应全部覆盖：

### 2.1 通用原生驱动

```
# pg (PostgreSQL)
pool.query(  |  client.query(

# mysql2
connection.query(  |  connection.execute(  |  pool.query(  |  pool.execute(

# better-sqlite3
db.prepare(  |  db.exec(

# sqlite3
db.run(  |  db.get(  |  db.all(  |  db.each(

# mssql (tedious)
request.query(  |  request.batch(
```

### 2.2 ORM 危险 API

详见各框架模块。以下为快速索引：

| ORM | 危险 API |
|---|---|
| Sequelize | `sequelize.query()` / `Sequelize.literal()` / `Sequelize.fn()` / `Sequelize.where()` / `Sequelize.col()` |
| TypeORM | `.query()` / `.createQueryBuilder()` 的 `.where()` `.orderBy()` + 字符串 |
| Prisma | `$queryRawUnsafe()` / `$executeRawUnsafe()` / `$queryRaw()` 非标签模板 |
| Knex | `knex.raw()` / `.whereRaw()` / `.orderByRaw()` / `.havingRaw()` / `.joinRaw()` |

---

## 3. 净化器模式

| 净化方式 | 代码模式 | 对值有效 | 对标识符有效 |
|---|---|---|---|
| 白名单 | `allowedFields.includes(input)` | ✅ | ✅ |
| parseInt | `parseInt(input, 10)` / `Number(input)` | ✅（纯数字场景） | ❌ |
| TS 枚举 | `enum SortField { Name = 'name' }` | ✅ | ✅（前提：值不来自外部） |
| Sequelize escape | `sequelize.escape(input)` | ✅ | ❌ |
| pg escapeLiteral | `pg.escapeLiteral(input)` | ✅ | ❌ |
| pg escapeIdentifier | `pg.escapeIdentifier(input)` | ❌ | ✅ |
| 正则过滤 | `/[^a-zA-Z0-9_]/g` | ⚠️ 需审查 | ⚠️ 需审查 |
| validator.js | `validator.isAlphanumeric(input)` | ✅ | ✅（alphanumeric 场景） |

---

## 4. 目录约定与搜索范围

### 4.1 应搜索的目录

```
**/src/**/*.ts
**/src/**/*.js
**/lib/**/*.ts
**/lib/**/*.js
**/app/**/*.ts          # NestJS / Next.js API routes
**/pages/api/**/*.ts    # Next.js pages API routes
**/server/**/*.ts
**/api/**/*.ts
**/services/**/*.ts
**/controllers/**/*.ts
**/repositories/**/*.ts
**/models/**/*.ts
**/dao/**/*.ts
**/routes/**/*.ts
**/resolvers/**/*.ts    # GraphQL resolvers
**/handlers/**/*.ts     # Lambda handlers
```

### 4.2 应排除的目录

```
**/node_modules/**
**/dist/**
**/build/**
**/.next/**
**/.nuxt/**
**/coverage/**
**/*.test.ts
**/*.spec.ts
**/__tests__/**
**/__mocks__/**
```

### 4.3 应单独标记的目录（搜索但标记为信息级别）

```
**/migrations/**
**/seeders/**
**/seeds/**
**/fixtures/**
```

---

## 5. 依赖文件解析

### 5.1 package.json 关键依赖

```json
{
  "dependencies": {
    "sequelize": "→ framework/sequelize.md",
    "typeorm": "→ framework/typeorm.md",
    "@prisma/client": "→ framework/prisma.md",
    "knex": "→ framework/knex.md",
    "pg": "→ database/postgresql.md",
    "mysql2": "→ database/mysql.md",
    "better-sqlite3": "→ database/sqlite.md",
    "sqlite3": "→ database/sqlite.md",
    "mssql": "→ database/mssql.md",
    "tedious": "→ database/mssql.md",
    "oracledb": "→ database/oracle.md"
  }
}
```

### 5.2 连接初始化搜索

```
# Sequelize
new Sequelize(

# TypeORM
createConnection(  |  DataSource(

# Prisma
new PrismaClient(

# Knex
knex({  |  require('knex')(

# 原生 pg
new Pool(  |  new Client(

# 原生 mysql2
mysql.createConnection(  |  mysql.createPool(
```

---

## 6. 支持的框架模块

- `framework/sequelize.md`
- `framework/typeorm.md`
- `framework/prisma.md`
- `framework/knex.md`
