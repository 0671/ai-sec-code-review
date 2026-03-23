## 架构总览

```
.cursor/
├── commands/
│   └── sqli-audit.md                       ← 审计流程编排（/sqli-audit 触发）
├── skills/
│   └── sqli-hunt/
│       ├── SKILL.md                        ← 核心引擎：判定树 + 严重性矩阵 + 方法论（语言无关）
│       ├── lang/                           ← 语言层：Source/Sink 模型 + 目录约定
│       │   ├── nodejs.md
│       │   ├── python.md
│       │   ├── java.md
│       │   ├── go.md
│       │   ├── php.md
│       │   ├── csharp.md
│       │   └── ruby.md
│       ├── framework/                      ← 框架层：模式库 + CVE + 修复模板
│       │   ├── sequelize.md
│       │   ├── typeorm.md
│       │   ├── prisma.md
│       │   ├── knex.md
│       │   ├── mybatis.md
│       │   ├── hibernate.md
│       │   ├── django-orm.md
│       │   ├── sqlalchemy.md
│       │   ├── gorm.md
│       │   ├── laravel-eloquent.md
│       │   ├── activerecord.md
│       │   └── entity-framework.md
│       └── database/                       ← 数据库层：引擎特异性知识 + 严重性修正
│           ├── postgresql.md
│           ├── mysql.md
│           ├── mssql.md
│           ├── sqlite.md
│           └── oracle.md
└── rules/                                  ← 被动拦截：按语言拆分，各自配 globs
    ├── sqli-guard-nodejs.mdc
    ├── sqli-guard-python.mdc
    ├── sqli-guard-java.mdc
    ├── sqli-guard-go.mdc
    ├── sqli-guard-php.mdc
    ├── sqli-guard-csharp.mdc
    └── sqli-guard-ruby.mdc
```

---

## 设计原则

### 三层知识分离

| 层 | 职责 | 加载时机 |
|---|---|---|
| **核心引擎**（SKILL.md） | 判定树、严重性矩阵、二阶注入方法论、误报指南、合规边界 | 每次审计必加载 |
| **语言层**（lang/*.md） | 该语言的 Source 模型、Sink 入口、净化器模式、目录约定 | Phase 0 识别语言后按需加载 |
| **框架层**（framework/*.md） | 具体 ORM/驱动的 grep 正则、已知 CVE、修复模板 | Phase 0 识别依赖后按需加载 |
| **数据库层**（database/*.md） | 引擎特有注入技法、严重性修正因子、数据外带方法 | Phase 0 识别数据库后按需加载 |

### 按需加载

Agent 在 Phase 0 完成技术画像后，仅 Read 项目实际使用的模块文件。一个 Spring Boot + MyBatis + MySQL 项目只会加载：
- `SKILL.md`（核心）
- `lang/java.md`
- `framework/mybatis.md`
- `database/mysql.md`

不会浪费 context window 去加载 Sequelize、Django 等无关知识。

### 分工

- **Command** 管「做什么、按什么顺序做、何时加载什么知识」
- **Skill 核心** 管「怎么判断、用什么决策逻辑」
- **Skill 插件** 管「具体技术栈的模式识别与修复方案」
- **Rule** 管「日常写代码时的被动拦截，按语言独立配置」

---

## 使用方式

### 日常开发

Rule 按语言自动生效。当你在对应目录编写数据库查询时，Agent 主动提醒注入风险。每种语言的 Rule 有独立的 globs 和禁止/必须规则，不会互相干扰。

### 按需审计

在 Cursor 聊天框输入 `/sqli-audit`，Agent 执行：
1. Phase 0 识别技术栈
2. Phase 0.5 按需加载对应知识模块
3. Phase 1-5 执行完整审计流程

### 工作流图

```
/sqli-audit (Command 触发)
    │
    ├── Phase 0: 技术画像
    │   └── 读 package.json / requirements.txt / go.mod / pom.xml / *.csproj / Gemfile
    │       → 识别语言、ORM/驱动、数据库类型
    │
    ├── Phase 0.5: 知识按需加载 ★ 新增
    │   ├── Read lang/{detected_language}.md        → Source/Sink 模型
    │   ├── Read framework/{detected_framework}.md  → 模式库 + CVE + 修复模板
    │   └── Read database/{detected_database}.md    → 引擎特异性 + 严重性修正
    │
    ├── Phase 1: 按加载的模式库 grep → 候选清单
    ├── Phase 2: 按核心引擎判定树 → 污点追踪
    ├── Phase 3: 按核心引擎严重性矩阵 + 数据库修正 → 风险分级
    ├── Phase 4: 按核心引擎二阶方法论 → 二阶注入专项
    └── Phase 5: 输出结构化报告（含框架特定修复代码）
```

---

## 扩展指南

### 新增语言支持

1. 在 `lang/` 下新建 `{language}.md`，定义 Source/Sink/Sanitizer/目录约定
2. 在 `rules/` 下新建 `sqli-guard-{language}.mdc`，配置 globs 和被动规则
3. 在 `framework/` 下为该语言的主流 ORM 各建一个文件

### 新增框架支持

1. 在 `framework/` 下新建 `{framework}.md`
2. 必须包含：模式库表格、安全/危险 API 对照、修复模板、已知 CVE
3. 在对应 `lang/*.md` 的"支持框架列表"中添加引用

### 新增数据库支持

1. 在 `database/` 下新建 `{database}.md`
2. 必须包含：引擎特有注入技法、严重性修正规则、数据外带方法
