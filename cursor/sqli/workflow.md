## 架构总览

```
.cursor/
├── commands/
│   └── sqli-audit.md          ← 审计流程编排（/sqli-audit 触发）
├── skills/
│   └── sqli-hunt/
│       └── SKILL.md           ← 方法论 + 模式库 + 判定树
└── rules/
    └── sqli-guard.mdc         ← 日常开发时的被动提醒
```

- **分工**：
- Command 管「**做什么、按什么顺序做**」
- Skill 管「**怎么判断、用什么知识**」
- Rule 管「**日常写代码时的被动拦截**」。


## 使用方式

### 日常开发

Rule 自动生效。当你在 `services/`、`controllers/` 等目录编写数据库查询时，Agent 会主动提醒注入风险。

### 按需审计

在 Cursor 聊天框输入 `/sqli-audit`，Agent 按 Command 的六个阶段自动执行完整审计，过程中引用 Skill 的模式库和判定树作为知识支撑。

### 工作流图

```
/sqli-audit (Command 触发)
    │
    ├── 阶段0: 读 package.json → 技术画像
    ├── 阶段1: 按 Skill§1 模式库 grep → 候选清单
    ├── 阶段2: 按 Skill§2 判定树 → 污点追踪
    ├── 阶段3: 按 Skill§4 严重性矩阵 → 风险分级
    ├── 阶段4: 按 Skill§3 方法 → 二阶注入专项
    └── 阶段5: 输出结构化报告
                │
                ├── 发现明细（文件/行号/Source/Sink/修复建议）
                └── 修复代码示例（引用 Skill§6 模板）
```
