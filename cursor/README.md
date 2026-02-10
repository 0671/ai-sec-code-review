# 工作流程
1. 在 cursor 中 配置 cursor 的command  
- 创建 User Commands `project-analysis`，内容在  [commands/project-analysis.md](./commands/project-analysis.md) 中。  
- 创建 User Commands `security-audit`，内容在  [commands/project-analysis.md](./commands/security-audit.md) 中。  
- 创建 User Commands `update-check`，内容在  [commands/project-analysis.md](./commands/update-check.md) 中。  

2. 在 cursor 中 打开项目

3. 在 cursor 的 chat 下（Agent模式），输入 /project-analysis 开始分析项目

4. 在 cursor 的 chat 下（Agent模式），输入 /security-audit 开始审计项目代码

4. 当项目变化时，在 cursor 的 chat 下（Agent模式），输入 /update-check 更新检查
