---
name: rapid-checklist
description: 渗透速查与Payload — 快速Payload家族、绕过提醒、验证顺序、常见测试卡片，适用于已知测试方向后快速查找
---

# 渗透速查与 Payload Skill

**仅在路由已明确后使用**。本 Skill 用于快速查找，不替代方法论或工作流选择。

## 使用场景

- 快速回忆某类漏洞或阻塞点应该先看什么
- 快速筛选 Payload 家族、绕过方向和验证顺序
- 快速确认 AI、MCP、容器、WebSocket、JWT、文件、认证、SSRF 等常见测试卡片
- 从"我知道要测什么"进入"我先从哪一类验证开始"

## 不适用场景

- 替代场景分流 → 用 `pentest-flow`
- 替代方法论决策 → 用对应专项 Skill
- 请求未抓到、重放未稳定时盲测 → 先用 `client-reverse`

## 快速路由卡片

### Web 注入 / 输出执行
- SQLi → `'`, `"`, `)`, 布尔差异, 时间差异, 报错差异
- XSS → `<script>`, `<img onerror>`, `javascript:`, DOM sink
- 命令注入 → `;id`, `|id`, `` `id` ``, `$(id)`
- SSTI → `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, 模板引擎指纹
- XXE → `<!ENTITY>`, 参数实体, OOB 外带

### 认证 / 逻辑 / Token
- JWT → none算法, 算法篡改, 密钥爆破, jku/x5u 注入
- CSRF → 缺少 Token, Token 可预测, Referer 校验缺陷
- IDOR → 修改 ID 参数, 批量遍历
- 支付逻辑 → 金额篡改, 负数, 竞态

### 浏览器签名 / 反爬
- 先用 `client-reverse` 稳定重放
- 阶段: locate → recover → runtime → validation

### 安卓运行态 / 签名恢复
- 先用 `client-reverse` runtime-first 路径
- 只有抓不到包/加密/无法重放时再逆向

### AI / MCP
- Prompt 注入 → 直接/间接/CoT 干扰
- 工具滥用 → MCP 投毒/指令覆盖
- 身份逃逸 → 角色越界/权限漂移

### 内网 / AD
- 先用 `intranet-pentest-advanced`
- 工具不确定时补看 `pentest-tools`

## 参考文档

- `references/08-rapid-checklists-and-payloads.md` — 速查与 Payload 整合参考
- `references/payloads.md` — Payload 详细集合
- `references/testing-methodology.md` — 测试方法论
