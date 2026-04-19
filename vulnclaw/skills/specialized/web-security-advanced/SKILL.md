---
name: web-security-advanced
description: Web高级安全测试 — 注入攻击族、协议安全、认证与逻辑漏洞、文件与部署安全、现代Web攻击面，含完整Playbook
---

# Web 高级安全测试 Skill

当目标是 Web 应用、API、网关或浏览器面向服务，且需要系统性的漏洞测试时使用本 Skill。

**前置条件**：如果请求仍由客户端控制且重放未稳定，先使用 `client-reverse` Skill。

## CTF 场景路由

> 当目标为 CTF 题目（已知有 flag，需要绕过特定过滤）时，优先使用 `ctf-web` Skill 获取具体绕过值和 payload：

| CTF 场景 | 路由到 ctf-web | 参考文档 |
|---------|---------------|---------|
| PHP 弱比较/类型绕过 | `ctf-web` | `references/php-bypass-cheatsheet.md` |
| 命令注入空格绕过 | `ctf-web` | `references/command-injection-bypass.md` |
| eval 回显/无回显 | `ctf-web` | `references/eval-and-rce-techniques.md` |
| PHP 代码审计 | `ctf-web` | `references/php-code-audit-checklist.md` |
| SSTI 注入链 | `ctf-web` | `references/ssti-injection-chains.md` |
| 反序列化利用链 | `ctf-web` | `references/deserialization-playbook.md` |
| 文件上传 → RCE | `ctf-web` | `references/file-upload-to-rce.md` |

**本 Skill 侧重渗透测试方法论**，CTF 实战绕过值和 payload 模板请参考 `ctf-web`。

## 场景路由

| 攻击面类型 | 首选参考 |
|-----------|---------|
| 参数注入（SQLi/XSS/命令执行/SSTI/XXE） | `references/web-injection.md` |
| 协议安全（CORS/GraphQL/WebSocket/OAuth/请求走私） | `references/web-modern-protocols.md` |
| 认证与逻辑（IDOR/越权/支付/密码重置/鉴权绕过） | `references/web-logic-auth.md` |
| 文件与基础设施（上传/遍历/包含/部署/缓存/CDN/云） | `references/web-file-infra.md` |
| 部署安全 | `references/web-deployment-security.md` |

## 测试流程

### 1. 输入验证测试
- SQL 注入：布尔/时间/报错/Union/堆叠
- XSS：反射/存储/DOM/CSP 绕过
- 命令注入：分隔符绕过、编码绕过
- SSTI：模板引擎识别 + RCE 链
- XXE：实体注入、OOB 数据外带
- 反序列化：Java/PHP/Python 链

### 2. 认证与会话测试
- 默认凭据、暴力破解
- 会话管理缺陷（固定/劫持/不安全 Cookie）
- JWT 安全（算法篡改/密钥爆破/none算法）
- OAuth/OIDC 配置缺陷
- MFA 绕过

### 3. 逻辑漏洞测试
- 越权访问（水平/垂直）
- 业务逻辑绕过（支付/优惠券/投票）
- 竞态条件
- IDOR（不安全直接对象引用）

### 4. 协议安全测试
- CORS 配置错误
- GraphQL 内省/注入
- WebSocket 认证与注入
- HTTP 请求走私
- SSRF（内网探测/云元数据）

### 5. 文件与部署安全
- 文件上传绕过
- 路径穿越
- LFI/RFI
- CDN/缓存投毒
- 供应链攻击
- 云安全配置

## 参考文档

- `references/03-web-security-integrated.md` — Web 安全整合参考
- `references/web-injection.md` — 注入攻击详细参考
- `references/web-modern-protocols.md` — 现代协议安全
- `references/web-logic-auth.md` — 认证与逻辑漏洞
- `references/web-file-infra.md` — 文件与基础设施安全
- `references/web-deployment-security.md` — 部署安全
- `references/web-ai-attack-map.md` — Web 与 AI 攻击映射
- `references/web-playbook-*.md` — 各专项 Playbook（23 个）
