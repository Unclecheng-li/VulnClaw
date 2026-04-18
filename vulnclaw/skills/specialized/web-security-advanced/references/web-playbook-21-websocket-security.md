# WebSocket安全
English: WebSocket Security
- Entry Count: 3
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## WebSocket跨站劫持(CSWSH)
- ID: ws-hijack
- Difficulty: intermediate
- Subcategory: WebSocket劫持
- Tags: WebSocket, CSWSH, Origin, 跨站, 会话劫持
- Original Extracted Source: original extracted web-security-wiki source/ws-hijack.md
Description:
利用WebSocket握手阶段缺少Origin验证的漏洞，通过恶意网页建立跨站WebSocket连接。攻击者可劫持受害者的WebSocket会话，窃取实时数据或以受害者身份发送消息。类似于CSRF但针对WebSocket协议。
Prerequisites:
- 目标使用WebSocket通信
- WebSocket握手未验证Origin
Execution Outline:
1. 1. 识别WebSocket端点
2. 2. 构造跨站劫持POC页面
3. 3. WebSocket消息注入
4. 4. WebSocket流量分析脚本
## WebSocket走私攻击
- ID: ws-smuggling
- Difficulty: expert
- Subcategory: WebSocket走私
- Tags: WebSocket, 走私, 反向代理, H2C, 内网穿透
- Original Extracted Source: original extracted web-security-wiki source/ws-smuggling.md
Description:
利用反向代理/负载均衡器对WebSocket协议处理的差异，通过WebSocket升级请求走私HTTP请求到内网服务。攻击者可绕过前端安全控制直接与后端通信，访问受保护的内部API或管理接口。
Prerequisites:
- 目标使用反向代理(Nginx/Varnish等)
- 代理允许WebSocket升级
- 后端存在内部服务
Execution Outline:
1. 1. 检测WebSocket走私可能性
2. 2. WebSocket隧道构造
3. 3. H2C走私绕过访问控制
4. 4. 反向代理差异利用
## WebSocket认证与授权绕过
- ID: ws-auth-bypass
- Difficulty: intermediate
- Subcategory: 认证绕过
- Tags: WebSocket, 认证, 授权, 越权, Token重放
- Original Extracted Source: original extracted web-security-wiki source/ws-auth-bypass.md
Description:
利用WebSocket连接建立后缺少持续认证检查的漏洞，通过会话固定、令牌重放、频道越权订阅等方式绕过认证和授权机制。WebSocket的长连接特性使得权限变更后原连接仍可保持访问。
Prerequisites:
- 目标使用WebSocket实时通信
- 已获取有效会话/Token
Execution Outline:
1. 1. WebSocket认证机制分析
2. 2. Token重放与会话固定
3. 3. 频道/房间越权订阅
4. 4. WebSocket速率限制与DoS测试

