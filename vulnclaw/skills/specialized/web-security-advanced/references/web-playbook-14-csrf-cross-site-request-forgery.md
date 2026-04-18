# CSRF跨站请求伪造
English: CSRF Cross-Site Request Forgery
- Entry Count: 8
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## CSRF基础攻击
- ID: csrf-basic
- Difficulty: beginner
- Subcategory: 基础攻击
- Tags: csrf, cross-site, request, forgery
- Original Extracted Source: original extracted web-security-wiki source/csrf-basic.md
Description:
跨站请求伪造基础攻击技术
Prerequisites:
- 目标存在敏感操作
- 缺少CSRF保护
Execution Outline:
1. 1. 构造CSRF表单
2. 2. GET请求CSRF
3. 3. JSON CSRF
4. 4. 链接诱导
## JSON CSRF攻击
- ID: csrf-json
- Difficulty: intermediate
- Subcategory: JSON CSRF
- Tags: csrf, json, api, post
- Original Extracted Source: original extracted web-security-wiki source/csrf-json.md
Description:
针对JSON请求的CSRF攻击技术
Prerequisites:
- 目标使用JSON格式请求
- 缺少CSRF保护
- CORS配置不当
Execution Outline:
1. 1. 简单JSON CSRF
2. 2. Flash JSON CSRF
3. 3. XSSI攻击
4. 4. SWF文件攻击
## CSRF绕过技术
- ID: csrf-bypass
- Difficulty: intermediate
- Subcategory: 绕过技术
- Tags: csrf, bypass, token, referer
- Original Extracted Source: original extracted web-security-wiki source/csrf-bypass.md
Description:
绕过CSRF防护的各种技术
Prerequisites:
- 目标存在CSRF防护
- 防护机制存在缺陷
Execution Outline:
1. 1. Token验证绕过
2. 2. Referer验证绕过
3. 3. Origin验证绕过
4. 4. SameSite绕过
## SameSite绕过技术
- ID: csrf-samesite
- Difficulty: intermediate
- Subcategory: SameSite绕过
- Tags: csrf, samesite, cookie, bypass
- Original Extracted Source: original extracted web-security-wiki source/csrf-samesite.md
Description:
绕过SameSite Cookie属性的CSRF攻击
Prerequisites:
- Cookie设置了SameSite属性
- SameSite配置存在缺陷
Execution Outline:
1. 1. SameSite=Lax绕过
2. 2. SameSite=Strict绕过
3. 3. 未设置SameSite
4. 4. 利用OAuth流程
## Token绕过技术
- ID: csrf-token-bypass
- Difficulty: intermediate
- Subcategory: Token绕过
- Tags: csrf, token, bypass, predictable
- Original Extracted Source: original extracted web-security-wiki source/csrf-token-bypass.md
Description:
绕过CSRF Token验证的技术
Prerequisites:
- 目标使用CSRF Token
- Token机制存在缺陷
Execution Outline:
1. 1. Token可预测
2. 2. Token未绑定会话
3. 3. Token泄露
4. 4. Token重放
## Referer绕过技术
- ID: csrf-referer-bypass
- Difficulty: intermediate
- Subcategory: Referer绕过
- Tags: csrf, referer, bypass, header
- Original Extracted Source: original extracted web-security-wiki source/csrf-referer-bypass.md
Description:
绕过Referer验证的CSRF攻击
Prerequisites:
- 目标验证Referer头
- 验证逻辑存在缺陷
Execution Outline:
1. 1. 正则匹配绕过
2. 2. 空Referer绕过
3. 3. 子域名绕过
4. 4. Referrer-Policy利用
## Flash CSRF攻击
- ID: csrf-flash
- Difficulty: advanced
- Subcategory: Flash CSRF
- Tags: csrf, flash, swf, crossdomain
- Original Extracted Source: original extracted web-security-wiki source/csrf-flash.md
Description:
利用Flash进行CSRF攻击
Prerequisites:
- 目标允许Flash请求
- crossdomain.xml配置不当
Execution Outline:
1. 1. crossdomain.xml利用
2. 2. 创建恶意SWF
3. 3. 发送JSON请求
4. 4. 自定义Header
## CORS配置错误利用
- ID: csrf-cors
- Difficulty: intermediate
- Subcategory: CORS配置错误
- Tags: csrf, cors, misconfiguration, api
- Original Extracted Source: original extracted web-security-wiki source/csrf-cors.md
Description:
利用CORS配置错误进行CSRF攻击
Prerequisites:
- CORS配置错误
- 允许跨域携带凭证
Execution Outline:
1. 1. 检测CORS配置
2. 2. 反射Origin攻击
3. 3. null源攻击
4. 4. 正则绕过

