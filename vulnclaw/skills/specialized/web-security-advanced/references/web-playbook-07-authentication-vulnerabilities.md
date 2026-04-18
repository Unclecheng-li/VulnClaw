# 认证漏洞
English: Authentication Vulnerabilities
- Entry Count: 10
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 认证绕过
- ID: auth-bypass
- Difficulty: intermediate
- Subcategory: 认证绕过
- Tags: auth, bypass, authentication
- Original Extracted Source: original extracted web-security-wiki source/auth-bypass.md
Description:
Web应用认证绕过技术
Prerequisites:
- 目标存在认证机制
- 认证实现存在缺陷
Execution Outline:
1. SQL注入绕过
2. 数组绕过
3. 类型转换
4. JSON绕过
## 暴力破解
- ID: auth-brute
- Difficulty: beginner
- Subcategory: 暴力破解
- Tags: auth, brute-force, password
- Original Extracted Source: original extracted web-security-wiki source/auth-brute.md
Description:
自动化密码猜测攻击
Prerequisites:
- 无验证码
- 无锁定策略
Execution Outline:
1. Pitchfork
2. Cluster bomb
3. 基于响应差异的用户名枚举
4. 验证码/OTP爆破与绕过
## 会话劫持
- ID: auth-session
- Difficulty: intermediate
- Subcategory: 会话管理
- Tags: auth, session, hijack
- Original Extracted Source: original extracted web-security-wiki source/auth-session.md
Description:
利用会话管理缺陷劫持或伪造用户会话，获取未授权访问权限
Prerequisites:
- 目标使用基于Cookie或Token的会话管理
- 可以截获或预测会话标识符
- 网络通信未完全加密(HTTP)或存在XSS
Execution Outline:
1. 会话Cookie属性分析
2. 会话固定攻击(Session Fixation)
3. 会话劫持(HTTP嗅探)
4. 会话预测(弱随机性)
## 密码重置漏洞
- ID: auth-password-reset
- Difficulty: intermediate
- Subcategory: 逻辑漏洞
- Tags: auth, password-reset, logic
- Original Extracted Source: original extracted web-security-wiki source/auth-password-reset.md
Description:
绕过密码重置流程
Prerequisites:
- 密码重置功能存在逻辑缺陷
Execution Outline:
1. Host头投毒
2. Token爆破
3. 密码重置Token可预测性分析
4. 密码重置流程逻辑缺陷
## OAuth漏洞
- ID: auth-oauth
- Difficulty: advanced
- Subcategory: OAuth
- Tags: auth, oauth, redirect
- Original Extracted Source: original extracted web-security-wiki source/auth-oauth.md
Description:
OAuth认证流程漏洞
Prerequisites:
- 使用OAuth登录
Execution Outline:
1. CSRF攻击
2. Redirect URI
3. OAuth State参数缺失/可预测CSRF
4. Token窃取与Scope越权
## SAML漏洞
- ID: auth-saml
- Difficulty: advanced
- Subcategory: SAML
- Tags: auth, saml, xml
- Original Extracted Source: original extracted web-security-wiki source/auth-saml.md
Description:
SAML断言攻击
Prerequisites:
- 使用SAML SSO
Execution Outline:
1. XML签名绕过
2. XXE攻击
3. SAML Response篡改与重放
4. SAML签名绕过高级技术
## 2FA绕过
- ID: auth-2fa
- Difficulty: intermediate
- Subcategory: 2FA
- Tags: auth, 2fa, mfa
- Original Extracted Source: original extracted web-security-wiki source/auth-2fa.md
Description:
绕过双因素认证
Prerequisites:
- 开启2FA
Execution Outline:
1. 直接访问
2. 验证码爆破
3. 逻辑绕过
## 验证码绕过
- ID: auth-captcha
- Difficulty: beginner
- Subcategory: 验证码
- Tags: auth, captcha, bypass
- Original Extracted Source: original extracted web-security-wiki source/auth-captcha.md
Description:
绕过图形验证码
Prerequisites:
- 存在验证码
Execution Outline:
1. 重复使用
2. 空值绕过
3. 删除参数
## 记住我漏洞
- ID: auth-remember-me
- Difficulty: intermediate
- Subcategory: 会话管理
- Tags: auth, remember-me, cookie
- Original Extracted Source: original extracted web-security-wiki source/auth-remember-me.md
Description:
Remember Me功能漏洞
Prerequisites:
- 开启Remember Me
Execution Outline:
1. Cookie伪造
2. Base64解码
3. 记住密码Token逆向分析
4. Shiro RememberMe反序列化RCE
## JWT认证漏洞
- ID: auth-jwt
- Difficulty: intermediate
- Subcategory: JWT
- Tags: auth, jwt, token
- Original Extracted Source: original extracted web-security-wiki source/auth-jwt.md
Description:
利用JWT(JSON Web Token)实现缺陷伪造或篡改认证令牌，实现未授权访问或权限提升
Prerequisites:
- 目标使用JWT进行认证
- 可以获取或拦截JWT令牌
- JWT库存在已知漏洞或服务端配置不当
Execution Outline:
1. JWT解码与分析
2. Algorithm None攻击
3. HS256密钥爆破
4. RS256→HS256算法混淆攻击

