# XSS跨站脚本
English: XSS Cross-Site Scripting
- Entry Count: 12
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 反射型XSS
- ID: xss-reflected
- Difficulty: beginner
- Subcategory: 反射型
- Tags: xss, reflected, javascript
- Original Extracted Source: original extracted web-security-wiki source/xss-reflected.md
Description:
反射型跨站脚本攻击技术
Prerequisites:
- 存在用户输入反射到页面
- 输入未经过滤或编码
Execution Outline:
1. 1. 探测XSS注入点
2. 2. 事件处理器绕过
3. 3. 标签绕过
4. 4. 窃取Cookie
## 存储型XSS
- ID: xss-stored
- Difficulty: intermediate
- Subcategory: 存储型
- Tags: xss, stored, persistent
- Original Extracted Source: original extracted web-security-wiki source/xss-stored.md
Description:
存储型跨站脚本攻击技术
Prerequisites:
- 存在数据存储功能
- 存储数据未经过滤显示
Execution Outline:
1. 1. 探测存储点
2. 2. 隐蔽Payload
3. 3. 持久化控制
4. 4. BeEF Hook
## DOM型XSS
- ID: xss-dom
- Difficulty: intermediate
- Subcategory: DOM型
- Tags: xss, dom, javascript
- Original Extracted Source: original extracted web-security-wiki source/xss-dom.md
Description:
基于DOM的跨站脚本攻击
Prerequisites:
- 存在JavaScript动态操作DOM
- 用户输入直接写入DOM
Execution Outline:
1. 1. 探测DOM XSS
2. 2. 常见Sink点
3. 3. location.hash利用
4. 4. postMessage利用
## CSP绕过
- ID: xss-csp-bypass
- Difficulty: advanced
- Subcategory: CSP绕过
- Tags: xss, csp, bypass
- Original Extracted Source: original extracted web-security-wiki source/xss-csp-bypass.md
Description:
绕过内容安全策略(CSP)的XSS技术
Prerequisites:
- 存在XSS漏洞
- 存在CSP策略但配置不当
Execution Outline:
1. 1. 分析CSP策略
2. 2. 利用unsafe-inline
3. 3. 利用unsafe-eval
4. 4. JSONP绕过
## 突变型XSS(mXSS)
- ID: xss-mxss
- Difficulty: advanced
- Subcategory: 突变型
- Tags: xss, mxss, mutation, bypass
- Original Extracted Source: original extracted web-security-wiki source/xss-mxss.md
Description:
利用浏览器解析差异导致的XSS攻击
Prerequisites:
- 存在HTML输出点
- 浏览器解析差异
Execution Outline:
1. 1. 基础mXSS探测
2. 2. SVG mXSS
3. 3. Math mXSS
4. 4. DOM clobbering配合
## Unicode XSS
- ID: xss-unicode
- Difficulty: intermediate
- Subcategory: Unicode编码
- Tags: xss, unicode, encoding, bypass
- Original Extracted Source: original extracted web-security-wiki source/xss-unicode.md
Description:
利用Unicode编码特性绕过过滤
Prerequisites:
- 存在XSS注入点
- 过滤器检查关键字
Execution Outline:
1. 1. Unicode转义
2. 2. HTML实体编码
3. 3. Unicode规范化攻击
4. 4. UTF-7编码
## XSS过滤器绕过
- ID: xss-filter-bypass
- Difficulty: intermediate
- Subcategory: 过滤器绕过
- Tags: xss, filter, bypass, waf
- Original Extracted Source: original extracted web-security-wiki source/xss-filter-bypass.md
Description:
各种绕过XSS过滤器的技术
Prerequisites:
- 存在XSS注入点
- 存在过滤机制
Execution Outline:
1. 1. 大小写混淆
2. 2. 双写绕过
3. 3. 注释混淆
4. 4. 空字节截断
## XSS编码绕过
- ID: xss-encoding
- Difficulty: intermediate
- Subcategory: 编码绕过
- Tags: xss, encoding, bypass
- Original Extracted Source: original extracted web-security-wiki source/xss-encoding.md
Description:
利用各种编码技术绕过XSS过滤
Prerequisites:
- 存在XSS注入点
- 存在编码处理
Execution Outline:
1. 1. URL编码
2. 2. HTML实体编码
3. 3. JavaScript编码
4. 4. CSS编码
## Polyglot XSS
- ID: xss-polyglot
- Difficulty: intermediate
- Subcategory: Polyglot
- Tags: xss, polyglot, universal
- Original Extracted Source: original extracted web-security-wiki source/xss-polyglot.md
Description:
多环境通用的XSS payload
Prerequisites:
- 存在XSS注入点
- 不确定具体环境
Execution Outline:
1. 1. 经典Polyglot
2. 2. 短Polyglot
3. 3. 属性注入Polyglot
4. 4. URL参数Polyglot
## XSS Cookie窃取
- ID: xss-cookie-theft
- Difficulty: beginner
- Subcategory: Cookie窃取
- Tags: xss, cookie, theft, session
- Original Extracted Source: original extracted web-security-wiki source/xss-cookie-theft.md
Description:
利用XSS窃取用户Cookie
Prerequisites:
- 存在XSS漏洞
- Cookie未设置HttpOnly
Execution Outline:
1. 1. 基础Cookie窃取
2. 2. Fetch API窃取
3. 3. XMLHttpRequest窃取
4. 4. 编码传输
## XSS键盘记录
- ID: xss-keylogger
- Difficulty: intermediate
- Subcategory: 键盘记录
- Tags: xss, keylogger, credential
- Original Extracted Source: original extracted web-security-wiki source/xss-keylogger.md
Description:
利用XSS记录用户键盘输入
Prerequisites:
- 存在存储型XSS
- 目标页面有敏感输入
Execution Outline:
1. 1. 基础键盘记录
2. 2. 完整键盘记录
3. 3. 表单窃取
4. 4. 表单提交劫持
## BeEF框架利用
- ID: xss-beef
- Difficulty: advanced
- Subcategory: BeEF利用
- Tags: xss, beef, framework, exploitation
- Original Extracted Source: original extracted web-security-wiki source/xss-beef.md
Description:
使用BeEF框架进行XSS利用
Prerequisites:
- 存在XSS漏洞
- 部署BeEF服务器
Execution Outline:
1. 1. 部署BeEF
2. 2. 注入Hook脚本
3. 3. 常用命令
4. 4. 模块利用

