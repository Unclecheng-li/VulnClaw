# 原型链污染
English: Prototype Pollution
- Entry Count: 3
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 服务端原型链污染到RCE
- ID: proto-server-rce
- Difficulty: advanced
- Subcategory: 服务端利用
- Tags: 原型链, Prototype Pollution, RCE, Node.js, __proto__
- Original Extracted Source: original extracted web-security-wiki source/proto-server-rce.md
Description:
通过污染JavaScript对象原型链(__proto__/constructor.prototype)注入恶意属性，在Node.js服务端利用child_process或EJS/Pug等模板引擎的gadget链实现远程代码执行。
Prerequisites:
- 目标使用Node.js
- 存在JSON合并/深拷贝操作
- 可控JSON输入
Execution Outline:
1. 1. 检测原型链污染点
2. 2. EJS模板引擎RCE Gadget
3. 3. Pug模板引擎RCE Gadget
4. 4. 通用DoS/信息泄露Gadget
## 客户端原型链污染到XSS
- ID: proto-client-xss
- Difficulty: advanced
- Subcategory: 客户端利用
- Tags: 原型链, XSS, 客户端, jQuery, DOM, Prototype Pollution
- Original Extracted Source: original extracted web-security-wiki source/proto-client-xss.md
Description:
通过URL参数、postMessage或DOM操作污染前端JavaScript原型链，利用jQuery/DOM操作库的gadget在客户端实现XSS。攻击者可通过精心构造的URL链接诱导受害者触发漏洞。
Prerequisites:
- 目标前端使用易受影响的JS库
- 存在URL参数到对象转换的逻辑
Execution Outline:
1. 1. 识别客户端污染源
2. 2. jQuery html() Gadget
3. 3. DOMPurify绕过Gadget
4. 4. 自动化检测脚本
## 原型链污染结合NoSQL注入
- ID: proto-nosql-injection
- Difficulty: expert
- Subcategory: 组合利用
- Tags: 原型链, NoSQL, MongoDB, 认证绕过, 组合攻击
- Original Extracted Source: original extracted web-security-wiki source/proto-nosql-injection.md
Description:
将原型链污染与MongoDB/NoSQL注入组合利用。通过污染查询对象的原型链属性，绕过认证逻辑或构造恶意查询条件，实现认证绕过和数据泄露。
Prerequisites:
- 目标使用MongoDB
- 存在原型链污染点
- 存在查询构造逻辑
Execution Outline:
1. 1. 识别MongoDB查询注入点
2. 2. 原型链污染绕过查询校验
3. 3. 布尔盲注提取数据
4. 4. 数据库枚举与导出

