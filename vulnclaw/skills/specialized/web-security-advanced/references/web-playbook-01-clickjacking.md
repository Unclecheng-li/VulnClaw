# 点击劫持
English: Clickjacking
- Entry Count: 2
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 基础点击劫持
- ID: clickjacking-basic
- Difficulty: beginner
- Subcategory: 基础
- Tags: clickjacking, ui-redressing, iframe
- Original Extracted Source: original extracted web-security-wiki source/clickjacking-basic.md
Description:
通过透明iframe覆盖诱使用户在不知情的情况下点击隐藏的恶意按钮或链接
Prerequisites:
- 目标站点允许被iframe嵌套
- 目标未设置X-Frame-Options响应头
- 目标未配置CSP frame-ancestors策略
- HTML/CSS基础知识
Execution Outline:
1. 检测X-Frame-Options和CSP
2. 基础透明iframe覆盖POC
3. 多步骤拖拽劫持(Drag-and-Drop)
4. 利用CSS pointer-events绕过
## 点击劫持+XSS
- ID: clickjacking-xss
- Difficulty: intermediate
- Subcategory: XSS
- Tags: clickjacking, xss
- Original Extracted Source: original extracted web-security-wiki source/clickjacking-xss.md
Description:
将点击劫持与XSS攻击结合，先通过点击劫持触发XSS攻击向量获取更深层的控制
Prerequisites:
- 目标存在XSS漏洞
- 目标允许被iframe嵌套
- XSS payload可被点击触发
Execution Outline:
1. 识别可利用的XSS和Clickjacking组合
2. Self-XSS + Clickjacking组合利用
3. 反射型XSS + iframe嵌套利用

