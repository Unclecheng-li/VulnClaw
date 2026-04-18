# 开放重定向
English: Open Redirect
- Entry Count: 3
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 基础开放重定向
- ID: redirect-basic
- Difficulty: beginner
- Subcategory: 基础
- Tags: redirect, url, phishing
- Original Extracted Source: original extracted web-security-wiki source/redirect-basic.md
Description:
URL跳转漏洞利用
Prerequisites:
- 目标参数控制跳转地址
Execution Outline:
1. 直接跳转
2. 绕过验证
3. 斜杠绕过
## 重定向绕过
- ID: redirect-bypass
- Difficulty: intermediate
- Subcategory: Bypass
- Tags: redirect, bypass
- Original Extracted Source: original extracted web-security-wiki source/redirect-bypass.md
Description:
开放重定向绕过技巧
Prerequisites:
- 存在重定向参数
Execution Outline:
1. URL编码
2. @符号
3. 反斜杠
## 重定向到SSRF
- ID: redirect-ssrf
- Difficulty: intermediate
- Subcategory: SSRF
- Tags: redirect, ssrf
- Original Extracted Source: original extracted web-security-wiki source/redirect-ssrf.md
Description:
利用开放重定向漏洞作为跳板将SSRF探测引导到内部网络，绕过SSRF的URL白名单/黑名单限制
Prerequisites:
- 目标存在开放重定向(Open Redirect)漏洞
- 目标存在SSRF功能点(URL参数/Webhook等)
- SSRF过滤仅检查初始URL而不跟踪重定向
Execution Outline:
1. 识别开放重定向点
2. 通过重定向绕过SSRF过滤
3. 短链接和DNS重绑定辅助
4. 完整利用链: 重定向→SSRF→内网探测

