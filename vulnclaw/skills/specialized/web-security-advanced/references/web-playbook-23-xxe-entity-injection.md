# XXE实体注入
English: XXE Entity Injection
- Entry Count: 9
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## XXE基础攻击
- ID: xxe-basic
- Difficulty: intermediate
- Subcategory: 基础攻击
- Tags: xxe, xml, external, entity
- Original Extracted Source: original extracted web-security-wiki source/xxe-basic.md
Description:
XML外部实体注入基础攻击技术
Prerequisites:
- 存在XML解析功能
- 外部实体未被禁用
Execution Outline:
1. 1. 探测XXE
2. 2. 读取文件
3. 3. 读取PHP源码
4. 4. SSRF攻击
## 盲注XXE攻击
- ID: xxe-blind
- Difficulty: intermediate
- Subcategory: 盲注XXE
- Tags: xxe, blind, oob, xml
- Original Extracted Source: original extracted web-security-wiki source/xxe-blind.md
Description:
无回显的XXE攻击技术
Prerequisites:
- 存在XML解析
- 无直接回显
Execution Outline:
1. 1. 外部实体探测
2. 2. 参数实体
3. 3. OOB外带数据
## XXE OOB外带攻击
- ID: xxe-oob
- Difficulty: intermediate
- Subcategory: OOB外带
- Tags: xxe, oob, exfiltration, xml
- Original Extracted Source: original extracted web-security-wiki source/xxe-oob.md
Description:
利用OOB技术外带XXE数据
Prerequisites:
- 存在XXE漏洞
- 可发起外部请求
Execution Outline:
1. 1. HTTP外带
2. 2. FTP外带
3. 3. DNS外带
## XXE+SSRF组合攻击
- ID: xxe-ssrf
- Difficulty: intermediate
- Subcategory: XXE+SSRF
- Tags: xxe, ssrf, combination, xml
- Original Extracted Source: original extracted web-security-wiki source/xxe-ssrf.md
Description:
利用XXE实现SSRF攻击
Prerequisites:
- 存在XXE漏洞
- 内网可访问
Execution Outline:
1. 1. 扫描内网端口
2. 2. 访问内网服务
## XXE到RCE
- ID: xxe-rce
- Difficulty: advanced
- Subcategory: XXE到RCE
- Tags: xxe, rce, php, expect
- Original Extracted Source: original extracted web-security-wiki source/xxe-rce.md
Description:
利用XXE实现远程代码执行
Prerequisites:
- 存在XXE漏洞
- PHP expect扩展加载
Execution Outline:
1. 1. Expect扩展RCE
2. 2. 写入WebShell
## XXE文件读取
- ID: xxe-file-read
- Difficulty: beginner
- Subcategory: 文件读取
- Tags: xxe, file, read, lfi
- Original Extracted Source: original extracted web-security-wiki source/xxe-file-read.md
Description:
利用XXE读取服务器文件
Prerequisites:
- 存在XXE漏洞
- 有文件读取权限
Execution Outline:
1. 1. 读取Linux文件
2. 2. 读取Windows文件
3. 3. 读取Web配置
4. 4. 读取源代码
## XXE外部DTD利用
- ID: xxe-dtd
- Difficulty: intermediate
- Subcategory: 外部DTD
- Tags: xxe, dtd, external, xml
- Original Extracted Source: original extracted web-security-wiki source/xxe-dtd.md
Description:
利用外部DTD文件进行XXE攻击
Prerequisites:
- 存在XXE漏洞
- 可访问外部DTD
Execution Outline:
1. 1. 托管恶意DTD
2. 2. 引用外部DTD
3. 3. 多步骤外带
4. 4. 错误消息泄露
## XLSX文件XXE
- ID: xxe-xlsx
- Difficulty: intermediate
- Subcategory: XLSX文件XXE
- Tags: xxe, xlsx, excel, office
- Original Extracted Source: original extracted web-security-wiki source/xxe-xlsx.md
Description:
利用XLSX文件进行XXE攻击
Prerequisites:
- 应用解析XLSX文件
- 存在XXE漏洞
Execution Outline:
1. 1. 解压XLSX文件
2. 2. 注入XXE Payload
## DOCX文件XXE
- ID: xxe-docx
- Difficulty: intermediate
- Subcategory: DOCX文件XXE
- Tags: xxe, docx, word, office
- Original Extracted Source: original extracted web-security-wiki source/xxe-docx.md
Description:
利用DOCX文件进行XXE攻击
Prerequisites:
- 应用解析DOCX文件
- 存在XXE漏洞
Execution Outline:
1. 1. 解压DOCX文件
2. 2. 注入XXE Payload

