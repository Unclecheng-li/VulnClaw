# RCE远程代码执行
English: RCE Remote Code Execution
- Entry Count: 12
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 命令注入
- ID: rce-command-injection
- Difficulty: intermediate
- Subcategory: 命令注入
- Tags: rce, command, injection, os
- Original Extracted Source: original extracted web-security-wiki source/rce-command-injection.md
Description:
操作系统命令注入攻击技术
Prerequisites:
- 存在系统命令执行功能
- 用户输入未过滤
Execution Outline:
1. 1. 探测命令注入
2. 2. Linux命令注入
3. 3. Windows命令注入
4. 4. 盲命令注入
## PHP代码执行
- ID: rce-php
- Difficulty: intermediate
- Subcategory: PHP代码执行
- Tags: rce, php, code, execution
- Original Extracted Source: original extracted web-security-wiki source/rce-php.md
Description:
PHP代码执行漏洞利用技术
Prerequisites:
- 存在PHP代码执行点
- 用户输入可控制代码
Execution Outline:
1. 1. 常见危险函数
2. 2. 命令执行
3. 3. 一句话木马
4. 4. 免杀一句话
## PHP Filter链RCE
- ID: rce-php-filter
- Difficulty: advanced
- Subcategory: PHP Filter链
- Tags: rce, php, filter, chain
- Original Extracted Source: original extracted web-security-wiki source/rce-php-filter.md
Description:
利用PHP Filter链构造RCE
Prerequisites:
- 存在文件包含漏洞
- PHP版本支持Filter链
Execution Outline:
1. 1. Filter链原理
2. 2. 构造Filter链
3. 3. 使用工具生成
4. 4. 完整利用示例
## 盲命令注入
- ID: rce-cmd-blind
- Difficulty: intermediate
- Subcategory: 盲命令注入
- Tags: rce, blind, command, injection
- Original Extracted Source: original extracted web-security-wiki source/rce-cmd-blind.md
Description:
无回显的命令注入利用技术
Prerequisites:
- 存在命令注入点
- 无直接回显
Execution Outline:
1. 1. 时间盲注
2. 2. DNS外带
3. 3. HTTP外带
4. 4. ICMP外带
## 反序列化漏洞
- ID: rce-deserialize
- Difficulty: advanced
- Subcategory: 反序列化
- Tags: rce, deserialize, java, php
- Original Extracted Source: original extracted web-security-wiki source/rce-deserialize.md
Description:
利用反序列化漏洞实现RCE
Prerequisites:
- 存在反序列化点
- 存在可利用的Gadget链
Execution Outline:
1. 1. Java反序列化
2. 2. PHP反序列化
3. 3. Python反序列化
4. 4. .NET反序列化
## PHP反序列化
- ID: rce-deserialize-php
- Difficulty: advanced
- Subcategory: PHP反序列化
- Tags: rce, php, deserialize, unserialize
- Original Extracted Source: original extracted web-security-wiki source/rce-deserialize-php.md
Description:
PHP反序列化漏洞利用技术
Prerequisites:
- 存在unserialize调用
- 存在可利用的类
Execution Outline:
1. 1. 魔术方法
2. 2. 构造POP链
3. 3. Phar反序列化
4. 4. Session反序列化
## Java反序列化
- ID: rce-deserialize-java
- Difficulty: advanced
- Subcategory: Java反序列化
- Tags: rce, java, deserialize, ysoserial
- Original Extracted Source: original extracted web-security-wiki source/rce-deserialize-java.md
Description:
Java反序列化漏洞利用技术
Prerequisites:
- 存在Java反序列化点
- 存在Gadget链
Execution Outline:
1. 1. 常见Gadget链
2. 2. 使用ysoserial
3. 3. JRMP攻击
4. 4. 内存马注入
## 文件上传漏洞
- ID: rce-file-upload
- Difficulty: intermediate
- Subcategory: 文件上传
- Tags: rce, upload, webshell, file
- Original Extracted Source: original extracted web-security-wiki source/rce-file-upload.md
Description:
利用文件上传漏洞获取RCE
Prerequisites:
- 存在文件上传功能
- 可上传可执行文件
Execution Outline:
1. 1. 基础上传
2. 2. 前端绕过
3. 3. 后端绕过
4. 4. 图片马
## 文件包含RCE
- ID: rce-include
- Difficulty: intermediate
- Subcategory: 文件包含
- Tags: rce, include, lfi, rfi
- Original Extracted Source: original extracted web-security-wiki source/rce-include.md
Description:
利用文件包含漏洞实现RCE
Prerequisites:
- 存在文件包含漏洞
- 可包含恶意文件
Execution Outline:
1. 1. 日志投毒
2. 2. Session文件包含
3. 3. /proc/self/environ
4. 4. PHP伪协议
## 日志投毒RCE
- ID: rce-log-poison
- Difficulty: intermediate
- Subcategory: 日志投毒
- Tags: rce, log, poison, lfi
- Original Extracted Source: original extracted web-security-wiki source/rce-log-poison.md
Description:
利用日志投毒实现RCE
Prerequisites:
- 存在文件包含漏洞
- 可读取日志文件
Execution Outline:
1. 1. Apache日志投毒
2. 2. Nginx日志投毒
## 图片马RCE
- ID: rce-image
- Difficulty: intermediate
- Subcategory: 图片马
- Tags: rce, image, webshell, upload
- Original Extracted Source: original extracted web-security-wiki source/rce-image.md
Description:
利用图片马实现RCE
Prerequisites:
- 存在文件上传
- 存在文件包含
Execution Outline:
1. 1. 制作图片马
2. 2. 图片马内容
3. 3. 利用文件包含执行
4. 4. 配合.htaccess
## .htaccess利用
- ID: rce-htaccess
- Difficulty: intermediate
- Subcategory: .htaccess
- Tags: rce, htaccess, apache, upload
- Original Extracted Source: original extracted web-security-wiki source/rce-htaccess.md
Description:
利用.htaccess文件实现RCE
Prerequisites:
- Apache服务器
- 可上传.htaccess
Execution Outline:
1. 1. 解析其他扩展名
2. 2. 自动包含
3. 3. 伪静态RCE
4. 4. 错误页面包含

