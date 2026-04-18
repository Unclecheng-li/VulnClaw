# LFI/RFI文件包含
English: LFI/RFI File Inclusion
- Entry Count: 12
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 本地文件包含
- ID: lfi-basic
- Difficulty: intermediate
- Subcategory: 本地包含
- Tags: lfi, local, file, inclusion
- Original Extracted Source: original extracted web-security-wiki source/lfi-basic.md
Description:
本地文件包含漏洞利用技术
Prerequisites:
- 存在文件包含功能
- 用户可控制包含路径
Execution Outline:
1. 1. 探测LFI
2. 2. 读取敏感文件
3. 3. PHP伪协议
4. 4. 日志投毒
## 远程文件包含
- ID: rfi-basic
- Difficulty: intermediate
- Subcategory: 远程包含
- Tags: rfi, remote, file, inclusion
- Original Extracted Source: original extracted web-security-wiki source/rfi-basic.md
Description:
远程文件包含漏洞利用技术
Prerequisites:
- 存在文件包含功能
- allow_url_include=On
- 用户可控制包含路径
Execution Outline:
1. 1. 探测RFI
2. 2. 托管恶意文件
3. 3. 反弹Shell
4. 4. 使用data协议
## 日志投毒LFI
- ID: lfi-log-poison
- Difficulty: intermediate
- Subcategory: 日志投毒
- Tags: lfi, log, poison, rce
- Original Extracted Source: original extracted web-security-wiki source/lfi-log-poison.md
Description:
通过日志投毒实现LFI到RCE
Prerequisites:
- 存在LFI漏洞
- 可包含日志文件
- 日志文件可写
Execution Outline:
1. 1. 探测日志文件位置
2. 2. 投毒User-Agent
3. 3. 投毒请求路径
4. 4. 执行命令
## PHP伪协议利用
- ID: lfi-wrapper
- Difficulty: intermediate
- Subcategory: 伪协议
- Tags: lfi, wrapper, php, protocol
- Original Extracted Source: original extracted web-security-wiki source/lfi-wrapper.md
Description:
利用PHP伪协议进行LFI攻击
Prerequisites:
- 存在LFI漏洞
- PHP环境
- 伪协议未禁用
Execution Outline:
1. 1. php://filter
2. 2. php://input
3. 3. data://协议
4. 4. phar://协议
## 目录遍历技术
- ID: lfi-traversal
- Difficulty: beginner
- Subcategory: 目录遍历
- Tags: lfi, traversal, bypass, path
- Original Extracted Source: original extracted web-security-wiki source/lfi-traversal.md
Description:
LFI目录遍历绕过技术
Prerequisites:
- 存在LFI漏洞
- 存在路径过滤
Execution Outline:
1. 1. 基础遍历
2. 2. 绕过删除../
3. 3. URL编码绕过
4. 4. Unicode编码绕过
## PHP Filter链攻击
- ID: lfi-php-filter
- Difficulty: intermediate
- Subcategory: PHP Filter
- Tags: lfi, php, filter, chain
- Original Extracted Source: original extracted web-security-wiki source/lfi-php-filter.md
Description:
利用PHP Filter链进行LFI攻击
Prerequisites:
- 存在LFI漏洞
- PHP环境
- filter伪协议可用
Execution Outline:
1. 1. 读取源码
2. 2. 多重过滤器
3. 3. Filter链RCE
4. 4. 读取配置文件
## PHP Input执行
- ID: lfi-php-input
- Difficulty: intermediate
- Subcategory: PHP Input
- Tags: lfi, php, input, rce
- Original Extracted Source: original extracted web-security-wiki source/lfi-php-input.md
Description:
利用php://input执行PHP代码
Prerequisites:
- 存在LFI漏洞
- allow_url_include=On
- POST方法可用
Execution Outline:
1. 1. 基础执行
2. 2. 命令执行
3. 3. 文件操作
4. 4. 反弹Shell
## PHP Data协议攻击
- ID: lfi-php-data
- Difficulty: intermediate
- Subcategory: PHP Data
- Tags: lfi, php, data, protocol
- Original Extracted Source: original extracted web-security-wiki source/lfi-php-data.md
Description:
利用data://协议执行PHP代码
Prerequisites:
- 存在LFI漏洞
- allow_url_include=On
- data协议可用
Execution Outline:
1. 1. 基础执行
2. 2. Base64编码
3. 3. 命令执行
4. 4. 反弹Shell
## PHP Zip协议攻击
- ID: lfi-php-zip
- Difficulty: intermediate
- Subcategory: PHP Zip
- Tags: lfi, php, zip, archive
- Original Extracted Source: original extracted web-security-wiki source/lfi-php-zip.md
Description:
利用zip://协议进行LFI攻击
Prerequisites:
- 存在LFI漏洞
- 可上传zip文件
- zip协议可用
Execution Outline:
1. 1. 创建恶意Zip
2. 2. 上传Zip文件
3. 3. 包含Zip文件
4. 4. 图片马
## Phar反序列化攻击
- ID: lfi-phar
- Difficulty: advanced
- Subcategory: Phar反序列化
- Tags: lfi, phar, deserialization, rce
- Original Extracted Source: original extracted web-security-wiki source/lfi-phar.md
Description:
利用Phar反序列化进行RCE
Prerequisites:
- 存在LFI漏洞
- PHP环境
- phar扩展可用
Execution Outline:
1. 1. 创建Phar文件
2. 2. 触发反序列化
3. 3. 图片马Phar
4. 4. 常见Gadget链
## Session文件包含
- ID: lfi-session
- Difficulty: intermediate
- Subcategory: Session包含
- Tags: lfi, session, file, inclusion
- Original Extracted Source: original extracted web-security-wiki source/lfi-session.md
Description:
利用Session文件进行LFI攻击
Prerequisites:
- 存在LFI漏洞
- 可控制Session内容
- 知道Session路径
Execution Outline:
1. 1. 探测Session路径
2. 2. 控制Session内容
3. 3. 包含Session文件
4. 4. Session竞争条件
## Proc文件系统利用
- ID: lfi-proc
- Difficulty: intermediate
- Subcategory: Proc文件系统
- Tags: lfi, proc, linux, environ
- Original Extracted Source: original extracted web-security-wiki source/lfi-proc.md
Description:
利用/proc文件系统进行LFI攻击
Prerequisites:
- 存在LFI漏洞
- Linux系统
- /proc可访问
Execution Outline:
1. 1. 读取进程信息
2. 2. 读取环境变量
3. 3. 通过fd读取日志
4. 4. 读取其他进程

