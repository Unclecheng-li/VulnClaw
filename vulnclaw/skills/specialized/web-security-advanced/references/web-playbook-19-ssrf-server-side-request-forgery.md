# SSRF服务端请求伪造
English: SSRF Server-Side Request Forgery
- Entry Count: 12
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 基础SSRF攻击
- ID: ssrf-basic
- Difficulty: intermediate
- Subcategory: 基础攻击
- Tags: ssrf, server-side, request
- Original Extracted Source: original extracted web-security-wiki source/ssrf-basic.md
Description:
服务端请求伪造基础攻击技术
Prerequisites:
- 存在URL输入点
- 服务器会请求用户提供的URL
Execution Outline:
1. 1. 探测SSRF
2. 2. 扫描内网端口
3. 3. 访问内网服务
4. 4. 读取本地文件
## AWS元数据攻击
- ID: ssrf-cloud-aws
- Difficulty: intermediate
- Subcategory: 云元数据
- Tags: ssrf, aws, metadata, cloud
- Original Extracted Source: original extracted web-security-wiki source/ssrf-cloud-aws.md
Description:
利用SSRF访问AWS EC2元数据服务
Prerequisites:
- 存在SSRF漏洞
- 目标运行在AWS EC2上
Execution Outline:
1. 1. 访问元数据服务
2. 2. 获取IAM凭证
3. 3. 获取用户数据
4. 4. 使用IMDSv2绕过
## GCP元数据攻击
- ID: ssrf-cloud-gcp
- Difficulty: intermediate
- Subcategory: GCP元数据
- Tags: ssrf, gcp, cloud, metadata
- Original Extracted Source: original extracted web-security-wiki source/ssrf-cloud-gcp.md
Description:
利用SSRF攻击Google Cloud元数据服务
Prerequisites:
- 存在SSRF漏洞
- 目标运行在GCP环境
Execution Outline:
1. 1. 访问元数据服务
2. 2. 获取访问令牌
3. 3. 获取服务账户信息
4. 4. 获取项目信息
## Azure元数据攻击
- ID: ssrf-cloud-azure
- Difficulty: intermediate
- Subcategory: Azure元数据
- Tags: ssrf, azure, cloud, metadata
- Original Extracted Source: original extracted web-security-wiki source/ssrf-cloud-azure.md
Description:
利用SSRF攻击Azure元数据服务
Prerequisites:
- 存在SSRF漏洞
- 目标运行在Azure环境
Execution Outline:
1. 1. 访问元数据服务
2. 2. 获取访问令牌
3. 3. 获取计算信息
4. 4. 获取网络信息
## SSRF协议利用
- ID: ssrf-protocol
- Difficulty: intermediate
- Subcategory: 协议利用
- Tags: ssrf, protocol, file, gopher
- Original Extracted Source: original extracted web-security-wiki source/ssrf-protocol.md
Description:
利用各种协议进行SSRF攻击
Prerequisites:
- 存在SSRF漏洞
- 服务器支持多种协议
Execution Outline:
1. 1. File协议
2. 2. Dict协议
3. 3. Gopher协议
4. 4. LDAP协议
## Gopher协议攻击
- ID: ssrf-gopher
- Difficulty: advanced
- Subcategory: Gopher攻击
- Tags: ssrf, gopher, redis, mysql
- Original Extracted Source: original extracted web-security-wiki source/ssrf-gopher.md
Description:
利用Gopher协议攻击内网服务
Prerequisites:
- 存在SSRF漏洞
- 服务器支持Gopher协议
Execution Outline:
1. 1. Gopher基础格式
2. 2. 攻击Redis
3. 3. 攻击MySQL
4. 4. 攻击FastCGI
## Dict协议攻击
- ID: ssrf-dict
- Difficulty: intermediate
- Subcategory: Dict协议
- Tags: ssrf, dict, redis, memcached
- Original Extracted Source: original extracted web-security-wiki source/ssrf-dict.md
Description:
利用Dict协议探测和攻击内网服务
Prerequisites:
- 存在SSRF漏洞
- 服务器支持Dict协议
Execution Outline:
1. 1. Dict协议格式
2. 2. 探测Redis
3. 3. 探测Memcached
4. 4. Redis写入文件
## File协议攻击
- ID: ssrf-file
- Difficulty: beginner
- Subcategory: File协议
- Tags: ssrf, file, lfi, read
- Original Extracted Source: original extracted web-security-wiki source/ssrf-file.md
Description:
利用File协议读取本地文件
Prerequisites:
- 存在SSRF漏洞
- 服务器支持File协议
Execution Outline:
1. 1. Linux敏感文件
2. 2. Windows敏感文件
3. 3. Web配置文件
4. 4. 云环境文件
## SSRF绕过技术
- ID: ssrf-bypass
- Difficulty: intermediate
- Subcategory: 绕过技术
- Tags: ssrf, bypass, waf, filter
- Original Extracted Source: original extracted web-security-wiki source/ssrf-bypass.md
Description:
各种绕过SSRF过滤的技术
Prerequisites:
- 存在SSRF漏洞
- 存在过滤机制
Execution Outline:
1. 1. IP格式绕过
2. 2. URL解析差异
3. 3. 重定向绕过
4. 4. DNS重绑定
## DNS重绑定攻击
- ID: ssrf-dns-rebinding
- Difficulty: advanced
- Subcategory: DNS重绑定
- Tags: ssrf, dns, rebinding, bypass
- Original Extracted Source: original extracted web-security-wiki source/ssrf-dns-rebinding.md
Description:
利用DNS重绑定绕过SSRF防护
Prerequisites:
- 存在SSRF漏洞
- 存在DNS解析验证
Execution Outline:
1. 1. DNS重绑定原理
2. 2. 使用公开服务
3. 3. 自建DNS服务器
4. 4. 攻击流程
## SSRF攻击Redis
- ID: ssrf-redis
- Difficulty: intermediate
- Subcategory: Redis攻击
- Tags: ssrf, redis, rce, webshell
- Original Extracted Source: original extracted web-security-wiki source/ssrf-redis.md
Description:
利用SSRF攻击内网Redis服务
Prerequisites:
- 存在SSRF漏洞
- 内网存在未授权Redis
Execution Outline:
1. 1. 探测Redis
2. 2. 写入WebShell
3. 3. 写入SSH公钥
4. 4. 写入Cron任务
## SSRF攻击MySQL
- ID: ssrf-mysql
- Difficulty: advanced
- Subcategory: MySQL攻击
- Tags: ssrf, mysql, gopher, database
- Original Extracted Source: original extracted web-security-wiki source/ssrf-mysql.md
Description:
利用SSRF攻击内网MySQL服务
Prerequisites:
- 存在SSRF漏洞
- 内网存在MySQL服务
- 知道MySQL用户名
Execution Outline:
1. 1. MySQL协议基础
2. 2. 使用Gopher攻击MySQL
3. 3. 使用工具生成Payload
4. 4. 执行SQL命令

