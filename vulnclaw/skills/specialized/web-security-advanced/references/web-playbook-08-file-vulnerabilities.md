# 文件漏洞
English: File Vulnerabilities
- Entry Count: 7
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 文件上传绕过
- ID: file-upload-bypass
- Difficulty: intermediate
- Subcategory: 文件上传
- Tags: upload, bypass, webshell
- Original Extracted Source: original extracted web-security-wiki source/file-upload-bypass.md
Description:
文件上传限制绕过技术
Prerequisites:
- 目标存在文件上传功能
- 存在上传限制
Execution Outline:
1. 扩展名绕过
2. Content-Type
3. 图片马
4. 空格绕过
## 任意文件下载
- ID: file-download
- Difficulty: beginner
- Subcategory: 下载
- Tags: file-download, lfi, leak
- Original Extracted Source: original extracted web-security-wiki source/file-download.md
Description:
利用文件下载功能中的路径控制缺陷下载服务器上的任意敏感文件
Prerequisites:
- 目标存在文件下载功能
- 文件路径参数可控
- 服务端未对路径进行严格过滤
Execution Outline:
1. 识别文件下载接口
2. 路径遍历下载敏感文件
3. 下载源码与数据库配置
4. 自动化批量敏感文件探测
## 条件竞争
- ID: file-competition
- Difficulty: advanced
- Subcategory: Race Condition
- Tags: race-condition, file-upload
- Original Extracted Source: original extracted web-security-wiki source/file-competition.md
Description:
利用文件上传/处理过程中的竞态条件(Race Condition)，在安全检查与文件使用之间的时间窗口内执行恶意操作
Prerequisites:
- 目标存在文件上传功能
- 服务端先上传后检查的处理流程
- 可以高并发访问上传的文件
- 了解临时文件存储路径
Execution Outline:
1. 识别竞态条件窗口
2. 竞态条件利用 - 上传与访问并发
3. Python并发竞态利用脚本
4. .htaccess竞态写入
## 路径遍历
- ID: file-traversal
- Difficulty: beginner
- Subcategory: Traversal
- Tags: traversal, file
- Original Extracted Source: original extracted web-security-wiki source/file-traversal.md
Description:
利用路径遍历(../)序列突破文件访问的目录限制，读取或写入Web根目录以外的任意文件
Prerequisites:
- 目标存在文件读取/包含功能
- 文件路径参数可控
- 服务端路径过滤不严格
Execution Outline:
1. 基础路径遍历测试
2. 编码绕过路径过滤
3. Windows特有路径遍历
4. LFI到RCE升级
## Zip Slip
- ID: file-zip-slip
- Difficulty: intermediate
- Subcategory: Zip
- Tags: zip-slip, file, rce
- Original Extracted Source: original extracted web-security-wiki source/file-zip-slip.md
Description:
利用恶意构造的压缩包文件(ZIP/TAR)中的路径遍历实现任意文件写入，覆盖服务器上的关键文件或写入Webshell
Prerequisites:
- 目标存在ZIP/TAR文件上传并自动解压功能
- 解压库未对文件名中的路径遍历进行过滤
- 了解Web根目录或其他关键目录的路径
Execution Outline:
1. 探测ZIP上传和解压功能
2. 构造Zip Slip恶意压缩包
3. 上传并验证Zip Slip
4. TAR包Zip Slip变体
## MIME类型绕过
- ID: file-mime
- Difficulty: beginner
- Subcategory: MIME
- Tags: mime, bypass
- Original Extracted Source: original extracted web-security-wiki source/file-mime.md
Description:
通过伪造MIME类型(Content-Type)绕过文件上传的类型检查，上传恶意可执行文件
Prerequisites:
- 目标存在文件上传功能
- 服务端仅通过Content-Type判断文件类型
- 了解目标允许的MIME类型
Execution Outline:
1. 探测文件类型检查机制
2. MIME类型伪造上传Webshell
3. Magic Bytes伪造
4. 验证上传结果
## 空字节截断
- ID: file-null-byte
- Difficulty: intermediate
- Subcategory: Null Byte
- Tags: null-byte, bypass
- Original Extracted Source: original extracted web-security-wiki source/file-null-byte.md
Description:
利用空字节(%00/\x00)截断文件名的扩展名验证，绕过文件上传白名单限制
Prerequisites:
- 目标使用白名单验证文件扩展名
- 后端语言或库受空字节截断影响(PHP<5.3.4, Java旧版本)
- 服务端在路径拼接中存在截断点
Execution Outline:
1. 空字节截断原理与环境检测
2. 文件上传空字节截断
3. 文件包含空字节截断
4. 现代替代方案(PHP>=5.3.4)

