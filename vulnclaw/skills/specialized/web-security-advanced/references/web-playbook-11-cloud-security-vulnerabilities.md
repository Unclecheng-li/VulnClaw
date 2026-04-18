# 云安全漏洞
English: Cloud Security Vulnerabilities
- Entry Count: 4
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 云SSRF窃取元数据凭据
- ID: cloud-ssrf-metadata
- Difficulty: intermediate
- Subcategory: IMDS攻击
- Tags: 云安全, SSRF, AWS, GCP, Azure, IMDS, 元数据
- Original Extracted Source: original extracted web-security-wiki source/cloud-ssrf-metadata.md
Description:
利用SSRF漏洞访问云服务(AWS/GCP/Azure)的实例元数据服务(IMDS)获取临时IAM凭据。攻击者可通过获取的Access Key接管云资源，实现从Web漏洞到云环境的横向升级。
Prerequisites:
- 目标运行在云环境
- 存在SSRF漏洞
- 实例绑定了IAM角色
Execution Outline:
1. 1. AWS元数据服务探测
2. 2. GCP/Azure元数据利用
3. 3. 利用获取的凭据横向移动
4. 4. 深度利用——S3数据泄露/权限提升
## S3存储桶配置错误利用
- ID: cloud-s3-misconfig
- Difficulty: beginner
- Subcategory: S3安全
- Tags: 云安全, S3, AWS, 配置错误, 数据泄露
- Original Extracted Source: original extracted web-security-wiki source/cloud-s3-misconfig.md
Description:
利用AWS S3存储桶的访问控制配置错误(公开读/写/列举)获取敏感数据或植入恶意文件。常见于静态网站托管、日志存储和备份桶，可能导致数据泄露、网站篡改或供应链攻击。
Prerequisites:
- 已知目标S3桶名
- AWS CLI或HTTP访问
Execution Outline:
1. 1. S3桶名枚举
2. 2. 权限枚举
3. 3. 敏感数据搜索
4. 4. 验证利用（静态网站篡改/XSS）
## AWS IAM权限提升
- ID: cloud-iam-escalation
- Difficulty: advanced
- Subcategory: IAM提权
- Tags: 云安全, AWS, IAM, 权限提升, Privilege Escalation
- Original Extracted Source: original extracted web-security-wiki source/cloud-iam-escalation.md
Description:
在已获取低权限AWS凭据后，利用IAM策略中的过度授权(如iam:PassRole、lambda:CreateFunction等)实现权限提升至管理员。涵盖20+种已知的AWS IAM提权路径。
Prerequisites:
- 已获取AWS凭据
- IAM策略存在过度授权
Execution Outline:
1. 1. 枚举当前权限
2. 2. iam:PassRole + Lambda提权
3. 3. 其他提权路径
4. 4. 自动化提权工具
## Kubernetes容器逃逸
- ID: cloud-k8s-escape
- Difficulty: expert
- Subcategory: 容器安全
- Tags: 云安全, Kubernetes, 容器逃逸, Docker, 特权容器
- Original Extracted Source: original extracted web-security-wiki source/cloud-k8s-escape.md
Description:
在已获取Kubernetes Pod Shell的前提下，利用配置错误(特权容器、挂载宿主机路径、ServiceAccount高权限)实现容器逃逸，进而控制宿主机或整个Kubernetes集群。
Prerequisites:
- 已获取Pod内Shell
- Pod存在配置错误
Execution Outline:
1. 1. 容器环境侦察
2. 2. 特权容器逃逸
3. 3. 利用ServiceAccount接管集群
4. 4. 创建特权Pod反弹Shell

