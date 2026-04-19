# CTF Web 快速参考

## 常见 flag 位置

### Linux
```
/flag
/flag.txt
/flag.php
/var/www/html/flag.php
/home/ctf/flag
/root/flag
/tmp/flag
/opt/flag
/srv/flag
```

### Docker/环境变量
```
/proc/self/environ
/environment
/.env
```

### PHP 特定
```php
// phpinfo() 中的 flag
// 查看环境变量段
// 查看自定义段

// 常见 flag 文件名
flag.php
flag.txt
f1ag.php
fl4g.php
fl@g.php
th1s_1s_flag.php
```

## First-Pass 工作流

```
1. 访问目标 URL
   → 查看页面源码（Ctrl+U）
   → 检查 HTTP 头（Server, X-Powered-By, Set-Cookie）
   → 检查 Cookie 值（base64/JWT/序列化）

2. 检查隐藏信息
   → robots.txt
   → .git/HEAD
   → .svn/
   → backup 文件：index.php.bak, www.zip, .index.php.swp, index.php~
   → DS_Store: .DS_Store

3. 目录扫描
   → /flag, /admin, /login, /upload, /api, /debug
   → /phpinfo.php, /info.php, /test.php
   → /console (Flask Debug), /actuator (Spring Boot)

4. 如有源码 → 代码审计
   → 参考 php-code-audit-checklist.md

5. 如无源码 → 主动探测
   → SQL 注入测试
   → XSS 测试
   → 文件上传
   → SSTI 测试
   → LFI/RFI
```

## 快速测试命令

```bash
# 检查基本信息
curl -I http://target/              # HTTP 头
curl http://target/robots.txt        # robots
curl http://target/.git/HEAD         # git 泄露

# 常见注入测试
' OR 1=1 --                          # SQLi
{{7*7}}                              # SSTI
<script>alert(1)</script>            # XSS
../../../etc/passwd                  # LFI
```

## 常见响应头 Hint

| 响应头 | 含义 | 下一步 |
|--------|------|--------|
| `X-Forwarded-For: 127.0.0.1` | 需要本地访问 | 添加 X-Forwarded-For 头 |
| `Server: nginx/1.x` | 服务器类型 | 搜索已知 CVE |
| `X-Powered-By: PHP/7.x` | PHP 版本 | PHP 特定漏洞 |
| `Set-Cookie: role=guest` | 权限控制 | 修改 Cookie |
| `Hint: xxx` | 直接提示 | 按提示操作 |
| `Flag: xxx` | 有时直接在头中 | 检查所有响应头 |

## 常见链形状

### PHP 简单链
```
URL → 源码 → 发现过滤 → 绕过过滤 → RCE → 读 flag
```

### PHP 多步链
```
入口页面 → 发现 hint → 跟随跳转 → 发现新页面 → 获取源码 → 分析利用 → RCE
```

### 文件包含链
```
LFI → 读源码（php://filter） → 发现包含点 → 日志投毒/Session包含 → RCE
```

### SQL 注入链
```
登录框 → SQLi → 读数据 → 发现管理员密码 → 登录后台 → 上传 Webshell → RCE
```

### 反序列化链
```
可控的序列化数据 → 分析可用的 Gadgets → 构造利用链 → RCE/SSRF/文件读取
```

## 编码/加密常见线索

| 特征 | 可能编码 | 解码方法 |
|------|---------|---------|
| 末尾有 `=` | Base64 | `crypto_decode base64_decode` |
| `0-9a-f` 偶数长度 | Hex | `crypto_decode hex_decode` |
| `%XX` | URL 编码 | `crypto_decode url_decode` |
| `&#xNN;` | HTML 实体 | `crypto_decode html_decode` |
| `\uXXXX` | Unicode 转义 | `crypto_decode unicode_decode` |
| 三段 `.` 分隔 | JWT | `crypto_decode jwt_decode` |
| 点划线 | Morse | `crypto_decode morse_decode` |
| 看不懂但像字母 | ROT13/Caesar | `crypto_decode rot13_decode` |
