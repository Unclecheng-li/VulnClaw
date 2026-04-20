# Web 指纹识别

## 检查项清单

### HTTP 响应头指纹
| 响应头 | 推断信息 | 示例 |
|--------|---------|------|
| `Server` | Web 服务器 | `nginx/1.18.0`、`Apache/2.4.41`、`GitHub.com` |
| `X-Powered-By` | 后端语言/框架 | `PHP/7.4.3`、`Express`、`Next.js` |
| `X-AspNet-Version` | .NET 版本 | `4.0.30319` |
| `Set-Cookie` | 框架特征 | `PHPSESSID`→PHP、`JSESSIONID`→Java、`csrf_token`→Django |
| `X-Generator` | CMS | `Hugo`、`WordPress`、`Ghost` |
| `X-DRupal-Cache` | CMS | Drupal |
| `Via` | 代理/CDN | `1.1 varnish`→Varnish CDN |

### HTML 源码指纹
```python
import re

# WordPress
wp_signs = ['wp-content', 'wp-includes', 'wordpress']
# Hexo
hexo_signs = ['hexo', 'hexo-theme']
# Hugo
hugo_signs = ['hugo', 'gohugo']
# Jekyll
jekyll_signs = ['jekyll']
# Next.js
next_signs = ['__NEXT_DATA__', '_next/']
# Vue
vue_signs = ['data-v-', '__vue__']
# React
react_signs = ['data-reactroot', '__react']

def detect_framework(html):
    html_lower = html.lower()
    frameworks = []
    checks = {
        'WordPress': wp_signs,
        'Hexo': hexo_signs,
        'Hugo': hugo_signs,
        'Jekyll': jekyll_signs,
        'Next.js': next_signs,
        'Vue': vue_signs,
        'React': react_signs,
    }
    for name, signs in checks.items():
        if any(s in html_lower for s in signs):
            frameworks.append(name)
    return frameworks
```

### JavaScript 文件指纹
- 框架特有 JS 文件路径：`/wp-includes/js/` → WordPress
- Vue/React DevTools 检测：`__VUE_DEVTOOLS_GLOBAL_HOOK__`、`__REACT_DEVTOOLS_GLOBAL_HOOK__`
- 框架版本通常在 JS 注释或变量中

### CSS 指纹
- `/wp-content/themes/` → WordPress
- Hexo 主题特征 class 名
- Bootstrap/Tailwind class 特征

### 特征文件
| 文件路径 | 推断信息 |
|---------|---------|
| `/robots.txt` | CMS 信息、隐藏路径 |
| `/sitemap.xml` | 站点结构 |
| `/favicon.ico` | 框架默认图标 |
| `/.well-known/security.txt` | 安全联系方式 |
| `/humans.txt` | 开发者信息 |
| `/.git/HEAD` | Git 仓库泄露 |
| `/.env` | 环境变量泄露 |

## GitHub Pages 特征
- 响应头 `Server: GitHub.com`
- `X-GitHub-Request-Id` 存在
- `X-Cache: HIT` + `X-Fastly-Request-ID` → Fastly CDN
- `Via: 1.1 varnish` → Varnish 缓存
- 常见框架：Jekyll、Hexo、Hugo

---

## WAF 检测

### 常见 WAF 识别特征
| WAF | 响应头/页面特征 | 拦截状态码 |
|-----|----------------|-----------|
| Cloudflare | `Server: cloudflare`, `CF-Ray` | 403 |
| AWS WAF | `x-amz-request-id`, `x-amz-cf-id` | 403 |
| 阿里云 WAF | Cookie 含 `acw_tc` | 405/403 |
| 腾讯云 WAF | 特定 JSON 拦截页面 | 403 |
| 宝塔 WAF | 拦截页面含 "宝塔" | 403 |
| 安全狗 | 拦截页面含 "safedog" | 403/404 |
| ModSecurity | 特定 403 + Server 头 | 403 |
| Nginx WAF | `HTTP/1.1 444` 或特殊 403 | 444/403 |

### WAF 检测方法
1. **正常请求 vs 攻击请求对比** — 发送带攻击特征的请求，观察响应差异
2. **响应头检查** — 某些 WAF 会添加特定响应头
3. **Cookie 检查** — 部分 WAF 设置追踪 Cookie
4. **状态码异常** — 攻击请求返回异常状态码（403/406/429/444）

### 常见 WAF 绕过触发 payload
```
/?id=1' OR 1=1--
/?search=<script>alert(1)</script>
/../../../etc/passwd
/?file=php://filter/convert.base64-encode/resource=index
```

---

## 源码泄露检查

### 常见源码泄露类型与检测
| 类型 | 路径 | 检测方法 | 危害等级 |
|------|------|---------|---------|
| Git 仓库 | `/.git/config`, `/.git/HEAD` | 200 且含 git 内容 | 🔴 Critical |
| SVN 仓库 | `/.svn/entries` | 200 且含 svn 内容 | 🔴 Critical |
| .DS_Store | `/.DS_Store` | 下载后解析目录结构 | 🟡 Medium |
| .env 文件 | `/.env` | 含 DB_PASSWORD 等 | 🔴 Critical |
| web.config | `/web.config` | IIS 配置泄露 | 🟡 Medium |
| 备份文件 | `/.bak`, `/.swp`, `/.old`, `/.tar.gz` | 直接下载 | 🟡 Medium |
| Docker | `/Dockerfile`, `/docker-compose.yml` | 容器配置 | 🟡 Medium |
| package.json | `/package.json` | Node.js 依赖 | 🟢 Low |
| composer.json | `/composer.json` | PHP 依赖 | 🟢 Low |
| webpack | `/webpack.json`, `/map Files` | 源码映射 | 🟡 Medium |

### Git 泄露利用流程
1. 访问 `/.git/HEAD` → 获取 ref 路径
2. 访问 `/.git/config` → 获取远程仓库信息
3. 访问 `/.git/objects/` → 遍历 Git 对象
4. 使用 GitHack/scrabble 工具自动恢复源码

### 敏感文件扫描路径列表
```
/.git/config
/.git/HEAD
/.svn/entries
/.DS_Store
/.env
/.env.bak
/.env.local
/web.config
/config.php
/config.yml
/backup.sql
/database.sql
/db.sql
/phpinfo.php
/test/
/debug/
/console/
/admin/
/wp-config.php
/robots.txt
/sitemap.xml
/.well-known/security.txt
```
