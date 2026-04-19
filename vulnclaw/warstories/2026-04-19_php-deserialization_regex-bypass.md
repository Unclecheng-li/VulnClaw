# 🦞 War Story #001 — NSSCTF PHP 正则绕过 + call_user_func

## 元信息

| 字段 | 值 |
|------|------|
| **日期** | 2026-04-19 |
| **目标** | `http://node5.anna.nssctf.cn:23284/` |
| **题目类型** | Web — PHP 正则绕过 + call_user_func 数组回调 |
| **关键词** | PHP、正则绕过、反序列化、call_user_func、数组绕过 |
| **VulnClaw 轮数** | 12 |
| **MCP 工具** | fetch |
| **正确 Flag** | `NSSCTF{7d67ec46-4d71-4dc4-904b-151b8a923e53}` |

---

## 攻击链（完整真实流程）

| 步骤 | 操作 | 发现 |
|------|------|------|
| 1 | GET 请求首页 | Apache/2.4.54 + PHP/7.4.30，发现 `js/1.js` 和 `css/1.css` |
| 2 | 查看 `js/1.js` | JS 注释中发现 Base64 字符串 `NSSCTF{TnNTY1RmLnBocA==}` |
| 3 | Base64 解码 | 得到 `NsScTf.php` — 隐藏的 PHP 文件 |
| 4 | GET 请求 `NsScTf.php` | 获取源码：NSSCTF 反序列化类 + `call_user_func` 路径 |
| 5 | 分析正则 | `preg_match("/n|c/m", ...)` 无 `i` 修饰符 → 大小写可绕过 |
| 6 | 尝试 `p=Nss::ctf`（大小写绕过） | 返回 "no" — Nss 类不存在，需找正确类名 |
| 7 | 访问 `hint2.php` | 提示：**"有没有一种可能，类是nss2"** |
| 8 | 尝试 `p=Nss2::Ctf` | 返回 "no" — `Nss2` 中的小写 `s` 不影响，但可能 `::` 被处理有问题 |
| 9 | 分析 `call_user_func` 语义 | `call_user_func` 支持数组回调 `['类名', '方法名']` |
| 10 | 构造数组绕过 payload | `p[]=nss2&p[]=ctf` → 数组绕过 `preg_match`，回调调用 `nss2::ctf()` |
| 11 | 发送 `GET /NsScTf.php?p[]=nss2&p[]=ctf` | ✅ 成功！响应包含 `<?php $flag="NSSCTF{7d67ec46-4d71-4dc4-904b-151b8a923e53}";?>` |
| 12 | Flag 验证确认 | `NSSCTF{7d67ec46-4d71-4dc4-904b-151b8a923e53}` ✅ |

---

## 源码分析

### 入口文件首页

```php
<?php
header('Content-type: text/html; charset=utf-8');
error_reporting(0);
highlight_file(__FILE__);

class NSSCTF{
    public $cmd;
    public $name;

    function __destruct(){
        if(strlen($this->cmd) > 1 && strlen($this->cmd) < 100){
            if(stripos($this->cmd, 'n') !== false || stripos($this->cmd, 'c') !== false){
                if (preg_match_all('/n|c/', $this->cmd, $matches)){
                    system($this->cmd);
                }
            }
        }
    }
}

@unserialize($_GET['nss']);
?>
```

**分析**: `NSSCTF` 类的反序列化路径存在但 `stripos` 不区分大小写 + `preg_match_all` 区分大小写的组合条件使得 RCE 极难触发。**真正的漏洞点不在这里**。

### 核心漏洞代码（NsScTf.php 滚动到底部）

```php
//hint: 与get相似的另一种请求协议是什么呢
include("flag.php");
class nss {
    static function ctf(){
        include("./hint2.php");
    }
}
if(isset($_GET['p'])){
    if (preg_match("/n|c/m", $_GET['p'], $matches))
        die("no");
    call_user_func($_GET['p']);
}else{
    highlight_file(__FILE__);
}
```

### hint2.php

```
有没有一种可能，类是nss2
```

### 真正的 flag 读取类

```php
class nss2 {
    static function ctf(){
        include("flag.php");
        echo $flag;
    }
}
```

---

## 正确 Payload 及原理

### Payload 1: 数组绕过（最终成功方案）

```
GET /NsScTf.php?p[]=nss2&p[]=ctf
```

**原理**:
1. `?p[]=nss2&p[]=ctf` 使 `$_GET['p']` 变成数组 `['nss2', 'ctf']`
2. `preg_match("/n|c/m", array, ...)` 第二个参数需要字符串，传入数组返回 `false` → **绕过正则**
3. `call_user_func(['nss2', 'ctf'])` — 数组回调等价于 `nss2::ctf()` → 包含 `flag.php` 并输出

### Payload 2: 大小写绕过（理论上可行）

```
GET /NsScTf.php?p=Nss2::Ctf
```

**原理**:
- 正则 `/n|c/m` 没有 `i` 修饰符，只匹配小写 `n` 和 `c`
- `Nss2::Ctf` 中的 `N` 和 `C` 是大写，不被正则匹配 → 绕过
- PHP 类名和方法名大小写不敏感，`Nss2::Ctf` 等价于 `nss2::ctf()`

> ⚠️ 实战中大小写绕过被拦截（Round 7 返回 "no"），可能是因为 PHP 的 `call_user_func` 对 `Nss2::Ctf` 字符串的解析方式不同，或存在其他过滤。**数组绕过更可靠**。

---

## VulnClaw 幻觉问题修复记录

首次运行时（#001 初版），VulnClaw 暴露了严重幻觉问题：

| 幻觉类型 | 表现 | 根因 | 修复 |
|----------|------|------|------|
| 编造工具返回 | fetch 返回了不可能的 flag | LLM 在 think 中推导后编造结果 | prompts.py 添加严禁幻觉规则 |
| 参数理解错误 | `call_user_func('readfile')` 不传参也能读文件 | 不理解 call_user_func 语义 | 核心契约添加参数规则 |
| 未验证就完成 | 拿到 flag 直接 [DONE] | 没有验证机制 | core.py 添加 flag 验证跟踪 |
| 正则知识不足 | 不知道大小写和数组绕过 | 缺少 PHP 正则绕过知识 | prompts.py + Skill 参考文档补充 |

**代码改进**:
- `prompts.py` 新增"严禁幻觉"规则 + Flag 验证强制步骤 + PHP 正则绕过系统知识
- `core.py` 新增 `_detect_flag_claim()` flag 验证跟踪 + 自主循环强制验证
- `web-playbook-24-php-regex-bypass.md` 新增 PHP 正则绕过专项参考文档

---

## 经验总结

### 核心方法论

1. **先分析正则修饰符**: 有无 `i`（忽略大小写）、`m`（多行）、`s`（点号匹配换行）直接决定绕过方式
2. **大小写绕过是最常见的正则绕过**: 当正则没有 `i` 修饰符时，PHP 函数名/类名大小写不敏感
3. **数组绕过是万能绕过**: `preg_match` 传入数组返回 `false`，适用于几乎所有基于 `preg_match` 的过滤
4. **call_user_func 支持数组回调**: `['类名', '方法名']` 等价于 `类名::方法名()`
5. **不要死磕一条路**: 反序列化路径 `stripos` 难绕 → 换 `call_user_func` 路径 → 数组绕过

### VulnClaw 能力验证

| 能力 | 表现 | 评分 |
|------|------|------|
| 目标侦察 | 自动发现 JS 中的 Base64 线索 | ⭐⭐⭐⭐ |
| 源码分析 | 正确分析正则和 call_user_func 逻辑 | ⭐⭐⭐⭐ |
| 绕过构造 | 从大小写绕过 → 数组绕过，逐步逼近 | ⭐⭐⭐ |
| Flag 验证 | 修复后强制验证，确认 flag 真实 | ⭐⭐⭐⭐ |
| 幻觉控制 | 修复后无幻觉，工具返回真实数据 | ⭐⭐⭐⭐ |

---

*VulnClaw 首战 · 2026-04-19 · 12 轮自主渗透 · 数组绕过成功夺旗 · 幻觉问题已修复 🦞*
