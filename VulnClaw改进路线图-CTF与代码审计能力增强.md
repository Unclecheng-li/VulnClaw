# VulnClaw 改进路线图：CTF 与代码审计能力增强

> 基于 NSSCTF #002（PHP RCE + 空格绕过 + 弱比较）实战失败分析
> 日期：2026-04-19

---

## 一、问题概述

VulnClaw 在 NSSCTF #002 题目中运行了 68 轮仍未解出，最终被用户手动中断。该题考点为 PHP 弱比较绕过 + RCE 空格绕过，属于 CTF Web 入门级难度。

VulnClaw 的表现暴露了系统性问题，不仅仅是"Skill 不够"，而是**工具能力、上下文管理、知识形态、提示策略**四层缺陷叠加导致的。

---

## 二、实战复盘：68 轮到底卡在哪？

### 2.1 题目核心逻辑

```php
// F1l1l1l1l1lag.php（经 learning.php → start.php → f14g.php 三层跳转发现）

// 入口1（简单路径）
if (isset($_GET['cmd']) && isset($_GET['web'])) {
    $web = $_GET['web'];
    if ($web == md5($web)) {                    // 弱比较绕过：0e215962017
        if (isset($_GET['space'])) {
            $space = $_GET['space'];
            if (!preg_match('/\s/i', $space)) { // 空格绕过
                $cmd = "system" . "(\"" . $space . " " . $cmd . "\")";
                eval($cmd);                      // 命令执行
            }
        }
    }
}

// 入口2（复杂路径）
if (isset($_GET['get'])) {
    $get = $_GET['get'];
    if (!strstr($get, "& ")) {
        $get = str_ireplace("flag", " ", $get);  // flag 被替换为空格
        if (strlen($get) > 18) {
            eval($get);
        }
    }
}
```

### 2.2 VulnClaw 的执行轨迹

| 阶段 | 轮数 | 行为 | 问题 |
|------|------|------|------|
| 信息收集 | 1-7 | 访问 learning.php，发现弱比较代码 | ✅ 正常 |
| 弱比较绕过 | 8 | `web=0e215962017` 成功 | ✅ 正常 |
| 链条发现 | 9-14 | 跟随 hint 发现 start.php → f14g.php → F1l1l1l1l1lag.php | ✅ 正常 |
| 源码分析 | 15 | 获取完整源码，发现两个入口 | ⚠️ 分析不够深入 |
| **死循环** | **16-68** | **几乎全部聚焦入口2（`get` 参数），反复尝试不同 payload** | **❌ 核心失败** |
| 未尝试 | - | 入口1（`cmd` + `space`）更简单，从未认真尝试 | ❌ 路径选择错误 |

### 2.3 关键失败点

1. **LLM 被 `highlight_file()` 吓住**：认为 eval 的输出被源码高亮"挡住"了，实际上入口1的 `system()` 输出会正常显示在页面末尾
2. **50+ 轮死磕入口2**：没有及时切换到更简单的入口1
3. **反复试同样的方法**：用 `?>` 结束 PHP、写 webshell、用 `ob_end_clean()` 等方法反复尝试，但没有记住哪些已经失败
4. **没有代码执行能力**：无法写 Python 脚本来精确构造 payload、解析响应差异

---

## 三、根因分析（5 层）

### 层1：工具能力缺失 — 只有 fetch，没有代码执行（权重 35%）

**现状**：VulnClaw 只有一个 `fetch` 工具发 HTTP 请求。

**问题**：
- 无法执行 Python/PHP 代码来构造复杂 payload
- 无法精确解析 HTML 响应中的细微差异（如 399 字节 vs 401 字节代表什么）
- 无法做 base64 编解码（crypto_toolkit 虽有但调度不稳定）
- 无法写文件到目标服务器再读回来
- 无法用 Python 脚本批量测试不同 payload

**人类 CTF 选手怎么做**：
```python
import requests

# 1. 先测弱比较
r = requests.get(url, params={"web": "0e215962017"})
print(r.text)  # 看到重定向

# 2. 用入口1，直接执行命令
r = requests.get(url, params={
    "web": "0e215962017",
    "cmd": "cat flag.php",
    "space": ""  # 空格用空字符串绕过
})
print(r.text)  # flag 直接在页面末尾
```

**修复方案**：新增 `python_execute` 工具，允许 LLM 执行 Python 代码片段。

---

### 层2：上下文丢失导致重复试错（权重 25%）

**现状**：

```python
# core.py 第 411 行 — 只保留最近 5 条步骤
recent_steps = state.executed_steps[-5:]

# core.py 第 630 行 — 工具结果截断到 500 字符
tool_summary_parts.append(f"工具结果: {tr['content'][:500]}")

# context.py 第 162-166 行 — 压缩时只保留含特定标记的行
if any(marker in stripped for marker in [
    "[+]", "[!]", "发现", "漏洞", "flag", "CVE",
    "端口", "开放", "服务", "路径", "泄露", "注入",
]):
```

**问题**：
1. **步骤只保留最近 5 条**：之前发现的关键信息（如"入口1存在且更简单"）在几轮之后就丢了
2. **工具结果截断 500 字符**：HTTP 响应的完整内容（特别是 `highlight_file` 的输出 vs eval 输出的差异）被截掉
3. **压缩只保留"发现"不保留"失败"**：`"我试过 ?> 但失败了"` 这类信息不在保留列表中
4. **LLM 分析被摘要化**：第 330 行 `f"[Round {round_num} 分析] {response_text}"` 只保留分析结论，不保留推理过程

**CTF 场景 vs 渗透测试场景的差异**：

| 维度 | 渗透测试 | CTF 解题 |
|------|---------|---------|
| 需要记住的 | 发现的漏洞、攻击面 | 试过但失败的方法 |
| 可以丢弃的 | 失败的尝试（不影响结论） | 重复的发现（只关注当前进度） |
| 关键信息类型 | "目标有 SQLi" | "用 get 参数试了 30 轮都失败" |
| 信息保留策略 | 正面信息优先 | 负面信息（失败历史）优先 |

**修复方案**：改进上下文压缩策略，增加"失败历史"保留。

---

### 层3：Skill 只有方法论没有知识库（权重 20%）

**现状**：

`web-security-advanced` Skill 的 SKILL.md 内容：
- ✅ 有测试流程框架（SQL 注入检测方法、XSS 分类等）
- ❌ 没有具体的 PHP 弱比较绕过值（如 `0e215962017`、`0e113810047`）
- ❌ 没有空格绕过的具体 payload（`${IFS}`、`$IFS$9`、`<`、`%09`、`{cat,flag}`）
- ❌ 没有 PHP `highlight_file` 与 `eval` 输出顺序的说明
- ❌ 没有 PHP 代码审计的 checklist

`dispatcher.py` 的关键词匹配：
```python
"web高级|注入|sql注入|xss|ssrf|ssti|xxe|命令注入|反序列化": ["web-security-advanced"],
```
- ✅ `"反序列化"` 能命中
- ❌ `"RCE"` 不在关键词中
- ❌ `"弱比较"` 不在关键词中
- ❌ `"空格绕过"` 不在关键词中

**对比 CTF Wiki / PayloadsAllTheThings**：

这类 CTF 知识库的特点是**精确的绕过值和 payload 模板**，不是方法论：

```
# PHP 弱比较绕过值
0e215962017  → md5("0e215962017") = "0e291242476940776845150308577824" (0e开头)
QNKCDZO      → md5("QNKCDZO") = "0e830400451993494058024219903391" (0e开头)
240610708    → md5("240610708") = "0e462097431906509019562988736854" (0e开头)

# 空格绕过
${IFS}       → $IFS 是 Linux 内部字段分隔符
$IFS$9       → $9 是当前 shell 第9个位置参数（空），防止歧义
<            → 重定向符代替空格：cat<flag.php
%09          → Tab 字符的 URL 编码
{cat,flag}   → Bash 大括号展开

# highlight_file + eval 输出顺序
highlight_file() 在 eval() 之前执行，但 system() 的输出是直接写入 stdout，
会出现在 highlight_file 输出之后，不会被"挡住"。
```

**修复方案**：新增 CTF 专项 Skill，以知识库形式提供具体绕过值和 payload 模板。

---

### 层4：LLM 代码审计精度不够（权重 15%）

**现状**：LLM 对 PHP 代码的分析停留在表面。

**具体表现**：

1. **没有理解 `eval($cmd)` 的构造逻辑**：
   ```php
   $cmd = "system" . "(\"" . $space . " " . $cmd . "\")";
   ```
   LLM 没有推算出当 `$space=""` 且 `$cmd="cat flag.php"` 时，最终执行的是 `system(" cat flag.php")` — 前面有个空格但不影响执行。

2. **没有理解 `highlight_file` 与 `system` 的输出顺序**：
   `highlight_file()` 输出源码高亮 → `eval($cmd)` 中的 `system()` 输出命令结果 → 两者在同一个 HTTP 响应中，命令结果在源码之后。

3. **路径选择失误**：入口1只需要 3 个参数（`web` + `cmd` + `space`），入口2需要绕过 `flag` 替换 + 长度限制 + eval 输出可见性问题。LLM 选择了更复杂的路径。

**修复方案**：改进代码审计提示策略，在系统提示中强调"先完整分析代码结构，再选择最简单的利用路径"。

---

### 层5：渗透测试 vs CTF 解题的定位差异（权重 5%）

这是最根本的定位问题，但不是 MVP 阶段需要解决的。

| 维度 | 渗透测试 | CTF 解题 |
|------|---------|---------|
| 目标 | 找到尽可能多的漏洞 | 找到唯一 flag |
| 信息量 | 目标大、信息多、需要过滤 | 目标小、信息少、需要深挖 |
| 失败模式 | 漏掉一个漏洞 | 卡在一个点上就出不来 |
| 需要的技能 | 广度：各种漏洞类型都要会 | 深度：特定 trick 必须精 |
| 工具需求 | 扫描器、代理、爆破 | 代码执行、编码转换、payload 构造 |
| 时间模型 | 可以长时间、分阶段 | 需要快速试错、迭代 |
| 知识形态 | 方法论（OWASP Top 10） | 知识库（0e 开头的 md5 值、空格绕过技巧大全） |

**修复方案**：长期考虑新增 CTF 模式，短期通过 P0-P2 改进覆盖。

---

## 四、改进方案（按优先级）

### P0：新增 `python_execute` 工具（解决 35% 问题）

**目标**：让 LLM 能执行 Python 代码片段，精确构造和发送 HTTP 请求。

**实现方案**：

```python
# 在 core.py 的 _build_openai_tools() 中新增
tools.append({
    "type": "function",
    "function": {
        "name": "python_execute",
        "description": (
            "执行 Python 代码片段。用于：构造复杂 HTTP 请求、解析响应、"
            "做编码转换、批量测试 payload、比较响应差异等。"
            "代码在受限环境中执行，有超时限制。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "要执行的 Python 代码",
                },
                "purpose": {
                    "type": "string",
                    "description": "简要说明执行目的（用于审计日志）",
                },
            },
            "required": ["code"],
        },
    },
})
```

**执行环境设计**：
- 使用 `subprocess` 运行，超时 30 秒
- 预装 `requests`、`beautifulsoup4`、`pycryptodome` 等常用库
- 沙箱限制：不能访问 `~/.vulnclaw/config.yaml`、不能写文件到项目目录外
- 输出捕获：stdout + stderr 都返回给 LLM

**预期效果**：
- LLM 可以写 Python 脚本精确构造 payload
- 可以解析 HTTP 响应中的细微差异
- 可以批量测试不同绕过技巧
- 可以做 base64/hex 编解码

---

### P1：改进上下文压缩策略（解决 25% 问题）

**目标**：CTF 场景下保留"失败历史"，避免重复试错。

**方案 1：增加失败历史注入**

在 `_build_round_context()` 中新增"失败历史"段落：

```python
# 在 _build_round_context() 中添加
failed_attempts = []
for step in state.executed_steps:
    if any(marker in step.lower() for marker in [
        "失败", "没有", "返回相同", "被拦截", "404", "no",
        "未成功", "无效", "error", "failed", "still",
    ]):
        failed_attempts.append(step[:150])

failed_summary = ""
if failed_attempts:
    failed_summary = f"\n失败历史（不要重复这些操作）:\n"
    for f in failed_attempts[-10:]:  # 保留最近 10 条失败
        failed_summary += f"  ❌ {f}\n"
```

**方案 2：改进工具结果截断策略**

```python
# 当前：粗暴截断到 500 字符
tool_summary_parts.append(f"工具结果: {tr['content'][:500]}")

# 改进：对 HTTP 响应保留头部 + 尾部（flag 通常在末尾）
content = tr['content']
if len(content) > 1000:
    content = content[:500] + "\n...[中间省略]...\n" + content[-500:]
```

**方案 3：压缩时保留负面信息**

```python
# 当前：只保留含特定标记的行
if any(marker in stripped for marker in ["[+]", "[!]", "发现", ...]):

# 改进：增加负面标记
if any(marker in stripped for marker in [
    "[+]", "[!]", "[-]", "发现", "失败", "无效", "没有", "返回相同",
    "漏洞", "flag", "CVE", "端口", "开放", "服务", "路径", "泄露", "注入",
    "Status:", "Headers:", "Body", "被拦截", "404", "错误",
]):
```

---

### P2：新增 CTF 专项 Skill（解决 20% 问题）

**目标**：提供 CTF 常见绕过技巧的知识库，而非通用的渗透测试方法论。

**Skill 结构**：

```
vulnclaw/skills/specialized/ctf-toolkit/
├── SKILL.md                          # Skill 入口 + 场景路由
└── references/
    ├── php-bypass-cheatsheet.md      # PHP 绕过技巧大全
    ├── command-injection-bypass.md   # 命令注入绕过技巧
    ├── web-shell-bypass.md           # Webshell 绕过技巧
    ├── ctf-common-values.md          # CTF 常用绕过值速查
    ├── php-code-audit-checklist.md   # PHP 代码审计 Checklist
    └── python-payload-templates.md   # Python payload 模板
```

**SKILL.md 触发词**：

```python
"ctf|夺旗|flag|弱比较|空格绕过|正则绕过|反序列化|rce|命令执行|代码审计": ["ctf-toolkit"],
"0e|md5绕过|preg_match绕过|eval绕过|highlight_file": ["ctf-toolkit"],
```

**`ctf-common-values.md` 内容示例**：

```markdown
# CTF 常用绕过值速查

## PHP 弱比较绕过（$a == md5($a)）

| 值 | MD5 结果 | 说明 |
|----|---------|------|
| QNKCDZO | 0e830400451993494058024219903391 | 0e 开头，PHP 视为 0 |
| 240610708 | 0e462097431906509019562988736854 | 同上 |
| 0e215962017 | 0e291242476940776845150308577824 | 同上 |
| s878926199a | 0e545993274517709034328855841020 | 同上 |
| s155964671a | 0e342768416822451524974117254469 | 同上 |

## PHP 弱比较绕过（$a != $b && md5($a) == md5($b)）

| 值A | 值B | MD5(值A) | MD5(值B) |
|-----|-----|---------|---------|
| QNKCDZO | 240610708 | 0e830... | 0e462... |
| s878926199a | s155964671a | 0e545... | 0e342... |

## 命令注入空格绕过

| 方法 | 示例 | 说明 |
|------|------|------|
| ${IFS} | cat${IFS}flag.php | 内部字段分隔符 |
| $IFS$9 | cat$IFS$9flag.php | 防止变量名歧义 |
| < | cat<flag.php | 重定向代替空格 |
| %09 | cat%09flag.php | Tab 的 URL 编码 |
| {cat,flag.php} | Bash 大括号展开 | 仅 Bash |
| %0a | cat%0aflag.php | 换行符 |

## PHP 正则绕过

| 场景 | 方法 | 示例 |
|------|------|------|
| 无 i 修饰符 | 大小写绕过 | Nss2 绕过 /n/ |
| preg_match 只检查字符串 | 数组绕过 | p[]=xxx 使 preg_match 返回 false |
| m 修饰符 | 不影响普通字符匹配 | /n/m 仍然匹配 n |
| ^$ + m | 换行绕过 | aaa%0abbb 绕过 /^aaa$/m |
```

---

### P3：改进代码审计提示策略（解决 15% 问题）

**目标**：引导 LLM 先完整分析代码结构，再选择最简单的利用路径。

**方案：在 AUTO_PENTEST_INSTRUCTION 中新增代码审计指令**

```python
CODE_AUDIT_INSTRUCTION = """\
## 代码审计模式（当遇到源码时启用）

当获取到目标应用的源码时，按以下步骤分析：

### 第一步：完整源码分析
- 识别所有用户输入入口（$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）
- 识别所有危险函数（eval/system/exec/passthru/shell_exec/unserialize/include/require）
- 识别所有过滤/检查逻辑（preg_match/strstr/strpos/strlen/黑名单）
- **画出数据流图**：用户输入 → 过滤检查 → 危险函数

### 第二步：路径选择
- 列出所有从"用户输入"到"危险函数"的路径
- 评估每条路径的绕过难度（过滤越少 → 越简单 → 越优先）
- **优先选择最简单的路径**，而非最"有趣"的路径
- 如果有多条路径，先尝试最简单的，失败再切换

### 第三步：输出可见性分析
- 确认命令/代码执行的输出如何返回给用户
- 常见情况：
  - `system()` 输出直接写入 stdout → 在 HTTP 响应中可见
  - `exec()` 输出需要 echo/print 才可见
  - `highlight_file()` 输出在 eval() 之前 → 不影响 eval 输出
  - PHP 输出缓冲（ob_start）可能捕获 eval 输出
- **如果不确定输出是否可见，先用简单命令测试**（如 `id`、`echo test123`）

### 第四步：Payload 构造
- 基于路径分析构造最小可行 payload
- 一次只改变一个变量
- 验证每一步（先测弱比较绕过是否生效，再测命令执行）
"""
```

---

### P4：LLM 调用优化（长期）

**目标**：减少无效轮次，提高每轮的信息获取效率。

**方案 1：多工具并行调用**

当前 `_call_llm_auto` 在一轮中只处理一次工具调用。可以改为：
- 允许 LLM 同时调用多个工具（如同时测试 `cmd` 参数和 `get` 参数）
- 减少总轮数

**方案 2：响应差异检测**

```python
# 自动比较不同 payload 的响应差异
async def _detect_response_diff(self, responses: list[dict]) -> str:
    """Compare multiple HTTP responses and highlight differences."""
    if len(responses) < 2:
        return ""
    lengths = [r.get("content_length", 0) for r in responses]
    if max(lengths) - min(lengths) > 0:
        return f"响应长度差异: {lengths}，最短={min(lengths)}，最长={max(lengths)}"
    return ""
```

**方案 3：自动路径切换建议**

当检测到连续 5 轮以上在同一路径上无进展时，注入提示：
```
⚠️ 你已经在当前路径上尝试了 5 轮以上但没有突破。
请重新审视源码，是否有其他更简单的利用路径？
列出所有可能的路径，然后切换到最简单的一条。
```

---

## 五、实施计划

| 优先级 | 改进项 | 预计工作量 | 目标版本 |
|--------|--------|-----------|---------|
| P0 | `python_execute` 工具 | 2-3 天 | v0.1.1 |
| P1 | 上下文压缩策略改进 | 1-2 天 | v0.1.1 |
| P2 | CTF 专项 Skill | 2-3 天 | v0.1.2 |
| P3 | 代码审计提示策略 | 0.5 天 | v0.1.1 |
| P4 | LLM 调用优化 | 3-5 天 | v0.2 |

### v0.1.1 里程碑（最快见效）

- [ ] 新增 `python_execute` 工具
- [ ] 改进 `_build_round_context()` 保留失败历史
- [ ] 改进工具结果截断策略（保留首尾）
- [ ] 压缩时保留负面信息
- [ ] 新增代码审计指令到 AUTO_PENTEST_INSTRUCTION

### v0.1.2 里程碑（CTF 专项）

- [ ] 新增 `ctf-toolkit` Skill（含知识库）
- [ ] 更新 dispatcher.py 触发词
- [ ] 添加 PHP 代码审计 checklist

---

## 六、验证标准

改进后，VulnClaw 应能在以下 CTF 题目中表现达标：

| 难度 | 题目类型 | 当前表现 | 目标表现 |
|------|---------|---------|---------|
| 入门 | PHP 弱比较 + RCE | ❌ 68 轮未解出 | ✅ ≤ 10 轮 |
| 入门 | PHP 正则绕过 + call_user_func | ✅ 12 轮解出 | ✅ ≤ 8 轮 |
| 中等 | SQL 注入 + WAF 绕过 | 未测试 | ✅ ≤ 15 轮 |
| 中等 | 文件上传 + 后缀绕过 | 未测试 | ✅ ≤ 15 轮 |

**核心指标**：
- **首次有效 payload 构造轮数**：从"发现源码"到"构造出可工作的 payload"的轮数
- **重复试错率**：同一方法被尝试的次数（目标 ≤ 2 次）
- **路径切换及时性**：从"卡住"到"切换路径"的轮数（目标 ≤ 3 轮）

---

## 七、Skill 差异分析与新增/更新/删除计划

> 基于 `ctf-skills-main`（21+17+13=51 个参考文件）与 VulnClaw 现有 9 个专项 Skill 的逐项对比

### 7.1 ctf-skills-main 知识资产盘点

| Skill | 参考文件数 | 总大小 | 知识形态 | 核心价值 |
|-------|-----------|--------|---------|---------|
| **ctf-web** | 21 | ~400KB | **实战知识库**：具体绕过值、payload 模板、真实赛题案例 | ⭐⭐⭐⭐⭐ 最常用 |
| **ctf-crypto** | 17 | ~390KB | **攻击手法库**：RSA/AES/ECC/LWE 具体攻击参数和代码 | ⭐⭐⭐⭐ |
| **ctf-misc** | 13 | ~220KB | **逃逸手册**：PyJail/BashJail/编码/游戏VM | ⭐⭐⭐ |
| ctf-pwn | 19 | ~350KB | 二进制利用链 | ⭐⭐ 非紧急 |
| ctf-reverse | 19 | ~350KB | 逆向技巧 | ⭐⭐ 已有 client-reverse 覆盖 |
| ctf-forensics | 15 | ~280KB | 取证分析 | ⭐ 非紧急 |
| ctf-ai-ml | - | - | AI/ML CTF | ⭐ 极少 |
| ctf-malware | - | - | 恶意软件分析 | ⭐ 极少 |
| ctf-osint | - | - | 开源情报 | ⭐ 极少 |

**ctf-web 详拆**（最核心的 21 个文件）：

| 文件 | 大小 | 核心内容 | VulnClaw 对应 |
|------|------|---------|-------------|
| `SKILL.md` | 10KB | 路由+First-Pass工作流+快速命令 | ❌ 无对应 |
| `server-side.md` | 29KB | **PHP Type Juggling 弱比较值、php://filter LFI、SSTI 模板注入链** | ❌ web-security-advanced 无此细节 |
| `server-side-2.md` | 15KB | XXE/OOB、PHP变量变量、uniqid预测、命令注入变体、GraphQL | ❌ 无 |
| `server-side-exec.md` | 21KB | **Ruby/Perl/LaTeX/JS eval注入、PHP preg_replace /e、文件上传RCE、PHP extract()覆写** | ❌ 无 |
| `server-side-exec-2.md` | 39KB | SQLi碎片绕过、路径解析trick、多语言Webshell、BMP像素马 | ❌ 无 |
| `server-side-deser.md` | 22KB | Java/Python/PHP反序列化+竞态、SoapClient CRLF SSRF | ⚠️ web-security-advanced 有playbook但不够深 |
| `server-side-advanced.md` | 16KB | SSRF高级、目录穿越、Nginx alias traversal | ⚠️ 部分覆盖 |
| `server-side-advanced-2~4.md` | 54KB | Docker API SSRF、Windows路径trick、WeasyPrint SSRF等 | ❌ 无 |
| `client-side.md` | 22KB | XSS/CSRF/缓存投毒/请求走私 | ⚠️ web-security-advanced 有覆盖 |
| `client-side-advanced.md` | 37KB | CSP绕过/Unicode/XSSI/CSS渗透 | ⚠️ 部分覆盖 |
| `auth-and-access.md` | 35KB | 认证绕过/IDOR/子域名接管 | ⚠️ web-logic-auth.md 有覆盖 |
| `auth-jwt.md` | 9KB | JWT/JWE攻击 | ⚠️ 部分覆盖 |
| `auth-infra.md` | 14KB | OAuth/SAML/CORS | ⚠️ 部分覆盖 |
| `node-and-prototype.md` | 7KB | 原型污染/Node攻击链 | ❌ 无 |
| `web3.md` | 16KB | Solidity/Web3 | ❌ 无（低优先级） |
| `cves.md` | 16KB | CVE驱动技巧 | ❌ 无 |
| `field-notes.md` | 35KB | **长篇exploit笔记：SQLi/XSS/LFI/JWT/SSTI/SSRF/命令注入/XXE/反序列化速查** | ❌ 无对应（这是最关键的参考） |
| `sql-injection.md` | 38KB | SQLi大全 | ⚠️ web-injection.md 有覆盖 |

**关键差距**：ctf-web 有大量**具体绕过值和真实赛题案例**（如 PHP 弱比较的 `0e` 值、`highlight_file` 输出顺序、空格绕过 `${IFS}`），而 VulnClaw 的 web-security-advanced 只有方法论框架。

---

### 7.2 VulnClaw 现有 Skill 状态评估

| Skill | 定位 | 问题 | 处置 |
|-------|------|------|------|
| **web-security-advanced** | Web高级安全（方法论） | ❌ 无CTF实战知识（无弱比较值、无空格绕过payload、无PHP代码审计checklist）| 🔄 **更新**：增加CTF实战速查参考 |
| **crypto-toolkit** | 编解码工具 | ❌ 只有编解码操作，无密码学攻击知识（无RSA攻击、无Padding Oracle、无ECC攻击）| 🔄 **更新**：增加密码学攻击参考 |
| **rapid-checklist** | 渗透速查 | ⚠️ 偏渗透测试，无CTF专项卡片 | 🔄 **更新**：增加CTF速查路由 |
| **waf-bypass** (core) | WAF绕过 | ⚠️ 有基本绕过技巧但不够深 | ✅ 保留（与CTF Skill互补） |
| web-pentest | Web渗透流程 | ✅ 流程性内容，与CTF Skill不冲突 | ✅ 保留 |
| pentest-tools | 工具速查 | ✅ 工具性内容 | ✅ 保留 |
| ai-mcp-security | AI安全 | ✅ 不涉及 | ✅ 保留 |
| android-pentest | 安卓渗透 | ✅ 不涉及 | ✅ 保留 |
| client-reverse | 客户端逆向 | ✅ 不涉及 | ✅ 保留 |
| intranet-pentest-advanced | 内网渗透 | ✅ 不涉及 | ✅ 保留 |

---

### 7.3 新增 Skill 计划（3 个专项）

#### 🆕 Skill 1：`ctf-web`（CTF Web 攻击知识库）

**路径**：`vulnclaw/skills/specialized/ctf-web/`

**定位**：CTF Web 题目实战知识库，提供**具体绕过值、payload 模板、代码审计 checklist**，而非渗透测试方法论。

**与 `web-security-advanced` 的关系**：
- `web-security-advanced` → 渗透测试方法论（怎么系统性测试一个Web应用）
- `ctf-web` → CTF实战知识库（PHP弱比较用什么值、空格怎么绕过、eval输出怎么回显）

**SKILL.md 结构**：

```yaml
---
name: ctf-web
description: CTF Web攻击知识库 — PHP弱比较绕过、命令注入空格绕过、eval回显技巧、SSTI注入链、反序列化利用链、PHP代码审计checklist、常见flag位置
---
```

**触发词（dispatcher.py 新增）**：

```python
"ctf|夺旗|flag|弱比较|空格绕过|正则绕过|rce|代码审计|eval绕过|highlight_file": ["ctf-web"],
"0e|md5绕过|preg_match绕过|类型绕过|type juggling|弱类型": ["ctf-web"],
"回显|无回显|blind|rce绕过|命令执行绕过|php代码审计": ["ctf-web"],
```

**references/ 文件规划**（从 ctf-skills-main 提炼+规范，不直接拷贝）：

| 新文件名 | 来源 | 内容（规范后） | 大小估计 |
|---------|------|-------------|---------|
| `php-bypass-cheatsheet.md` | server-side.md PHP Type Juggling + server-side-exec.md eval绕过 | PHP弱比较值表（0e开头MD5值大全）、数组绕过、extract()覆写、变量变量、intval()绕过 | ~8KB |
| `command-injection-bypass.md` | server-side-2.md 命令注入 + waf-bypass.md | 空格绕过全表（${IFS}/$IFS$9/</%09/%0a/{}）、分隔符变体、命令混淆、通配符、编码绕过 | ~6KB |
| `eval-and-rce-techniques.md` | server-side-exec.md + server-side-exec-2.md | eval回显技巧（system/exec/passthru/shell_exec区别）、highlight_file+eval输出顺序、无回显外带（DNS/HTTP）、PHP preg_replace /e、assert()注入 | ~10KB |
| `ssti-injection-chains.md` | server-side.md SSTI章节 | Jinja2/Twig/ERB/Mako/EJS/Vue.js/Smarty/Thymeleaf注入链速查表 | ~8KB |
| `deserialization-playbook.md` | server-side-deser.md | PHP/Java/Python反序列化利用链、SoapClient CRLF SSRF、PHP序列化长度操纵 | ~10KB |
| `file-upload-to-rce.md` | server-side-exec.md 上传章节 | .htaccess绕过、日志投毒、多语言Webshell、BMP像素马、ZIP PHP webshell、polyglot上传 | ~8KB |
| `web-ctf-quick-reference.md` | field-notes.md + SKILL.md | 综合速查：常见flag位置、First-Pass工作流、快速测试命令、常见链形状、响应头hint利用 | ~10KB |
| `php-code-audit-checklist.md` | 综合（新写） | PHP代码审计流程：输入入口→过滤检查→危险函数→输出回显→路径选择 | ~5KB |

**总计**：8 个参考文件，~65KB

---

#### 🆕 Skill 2：`ctf-crypto`（CTF 密码学攻击知识库）

**路径**：`vulnclaw/skills/specialized/ctf-crypto/`

**定位**：CTF 密码学攻击知识库，提供**具体攻击参数、数学公式、Python 代码片段**，而非密码学原理。

**与 `crypto-toolkit` 的关系**：
- `crypto-toolkit` → 编解码操作工具（base64解码、MD5哈希、AES加密解密）
- `ctf-crypto` → 密码学攻击知识（RSA小指数攻击怎么做、Padding Oracle怎么利用、ECC小子群攻击怎么构造）

**SKILL.md 结构**：

```yaml
---
name: ctf-crypto
description: CTF密码学攻击知识库 — RSA攻击（小指数/共模/Wiener/Coppersmith）、AES攻击（Padding Oracle/ECB字节翻转/GCM nonce重用）、ECC攻击、LFSR/LCG/PRNG攻击、古典密码、LWE格攻击
---
```

**触发词（dispatcher.py 新增）**：

```python
"rsa攻击|小指数|共模攻击|wiener|coppersmith|padding oracle": ["ctf-crypto"],
"ecc攻击|小子群|离散对数|ecdsa|ed25519|pohlig-hellman": ["ctf-crypto"],
"lfsr|lcg|prng|mt19937|随机数预测|流密码": ["ctf-crypto"],
"lwe|格攻击|lll|cvp|svp|格基规约": ["ctf-crypto"],
"古典密码|维吉尼亚|凯撒|栅栏|替换密码|频率分析": ["ctf-crypto"],
```

**references/ 文件规划**：

| 新文件名 | 来源 | 内容（规范后） | 大小估计 |
|---------|------|-------------|---------|
| `rsa-attacks-cheatsheet.md` | rsa-attacks.md + rsa-attacks-2.md | RSA攻击速查表：小e立方根/共模/Wiener/Pollard p-1/Hastad/Fermat/Coppersmith，含参数范围和Python代码 | ~12KB |
| `aes-and-block-cipher-attacks.md` | modern-ciphers.md + modern-ciphers-2.md + modern-ciphers-3.md | AES攻击：ECB字节翻转/CBC IV翻转/Padding Oracle/GCM nonce重用/CTR重用，含Python代码 | ~10KB |
| `ecc-attacks-cheatsheet.md` | ecc-attacks.md | ECC攻击：小子群/invalid curve/Smart攻击/Pohlig-Hellman/ECDSA nonce重用，含Sage代码 | ~8KB |
| `prng-and-stream-cipher-attacks.md` | prng.md + prng-attacks.md + stream-ciphers.md | MT19937状态恢复/LCG预测/LFSR Berlekamp-Massey/RC4偏差 | ~8KB |
| `classic-cipher-attacks.md` | classic-ciphers.md | Vigenere+Kasiski/多字节XOR频率分析/OTP重用/培根密码/栅栏密码 | ~6KB |
| `lattice-and-lwe-attacks.md` | lattice-and-lwe.md + advanced-math.md | LLL/BKZ/HNP/LWE embedding/CVP，含Python/Sage代码 | ~8KB |

**总计**：6 个参考文件，~52KB

---

#### 🆕 Skill 3：`ctf-misc`（CTF Misc 杂项知识库）

**路径**：`vulnclaw/skills/specialized/ctf-misc/`

**定位**：CTF Misc 题目实战知识库，覆盖**Python Jail/Bash Jail 逃逸、编码链识别、游戏VM逆向**等杂项题型。

**SKILL.md 结构**：

```yaml
---
name: ctf-misc
description: CTF杂项知识库 — Python Jail逃逸、Bash Jail逃逸、编码链识别与解码、QR/音频/图像隐写、游戏VM逆向、CTFd API导航、Linux提权
---
```

**触发词（dispatcher.py 新增）**：

```python
"pyjail|python沙箱|jail逃逸|sandbox_escape|python jail": ["ctf-misc"],
"bashjail|bash沙箱|restricted shell|rbash逃逸": ["ctf-misc"],
"编码链|多层编码|杂项|misc|隐写|stego": ["ctf-misc"],
"ctfd|夺旗平台|flag提交|题目下载": ["ctf-misc"],
```

**references/ 文件规划**：

| 新文件名 | 来源 | 内容（规范后） | 大小估计 |
|---------|------|-------------|---------|
| `python-jail-escape.md` | pyjails.md | Python Jail逃逸全表：\_\_import\_\_/os.system/\_\_builtins\_\_/func\_globals/subprocess/eval+exec链、字符集限制绕过 | ~10KB |
| `bash-jail-escape.md` | bashjails.md | Bash Jail逃逸：HISTFILE读文件/ctypes.sh调C库/vi/ed/awk/perl反弹、rbash绕过 | ~6KB |
| `encoding-chain-reference.md` | encodings.md + encodings-advanced.md | 编码链识别与自动解码：Base64→Hex→ROT13多层嵌套、BCD/Gray码/UTF-16/RTF标签 | ~8KB |
| `game-and-vm-reverse.md` | games-and-vms.md + games-and-vms-2~4.md | WASM patching/Brainfuck/自定义VM/Z3约束求解/游戏状态篡改（精选） | ~8KB |
| `ctfd-platform-guide.md` | ctfd-navigation.md | CTFd API使用：检测平台/登录/下载附件/提交flag/查看提示 | ~6KB |
| `linux-privesc-quick.md` | linux-privesc.md | Linux提权速查：SUID/sudo滥用/cron/NFS/内核漏洞（精选高频项） | ~6KB |

**总计**：6 个参考文件，~44KB

---

### 7.4 现有 Skill 更新计划

#### 🔄 更新 `web-security-advanced`

**变更内容**：

1. **SKILL.md 新增 CTF 路由指引**：

```markdown
## CTF 场景路由

当目标为 CTF 题目（已知有 flag，需要绕过特定过滤）时，优先使用 `ctf-web` Skill：
- PHP 弱比较/类型绕过 → `ctf-web` → `references/php-bypass-cheatsheet.md`
- 命令注入空格绕过 → `ctf-web` → `references/command-injection-bypass.md`
- eval 回显/无回显 → `ctf-web` → `references/eval-and-rce-techniques.md`
- PHP 代码审计 → `ctf-web` → `references/php-code-audit-checklist.md`

本 Skill 侧重渗透测试方法论，CTF 实战绕过值请参考 `ctf-web`。
```

2. **触发词更新**（dispatcher.py）：

```python
# 现有
"web高级|注入|sql注入|xss|ssrf|ssti|xxe|命令注入|反序列化": ["web-security-advanced"],
# 新增 RCE 触发词
"web高级|注入|sql注入|xss|ssrf|ssti|xxe|命令注入|反序列化|rce|远程代码执行": ["web-security-advanced"],
```

---

#### 🔄 更新 `crypto-toolkit`

**变更内容**：

1. **SKILL.md 新增密码学攻击路由指引**：

```markdown
## CTF 密码学攻击路由

当遇到密码学攻击场景（已知加密算法，需要恢复明文或密钥）时，优先使用 `ctf-crypto` Skill：
- RSA 小指数/共模/Wiener → `ctf-crypto` → `references/rsa-attacks-cheatsheet.md`
- AES Padding Oracle/ECB 翻转 → `ctf-crypto` → `references/aes-and-block-cipher-attacks.md`
- ECC 小子群/离散对数 → `ctf-crypto` → `references/ecc-attacks-cheatsheet.md`

本 Skill 侧重编解码操作工具，密码学攻击知识请参考 `ctf-crypto`。
```

2. **references/ 新增**：

| 新文件 | 内容 |
|--------|------|
| `crypto-attacks-roadmap.md` | 密码学攻击分类路由：根据题目特征（密钥长度/模式/已知量）选择攻击方法 |

---

#### 🔄 更新 `rapid-checklist`

**变更内容**：

SKILL.md 新增 CTF 速查路由卡片：

```markdown
### CTF 专项
- PHP 弱比较 → 0e 开头 MD5 值大全 → `ctf-web`
- 命令注入空格绕过 → ${IFS}/$IFS$9/</%09 → `ctf-web`
- eval 无回显 → 写文件/DNS外带/写webshell → `ctf-web`
- RSA 小指数 → 立方根/Coppersmith → `ctf-crypto`
- Python Jail → \_\_import\_\_/func\_globals/eval链 → `ctf-misc`
```

---

### 7.5 dispatcher.py 完整更新方案

```python
# ── 新增 CTF 触发词 ──────────────────────────────────────────────
# ctf-web
"ctf|夺旗|flag|弱比较|空格绕过|正则绕过|rce|代码审计|eval绕过|highlight_file": ["ctf-web"],
"0e|md5绕过|preg_match绕过|类型绕过|type juggling|弱类型": ["ctf-web"],
"回显|无回显|blind rce|命令执行绕过|php代码审计|ssti注入": ["ctf-web"],
# ctf-crypto
"rsa攻击|小指数|共模攻击|wiener|coppersmith|padding oracle": ["ctf-crypto"],
"ecc攻击|小子群|离散对数|ecdsa|ed25519|pohlig-hellman": ["ctf-crypto"],
"lfsr|lcg|prng|mt19937|随机数预测|流密码": ["ctf-crypto"],
"lwe|格攻击|lll|cvp|svp|格基规约": ["ctf-crypto"],
# ctf-misc
"pyjail|python沙箱|jail逃逸|sandbox_escape|python jail": ["ctf-misc"],
"bashjail|bash沙箱|restricted shell|rbash逃逸": ["ctf-misc"],
"编码链|多层编码|杂项|misc|隐写|stego": ["ctf-misc"],
"ctfd|夺旗平台|flag提交|题目下载": ["ctf-misc"],

# ── 更新现有触发词 ──────────────────────────────────────────────
# web-security-advanced 增加 RCE
"web高级|注入|sql注入|xss|ssrf|ssti|xxe|命令注入|反序列化|rce|远程代码执行": ["web-security-advanced"],
```

---

### 7.6 不需要删除的 Skill

现有 9 个专项 Skill **全部保留**，无需删除。原因：

| Skill | 保留理由 |
|-------|---------|
| web-security-advanced | 渗透测试场景仍需方法论，与 ctf-web 互补 |
| web-pentest | Web 渗透流程指导，与 CTF 不冲突 |
| crypto-toolkit | 编解码操作工具，与 ctf-crypto 攻击知识互补 |
| rapid-checklist | 速查卡片，增加 CTF 路由即可 |
| 其余5个 | 定位完全不同，不涉及 CTF |

---

### 7.7 实施优先级与文件清单

| 优先级 | 任务 | 文件操作 | 预计工作量 |
|--------|------|---------|-----------|
| **P0** | 创建 `ctf-web` Skill | 新建 `vulnclaw/skills/specialized/ctf-web/SKILL.md` + 8 个 references | 1-2 天 |
| **P0** | 创建 `ctf-crypto` Skill | 新建 `vulnclaw/skills/specialized/ctf-crypto/SKILL.md` + 6 个 references | 1 天 |
| **P0** | 创建 `ctf-misc` Skill | 新建 `vulnclaw/skills/specialized/ctf-misc/SKILL.md` + 6 个 references | 1 天 |
| **P1** | 更新 dispatcher.py | 修改 `vulnclaw/skills/dispatcher.py` | 0.5 小时 |
| **P1** | 更新 web-security-advanced SKILL.md | 修改 SKILL.md 加 CTF 路由 | 0.5 小时 |
| **P1** | 更新 crypto-toolkit SKILL.md | 修改 SKILL.md 加攻击路由 + 新增 references | 1 小时 |
| **P2** | 更新 rapid-checklist SKILL.md | 修改 SKILL.md 加 CTF 卡片 | 0.5 小时 |

**总计**：3 个新 Skill（20 个参考文件）+ 4 个现有 Skill 更新，预计 4-5 天

---

### 7.8 内容规范原则

从 ctf-skills-main 提炼内容时，遵循以下规范：

1. **文件名规范**：VulnClaw 统一使用小写+连字符（如 `php-bypass-cheatsheet.md`），不使用原项目的大驼峰（如 `server-side-exec.md`）
2. **内容提炼**：从原项目的大量赛题案例中提炼**通用规律和速查表**，而非保留全部案例。例如：
   - 原文：5 个不同 CTF 赛题的 PHP Type Juggling 实例 → 提炼为：弱比较值大全表 + 3 种绕过模式
   - 原文：3 个不同 CTF 赛题的 eval 无回显解法 → 提炼为：无回显利用路径表（写文件/DNS外带/写webshell/写环境变量）
3. **语言统一**：SKILL.md 和 references 使用中文标题+中文说明+英文技术术语（与 VulnClaw 现有风格一致）
4. **添加 VulnClaw 专属内容**：原项目没有的内容，如 PHP 代码审计 checklist、eval 回显技巧总结、highlight_file 输出顺序说明等
5. **代码示例保留**：关键的 Python/Sage/PHP 代码片段保留，但去掉冗余的注释和重复逻辑
6. **不保留原项目的 Prerequisites/安装命令**：VulnClaw 不依赖 bash/Go 工具安装，这些命令不适用
