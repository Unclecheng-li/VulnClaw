# 信息收集维度完成度检测 Bug 诊断报告

## 概述

2026-04-20 对 `https://unclecheng-li.github.io` 进行实战测试，发现**维度完成度检测机制存在严重缺陷**，导致：
1. blocking 双重保障全部失效
2. LLM 连续 6 轮无实际进展
3. 报告生成延迟

---

## Bug 根因分析

### 根因 1：关键词检测过于宽泛（Keyword Collision）

**问题位置**: `core.py` → `_update_recon_dimension_completion()`

**触发场景**: Round 7 执行了以下 `python_execute` 代码：

```python
social_patterns = ['github.com', 'twitter.com', 'bilibili.com', 'weibo.com', 'telegram', 'facebook.com']
for pattern in social_patterns:
    if pattern in link.lower():
        print(f"  - {link}")
```

**关键词命中链路**:
1. python_execute 代码片段写入 notes/context
2. `_update_recon_dimension_completion()` 扫描 combined = `response + notes + steps`
3. combined 文本中含 `"github.com"`, `"twitter.com"`, `"email"`, `"link"` 等关键词
4. `_RECON_DIM_KEYWORDS["personnel"]` 命中：
   ```python
   "personnel": [
       "作者", "author", "人物追踪", "社工", "社会工程",
       "跨平台", "用户名搜索", "github用户", "邮箱关联",  # ← 命中！
   ],
   ```
5. `mark_recon_dimension("personnel")` 被错误调用
6. `is_recon_complete()` 返回 `True`
7. **blocking 的第二层保障完全失效**

**对比分析**:

| 维度 | 关键词列表 | 误触发风险 |
|------|-----------|-----------|
| server | "端口", "port", "nmap" | 低（较专业） |
| website | "waf", "cms", "框架" | 中（有时代码含这些词） |
| domain | "whois", "dns", "子域名" | 中（有时代码含这些词） |
| **personnel** | "github", "邮箱", "作者", "twitter" | **极高（任何社工相关代码都含）** |

---

### 根因 2：`recon_dimension4_active` 初始值覆盖问题

**问题位置**: `core.py` → `auto_pentest()` 初始化

```python
self.context.state.recon_dimension4_active = any(
    kw in user_input.lower() for kw in social_engineering_keywords
)
```

**但**: 如果 `recon_dimension4_active = False`，维度四的关键词检测仍然执行（虽然 `is_recon_complete()` 会跳过维度四检查，但 `_update_recon_dimension_completion()` 中的这段代码绕过了 `recon_dimension4_active` 检查：

```python
for dim, keywords in _RECON_DIM_KEYWORDS.items():
    if dim == "personnel" and not self.context.state.recon_dimension4_active:
        continue  # ← 这里跳过了
    if not self.context.state.recon_dimensions_completed.get(dim, False):
        if any(kw in combined for kw in keywords):
            self.context.state.mark_recon_dimension(dim)
```

**问题**: `_update_recon_dimension_completion` 内部虽然跳过了未激活的 personnel，但其他三个维度（server/website/domain）仍然会被代码片段中的通用关键词误触发。

---

### 根因 3：LLM 陷入"分析-建议"循环

**现象**: Round 7-12 没有新的工具调用，只有文本推理和"下一步建议"。

**触发路径**:
```
Round 7: python_execute 执行完 → 分析建议
Round 8: python_execute 执行完 → 重新审视
Round 9: python_execute 执行完 → 再次分析
```

**根本原因**: LLM 在连续多轮中**缺少真正的新工具结果**来驱动决策**。每次输出都基于之前已经见过的信息做"更深入分析"，但没有新数据。这种循环是 LLM 的固有行为模式（无法自行判断"够了"）。

---

## 修复方案

### 修复 1：关键词分层 — 用工具结果特征而非通用关键词

**核心思路**: 维度完成度应该基于**工具调用的实际结果**，而不是 LLM 输出文本中的关键词。

**方案 A（推荐）：基于工具调用类型检测**

```python
_RECON_DIM_TOOLS: dict[str, list[str]] = {
    "server": [
        "nmap", "socket.connect", "grab_banner",  # 端口扫描相关
        "真实ip", "cdn检测",
    ],
    "website": [
        "web指纹", "cms识别", "waf检测",
        "敏感目录", "dirb", "gobuster",  # 目录扫描
        "源码泄露", ".git", ".svn",  # 源码相关
        "旁站", "c段",  # 旁站C段
    ],
    "domain": [
        "whois", "dns查询", "dns_lookup",
        "icp备案", "子域名", "crt.sh",
        "dns记录", "mx记录", "txt记录",
    ],
    "personnel": [
        "github.*api",  # GitHub API 调用结果
        "twitter.*api",  # Twitter API 调用
        "邮箱",  # 明确的邮箱提取结果
    ],
}
```

**方案 B：区分"工具结果文本"和"LLM 推理文本"**

```python
def _update_recon_dimension_completion(self, response: str) -> None:
    """Auto-detect which recon dimensions have been explored.

    Only checks tool results (notes and steps from executed tools),
    NOT the LLM's reasoning text.
    """
    # Only check tool results - these are real observations
    tool_context = " ".join(self.context.state.notes[-10:]).lower()
    tool_steps = " ".join(self.context.state.executed_steps[-10:]).lower()

    # Skip LLM response text - it contains reasoning, not results
    # This prevents "github" in a code snippet from falsely triggering

    for dim, keywords in _RECON_DIM_KEYWORDS.items():
        if dim == "personnel" and not self.context.state.recon_dimension4_active:
            continue
        if not self.context.state.recon_dimensions_completed.get(dim, False):
            # Only check tool context, not LLM response
            if any(kw in tool_context or kw in tool_steps for kw in keywords):
                self.context.state.mark_recon_dimension(dim)
```

**方案 C（最简单）：增加关键词黑名单过滤**

```python
# 在关键词匹配前过滤掉代码片段
blacklist = ["import ", "def ", "for ", "if ", "print(", "requests"]

def _is_meaningful_keyword_match(text: str, keyword: str) -> bool:
    """Check if keyword appears in meaningful context, not code."""
    if keyword in text:
        # Find surrounding context
        idx = text.index(keyword)
        context = text[max(0, idx-20):idx+len(keyword)+20]
        # If surrounded by code chars, it's code - not a match
        code_chars = sum(1 for c in context if c in '(){}[]=+*&^%$#@!')
        alpha_chars = sum(1 for c in context if c.isalpha())
        if code_chars > alpha_chars * 0.5:
            return False  # Likely code
        return True
    return False
```

---

### 修复 2：阶段切换强制检查

在每轮 `auto_pentest` 中，如果连续 N 轮没有任何新发现，强制提示阶段切换：

```python
# 在 _build_round_context 中追加
if rounds_no_new_tool_result >= 3:
    prompt += (
        "\n\n🔴 警告：你已经连续 3 轮没有任何新的工具执行结果！"
        "\n如果你已经收集了足够的信息，请立即："
        "\n1. 生成简洁的侦察总结"
        "\n2. 如果发现了可攻击的目标 → 输出'进入漏洞发现'切换阶段"
        "\n3. 否则 → 输出 [DONE] 结束本次侦察"
        "\n⚠️ 不要继续重复分析已有信息！"
    )
```

---

### 修复 3：维度完成度状态持久化为"锁定"机制

一旦维度被标记为完成，后续不应该被撤销。但如果后续发现真正完成了一个维度，应该升级报告质量而不是重复收集。

---

## 修复优先级

| 优先级 | 修复 | 影响 |
|--------|------|------|
| **P0** | 修复 1（区分工具结果 vs LLM 推理） | 解决 blocking 失效 |
| **P1** | 修复 2（无新结果时强制阶段切换） | 解决分析循环 |
| **P2** | 优化维度关键词（移除宽泛词） | 减少误触发 |

---

## 测试用例

修复后用同样输入测试：

```
输入：搜集基础信息(社会工程)https://unclecheng-li.github.io
```

**预期行为**:
- Round 1-3: 获取 GitHub 用户信息 + 社工数据
- Round 4-5: 补充 WHOIS/备案/子域名
- Round 6-8: 维度完成度全部 ✅
- Round 9: LLM 判断收集完成 → 汇总报告 → [DONE]
- **总计约 9-10 轮，不超过 12 轮**

**对比当前问题**:
- Round 7-12 连续 6 轮无新进展
- 修复后应该 Round 7-8 就能判断收集完成
