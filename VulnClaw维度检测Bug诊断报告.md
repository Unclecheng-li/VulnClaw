# 信息收集维度完成度检测 Bug 诊断报告

> 日期: 2026-04-20
> 实战测试: `搜集基础信息(社会工程)https://unclecheng-li.github.io`

---

## 一、实战结果

| 指标 | 数值 |
|------|------|
| 总轮数 | 12 轮 |
| 执行步骤 | 14 个 |
| 发现漏洞 | 0（信息收集阶段正常） |
| 实际有效收集轮数 | 约 6 轮 |
| 浪费轮数（无新进展） | **约 6 轮** |
| 报告保存 | ✅ 成功 |

**结论**: 功能正常，但效率偏低，维度完成度检测存在缺陷。

---

## 二、Bug 根因分析

### Bug 1：关键词检测过于宽泛 — 误触发 personnel 维度

**问题位置**: `core.py` → `_update_recon_dimension_completion()`

**触发链路**:

Round 7 执行了以下 `python_execute` 代码（用于解析 HTML 中的社交媒体链接）：

```python
social_patterns = ['github.com', 'twitter.com', 'bilibili.com', 'weibo.com']
for pattern in social_patterns:
    if pattern in link.lower():
        print(f"  - {link}")
```

这些代码片段被追加到 `executed_steps` 中。Round 8 的 `_update_recon_dimension_completion` 扫描：

```python
combined = f"{response} {recent_context} {recent_steps}"
# combined 文本中含 "github.com", "twitter.com", "email", "link" 等
```

命中 `_RECON_DIM_KEYWORDS["personnel"]`：
```python
"personnel": [
    "github用户", "邮箱关联",  # ← 命中！
    "作者", "author", "社工", ...
],
```

**结果**: `mark_recon_dimension("personnel")` 被错误调用 → `is_recon_complete()` 返回 `True` → **blocking 的第二层保障（维度完成度）完全失效**。

---

### Bug 2：blocking 双重保障全部失效

| 保障层 | 生效条件 | Round 9+ 是否生效 |
|--------|---------|-----------------|
| 最低轮数保障 | `round < RECON_MIN_ROUNDS(8)` | ❌ 失效（第 8 轮后不生效） |
| 维度完成度保障 | `is_recon_complete() == False` | ❌ 失效（被误触发绕过） |

**结果**: Round 9-12 期间，LLM 想输出 [DONE] 时，blocking 两层全部失效，**只能靠 LLM 自己判断"够了"**。但 LLM 陷入了"分析-建议-再分析"循环，没有主动 [DONE]。

---

### Bug 3：LLM 陷入"分析-建议"循环

**现象**:
```
Round 7: python_execute → 分析建议"继续深入收集"
Round 8: python_execute → "重新审视收集进度"
Round 9: python_execute → "检测到循环"
Round 10: python_execute → 再次分析
...
```

**根因**: LLM 每次输出都基于已经见过的信息做"更深入分析"，但没有新的工具数据驱动决策。连续多轮没有新发现时，LLM 倾向于继续"深入"而不是停下来。

---

## 三、修复方案

### 修复 1（P0）：区分"工具结果文本"和"LLM 推理文本"

**核心思路**: 维度完成度应该基于**实际工具执行结果**，不是 LLM 输出中出现的通用关键词。

**改动**: `core.py` → `_update_recon_dimension_completion()`

```python
def _update_recon_dimension_completion(self, response: str) -> None:
    """Auto-detect which recon dimensions have been explored.

    只检查工具结果（notes 和 executed_steps），不检查 LLM 推理文本。
    这样可以防止 python_execute 代码中的通用关键词被误判为维度已完成。
    """
    # 只检查工具结果，不检查 LLM 推理
    tool_notes = " ".join(self.context.state.notes[-10:]).lower()
    tool_steps = " ".join(self.context.state.executed_steps[-10:]).lower()
    tool_context = f"{tool_notes} {tool_steps}"

    # 排除 LLM response 文本——防止代码片段中的关键词误触发
    # （如 python_execute 代码里写了 "github.com" 不等于真正执行了 GitHub API）

    for dim, keywords in _RECON_DIM_KEYWORDS.items():
        if dim == "personnel" and not self.context.state.recon_dimension4_active:
            continue
        if not self.context.state.recon_dimensions_completed.get(dim, False):
            # 只在工具结果中检测关键词
            if any(kw in tool_context for kw in keywords):
                self.context.state.mark_recon_dimension(dim)
```

---

### 修复 2（P1）：无新进展时强制阶段切换提示

**改动**: `core.py` → `_build_round_context()`

在 `dead_loop_warning` 之后追加：

```python
# ★ Recon phase: no progress + all dimensions marked = force summary
recon_force_summary = ""
if getattr(self, '_is_recon_phase', False):
    rounds_no_progress = getattr(self, '_rounds_without_progress', 0)
    is_complete = self.context.state.is_recon_complete()
    if rounds_no_progress >= 3 and is_complete:
        recon_force_summary = (
            "\n\n🔴 侦察强制指令："
            f"\n你已经连续 {rounds_no_progress} 轮没有任何新的工具发现。"
            f"\n所有维度已完成 ✅，请立即："
            "\n1. 整理已收集的信息"
            "\n2. 生成简洁的侦察总结"
            "\n3. 使用 python_execute 保存报告到桌面"
            "\n4. 输出 [DONE] 结束本次侦察"
            "\n⚠️ 禁止继续发送请求或重复分析！"
        )
```

同时在 `auto_pentest` 的 blocking 逻辑中追加：

```python
# ★ Recon: if all dimensions complete but LLM won't [DONE], force after 3 stale rounds
if getattr(self, '_is_recon_phase', False) and result.should_continue:
    if rounds_no_progress >= 5 and self.context.state.is_recon_complete():
        # Force stop — dimensions done and no progress for 5 rounds
        result.should_continue = False
```

---

### 修复 3（P2）：关键词优化 — 移除 personnel 维度的宽泛词

**改动**: `core.py` → `_RECON_DIM_KEYWORDS`

```python
_RECON_DIM_KEYWORDS: dict[str, list[str]] = {
    "server": [
        "端口", "port", "开放", "nmap",
        "真实ip", "cdn检测", "源站",
        "操作系统", "os检测", "ttl",
        "中间件", "数据库",
    ],
    "website": [
        "waf", "web应用防火墙",
        "敏感目录", "目录扫描", "dirb", "gobuster",
        "源码泄露", ".git", ".svn", ".env",
        "旁站", "c段", "同ip", "同网段",
        "cms", "指纹", "hexo", "wordpress",  # 框架关键词
    ],
    "domain": [
        "whois", "注册人", "注册商",
        "icp备案", "子域名", "subdomain",
        "dns记录", "mx记录", "txt记录",
        "crt.sh", "证书透明",
    ],
    # ⚠️ 移除宽泛词：github、邮箱、作者、twitter
    # personnel 维度应该通过 _post_flag_rounds 类的计数来确认，不靠关键词
    "personnel": [
        # 只保留真正的社工结果特征（不是代码中的词）
        "github.*api",  # GitHub API 实际返回了数据
        "真实姓名",  # 从 API 中提取到了真实姓名
    ],
}
```

---

## 四、修复优先级

| 优先级 | 修复 | 预计影响 |
|--------|------|---------|
| **P0** | 修复 1：区分工具结果 vs LLM 推理 | 解决 blocking 失效的根本原因 |
| **P1** | 修复 2：强制总结指令 | 解决分析循环 |
| **P2** | 修复 3：优化 personnel 关键词 | 减少误触发 |

---

## 五、预期效果

修复后，同样输入：

```
搜集基础信息(社会工程)https://unclecheng-li.github.io
```

**预期行为**:
```
Round 1-3: fetch 目标 → GitHub API → 获取用户信息
Round 4-5: 补充网站指纹、WHOIS/子域名
Round 6-7: 社工数据验证
Round 8: 所有维度完成 ✅
Round 9-10: 维度完成但无新进展 → 触发强制总结 → 输出 [DONE]
```

**对比**:
| 指标 | 修复前 | 修复后 |
|------|--------|--------|
| 总轮数 | 12 轮 | ~10 轮 |
| 浪费轮数 | ~6 轮 | ~2 轮 |
| blocking 有效性 | 失效 | 生效 |
| 报告及时性 | 延迟 | 正常 |
