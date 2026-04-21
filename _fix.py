# VulnClaw 死循环检测修复方案

## 问题分析

### 当前死循环检测逻辑

```python
has_new_progress = (
    current_findings > self._last_findings_count
    or current_notes > self._last_notes_count
    or current_steps > self._last_steps_count + 1  # ← 问题
)
```

### 问题

每次 LLM 说"让我尝试连接 shenbao.conac.cn（失败）"，添加一个步骤，就被判定为"有进展"，死循环计数器被重置。

**结果**: LLM 连续 10+ 轮都在重复尝试同一个失败的目标。

---

## 修复方案

### 方案 A: 目标级失败检测（推荐）

在 `core.py` 的死循环检测部分，增加对"连续失败目标"的识别：

```python
# 在死循环检测前添加：

# ★ 目标级失败检测：如果最近几步都访问同一个目标且都失败，强制切换
FAILED_TARGET_PATTERNS = [
    "shenbao.conac.cn",
    "连接失败",
    "502",
    "SSLError",
    "ReadTimeout",
    "连接超时",
    "无法访问",
    "访问失败",
]

def _detect_repeated_failed_target(state, recent_count=5):
    """检测是否连续尝试访问同一个失败目标."""
    if len(state.executed_steps) < recent_count:
        return None

    recent_steps = state.executed_steps[-recent_count:]
    failed_count = 0
    last_failed_target = None

    for step in recent_steps:
        has_failed = any(pattern in step for pattern in FAILED_TARGET_PATTERNS)
        if has_failed:
            failed_count += 1
            # 提取失败的目标
            import re
            target_match = re.search(r'https?://[^\s/]+', step)
            if target_match:
                last_failed_target = target_match.group(0)

    if failed_count >= recent_count - 1:  # 至少 4/5 步都失败
        return last_failed_target or "目标"
    return None

# 在死循环检测逻辑中：
failed_target = _detect_repeated_failed_target(state)
if failed_target:
    dead_loop_warning += (
        f"\n\n🚨 目标不可访问警告：'{failed_target}' 已连续 {recent_count} 轮访问失败！"
        f"\n不要重复尝试访问不可用的目标。"
        f"\n立即切换到其他攻击方向："
        f"\n1. 停止访问 '{failed_target}'"
        f"\n2. 专注于已确认存活的站点"
        f"\n3. 切换到其他攻击向量"
    )
    self._rounds_without_progress = stale_threshold  # 强制触发死循环警告
```

### 方案 B: 失败不计"进展"

修改 `has_new_progress` 逻辑，只有有效的步骤才计入进展：

```python
# 有效的"进展"步骤
VALID_PROGRESS_KEYWORDS = [
    "发现", "确认", "漏洞", "端口", "路径",
    "flag", "成功", "CVE", "泄露", "绕过",
]

# 如果步骤只包含失败关键词，不算进展
def _is_meaningful_step(step):
    return any(kw in step for kw in VALID_PROGRESS_KEYWORDS)

has_new_progress = (
    current_findings > self._last_findings_count
    or current_notes > self._last_notes_count
    or (current_steps > self._last_steps_count + 1 and _is_meaningful_step(state.executed_steps[-1]))
)
```

---

## 推荐实施

**方案 A + 方案 B 结合使用**：

1. 方案 A 检测连续失败目标，强制切换
2. 方案 B 确保只有有效步骤才重置死循环计数器

---

## 需要修改的文件

- `vulnclaw/agent/core.py` - 在死循环检测逻辑中添加目标级失败检测

---

## 预期效果

**修复前**:
```
Round 45: 尝试连接 shenbao.conac.cn → SSL错误
Round 46: 尝试连接 shenbao.conac.cn → 502
Round 47: 尝试连接 shenbao.conac.cn → 超时
... (无限循环)
```

**修复后**:
```
Round 45: 尝试连接 shenbao.conac.cn → SSL错误
Round 46: 尝试连接 shenbao.conac.cn → 502
Round 47: 🚨 目标不可访问警告：'shenbao.conac.cn' 已连续 5 轮访问失败！
    → 立即切换到其他攻击方向
```
