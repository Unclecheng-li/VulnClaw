# Browser Request Chain Template

Use this template for browser-side sign, token, anti-bot, worker, wasm, cookie-hop, and replay tasks.

## Template

```markdown
# 浏览器请求链记录

## 基本信息

- 目标页面：
- 目标请求：
- 目标字段：
- 触发动作：
- 当前阶段：locate / recover / runtime / validation
- 当前状态：🟡 进行中 / ✅ 已闭环 / ⛔ 阻塞
- 目标：
- 约束：

## 样本与现象

- 正常态样本：
- 风控态样本：
- 浏览器现象：
- 本地现象：
- 当前差异：

## 请求链主表

| 项目 | 内容 |
| --- | --- |
| writer |  |
| builder |  |
| entry |  |
| source |  |
| 上游依赖 |  |
| 状态载体 |  |
| 风控分叉点 |  |
| 当前结论 |  |

## 关键证据

| 证据类型 | 位置/点位 | 内容 | 结论 |
| --- | --- | --- | --- |
| 请求样本 |  |  |  |
| 调用栈 |  |  |  |
| 断点/Hook |  |  |  |
| 中间值 |  |  |  |
| Cookie/Storage |  |  |  |

## 阶段补充

### Locate 补充

- Sink：
- 真实写入点：
- 上游请求：
- 正常态 / 风控态区分：

### Recover 补充

- 遮蔽层类型：
- 当前恢复级别：A / B / C
- 已恢复契约：
- 仍未恢复缺口：

### Runtime 补充

- 缺失对象：
- 缺失状态：
- 固定源：
- 首个分歧点：
- 风控 / 反调试：

### Validation 补充

| 检查点 | 浏览器侧 | 本地/恢复侧 | 结果 | 证据 | 缺口 |
| --- | --- | --- | --- | --- | --- |
| 检查点1 |  |  |  |  |  |

## Burp 重放基线

- Method：
- Path：
- Query：
- Headers：
- Body：
- 必须保留字段：
- 可变异字段：
- 前置状态：

## Stage Handoff

--- Stage Handoff ---
From:
To:
Proven:
Open:
Invalidated:

## 下一步

- 下一动作：
- 预期输出：
- 阻塞点：
```

## Minimum Required Fields

Even in a compact record, keep:

- target page and target request
- current stage
- `writer / builder / entry / source`
- one real request sample
- one concrete evidence row
- Burp replay baseline or explicit blocker
