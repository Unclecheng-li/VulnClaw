---
name: client-reverse
description: 客户端逆向与Burp重放 — 复杂客户端签名恢复、加密还原、请求链追踪、稳定重放，适用于已授权安卓App渗透测试、浏览器JS签名、桌面客户端逆向
---

# 客户端逆向与 Burp 重放 Skill

当请求由客户端（安卓App、浏览器JS、桌面客户端）构造，且存在签名、加密、token状态、设备绑定或反自动化逻辑导致 Burp 无法直接重放时，使用本 Skill。

## 核心原则

**Packet-First**：先捕获并分析真实的 HTTP/HTTPS 请求或 WebSocket 流量，确认可用性，再按需逆向阻塞点。逆向是阻塞解决步骤，不是默认入口。

## 场景路由

### 已授权安卓 App 渗透测试

**不要先用 jadx、ida_pro_mcp 分析 APK**，按以下顺序操作：

1. 确认目标 App 已安装在连接设备上
2. 准备好 Burp 或 Charles 抓包
3. 用 scrcpy_vision 打开 App，驱动真实业务流程
4. 每个关键动作后检查 Burp/Charles 是否出现 HTTP/HTTPS 或 WebSocket 数据包
5. 如果包可见且可重放 → 立即进入 `web-security-advanced` 做 Web/API 安全测试
6. 重复"界面动作 → 抓包 → Web 安全分析"循环
7. 只有抓不到包/包被加密/无法重放时 → 升级到 jadx → frida_mcp → ida_pro_mcp

**MCP 工具链**：scrcpy_vision → burp/charles → adb_mcp → jadx → frida_mcp → ida_pro_mcp

### 浏览器 JS 签名、反爬、WebSocket 握手

1. chrome_devtools 查看页面状态和请求链
2. js_reverse 定位 token/sign 生成逻辑
3. burp 验证重放并确定可变字段

**阶段模型**：locate → recover → runtime → validation → replay

**MCP 工具链**：chrome_devtools → js_reverse → burp

### 桌面客户端 / 本地 signer

1. everything_search 定位相关文件
2. ida_pro_mcp 静态分析签名函数
3. frida_mcp 获取运行时参数
4. burp 验证稳定重放

**MCP 工具链**：everything_search → ida_pro_mcp → frida_mcp → burp

## 重放就绪检查清单

在进入 Payload 测试前，必须能回答：

- 请求体如何构造？
- 签名/加密输入来自哪里？
- 哪些 cookie、header、token、设备值、时间戳、nonce 是必须的？
- 请求是否依赖顺序或会话状态？
- 哪些字段改动后不会破坏重放？

## 证据保留

- builder/signer/crypto 代码位置
- 关键 hook 点和运行时观察值
- 可用的 replay 请求样本
- 前置条件、失败模式和反自动化行为说明

## 参考文档

- `references/02-client-api-reverse-and-burp.md` — 客户端逆向到 Burp 重放总工作流
- `references/android-authorized-app-pentest-sop.md` — 安卓 App 渗透 SOP
- `references/browser-js-signing-workflow.md` — 浏览器 JS 签名工作流
- `references/android-signing-and-crypto-workflow.md` — 安卓签名与加密工作流
- `references/android-ui-driven-observation-and-packet-loop.md` — 安卓 UI 驱动观察循环
- `references/android-external-url-runtime-first-workflow.md` — 安卓外部 URL 测试
- `references/android-network-layer-testing-quick-reference.md` — 安卓网络层测试速查
- `references/MCP.md` — MCP 能力总文档
- `references/tool-selection-map.md` — 工具选型地图
