<div align="center">

# VulnClaw 🦞

> *AI 驱动的渗透测试 CLI 工具 — 说人话，打漏洞。*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![OpenAI Compatible](https://img.shields.io/badge/API-OpenAI_Compatible-green)](https://platform.openai.com/)
[![MCP](https://img.shields.io/badge/Toolchain-MCP-orange)](https://modelcontextprotocol.io/)
[![PyPI](https://img.shields.io/badge/PyPI-v0.1.0-blueviolet)](https://pypi.org/project/vulnclaw/)
[![Security](https://img.shields.io/badge/Scope-Authorized_Only-red)](#-安全声明)
<br>

**不是脚本合集，是可运行的 AI 渗透测试 Agent。**

<br>

基于 LLM Agent + MCP 工具链 + 渗透 Skill 编排，
配合 OpenAI / MiniMax / DeepSeek 等兼容模型，
自然语言输入 → 自动完成「信息收集 → 漏洞发现 → 漏洞利用 → 报告生成」全流程。

[快速开始](#快速开始) · [架构设计](#️-架构) · [Skill 体系](#-内置-skill) · [版本路线](#️-版本路线)

</div>

---

## 它能做什么

输入自然语言，AI 自动执行渗透测试全流程：

```
用户输入：帮我对 http://target.example.com 进行渗透测试

VulnClaw 自动执行：
  Round 1:  信息收集 → 指纹识别、端口扫描、目录枚举
  Round 2:  漏洞发现 → 检测注入点、已知 CVE、配置缺陷
  Round 3:  漏洞利用 → PoC 验证、权限获取
  Round 4:  报告生成 → 结构化报告 + Python PoC 脚本
```

<img width="1148" height="642" alt="image" src="https://github.com/user-attachments/assets/576e1cf6-25da-4969-864b-40e77d020dbf" />


适用于已授权的渗透测试、CTF 竞赛、安全教学、红队演练等场景。

---

## 特性

- **自然语言驱动** — 用人话描述渗透意图，自动识别阶段和工具
- **8 个 LLM Provider** — OpenAI / MiniMax / DeepSeek / 智谱 / Moonshot / 千问 / SiliconFlow，一键切换
- **MCP 工具链** — 11 个安全 MCP 服务 + 23 个工具定义（fetch / Burp / Frida / Chrome DevTools / IDA Pro 等）
- **AI Agent 核心** — OpenAI 兼容协议 + Tool Calling + 自主渗透循环
- **19 个渗透 Skill** — 7 核心 + 12 专项 Skill（含 CTF Web/Crypto/Misc），含 131 个参考文档
- **编解码/加解密工具** — 29 种操作（Base64/Hex/URL/AES/JWT/Morse 等），LLM 可精确调用，不再靠猜测
- **Python 代码执行** — 内置 `python_execute` 工具，LLM 可写 Python 脚本精确构造 payload 和解析响应
- **持续性渗透测试** — 周期循环（默认 100 轮/周期 × 10 周期 = 1000 轮），每周期自动生成报告，直到手动终止
- **推理过程显示控制** — `think on/off` 一键切换 LLM 思考过程的显示/隐藏，默认关闭，干净输出只看结论
- **沙盒模式提示词** — 解锁 AI 安全测试能力，CTF / 授权渗透场景专用
- **自动报告 & PoC** — 生成结构化 Markdown 报告和可运行的 Python PoC 脚本
- **安全知识库** — 内置 CVE 数据库、WAF 绕过技巧、漏洞利用方法

---

## CTF 能力增强

基于 NSSCTF 实战反馈（68 轮未解出入门题），系统性增强 CTF 解题能力：

- **Python 代码执行** — `python_execute` 工具，LLM 可写脚本精确构造 payload、解析响应差异
- **上下文记忆增强** — 失败历史保留（避免重复试错）、工具结果首尾保留（不再粗暴截断）、负面信息压缩保留
- **CTF 专项 Skill** — `ctf-web`(PHP 绕过/RCE/SSTI/反序列化) / `ctf-crypto`(RSA/AES/ECC/格攻击) / `ctf-misc`(PyJail/BashJail/编码链)
- **代码审计模式** — 系统提示注入「完整源码分析 → 路径选择 → 输出可见性 → Payload 构造」四步流程
- **反幻觉机制** — 严禁编造工具调用结果 + flag 验证跟踪
- **CTF 知识库** — 具体绕过值（如 PHP 弱比较 `0e` 值）、空格绕过 payload 模板、命令注入速查表

---

## 快速开始

### 安装

```bash
# 从 PyPI 安装（推荐）
pip install vulnclaw

# 从源码安装
git clone https://github.com/Unclecheng-li/VulnClaw.git
cd VulnClaw
pip install -e .
```

### 四步启动

```bash
# 1. 选择提供商（自动填充 Base URL 和模型名）
vulnclaw config provider minimax   (或 openai/deepseek/zhipu/moonshot/qwen/siliconflow)

# 1.2（可选）自定义 Base URL 或模型名
vulnclaw config set llm.base_url https://your-own-api.example.com/v1 
vulnclaw config set llm.model your-model-name

# 2. 设置 API Key
vulnclaw config set llm.api_key sk-your-key-here

# 3. 元神启动！
vulnclaw
```

### 环境检查

```bash
vulnclaw doctor
```

输出示例：

```
🦞 VulnClaw 环境检查

  Python: 3.14.4
  Node.js: v24.14.1
  npx: 已安装
  nmap: 已安装

LLM 配置:
  Provider: openai
  API Key: 已设置
  Base URL: https://api.openai.com/v1
  Model: gpt-4o

MCP 服务:
  fetch: 已启用 [P0]
  memory: 已启用 [P0]
  ...

✅ 环境就绪，运行 vulnclaw 开始
```

---

## 使用方式

### 方式一：REPL 交互模式（推荐）

```bash
$ vulnclaw
```

进入 🦞 交互界面，用自然语言对话：

```
🦞 vulnclaw> 对 192.168.1.100 进行渗透测试，这是我授权的靶场

[*] 进入自主渗透模式，按 Ctrl+C 可随时中断
── Round 1 ──
  [+] 目标: 192.168.1.100
  [+] 开放端口: 22, 80, 443, 8080
  [+] Web 指纹: Apache/2.4.62
── Round 2 ──
  [+] 发现 /manager/html (Tomcat Manager)
  [+] 命中 CVE-202X-XXXX: Apache Tomcat 认证绕过
── Round 3 ──
  [+] 漏洞验证成功

🦞 192.168.1.100 | 报告> 生成渗透报告
[+] 报告已保存: ./reports/192.168.1.100_20260418.md
[+] PoC 脚本已保存: ./pocs/CVE-202X-XXXX.py
```

#### REPL 内置命令

| 命令                  | 说明                                       |
| --------------------- | ------------------------------------------ |
| `target <host>`       | 设置渗透测试目标                           |
| `status`              | 查看当前状态（目标、阶段、工具、推理显示） |
| `tools`               | 列出当前可用 MCP 工具                      |
| `think`               | 切换推理过程显示/隐藏                      |
| `think on` / `off`    | 精确控制推理过程显示                       |
| `persistent`          | 启动持续性渗透测试（100轮/周期，自动报告） |
| `persistent <host>`   | 对指定目标启动持续性渗透                   |
| `clear`               | 清空当前会话                               |
| `help`                | 显示帮助信息                               |
| `exit` / `quit` / `q` | 退出 VulnClaw                              |

#### 自主渗透模式

VulnClaw 检测到以下关键词 + 目标时，自动进入多轮自主渗透循环：

| 触发方式 | 示例 |
| -------- | ---- |
| 渗透指令 | `对 http://target.com 进行渗透测试` |
| CTF / 找 flag | `帮我对 http://ctf.site 找出flag` |
| 爆破 / 绕过 | `对 http://target.com 弱口令爆破` |
| **显式触发** | `目标：http://target.com，进入自主渗透模式` |

> 💡 输入 `Ctrl+C` 可随时中断自主循环。切换目标时自动重置会话上下文。

### 方式二：单命令模式

```bash
# 一键全流程渗透测试
vulnclaw run 192.168.1.100

# 持续性渗透测试（每周期100轮，最多10周期，自动生成报告）
vulnclaw persistent 192.168.1.100

# 自定义周期参数
vulnclaw persistent 192.168.1.100 --rounds 200 --cycles 5

# 仅信息收集
vulnclaw recon 192.168.1.100

# 漏洞扫描（可指定端口）
vulnclaw scan 192.168.1.100 --ports 80,443,8080

# 漏洞利用（可指定 CVE）
vulnclaw exploit 192.168.1.100 --cve CVE-2024-1234 --cmd id

# 生成报告
vulnclaw report session.json
```

### 方式三：持续性渗透模式

适用于需要长时间深度渗透的场景。VulnClaw 以**周期循环**方式运行：

```
┌──────────────────────────────────────────────┐
│  Cycle 1 (100轮) → 自动报告 → 继续          │
│  Cycle 2 (100轮) → 自动报告 → 继续          │
│  Cycle 3 (100轮) → 自动报告 → 继续          │
│  ...                                         │
│  直到 Ctrl+C 或达到最大周期数（默认10）      │
└──────────────────────────────────────────────┘
```

**特点**：
- **跨周期状态保持** — 每个周期保留之前的所有发现、漏洞和步骤记录
- **周期报告** — 每个周期结束自动生成独立的 Markdown 报告（含新增漏洞和累计汇总）
- **灵活中断** — Ctrl+C 随时中断，中断时仍生成本周期报告
- **增量发现** — 报告区分"本周期新增"和"累计总计"，清晰追踪进展
- **可配置** — 每周期轮数、最大周期数、是否自动报告均可配置

```bash
# CLI 方式
vulnclaw persistent 192.168.1.100              # 默认 100轮/周期 × 10周期
vulnclaw persistent 192.168.1.100 -r 200 -c 5  # 200轮/周期 × 5周期
vulnclaw persistent 192.168.1.100 --no-report   # 不自动生成报告

# REPL 方式
🦞 vulnclaw> target 192.168.1.100
🦞 vulnclaw> persistent
# 或直接
🦞 vulnclaw> persistent 192.168.1.100
```

---

## LLM 提供商配置

VulnClaw 支持所有 OpenAI 兼容协议的 API，内置 8 个提供商预设：

```bash
vulnclaw config provider --list    # 查看所有提供商
vulnclaw config provider minimax   # 一键切换
```

| 提供商      | 命令                   | 默认模型         |
| ----------- | ---------------------- | ---------------- |
| OpenAI      | `provider openai`      | gpt-4o           |
| MiniMax     | `provider minimax`     | MiniMax-M2.7     |
| DeepSeek    | `provider deepseek`    | deepseek-chat    |
| 智谱 GLM    | `provider zhipu`       | glm-4-plus       |
| Moonshot    | `provider moonshot`    | moonshot-v1-128k |
| 通义千问    | `provider qwen`        | qwen-max         |
| SiliconFlow | `provider siliconflow` | DeepSeek-V3      |
| 自定义      | `provider custom`      | 手动填写         |

---

## 架构

```
┌─────────────────────────────────────────────┐
│                VulnClaw CLI                  │
│  ┌─────────┐  ┌─────────┐  ┌────────────┐  │
│  │  自然语言 │  │  任务编排 │  │ 报告 & PoC │  │
│  │  交互层  │  │  引擎    │  │   生成器   │  │
│  └────┬────┘  └────┬────┘  └─────┬──────┘  │
│       └─────────────┼─────────────┘        │
│               ┌─────▼──────┐                │
│               │ LLM Agent  │                │
│               │ (越狱+Skill)│               │
│               └─────┬──────┘                │
│               ┌─────▼──────┐                │
│               │ MCP 编排层  │                │
│               │ (11 服务)  │                │
│               └─────┬──────┘                │
│               ┌─────▼──────┐                │
│               │ 安全知识库  │                │
│               └────────────┘                │
└─────────────────────────────────────────────┘
```

### 核心模块

| 模块           | 文件                                             | 说明                                          |
| -------------- | ------------------------------------------------ | --------------------------------------------- |
| **CLI 入口**   | `cli/main.py`                                    | Typer REPL + 9 个子命令（含 persistent）       |
| **Agent 核心** | `agent/core.py`                                  | OpenAI SDK + Tool Calling + 自主渗透循环 + 持续性渗透 + think 过滤 |
| **动态提示词** | `agent/prompts.py`                               | 基础身份 + 核心契约 + Skill + MCP 工具列表    |
| **会话状态**   | `agent/context.py`                               | 阶段追踪 + 漏洞发现 + 步骤记录                |
| **MCP 编排**   | `mcp/registry.py` + `lifecycle.py` + `router.py` | 服务注册 + 生命周期 + 自然语言→工具路由       |
| **Skill 调度** | `skills/loader.py` + `dispatcher.py`             | 目录格式 Skill + 16 种意图动态调度            |
| **编解码工具** | `skills/crypto_tools.py`                         | 29 种编解码/加解密操作，注册为内置 Agent 工具  |
| **配置管理**   | `config/schema.py` + `settings.py`               | Pydantic 模型 + YAML 持久化 + 8 Provider 预设 |
| **报告生成**   | `report/generator.py` + `poc_builder.py`         | Markdown 报告 + Python PoC 模板               |
| **安全知识库** | `kb/store.py` + `retriever.py`                   | JSON 存储 + CVE/技术/工具检索                 |

---

## MCP 工具链

| MCP 服务            | 工具数 | 用途                   | 优先级 |
| ------------------- | ------ | ---------------------- | ------ |
| fetch               | 1      | HTTP 请求、API 测试    | P0     |
| memory              | 2      | 上下文记忆、状态持久化 | P0     |
| chrome-devtools     | 4      | 浏览器自动化           | P0     |
| js-reverse          | 2      | JS 逆向工程            | P0     |
| burp                | 2      | HTTP 抓包、重放        | P0     |
| frida-mcp           | 2      | 移动端 Hook            | P1     |
| adb-mcp             | 3      | 安卓设备控制           | P1     |
| jadx                | 2      | APK 反编译             | P1     |
| ida-pro-mcp         | 2      | 二进制逆向             | P1     |
| sequential-thinking | 1      | 复杂推理链             | P1     |
| context7            | 1      | 代码上下文检索         | P1     |
| everything-search   | 1      | 本地文件搜索           | P2     |

> 共 11 个 MCP 服务、23 个工具定义。另有 3 个内置 Agent 工具（`load_skill_reference` + `crypto_decode` + `python_execute`），无需 MCP 即可调用。

---

## 内置 Skill

### 核心 Skill (7)

| Skill             | 说明               |
| ----------------- | ------------------ |
| pentest-flow      | 渗透测试全流程编排 |
| recon             | 信息收集流程       |
| vuln-discovery    | 漏洞发现流程       |
| exploitation      | 漏洞利用流程       |
| post-exploitation | 后渗透流程         |
| reporting         | 报告生成流程       |
| waf-bypass        | WAF 绕过技巧库     |

### 专项 Skill (12)

| Skill                     | 参考文档数 | 说明                                         |
| ------------------------- | ---------- | -------------------------------------------- |
| web-pentest               | 4          | Web 应用渗透                                 |
| android-pentest           | 9          | 安卓应用渗透                                 |
| client-reverse            | 20         | 客户端逆向分析                               |
| web-security-advanced     | 33         | Web 安全进阶（注入、绕过、利用链）           |
| ai-mcp-security           | 7          | AI/MCP 安全测试                              |
| intranet-pentest-advanced | 15         | 内网渗透进阶                                 |
| pentest-tools             | 18         | 渗透工具速查                                 |
| rapid-checklist           | 3          | 快速检查清单                                 |
| crypto-toolkit            | 3          | 编解码/加解密（29 种操作，注册为内置工具）   |
| **ctf-web**               | 8          | 🆕 CTF Web 攻击知识库（PHP绕过/RCE/SSTI/反序列化） |
| **ctf-crypto**            | 6          | 🆕 CTF 密码学攻击知识库（RSA/AES/ECC/PRNG/格攻击） |
| **ctf-misc**              | 6          | 🆕 CTF 杂项知识库（PyJail/BashJail/编码链/VM逆向） |

Skill 会根据用户输入自动调度，无需手动选择。专项 Skill 含 `references/` 目录下的详细方法论文档，LLM 可通过 `load_skill_reference` 工具按需加载。

### 内置编解码/加解密工具 (crypto_decode)

`crypto_decode` 注册为 Agent 内置工具，LLM 在任何上下文中均可调用，不再靠猜测解码结果：

| 类别     | 操作                                                                                     |
| -------- | ---------------------------------------------------------------------------------------- |
| 编解码   | base64, base32, base58, hex, url, html, unicode, rot13, caesar, morse（各有 encode/decode） |
| 哈希     | md5, sha1, sha256, sha512                                                                |
| 加解密   | aes_encrypt, aes_decrypt（CBC 模式，PKCS7 填充）                                          |
| JWT      | jwt_decode, jwt_encode                                                                   |
| 自动识别 | auto_decode — 尝试所有常见编码，返回匹配结果                                              |

---

## 配置管理

### 命令行配置

```bash
vulnclaw config list                          # 查看所有配置
vulnclaw config get llm.model                 # 查看单项
vulnclaw config set llm.api_key sk-xx         # 设置 API Key
vulnclaw config set session.max_rounds 30     # 设置自主渗透最大轮数（默认 15）
vulnclaw config set session.stale_rounds_threshold 8  # 设置死循环检测阈值（默认 5）
vulnclaw config set session.show_thinking false # 隐藏推理过程（也可在 REPL 中用 think off）
```

### 可配置项

| 配置项                   | 默认值 | 说明                                     |
| ------------------------ | ------ | ---------------------------------------- |
| `llm.provider`           | openai | LLM 提供商（8 个内置 + custom）          |
| `llm.api_key`            | 空     | API Key                                  |
| `llm.base_url`           | 按 provider | API 基础 URL，可自定义              |
| `llm.model`              | 按 provider | 模型名称，可自定义                   |
| `llm.temperature`        | 0.1    | 采样温度                                 |
| `llm.max_tokens`         | 4096   | 单次最大输出 token                       |
| `session.max_rounds`     | 15     | 自主渗透循环最大轮数（建议 10-50）       |
| `session.output_dir`     | ./vulnclaw-output | 报告输出目录                    |
| `session.report_format`  | markdown | 报告格式（markdown / html）            |
| `session.poc_language`   | python | PoC 生成语言（python / bash）            |
| `session.show_thinking`  | false  | 显示 LLM 推理过程（think 标签内容，默认关闭） |
| `session.persistent_rounds_per_cycle` | 100 | 持续性渗透每周期轮数 |
| `session.persistent_max_cycles` | 10 | 持续性渗透最大周期数（0=无限） |
| `session.persistent_auto_report` | true | 持续性渗透每周期自动生成报告 |
| `session.stale_rounds_threshold` | 5 | 死循环检测阈值 — 连续无新发现轮数达到此值时触发强制策略切换 |

### 环境变量

| 变量                          | 说明                   |
| ----------------------------- | ---------------------- |
| `VULNCLAW_LLM_PROVIDER`       | LLM 提供商名称         |
| `VULNCLAW_LLM_API_KEY`        | API Key                |
| `VULNCLAW_LLM_BASE_URL`       | API 基础 URL           |
| `VULNCLAW_LLM_MODEL`          | 模型名称               |
| `VULNCLAW_SESSION__MAX_ROUNDS`| 自主渗透最大轮数       |
| `VULNCLAW_SESSION__STALE_ROUNDS_THRESHOLD` | 死循环检测阈值 |

优先级：**环境变量 > 配置文件 > 内置默认值**

配置文件位于 `~/.vulnclaw/config.yaml`。

---

## 版本路线

| 版本     | 目标                                                    | 状态       |
| -------- | ------------------------------------------------------- | ---------- |
| v0.1 MVP | CLI + LLM Agent + 基础 MCP + Skill + 报告 + 多 Provider | ✅ 当前    |
| v0.1.1   | `python_execute` + 上下文压缩 + 代码审计策略 + 反幻觉  | ✅ 已完成  |
| v0.1.2   | 3 个 CTF 专项 Skill + 3 个现有 Skill 更新 + 触发词扩展 | ✅ 已完成  |
| v0.2     | 移动端能力（Frida / ADB / JADX）+ LLM 调用优化          | 🔜 Skill ✅ |
| v0.3     | 逆向能力（IDA Pro）— Skill 已就绪                       | 📋 Skill ✅ |
| v0.4     | 知识库增强（ChromaDB 向量检索 + 语义 Skill 调度）       | 📋         |
| v1.0     | 正式发布（PyPI + 文档 + CI/CD）                         | 📋         |

---

## 安全声明

VulnClaw 仅用于**已授权的安全测试**。使用本工具前，请确保：

1. 你已获得目标系统的**明确授权**
2. 测试范围已与目标所有者**书面确认**
3. 你遵守当地**法律法规**

未经授权对系统进行渗透测试是违法行为。本工具作者不对滥用行为承担责任。

---

## 许可证

[MIT License](LICENSE)

---

<div align="center">

> 🦞 **VulnClaw** — 让每一次渗透都有章可循。

</div>