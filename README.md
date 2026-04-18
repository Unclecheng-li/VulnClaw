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
- **MCP 工具链** — 内置 12 个安全 MCP 服务（fetch / Burp / Frida / Chrome DevTools / IDA Pro 等）
- **AI Agent 核心** — OpenAI 兼容协议 + Tool Calling + 自主渗透循环
- **15 个渗透 Skill** — 从信息收集到后渗透，7 核心 + 8 专项 Skill，含 109 个参考文档
- **沙盒模式提示词** — 解锁 AI 安全测试能力，CTF / 授权渗透场景专用
- **自动报告 & PoC** — 生成结构化 Markdown 报告和可运行的 Python PoC 脚本
- **安全知识库** — 内置 CVE 数据库、WAF 绕过技巧、漏洞利用方法

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
# 自定义 Base URL
vulnclaw config set llm.base_url https://your-own-api.example.com/v1 (记得换成宝贝你的喵~)

# 自定义模型名
vulnclaw config set llm.model your-model-name (这个也要换喵~)

# 设置 Key
vulnclaw config set llm.api_key sk-your-key-here (要换的喵~)

# 元神启动！
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
  Provider: minimax
  API Key: 已设置
  Base URL: https://api.minimaxi.com/v1
  Model: MiniMax-M2.7

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

| 命令                  | 说明                             |
| --------------------- | -------------------------------- |
| `target <host>`       | 设置渗透测试目标                 |
| `status`              | 查看当前状态（目标、阶段、工具） |
| `tools`               | 列出当前可用 MCP 工具            |
| `clear`               | 清空当前会话                     |
| `help`                | 显示帮助信息                     |
| `exit` / `quit` / `q` | 退出 VulnClaw                    |

### 方式二：单命令模式

```bash
# 一键全流程渗透测试
vulnclaw run 192.168.1.100

# 仅信息收集
vulnclaw recon 192.168.1.100

# 漏洞扫描（可指定端口）
vulnclaw scan 192.168.1.100 --ports 80,443,8080

# 漏洞利用（可指定 CVE）
vulnclaw exploit 192.168.1.100 --cve CVE-2024-1234 --cmd id

# 生成报告
vulnclaw report session.json
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
│               │ (12 工具链) │                │
│               └─────┬──────┘                │
│               ┌─────▼──────┐                │
│               │ 安全知识库  │                │
│               └────────────┘                │
└─────────────────────────────────────────────┘
```

### 核心模块

| 模块           | 文件                                             | 说明                                          |
| -------------- | ------------------------------------------------ | --------------------------------------------- |
| **CLI 入口**   | `cli/main.py`                                    | Typer REPL + 8 个子命令                       |
| **Agent 核心** | `agent/core.py`                                  | OpenAI SDK + Tool Calling + 自主渗透循环      |
| **动态提示词** | `agent/prompts.py`                               | 基础身份 + 核心契约 + Skill + MCP 工具列表    |
| **会话状态**   | `agent/context.py`                               | 阶段追踪 + 漏洞发现 + 步骤记录                |
| **MCP 编排**   | `mcp/registry.py` + `lifecycle.py` + `router.py` | 服务注册 + 生命周期 + 自然语言→工具路由       |
| **Skill 调度** | `skills/loader.py` + `dispatcher.py`             | 目录格式 Skill + 15 种意图动态调度            |
| **配置管理**   | `config/schema.py` + `settings.py`               | Pydantic 模型 + YAML 持久化 + 8 Provider 预设 |
| **报告生成**   | `report/generator.py` + `poc_builder.py`         | Markdown 报告 + Python PoC 模板               |
| **安全知识库** | `kb/store.py` + `retriever.py`                   | JSON 存储 + CVE/技术/工具检索                 |

---

## MCP 工具链

| MCP 服务            | 用途                   | 优先级 |
| ------------------- | ---------------------- | ------ |
| fetch               | HTTP 请求、API 测试    | P0     |
| memory              | 上下文记忆、状态持久化 | P0     |
| chrome-devtools     | 浏览器自动化           | P0     |
| js-reverse          | JS 逆向工程            | P0     |
| burp                | HTTP 抓包、重放        | P0     |
| frida-mcp           | 移动端 Hook            | P1     |
| adb-mcp             | 安卓设备控制           | P1     |
| jadx                | APK 反编译             | P1     |
| ida-pro-mcp         | 二进制逆向             | P1     |
| sequential-thinking | 复杂推理链             | P1     |
| context7            | 代码上下文检索         | P1     |
| everything-search   | 本地文件搜索           | P2     |

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

### 专项 Skill (8)

| Skill                     | 参考文档数 | 说明                               |
| ------------------------- | ---------- | ---------------------------------- |
| web-pentest               | 4          | Web 应用渗透                       |
| android-pentest           | 9          | 安卓应用渗透                       |
| client-reverse            | 20         | 客户端逆向分析                     |
| web-security-advanced     | 33         | Web 安全进阶（注入、绕过、利用链） |
| ai-mcp-security           | 7          | AI/MCP 安全测试                    |
| intranet-pentest-advanced | 15         | 内网渗透进阶                       |
| pentest-tools             | 18         | 渗透工具速查                       |
| rapid-checklist           | 3          | 快速检查清单                       |

Skill 会根据用户输入自动调度，无需手动选择。专项 Skill 含 `references/` 目录下的详细方法论文档，LLM 可通过 `load_skill_reference` 工具按需加载。

---

## 配置管理

### 命令行配置

```bash
vulnclaw config list                          # 查看所有配置
vulnclaw config get llm.model                 # 查看单项
vulnclaw config set llm.api_key sk-xx         # 设置 API Key
vulnclaw config set session.max_rounds 30     # 设置自主渗透最大轮数（默认 15）
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

### 环境变量

| 变量                          | 说明                   |
| ----------------------------- | ---------------------- |
| `VULNCLAW_LLM_PROVIDER`       | LLM 提供商名称         |
| `VULNCLAW_LLM_API_KEY`        | API Key                |
| `VULNCLAW_LLM_BASE_URL`       | API 基础 URL           |
| `VULNCLAW_LLM_MODEL`          | 模型名称               |
| `VULNCLAW_SESSION__MAX_ROUNDS`| 自主渗透最大轮数       |

优先级：**环境变量 > 配置文件 > 内置默认值**

配置文件位于 `~/.vulnclaw/config.yaml`。

---

## 版本路线

| 版本     | 目标                                                    | 状态   |
| -------- | ------------------------------------------------------- | ------ |
| v0.1 MVP | CLI + LLM Agent + 基础 MCP + Skill + 报告 + 多 Provider | ✅ 当前 |
| v0.2     | 移动端能力（Frida / ADB / JADX）                        | 🔜      |
| v0.3     | 逆向能力（IDA Pro）                                     | 📋      |
| v0.4     | 知识库增强（ChromaDB 向量检索 + 语义 Skill 调度）       | 📋      |
| v1.0     | 正式发布（PyPI + 文档 + CI/CD）                         | 📋      |

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