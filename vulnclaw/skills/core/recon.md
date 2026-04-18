---
name: recon
description: 信息收集流程 — 被动+主动侦察
---

# 信息收集 Skill

执行被动和主动信息收集，构建目标画像和攻击面地图。

## 执行步骤

### 1. 被动侦察
- 通过 fetch 工具访问目标，收集 HTTP 响应头
- 识别服务器类型、版本、WAF
- 分析 HTML 源码中的技术栈标识

### 2. 主动侦察
- 探测常见 Web 端口
- 枚举目录和路径
- 检查敏感文件（robots.txt, .env, .git）
- 发现 API 端点

### 3. 技术栈识别
- 前端框架（React/Vue/Angular/jQuery）
- 后端框架（Express/Django/Flask/Spring）
- CMS 系统（WordPress/Joomla/自定义）
- 数据库类型

### 4. 输出
- 目标画像（IP/域名/端口/服务/技术栈）
- 攻击面地图（可访问路径、API、管理入口）
