# 供应链攻击
English: Supply Chain Attacks
- Entry Count: 3
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## NPM包名仿冒(Typosquatting)
- ID: supply-typosquat
- Difficulty: intermediate
- Subcategory: 包管理器投毒
- Tags: 供应链, NPM, Typosquatting, 包投毒, postinstall
- Original Extracted Source: original extracted web-security-wiki source/supply-typosquat.md
Description:
通过注册与流行NPM包名高度相似的恶意包(如lodash→1odash, colors→co1ors)，诱导开发者误安装。恶意包在install/postinstall钩子中执行反弹Shell、窃取环境变量或植入后门。
Prerequisites:
- NPM账号
- 了解目标项目依赖
- 恶意包基础设施
Execution Outline:
1. 1. 侦察目标依赖
2. 2. 生成仿冒包名
3. 3. 构造恶意包
4. 4. 检测与取证
## CI/CD管道投毒
- ID: supply-ci-poison
- Difficulty: advanced
- Subcategory: CI/CD攻击
- Tags: 供应链, CI/CD, GitHub Actions, Jenkins, Pipeline
- Original Extracted Source: original extracted web-security-wiki source/supply-ci-poison.md
Description:
通过恶意Pull Request、Actions注入或构建脚本篡改来攻击CI/CD管道。攻击者可窃取构建密钥、投毒构建产物或在部署流程中植入后门代码。
Prerequisites:
- 目标使用公开CI/CD
- 可提交PR或Fork
Execution Outline:
1. 1. 识别CI/CD配置
2. 2. PR触发的工作流注入
3. 3. Actions表达式注入
4. 4. 构建产物投毒
## 依赖混淆攻击
- ID: supply-dependency-confusion
- Difficulty: intermediate
- Subcategory: 依赖混淆
- Tags: 供应链, 依赖混淆, NPM, PyPI, Dependency Confusion
- Original Extracted Source: original extracted web-security-wiki source/supply-dependency-confusion.md
Description:
利用包管理器在公共注册表和私有注册表之间的解析优先级漏洞。当企业使用内部包名时，攻击者在公共NPM/PyPI注册更高版本号的同名包，包管理器会优先安装公共高版本包从而执行恶意代码。
Prerequisites:
- 已知目标内部包名
- 公共注册表账号
Execution Outline:
1. 1. 发现内部包名
2. 2. 在公共注册表注册同名包
3. 3. 监控DNS回调确认命中
4. 4. 影响评估与报告

