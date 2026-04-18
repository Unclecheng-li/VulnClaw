# SSTI模板注入
English: SSTI Template Injection
- Entry Count: 10
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## Jinja2模板注入
- ID: ssti-jinja2
- Difficulty: advanced
- Subcategory: Jinja2
- Tags: ssti, jinja2, twig, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-jinja2.md
Description:
Jinja2/Twig模板注入攻击技术
Prerequisites:
- 使用Jinja2/Twig模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行
4. 4. 反弹Shell
## FreeMarker模板注入
- ID: ssti-freemarker
- Difficulty: intermediate
- Subcategory: FreeMarker
- Tags: ssti, freemarker, java, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-freemarker.md
Description:
FreeMarker模板引擎注入攻击技术
Prerequisites:
- 使用FreeMarker模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - new
4. 4. 命令执行 - api
## Velocity模板注入
- ID: ssti-velocity
- Difficulty: advanced
- Subcategory: Velocity
- Tags: ssti, velocity, java, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-velocity.md
Description:
Velocity模板引擎注入攻击技术
Prerequisites:
- 使用Velocity模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - ClassTool
4. 4. 命令执行 - 反射
## Thymeleaf模板注入
- ID: ssti-thymeleaf
- Difficulty: intermediate
- Subcategory: Thymeleaf
- Tags: ssti, thymeleaf, java, spring, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-thymeleaf.md
Description:
Thymeleaf模板引擎注入攻击技术
Prerequisites:
- 使用Thymeleaf模板引擎
- Spring框架
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - Spring表达式
4. 4. 命令执行 - ProcessBuilder
## Smarty模板注入
- ID: ssti-smarty
- Difficulty: intermediate
- Subcategory: Smarty
- Tags: ssti, smarty, php, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-smarty.md
Description:
Smarty模板引擎注入攻击技术
Prerequisites:
- 使用Smarty模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - system
4. 4. 命令执行 - passthru
## Mako模板注入
- ID: ssti-mako
- Difficulty: intermediate
- Subcategory: Mako
- Tags: ssti, mako, python, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-mako.md
Description:
Mako模板引擎注入攻击技术
Prerequisites:
- 使用Mako模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - os模块
4. 4. 命令执行 - subprocess
## Tornado模板注入
- ID: ssti-tornado
- Difficulty: intermediate
- Subcategory: Tornado
- Tags: ssti, tornado, python, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-tornado.md
Description:
Tornado模板引擎注入攻击技术
Prerequisites:
- 使用Tornado模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - os
4. 4. 命令执行 - subprocess
## Django模板注入
- ID: ssti-django
- Difficulty: intermediate
- Subcategory: Django
- Tags: ssti, django, python, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-django.md
Description:
Django模板引擎注入攻击技术
Prerequisites:
- 使用Django模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - 通过settings
4. 4. 命令执行 - 对象链
## ERB模板注入
- ID: ssti-erb
- Difficulty: intermediate
- Subcategory: ERB
- Tags: ssti, erb, ruby, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-erb.md
Description:
ERB(Ruby)模板引擎注入攻击技术
Prerequisites:
- 使用ERB模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - 反引号
4. 4. 命令执行 - system
## Pug/Jade模板注入
- ID: ssti-pug
- Difficulty: intermediate
- Subcategory: Pug
- Tags: ssti, pug, jade, nodejs, template
- Original Extracted Source: original extracted web-security-wiki source/ssti-pug.md
Description:
Pug/Jade模板引擎注入攻击技术
Prerequisites:
- 使用Pug/Jade模板引擎
- 用户输入直接渲染到模板
Execution Outline:
1. 1. 探测SSTI
2. 2. 信息收集
3. 3. 命令执行 - child_process
4. 4. 命令执行 - execSync

