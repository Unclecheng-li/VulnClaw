# 游戏与自定义 VM 逆向

## Brainfuck

```python
# Brainfuck 解释器
import sys

def brainfuck(code, input_data=''):
    code = ''.join(c for c in code if c in '><+-.,[]')
    tape = [0] * 30000
    ptr = 0
    iptr = 0
    input_ptr = 0
    output = []

    while iptr < len(code):
        op = code[iptr]
        if op == '>':
            ptr += 1
        elif op == '<':
            ptr -= 1
        elif op == '+':
            tape[ptr] = (tape[ptr] + 1) % 256
        elif op == '-':
            tape[ptr] = (tape[ptr] - 1) % 256
        elif op == '.':
            output.append(chr(tape[ptr]))
        elif op == ',':
            if input_ptr < len(input_data):
                tape[ptr] = ord(input_data[input_ptr])
                input_ptr += 1
            else:
                tape[ptr] = 0
        elif op == '[':
            if tape[ptr] == 0:
                depth = 1
                while depth > 0:
                    iptr += 1
                    if code[iptr] == '[':
                        depth += 1
                    elif code[iptr] == ']':
                        depth -= 1
        elif op == ']':
            if tape[ptr] != 0:
                depth = 1
                while depth > 0:
                    iptr -= 1
                    if code[iptr] == '[':
                        depth -= 1
                    elif code[iptr] == ']':
                        depth += 1
        iptr += 1

    return ''.join(output)
```

## Ook!

```python
# Ook! 到 Brainfuck 转换
ook_to_bf = {
    'Ook. Ook?': '>',
    'Ook? Ook.': '<',
    'Ook. Ook.': '+',
    'Ook! Ook!': '-',
    'Ook! Ook.': '.',
    'Ook. Ook!': ',',
    'Ook! Ook?': '[',
    'Ook? Ook!': ']',
}
```

## 自定义 VM逆向流程

```python
# 分析自定义 VM 的步骤：
# 1. 找到 opcode 定义表
# 2. 找到 VM 初始化代码（寄存器、内存初始化）
# 3. 跟踪 main loop，找到指令分发
# 4. 分析每个 opcode 的功能
# 5. 提取 bytecode 文件
# 6. 写反汇编器或直接模拟执行

"""
常见 opcode 模式：
0x00 = NOP
0x01 = LOAD  (加载数据)
0x02 = STORE (存储数据)
0x03 = ADD
0x04 = SUB
0x05 = JMP
0x06 = JZ    (条件跳转)
0x07 = HALT
"""

class SimpleVM:
    def __init__(self, bytecode):
        self.bytecode = bytecode
        self.regs = [0] * 8
        self.memory = bytecode[256:]  # 假设代码后是数据
        self.pc = 0
        self.running = True

    def step(self):
        op = self.bytecode[self.pc]
        if op == 0x01:  # LOAD
            self.pc += 1
            reg = self.bytecode[self.pc]
            self.pc += 1
            addr = self.bytecode[self.pc]
            self.regs[reg] = self.memory[addr]
        elif op == 0x05:  # JMP
            self.pc += 1
            self.pc = self.bytecode[self.pc]
        elif op == 0x07:  # HALT
            self.running = False
        self.pc += 1

    def run(self):
        while self.running and self.pc < len(self.bytecode):
            self.step()
```

## Z3 约束求解

```python
from z3 import *

def solve_with_z3(constraints, variables):
    """使用 Z3 求解约束"""
    s = Solver()
    for constraint in constraints:
        s.add(constraint)
    if s.check() == sat:
        model = s.model()
        return {v: model[v] for v in variables}
    return None
```

## WASM 分析

```python
# 常用 wasm 分析命令
"""
# 提取 wasm 字符串
strings game.wasm | grep -i flag

# 查看导出函数
wasm-objdump -h game.wasm

# 反编译为 wasm 文本格式
wasm2wat game.wasm -o game.wat

# 查看函数
wasm-objdump -d game.wasm

# 用 wasmer 或 wasmtime 执行
wasmer game.wasm
"""
```
