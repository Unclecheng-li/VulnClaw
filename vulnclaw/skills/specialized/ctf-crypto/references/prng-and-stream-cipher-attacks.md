# PRNG 与流密码攻击

## MT19937 ( Mersenne Twister ) 攻击

```python
# MT19937 状态恢复（给定 624 个输出）
from ctypes import *

def untemper(y):
    y ^= y >> 18
    y ^= (y << 15) & 0xefc60000
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 14) & 0x9d2c5680
    y ^= (y << 13) & 0x9d2c5680
    y ^= (y << 11) & 0x9d2c5680
    y ^= y >> 18
    return y

def recover_mt(outputs):
    """从 624 个连续 MT19937 输出恢复内部状态"""
    state = [untemper(y) for y in outputs[:624]]
    MT = c_ulong * 624
    mt = MT(*state)
    index = 624
    def twist():
        global index, mt
        for i in range(227):
            y = (mt[i] & 0x80000000) + (mt[(i+1)%624] & 0x7fffffff)
            mt[i] = mt[(i+397) % 624] ^ (y >> 1)
            if y & 1:
                mt[i] ^= 0x9908b0df
        index = 0
    return mt, twist, index
```

## LCG (线性同余生成器) 攻击

```python
"""
LCG: s_{n+1} = a * s_n + c (mod m)
已知参数时：直接递推
未知参数时：已知 3 组 (s, s_next) 可求 a, c, m
"""

def lcg_attack(states):
    """从 3 个连续状态恢复 LCG 参数 (a, c, m)"""
    s0, s1, s2 = states[0], states[1], states[2]
    # s1 = a*s0 + c (mod m)
    # s2 = a*s1 + c (mod m)
    # s2 - s1 = a*(s1 - s0) (mod m)
    # 扩展欧几里得求 a, m
```

## LFSR (线性反馈移位寄存器) 攻击

```python
"""
Berlekamp-Massey 算法：从输出序列恢复 LFSR 反馈多项式
"""

def berlekamp_massey(s):
    """从二进制序列恢复 LFSR 最短反馈多项式"""
    # Sage 实现
    # F.<x> = GF(2)[]
    # s_seq = sequence(s)
    # return list(lfsr_sequence(f, [1]+[0]*15, len(s)))
```

## 已知明文攻击 (XOR 流密码)

```python
"""
流密码: C = P XOR keystream
如果知道部分明文 P，可以恢复 keystream = C XOR P
keystream 可用于解密其他密文
"""

def xor_attack(ciphertext, known_plaintext):
    """XOR 流密码已知明文攻击"""
    key = bytes(a ^ b for a, b in zip(ciphertext, known_plaintext))
    return key

def xor_decrypt(key, ciphertext):
    """用恢复的密钥流解密"""
    return bytes(a ^ b for a, b in zip(key, ciphertext))
```

## RC4 攻击

```python
"""
RC4 已知弱点：
1. RC4 Drop (丢弃前 N 字节后，密钥流接近随机)
2. 某些密钥初始化有偏差
"""

def rc4_drop(ciphertext, drop=3072):
    """RC4 Drop N 字节后解密"""
```

## Python random 模块预测

```python
import random

# 如果能访问 Python random 状态，可以预测未来随机数
# 已知 624 * 4 = 2496 字节的状态
state = random.getstate()
# 推进随机数
random.setstate(state)
next_val = random.randint(0, 2**31)
```
