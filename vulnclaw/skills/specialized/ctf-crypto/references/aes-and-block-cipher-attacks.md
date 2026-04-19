# AES 与分组密码攻击

## 加密模式速查

| 模式 | 特点 | 可利用漏洞 |
|------|------|-----------|
| ECB | 相同明文→相同密文 | 模式识别、重排攻击 |
| CBC | 前一块密文参与当前加密 | IV 翻转、Padding Oracle |
| CTR | 流式加密 | nonce 重用 → XOR 泄露 |
| CFB | 类似流密码 | IV 翻转 |
| OFB | 类似流密码 | nonce 重用 |
| GCM | 认证加密 | nonce 重用 → 密钥流恢复 |

## ECB 字节翻转

```python
from Crypto.Cipher import AES

# ECB 模式下相同明文块产生相同密文块
# 攻击：识别重复密文块 → 推断明文结构
# 可重排密文块改变明文结构

def ecb_detect(ciphertext, block_size=16):
    """检测 ECB 模式（查找重复块）"""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))
```

## CBC IV 翻转攻击

```python
"""
原理：在 CBC 中，P[i] = Decrypt(C[i]) XOR C[i-1]
修改 C[i-1] 的某字节 → 对应 P[i] 的该字节也被翻转

用途：修改 IV 可改变第一块明文，修改 C[i-1] 可改变第 i 块明文
代价：C[i-1] 对应的明文 P[i-1] 会被破坏
"""

def cbc_iv_flip(ciphertext, known_plain, target_plain, block_size=16):
    """翻转 CBC 第一块明文（修改 IV）"""
    iv = bytearray(ciphertext[:block_size])
    for i in range(block_size):
        iv[i] = iv[i] ^ known_plain[i] ^ target_plain[i]
    return bytes(iv) + ciphertext[block_size:]
```

## Padding Oracle 攻击

```python
"""
原理：CBC 解密时如果 Padding 不合法，服务器返回不同错误
通过逐字节爆破，利用错误/正确差异恢复明文

条件：
1. 使用 CBC 模式
2. 服务器对 Padding 错误和密文错误返回不同响应
3. 可以反复提交修改后的密文
"""

def padding_oracle_attack(oracle, ciphertext, block_size=16):
    """Padding Oracle 攻击恢复明文
    
    oracle: 函数，接受密文返回 True(padding正确)/False(padding错误)
    """
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext = b''
    
    for block_idx in range(1, len(blocks)):
        prev_block = bytearray(blocks[block_idx - 1])
        curr_block = blocks[block_idx]
        intermediate = bytearray(block_size)
        
        for byte_pos in range(block_size - 1, -1, -1):
            padding_val = block_size - byte_pos
            
            # 构造测试密文
            test_block = bytearray(block_size)
            for k in range(byte_pos + 1, block_size):
                test_block[k] = intermediate[k] ^ padding_val
            
            found = False
            for guess in range(256):
                test_block[byte_pos] = guess
                test_cipher = bytes(test_block) + curr_block
                
                if oracle(test_cipher):
                    intermediate[byte_pos] = guess ^ padding_val
                    found = True
                    break
            
            if not found:
                raise Exception(f"Padding oracle attack failed at byte {byte_pos}")
        
        # 恢复明文
        for i in range(block_size):
            plaintext += bytes([intermediate[i] ^ prev_block[i]])
    
    return plaintext
```

## GCM Nonce 重用攻击

```python
"""
当同一个 nonce 被用于两次加密时：
- 两次加密使用相同的密钥流
- C1 = P1 XOR keystream
- C2 = P2 XOR keystream
- C1 XOR C2 = P1 XOR P2

如果知道 P1，可以恢复 P2
"""

def gcm_nonce_reuse(c1, c2, p1):
    """利用 GCM nonce 重用恢复明文"""
    return bytes(a ^ b ^ c for a, b, c in zip(c1, c2, p1))
```

## CTR Nonce 重用

```python
"""
CTR 模式下 nonce 重用等价于流密码密钥重用
C1 = P1 XOR keystream
C2 = P2 XOR keystream
C1 XOR C2 = P1 XOR P2
"""

def ctr_nonce_reuse(c1, c2, known_p1):
    """利用 CTR nonce 重用恢复明文"""
    return bytes(a ^ b ^ c for a, b, c in zip(c1, c2, known_p1))
```
