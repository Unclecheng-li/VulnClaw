# 古典密码攻击

## 凯撒密码

```python
def caesar_break(ciphertext):
    """遍历所有位移"""
    for shift in range(26):
        result = ""
        for c in ciphertext:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result += chr((ord(c) - base + shift) % 26 + base)
            else:
                result += c
        print(f"Shift {shift}: {result}")
```

## Vigenère 密码

```python
def vigenere_break(ciphertext, max_keylen=20):
    """Kasiski + 频率分析破解 Vigenère"""
    from collections import Counter

    # 1. Kasiski: 找到重复序列，估算密钥长度
    def kasiski(text):
        distances = []
        for length in range(3, 6):
            seqs = {}
            for i in range(len(text) - length):
                seq = text[i:i+length]
                if seq in seqs:
                    distances.append(i - seqs[seq])
                seqs[seq] = i
        return distances

    # 2. 重合指数 (IC) 估算密钥长度
    def ic(text):
        freq = Counter(text.upper())
        n = len(text)
        return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

    # 3. 频率分析解单个字母
    def solve_char(text, key_char):
        ENGLISH_FREQ = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
        key_base = ord(key_char.upper()) - ord('A')
        best_score = 0
        best_char = 'E'
        for shift in range(26):
            freq = Counter()
            for c in text:
                if c.isalpha():
                    shifted = chr((ord(c.upper()) - ord('A') - shift) % 26 + ord('A'))
                    freq[shifted] += 1
            score = sum(ENGLISH_FREQ.index(k) * freq[k] for k in freq if k in ENGLISH_FREQ)
            if score > best_score:
                best_score = score
                best_char = chr(ord('A') + shift)
        return best_char
```

## XOR 多字节加密

```python
def multi_byte_xor_break(ciphertext, max_keylen=16):
    """多字节 XOR 攻击：汉明距离 + 频率分析"""
    from collections import Counter

    def hamming_distance(b1, b2):
        return sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))

    # 用汉明距离估算密钥长度
    best_keylen = 1
    best_score = float('inf')
    for keylen in range(2, max_keylen + 1):
        chunks = [ciphertext[i:i+keylen] for i in range(0, len(ciphertext), keylen)]
        avg_dist = sum(hamming_distance(c1, c2) for c1, c2 in zip(chunks[:4], chunks[1:5])) / 4
        normalized = avg_dist / keylen
        if normalized < best_score:
            best_score = normalized
            best_keylen = keylen

    # 按密钥长度分组，每组做单字节 XOR
    key = b''
    for i in range(best_keylen):
        block = bytes(ciphertext[j] for j in range(i, len(ciphertext), best_keylen))
        # 频率分析找最佳单字节密钥
        best = 0
        best_score = 0
        for k in range(256):
            decrypted = bytes(b ^ k for b in block)
            score = sum(1 for b in decrypted if chr(b).isalpha() or chr(b).isspace())
            if score > best_score:
                best_score = score
                best = k
        key += bytes([best])

    return key
```

## One-Time Pad (OTP) 重用攻击

```python
"""
如果同一个 OTP 密钥被用于加密两条消息：
C1 = P1 XOR key
C2 = P2 XOR key
C1 XOR C2 = P1 XOR P2

利用语言冗余性（英文词频）破解
"""
from collections import Counter

def otp_reuse_attack(c1, c2):
    """OTP 密钥重用攻击"""
    xor_result = bytes(a ^ b for a, b in zip(c1, c2))
    # 频率分析恢复明文
```

## 栅栏密码

```python
def railfence_break(ciphertext, max_rails=10):
    """遍历栅栏数解密"""
    for rails in range(2, max_rails + 1):
        # 重建栅栏结构
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for c in ciphertext:
            fence[rail].append(c)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction
        # 逐行读取
        result = ''.join(''.join(row) for row in fence)
        print(f"Rails {rails}: {result}")
```
