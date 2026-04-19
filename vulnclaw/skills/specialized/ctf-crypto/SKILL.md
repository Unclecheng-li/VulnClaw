---
name: ctf-crypto
description: CTF密码学攻击知识库 — RSA攻击（小指数/共模/Wiener/Coppersmith）、AES攻击（Padding Oracle/ECB字节翻转/GCM nonce重用）、ECC攻击、LFSR/LCG/PRNG攻击、古典密码、LWE格攻击
---

# CTF 密码学攻击知识库

针对 CTF Crypto 题目的实战攻击知识库，提供**具体攻击参数、数学公式、Python 代码片段**。

**与 `crypto-toolkit` 的区别**：
- `crypto-toolkit` → 编解码操作工具（base64 解码、MD5 哈希、AES 加解密）
- `ctf-crypto` → 密码学攻击知识（RSA 小指数攻击怎么做、Padding Oracle 怎么利用）

## 核心原则

1. **先识别加密体系** — 看密钥长度、加密模式、已知量，确定攻击方向
2. **工具验证** — 使用 `python_execute` 执行攻击代码，用 `crypto_decode` 做辅助编解码
3. **参数敏感** — 密码学攻击对参数极其敏感，必须精确计算

## 场景路由

| 场景 | 参考文档 | 核心攻击 |
|------|---------|---------|
| RSA 攻击 | `rsa-attacks-cheatsheet.md` | 小e/共模/Wiener/Pollard/Fermat/Coppersmith |
| AES/分组密码攻击 | `aes-and-block-cipher-attacks.md` | ECB翻转/Padding Oracle/GCM nonce重用 |
| ECC 攻击 | `ecc-attacks-cheatsheet.md` | 小子群/invalid curve/Smart/Pohlig-Hellman |
| PRNG/流密码攻击 | `prng-and-stream-cipher-attacks.md` | MT19937/LCG/LFSR/RC4 |
| 古典密码 | `classic-cipher-attacks.md` | Vigenere/XOR频率分析/OTP重用 |
| 格攻击 | `lattice-and-lwe-attacks.md` | LLL/BKZ/HNP/LWE embedding |

## 快速判题指南

| 题目特征 | 可能攻击 | 推荐参考 |
|---------|---------|---------|
| 给了 n, e, c | RSA | rsa-attacks-cheatsheet.md |
| e=3 或 e 很小 | RSA 小指数攻击 | rsa-attacks-cheatsheet.md |
| 多组 (n, e, c) 且 n 相同 | RSA 共模攻击 | rsa-attacks-cheatsheet.md |
| n 很大但 e 很大 | Wiener 攻击 | rsa-attacks-cheatsheet.md |
| AES-CBC + 解密 oracle | Padding Oracle | aes-and-block-cipher-attacks.md |
| AES-ECB + 可控明文 | ECB 字节翻转 | aes-and-block-cipher-attacks.md |
| 椭圆曲线参数 | ECC 攻击 | ecc-attacks-cheatsheet.md |
| 给了随机数序列 | PRNG 预测 | prng-and-stream-cipher-attacks.md |
| 给了密文和部分明文 | XOR/流密码 | classic-cipher-attacks.md |
| 矩阵/向量运算 | 格攻击 | lattice-and-lwe-attacks.md |
