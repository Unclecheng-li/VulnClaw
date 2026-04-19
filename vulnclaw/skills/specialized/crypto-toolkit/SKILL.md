---
name: crypto-toolkit
description: 编码解码与加解密工具 — base64/URL/Hex/HTML实体编码解码，MD5/SHA哈希，AES/DES/RSA加解密，JWT解析，Caesar/ROT13密码，栅栏/Vigenere密码，Unicode转义，Morse电码等
---

# 编码解码与加解密 Skill

针对渗透测试中常见的编码、加密、混淆场景，提供全面的编解码和加解密能力。
**重要**：遇到任何编码/加密字符串时，优先使用 `crypto_decode` 工具进行解码，而非靠直觉猜测。

## 核心原则

1. **工具优先** — 遇到 base64、hex、URL编码等字符串，调用 `crypto_decode` 工具解码，不要自行脑补
2. **多格式尝试** — 如果一种解码方式结果不合理，尝试其他编码格式
3. **链式解码** — CTF 中常见多层编码（如 base64→hex→ROT13），解码后检查结果是否还需再次解码
4. **验证结果** — 解码后验证结果的合理性（是否为可读文本、是否像路径/URL/flag 等）

## 1. 编码识别与解码

### 常见编码特征识别

| 编码类型 | 特征 | 示例 |
|---------|------|------|
| Base64 | `A-Za-z0-9+/=` 结尾常有 `=` 填充 | `TnNTY1RmLnBocA==` |
| Base32 | `A-Z2-7=` | `OBZHK5DFN2A====` |
| Hex | `0-9a-f` 偶数长度 | `4e73536354662e706870` |
| URL编码 | `%XX` 格式 | `%2F%61%64%6D%69%6E` |
| HTML实体 | `&#xNN;` 或 `&#NNN;` | `&#x3C;script&#x3E;` |
| Unicode转义 | `\uXXXX` 或 `\UXXXXXXXX` | `\u003c\u0073\u0063` |
| JWT | 三段 `.` 分隔的 base64 | `eyJhbG...` |

### 解码策略

1. 识别编码类型 → 调用 `crypto_decode` 工具指定对应操作
2. 检查解码结果是否可读/合理
3. 不合理则尝试其他编码格式
4. 如果结果仍像编码，重复步骤 1-3

## 2. 哈希与散列

### 常见哈希类型

| 类型 | 输出长度 | 特征 |
|------|---------|------|
| MD5 | 32 hex | `e10adc3949ba59abbe56e057f20f883e` |
| SHA1 | 40 hex | `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` |
| SHA256 | 64 hex | `2c26b46b68ffc68ff99b453c1d30413413422d7064...` |
| SHA512 | 128 hex | 更长的hex字符串 |
| NTLM | 32 hex | Windows hash |
| MySQL5 | 41字符 | `*E6CC90B878B948C35E92B003C792C46758BF4` |

### 哈希处理策略

- 识别哈希类型（通过长度和字符集）
- 尝试在线彩虹表查询（通过 fetch 工具访问 crackstation 等）
- 对于已知盐值的哈希，尝试带盐值暴力破解

## 3. 对称加密

### AES/DES/3DES

- 需要密钥和模式（ECB/CBC/CTR 等）
- CBC 模式需要 IV
- 常见填充：PKCS7/ZeroPadding
- 渗透中常遇到硬编码密钥，优先从源码中提取

## 4. 非对称加密

### RSA

- 从公钥/私钥文件中提取参数
- 模数过小的 RSA 可分解
- 已知私钥可直接解密

## 5. 古典密码

| 类型 | 特征 | 破解方法 |
|------|------|---------|
| Caesar/ROT13 | 字母位移 | 暴力25种位移 |
| Vigenere | 多表替换 | Kasiski/频率分析 |
| 栅栏密码 | 字符分组重组 | 尝试常见栏数 |
| 培根密码 | AB 五元组 | 查表 |
| Morse | `.-` 点划 | 查表 |

## 6. JWT 处理

- 解码 Header + Payload（base64url）
- 检查算法：`none` 算法绕过、RS256→HS256 算法混淆
- 尝试弱密钥签名伪造
- 检查 exp/nbf 等时间声明

## 工具使用

### `crypto_decode` 工具

当遇到需要编码/解码/加密/解密的操作时，调用此工具：

```
crypto_decode(operation="base64_decode", input="TnNTY1RmLnBocA==")
```

支持的操作列表：
- **编码**: `base64_encode`, `base32_encode`, `hex_encode`, `url_encode`, `html_encode`, `unicode_encode`, `rot13_encode`, `morse_encode`, `caesar_encode`, `base58_encode`
- **解码**: `base64_decode`, `base32_decode`, `hex_decode`, `url_decode`, `html_decode`, `unicode_decode`, `rot13_decode`, `morse_decode`, `caesar_decode`, `base58_decode`
- **哈希**: `md5_hash`, `sha1_hash`, `sha256_hash`, `sha512_hash`
- **加密/解密**: `aes_encrypt`, `aes_decrypt`, `des_encrypt`, `des_decrypt`, `rsa_encrypt`, `rsa_decrypt`
- **JWT**: `jwt_decode`, `jwt_encode`
- **自动识别**: `auto_decode` (自动识别编码类型并解码)

## CTF 密码学攻击路由

> 当遇到密码学攻击场景（已知加密算法，需要恢复明文或密钥）时，优先使用 `ctf-crypto` Skill：

| 攻击场景 | 路由到 ctf-crypto | 参考文档 |
|---------|-----------------|---------|
| RSA 小指数/共模/Wiener | `ctf-crypto` | `references/rsa-attacks-cheatsheet.md` |
| AES Padding Oracle/ECB 翻转 | `ctf-crypto` | `references/aes-and-block-cipher-attacks.md` |
| ECC 小子群/离散对数 | `ctf-crypto` | `references/ecc-attacks-cheatsheet.md` |
| PRNG/MT19937 预测 | `ctf-crypto` | `references/prng-and-stream-cipher-attacks.md` |
| 古典密码（Vigenere/XOR） | `ctf-crypto` | `references/classic-cipher-attacks.md` |
| 格攻击/LWE | `ctf-crypto` | `references/lattice-and-lwe-attacks.md` |

**本 Skill 侧重编解码操作工具**，密码学具体攻击方法和参数请参考 `ctf-crypto`。

## 参考文档

- `references/encoding-cheatsheet.md` — 编码识别速查表
- `references/crypto-attacks.md` — 密码学攻击手法
- `references/crypto-attacks-roadmap.md` — 密码学攻击分类路由（根据题目特征选择攻击方法）

