# 编码识别速查表

## 快速识别流程

```
输入字符串
  ├─ 包含 %XX → URL 编码 → url_decode
  ├─ 包含 &# 或 &#x → HTML 实体 → html_decode
  ├─ 包含 \uXXXX → Unicode 转义 → unicode_decode
  ├─ 包含 .- 且只有点划空格 → Morse → morse_decode
  ├─ 三段 base64 用 . 连接 → JWT → jwt_decode
  ├─ 末尾有 = 填充 + A-Za-z0-9+/ → Base64 → base64_decode
  ├─ 末尾有 = 填充 + A-Z2-7 → Base32 → base32_decode
  ├─ 纯 hex 字符(0-9a-f) 偶数长度 → Hex → hex_decode
  ├─ 纯大写字母 + 数字，无填充 → 可能 Base58 → base58_decode
  ├─ 字母位移特征(如 E→M, A→I) → Caesar → caesar_decode
  └─ 无法确定 → auto_decode
```

## Base64 变体

| 变体 | 字符集 | 用途 |
|------|--------|------|
| 标准 Base64 | `A-Za-z0-9+/=` | 通用 |
| URL-safe Base64 | `A-Za-z0-9-_` | URL 参数 |
| Base64url (JWT) | `A-Za-z0-9_-` 无填充 | JWT |

## Base58

| 变体 | 排除字符 | 用途 |
|------|---------|------|
| Bitcoin | `0OIl` | 地址编码 |
| Flickr | `0OIl` | 短URL |
| Ripple | `0OIl` | 地址编码 |

## 常见混淆模式

### 双重编码
```
原始: admin
→ URL编码: %61%64%6D%69%6E
→ 双重URL编码: %2561%2564%256D%2569%256E
```

### Base64 + Hex 链
```
原始: NsScTf.php
→ Hex: 4e73536354662e706870
→ Base64: TnNTY1RmLnBocA==
```

### ROT13 嵌套
```
原始: password
→ ROT13: cnffjbeq
→ ROT13 again: password (ROT13 自逆)
```

## 长度与编码对照

| 原文长度 | Base64 长度 | Hex 长度 | Base32 长度 |
|---------|------------|---------|------------|
| 1 byte | 4 chars | 2 chars | 8 chars |
| 4 bytes | 8 chars | 8 chars | 8 chars |
| 8 bytes | 12 chars | 16 chars | 16 chars |
| 16 bytes | 24 chars | 32 chars | 28 chars |

## CTF 常见编码链

1. **Base64 → 明文** — 最常见
2. **Base64 → Hex → 明文** — 双重编码
3. **Base64 → Base64 → 明文** — 嵌套 Base64
4. **Hex → Base64 → ROT13 → 明文** — 三层编码
5. **URL编码 → Base64 → 明文** — Web 场景常见
6. **Morse → Base64 → Hex → 明文** — Crypto 题目

## 解码后验证

解码后检查结果是否：
- [ ] 可读 ASCII/UTF-8 文本
- [ ] 看起来像路径（/xxx/yyy.php）
- [ ] 看起来像 URL（http://...）
- [ ] 包含 flag 格式（flag{...}, NSSCTF{...}）
- [ ] 仍然是编码（需要继续解码）
