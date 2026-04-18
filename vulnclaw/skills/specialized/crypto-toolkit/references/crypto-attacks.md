# 密码学攻击手法

## 1. 哈希攻击

### 彩虹表查询
- crackstation.net — 免费，支持 MD5/SHA1/SHA256
- cmd5.com — 中文，覆盖广泛
- hashes.org — 社区维护

### 哈希长度扩展攻击
- 适用：MD5, SHA1, SHA256 等基于 Merkle-Damgård 的哈希
- 条件：知道 `H(message)` 和 `len(message)`，不知道 message 本身
- 工具：hashpump, hash_extender
- 场景：API 签名验证绕过

### 哈希碰撞
- MD5：fastcoll, HashClash
- SHA1：SHAttered (理论可行)
- 场景：文件完整性绕过、证书伪造

## 2. 对称加密攻击

### ECB 模式攻击
- 相同明文块 → 相同密文块
- 可通过重排密文块重排明文
- 可识别重复模式（如用户角色字段）

### CBC 字节翻转攻击
- 修改 IV 或前一块密文即可翻转下一块明文的对应字节
- 公式：`P[i] = D(C[i]) XOR C[i-1]`
- 修改 `C[i-1][j]` → `P[i][j]` 翻转
- 场景：修改加密的用户ID、角色字段

### Padding Oracle 攻击
- 条件：服务端返回 padding 是否正确
- 逐字节恢复明文，无需密钥
- 工具：padbuster, padding-oracle-attacker
- 场景：ASP.NET、Java 序列化 token

### IV 重用攻击
- CBC 模式下相同 IV + 相同 Key → 信息泄露
- 可推断明文是否相同

## 3. RSA 攻击

### 小公钥指数攻击
- e=3 时，如果明文 m^3 < n，直接开立方根恢复
- 低加密指数广播攻击：同一明文用相同 e 不同 n 加密

### 共模攻击
- 同一明文用相同 n 不同 e 加密
- 通过扩展欧几里得算法恢复明文

### Wiener 攻击
- d < n^0.25 时可分解 n
- 适用于小私钥指数场景

### Fermat 分解
- p 和 q 相近时可快速分解 n
- 适用于弱密钥生成

### 已知密钥文件
- 从 .pem/.der 文件中提取参数
- openssl rsa -text -noout -in key.pem

## 4. 古典密码攻击

### Caesar 暴力
- 仅 25 种可能，直接遍历
- 配合词频分析选择最可能的结果

### Vigenere 分析
- Kasiski 测试确定密钥长度
- 重合指数法验证密钥长度
- 确定长度后每列做 Caesar 破解

### 栅栏密码
- 常见栏数：2-8
- 遍历所有可能的栏数
- 检查结果是否有意义

### 培根密码
- 两种字体/样式 → A/B 编码
- 每5个字符解码一个字母

## 5. JWT 攻击

### none 算法绕过
```json
{"alg": "none", "typ": "JWT"}
```
- 将算法改为 none
- 移除签名部分
- 某些实现会接受无签名的 token

### RS256 → HS256 算法混淆
- 将算法从 RS256 改为 HS256
- 用公钥作为 HMAC 密钥签名
- 如果服务端用公钥验证 HS256 签名 → 绕过

### 弱密钥爆破
- jwt-tool, jwt-cracker
- 常见弱密钥：secret, password, 123456 等

### JWK / jku 注入
- 在 Header 中嵌入公钥（jwk 字段）
- 或指向攻击者控制的 jku URL
- 如果服务端信任 Header 中的密钥 → 伪造

## 6. 编码链攻击模式

### WAF 绕过编码
- 双重 URL 编码：`%2527` → `%27` → `'`
- Unicode 标准化：`％27` → `'`（全角变半角）
- HTML 实体：`&#39;` → `'`
- Base64 编码注入参数

### 反序列化中的编码
- PHP: base64 编码的序列化对象
- Java: Base64 编码的序列化字节流
- Python: base64 pickle payloads

## 7. 工具速查

| 场景 | 工具 |
|------|------|
| 通用编解码 | CyberChef |
| 哈希破解 | hashcat, john |
| RSA 分析 | RsaCtfTool |
| JWT 分析 | jwt-tool |
| Padding Oracle | padbuster |
| 哈希扩展 | hashpump |
| 在线解码 | base64decode.org, cyberchef.org |
