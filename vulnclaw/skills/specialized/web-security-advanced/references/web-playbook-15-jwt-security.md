# JWT安全
English: JWT Security
- Entry Count: 4
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## JWT None算法攻击
- ID: jwt-none-attack
- Difficulty: beginner
- Subcategory: 算法攻击
- Tags: JWT, none算法, 认证绕过, 令牌伪造, CVE-2015-2951
- Original Extracted Source: original extracted web-security-wiki source/jwt-none-attack.md
Description:
利用JWT库对"none"算法的支持缺陷，将JWT头部的签名算法修改为none后移除签名部分，构造无需密钥即可通过验证的伪造令牌。这是最经典的JWT漏洞之一。
Prerequisites:
- 目标使用JWT进行身份认证
- jwt_tool或Python PyJWT库
Execution Outline:
1. 1. 解码现有JWT
2. 2. 构造None算法JWT
3. 3. jwt_tool自动攻击
4. 4. 验证伪造令牌
## JWT密钥混淆攻击(RS→HS)
- ID: jwt-key-confusion
- Difficulty: advanced
- Subcategory: 算法攻击
- Tags: JWT, 密钥混淆, RS256, HS256, 算法篡改
- Original Extracted Source: original extracted web-security-wiki source/jwt-key-confusion.md
Description:
当服务端使用RSA公钥验证JWT时，攻击者将算法从RS256改为HS256，此时服务端会错误地使用RSA公钥作为HMAC密钥进行验证。由于RSA公钥是公开的，攻击者可用它签名任意JWT。
Prerequisites:
- 目标JWT使用RS256/RS384/RS512算法
- 已获取RSA公钥
- jwt_tool或Python
Execution Outline:
1. 1. 获取RSA公钥
2. 2. 密钥混淆攻击
3. 3. jwt_tool自动攻击
4. 4. JWKS端点注入
## JWT密钥爆破
- ID: jwt-secret-bruteforce
- Difficulty: intermediate
- Subcategory: 密钥破解
- Tags: JWT, 密钥爆破, HS256, 弱密钥, hashcat
- Original Extracted Source: original extracted web-security-wiki source/jwt-secret-bruteforce.md
Description:
当JWT使用HMAC对称算法(HS256/HS384/HS512)且密钥为弱密码时，可通过字典或暴力破解还原签名密钥，进而伪造任意JWT令牌。
Prerequisites:
- 目标JWT使用HMAC算法(HS256等)
- 已获取有效JWT样本
- hashcat或jwt_tool
Execution Outline:
1. 1. 确认算法和结构
2. 2. hashcat GPU加速爆破
3. 3. jwt_tool字典爆破
4. 4. 使用破解密钥伪造JWT
## JWT JKU/X5U头注入
- ID: jwt-jku-x5u-injection
- Difficulty: advanced
- Subcategory: Header注入
- Tags: JWT, JKU, X5U, Header注入, JWKS, 密钥劫持
- Original Extracted Source: original extracted web-security-wiki source/jwt-jku-x5u-injection.md
Description:
利用JWT Header中的jku(JWK Set URL)或x5u(X.509 URL)参数，将密钥来源指向攻击者控制的服务器，使服务端使用攻击者的公钥验证JWT，从而实现令牌伪造。
Prerequisites:
- 目标JWT支持jku/x5u Header参数
- 攻击者拥有公网服务器
- Python环境
Execution Outline:
1. 1. 探测JKU/X5U支持
2. 2. 生成攻击者密钥对
3. 3. 托管JWKS并签名JWT
4. 4. 验证攻击

