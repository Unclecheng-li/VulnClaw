# API安全
English: API Security
- Entry Count: 12
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## JWT安全漏洞
- ID: jwt-security
- Difficulty: intermediate
- Subcategory: JWT
- Tags: jwt, token, authentication
- Original Extracted Source: original extracted web-security-wiki source/jwt-security.md
Description:
JSON Web Token安全漏洞利用
Prerequisites:
- 使用JWT进行认证
- JWT配置或验证存在问题
Execution Outline:
1. 1. 解码JWT
2. 2. None算法攻击
3. 3. 弱密钥破解
4. 4. 密钥混淆攻击
## GraphQL注入攻击
- ID: graphql-injection
- Difficulty: intermediate
- Subcategory: GraphQL
- Tags: graphql, api, injection, introspection
- Original Extracted Source: original extracted web-security-wiki source/graphql-injection.md
Description:
GraphQL API注入与信息泄露攻击
Prerequisites:
- 目标使用GraphQL API
- 存在未授权访问或注入点
Execution Outline:
1. 1. 探测GraphQL端点
2. 2. 内省查询
3. 3. 批量查询攻击
4. 4. SQL注入
## GraphQL内省攻击
- ID: graphql-introspection
- Difficulty: beginner
- Subcategory: GraphQL内省
- Tags: graphql, introspection, enumeration, api
- Original Extracted Source: original extracted web-security-wiki source/graphql-introspection.md
Description:
利用GraphQL内省功能获取API结构
Prerequisites:
- 目标使用GraphQL
- 内省功能未禁用
Execution Outline:
1. 1. 基础内省
2. 2. 完整内省
3. 3. 使用工具分析
## GraphQL批量查询攻击
- ID: graphql-batching
- Difficulty: intermediate
- Subcategory: GraphQL批量查询
- Tags: graphql, batching, rate-limit, bypass
- Original Extracted Source: original extracted web-security-wiki source/graphql-batching.md
Description:
利用GraphQL批量查询绕过速率限制
Prerequisites:
- 目标使用GraphQL
- 存在速率限制
Execution Outline:
1. 1. 别名批量查询
2. 2. 数组批量查询
3. 3. 暴力破解
## REST API安全测试
- ID: rest-api-security
- Difficulty: intermediate
- Subcategory: REST API
- Tags: rest, api, security, testing
- Original Extracted Source: original extracted web-security-wiki source/rest-api-security.md
Description:
REST API安全测试与漏洞利用
Prerequisites:
- 目标使用REST API
- 了解API端点
Execution Outline:
1. 1. API端点发现
2. 2. 认证测试
3. 3. HTTP方法测试
4. 4. 参数污染
## JWT None算法攻击
- ID: jwt-none-alg
- Difficulty: beginner
- Subcategory: JWT安全
- Tags: jwt, none, algorithm, bypass
- Original Extracted Source: original extracted web-security-wiki source/jwt-none-alg.md
Description:
利用JWT None算法绕过签名验证
Prerequisites:
- 目标使用JWT认证
- 服务器未正确验证算法
Execution Outline:
1. 1. 解码JWT
2. 2. 构造None算法Token
3. 3. 修改用户权限
4. 4. 发送恶意Token
## JWT密钥混淆攻击
- ID: jwt-key-confusion
- Difficulty: intermediate
- Subcategory: JWT安全
- Tags: jwt, algorithm, confusion, rs256
- Original Extracted Source: original extracted web-security-wiki source/jwt-key-confusion.md
Description:
利用JWT算法混淆实现签名绕过
Prerequisites:
- 目标使用RS256算法
- 可获取公钥
Execution Outline:
1. 1. 获取公钥
2. 2. 算法混淆攻击
3. 3. 发送恶意Token
## IDOR不安全的直接对象引用
- ID: api-idor
- Difficulty: beginner
- Subcategory: IDOR
- Tags: idor, api, authorization, bypass
- Original Extracted Source: original extracted web-security-wiki source/api-idor.md
Description:
利用IDOR漏洞访问未授权资源
Prerequisites:
- 目标使用ID引用资源
- 存在授权检查缺陷
Execution Outline:
1. 1. 识别ID参数
2. 2. 枚举ID
3. 3. 批量检测
4. 4. 跨用户访问
## API速率限制绕过
- ID: api-rate-limit
- Difficulty: intermediate
- Subcategory: 速率限制
- Tags: api, rate-limit, bypass, brute-force
- Original Extracted Source: original extracted web-security-wiki source/api-rate-limit.md
Description:
绕过API速率限制进行暴力攻击
Prerequisites:
- 目标有速率限制
- 限制实现有缺陷
Execution Outline:
1. 1. 检测速率限制
2. 2. IP绕过
3. 3. 分布式绕过
4. 4. 其他绕过技术
## 批量赋值漏洞
- ID: api-mass-assignment
- Difficulty: beginner
- Subcategory: 批量赋值
- Tags: api, mass-assignment, privilege-escalation
- Original Extracted Source: original extracted web-security-wiki source/api-mass-assignment.md
Description:
利用批量赋值漏洞修改敏感字段
Prerequisites:
- API接受JSON输入
- 存在未过滤的字段
Execution Outline:
1. 1. 识别输入字段
2. 2. 添加敏感字段
3. 3. 更新操作
4. 4. 嵌套对象
## BOLA破坏对象级授权
- ID: api-bola
- Difficulty: intermediate
- Subcategory: BOLA
- Tags: api, bola, authorization, idor
- Original Extracted Source: original extracted web-security-wiki source/api-bola.md
Description:
利用BOLA漏洞访问未授权对象
Prerequisites:
- API使用对象ID
- 授权检查缺陷
Execution Outline:
1. 1. 识别对象访问
2. 2. 测试授权
3. 3. 横向访问
4. 4. 修改/删除操作
## API注入攻击
- ID: api-injection
- Difficulty: intermediate
- Subcategory: API注入
- Tags: api, injection, sqli, nosqli
- Original Extracted Source: original extracted web-security-wiki source/api-injection.md
Description:
API端点中的各类注入攻击
Prerequisites:
- API接受用户输入
- 输入未正确过滤
Execution Outline:
1. 1. SQL注入
2. 2. NoSQL注入
3. 3. LDAP注入
4. 4. 命令注入

