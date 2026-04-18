# 业务逻辑漏洞
English: Business Logic Vulnerabilities
- Entry Count: 5
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## IDOR越权访问
- ID: biz-idor
- Difficulty: beginner
- Subcategory: 越权漏洞
- Tags: IDOR, 越权, 业务逻辑, OWASP, A01
- Original Extracted Source: original extracted web-security-wiki source/biz-idor.md
Description:
不安全的直接对象引用(IDOR)，通过篡改请求参数中的对象ID越权访问他人数据。攻击者可遍历用户ID、订单号等参数获取未授权资源。
Prerequisites:
- 目标存在基于ID的资源访问接口
- 已登录普通用户账号
Execution Outline:
1. 1. 识别可遍历参数
2. 2. 水平越权测试
3. 3. 垂直越权测试
4. 4. 参数污染越权
## 竞态条件攻击
- ID: biz-race-condition
- Difficulty: intermediate
- Subcategory: 竞态条件
- Tags: 竞态条件, Race Condition, TOCTOU, 并发, 业务逻辑
- Original Extracted Source: original extracted web-security-wiki source/biz-race-condition.md
Description:
利用服务端TOCTOU(Time-of-Check to Time-of-Use)漏洞，通过并发请求在检查与执行之间的时间窗口内多次触发同一操作，实现重复领券、重复提现、超额购买等业务逻辑突破。
Prerequisites:
- 目标存在余额/积分/优惠券等可量化资源操作
- Python/Turbo Intruder环境
Execution Outline:
1. 1. 识别竞态目标
2. 2. Python并发测试脚本
3. 3. Burp Turbo Intruder测试
4. 4. 验证竞态成功
## 支付逻辑篡改
- ID: biz-payment-tamper
- Difficulty: intermediate
- Subcategory: 支付安全
- Tags: 支付, 金额篡改, 业务逻辑, 0元购, 电商安全
- Original Extracted Source: original extracted web-security-wiki source/biz-payment-tamper.md
Description:
通过修改支付请求中的金额、数量、折扣等参数来操纵交易逻辑。常见于电商平台和在线支付系统中，可导致0元购、负价格、折扣叠加等严重业务风险。
Prerequisites:
- 目标存在支付/下单功能
- 可拦截和修改HTTP请求
Execution Outline:
1. 1. 金额篡改测试
2. 2. 数量与运费篡改
3. 3. 优惠券叠加与替换
4. 4. 支付回调篡改
## 密码重置逻辑缺陷
- ID: biz-password-reset
- Difficulty: intermediate
- Subcategory: 认证缺陷
- Tags: 密码重置, 认证绕过, 业务逻辑, 验证码, Host注入
- Original Extracted Source: original extracted web-security-wiki source/biz-password-reset.md
Description:
密码重置流程中的逻辑漏洞，包括重置令牌泄露、验证码爆破、响应操纵、Host头注入等攻击手法，可实现任意用户密码重置。
Prerequisites:
- 目标存在密码重置/找回功能
- 可拦截HTTP请求
Execution Outline:
1. 1. Host头注入窃取重置链接
2. 2. 验证码爆破
3. 3. 响应操纵绕过
4. 4. 重置令牌弱随机性
## 验证码绕过技术
- ID: biz-captcha-bypass
- Difficulty: beginner
- Subcategory: 验证码安全
- Tags: 验证码, CAPTCHA, 绕过, 短信验证码, 人机验证
- Original Extracted Source: original extracted web-security-wiki source/biz-captcha-bypass.md
Description:
绕过图形验证码、短信验证码、滑动验证等人机验证机制的各种技术手法，包括响应泄露、复用攻击、OCR识别、逻辑缺陷利用等。
Prerequisites:
- 目标存在验证码保护的功能
- Python环境
Execution Outline:
1. 1. 验证码响应泄露
2. 2. 验证码复用攻击
3. 3. 删除验证码参数
4. 4. 万能验证码

