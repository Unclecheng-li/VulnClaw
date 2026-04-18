# 缓存与CDN安全
English: Cache & CDN Security
- Entry Count: 3
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## 缓存投毒
- ID: cache-poisoning
- Difficulty: advanced
- Subcategory: 缓存投毒
- Tags: cache, poisoning, web-cache
- Original Extracted Source: original extracted web-security-wiki source/cache-poisoning.md
Description:
Web缓存投毒攻击
Prerequisites:
- 目标使用缓存
- 缓存键配置不当
Execution Outline:
1. 探测缓存
2. 未键入头
3. 缓存投毒
4. Fat GET
## 缓存欺骗
- ID: cache-deception
- Difficulty: intermediate
- Subcategory: Deception
- Tags: cache, deception, auth
- Original Extracted Source: original extracted web-security-wiki source/cache-deception.md
Description:
利用Web缓存和服务器路径解析的差异，诱导CDN/缓存层缓存包含敏感信息的动态页面
Prerequisites:
- 目标使用CDN或反向代理缓存
- 路径解析存在差异(后端忽略路径后缀)
- 缓存策略基于URL扩展名
Execution Outline:
1. 探测缓存行为
2. 路径混淆缓存欺骗
3. 高级缓存欺骗变体
4. 完整攻击流程验证
## CDN绕过
- ID: cdn-bypass
- Difficulty: intermediate
- Subcategory: CDN
- Tags: cdn, bypass, recon
- Original Extracted Source: original extracted web-security-wiki source/cdn-bypass.md
Description:
绕过CDN查找真实IP
Prerequisites:
- 目标使用CDN
Execution Outline:
1. 历史DNS
2. 邮件头
3. DNS历史与证书透明度查询
4. 子域名与相关服务探测真实IP

