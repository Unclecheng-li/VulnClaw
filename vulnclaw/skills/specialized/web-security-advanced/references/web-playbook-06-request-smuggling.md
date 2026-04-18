# 请求走私
English: Request Smuggling
- Entry Count: 4
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## CL-TE请求走私
- ID: smuggling-cl-te
- Difficulty: advanced
- Subcategory: CL-TE
- Tags: smuggling, request, http
- Original Extracted Source: original extracted web-security-wiki source/smuggling-cl-te.md
Description:
Content-Length与Transfer-Encoding走私
Prerequisites:
- 目标使用多层代理
- 前后端处理差异
Execution Outline:
1. CL-TE基础
2. TE-CL基础
3. TE-TE
## CL-CL走私
- ID: smuggling-cl-cl
- Difficulty: advanced
- Subcategory: CL-CL
- Tags: smuggling, cl-cl, http
- Original Extracted Source: original extracted web-security-wiki source/smuggling-cl-cl.md
Description:
利用前端代理和后端服务器同时处理Content-Length头但对多个CL头的处理差异实现HTTP请求走私
Prerequisites:
- 存在前端代理(如HAProxy/Nginx)+后端服务器架构
- 两端对Content-Length头的解析存在差异
- 理解HTTP请求走私原理
Execution Outline:
1. 检测CL-CL走私条件
2. CL-CL请求走私POC
3. 利用CL-CL走私绕过前端访问控制
## TE-CL走私
- ID: smuggling-te-cl
- Difficulty: expert
- Subcategory: TE-CL
- Tags: smuggling, te-cl, http
- Original Extracted Source: original extracted web-security-wiki source/smuggling-te-cl.md
Description:
利用前端使用Transfer-Encoding而后端使用Content-Length的差异实现HTTP请求走私
Prerequisites:
- 前端代理优先处理Transfer-Encoding
- 后端服务器优先处理Content-Length
- 理解chunked编码格式
Execution Outline:
1. 检测TE-CL差异
2. TE-CL走私POC
3. TE-CL走私实现请求劫持
## TE-TE走私
- ID: smuggling-te-te
- Difficulty: expert
- Subcategory: TE-TE
- Tags: smuggling, te-te, http
- Original Extracted Source: original extracted web-security-wiki source/smuggling-te-te.md
Description:
利用前端和后端对Transfer-Encoding头的不同混淆变体的处理差异实现请求走私
Prerequisites:
- 前后端都支持Transfer-Encoding
- 可以通过TE头混淆使一端忽略TE
- 了解chunked编码和HTTP走私原理
Execution Outline:
1. TE混淆变体探测
2. TE-TE走私利用(前端忽略混淆TE)
3. TE-TE缓存投毒攻击

