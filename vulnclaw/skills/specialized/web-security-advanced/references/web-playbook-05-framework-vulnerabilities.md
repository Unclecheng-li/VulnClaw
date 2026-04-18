# 框架漏洞
English: Framework Vulnerabilities
- Entry Count: 18
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## Log4j RCE (Log4Shell)
- ID: log4j-rce
- Difficulty: intermediate
- Subcategory: Log4j
- Tags: log4j, rce, cve-2021-44228, log4shell
- Original Extracted Source: original extracted web-security-wiki source/log4j-rce.md
Description:
Apache Log4j远程代码执行漏洞
Prerequisites:
- 使用Log4j 2.x版本
- 用户输入被记录到日志
Execution Outline:
1. 1. 探测漏洞
2. 2. DNS外带测试
3. 3. 构造恶意LDAP服务器
4. 4. 获取Shell
## Spring Actuator漏洞
- ID: spring-actuator
- Difficulty: intermediate
- Subcategory: Spring
- Tags: spring, actuator, rce, java
- Original Extracted Source: original extracted web-security-wiki source/spring-actuator.md
Description:
Spring Boot Actuator端点安全漏洞
Prerequisites:
- Spring Boot应用
- Actuator端点暴露
Execution Outline:
1. 1. 探测Actuator端点
2. 2. 获取敏感信息
3. 3. 下载堆转储
4. 4. env端点RCE
## Fastjson RCE
- ID: fastjson-rce
- Difficulty: advanced
- Subcategory: Fastjson
- Tags: fastjson, rce, deserialization, java
- Original Extracted Source: original extracted web-security-wiki source/fastjson-rce.md
Description:
Alibaba Fastjson反序列化远程代码执行
Prerequisites:
- 使用Fastjson库
- 存在反序列化点
Execution Outline:
1. 1. 探测Fastjson
2. 2. JNDI注入
3. 3. 搭建恶意服务
4. 4. 绕过AutoType检查
## Spring SpEL注入
- ID: spring-spel
- Difficulty: intermediate
- Subcategory: Spring SpEL
- Tags: spring, spel, expression, rce
- Original Extracted Source: original extracted web-security-wiki source/spring-spel.md
Description:
Spring表达式语言注入攻击
Prerequisites:
- 使用Spring框架
- 存在SpEL注入点
Execution Outline:
1. 1. 探测SpEL注入
2. 2. 命令执行
3. 3. 文件读取
4. 4. DNS外带
## Spring Cloud漏洞
- ID: spring-cloud
- Difficulty: advanced
- Subcategory: Spring Cloud
- Tags: spring, cloud, rce, deserialization
- Original Extracted Source: original extracted web-security-wiki source/spring-cloud.md
Description:
Spring Cloud相关漏洞利用
Prerequisites:
- 使用Spring Cloud
- 存在漏洞版本
Execution Outline:
1. 1. Spring Cloud Gateway RCE
2. 2. Spring Cloud Function SpEL
3. 3. Spring Cloud Netflix
## Struts2远程代码执行
- ID: struts2-rce
- Difficulty: intermediate
- Subcategory: Struts2
- Tags: struts2, rce, java, apache
- Original Extracted Source: original extracted web-security-wiki source/struts2-rce.md
Description:
Apache Struts2框架RCE漏洞
Prerequisites:
- 使用Struts2框架
- 存在漏洞版本
Execution Outline:
1. 1. S2-045漏洞
2. 2. S2-046漏洞
3. 3. S2-057漏洞
4. 4. S2-061/S2-062漏洞
## Struts2 OGNL表达式注入
- ID: struts2-ognl
- Difficulty: advanced
- Subcategory: Struts2 OGNL
- Tags: struts2, ognl, expression, injection
- Original Extracted Source: original extracted web-security-wiki source/struts2-ognl.md
Description:
Struts2 OGNL表达式注入技术详解
Prerequisites:
- 使用Struts2框架
- 存在OGNL注入点
Execution Outline:
1. 1. OGNL基础语法
2. 2. 绕过安全限制
3. 3. 命令执行技巧
4. 4. 文件操作
## WebLogic远程代码执行
- ID: weblogic-rce
- Difficulty: advanced
- Subcategory: WebLogic
- Tags: weblogic, rce, java, oracle
- Original Extracted Source: original extracted web-security-wiki source/weblogic-rce.md
Description:
Oracle WebLogic Server RCE漏洞
Prerequisites:
- 使用WebLogic Server
- 存在漏洞版本
Execution Outline:
1. 1. CVE-2017-10271
2. 2. CVE-2019-2725
3. 3. CVE-2020-14882
## WebLogic T3协议攻击
- ID: weblogic-t3
- Difficulty: advanced
- Subcategory: WebLogic T3
- Tags: weblogic, t3, deserialization, java
- Original Extracted Source: original extracted web-security-wiki source/weblogic-t3.md
Description:
WebLogic T3协议反序列化漏洞
Prerequisites:
- WebLogic开放T3端口
- 存在漏洞版本
Execution Outline:
1. 1. 探测T3服务
2. 2. 使用工具攻击
3. 3. 构造恶意T3请求
## WebLogic IIOP协议攻击
- ID: weblogic-iiop
- Difficulty: advanced
- Subcategory: WebLogic IIOP
- Tags: weblogic, iiop, deserialization, corba
- Original Extracted Source: original extracted web-security-wiki source/weblogic-iiop.md
Description:
WebLogic IIOP协议反序列化漏洞
Prerequisites:
- WebLogic开放IIOP端口
- 存在漏洞版本
Execution Outline:
1. 1. 探测IIOP服务
2. 2. CVE-2020-2551
3. 3. 构造IIOP请求
## ThinkPHP远程代码执行
- ID: thinkphp-rce
- Difficulty: intermediate
- Subcategory: ThinkPHP
- Tags: thinkphp, rce, php, framework
- Original Extracted Source: original extracted web-security-wiki source/thinkphp-rce.md
Description:
ThinkPHP框架RCE漏洞
Prerequisites:
- 使用ThinkPHP框架
- 存在漏洞版本
Execution Outline:
1. 1. ThinkPHP 5.x RCE
2. 2. ThinkPHP 5.1.x RCE
3. 3. ThinkPHP 5.0.23 RCE
4. 4. 信息收集
## Laravel远程代码执行
- ID: laravel-rce
- Difficulty: intermediate
- Subcategory: Laravel
- Tags: laravel, rce, php, framework
- Original Extracted Source: original extracted web-security-wiki source/laravel-rce.md
Description:
Laravel框架RCE漏洞
Prerequisites:
- 使用Laravel框架
- 存在漏洞版本或配置
Execution Outline:
1. 1. CVE-2021-3129
2. 2. 调试模式信息泄露
3. 3. .env文件泄露
4. 4. APP_KEY利用
## Apache Shiro反序列化
- ID: shiro-deserialize
- Difficulty: intermediate
- Subcategory: Apache Shiro
- Tags: shiro, deserialization, java, rememberme
- Original Extracted Source: original extracted web-security-wiki source/shiro-deserialize.md
Description:
Apache Shiro RememberMe反序列化漏洞
Prerequisites:
- 使用Apache Shiro
- 存在漏洞版本
Execution Outline:
1. 1. 检测Shiro
2. 2. 使用ysoserial生成payload
3. 3. 发送恶意请求
4. 4. 常见密钥列表
## JBoss漏洞利用
- ID: jboss-vuln
- Difficulty: intermediate
- Subcategory: JBoss
- Tags: jboss, rce, java, deserialization
- Original Extracted Source: original extracted web-security-wiki source/jboss-vuln.md
Description:
JBoss应用服务器漏洞
Prerequisites:
- 使用JBoss服务器
- 存在漏洞版本
Execution Outline:
1. 1. JMXInvokerServlet反序列化
2. 2. JMX Console部署War包
3. 3. BSHDeployer部署
4. 4. 使用工具
## Apache Tomcat漏洞
- ID: tomcat-vuln
- Difficulty: intermediate
- Subcategory: Tomcat
- Tags: tomcat, rce, java, manager
- Original Extracted Source: original extracted web-security-wiki source/tomcat-vuln.md
Description:
Apache Tomcat服务器漏洞利用
Prerequisites:
- 使用Tomcat服务器
- 存在漏洞版本或配置
Execution Outline:
1. 1. Manager App弱口令
2. 2. 部署War包
3. 3. CVE-2020-1938 Ghostcat
4. 4. PUT方法任意文件写入
## Django框架漏洞
- ID: django-vuln
- Difficulty: intermediate
- Subcategory: Django
- Tags: django, python, framework, sql
- Original Extracted Source: original extracted web-security-wiki source/django-vuln.md
Description:
Django框架安全漏洞
Prerequisites:
- 使用Django框架
- 存在漏洞版本
Execution Outline:
1. 1. SQL注入
2. 2. 调试模式信息泄露
3. 3. SECRET_KEY利用
4. 4. 路径遍历
## Flask框架漏洞
- ID: flask-vuln
- Difficulty: intermediate
- Subcategory: Flask
- Tags: flask, python, framework, ssti
- Original Extracted Source: original extracted web-security-wiki source/flask-vuln.md
Description:
Flask框架安全漏洞
Prerequisites:
- 使用Flask框架
- 存在漏洞配置
Execution Outline:
1. 1. SSTI模板注入
2. 2. SECRET_KEY利用
3. 3. 调试模式RCE
4. 4. PIN码绕过
## WebLogic XMLDecoder
- ID: weblogic-xmldecoder
- Difficulty: intermediate
- Subcategory: WebLogic
- Tags: weblogic, xmldecoder, rce
- Original Extracted Source: original extracted web-security-wiki source/weblogic-xmldecoder.md
Description:
利用WebLogic Server中XMLDecoder反序列化漏洞(CVE-2017-10271/CVE-2017-3506)实现远程代码执行
Prerequisites:
- 目标运行WebLogic Server
- 存在/wls-wsat/或/_async/路径
- XMLDecoder组件未被禁用
- WebLogic版本存在漏洞(10.3.6.0/12.1.3.0等)
Execution Outline:
1. 探测WebLogic版本和路径
2. CVE-2017-10271 XMLDecoder RCE
3. CVE-2019-2725 反序列化RCE
4. 写入Webshell获取持久权限

