# SQL/NoSQL注入
English: SQL/NoSQL Injection
- Entry Count: 17
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## MySQL注入 - 基础探测
- ID: sqli-mysql-basic
- Difficulty: beginner
- Subcategory: MySQL
- Tags: sqli, mysql, injection, database
- Original Extracted Source: original extracted web-security-wiki source/sqli-mysql-basic.md
Description:
MySQL数据库注入基础探测与数据提取技术
Prerequisites:
- 目标存在SQL注入点
- 后端数据库为MySQL
- 了解基本SQL语法
Execution Outline:
1. 1. 探测注入点
2. 2. 确定列数
3. 3. 确定显示位置
4. 4. 获取数据库信息
## MySQL注入 - 高级技术
- ID: sqli-mysql-advanced
- Difficulty: advanced
- Subcategory: MySQL
- Tags: sqli, mysql, advanced, file-read, rce
- Original Extracted Source: original extracted web-security-wiki source/sqli-mysql-advanced.md
Description:
MySQL高级注入技术：文件读写、UDF提权、命令执行
Prerequisites:
- MySQL用户具有FILE权限
- 知道网站绝对路径
- secure_file_priv配置允许
Execution Outline:
1. 1. 检测FILE权限
2. 2. 获取网站路径
3. 3. 读取敏感文件
4. 4. 写入WebShell
## MSSQL注入 - 基础探测
- ID: sqli-mssql-basic
- Difficulty: intermediate
- Subcategory: MSSQL
- Tags: sqli, mssql, sqlserver, injection
- Original Extracted Source: original extracted web-security-wiki source/sqli-mssql-basic.md
Description:
Microsoft SQL Server数据库注入技术
Prerequisites:
- 目标存在SQL注入点
- 后端使用MSSQL数据库
Execution Outline:
1. 1. 探测注入点
2. 2. 获取版本信息
3. 3. 获取用户信息
4. 4. 获取数据库信息
## MSSQL注入 - 高级技术
- ID: sqli-mssql-advanced
- Difficulty: advanced
- Subcategory: MSSQL
- Tags: sqli, mssql, xp_cmdshell, rce
- Original Extracted Source: original extracted web-security-wiki source/sqli-mssql-advanced.md
Description:
MSSQL高级注入：xp_cmdshell、SP_OACREATE命令执行
Prerequisites:
- MSSQL具有高权限
- xp_cmdshell可用或可开启
Execution Outline:
1. 1. 检测xp_cmdshell状态
2. 2. 开启xp_cmdshell
3. 3. 执行系统命令
4. 4. 写入WebShell
## Oracle注入 - 基础探测
- ID: sqli-oracle-basic
- Difficulty: intermediate
- Subcategory: Oracle
- Tags: sqli, oracle, injection
- Original Extracted Source: original extracted web-security-wiki source/sqli-oracle-basic.md
Description:
Oracle数据库注入基础技术
Prerequisites:
- 目标存在SQL注入点
- 后端使用Oracle数据库
Execution Outline:
1. 1. 探测注入点
2. 2. 获取版本信息
3. 3. 获取用户信息
4. 4. 获取表名
## Oracle注入 - 高级技术
- ID: sqli-oracle-advanced
- Difficulty: advanced
- Subcategory: Oracle
- Tags: sqli, oracle, advanced, rce
- Original Extracted Source: original extracted web-security-wiki source/sqli-oracle-advanced.md
Description:
Oracle高级注入技术：Java存储过程、UTL_FILE文件操作
Prerequisites:
- Oracle高权限
- Java虚拟机可用
Execution Outline:
1. 1. 检测Java权限
2. 2. 创建Java执行函数
3. 3. UTL_FILE读取文件
## PostgreSQL注入 - 基础探测
- ID: sqli-postgres-basic
- Difficulty: intermediate
- Subcategory: PostgreSQL
- Tags: sqli, postgresql, postgres, injection
- Original Extracted Source: original extracted web-security-wiki source/sqli-postgres-basic.md
Description:
PostgreSQL数据库注入技术
Prerequisites:
- 目标存在SQL注入点
- 后端使用PostgreSQL
Execution Outline:
1. 1. 探测注入点
2. 2. 获取版本信息
3. 3. 获取表名
4. 4. 获取列名
## SQLite注入
- ID: sqli-sqlite-basic
- Difficulty: intermediate
- Subcategory: SQLite
- Tags: sqli, sqlite
- Original Extracted Source: original extracted web-security-wiki source/sqli-sqlite-basic.md
Description:
SQLite数据库注入攻击
Prerequisites:
- SQLite数据库
- 存在注入点
Execution Outline:
1. 1. 探测注入点
2. 2. 获取版本
3. 3. 获取表名
4. 4. 获取表结构
## MongoDB注入
- ID: sqli-mongodb-basic
- Difficulty: intermediate
- Subcategory: MongoDB
- Tags: nosql, mongodb, injection
- Original Extracted Source: original extracted web-security-wiki source/sqli-mongodb-basic.md
Description:
NoSQL数据库注入攻击技术
Prerequisites:
- 目标使用MongoDB
- 存在用户输入拼接查询
Execution Outline:
1. 1. 探测注入点
2. 2. 绕过认证
3. 3. 逻辑运算注入
4. 4. 正则注入
## Redis未授权访问
- ID: sqli-redis
- Difficulty: intermediate
- Subcategory: Redis
- Tags: redis, nosql, injection
- Original Extracted Source: original extracted web-security-wiki source/sqli-redis.md
Description:
Redis未授权访问和命令注入
Prerequisites:
- Redis服务可访问
- 未授权或弱密码
Execution Outline:
1. 1. 探测Redis
2. 2. 未授权访问
3. 3. 写入Webshell
4. 4. 写入SSH公钥
## 布尔盲注
- ID: sqli-blind
- Difficulty: intermediate
- Subcategory: 盲注
- Tags: sqli, blind, boolean
- Original Extracted Source: original extracted web-security-wiki source/sqli-blind.md
Description:
基于布尔条件的SQL盲注技术
Prerequisites:
- 存在SQL注入
- 页面有真/假两种不同响应
Execution Outline:
1. 1. 确认盲注
2. 2. 获取数据库名长度
3. 3. 逐字符枚举数据库名
4. 4. 使用工具自动化
## 时间盲注
- ID: sqli-time-based
- Difficulty: intermediate
- Subcategory: 盲注
- Tags: sqli, blind, time
- Original Extracted Source: original extracted web-security-wiki source/sqli-time-based.md
Description:
基于时间延迟的SQL盲注技术
Prerequisites:
- 存在SQL注入
- 页面响应时间可控
Execution Outline:
1. 1. 确认时间盲注
2. 2. 获取数据库名长度
3. 3. 逐字符提取
4. 4. 不同数据库延时函数
## 报错注入
- ID: sqli-error-based
- Difficulty: intermediate
- Subcategory: 报错注入
- Tags: sqli, error, extractvalue
- Original Extracted Source: original extracted web-security-wiki source/sqli-error-based.md
Description:
利用错误信息提取数据的SQL注入
Prerequisites:
- 存在SQL注入
- 错误信息会显示在页面上
Execution Outline:
1. 1. 确认报错注入
2. 2. 获取数据库信息
3. 3. 获取表名
4. 4. 获取数据
## 二阶SQL注入
- ID: sqli-second-order
- Difficulty: advanced
- Subcategory: 二阶注入
- Tags: sqli, second-order, stored
- Original Extracted Source: original extracted web-security-wiki source/sqli-second-order.md
Description:
存储后触发的SQL注入攻击
Prerequisites:
- 存在数据存储功能
- 存储数据被二次使用
Execution Outline:
1. 1. 探测二阶注入
2. 2. 用户名注入
3. 3. 密码重置注入
4. 4. 订单/评论注入
## 联合查询注入
- ID: sqli-union
- Difficulty: beginner
- Subcategory: 联合查询
- Tags: sqli, union, select
- Original Extracted Source: original extracted web-security-wiki source/sqli-union.md
Description:
使用UNION SELECT提取数据
Prerequisites:
- 存在注入点
- 可显示查询结果
Execution Outline:
1. 1. 确定列数
2. 2. 确定显示列
3. 3. 提取数据
4. 4. 绕过过滤
## 堆叠查询注入
- ID: sqli-stacked
- Difficulty: intermediate
- Subcategory: 堆叠查询
- Tags: sqli, stacked, queries
- Original Extracted Source: original extracted web-security-wiki source/sqli-stacked.md
Description:
执行多条SQL语句的注入
Prerequisites:
- 支持多语句执行
- MySQL/PostgreSQL/MSSQL
Execution Outline:
1. 1. 探测堆叠查询
2. 2. MySQL堆叠查询
3. 3. MSSQL堆叠查询
4. 4. PostgreSQL堆叠查询
## SQL注入WAF绕过
- ID: sqli-waf-bypass
- Difficulty: advanced
- Subcategory: WAF绕过
- Tags: sqli, waf, bypass
- Original Extracted Source: original extracted web-security-wiki source/sqli-waf-bypass.md
Description:
绕过Web应用防火墙的技术
Prerequisites:
- 目标存在SQL注入点
- 存在WAF防护
Execution Outline:
1. 分块传输编码
2. HTTP参数污染(HPP)
3. 等价函数替换
4. 无逗号注入

