# MCP 能力总文档

## 1. 文档目的

本文档整理了当前会话里我可以直接调用的 MCP 能力，目标不是只做一份“工具清单”，而是提供一份适合后续编写 `skills` 的参考底稿。  
重点覆盖以下内容：

- 每个 MCP 服务器/命名空间的定位
- 每个方法的调用方式
- 主要参数的含义
- 返回结果大致会包含什么
- 典型使用场景
- 与其他 MCP 组合时的常见工作流

本文默认面向 Codex / Agent 类工具编排，不是通用 SDK 文档。因此会更强调“什么时候用它”“写 skill 时怎么描述调用策略”。

---

## 2. 通用调用约定

### 2.1 工具命名格式

当前环境里的 MCP 工具名大多遵循下面格式：

```text
mcp__<server_name>__<tool_name>
```

例如：

- `mcp__adb_mcp__list_devices`
- `mcp__chrome_devtools__navigate_page`
- `mcp__ida_pro_mcp__decompile`

少数与 MCP 资源访问相关的函数不带 `mcp__` 前缀，但本质上也是 MCP 生态能力：

- `list_mcp_resources`
- `list_mcp_resource_templates`
- `read_mcp_resource`

### 2.2 调用参数格式

所有 MCP 工具都使用 JSON 风格参数对象。典型格式：

```json
{
  "device_id": "emulator-5554",
  "lines": 200
}
```

注意点：

- 只传需要的字段，不要无意义地塞空数组或 `null`
- `optional` 参数一般可省略
- 某些工具要求绝对路径，尤其是截图、保存源码、拉取文件、录屏输出路径等
- 某些工具使用分页参数，如 `offset`、`count`、`pageIdx`、`pageSize`

### 2.3 写 skill 时建议描述的要点

如果你要把这些能力写成 skill，建议每个 skill 明确写出：

1. 触发条件  
2. 优先使用的 MCP  
3. 工具之间的先后顺序  
4. 哪些参数是必须补全的  
5. 什么情况下切换到其他 MCP  
6. 如果输出为空/失败，下一步应该怎么补救

### 2.4 MCP 选型速查

| 任务类型 | 优先 MCP |
| --- | --- |
| Android 设备管理、安装 APK、点击滑动、拉文件 | `adb_mcp` |
| Android 可视化控制、UI 树定位、无线 ADB、实时画面 | `scrcpy_vision` |
| Android 抓 HTTP/HTTPS 流量、Charles 会话分析 | `charles` |
| Burp 历史、Repeater、Collaborator、Intruder | `burp` |
| 网页自动化、截图、表单、网络请求、控制台 | `chrome_devtools` |
| JS 断点、源码搜索、XHR 发起链、函数追踪 | `js_reverse` |
| 官方文档检索、代码示例查询 | `context7` |
| 通用网页抓取/拉取网页内容 | `fetch` |
| 本地文件极速搜索 | `everything_search` |
| Android 动态注入、Frida attach/spawn | `frida_mcp` |
| 二进制静态分析、IDA 批量重命名/反编译/类型修复 | `ida_pro_mcp` |
| APK 反编译、Manifest、类/方法/xref 查询 | `jadx` |
| 记忆图谱、长期结构化记忆 | `memory` |
| 复杂问题分步思考 | `sequential_thinking` |

### 2.5 常见组合工作流

#### Android App 分析

- 静态：`jadx`
- 动态：`frida_mcp`
- 抓包：`charles`
- 设备控制：`adb_mcp`
- 可视化/UI 自动化：`scrcpy_vision`

#### Web 前端逆向

- 页面操作：`chrome_devtools`
- JS 断点与源码搜索：`js_reverse`
- HTTP 重放与安全测试：`burp`

#### Native / APK So 逆向

- IDA 静态分析：`ida_pro_mcp`
- 运行时 hook：`frida_mcp`
- 设备端协助：`adb_mcp` / `scrcpy_vision`

---

## 3. MCP 资源类通用接口

这三类函数不是具体业务服务器，而是“访问 MCP 服务器暴露资源”的通用能力。

### 3.1 `list_mcp_resources`

- 作用：列出某个 MCP 服务器或所有服务器公开的资源
- 典型用途：找可直接读取的文件、上下文、数据库 schema、配置片段
- 参数：
  - `server`：可选，指定服务器名
  - `cursor`：可选，分页游标
- 适合 skill 的描述：先枚举资源，再决定是否调用 `read_mcp_resource`

示例：

```json
{
  "server": "some_server"
}
```

### 3.2 `list_mcp_resource_templates`

- 作用：列出参数化资源模板
- 典型用途：发现“带参数读取”的资源，例如按表名、按主键、按路径查询的资源
- 参数：
  - `server`
  - `cursor`
- 适合 skill 的描述：当资源不是固定 URI，而是“模板 URI”时先查这个

### 3.3 `read_mcp_resource`

- 作用：读取具体资源内容
- 参数：
  - `server`：服务器名
  - `uri`：资源 URI
- 适合场景：
  - 读配置
  - 读 schema
  - 读服务上下文
  - 读共享状态

示例：

```json
{
  "server": "some_server",
  "uri": "resource://example/path"
}
```

---

## 4. `adb_mcp`：Android 设备控制与文件交互

### 4.1 定位

`adb_mcp` 是最基础的 Android 设备交互层，适合做：

- 设备列表与状态确认
- 安装/卸载 APK
- 截图、录屏
- 输入文本、点击、滑动、发按键
- 拉取/推送文件
- 读取 logcat、电池、内存、存储信息

如果你的 skill 需要“控制设备本身”，优先考虑它。

### 4.2 常见工作流

1. `list_devices` 确认设备  
2. `get_device_info` / `get_battery_info` 判断环境  
3. `install_app` 或 `list_packages`  
4. `send_tap` / `send_swipe` / `send_text` 驱动交互  
5. `take_screenshot` / `record_screen` 留证据  
6. `get_logcat` 排错  

### 4.3 方法清单

| 工具 | 主要参数 | 作用 | 典型用途 |
| --- | --- | --- | --- |
| `mcp__adb_mcp__list_devices` | 无 | 列出连接的 Android 设备 | 任务入口，先确认设备是否在线 |
| `mcp__adb_mcp__get_device_info` | `device_id?` | 读取设备详细信息 | 看型号、系统版本、序列号 |
| `mcp__adb_mcp__get_battery_info` | `device_id?` | 读取电池状态 | 长时测试前确认电量 |
| `mcp__adb_mcp__get_memory_info` | `device_id?` | 读取内存信息 | 性能/稳定性排查 |
| `mcp__adb_mcp__get_storage_info` | `device_id?` | 读取存储信息 | 看空间是否足够安装/录屏 |
| `mcp__adb_mcp__clear_logcat` | `device_id?` | 清空 logcat | 做一次干净抓日志 |
| `mcp__adb_mcp__get_logcat` | `device_id?`, `filter_tag?`, `lines?` | 读取日志 | 崩溃、网络、SSL、调试排错 |
| `mcp__adb_mcp__install_app` | `apk_path`, `device_id?` | 安装 APK | 部署测试包 |
| `mcp__adb_mcp__uninstall_app` | `package_name`, `device_id?` | 卸载应用 | 清理环境 |
| `mcp__adb_mcp__list_packages` | `device_id?`, `system_apps?` | 列出安装包名 | 找目标包名 |
| `mcp__adb_mcp__list_files` | `remote_path`, `device_id?` | 查看设备目录 | 找缓存、配置、导出文件 |
| `mcp__adb_mcp__pull_file` | `remote_path`, `local_path`, `device_id?` | 从设备拉文件到本地 | 导出数据库、日志、缓存 |
| `mcp__adb_mcp__push_file` | `local_path`, `remote_path`, `device_id?` | 推文件到设备 | 推证书、脚本、补丁 |
| `mcp__adb_mcp__send_keyevent` | `keycode`, `device_id?` | 发送按键事件 | 返回键、Home、菜单键 |
| `mcp__adb_mcp__send_tap` | `x`, `y`, `device_id?` | 点击坐标 | 自动化操作 |
| `mcp__adb_mcp__send_swipe` | `x1`,`y1`,`x2`,`y2`,`duration?`,`device_id?` | 滑动 | 滚动列表、解锁、切页 |
| `mcp__adb_mcp__send_text` | `text`, `device_id?` | 输入文本 | 搜索、登录、表单输入 |
| `mcp__adb_mcp__take_screenshot` | `save_path`, `device_id?` | 截图到本地 | 证据保留、UI 状态确认 |
| `mcp__adb_mcp__record_screen` | `duration?`, `save_path?`, `device_id?` | 录屏 | 复现流程留证 |

### 4.4 典型调用示例

列设备：

```json
{}
```

截图：

```json
{
  "device_id": "emulator-5554",
  "save_path": "C:\\Users\\28484\\Desktop\\screen.png"
}
```

读取最近 200 行日志：

```json
{
  "device_id": "emulator-5554",
  "lines": 200
}
```

### 4.5 写 skill 时的注意点

- 任何 Android 任务几乎都应该先跑一次 `list_devices`
- `take_screenshot` 明确要求本地绝对路径
- `get_logcat` 在复杂场景里建议先 `clear_logcat`
- `send_tap` / `send_swipe` 完全依赖坐标，适合固定界面，不适合强动态布局
- `push_file` 与 `pull_file` 是做证书安装、日志导出、数据留证的高频工具

---

## 5. `charles`：Charles 抓包与会话分析

### 5.1 定位

`charles` 负责读取和分析 Charles Proxy 已捕获的流量，重点不是“直接控制 Android 代理”，而是：

- 检查 Charles 是否在线、是否已有活动抓包会话
- 启动或接管 live capture，拿到 `capture_id`
- 结构化筛选 live traffic 或已保存 recording
- 下钻单条请求，查看头、状态码、请求体/响应体预览
- 对流量按 host、path、status、resource class 分组分析
- 结束抓包并持久化快照，方便后续复盘

### 5.2 适合的 skill 类型

- Android API 逆向
- HTTPS 抓包
- App 接口行为分析
- 参数签名前后对比
- 查找 token、session、加密字段
- 会话录制、筛选与证据留存

### 5.3 方法清单

| 工具 | 主要参数 | 作用 | 典型用途 |
| --- | --- | --- | --- |
| `mcp__charles__charles_status` | 无 | 检查 Charles 连通性与 live capture 状态 | 确认环境是否就绪 |
| `mcp__charles__reset_environment` | 无 | 重置 Charles 环境并恢复保存的配置 | 做干净实验 |
| `mcp__charles__start_live_capture` | `adopt_existing?`,`include_existing?`,`reset_session?` | 启动或接管 live capture | 获取后续分析要用的 `capture_id` |
| `mcp__charles__query_live_capture_entries` | `capture_id`,`cursor?`,`preset?`,`host_contains?`,`path_contains?`,`method_in?`,`status_in?`,`request_body_contains?`,`response_body_contains?`,`max_items?` | 结构化筛选 live 流量 | 推荐的实时检索入口 |
| `mcp__charles__peek_live_capture` | `capture_id`,`cursor?`,`limit?` | 预览当前 live capture 里的新条目 | 轻量查看最近请求 |
| `mcp__charles__read_live_capture` | `capture_id`,`cursor?`,`limit?` | 增量读取并推进 live cursor | 需要流式读取新流量时使用 |
| `mcp__charles__get_traffic_entry_detail` | `source`,`entry_id`,`capture_id?`,`recording_path?`,`include_full_body?`,`max_body_chars?` | 下钻单条流量详情 | 看头、body 预览、请求响应细节 |
| `mcp__charles__group_capture_analysis` | `source`,`capture_id?`,`recording_path?`,`group_by`,`preset?`,`host_contains?`,`path_contains?`,`status_in?` | 按 host/path/status/resource class 分组 | 快速找热点接口 |
| `mcp__charles__get_capture_analysis_stats` | `source`,`capture_id?`,`recording_path?`,`preset?` | 返回粗粒度统计 | 看抓包全局分布 |
| `mcp__charles__stop_live_capture` | `capture_id`,`persist?` | 停止 live capture 并可持久化 | 结束实验并保存快照 |
| `mcp__charles__list_recordings` | 无 | 列出已保存录制文件 | 选择历史流量包 |
| `mcp__charles__list_sessions` | 无 | 兼容方式列出历史 session | 兼容旧命名 |
| `mcp__charles__get_recording_snapshot` | `path?` | 读取已保存录制的快照元信息 | 离线检查 recording |
| `mcp__charles__analyze_recorded_traffic` | `recording_path?`,`preset?`,`host_contains?`,`path_contains?`,`method_in?`,`status_in?`,`request_body_contains?`,`response_body_contains?`,`max_items?` | 分析历史录制 | 离线回看与复盘 |
| `mcp__charles__query_recorded_traffic` | `host_contains?`,`http_method?`,`keyword_regex?`,`keep_request?`,`keep_response?` | 查询最新保存的 recording | 快速过滤历史流量 |
| `mcp__charles__proxy_by_time` | `record_seconds` | 按固定时长抓取或读取最新历史包 | 快速时间窗分析 |
| `mcp__charles__filter_func` | `capture_seconds`,`host_contains?`,`http_method?`,`keyword_regex?`,`keep_request?`,`keep_response?` | 按时间窗和条件过滤流量 | 快速缩小范围 |
| `mcp__charles__throttling` | `preset` | 设置 Charles 弱网/限速预设 | 弱网复现与行为验证 |

### 5.4 推荐工作流

1. `charles_status`  
2. 确认 Charles 已开启监听，Android 代理已指向抓包机，HTTPS 需要时已安装 Charles 证书  
3. `reset_environment`（可选，做干净实验）  
4. `start_live_capture`  
5. 操作 App  
6. `query_live_capture_entries`  
7. `get_traffic_entry_detail`  
8. `group_capture_analysis` / `get_capture_analysis_stats`  
9. `stop_live_capture`，必要时设置 `persist: true`  
10. `analyze_recorded_traffic` / `query_recorded_traffic`

### 5.5 调用示例

启动实时抓包：

```json
{
  "reset_session": true,
  "include_existing": false
}
```

筛选实时接口流量：

```json
{
  "capture_id": "capture-id-from-start",
  "preset": "api_focus",
  "host_contains": "api.example.com",
  "max_items": 10
}
```

### 5.6 注意点

- `charles` MCP 不会替你配置 Android 系统代理；要先完成 Charles 监听、设备代理和证书准备
- 实时检索优先用 `query_live_capture_entries`，不要默认用会推进游标的 `read_live_capture`
- `get_traffic_entry_detail` 默认只看预览更省上下文，只有确实需要原文时再开 `include_full_body`
- 如果想复盘抓包结果，结束 live capture 时建议 `persist: true`
- 如果 Charles 已经在运行并且你不想清空当前会话，用 `adopt_existing: true`

---

## 6. `burp`：Burp Suite 协同操作

### 6.1 定位

`burp` MCP 是面向 Burp Suite 的控制与数据访问层，适合：

- 读取代理历史
- 把请求送到 Repeater / Intruder
- 发 HTTP/1.1、HTTP/2 请求
- 生成 Collaborator 载荷
- 看扫描器问题
- 读写当前编辑器内容
- 调整代理拦截、任务执行状态
- 读写 Burp 配置

### 6.2 方法清单

| 工具 | 主要参数 | 作用 | 典型用途 |
| --- | --- | --- | --- |
| `mcp__burp__base64_encode` | `content` | Base64 编码 | 构造 payload |
| `mcp__burp__base64_decode` | `content` | Base64 解码 | 看编码数据 |
| `mcp__burp__url_encode` | `content` | URL 编码 | 构造参数 |
| `mcp__burp__url_decode` | `content` | URL 解码 | 还原参数 |
| `mcp__burp__generate_random_string` | `length`,`characterSet` | 生成随机串 | token、边界值、探测串 |
| `mcp__burp__get_active_editor_contents` | 无 | 获取当前编辑器内容 | 读取手工编辑请求 |
| `mcp__burp__set_active_editor_contents` | `text` | 设置当前编辑器内容 | 自动填入请求模板 |
| `mcp__burp__create_repeater_tab` | `content`,`targetHostname`,`targetPort`,`usesHttps`,`tabName?` | 新建 Repeater 标签页 | 送请求到 Repeater |
| `mcp__burp__send_to_intruder` | `content`,`targetHostname`,`targetPort`,`usesHttps`,`tabName?` | 送到 Intruder | 爆破/批量测试 |
| `mcp__burp__send_http1_request` | `content`,`targetHostname`,`targetPort`,`usesHttps` | 发 HTTP/1.1 请求 | 精确重放 |
| `mcp__burp__send_http2_request` | `pseudoHeaders`,`headers`,`requestBody`,`targetHostname`,`targetPort`,`usesHttps` | 发 HTTP/2 请求 | H2 特定场景 |
| `mcp__burp__generate_collaborator_payload` | `customData?` | 生成 OOB 域名 | SSRF / RCE / Blind XXE 测试 |
| `mcp__burp__get_collaborator_interactions` | `payloadId?` | 轮询 OOB 交互 | 看是否出站 |
| `mcp__burp__get_proxy_http_history` | `count`,`offset` | 读取代理 HTTP 历史 | 回看请求 |
| `mcp__burp__get_proxy_http_history_regex` | `count`,`offset`,`regex` | 按正则过滤 HTTP 历史 | 精确筛选 |
| `mcp__burp__get_proxy_websocket_history` | `count`,`offset` | 读取 WS 历史 | 分析 WebSocket |
| `mcp__burp__get_proxy_websocket_history_regex` | `count`,`offset`,`regex` | 正则过滤 WS 历史 | 查 token、命令字段 |
| `mcp__burp__get_scanner_issues` | `count`,`offset` | 列出扫描器发现 | 漏洞巡检 |
| `mcp__burp__output_project_options` | 无 | 导出项目级配置 | 查看配置 schema |
| `mcp__burp__output_user_options` | 无 | 导出用户级配置 | 查看配置 schema |
| `mcp__burp__set_project_options` | `json` | 设置项目级配置 | 自动化调优 |
| `mcp__burp__set_user_options` | `json` | 设置用户级配置 | 用户全局配置 |
| `mcp__burp__set_proxy_intercept_state` | `intercepting` | 开关代理拦截 | 开/关 Intercept |
| `mcp__burp__set_task_execution_engine_state` | `running` | 开关任务执行引擎 | 暂停/恢复扫描任务 |

### 6.3 典型调用示例

创建 Repeater：

```json
{
  "content": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
  "targetHostname": "example.com",
  "targetPort": 443,
  "usesHttps": true,
  "tabName": "home"
}
```

生成 Collaborator：

```json
{
  "customData": "ssrf-test"
}
```

### 6.4 注意点

- `send_http2_request` 的请求体和头是拆开的，不要把头写进 body
- 改配置前建议先 `output_project_options` / `output_user_options`
- OOB 检测一般是：`generate_collaborator_payload` -> 注入业务点 -> `get_collaborator_interactions`
- `get_proxy_http_history_regex` 很适合写 skill 时做“自动筛选相关历史请求”

---

## 7. `chrome_devtools`：浏览器自动化、页面诊断与性能分析

### 7.1 定位

`chrome_devtools` 负责浏览器页面的自动化控制与 DevTools 级观测。核心能力包括：

- 打开/关闭/选择页面
- 导航、刷新、模拟设备
- DOM 快照、截图
- 点击、输入、上传文件
- 列表化网络请求和控制台信息
- 执行页面脚本
- Lighthouse 审计
- 性能 trace
- 堆快照

如果你要“像人在浏览器里操作页面”，它是首选。

### 7.2 页面与上下文控制

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__chrome_devtools__list_pages` | 无 | 列出当前打开的页面 |
| `mcp__chrome_devtools__new_page` | `url`,`background?`,`isolatedContext?`,`timeout?` | 新建标签页并访问 URL |
| `mcp__chrome_devtools__select_page` | `pageId`,`bringToFront?` | 切换当前操作页面 |
| `mcp__chrome_devtools__close_page` | `pageId` | 关闭页面 |
| `mcp__chrome_devtools__navigate_page` | `type`,`url?`,`timeout?`,`ignoreCache?`,`handleBeforeUnload?`,`initScript?` | URL 导航、前进、后退、刷新 |
| `mcp__chrome_devtools__resize_page` | `width`,`height` | 调整浏览器尺寸 |
| `mcp__chrome_devtools__emulate` | `viewport?`,`colorScheme?`,`geolocation?`,`networkConditions?`,`userAgent?`,`cpuThrottlingRate?` | 设备/网络/UA 模拟 |

### 7.3 页面结构与截图

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__chrome_devtools__take_snapshot` | `filePath?`,`verbose?` | 获取页面 a11y 树快照，返回元素 `uid` |
| `mcp__chrome_devtools__take_screenshot` | `filePath?`,`format?`,`fullPage?`,`quality?`,`uid?` | 页面或元素截图 |
| `mcp__chrome_devtools__wait_for` | `text`,`timeout?` | 等待某些文本出现 |

说明：

- 先 `take_snapshot`，再使用里面的 `uid` 去做 click/fill/hover，通常最稳
- `uid` 是当前快照上下文里的元素标识，快照更新后可能变化

### 7.4 页面交互

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__chrome_devtools__click` | `uid`,`dblClick?`,`includeSnapshot?` | 点击元素 |
| `mcp__chrome_devtools__hover` | `uid`,`includeSnapshot?` | 悬停元素 |
| `mcp__chrome_devtools__drag` | `from_uid`,`to_uid`,`includeSnapshot?` | 拖拽 |
| `mcp__chrome_devtools__fill` | `uid`,`value`,`includeSnapshot?` | 填单个输入框 |
| `mcp__chrome_devtools__fill_form` | `elements`,`includeSnapshot?` | 批量填表单 |
| `mcp__chrome_devtools__type_text` | `text`,`submitKey?` | 向当前焦点输入文本 |
| `mcp__chrome_devtools__press_key` | `key`,`includeSnapshot?` | 键盘快捷键、特殊按键 |
| `mcp__chrome_devtools__upload_file` | `uid`,`filePath`,`includeSnapshot?` | 上传文件 |
| `mcp__chrome_devtools__handle_dialog` | `action`,`promptText?` | 处理 alert/confirm/prompt |

### 7.5 页面脚本与调试信息

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__chrome_devtools__evaluate_script` | `function`,`args?` | 在页面内执行 JS |
| `mcp__chrome_devtools__list_console_messages` | `includePreservedMessages?`,`pageIdx?`,`pageSize?`,`types?` | 查看控制台日志 |
| `mcp__chrome_devtools__get_console_message` | `msgid` | 获取单条控制台消息详情 |
| `mcp__chrome_devtools__list_network_requests` | `includePreservedRequests?`,`pageIdx?`,`pageSize?`,`resourceTypes?` | 查看网络请求列表 |
| `mcp__chrome_devtools__get_network_request` | `reqid?`,`requestFilePath?`,`responseFilePath?` | 查看或导出请求详情/体 |

### 7.6 审计与性能

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__chrome_devtools__lighthouse_audit` | `device?`,`mode?`,`outputDirPath?` | 跑 Lighthouse（不含性能分） |
| `mcp__chrome_devtools__performance_start_trace` | `autoStop?`,`filePath?`,`reload?` | 启动性能 trace |
| `mcp__chrome_devtools__performance_stop_trace` | `filePath?` | 停止性能 trace |
| `mcp__chrome_devtools__performance_analyze_insight` | `insightName`,`insightSetId` | 分析某个性能 insight |
| `mcp__chrome_devtools__take_memory_snapshot` | `filePath` | 导出 JS 堆快照 |

### 7.7 推荐工作流

#### 页面自动化

1. `new_page`
2. `take_snapshot`
3. `click` / `fill` / `press_key`
4. `wait_for`
5. `take_screenshot`

#### 抓页面请求

1. `new_page`
2. 页面交互
3. `list_network_requests`
4. `get_network_request`

#### 性能排查

1. `navigate_page`
2. `performance_start_trace`
3. 页面操作或 reload
4. `performance_stop_trace`
5. `performance_analyze_insight`

### 7.8 注意点

- 做 DOM 交互前优先 `take_snapshot`
- 页面刷新后旧 `uid` 不一定还能用
- 获取请求体/响应体时，必要时用 `requestFilePath` / `responseFilePath` 落地到文件
- 若你关注“JS 调用链和断点”，`js_reverse` 往往比这里更适合

---

## 8. `context7`：实时文档与示例检索

### 8.1 定位

`context7` 适合查询第三方库、框架、官方文档和代码示例，尤其适合技能编写里“要引用最新官方用法”的场景。

### 8.2 方法

#### `mcp__context7__resolve_library_id`

- 作用：先把“库名”解析成 Context7 可识别的文档 ID
- 参数：
  - `libraryName`
  - `query`
- 返回重点：
  - `libraryId`
  - 库名
  - 描述
  - snippets 数量
  - source reputation
  - benchmark score

#### `mcp__context7__query_docs`

- 作用：基于已经解析出的 `libraryId` 检索文档和示例
- 参数：
  - `libraryId`
  - `query`

### 8.3 推荐工作流

1. `resolve_library_id`
2. 选最合适的 `libraryId`
3. `query_docs`

### 8.4 示例

先解析：

```json
{
  "libraryName": "Next.js",
  "query": "App Router middleware authentication examples"
}
```

再查询：

```json
{
  "libraryId": "/vercel/next.js",
  "query": "How to protect routes in App Router middleware?"
}
```

### 8.5 写 skill 的注意点

- 如果用户给的是模糊库名，先 `resolve_library_id`
- 这是“文档问答 MCP”，不是联网随便搜网页
- 对技术问题，优先把它当作“官方文档检索器”

---

## 9. `everything_search`：本地文件极速搜索

### 9.1 定位

这是 Windows 本地文件搜索 MCP，适合大目录、全盘、模糊条件下快速找文件。

### 9.2 方法

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__everything_search__search` | `query`,`maxResults?`,`parentPath?`,`filesOnly?`,`foldersOnly?`,`matchPath?`,`regex?`,`caseSensitive?`,`wholeWord?`,`sortBy?`,`sortDescending?`,`showSize?`,`showDateModified?` | 搜索文件或目录 |
| `mcp__everything_search__get_file_info` | `filename` | 获取某个文件详细信息 |

### 9.3 示例

搜索指定目录下的所有 `.apk`：

```json
{
  "query": "*.apk",
  "parentPath": "C:\\Users\\28484",
  "filesOnly": true,
  "maxResults": 50
}
```

### 9.4 适用场景

- 找 APK / SO / 日志 / 导出文件
- 给逆向类 skill 找目标文件
- 在大目录里找配置、脚本、数据库、证书

---

## 10. `fetch`：通用网页抓取

### 10.1 定位

`fetch` 是“抓取网页/URL 内容”的通用工具，适合：

- 拉网页内容
- 抓文档页
- 读取 HTML
- 做简单网页内容提取

### 10.2 方法

#### `mcp__fetch__fetch`

- 参数：
  - `url`
  - `max_length?`
  - `raw?`
  - `start_index?`
- 作用：
  - 获取网页内容
  - 可返回简化后的 markdown 式内容
  - 可指定偏移继续读长页面

### 10.3 示例

```json
{
  "url": "https://example.com",
  "max_length": 6000
}
```

### 10.4 注意点

- 更适合“已知 URL 的内容抓取”，不是搜索引擎
- 如果页面太长，可以通过 `start_index` 分片读取
- 技术文档场景里，如有 `context7`，通常优先 `context7`

---

## 11. `frida_mcp`：Android 动态注入与运行时 Hook

### 11.1 定位

`frida_mcp` 是 Android 动态分析层，核心用途：

- 检查/启动/停止 `frida-server`
- 枚举应用
- 获取当前前台应用
- `spawn` 或 `attach` 到目标进程
- 注入 Frida JS 脚本
- 获取脚本输出日志

适合的场景：

- SSL Pinning 绕过
- 方法参数/返回值打印
- 动态抓签名、token、header
- native/Java 层运行时观察

### 11.2 方法清单

| 工具 | 主要参数 | 作用 | 典型用途 |
| --- | --- | --- | --- |
| `mcp__frida_mcp__check_frida_status` | 无 | 查看 frida-server 是否运行 | 前置检查 |
| `mcp__frida_mcp__start_frida_server` | 无 | 启动 frida-server | 动态分析准备 |
| `mcp__frida_mcp__stop_frida_server` | 无 | 停止 frida-server | 清理环境 |
| `mcp__frida_mcp__list_applications` | 无 | 列出设备应用 | 找包名、看是否运行中 |
| `mcp__frida_mcp__get_frontmost_application` | 无 | 获取当前前台应用 | 确认当前界面所属包名 |
| `mcp__frida_mcp__spawn` | `package_name`,`initial_script?`,`script_file_path?`,`output_file?` | 挂起启动并附加目标应用 | 早期时机 hook |
| `mcp__frida_mcp__attach` | `target`,`initial_script?`,`script_file_path?`,`output_file?` | 附加到 PID 或包名 | 对已运行应用注入 |
| `mcp__frida_mcp__get_messages` | `max_messages?` | 获取 hook/log 输出缓冲 | 看脚本打印结果 |

### 11.3 `attach` 与 `spawn` 的区别

- `attach`
  - 用于目标已经在运行
  - 可以按 PID 或包名附加
  - 适合临时观察、晚期 hook

- `spawn`
  - 用于在应用恢复前注入脚本
  - 适合早期类加载、启动流程、签名初始化、SSL pinning 早期绕过

### 11.4 示例

检查状态：

```json
{}
```

按包名启动并注入脚本文件：

```json
{
  "package_name": "com.example.app",
  "script_file_path": "C:\\Users\\28484\\Desktop\\hook.js",
  "output_file": "C:\\Users\\28484\\Desktop\\frida.log"
}
```

附加已运行应用并直接写内联脚本：

```json
{
  "target": "com.example.app",
  "initial_script": "Java.perform(function(){ console.log('hook loaded'); });"
}
```

### 11.5 推荐工作流

1. `check_frida_status`
2. 若未运行则 `start_frida_server`
3. `list_applications` 或 `get_frontmost_application`
4. `spawn` 或 `attach`
5. `get_messages`

### 11.6 注意点

- 需要设备环境正确部署 `frida-server`
- `script_file_path` 优先级高于 `initial_script`
- 大多数签名/加密定位任务通常是：`jadx` 静态定位 -> `frida_mcp` 动态验证

---

## 12. `ida_pro_mcp`：IDA Pro 静态分析与批处理重构

### 12.1 定位

`ida_pro_mcp` 是当前能力里最重的静态分析 MCP。它不是“只看反编译”，而是覆盖：

- 打开/切换 IDA 实例
- 快速 survey 二进制
- 列函数、全局、导入、类型
- 查 xref / callgraph / basic block
- 反编译、反汇编、导出函数信息
- 修改注释、重命名、声明类型、创建栈变量
- 读内存、补丁字节、补丁汇编
- 用 Python 在 IDA 上下文执行脚本

如果 skill 是面向 native 逆向、恶意代码分析、补丁、批量重命名，它几乎是核心。

### 12.2 强烈建议的入口工具

#### `mcp__ida_pro_mcp__survey_binary`

这是最适合做第一步 triage 的工具。它可以一次性给出：

- 文件元信息
- 段布局
- 入口点
- 统计信息
- 高频字符串
- 高价值函数
- imports 分类
- 调用图概况

写 skill 时可以明确规定：  
“开始分析 IDB 后，先调用 `survey_binary`，不要直接盲目 `list_funcs`。”

### 12.3 实例与会话管理

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__ida_pro_mcp__list_instances` | 无 | 列出当前可连接的 IDA 实例 |
| `mcp__ida_pro_mcp__select_instance` | `port`,`host?` | 切换当前 MCP 指向的 IDA 实例 |
| `mcp__ida_pro_mcp__open_file` | `file_path`,`autonomous?`,`new_database?`,`switch?`,`timeout?` | 打开文件到新的 IDA 实例 |
| `mcp__ida_pro_mcp__server_health` | 无 | 看当前 IDB/服务健康状态 |
| `mcp__ida_pro_mcp__server_warmup` | `build_caches?`,`init_hexrays?`,`wait_auto_analysis?` | 预热分析环境 |
| `mcp__ida_pro_mcp__idb_save` | `path?` | 保存当前 IDB |

### 12.4 二进制总览与发现

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__ida_pro_mcp__survey_binary` | `detail_level?` | 二进制总览 |
| `mcp__ida_pro_mcp__entity_query` | 复杂查询对象 | 查 functions/globals/imports/strings/names |
| `mcp__ida_pro_mcp__find_regex` | `pattern`,`limit?`,`offset?` | 在字符串中用正则查 |
| `mcp__ida_pro_mcp__find` | `targets`,`type`,`limit?`,`offset?` | 查字符串、立即数、数据/代码引用 |
| `mcp__ida_pro_mcp__find_bytes` | `patterns`,`limit?`,`offset?` | 字节模式搜索 |

### 12.5 函数与图分析

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__ida_pro_mcp__list_funcs` | `queries` | 列函数 |
| `mcp__ida_pro_mcp__func_query` | 过滤条件集合 | 按大小/名字/是否有类型过滤函数 |
| `mcp__ida_pro_mcp__func_profile` | 查询集合 | 给函数做概览画像 |
| `mcp__ida_pro_mcp__lookup_funcs` | `queries` | 按地址或名称查询函数 |
| `mcp__ida_pro_mcp__callees` | `addrs`,`limit?` | 查被调用函数 |
| `mcp__ida_pro_mcp__callgraph` | `roots`,`max_depth?`,`max_nodes?`,`max_edges?`,`max_edges_per_func?` | 构建调用图 |
| `mcp__ida_pro_mcp__basic_blocks` | `addrs`,`offset?`,`max_blocks?` | 获取 CFG 基本块 |
| `mcp__ida_pro_mcp__analyze_function` | `addr`,`include_asm?` | 紧凑单函数分析 |
| `mcp__ida_pro_mcp__analyze_batch` | `queries` | 批量多函数综合分析 |
| `mcp__ida_pro_mcp__analyze_component` | `addrs` | 对一组相关函数做组件分析 |

### 12.6 反编译、反汇编与导出

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__ida_pro_mcp__decompile` | `addr` | 反编译函数 |
| `mcp__ida_pro_mcp__disasm` | `addr`,`offset?`,`max_instructions?`,`include_total?` | 反汇编函数 |
| `mcp__ida_pro_mcp__export_funcs` | `addrs`,`format?` | 导出函数为 JSON / C 头 / 原型 |

### 12.7 交叉引用与数据流

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__ida_pro_mcp__xrefs_to` | `addrs`,`limit?` | 获取 xrefs to |
| `mcp__ida_pro_mcp__xref_query` | 查询集合 | 按方向/类型批量查询 xref |
| `mcp__ida_pro_mcp__trace_data_flow` | `addr`,`direction?`,`max_depth?` | 追踪多跳数据流 |
| `mcp__ida_pro_mcp__xrefs_to_field` | `queries` | 查结构体字段引用 |

### 12.8 类型系统与结构恢复

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__ida_pro_mcp__type_query` | 查询集合 | 查本地类型 |
| `mcp__ida_pro_mcp__type_inspect` | `queries` | 查看类型声明与成员 |
| `mcp__ida_pro_mcp__declare_type` | `decls` | 注入 C 类型声明 |
| `mcp__ida_pro_mcp__set_type` | `edits` | 设置函数/变量/局部变量类型 |
| `mcp__ida_pro_mcp__type_apply_batch` | `batch` | 批量应用类型 |
| `mcp__ida_pro_mcp__infer_types` | `addrs` | 推断类型 |
| `mcp__ida_pro_mcp__enum_upsert` | `queries` | 创建/补充枚举 |
| `mcp__ida_pro_mcp__search_structs` | `filter` | 搜结构体/联合体 |
| `mcp__ida_pro_mcp__read_struct` | `queries` | 读取某地址处结构体字段值 |

### 12.9 栈帧与局部变量

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__ida_pro_mcp__stack_frame` | `addrs` | 获取函数栈帧 |
| `mcp__ida_pro_mcp__declare_stack` | `items` | 声明栈变量 |
| `mcp__ida_pro_mcp__delete_stack` | `items` | 删除栈变量 |

### 12.10 重命名、注释与差异验证

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__ida_pro_mcp__rename` | `batch` | 批量重命名函数/数据/局部/栈变量 |
| `mcp__ida_pro_mcp__set_comments` | `items` | 设置注释 |
| `mcp__ida_pro_mcp__append_comments` | `items` | 追加注释 |
| `mcp__ida_pro_mcp__diff_before_after` | `addr`,`action`,`action_args` | 应用 rename/type/comment 后比较前后反编译 |

### 12.11 原始内存读取与补丁

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__ida_pro_mcp__get_bytes` | `regions` | 读字节 |
| `mcp__ida_pro_mcp__get_int` | `queries` | 读整数 |
| `mcp__ida_pro_mcp__get_string` | `addrs` | 读字符串 |
| `mcp__ida_pro_mcp__get_global_value` | `queries` | 读全局变量值 |
| `mcp__ida_pro_mcp__put_int` | `items` | 写整数 |
| `mcp__ida_pro_mcp__patch` | `patches` | 补丁字节 |
| `mcp__ida_pro_mcp__patch_asm` | `items` | 补丁汇编 |
| `mcp__ida_pro_mcp__undefine` | `items` | 取消定义为原始字节 |
| `mcp__ida_pro_mcp__define_code` | `items` | 将字节定义为代码 |
| `mcp__ida_pro_mcp__define_func` | `items` | 定义函数 |

### 12.12 导入、全局、指令与实体查询

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__ida_pro_mcp__imports` | `count`,`offset` | 列导入 |
| `mcp__ida_pro_mcp__imports_query` | `queries` | 按模块/名字过滤导入 |
| `mcp__ida_pro_mcp__list_globals` | `queries` | 列全局变量 |
| `mcp__ida_pro_mcp__insn_query` | `queries` | 查询指令模式 |
| `mcp__ida_pro_mcp__int_convert` | `inputs` | 数字格式转换 |

### 12.13 Python 扩展

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__ida_pro_mcp__py_eval` | `code` | 在 IDA 环境里执行 Python 片段 |
| `mcp__ida_pro_mcp__py_exec_file` | `file_path` | 执行整个 Python 脚本文件 |

### 12.14 推荐工作流

#### 初始 triage

1. `server_health`
2. `server_warmup`
3. `survey_binary`
4. `find_regex` / `imports_query`
5. `analyze_function` / `decompile`

#### 恢复语义

1. `decompile`
2. `stack_frame`
3. `type_query` / `type_inspect`
4. `set_type` / `declare_type`
5. `rename`
6. `diff_before_after`

#### 跟踪敏感字符串

1. `find_regex`
2. `xrefs_to`
3. `trace_data_flow`
4. `analyze_component`

### 12.15 skill 编写建议

- 一开始就写死“先 `survey_binary`”通常是好策略
- 如果要做批量重命名，最好把 `diff_before_after` 当成验证步骤
- 要分析 JNI / crypto / dispatch 表，`trace_data_flow` 很有价值
- `type_apply_batch` 适合做“自动修类型”类 skill
- `py_eval` / `py_exec_file` 适合做高级自动化，但应谨慎定义脚本边界

---

## 13. `jadx`：APK 静态反编译与 Android 代码导航

### 13.1 定位

`jadx` MCP 是 Android 静态分析入口，适合：

- 读 `AndroidManifest.xml`
- 找主 Activity、组件、导出组件
- 搜索类/方法/字段
- 获取类源码、方法源码、smali
- 查引用关系
- 重命名类/方法/字段/变量/包

它和 `ida_pro_mcp` 的差异在于：

- `jadx` 更偏 Java/Kotlin 层 APK
- `ida_pro_mcp` 更偏 native 二进制 / so / ELF / PE

### 13.2 入口信息与 Manifest

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__jadx__get_android_manifest` | 无 | 获取 Manifest 全文 |
| `mcp__jadx__get_main_activity_class` | 无 | 获取主 Activity |
| `mcp__jadx__get_main_application_classes_names` | 无 | 获取主应用包下主要类名 |
| `mcp__jadx__get_main_application_classes_code` | `count?`,`offset?` | 获取主要类代码 |
| `mcp__jadx__get_manifest_component` | `component_type`,`only_exported?` | 获取 activity/service/provider/receiver 组件信息 |

### 13.3 类与源码读取

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__jadx__get_all_classes` | `count?`,`offset?` | 获取所有类名 |
| `mcp__jadx__fetch_current_class` | 无 | 取 GUI 当前选中类源码 |
| `mcp__jadx__get_class_source` | `class_name` | 获取某类 Java 源码 |
| `mcp__jadx__get_smali_of_class` | `class_name` | 获取某类 smali |
| `mcp__jadx__get_methods_of_class` | `class_name` | 列方法 |
| `mcp__jadx__get_fields_of_class` | `class_name` | 列字段 |
| `mcp__jadx__get_method_by_name` | `class_name`,`method_name` | 取某方法源码 |
| `mcp__jadx__get_selected_text` | 无 | 获取当前选中文字 |

### 13.4 资源与字符串

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__jadx__get_all_resource_file_names` | `count?`,`offset?` | 列资源文件 |
| `mcp__jadx__get_resource_file` | `resource_name` | 读资源文件内容 |
| `mcp__jadx__get_strings` | `count?`,`offset?` | 获取 strings.xml 内容 |

### 13.5 搜索与引用

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__jadx__search_classes_by_keyword` | `search_term`,`package?`,`search_in?`,`offset?`,`count?` | 跨代码搜索类/方法/字段/代码内容 |
| `mcp__jadx__search_method_by_name` | `method_name` | 搜方法名 |
| `mcp__jadx__get_xrefs_to_class` | `class_name`,`count?`,`offset?` | 查类引用 |
| `mcp__jadx__get_xrefs_to_field` | `class_name`,`field_name`,`count?`,`offset?` | 查字段引用 |
| `mcp__jadx__get_xrefs_to_method` | `class_name`,`method_name`,`count?`,`offset?` | 查方法引用 |

### 13.6 重命名

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__jadx__rename_class` | `class_name`,`new_name` | 重命名类 |
| `mcp__jadx__rename_field` | `class_name`,`field_name`,`new_name` | 重命名字段 |
| `mcp__jadx__rename_method` | `method_name`,`new_name` | 重命名方法 |
| `mcp__jadx__rename_variable` | `class_name`,`method_name`,`variable_name`,`new_name`,`reg?`,`ssa?` | 重命名变量 |
| `mcp__jadx__rename_package` | `old_package_name`,`new_package_name` | 重命名包 |

### 13.7 调试相关

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__jadx__debug_get_threads` | 无 | 查看调试线程 |
| `mcp__jadx__debug_get_stack_frames` | 无 | 查看当前调用栈 |
| `mcp__jadx__debug_get_variables` | 无 | 查看当前变量 |

### 13.8 推荐工作流

#### APK 初步分析

1. `get_android_manifest`
2. `get_main_activity_class`
3. `get_manifest_component`
4. `search_classes_by_keyword`
5. `get_class_source`

#### 签名/接口定位

1. `search_classes_by_keyword` 搜 `okhttp`, `retrofit`, `sign`, `token`, `encrypt`
2. `get_xrefs_to_method`
3. `get_method_by_name`
4. 必要时切到 `frida_mcp` 动态验证

### 13.9 注意点

- `search_classes_by_keyword` 是 `jadx` 里非常高价值的入口工具
- `search_in` 可指定 `class,method,field,code,comment`
- 对 JNI 场景，通常 `jadx` 找 native 注册点，`ida_pro_mcp` 深挖 so

---

## 14. `js_reverse`：Web 前端 JavaScript 逆向与断点调试

### 14.1 定位

`js_reverse` 是面向 Web 前端逆向的专业 MCP。它和 `chrome_devtools` 的区别：

- `chrome_devtools` 更偏页面操作、网络、快照、性能
- `js_reverse` 更偏 JS 源码、断点、调用链、XHR 发起者、函数跟踪、源码保存

适用场景：

- 分析签名函数
- 追踪 XHR/Fetch 发起链
- 定位混淆函数
- 搜索 JS 源码中的关键词
- 在执行上下文中取变量
- 分析 WebSocket 消息模式

### 14.2 页面与上下文

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__js_reverse__new_page` | `url`,`timeout?` | 新建页面 |
| `mcp__js_reverse__select_page` | `pageIdx?` | 列出或切换页面 |
| `mcp__js_reverse__navigate_page` | `type`,`url?`,`timeout?`,`ignoreCache?` | 导航/刷新 |
| `mcp__js_reverse__select_frame` | `frameIdx?` | 列出或切换 frame/iframe |

### 14.3 脚本枚举与源码读取

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__js_reverse__list_scripts` | `filter?` | 列出当前页面脚本 |
| `mcp__js_reverse__search_in_sources` | `query`,`isRegex?`,`caseSensitive?`,`excludeMinified?`,`urlFilter?`,`maxResults?`,`maxLineLength?` | 在全部脚本中搜索 |
| `mcp__js_reverse__get_script_source` | `url?`,`scriptId?`,`startLine?`,`endLine?`,`offset?`,`length?` | 读取小片段源码 |
| `mcp__js_reverse__save_script_source` | `filePath`,`url?`,`scriptId?` | 保存完整脚本到本地 |

说明：

- `get_script_source` 设计成“看局部”，不是拉整个文件
- 大脚本应使用 `save_script_source`

### 14.4 断点、追踪与执行控制

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__js_reverse__set_breakpoint_on_text` | `text`,`urlFilter?`,`occurrence?`,`condition?` | 按代码文本自动下断点 |
| `mcp__js_reverse__list_breakpoints` | 无 | 列断点 |
| `mcp__js_reverse__remove_breakpoint` | `breakpointId?`,`url?` | 删除断点或 XHR 断点 |
| `mcp__js_reverse__pause_or_resume` | 无 | 暂停或继续执行 |
| `mcp__js_reverse__step` | `direction` | 单步 over/into/out |
| `mcp__js_reverse__trace_function` | `functionName`,`logArgs?`,`logThis?`,`pause?`,`traceId?`,`urlFilter?` | 跟踪函数调用 |
| `mcp__js_reverse__inject_before_load` | `script?`,`identifier?` | 页面加载前注入脚本 |

### 14.5 断点命中后的上下文分析

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__js_reverse__get_paused_info` | `frameIndex?`,`includeScopes?`,`maxScopeDepth?` | 获取断点命中时的栈与作用域变量 |
| `mcp__js_reverse__evaluate_script` | `function`,`frameIndex?`,`mainWorld?` | 在当前页面或断点帧中执行 JS |

### 14.6 网络与调用链

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__js_reverse__break_on_xhr` | `url` | 对包含目标 URL 的 XHR/Fetch 设置断点 |
| `mcp__js_reverse__list_network_requests` | `reqid?`,`pageIdx?`,`pageSize?`,`resourceTypes?`,`urlFilter?`,`includePreservedRequests?` | 查看请求列表或单请求详情 |
| `mcp__js_reverse__get_request_initiator` | `requestId` | 查看某请求由哪段 JS 发起 |
| `mcp__js_reverse__list_console_messages` | `msgid?`,`pageIdx?`,`pageSize?`,`types?`,`includePreservedMessages?` | 查看控制台 |

### 14.7 WebSocket 分析

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__js_reverse__get_websocket_messages` | `wsid?`,`analyze?`,`groupId?`,`frameIndex?`,`direction?`,`show_content?`,`pageIdx?`,`pageSize?`,`urlFilter?`,`includePreservedConnections?` | 列 WS 连接、分析消息分组、看具体帧 |

### 14.8 截图

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__js_reverse__take_screenshot` | `filePath?`,`format?`,`fullPage?`,`quality?` | 截图 |

### 14.9 推荐工作流

#### 定位签名函数

1. `new_page`
2. `list_scripts`
3. `search_in_sources` 搜 `sign` / `token` / 路径关键字
4. `set_breakpoint_on_text`
5. 触发请求
6. `get_paused_info`
7. `step`
8. `evaluate_script`

#### 跟踪请求是谁发起的

1. 操作页面
2. `list_network_requests`
3. `get_request_initiator`
4. 必要时 `break_on_xhr`

#### 分析混淆脚本

1. `search_in_sources`
2. `save_script_source`
3. `set_breakpoint_on_text`
4. `trace_function`

### 14.10 skill 编写建议

- 有源码关键词时，优先 `search_in_sources`
- 有请求 URL 时，优先 `break_on_xhr` 或 `get_request_initiator`
- 需要在页面脚本作用域里拿全局变量时，可考虑 `mainWorld: true`
- 如果页面重载频繁，优先按 URL 查脚本，不要过度依赖临时 `scriptId`

---

## 15. `memory`：结构化知识图谱记忆

### 15.1 定位

`memory` 是长期结构化记忆层，不是普通笔记。它维护的是“实体-观察-关系”的知识图谱。

适合用来：

- 记录用户偏好
- 记录项目事实
- 记录设备、目标、包名、接口名、漏洞点等结构化知识
- 在多轮任务之间保存稳定事实

### 15.2 核心对象

- 实体 `entity`
  - 有名字 `name`
  - 有类型 `entityType`
  - 有多条观察 `observations`

- 关系 `relation`
  - `from`
  - `relationType`
  - `to`

### 15.3 方法清单

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `mcp__memory__read_graph` | 无 | 读取整个图谱 |
| `mcp__memory__search_nodes` | `query` | 搜实体/类型/观察 |
| `mcp__memory__open_nodes` | `names` | 打开指定实体详情 |
| `mcp__memory__create_entities` | `entities` | 批量创建实体 |
| `mcp__memory__delete_entities` | `entityNames` | 删除实体 |
| `mcp__memory__add_observations` | `observations` | 给实体追加观察 |
| `mcp__memory__delete_observations` | `deletions` | 删除观察 |
| `mcp__memory__create_relations` | `relations` | 创建关系 |
| `mcp__memory__delete_relations` | `relations` | 删除关系 |

### 15.4 示例

创建实体：

```json
{
  "entities": [
    {
      "name": "com.example.app",
      "entityType": "android_app",
      "observations": [
        "主包名",
        "使用 OkHttp"
      ]
    }
  ]
}
```

创建关系：

```json
{
  "relations": [
    {
      "from": "com.example.app",
      "relationType": "uses",
      "to": "OkHttp"
    }
  ]
}
```

### 15.5 适合 skill 的用途

- 在逆向 skill 中记住目标包名、加密类、so 名、关键接口
- 在渗透测试 skill 中记住域名、漏洞点、扫描结果
- 在自动化 skill 中记住账号环境、部署方式、约定路径

### 15.6 注意点

- 关系建议用主动语态，例如 `App uses OkHttp`
- 不适合存超长原文，更适合存“可检索事实”

---

## 16. `sequential_thinking`：分步思考辅助

### 16.1 定位

这是一个“显式多步思考”工具，用于复杂问题分析、修正、分支、验证假设。  
它适合做：

- 多步骤逆向分析规划
- 不确定任务的方案探索
- 需要修正前面判断的复杂决策
- 大任务分解

### 16.2 方法

#### `mcp__sequential_thinking__sequentialthinking`

主要参数：

- `thought`
- `thoughtNumber`
- `totalThoughts`
- `nextThoughtNeeded`
- `isRevision?`
- `revisesThought?`
- `branchFromThought?`
- `branchId?`
- `needsMoreThoughts?`

### 16.3 使用方式理解

这个工具不是用来“查数据”的，而是用来把推理状态结构化地提交给系统。  
你可以：

- 从第 1 步开始分析
- 发现前面错了就 revision
- 从某一步分叉 branch
- 最后形成一个经过验证的解法

### 16.4 适合 skill 的场景

- 自动 triage skill
- 多阶段漏洞利用路线判断
- 逆向中“先 Java 还是先 native”的决策
- 多候选签名函数筛选

### 16.5 示例

```json
{
  "thought": "先确认问题是前端签名还是服务端校验导致 403。",
  "thoughtNumber": 1,
  "totalThoughts": 4,
  "nextThoughtNeeded": true
}
```

### 16.6 注意点

- 这是分析增强器，不是执行器
- 对简单任务没必要使用
- 对复杂、模糊、容易走错路的问题尤其有价值

---

## 17. `scrcpy_vision`：Android 可视化控制、UI 定位与无线调试

### 17.1 定位

`scrcpy_vision` 把 ADB、scrcpy 低延迟控制、屏幕截图/串流、`uiautomator` UI 树读取整合到一组工具里，适合做：

- 以 `serial` 为核心的 Android 设备连接与识别
- 基于当前页面元素文本、`resource-id`、`content-desc` 的 UI 定位
- 坐标点击、拖拽、长按、滑动、键盘输入
- 屏幕唤醒/解锁、前台 Activity、通知、剪贴板等状态确认
- USB 转 WiFi ADB 调试
- 单帧截图或持续画面流，用于观察界面变化和自动化联动

和 `adb_mcp` 相比，它更偏“可视化控制”和“UI 层定位”；`adb_mcp` 更偏基础设备管理、安装 APK、logcat、录屏、文件传输。写 skill 时两者通常是互补关系，而不是二选一。

### 17.2 适合的 skill 类型

- Android UI 自动化与页面回归
- App 动态测试中的元素定位与界面驱动
- 无线调试切换与真机远程控制
- 抓包/Hook 前后的页面状态验证
- 需要通过 UI 树确认按钮、输入框、弹窗位置的任务
- 需要连续查看设备画面而不是只截单张图的任务

### 17.3 方法清单

#### 设备连接与识别

| 工具 | 主要参数 | 作用 | 典型用途 |
| --- | --- | --- | --- |
| `mcp__scrcpy_vision__android_devices_list` | 无 | 列出已连接设备 | 获取 `serial`，确认 USB/WiFi 连接是否正常 |
| `mcp__scrcpy_vision__android_devices_info` | `serial` | 读取设备基础 `getprop` 信息 | 看型号、系统版本、ABI、设备标识 |
| `mcp__scrcpy_vision__android_adb_enableTcpip` | `serial`,`port?` | 在 USB 已连接时开启 WiFi 调试 | 为无线 ADB 做前置准备 |
| `mcp__scrcpy_vision__android_adb_getDeviceIp` | `serial` | 获取设备 WiFi IP | 准备 `connectWifi` |
| `mcp__scrcpy_vision__android_adb_connectWifi` | `ipAddress`,`port?` | 通过 WiFi 连接设备 | 无线调试 |
| `mcp__scrcpy_vision__android_adb_disconnectWifi` | `ipAddress?` | 断开指定或全部 WiFi ADB 连接 | 清理无线调试会话 |

#### 应用与运行态

| 工具 | 主要参数 | 作用 | 典型用途 |
| --- | --- | --- | --- |
| `mcp__scrcpy_vision__android_app_start` | `serial`,`packageName`,`activity?` | 启动应用或指定 Activity | 打开目标 App、直达指定页面 |
| `mcp__scrcpy_vision__android_app_stop` | `serial`,`packageName` | 强制停止应用 | 重置应用状态 |
| `mcp__scrcpy_vision__android_apps_list` | `serial`,`system?` | 列出已安装包 | 找包名、确认应用是否安装 |
| `mcp__scrcpy_vision__android_activity_current` | `serial` | 获取当前前台包名与 Activity | 判断当前页面是否切换成功 |
| `mcp__scrcpy_vision__android_notifications_get` | `serial` | 导出当前通知详情 | 查验证码通知、推送文案、包名来源 |

#### 屏幕、剪贴板与设备状态

| 工具 | 主要参数 | 作用 | 典型用途 |
| --- | --- | --- | --- |
| `mcp__scrcpy_vision__android_screen_isOn` | `serial` | 判断屏幕是否点亮 | 自动化前检查设备状态 |
| `mcp__scrcpy_vision__android_screen_wake` | `serial` | 点亮屏幕 | 准备操作设备 |
| `mcp__scrcpy_vision__android_screen_sleep` | `serial` | 熄灭屏幕 | 收尾或验证锁屏行为 |
| `mcp__scrcpy_vision__android_screen_unlock` | `serial` | 尝试唤醒并解锁设备 | 无安全锁时快速进入桌面 |
| `mcp__scrcpy_vision__android_clipboard_get` | `serial` | 读取剪贴板内容 | 取验证码、分享链接、复制结果 |
| `mcp__scrcpy_vision__android_clipboard_set` | `serial`,`text` | 尝试设置剪贴板 | 向输入框粘贴准备好的文本 |

#### 文件与 Shell

| 工具 | 主要参数 | 作用 | 典型用途 |
| --- | --- | --- | --- |
| `mcp__scrcpy_vision__android_file_list` | `serial`,`path` | 列出设备目录内容 | 查看导出目录、缓存目录、下载目录 |
| `mcp__scrcpy_vision__android_file_pull` | `serial`,`remotePath`,`localPath` | 从设备拉文件到本地 | 导出日志、图片、下载文件 |
| `mcp__scrcpy_vision__android_file_push` | `serial`,`localPath`,`remotePath` | 推送本地文件到设备 | 推配置、测试文件、证书 |
| `mcp__scrcpy_vision__android_shell_exec` | `serial`,`command` | 执行任意 `adb shell` 命令 | 在必须时做高级诊断、分辨率查询或设备操作 |

#### UI 树读取与输入控制

| 工具 | 主要参数 | 作用 | 典型用途 |
| --- | --- | --- | --- |
| `mcp__scrcpy_vision__android_ui_dump` | `serial` | 导出当前页面的 `uiautomator` XML | 获取元素文本、类名、边界、`resource-id` |
| `mcp__scrcpy_vision__android_ui_findElement` | `serial`,`text?`,`resourceId?`,`className?`,`contentDesc?` | 按 UI 属性查元素并返回中心坐标 | 定位按钮、输入框、弹窗控件 |
| `mcp__scrcpy_vision__android_input_tap` | `serial`,`x`,`y` | 点击坐标 | 点按钮、列表项、菜单 |
| `mcp__scrcpy_vision__android_input_longPress` | `serial`,`x`,`y`,`durationMs?` | 长按坐标 | 呼出上下文菜单、拖动态准备 |
| `mcp__scrcpy_vision__android_input_swipe` | `serial`,`x1`,`y1`,`x2`,`y2`,`durationMs?` | 滑动屏幕 | 滚动列表、切页、下拉刷新 |
| `mcp__scrcpy_vision__android_input_dragDrop` | `serial`,`startX`,`startY`,`endX`,`endY`,`durationMs?` | 拖拽到目标位置 | 拖动卡片、图标、排序项 |
| `mcp__scrcpy_vision__android_input_pinch` | `serial`,`centerX`,`centerY`,`startDistance`,`endDistance`,`durationMs?` | 近似模拟缩放手势 | 地图、图片缩放验证 |
| `mcp__scrcpy_vision__android_input_keyevent` | `serial`,`keycode` | 发送 Android 按键 | Home、Back、Enter、Delete、音量键 |
| `mcp__scrcpy_vision__android_input_text` | `serial`,`text` | 输入文本 | 登录、搜索、表单填写 |

#### 视觉能力

| 工具 | 主要参数 | 作用 | 典型用途 |
| --- | --- | --- | --- |
| `mcp__scrcpy_vision__android_vision_snapshot` | `serial` | 通过 `adb exec-out screencap -p` 获取当前屏幕 PNG | 单次截图确认界面 |
| `mcp__scrcpy_vision__android_vision_startStream` | `serial`,`frameFps?`,`maxFps?`,`maxSize?` | 启动 scrcpy+ffmpeg 持续画面流 | 持续观察页面变化，配合快速输入控制 |
| `mcp__scrcpy_vision__android_vision_stopStream` | `serial` | 停止画面流并移除资源 | 收尾，释放流资源 |

### 17.4 推荐工作流

#### 页面自动化与定位

1. `android_devices_list`
2. `android_screen_isOn` / `android_screen_wake` / `android_screen_unlock`
3. 如果后续要用坐标点击或滑动，先用 `android_shell_exec` 执行 `wm size` 获取当前分辨率
4. `android_vision_snapshot` 或 `android_vision_startStream`
5. `android_ui_dump` 或 `android_ui_findElement`
6. `android_input_tap` / `android_input_text` / `android_input_swipe`
7. `android_activity_current` 确认是否进入目标页面
8. 需要持续观察时保留 stream，结束后 `android_vision_stopStream`

#### WiFi ADB 切换

1. USB 连接设备后执行 `android_adb_enableTcpip`
2. `android_adb_getDeviceIp`
3. `android_adb_connectWifi`
4. `android_devices_list` 确认无线连接已出现
5. 测试完成后用 `android_adb_disconnectWifi` 清理

### 17.5 调用示例

开启 WiFi 调试：

```json
{
  "serial": "R58N123456A",
  "port": 5555
}
```

按文本找元素：

```json
{
  "serial": "R58N123456A",
  "text": "登录"
}
```

启动持续画面流：

```json
{
  "serial": "R58N123456A",
  "frameFps": 5,
  "maxSize": 1080
}
```

查询当前分辨率：

```json
{
  "serial": "R58N123456A",
  "command": "wm size"
}
```

### 17.6 注意点

- 除 `android_devices_list`、`android_adb_connectWifi`、`android_adb_disconnectWifi` 之外，大多数方法都要求先拿到设备 `serial`
- 如果 scrcpy 画面流已启动，点击、滑动、输入等操作会优先走更快的 scrcpy 控制通道；否则回退到 ADB 输入
- 如果要发坐标点击、长按、滑动、拖拽或 pinch，先查询当前分辨率；不同设备、横竖屏、缩放或截图尺寸假设都可能导致坐标偏移
- `android_ui_findElement` 适合当前页面的静态定位，页面变化后建议重新 `ui_dump` 或重新查元素
- 能用 `android_ui_findElement` / `android_ui_dump` 就尽量别直接写死坐标；只有在元素定位不可靠时才退回坐标点击
- `android_screen_unlock` 只适用于没有 PIN/密码/图案等安全锁的设备
- `android_clipboard_set` 在 Android 10+ 上可能受到系统限制，不保证所有设备都能直接生效
- `android_input_pinch` 是近似手势，不是真正的多点触控
- `android_shell_exec`、`android_file_push` 会直接改动设备环境，写 skill 时应明确这是高风险操作
- `android_vision_startStream` 产出的是实时资源而不是落地文件；如果只是单次截图，优先用 `android_vision_snapshot`

---

## 18. 结合 skill 编写的推荐分组

为了后续写 skill，更推荐你按“任务域”来组织，而不是按“工具服务器名”机械拆分。

### 18.1 Android 静态分析 skill

优先 MCP：

- `jadx`
- `everything_search`

常见流程：

1. 找 APK / 资源
2. 读 Manifest
3. 搜关键类
4. 拉方法源码
5. 追 xref

### 18.2 Android 动态分析 skill

优先 MCP：

- `adb_mcp`
- `scrcpy_vision`
- `frida_mcp`
- `charles`

常见流程：

1. 确认设备
2. 安装应用
3. 视情况启动 scrcpy 画面流或读取 UI 树
4. 启动 Charles live capture
5. 注入 hook
6. 查看请求、界面和日志

### 18.3 Native 逆向 skill

优先 MCP：

- `ida_pro_mcp`
- `everything_search`

常见流程：

1. 找 so / exe
2. `survey_binary`
3. 查字符串/导入
4. 反编译关键函数
5. 重命名、修类型、追数据流

### 18.4 Web 页面自动化 skill

优先 MCP：

- `chrome_devtools`

常见流程：

1. 打开页面
2. 获取快照
3. 交互表单
4. 抓请求
5. 截图留证

### 18.5 Web JS 逆向 skill

优先 MCP：

- `js_reverse`
- `chrome_devtools`
- `burp`

常见流程：

1. 搜源码
2. 对请求 URL 断点
3. 追调用链
4. 导出脚本
5. Burp 重放

### 18.6 文档检索 skill

优先 MCP：

- `context7`
- `fetch`

常见流程：

1. `resolve_library_id`
2. `query_docs`
3. 如需补充页面内容，再用 `fetch`

---

## 19. 写 skill 时可直接复用的提示词模板

下面给你几个适合直接改写进 skill 的模板。

### 19.1 Android 逆向 skill 模板片段

```text
当用户要求分析 Android APK 时：
1. 若任务是对已授权 Android App 做渗透测试，不要先静态分析 APK；先确认连接设备上是否已安装目标 App。
2. 先准备 burp 或 charles 的抓包可见性，再使用 scrcpy_vision 打开 App、驱动真实业务点击、输入和导航。
3. 每个关键动作后，先检查 burp 或 charles 是否已经出现 HTTP/HTTPS 或 WebSocket 数据包，并结合 adb_mcp 查看日志、界面异常和运行时状态。
4. 如果数据包已经可见且可重放，直接转入 Web/API/WebSocket 安全测试，按“界面动作 -> 数据包 -> Web 安全分析”的循环继续推进不同业务功能。
5. 只有在抓不到包、包被加密、明文不可得、协议仍不透明、无法稳定重放，或异常明显指向客户端逻辑阻塞时，才使用 jadx 读取 AndroidManifest.xml、主 Activity、导出组件，并搜索 okhttp/retrofit/sign/token/encrypt 等关键字。
6. 若 Java 层仍不够，使用 frida_mcp hook Java 或 native 边界恢复明文；若发现 native 线索（System.loadLibrary、JNI、so 文件）且 Java 与 hook 仍无法解决，再切换到 ida_pro_mcp 分析 dump 出来的 so。
7. 若需要控制设备、按 UI 元素定位、观察实时画面或切到 WiFi 调试，使用 scrcpy_vision；若需要安装应用、录屏、logcat、基础文件传输，使用 adb_mcp。
```

### 19.2 Web JS 逆向 skill 模板片段

```text
当用户要求定位前端签名、混淆函数或接口调用链时：
1. 优先使用 js_reverse 列举脚本并用 search_in_sources 搜索 sign/token/hash/encode/api path 等关键词。
2. 如果已知请求 URL，优先使用 break_on_xhr 或 get_request_initiator 确定发起位置。
3. 对关键函数使用 set_breakpoint_on_text、trace_function、get_paused_info、step 和 evaluate_script 获取运行时上下文。
4. 若需要保存完整脚本用于离线分析，使用 save_script_source。
5. 若需要复现或重放请求，配合 burp 的 create_repeater_tab、send_http1_request、send_http2_request。
6. 若需要页面级交互或截图，配合 chrome_devtools。
```

### 19.3 Native 二进制分析 skill 模板片段

```text
当用户要求分析二进制、so、恶意样本或 patch 点时：
1. 打开 IDA 后先调用 ida_pro_mcp.survey_binary 做总览，不要直接盲目 list_funcs。
2. 优先从 strings、imports、callgraph、关键常量、敏感 API 入手缩小范围。
3. 对可疑函数使用 analyze_function / decompile / xref_query / trace_data_flow。
4. 如果函数可读性差，使用 rename、set_type、declare_type、stack_frame、diff_before_after 逐步恢复语义。
5. 如需修改样本，使用 patch / patch_asm / put_int，并在必要时保存 IDB。
```

---

## 20. 常见注意事项汇总

### 20.1 绝对路径要求

以下类型工具经常要求绝对路径：

- `adb_mcp.take_screenshot`
- `adb_mcp.record_screen`
- `adb_mcp.pull_file` / `push_file`
- `scrcpy_vision.android_file_pull` / `android_file_push`
- `frida_mcp` 的 `script_file_path`、`output_file`
- `js_reverse.save_script_source`
- `chrome_devtools.take_screenshot`
- `chrome_devtools.take_memory_snapshot`
- `ida_pro_mcp.open_file`

### 20.2 分页类参数

常见分页/分片参数：

- `offset`
- `count`
- `limit`
- `pageIdx`
- `pageSize`
- `start_index`
- `length`

写 skill 时建议显式说明：

- 默认先取小批量样本
- 若结果过多，再增大 limit / count

### 20.3 先发现，再深入

很多 MCP 都有明显的“发现阶段工具”，不要一上来就深挖：

- `ida_pro_mcp`: `survey_binary`
- `jadx`: `get_android_manifest` / `search_classes_by_keyword`
- `js_reverse`: `list_scripts` / `search_in_sources`
- `chrome_devtools`: `take_snapshot`
- `charles`: `query_live_capture_entries`

### 20.4 证据留存

适合做证据保留的 MCP：

- `adb_mcp.take_screenshot`
- `adb_mcp.record_screen`
- `scrcpy_vision.android_vision_snapshot`
- `chrome_devtools.take_screenshot`
- `js_reverse.take_screenshot`
- `charles.get_traffic_entry_detail`
- `burp` 历史与 Repeater

### 20.5 最常见的组合

- Android 静态 + 动态：`jadx` + `frida_mcp`
- Android 动态 + 流量：`adb_mcp` + `charles`
- Android 动态 + UI 自动化：`scrcpy_vision` + `frida_mcp`
- Android 抓包 + 页面驱动：`scrcpy_vision` + `charles`
- Web 自动化 + JS 逆向：`chrome_devtools` + `js_reverse`
- Web 安全重放：`js_reverse` + `burp`
- Native 静态 + 动态：`ida_pro_mcp` + `frida_mcp`

---

## 21. 总结

如果你的目标是“方便后续写成 skills”，最实用的做法不是为每个 MCP 单独写一个 skill，而是按任务域拆：

- Android 静态分析
- Android 动态分析与抓包
- Web 自动化
- Web JS 逆向
- Native 二进制分析
- 文档检索
- 记忆与任务状态管理

其中最值得优先围绕其设计 skill 的 MCP 是：

1. `jadx`
2. `ida_pro_mcp`
3. `js_reverse`
4. `chrome_devtools`
5. `frida_mcp`
6. `charles`
7. `adb_mcp`

如果后面你要，我还可以在这份文档基础上继续帮你做两件事：

1. 再生成一份“适合 skills 的精简版 MCP 速查表”
2. 直接把这份文档拆成多个 `SKILL.md` 模板骨架
