# Android Signature Reverse Template

Use this template for Android sign, token, encrypt, decrypt, JNI, interceptor, and replay tasks.

## Template

```markdown
# Android 签名逆向记录

## 基本信息

- APK / 包名：
- 目标功能：
- 目标请求：
- 目标字段：
- 当前阶段：static / dynamic / native / replay
- 当前状态：🟡 进行中 / ✅ 已闭环 / ⛔ 阻塞
- 目标：
- 约束：

## 静态总览

| 项目 | 内容 |
| --- | --- |
| Manifest 入口 |  |
| Application |  |
| 主 Activity / 目标组件 |  |
| 主要包结构 |  |
| 网络框架 |  |
| DI 框架 |  |
| 当前结论 |  |

## 请求调用链

```text
Activity / Fragment / Service
-> ViewModel / Presenter / UseCase
-> Repository / DataSource
-> ApiService / RequestBuilder / Interceptor
-> Signer / Encryptor / Serializer
```

- 真实调用链：
- 请求 Method / Path：
- Header 写入点：
- Body 写入点：
- Sign 输入汇合点：
- 序列 / 前置依赖：

## Sign / Crypto 定位

| 项目 | 内容 |
| --- | --- |
| Sign 类 / 方法 |  |
| Encrypt 类 / 方法 |  |
| 关键常量 |  |
| 关键 Header |  |
| 关键 Token / Device 值 |  |
| Java-only / Java+JNI / Native-first |  |

## 动态验证

| Hook 点 | 原因 | 捕获内容 | 结果 |
| --- | --- | --- | --- |
| Hook1 |  |  |  |

- URL：
- Headers：
- Body：
- Sign 输入：
- Sign 输出：
- 代理验证：

## JNI / SO 分析

| 项目 | 内容 |
| --- | --- |
| Java native 入口 |  |
| SO 名称 |  |
| JNI 类型 | static / dynamic |
| 输入参数 |  |
| 输出角色 | 最终 sign / 中间 token / 其他 |
| 是否需要 deeper RE |  |

## Burp 重放基线

- Method：
- Path：
- Query：
- Headers：
- Body：
- 必须保留字段：
- 可变异字段：
- 前置状态：
- 是否需要设备 / Hook / App 协助：

## 结论

- 当前闭环程度：
- 剩余阻塞：
- 下一步建议：
```

## Minimum Required Fields

Even in a compact record, keep:

- APK or package
- target request
- real call-flow summary
- network stack
- sign or crypto location
- Java versus JNI conclusion
- one runtime hook or explicit reason why runtime is not needed
- Burp replay baseline or explicit blocker
