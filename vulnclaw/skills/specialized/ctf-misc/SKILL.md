---
name: ctf-misc
description: CTF杂项知识库 — Python Jail逃逸、Bash Jail逃逸、编码链识别与解码、QR/音频/图像隐写、游戏VM逆向、CTFd API导航、Linux提权
---

# CTF 杂项知识库

针对 CTF Misc 题目的实战知识库，覆盖**沙箱逃逸、编码链识别、隐写术、游戏逆向**等杂项题型。

## 场景路由

| 场景 | 参考文档 | 核心内容 |
|------|---------|---------|
| Python 沙箱逃逸 | `python-jail-escape.md` | `__import__`/func\_globals/eval链 |
| Bash 沙箱逃逸 | `bash-jail-escape.md` | HISTFILE/ctypes.sh/vi编辑器逃逸 |
| 编码链识别与解码 | `encoding-chain-reference.md` | Base64→Hex→ROT13 多层嵌套 |
| 游戏/自定义 VM 逆向 | `game-and-vm-reverse.md` | WASM/Brainfuck/Z3 约束求解 |
| CTFd 平台操作 | `ctfd-platform-guide.md` | API 下载附件/提交 flag |
| Linux 提权 | `linux-privesc-quick.md` | SUID/sudo/cron/内核漏洞 |

## 快速判题

| 题目特征 | 可能考点 | 推荐参考 |
|---------|---------|---------|
| Python exec/eval 输入框 | PyJail 逃逸 | python-jail-escape.md |
| 命令行 restricted bash | BashJail 逃逸 | bash-jail-escape.md |
| 奇怪编码字符串 | 编码链解码 | encoding-chain-reference.md |
| 二维码/音频文件 | 隐写术 | encoding-chain-reference.md |
| 游戏二进制/WASM | 自定义 VM 逆向 | game-and-vm-reverse.md |
| CTFtime / CTFd 平台 | 平台 API | ctfd-platform-guide.md |
| 给了一个 shell | Linux 提权 | linux-privesc-quick.md |
