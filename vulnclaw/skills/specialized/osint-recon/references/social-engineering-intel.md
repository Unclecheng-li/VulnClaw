# 社会工程信息汇总

## 人物画像构建框架

### 信息维度

| 维度 | 数据源 | 提取方法 |
|------|--------|---------|
| 身份标识 | 页面 meta、GitHub | 正则提取 author/copyright |
| 社交网络 | 页面外部链接 | `<a href>` 匹配社交媒体域名 |
| 技术偏好 | GitHub 仓库语言分布 | GitHub API |
| 地理位置 | GitHub location、博客 | 个人资料页 |
| 职业信息 | GitHub company、LinkedIn | 个人资料页 |
| 联系方式 | GitHub email、博客联系页 | API + 页面提取 |
| 兴趣领域 | GitHub 仓库主题、博客文章 | 仓库 topics + 文章分类 |

## 信息交叉验证

### 原则
1. **单一来源不采信** — 关键信息需要至少 2 个独立来源确认
2. **时效性标注** — 标注信息的获取时间，过时信息单独标记
3. **置信度评级**：
   - 🟢 **高**：多个独立来源确认
   - 🟡 **中**：单一可靠来源
   - 🔴 **低**：推断/未验证

### 常见关联模式

```
博客 GitHub 链接 → GitHub 用户名 → GitHub API 获取邮箱
                                  → GitHub API 获取仓库 → 技术栈推断
                                  → GitHub 提交邮箱 → 关联其他身份

博客 B站 链接 → B站 UID → B站主页 → 关注/粉丝 → 兴趣标签
                                    → 投稿视频 → 技术领域

用户名 → 跨平台搜索 → 发现更多社交账号
邮箱 → haveibeenpwned → 数据泄露记录
```

## 社交媒体信息提取

### B站
```python
import re

def extract_bilibili_uid(url):
    """从 B站 URL 提取 UID"""
    # space.bilibili.com/12345
    m = re.search(r'bilibili\.com/(\d+)', url)
    if m:
        return m.group(1)
    return None
```

### 微博
```python
def extract_weibo_uid(url):
    """从微博 URL 提取 UID"""
    # weibo.com/u/12345 或 weibo.com/username
    m = re.search(r'weibo\.com/(?:u/)?(\w+)', url)
    if m:
        return m.group(1)
    return None
```

### 知乎
```python
def extract_zhihu_username(url):
    """从知乎 URL 提取用户名"""
    # zhihu.com/people/username
    m = re.search(r'zhihu\.com/people/([^/?]+)', url)
    if m:
        return m.group(1)
    return None
```

## 信息汇总报告格式

```markdown
# 目标侦察报告

## 📋 基本信息
| 项目 | 内容 | 置信度 | 来源 |
|------|------|--------|------|
| 目标 | https://xxx | - | 用户输入 |
| 框架 | Hexo | 🟢 | HTTP头+HTML特征 |
| 服务器 | GitHub Pages | 🟢 | Server头 |
| 作者 | XXX | 🟢 | meta author |
| ... | ... | ... | ... |

## 👤 人物画像
- **昵称**：XXX
- **GitHub**：https://github.com/xxx
- **B站**：https://space.bilibili.com/xxx
- **技术栈**：Python / JavaScript
- **位置**：深圳
- ...

## 🔗 关联发现
- [发现1]
- [发现2]

## 📌 关键发现
1. ...
2. ...

---
*报告生成时间：YYYY-MM-DD HH:MM*
*数据来源：目标网站、GitHub API、社交媒体公开信息*
```

## 隐私与伦理

- ✅ 只收集**公开信息**（不需要登录即可访问的内容）
- ✅ 不尝试登录他人账号
- ✅ 不利用收集的信息进行骚扰或社会工程攻击
- ✅ 标注信息来源，确保可追溯
- ❌ 不收集私人通讯内容
- ❌ 不利用信息进行钓鱼或其他欺骗行为
