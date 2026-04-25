"""Recon dimension tracking helpers for AgentCore."""

from __future__ import annotations

from typing import Any


RECON_MIN_ROUNDS = 8  # 信息收集阶段最低轮数，低于此数 [DONE] 被忽略

# ★ Include BOTH tool-result signatures AND natural-language descriptions from notes/confirmed_facts
RECON_DIM_KEYWORDS: dict[str, list[str]] = {
    "server": [
        "端口", "port", "nmap", "开放", "open", "服务版本", "service",
        "真实ip", "real ip", "cdn", "源站", "操作系统", "os检测", "ttl",
        "中间件", "middleware", "数据库", "database", "mysql", "redis",
        "扫描", "端口扫描", "ip地址", "ip探测", "存活主机",
        "apache", "nginx", "tomcat", "iis", "jetty",
        "操作系统", "linux", "windows", "ubuntu", "centos",
    ],
    "website": [
        "waf", "web应用防火墙", "敏感目录", "目录扫描", "dirsearch", "gobuster",
        "源码泄露", ".git", ".svn", ".ds_store", ".env", "备份文件", ".bak",
        "旁站", "同ip", "c段", "同网段", "指纹", "cms", "框架", "framework",
        "架构", "技术栈", "web指纹",
        "网站", "web", "javascript", "js文件", "api端点", "api端",
        "cms", "wordpress", "dedecms", "phpcms", "discuz",
        "登录", "后台", "管理", "admin", "login",
        "页面", "url", "目录", "文件",
    ],
    "domain": [
        "whois", "注册人", "注册商", "icp", "备案", "子域名", "subdomain",
        "dns记录", "cname", "mx记录", "txt记录", "证书透明", "crt.sh",
        "证书信息", "ssl证书",
        "域名", "dns", " registr", "注册信息", "icp备案",
        "子域名", "子站", "crt.sh", "证书",
    ],
    "personnel": [
        "github_id", "followers", "following", "public_repos",
        "unclecheng",
        "twitter",
        "社工", "社会工程", "人员信息", "作者追踪", "人物画像",
    ],
}


def update_recon_dimension_completion(agent: Any, response: str) -> None:
    """Auto-detect which recon dimensions have been explored.

    Uses signal-weighted sources instead of blindly scanning all round text.
    response 参数保留是为了兼容现有调用签名，但逻辑上不使用原始推理文本。
    """
    note_text = " ".join(agent.context.state.notes[-15:]).lower()
    fact_text = " ".join(getattr(agent.context.state, "confirmed_facts", [])[-15:]).lower()
    step_text = " ".join(agent.context.state.executed_steps[-15:]).lower()

    for dim, keywords in RECON_DIM_KEYWORDS.items():
        if dim == "personnel":
            if not agent.context.state.recon_dimension4_active:
                continue
            source_text = fact_text
        else:
            source_text = f"{fact_text} {note_text} {step_text}"

        if not source_text.strip():
            continue

        if not agent.context.state.recon_dimensions_completed.get(dim, False):
            if any(kw.lower() in source_text for kw in keywords):
                agent.context.state.mark_recon_dimension(dim)
