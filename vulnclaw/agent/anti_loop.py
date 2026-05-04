"""Anti-loop and phase-detection helpers for AgentCore."""

from __future__ import annotations

import re
from typing import Optional

from vulnclaw.agent.context import PentestPhase


FAILED_ACCESS_PATTERNS = [
    "SSLError", "ReadTimeout", "连接超时", "连接失败",
    "502 Bad Gateway", "502", "503", "无法访问", "访问失败",
    "Connection refused", "ConnectionError", "TimeoutError",
    "Name or service not known", "No route to host",
    "SSL: CERTIFICATE_VERIFY_FAILED", "超时",
]


def detect_phase_from_output(output: str) -> Optional[PentestPhase]:
    """Detect phase transition signals from LLM output."""
    output_lower = output.lower()
    transitions = [
        (PentestPhase.VULN_DISCOVERY, ["进入漏洞发现", "开始漏洞扫描", "漏洞检测", "切换到漏洞发现", "phase: vuln_discovery"]),
        (PentestPhase.EXPLOITATION, ["进入漏洞利用", "开始利用", "尝试利用", "切换到漏洞利用", "phase: exploitation"]),
        (PentestPhase.POST_EXPLOITATION, ["进入后渗透", "内网渗透", "横向移动", "切换到后渗透", "phase: post_exploitation"]),
        (PentestPhase.REPORTING, ["生成报告", "整理结果", "渗透测试完成", "切换到报告", "phase: reporting"]),
    ]

    for phase, signals in transitions:
        if any(signal in output_lower for signal in signals):
            return phase
    return None


def is_completion_signal(output: str) -> bool:
    """Check if the LLM output signals task completion."""
    completion_signals = [
        "[DONE]",
        "[COMPLETE]",
        "渗透测试已完成",
        "测试结束",
        "任务完成",
    ]
    return any(signal in output for signal in completion_signals)


def track_failed_target(agent, response_text: str) -> Optional[str]:
    """Track target-level failures and detect repeatedly failed targets."""
    hostname = None
    url_match = re.search(r'https?://([^\s/<>"\')\]]+)', response_text)
    if url_match:
        hostname = url_match.group(1)

    if not hostname:
        return None

    is_failed_access = any(pattern in response_text for pattern in FAILED_ACCESS_PATTERNS)

    if is_failed_access:
        agent.runtime.failed_targets[hostname] = agent.runtime.failed_targets.get(hostname, 0) + 1
        if agent.runtime.failed_targets[hostname] >= 3:
            agent.runtime.blocked_targets.add(hostname)
            return hostname
    else:
        if hostname in agent.runtime.failed_targets and agent.runtime.failed_targets[hostname] > 0:
            agent.runtime.failed_targets[hostname] -= 1

    return None


def is_meaningful_step(step: str) -> bool:
    """Check if a step represents meaningful progress (not just a failed retry)."""
    failure_only_keywords = [
        "SSLError", "ReadTimeout", "连接超时", "连接失败",
        "502 Bad Gateway", "无法访问", "访问失败",
        "Connection refused", "ConnectionError", "TimeoutError",
        "请求失败",
    ]
    progress_keywords = [
        "发现", "确认", "漏洞", "端口", "路径",
        "flag", "成功", "CVE", "泄露", "绕过",
        "验证通过", "已确认",
    ]

    if any(keyword in step for keyword in progress_keywords):
        return True
    if any(keyword in step for keyword in failure_only_keywords):
        return False
    return True


def detect_attack_path(output: str) -> Optional[str]:
    """Detect the current attack path/technique from LLM output."""
    output_lower = output.lower()
    path_patterns = [
        ("regex_bypass", ["preg_replace", "preg_match", "正则绕过", "大小写绕过", "数组绕过", "双写绕过"]),
        ("file_inclusion", ["php://filter", "文件包含", "include", "require", "伪协议", "php://input", "data://"]),
        ("rce", ["eval(", "system(", "exec(", "passthru(", "shell_exec(", "命令执行", "rce"]),
        ("sqli", ["sql注入", "union select", "information_schema", "sqli", "sqlmap"]),
        ("ssti", ["ssti", "template", "jinja2", "twig", "{{", "模板注入"]),
        ("deserialization", ["反序列化", "unserialize", "serialize", "pop链", "wakeup"]),
        ("file_upload", ["文件上传", "upload", "webshell", "一句话木马"]),
        ("ssrf", ["ssrf", "gopher://", "dict://", "内网访问"]),
        ("xxe", ["xxe", "xml外部实体", "ENTITY"]),
        ("info_leak", ["源码泄露", ".git", ".svn", "备份文件", "目录遍历", "robots.txt"]),
        ("brute_force", ["爆破", "弱口令", "字典", "brute"]),
    ]

    for path_name, keywords in path_patterns:
        if any(keyword in output_lower for keyword in keywords):
            return path_name
    return None
