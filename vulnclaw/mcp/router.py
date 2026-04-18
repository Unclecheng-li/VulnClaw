"""VulnClaw MCP Router — route natural language intents to MCP tool calls."""

from __future__ import annotations

import re
from typing import Any, Optional


# ── Intent → Tool mapping ───────────────────────────────────────────

INTENT_TOOL_MAP: dict[str, list[dict[str, Any]]] = {
    # Browser automation
    "打开网页|访问url|访问页面|navigate": [
        {"tool": "new_page", "server": "chrome-devtools"},
        {"tool": "navigate", "server": "chrome-devtools"},
    ],
    "截图|screenshot|截屏": [
        {"tool": "screenshot", "server": "chrome-devtools"},
    ],
    "执行js|eval js|运行javascript": [
        {"tool": "evaluate_js", "server": "chrome-devtools"},
    ],
    # HTTP requests
    "发请求|http请求|fetch|访问接口|调用api": [
        {"tool": "fetch", "server": "fetch"},
        {"tool": "send_http1_request", "server": "burp"},
    ],
    # Burp Suite
    "抓包|查看请求|拦截请求|proxy": [
        {"tool": "get_proxy_history", "server": "burp"},
    ],
    "修改数据包|重放|replay|篡改": [
        {"tool": "send_http1_request", "server": "burp"},
    ],
    # JS reverse
    "分析js|js逆向|js逻辑|extract endpoints": [
        {"tool": "analyze_js", "server": "js-reverse"},
        {"tool": "extract_endpoints", "server": "js-reverse"},
    ],
    # Frida
    "hook|插桩|frida|动态调试|hook函数": [
        {"tool": "frida_attach", "server": "frida-mcp"},
        {"tool": "frida_spawn", "server": "frida-mcp"},
    ],
    # ADB
    "控制手机|点击屏幕|adb|安卓操作": [
        {"tool": "adb_tap", "server": "adb-mcp"},
        {"tool": "adb_shell", "server": "adb-mcp"},
        {"tool": "adb_screenshot", "server": "adb-mcp"},
    ],
    # JADX
    "反编译apk|apk源码|jadx": [
        {"tool": "decompile", "server": "jadx"},
        {"tool": "get_source", "server": "jadx"},
    ],
    # IDA Pro
    "逆向二进制|ida|反编译函数|二进制分析": [
        {"tool": "decompile_function", "server": "ida-pro-mcp"},
        {"tool": "get_xrefs", "server": "ida-pro-mcp"},
    ],
    # Memory
    "记住|记录|save memory": [
        {"tool": "save", "server": "memory"},
    ],
    "回忆|查询记录|retrieve memory": [
        {"tool": "retrieve", "server": "memory"},
    ],
}


class MCPRouter:
    """Routes natural language intents to MCP tool calls."""

    def route(self, user_input: str) -> list[dict[str, Any]]:
        """Analyze user input and return suggested tool calls.

        Returns a list of dicts with keys: tool, server, confidence.
        """
        input_lower = user_input.lower()
        results = []

        for pattern, tools in INTENT_TOOL_MAP.items():
            keywords = pattern.split("|")
            if any(kw in input_lower for kw in keywords):
                for tool_entry in tools:
                    results.append({
                        "tool": tool_entry["tool"],
                        "server": tool_entry["server"],
                        "confidence": 0.8,
                    })

        return results

    def extract_url(self, text: str) -> Optional[str]:
        """Extract URL from text."""
        url_match = re.search(r'(https?://\S+)', text)
        return url_match.group(1) if url_match else None

    def extract_ip(self, text: str) -> Optional[str]:
        """Extract IP address from text."""
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text)
        return ip_match.group(1) if ip_match else None

    def suggest_tools_for_phase(self, phase: str) -> list[dict[str, Any]]:
        """Suggest tools based on pentest phase."""
        phase_tools = {
            "信息收集": [
                {"tool": "fetch", "server": "fetch", "reason": "HTTP 请求探测目标"},
                {"tool": "new_page", "server": "chrome-devtools", "reason": "浏览器访问目标"},
                {"tool": "screenshot", "server": "chrome-devtools", "reason": "截图记录目标页面"},
            ],
            "漏洞发现": [
                {"tool": "fetch", "server": "fetch", "reason": "发送漏洞探测请求"},
                {"tool": "analyze_js", "server": "js-reverse", "reason": "分析 JS 寻找漏洞"},
                {"tool": "extract_endpoints", "server": "js-reverse", "reason": "提取 API 端点"},
            ],
            "漏洞利用": [
                {"tool": "send_http1_request", "server": "burp", "reason": "构造利用请求"},
                {"tool": "fetch", "server": "fetch", "reason": "发送利用 payload"},
                {"tool": "evaluate_js", "server": "chrome-devtools", "reason": "浏览器内利用"},
            ],
            "后渗透": [
                {"tool": "adb_shell", "server": "adb-mcp", "reason": "设备命令执行"},
                {"tool": "frida_attach", "server": "frida-mcp", "reason": "动态 Hook"},
            ],
        }

        return phase_tools.get(phase, [])
