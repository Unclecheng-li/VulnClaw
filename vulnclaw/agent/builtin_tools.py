"""Agent built-in tools and OpenAI tool schema helpers."""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from typing import Any


BLOCKED_PATTERNS: list[str] = [
    r"os\.\s*system\s*\(",
    r"subprocess\.\s*Popen\s*\(",
    r"shutil\.\s*rmtree\s*\(",
    r"__import__\s*\(\s*['\"]os['\"]",
    r"open\s*\(\s*['\"].*vulnclaw.*config",
    r"open\s*\(\s*['\"].*\.vulnclaw",
]

RESERVED_IP_RANGES: list[tuple[str, str, str]] = [
    ("198.18.0.0", "198.19.255.255", "RFC 2544 基准测试地址"),
    ("10.0.0.0", "10.255.255.255", "RFC 1918 私有地址"),
    ("172.16.0.0", "172.31.255.255", "RFC 1918 私有地址"),
    ("192.168.0.0", "192.168.255.255", "RFC 1918 私有地址"),
    ("127.0.0.0", "127.255.255.255", "RFC 1122 环回地址"),
    ("169.254.0.0", "169.254.255.255", "RFC 3927 链路本地"),
    ("0.0.0.0", "0.255.255.255", "RFC 1122 当前网络"),
    ("224.0.0.0", "239.255.255.255", "RFC 5771 多播地址"),
    ("240.0.0.0", "255.255.255.255", "RFC 1112 保留地址"),
]


async def execute_mcp_tool(agent: Any, tool_name: str, args: dict[str, Any]) -> str:
    """Execute a tool call via MCP manager or built-in tools."""
    if tool_name == "python_execute":
        return await execute_python(agent, args)

    if tool_name == "load_skill_reference":
        try:
            from vulnclaw.skills.loader import load_skill_reference

            skill_name = args.get("skill_name", "")
            ref_name = args.get("reference_name", "")
            content = load_skill_reference(skill_name, ref_name)
            if content:
                return content
            return f"[!] 参考文档未找到: {skill_name}/{ref_name}"
        except Exception as e:
            return f"[!] 加载参考文档错误: {e}"

    if tool_name == "nmap_scan":
        return await execute_nmap(agent, args)

    if tool_name == "crypto_decode":
        try:
            from vulnclaw.skills.crypto_tools import execute as crypto_execute

            operation = args.get("operation", "")
            input_str = args.get("input", "")
            kwargs: dict[str, Any] = {}
            for key in ("key", "iv", "shift", "secret", "header", "algorithm"):
                if key in args and args[key]:
                    kwargs[key] = args[key]
                    if key == "shift":
                        kwargs[key] = int(args[key])
            result = crypto_execute(operation=operation, input_str=input_str, **kwargs)
            if result.get("success"):
                return f"[✓] {operation} 结果:\n{result['result']}"
            return f"[!] {operation} 失败: {result.get('error', '未知错误')}"
        except Exception as e:
            return f"[!] 加密工具执行错误: {e}"

    if not agent.mcp_manager:
        return f"[!] MCP 管理器未初始化，无法执行工具: {tool_name}"

    try:
        result = await agent.mcp_manager.call_tool(tool_name, args)
        return str(result)
    except Exception as e:
        return f"[!] 工具执行错误 ({tool_name}): {e}"


def build_openai_tools(mcp_manager: Any) -> list[dict[str, Any]]:
    """Build OpenAI function calling schema from MCP tools + built-in tools."""
    tools: list[dict[str, Any]] = []

    tools.append({
        "type": "function",
        "function": {
            "name": "load_skill_reference",
            "description": "加载指定 Skill 的参考文档，获取详细的渗透测试方法论、工作流或命令参考。当系统提示中提到'可用参考文档'时，使用此工具获取具体内容。",
            "parameters": {
                "type": "object",
                "properties": {
                    "skill_name": {
                        "type": "string",
                        "description": "Skill 名称，如 client-reverse, web-security-advanced, ai-mcp-security, intranet-pentest-advanced, pentest-tools, rapid-checklist, crypto-toolkit, ctf-web, ctf-crypto, ctf-misc, osint-recon",
                    },
                    "reference_name": {
                        "type": "string",
                        "description": "参考文档文件名，如 02-client-api-reverse-and-burp.md, web-injection.md, encoding-cheatsheet.md",
                    },
                },
                "required": ["skill_name", "reference_name"],
            },
        },
    })

    tools.append({
        "type": "function",
        "function": {
            "name": "python_execute",
            "description": (
                "执行 Python 代码片段。用于：构造复杂 HTTP 请求并解析响应、"
                "做编码转换和数据处理、批量测试不同 payload、比较响应差异、"
                "执行数学计算等。代码在受限环境中执行，超时 30 秒。"
                "预装库：requests, beautifulsoup4, pycryptodome, base64, json, re 等。"
                "重要：构造 HTTP 请求时请使用此工具而非猜测响应内容。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "要执行的 Python 代码。支持多行，可 import 标准库和 requests/bs4 等。",
                    },
                    "purpose": {
                        "type": "string",
                        "description": "简要说明执行目的（用于审计日志），如'构造HTTP请求测试弱比较绕过'",
                    },
                },
                "required": ["code"],
            },
        },
    })

    tools.append({
        "type": "function",
        "function": {
            "name": "crypto_decode",
            "description": (
                "编码解码与加解密工具。遇到 base64/hex/URL/HTML/Unicode 编码字符串、"
                "需要计算哈希、解密 AES/DES、解析 JWT 等场景时调用此工具。"
                "重要：不要自行脑补解码结果，始终使用此工具确保准确性。"
                "支持操作：base64_encode/decode, base32_encode/decode, base58_encode/decode, "
                "hex_encode/decode, url_encode/decode, html_encode/decode, unicode_encode/decode, "
                "rot13_encode/decode, caesar_encode/decode, morse_encode/decode, "
                "md5_hash, sha1_hash, sha256_hash, sha512_hash, "
                "aes_encrypt/decrypt, jwt_decode/encode, auto_decode"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "operation": {"type": "string", "description": "操作名称"},
                    "input": {"type": "string", "description": "待处理的输入字符串（待编码/解码/哈希/加密的文本）"},
                    "key": {"type": "string", "description": "加密/解密密钥（AES/DES 需要，16/24/32字节）"},
                    "iv": {"type": "string", "description": "AES 初始化向量（16字节，可选）"},
                    "shift": {"type": "integer", "description": "Caesar 密码位移量（默认3，解码时不提供则暴力所有位移）"},
                    "secret": {"type": "string", "description": "JWT 签名密钥"},
                },
                "required": ["operation", "input"],
            },
        },
    })

    tools.append({
        "type": "function",
        "function": {
            "name": "nmap_scan",
            "description": (
                "nmap 网络端口扫描工具。信息收集时用于发现目标开放端口、服务版本和操作系统指纹。\n"
                "用法示例：\n"
                "  扫描常见端口: scan_type=top_ports, target=1.2.3.4\n"
                "  SYN扫描: scan_type=syn, target=1.2.3.4（需要管理员权限）\n"
                "  服务版本检测: scan_type=service, target=1.2.3.4\n"
                "  漏洞扫描: scan_type=vuln, target=1.2.3.4\n"
                "  全量扫描: scan_type=full, target=1.2.3.4\n"
                "优先使用 nmap_scan 而非 python_execute 构造 socket 扫描，nmap 更专业更准确。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标 IP 地址或域名（必填），如 192.168.1.1 或 scanme.nmap.org"},
                    "scan_type": {"type": "string", "description": "扫描类型：top_ports/syn/tcp/service/os/vuln/full"},
                    "ports": {"type": "string", "description": "指定端口或范围（可选），如 80,443,8080 或 1-1000"},
                    "timing": {"type": "integer", "description": "扫描速度模板 0-5（默认4），数字越大越快但越容易被检测"},
                },
                "required": ["target"],
            },
        },
    })

    if mcp_manager:
        for schema in mcp_manager.get_tool_schemas():
            tools.append({
                "type": "function",
                "function": {
                    "name": schema.get("name", ""),
                    "description": schema.get("description", ""),
                    "parameters": schema.get("inputSchema", {"type": "object", "properties": {}}),
                },
            })

    return tools


async def execute_nmap(agent: Any, args: dict[str, Any]) -> str:
    target = args.get("target", "").strip()
    if not target:
        return "[!] nmap_scan 需要 target 参数（目标 IP 或域名）"

    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        if ips:
            ip = ips[0][4][0]
            is_reserved, reason = is_reserved_ip(ip)
            if is_reserved:
                return (
                    f"[SKIP] 目标 {target} 解析到保留/内网地址 ({reason}, IP: {ip})\n"
                    f"跳过 nmap 扫描。建议直接通过 Web 指纹、目录枚举等方法收集信息，"
                    f"不要在保留地址上浪费轮次。"
                )
    except Exception:
        pass

    scan_type = args.get("scan_type", "top_ports")
    custom_ports = args.get("ports", "")
    timing = int(args.get("timing", 4))

    nmap_cmd = shutil.which("nmap")
    if not nmap_cmd:
        try:
            result = subprocess.run(["where.exe", "nmap"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                nmap_cmd = result.stdout.strip().split("\n")[0]
        except Exception:
            pass
    if not nmap_cmd:
        return "[!] nmap 未安装或不在 PATH 中。请确认 nmap 已安装并加入系统 PATH。"

    cmd = [nmap_cmd, "-v" if scan_type == "full" else "-q", f"-T{max(0, min(5, timing))}"]
    if scan_type == "top_ports":
        cmd.extend(["--top-ports", "100", "-oX", "-"])
    elif scan_type == "syn":
        cmd.extend(["-sS", "-oX", "-"])
    elif scan_type == "tcp":
        cmd.extend(["-sT", "-oX", "-"])
    elif scan_type == "service":
        cmd.extend(["-sV", "-oX", "-"])
    elif scan_type == "os":
        cmd.extend(["-O", "-oX", "-"])
    elif scan_type == "vuln":
        cmd.extend(["--script", "vuln", "-oX", "-"])
    elif scan_type == "full":
        cmd.extend(["-sS", "-O", "-sV", "--script", "default,safe", "-oX", "-"])
    else:
        cmd.extend(["-sV", "-oX", "-"])

    if custom_ports:
        cmd.extend(["-p", custom_ports])
    cmd.append(target)

    try:
        kwargs: dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "timeout": 120,
        }
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            kwargs["startupinfo"] = startupinfo
        result = subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired:
        return "[!] nmap 扫描超时（120秒），请减少扫描范围或使用更快的 timing"
    except PermissionError:
        return "[!] nmap 执行被拒绝（权限不足）。Windows 请以管理员身份运行终端。"
    except Exception as e:
        return f"[!] nmap 执行错误: {e}"

    if result.returncode != 0 and not result.stdout:
        return f"[!] nmap 扫描失败（{result.returncode}）: {result.stderr[:500]}"
    return parse_nmap_xml(result.stdout or result.stderr, target)


def is_reserved_ip(ip: str) -> tuple[bool, str]:
    try:
        import ipaddress

        addr = ipaddress.ip_address(ip)
        for start, end, desc in RESERVED_IP_RANGES:
            if ipaddress.ip_address(start) <= addr <= ipaddress.ip_address(end):
                return True, desc
        return False, ""
    except Exception:
        return False, ""


def validate_scan_target(target: str) -> str:
    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        if not ips:
            return ""
        ip = ips[0][4][0]
        is_reserved, reason = is_reserved_ip(ip)
        if is_reserved:
            return (
                f"\n\n⚠️ **警告：目标 {target} 解析到保留/内网地址 ({reason})\n"
                f"   IP: {ip}\n"
                f"   扫描此地址得到的结果不代表真实系统的安全状态。\n"
                f"   nmap 扫描结果中的端口信息可能与真实目标无关。**"
            )
    except Exception:
        pass
    return ""


def parse_nmap_xml(xml_output: str, target: str) -> str:
    if not xml_output or "<nmaprun" not in xml_output:
        lines = xml_output.strip().splitlines()[:80]
        return "nmap 原始输出:\n" + "\n".join(lines)

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        lines = xml_output.strip().splitlines()[:80]
        return "nmap 原始输出:\n" + "\n".join(lines)

    lines = [f"nmap 扫描结果 — {target}", "=" * 60]
    for host in root.findall(".//host"):
        hostname = host.find(".//hostname[@type='user']")
        addrs = [a.get("addr", "") for a in host.findall("address")]
        status = host.find("status")
        status_val = status.get("state", "unknown") if status is not None else "unknown"
        host_ip = addrs[0] if addrs else target
        reserved, reason = is_reserved_ip(host_ip)
        if reserved:
            host_str = f"\n[主机] {host_ip} ⚠️ **保留地址 ({reason})，测试网络结果不代表真实目标安全状态**"
        else:
            host_str = f"\n[主机] {host_ip}"
        if hostname is not None:
            host_str += f" ({hostname.get('name', '')})"
        host_str += f" — {status_val}"
        lines.append(host_str)

        for port in host.findall(".//port"):
            port_id = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            port_state = port.find("state")
            svc = port.find("service")
            state_val = port_state.get("state", "unknown") if port_state is not None else "unknown"
            svc_name = svc.get("name", "") if svc is not None else ""
            svc_product = svc.get("product", "") if svc is not None else ""
            svc_version = svc.get("version", "") if svc is not None else ""
            lines.append(
                f"  {proto.upper():5} {port_id}/{'s' if svc is not None and svc.get('tunnel') == 'ssl' else ''} "
                f"{state_val:8}{svc_name:15}{(svc_product + ' ' + svc_version).rstrip()}"
            )
            for script in port.findall("script"):
                lines.append(f"    | {script.get('id', '')}: {script.get('output', '')[:120]}")

    runstats = root.find(".//runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            elapsed = finished.get("elapsed", "")
            summary = finished.get("summary", "")
            lines.append(f"\n完成时间: {elapsed}s | {summary}")
    return "\n".join(lines) or f"nmap 扫描完成（无输出）: {target}"


async def execute_python(agent: Any, args: dict[str, Any]) -> str:
    code = args.get("code", "")
    purpose = args.get("purpose", "")
    if not code.strip():
        return "[!] 代码为空，未执行"

    if not getattr(agent.config, "safety", None) or not agent.config.safety.enable_python_execute:
        return "[!] python_execute 已被禁用。如需启用，请在配置中设置 safety.enable_python_execute = true"

    max_lines = getattr(getattr(agent.config, "safety", None), "python_execute_max_lines", 50)
    if code.count("\n") + 1 > max_lines:
        return f"[!] 代码行数超过限制（{max_lines} 行），请拆分或精简脚本"

    show_warning = getattr(getattr(agent.config, "safety", None), "python_execute_show_warning", True)
    warning_prefix = ""
    if show_warning:
        warning_prefix = (
            "⚠️ 安全警告：python_execute 将在本地以当前用户权限执行 Python 代码。\n"
            "请确保你信任此命令的来源，且代码不会破坏系统或泄露敏感数据。\n"
            "---\n"
        )

    recon_keywords = ["recon", "信息收集", "侦察", "枚举", "扫描", "crawl", "spider", "目录", "子域名", "端口", "指纹", "收集"]
    timeout_seconds = 60 if any(kw in purpose.lower() for kw in recon_keywords) else 30

    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, code):
            return f"[!] 代码包含被禁止的操作模式: {pattern}，出于安全原因拒绝执行"

    restricted = getattr(getattr(agent.config, "safety", None), "python_execute_restricted", False)
    if restricted:
        restricted_patterns = [
            r"open\s*\(",
            r"with\s+open\s*\(",
            r"socket\.",
            r"urllib",
            r"http\.client",
            r"ftplib",
            r"smtplib",
            r"import\s+os",
            r"from\s+os\s+import",
            r"import\s+subprocess",
            r"from\s+subprocess\s+import",
            r"import\s+shutil",
            r"from\s+shutil\s+import",
            r"__import__",
        ]
        for pattern in restricted_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return f"[!] 受限模式下禁止的操作: {pattern}\n提示：如需执行文件/网络操作，请关闭 restricted 模式或改用其他工具。"

    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            preamble = (
                "import sys, json, re, os, base64, hashlib, itertools, collections, datetime, struct, binascii, textwrap\n"
                "try:\n    import requests\nexcept ImportError:\n    pass\n"
                "try:\n    from bs4 import BeautifulSoup\nexcept ImportError:\n    pass\n"
                "try:\n    from Crypto.Cipher import AES\nexcept ImportError:\n    pass\n\n"
            )
            f.write(preamble)
            f.write(code)
            tmp_path = f.name

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                [sys.executable, tmp_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                cwd=tempfile.gettempdir(),
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            ),
        )

        try:
            os.unlink(tmp_path)
        except OSError:
            pass

        output_parts: list[str] = []
        if result.stdout:
            output_parts.append(result.stdout)
        if result.stderr:
            stderr_lines = [line for line in result.stderr.splitlines() if "ImportError" not in line and "No module named" not in line]
            if stderr_lines:
                output_parts.append("[stderr]\n" + "\n".join(stderr_lines))

        if not output_parts:
            return "[✓] 代码执行成功，无输出"

        output = "\n".join(output_parts)
        for sig in ["[DONE]", "[COMPLETE]"]:
            output = output.replace(sig, f"[BLOCKED_{sig[1:-1]}]")
        if len(output) > 8000:
            output = output[:4000] + "\n...[中间省略]...\n" + output[-4000:]
        return f"{warning_prefix}[✓] Python 执行结果:\n{output}"
    except subprocess.TimeoutExpired:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        agent.runtime.python_timeout_rounds += 1
        return f"[!] Python 执行超时（{timeout_seconds}秒），请简化代码或分步执行，禁止写超过10行的复杂脚本"
    except Exception as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return f"[!] Python 执行错误: {e}"
