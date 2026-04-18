"""VulnClaw MCP Lifecycle Manager — start/stop MCP servers and manage their lifetime."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from typing import Any, Optional

from vulnclaw.config.schema import VulnClawConfig, MCPServerConfig
from vulnclaw.mcp.registry import MCPRegistry


class MCPLifecycleManager:
    """Manages the lifecycle of MCP servers: start, stop, health check.

    For MVP, we use subprocess-based MCP communication.
    In later versions, this will use the Python MCP SDK for proper protocol handling.
    """

    def __init__(self, config: VulnClawConfig) -> None:
        self.config = config
        self.registry = MCPRegistry()
        self._processes: dict[str, subprocess.Popen] = {}
        self._mcp_clients: dict[str, Any] = {}  # Future: MCP Client instances

    def start_enabled_servers(self) -> int:
        """Start all enabled MCP servers.

        Returns the number of servers successfully started.
        """
        started = 0
        for name, server_config in self.config.mcp.servers.items():
            if server_config.enabled:
                self.registry.register_server(name)
                try:
                    if self._start_server(name, server_config):
                        started += 1
                except Exception as e:
                    self.registry.set_server_error(name, str(e))
        return started

    def _start_server(self, name: str, config: MCPServerConfig) -> bool:
        """Start a single MCP server.

        For MVP, we just register the server and its known tools.
        Actual process management will be enhanced with MCP SDK.
        """
        transport = config.transport

        if transport.type == "stdio":
            # Register the server — actual subprocess launch deferred to MCP SDK
            self.registry.set_server_running(name, running=True)
            self._register_known_tools(name)
            return True

        elif transport.type == "sse":
            # SSE servers are assumed to be already running
            self.registry.set_server_running(name, running=True)
            self._register_known_tools(name)
            return True

        return False

    def _register_known_tools(self, server_name: str) -> None:
        """Register known tools for a server based on its type.

        This is a temporary approach for MVP. In production, tools will be
        discovered dynamically via the MCP protocol.
        """
        KNOWN_TOOLS: dict[str, list[dict]] = {
            "fetch": [
                {
                    "name": "fetch",
                    "description": "Fetch a URL and return the content",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL to fetch"},
                            "method": {"type": "string", "description": "HTTP method", "default": "GET"},
                            "headers": {"type": "object", "description": "HTTP headers"},
                            "body": {"type": "string", "description": "Request body"},
                        },
                        "required": ["url"],
                    },
                },
            ],
            "memory": [
                {
                    "name": "save",
                    "description": "Save information to persistent memory",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string", "description": "Memory key"},
                            "value": {"type": "string", "description": "Memory value"},
                        },
                        "required": ["key", "value"],
                    },
                },
                {
                    "name": "retrieve",
                    "description": "Retrieve information from persistent memory",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string", "description": "Memory key to retrieve"},
                        },
                        "required": ["key"],
                    },
                },
            ],
            "chrome-devtools": [
                {
                    "name": "new_page",
                    "description": "Open a new browser page",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL to navigate to"},
                        },
                    },
                },
                {
                    "name": "navigate",
                    "description": "Navigate to a URL in the current page",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL to navigate to"},
                        },
                        "required": ["url"],
                    },
                },
                {
                    "name": "screenshot",
                    "description": "Take a screenshot of the current page",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "evaluate_js",
                    "description": "Evaluate JavaScript in the browser",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "expression": {"type": "string", "description": "JS expression to evaluate"},
                        },
                        "required": ["expression"],
                    },
                },
            ],
            "js-reverse": [
                {
                    "name": "analyze_js",
                    "description": "Analyze JavaScript code for security-relevant patterns",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL of the JS file to analyze"},
                            "code": {"type": "string", "description": "Raw JS code to analyze"},
                        },
                    },
                },
                {
                    "name": "extract_endpoints",
                    "description": "Extract API endpoints from JavaScript",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL of the page to extract endpoints from"},
                        },
                        "required": ["url"],
                    },
                },
            ],
            "burp": [
                {
                    "name": "send_http1_request",
                    "description": "Send an HTTP/1 request through Burp proxy",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "method": {"type": "string", "description": "HTTP method"},
                            "url": {"type": "string", "description": "Target URL"},
                            "headers": {"type": "object", "description": "Request headers"},
                            "body": {"type": "string", "description": "Request body"},
                        },
                        "required": ["method", "url"],
                    },
                },
                {
                    "name": "get_proxy_history",
                    "description": "Get proxy history from Burp",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
            "frida-mcp": [
                {
                    "name": "frida_attach",
                    "description": "Attach Frida to a running process",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "process": {"type": "string", "description": "Process name or PID"},
                            "script": {"type": "string", "description": "Frida script to inject"},
                        },
                        "required": ["process", "script"],
                    },
                },
                {
                    "name": "frida_spawn",
                    "description": "Spawn an app with Frida attached",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "package": {"type": "string", "description": "App package name"},
                            "script": {"type": "string", "description": "Frida script to inject"},
                        },
                        "required": ["package", "script"],
                    },
                },
            ],
            "adb-mcp": [
                {
                    "name": "adb_tap",
                    "description": "Tap on screen coordinates via ADB",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "x": {"type": "integer", "description": "X coordinate"},
                            "y": {"type": "integer", "description": "Y coordinate"},
                        },
                        "required": ["x", "y"],
                    },
                },
                {
                    "name": "adb_screenshot",
                    "description": "Take a screenshot via ADB",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "adb_shell",
                    "description": "Execute shell command on Android device",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string", "description": "Shell command to execute"},
                        },
                        "required": ["command"],
                    },
                },
            ],
            "jadx": [
                {
                    "name": "decompile",
                    "description": "Decompile an APK file",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "apk_path": {"type": "string", "description": "Path to APK file"},
                        },
                        "required": ["apk_path"],
                    },
                },
                {
                    "name": "get_source",
                    "description": "Get decompiled source code for a class",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "class_name": {"type": "string", "description": "Fully qualified class name"},
                        },
                        "required": ["class_name"],
                    },
                },
            ],
            "ida-pro-mcp": [
                {
                    "name": "decompile_function",
                    "description": "Decompile a function in IDA Pro",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "address": {"type": "string", "description": "Function address"},
                        },
                        "required": ["address"],
                    },
                },
                {
                    "name": "get_xrefs",
                    "description": "Get cross-references to an address",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "address": {"type": "string", "description": "Address to find xrefs for"},
                        },
                        "required": ["address"],
                    },
                },
            ],
            "sequential-thinking": [
                {
                    "name": "sequential_thinking",
                    "description": "Use structured sequential thinking for complex analysis",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "thought": {"type": "string", "description": "Current thought step"},
                            "next_step": {"type": "string", "description": "What to think about next"},
                        },
                        "required": ["thought"],
                    },
                },
            ],
            "context7": [
                {
                    "name": "resolve_library_id",
                    "description": "Resolve a library name to its context7 ID",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "library_name": {"type": "string", "description": "Name of the library"},
                        },
                        "required": ["library_name"],
                    },
                },
            ],
            "everything-search": [
                {
                    "name": "search_files",
                    "description": "Search for files on the local system",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "Search query"},
                            "max_results": {"type": "integer", "description": "Max results to return"},
                        },
                        "required": ["query"],
                    },
                },
            ],
        }

        tools = KNOWN_TOOLS.get(server_name, [])
        for tool in tools:
            self.registry.register_tool(server_name, tool)

    def stop_server(self, name: str) -> None:
        """Stop a single MCP server."""
        if name in self._processes:
            try:
                self._processes[name].terminate()
                self._processes[name].wait(timeout=5)
            except Exception:
                try:
                    self._processes[name].kill()
                except Exception:
                    pass
            del self._processes[name]

        self.registry.set_server_running(name, running=False)

    def stop_all(self) -> None:
        """Stop all running MCP servers."""
        for name in list(self._processes.keys()):
            self.stop_server(name)

        for name in self.registry.get_running_servers():
            self.registry.set_server_running(name, running=False)

    def running_count(self) -> int:
        """Number of currently running servers."""
        return len(self.registry.get_running_servers())

    def list_available_tools(self) -> list[str]:
        """List all available tool names."""
        return [schema.name for schema in
                [self.registry.get_tool_schema(n) for n in
                 [t for server_tools in self.registry._server_tools.values() for t in server_tools]]
                if schema is not None]

    def get_tool_schemas(self) -> list[dict[str, Any]]:
        """Get all tool schemas for LLM function calling."""
        return self.registry.get_all_tool_schemas()

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        """Call an MCP tool by name.

        For MVP, this uses direct subprocess/httpx calls.
        In later versions, this will use proper MCP protocol.
        """
        server_name = self.registry.get_server_for_tool(tool_name)
        if not server_name:
            raise ValueError(f"Unknown tool: {tool_name}")

        # Route to appropriate handler
        if server_name == "fetch" and tool_name == "fetch":
            return await self._call_fetch(arguments)
        elif server_name == "memory":
            return await self._call_memory(tool_name, arguments)
        elif server_name == "chrome-devtools":
            return await self._call_chrome(tool_name, arguments)
        elif server_name == "burp":
            return await self._call_burp(tool_name, arguments)
        else:
            # Generic: try to forward via MCP protocol
            return f"[!] MCP 工具 '{tool_name}' 尚未实现直接调用，请通过 shell 执行"

    async def _call_fetch(self, args: dict) -> str:
        """Execute a fetch request using httpx."""
        try:
            import httpx
            url = args.get("url", "")
            method = args.get("method", "GET").upper()
            headers = args.get("headers", {})
            body = args.get("body")

            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body,
                )

            result = f"Status: {response.status_code}\n"
            result += f"Headers: {dict(response.headers)}\n"
            result += f"Body (first 2000 chars): {response.text[:2000]}"
            return result

        except ImportError:
            return "[!] httpx 未安装，无法执行 fetch 请求"
        except Exception as e:
            return f"[!] fetch 请求失败: {e}"

    async def _call_memory(self, tool_name: str, args: dict) -> str:
        """Execute a memory tool call (local implementation)."""
        from vulnclaw.agent.memory import MemoryStore
        store = MemoryStore()

        if tool_name == "save":
            store.save(args.get("key", ""), args.get("value", ""))
            return f"[+] 已保存: {args.get('key', '')}"
        elif tool_name == "retrieve":
            value = store.retrieve(args.get("key", ""))
            return str(value) if value else "[-] 未找到"
        return "[!] 未知 memory 工具"

    async def _call_chrome(self, tool_name: str, args: dict) -> str:
        """Execute a Chrome DevTools tool call."""
        # For MVP, provide guidance rather than actual execution
        return f"[→] Chrome DevTools 工具 '{tool_name}' 需要启动 chrome-devtools-mcp 服务"

    async def _call_burp(self, tool_name: str, args: dict) -> str:
        """Execute a Burp Suite tool call."""
        return f"[→] Burp Suite 工具 '{tool_name}' 需要启动 Burp MCP 服务"
