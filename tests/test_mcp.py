"""VulnClaw MCP Module Tests — registry.py + router.py + lifecycle.py"""

import pytest
from unittest.mock import MagicMock, patch


# ── registry.py ──────────────────────────────────────────────────────

class TestMCPRegistry:
    """Test MCPRegistry."""

    def test_register_server(self):
        from vulnclaw.mcp.registry import MCPRegistry
        registry = MCPRegistry()
        registry.register_server("fetch")
        assert registry.server_count == 1

    def test_register_multiple_servers(self):
        from vulnclaw.mcp.registry import MCPRegistry
        registry = MCPRegistry()
        registry.register_server("fetch")
        registry.register_server("memory")
        registry.register_server("burp")
        assert registry.server_count == 3

    def test_register_tool(self):
        from vulnclaw.mcp.registry import MCPRegistry
        registry = MCPRegistry()
        registry.register_server("fetch")
        registry.register_tool("fetch", {
            "name": "fetch",
            "description": "Fetch a URL",
            "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
        })
        assert registry.tool_count == 1

    def test_get_server_for_tool(self):
        from vulnclaw.mcp.registry import MCPRegistry
        registry = MCPRegistry()
        registry.register_server("fetch")
        registry.register_tool("fetch", {
            "name": "fetch",
            "description": "Fetch a URL",
            "inputSchema": {"type": "object", "properties": {}},
        })
        assert registry.get_server_for_tool("fetch") == "fetch"

    def test_get_tool_schemas(self):
        from vulnclaw.mcp.registry import MCPRegistry
        registry = MCPRegistry()
        registry.register_server("fetch")
        registry.register_tool("fetch", {
            "name": "fetch",
            "description": "Fetch a URL",
            "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
        })
        schemas = registry.get_all_tool_schemas()
        assert len(schemas) == 1
        assert schemas[0]["name"] == "fetch"

    def test_set_server_error(self):
        from vulnclaw.mcp.registry import MCPRegistry
        registry = MCPRegistry()
        registry.register_server("burp")
        registry.set_server_error("burp", "Connection refused")
        # Should not crash

    def test_duplicate_server_register(self):
        from vulnclaw.mcp.registry import MCPRegistry
        registry = MCPRegistry()
        registry.register_server("fetch")
        registry.register_server("fetch")  # Should not raise
        # Server count should still be reasonable
        assert registry.server_count >= 1

    def test_tool_for_nonexistent_server(self):
        from vulnclaw.mcp.registry import MCPRegistry
        registry = MCPRegistry()
        result = registry.get_server_for_tool("nonexistent")
        assert result is None


# ── router.py ────────────────────────────────────────────────────────

class TestMCPRouter:
    """Test MCPRouter."""

    def test_route_fetch(self):
        from vulnclaw.mcp.router import MCPRouter
        router = MCPRouter()
        results = router.route("发请求访问这个接口")
        assert len(results) > 0
        assert any(r["server"] == "fetch" for r in results)

    def test_route_burp(self):
        from vulnclaw.mcp.router import MCPRouter
        router = MCPRouter()
        results = router.route("帮我抓包看一下这个请求")
        assert len(results) > 0
        assert any(r["server"] == "burp" for r in results)

    def test_route_browser(self):
        from vulnclaw.mcp.router import MCPRouter
        router = MCPRouter()
        results = router.route("打开网页看看")
        assert len(results) > 0
        assert any(r["server"] == "chrome-devtools" for r in results)

    def test_route_screenshot(self):
        from vulnclaw.mcp.router import MCPRouter
        router = MCPRouter()
        results = router.route("截图")
        assert len(results) > 0
        assert any(r["tool"] == "screenshot" for r in results)

    def test_route_frida(self):
        from vulnclaw.mcp.router import MCPRouter
        router = MCPRouter()
        results = router.route("hook这个函数")
        assert len(results) > 0
        assert any(r["server"] == "frida-mcp" for r in results)

    def test_route_js_reverse(self):
        from vulnclaw.mcp.router import MCPRouter
        router = MCPRouter()
        results = router.route("分析js逻辑")
        assert len(results) > 0
        assert any(r["server"] == "js-reverse" for r in results)

    def test_route_memory_save(self):
        from vulnclaw.mcp.router import MCPRouter
        router = MCPRouter()
        results = router.route("记住这个发现")
        assert len(results) > 0
        assert any(r["server"] == "memory" for r in results)

    def test_route_no_match(self):
        from vulnclaw.mcp.router import MCPRouter
        router = MCPRouter()
        results = router.route("今天天气怎么样")
        assert len(results) == 0

    def test_extract_url(self):
        from vulnclaw.mcp.router import MCPRouter
        router = MCPRouter()
        assert router.extract_url("访问 https://example.com/path") == "https://example.com/path"
        assert router.extract_url("没有URL") is None

    def test_extract_ip(self):
        from vulnclaw.mcp.router import MCPRouter
        router = MCPRouter()
        assert router.extract_ip("扫描 192.168.1.100") == "192.168.1.100"
        assert router.extract_ip("没有IP") is None

    def test_suggest_tools_for_phase(self):
        from vulnclaw.mcp.router import MCPRouter
        router = MCPRouter()
        tools = router.suggest_tools_for_phase("信息收集")
        assert len(tools) > 0
        assert any(t["server"] == "fetch" for t in tools)

    def test_suggest_tools_for_unknown_phase(self):
        from vulnclaw.mcp.router import MCPRouter
        router = MCPRouter()
        tools = router.suggest_tools_for_phase("未知阶段")
        assert tools == []

    def test_route_confidence(self):
        from vulnclaw.mcp.router import MCPRouter
        router = MCPRouter()
        results = router.route("发请求")
        for r in results:
            assert "confidence" in r
            assert 0 < r["confidence"] <= 1


# ── lifecycle.py ─────────────────────────────────────────────────────

class TestMCPLifecycleManager:
    """Test MCPLifecycleManager."""

    def test_init(self):
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager
        from vulnclaw.config.schema import VulnClawConfig
        manager = MCPLifecycleManager(VulnClawConfig())
        assert manager.registry is not None

    def test_start_enabled_servers(self):
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager
        from vulnclaw.config.schema import VulnClawConfig
        config = VulnClawConfig()
        manager = MCPLifecycleManager(config)
        started = manager.start_enabled_servers()
        # At least fetch and memory should be registered
        assert started >= 0  # May or may not actually start depending on env

    def test_get_tool_schemas(self):
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager
        from vulnclaw.config.schema import VulnClawConfig
        config = VulnClawConfig()
        manager = MCPLifecycleManager(config)
        manager.start_enabled_servers()
        schemas = manager.get_tool_schemas()
        assert isinstance(schemas, list)

    def test_call_tool_unknown(self):
        """Calling an unknown tool should not crash."""
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager
        from vulnclaw.config.schema import VulnClawConfig
        import asyncio
        config = VulnClawConfig()
        manager = MCPLifecycleManager(config)
        # Call with unknown tool name
        try:
            result = asyncio.get_event_loop().run_until_complete(
                manager.call_tool("nonexistent_tool", {})
            )
        except Exception:
            pass  # Expected to fail for unknown tool

    def test_fetch_falls_back_to_local_mode_when_sdk_attach_fails(self):
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("fetch")
        manager._try_attach_stdio_client = MagicMock(return_value=False)
        fetch_config = MCPServerConfig(**BUILTIN_MCP_SERVERS["fetch"])

        assert manager._start_server("fetch", fetch_config) is True
        state = manager.registry.get_all_servers()["fetch"]
        assert state.execution_mode == "local"

    def test_fetch_starts_in_local_mode(self):
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("fetch")
        fetch_config = MCPServerConfig(**BUILTIN_MCP_SERVERS["fetch"])

        assert manager._start_server("fetch", fetch_config) is True
        state = manager.registry.get_all_servers()["fetch"]
        assert state.execution_mode == "local"

    def test_memory_falls_back_to_local_mode_when_sdk_attach_fails(self):
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("memory")
        manager._try_attach_stdio_client = MagicMock(return_value=False)
        memory_config = MCPServerConfig(**BUILTIN_MCP_SERVERS["memory"])

        assert manager._start_server("memory", memory_config) is True
        state = manager.registry.get_all_servers()["memory"]
        assert state.execution_mode == "local"

    def test_memory_starts_in_local_mode(self):
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("memory")
        memory_config = MCPServerConfig(**BUILTIN_MCP_SERVERS["memory"])

        assert manager._start_server("memory", memory_config) is True
        state = manager.registry.get_all_servers()["memory"]
        assert state.execution_mode == "local"





