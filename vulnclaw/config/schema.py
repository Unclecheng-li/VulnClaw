"""VulnClaw configuration schema — Pydantic models for type-safe config."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── LLM Provider Presets ────────────────────────────────────────────

class LLMProvider(str, Enum):
    """Supported LLM providers with OpenAI-compatible APIs."""

    OPENAI = "openai"
    MINIMAX = "minimax"
    DEEPSEEK = "deepseek"
    ZHIPU = "zhipu"
    MOONSHOT = "moonshot"
    QWEN = "qwen"
    SILICONFLOW = "siliconflow"
    CUSTOM = "custom"


# Provider preset definitions: base_url + default_model + notes
PROVIDER_PRESETS: dict[LLMProvider, dict[str, str]] = {
    LLMProvider.OPENAI: {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o",
        "label": "OpenAI",
    },
    LLMProvider.MINIMAX: {
        "base_url": "https://api.minimaxi.com/v1",
        "default_model": "MiniMax-M2.7",
        "label": "MiniMax",
    },
    LLMProvider.DEEPSEEK: {
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "label": "DeepSeek",
    },
    LLMProvider.ZHIPU: {
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "default_model": "glm-4-plus",
        "label": "智谱 GLM",
    },
    LLMProvider.MOONSHOT: {
        "base_url": "https://api.moonshot.cn/v1",
        "default_model": "moonshot-v1-128k",
        "label": "Moonshot (月之暗面)",
    },
    LLMProvider.QWEN: {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "default_model": "qwen-max",
        "label": "通义千问",
    },
    LLMProvider.SILICONFLOW: {
        "base_url": "https://api.siliconflow.cn/v1",
        "default_model": "deepseek-ai/DeepSeek-V3",
        "label": "SiliconFlow",
    },
    LLMProvider.CUSTOM: {
        "base_url": "",
        "default_model": "",
        "label": "自定义",
    },
}


class LLMConfig(BaseModel):
    """LLM provider configuration."""

    provider: str = Field(
        default="openai",
        description="LLM provider name (openai/minimax/deepseek/zhipu/moonshot/qwen/siliconflow/custom)",
    )
    api_key: str = Field(default="", description="API key for the chosen provider")
    base_url: str = Field(
        default="https://api.openai.com/v1",
        description="OpenAI-compatible API base URL (auto-filled by provider)",
    )
    model: str = Field(default="gpt-4o", description="Model name to use (auto-filled by provider)")
    max_tokens: int = Field(default=4096, description="Max tokens per response")
    temperature: float = Field(default=0.1, description="Sampling temperature")
    reasoning_effort: str = Field(default="high", description="Reasoning effort level (OpenAI o-series only)")


class MCPTransportConfig(BaseModel):
    """MCP server transport configuration."""

    type: str = Field(description="Transport type: stdio, sse")
    command: Optional[str] = Field(default=None, description="Command to start the server (stdio)")
    args: Optional[list[str]] = Field(default=None, description="Command arguments")
    url: Optional[str] = Field(default=None, description="Server URL (sse)")
    env: Optional[dict[str, str]] = Field(default=None, description="Environment variables")
    startup_timeout: int = Field(default=30000, description="Startup timeout in ms")
    tool_timeout: int = Field(default=300000, description="Tool call timeout in ms")


class MCPServerConfig(BaseModel):
    """Single MCP server configuration."""

    name: str = Field(description="Server identifier")
    enabled: bool = Field(default=True, description="Whether to auto-start this server")
    priority: int = Field(default=1, description="Priority: 0=critical, 1=normal, 2=optional")
    transport: MCPTransportConfig = Field(description="Transport configuration")
    description: str = Field(default="", description="Human-readable description")


class MCPServersConfig(BaseModel):
    """All MCP servers configuration."""

    servers: dict[str, MCPServerConfig] = Field(default_factory=dict)


class SessionConfig(BaseModel):
    """Session / output configuration."""

    output_dir: Path = Field(default=Path("./vulnclaw-output"), description="Output directory")
    auto_save: bool = Field(default=True, description="Auto-save session state")
    report_format: str = Field(default="markdown", description="Default report format: markdown, html")
    poc_language: str = Field(default="python", description="Default PoC language: python, bash")
    max_rounds: int = Field(default=15, description="Max autonomous pentest rounds (1-100)")


class VulnClawConfig(BaseModel):
    """Top-level VulnClaw configuration."""

    llm: LLMConfig = Field(default_factory=LLMConfig)
    mcp: MCPServersConfig = Field(default_factory=MCPServersConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)

    class Config:
        env_prefix = "VULNCLAW_"
        env_nested_delimiter = "__"


# ── Built-in MCP server definitions (MVP) ──────────────────────────

BUILTIN_MCP_SERVERS: dict[str, dict[str, Any]] = {
    "fetch": {
        "name": "fetch",
        "enabled": True,
        "priority": 0,
        "description": "HTTP request tool for API testing & web interaction",
        "transport": {
            "type": "stdio",
            "command": "uvx",
            "args": ["mcp-server-fetch"],
        },
    },
    "memory": {
        "name": "memory",
        "enabled": True,
        "priority": 0,
        "description": "Context memory & session state persistence",
        "transport": {
            "type": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-memory"],
        },
    },
    "chrome-devtools": {
        "name": "chrome-devtools",
        "enabled": False,
        "priority": 0,
        "description": "Browser automation for Web app pentest",
        "transport": {
            "type": "stdio",
            "command": "npx",
            "args": ["-y", "chrome-devtools-mcp@latest"],
        },
    },
    "js-reverse": {
        "name": "js-reverse",
        "enabled": False,
        "priority": 0,
        "description": "JavaScript reverse engineering with anti-detection",
        "transport": {
            "type": "stdio",
            "command": "npx",
            "args": ["js-reverse-mcp"],
        },
    },
    "burp": {
        "name": "burp",
        "enabled": False,
        "priority": 0,
        "description": "Burp Suite proxy integration for HTTP interception",
        "transport": {
            "type": "stdio",
            "command": "java",
            "args": ["-jar", "mcp-proxy.jar", "--sse-url", "http://127.0.0.1:9876"],
        },
    },
    "frida-mcp": {
        "name": "frida-mcp",
        "enabled": False,
        "priority": 1,
        "description": "Frida dynamic instrumentation for mobile pentest",
        "transport": {
            "type": "stdio",
            "command": "python",
            "args": ["frida_mcp.py"],
        },
    },
    "adb-mcp": {
        "name": "adb-mcp",
        "enabled": False,
        "priority": 1,
        "description": "ADB device control for Android pentest",
        "transport": {
            "type": "stdio",
            "command": "python",
            "args": ["adb-mcp/server.py"],
        },
    },
    "jadx": {
        "name": "jadx",
        "enabled": False,
        "priority": 1,
        "description": "APK decompilation via JADX",
        "transport": {
            "type": "sse",
            "url": "http://localhost:8651/mcp",
        },
    },
    "ida-pro-mcp": {
        "name": "ida-pro-mcp",
        "enabled": False,
        "priority": 1,
        "description": "IDA Pro reverse engineering assistant",
        "transport": {
            "type": "stdio",
            "command": "python",
            "args": ["ida_pro_mcp/server.py"],
        },
    },
    "sequential-thinking": {
        "name": "sequential-thinking",
        "enabled": False,
        "priority": 1,
        "description": "Complex reasoning chain for multi-step analysis",
        "transport": {
            "type": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-sequential-thinking"],
        },
    },
    "context7": {
        "name": "context7",
        "enabled": False,
        "priority": 1,
        "description": "Code & documentation context retrieval",
        "transport": {
            "type": "stdio",
            "command": "npx",
            "args": ["-y", "@upstash/context7-mcp"],
        },
    },
    "everything-search": {
        "name": "everything-search",
        "enabled": False,
        "priority": 2,
        "description": "Local file search (Windows Everything integration)",
        "transport": {
            "type": "stdio",
            "command": "node",
            "args": ["everything-mcp/index.js"],
        },
    },
}
