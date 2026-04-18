"""VulnClaw MCP Registry — service metadata and tool registration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


class MCPToolSchema(BaseModel):
    """Schema for a single MCP tool."""

    name: str = Field(description="Tool name")
    description: str = Field(default="", description="Tool description")
    input_schema: dict[str, Any] = Field(
        default_factory=lambda: {"type": "object", "properties": {}},
        description="JSON Schema for tool input",
    )
    server_name: str = Field(description="Owning MCP server name")


class MCPServerState(BaseModel):
    """Runtime state of an MCP server."""

    name: str
    running: bool = False
    pid: Optional[int] = None
    tools: list[str] = Field(default_factory=list)
    error: Optional[str] = None
    started_at: Optional[str] = None


class MCPRegistry:
    """Central registry for MCP servers and their tools.

    Maintains:
    - Server configurations and metadata
    - Tool schemas from each server
    - Runtime state (running/stopped, health)
    """

    def __init__(self) -> None:
        self._servers: dict[str, MCPServerState] = {}
        self._tools: dict[str, MCPToolSchema] = {}  # tool_name -> schema
        self._server_tools: dict[str, list[str]] = {}  # server_name -> [tool_names]

    def register_server(self, name: str) -> None:
        """Register a new MCP server."""
        if name not in self._servers:
            self._servers[name] = MCPServerState(name=name)
            self._server_tools[name] = []

    def set_server_running(self, name: str, running: bool, pid: Optional[int] = None) -> None:
        """Update server running state."""
        if name in self._servers:
            self._servers[name].running = running
            self._servers[name].pid = pid
            if running:
                from datetime import datetime
                self._servers[name].started_at = datetime.now().isoformat()

    def set_server_error(self, name: str, error: str) -> None:
        """Record a server error."""
        if name in self._servers:
            self._servers[name].error = error

    def register_tool(self, server_name: str, tool_schema: dict[str, Any]) -> None:
        """Register a tool from an MCP server."""
        tool_name = tool_schema.get("name", "")
        if not tool_name:
            return

        schema = MCPToolSchema(
            name=tool_name,
            description=tool_schema.get("description", ""),
            input_schema=tool_schema.get("inputSchema", {"type": "object", "properties": {}}),
            server_name=server_name,
        )

        self._tools[tool_name] = schema
        if server_name not in self._server_tools:
            self._server_tools[server_name] = []
        if tool_name not in self._server_tools[server_name]:
            self._server_tools[server_name].append(tool_name)

        # Update server state
        if server_name in self._servers:
            self._servers[server_name].tools = self._server_tools[server_name]

    def unregister_server(self, name: str) -> None:
        """Remove a server and all its tools."""
        if name in self._server_tools:
            for tool_name in self._server_tools[name]:
                self._tools.pop(tool_name, None)
            del self._server_tools[name]
        self._servers.pop(name, None)

    def get_tool_schema(self, tool_name: str) -> Optional[MCPToolSchema]:
        """Get the schema for a specific tool."""
        return self._tools.get(tool_name)

    def get_all_tool_schemas(self) -> list[dict[str, Any]]:
        """Get all tool schemas in OpenAI function-calling format."""
        return [
            {
                "name": schema.name,
                "description": schema.description,
                "inputSchema": schema.input_schema,
            }
            for schema in self._tools.values()
        ]

    def get_server_for_tool(self, tool_name: str) -> Optional[str]:
        """Find which server owns a tool."""
        schema = self._tools.get(tool_name)
        return schema.server_name if schema else None

    def get_server_tools(self, server_name: str) -> list[str]:
        """Get all tool names for a server."""
        return self._server_tools.get(server_name, [])

    def get_running_servers(self) -> list[str]:
        """Get names of all running servers."""
        return [name for name, state in self._servers.items() if state.running]

    def get_all_servers(self) -> dict[str, MCPServerState]:
        """Get all server states."""
        return self._servers.copy()

    @property
    def tool_count(self) -> int:
        """Total number of registered tools."""
        return len(self._tools)

    @property
    def server_count(self) -> int:
        """Total number of registered servers."""
        return len(self._servers)
