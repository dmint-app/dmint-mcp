"""Downstream MCP client connection abstraction."""

from __future__ import annotations

import os
from contextlib import AsyncExitStack
from typing import Any

import mcp.types as types
from mcp import ClientSession, StdioServerParameters, stdio_client

from .errors import MCPConnectionError, MCPError, MCPProtocolError
from .config import MCPIntegrationConfig, MCPTransportType


class DownstreamMCPClient:
    """Connection layer managing communication with one downstream MCP server."""

    def __init__(self, config: MCPIntegrationConfig) -> None:
        if type(config) is not MCPIntegrationConfig:
            raise TypeError("config must be an MCPIntegrationConfig")
        self._config = config
        self._exit_stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    @property
    def config(self) -> MCPIntegrationConfig:
        return self._config

    @property
    def is_connected(self) -> bool:
        return self._session is not None

    async def connect(self) -> None:
        """Connect to downstream MCP server, run session handshake and initialize."""
        if self.is_connected:
            return

        if self._config.transport_type != MCPTransportType.STDIO:
            raise MCPConnectionError(f"unsupported transport: {self._config.transport_type}")

        env = dict(os.environ)
        if self._config.env:
            env.update(self._config.env)

        server_params = StdioServerParameters(
            command=self._config.command,
            args=list(self._config.args),
            env=env,
            cwd=self._config.cwd,
        )

        stack = AsyncExitStack()
        try:
            read_stream, write_stream = await stack.enter_async_context(stdio_client(server_params))
            session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
            await session.initialize()
            self._exit_stack = stack
            self._session = session
        except Exception as exc:
            await stack.aclose()
            self._exit_stack = None
            self._session = None
            raise MCPConnectionError("could not connect or initialize downstream MCP server") from exc

    async def disconnect(self) -> None:
        """Disconnect and cleanup downstream streams and process context."""
        if self._exit_stack is not None:
            try:
                await self._exit_stack.aclose()
            except Exception:
                pass
            finally:
                self._exit_stack = None
                self._session = None

    async def __aenter__(self) -> "DownstreamMCPClient":
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.disconnect()

    def _require_session(self) -> ClientSession:
        if self._session is None:
            raise MCPConnectionError("downstream MCP client is not connected")
        return self._session

    async def list_tools(self) -> list[types.Tool]:
        """Fetch downstream tool declarations."""
        session = self._require_session()
        try:
            result = await session.list_tools()
            if not isinstance(result, types.ListToolsResult) or not hasattr(result, "tools"):
                raise MCPProtocolError("invalid tools/list response from downstream server")
            return list(result.tools)
        except MCPError:
            raise
        except Exception as exc:
            raise MCPConnectionError("failed to retrieve downstream tools list") from exc

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> types.CallToolResult:
        """Forward low-level tool invocation call downstream."""
        session = self._require_session()
        try:
            result = await session.call_tool(name, arguments=arguments)
            if not isinstance(result, types.CallToolResult):
                raise MCPProtocolError("invalid tools/call response from downstream server")
            return result
        except MCPError:
            raise
        except Exception as exc:
            raise MCPConnectionError("downstream tool call execution failed") from exc
