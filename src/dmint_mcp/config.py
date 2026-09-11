"""Trusted MCP integration and capability configuration."""

from __future__ import annotations

from collections.abc import Container, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from dmint.canonicalize import DEFAULT_SENSITIVE_KEYS, redact_sensitive_data
from dmint.models import validate_text
from .errors import MCPConfigurationError


class MCPTransportType(str, Enum):
    """Supported downstream MCP transports."""

    STDIO = "stdio"


class DiscoveryMode(str, Enum):
    """Trusted discovery policy for exposing a tool through tools/list.

    Discovery controls whether the agent can *see* a tool. It is NOT an
    execution authorization boundary. Execution is always enforced
    independently by the tools/call authorization gate (MCP-5+).
    """

    EXPOSED = "exposed"
    HIDDEN = "hidden"


class DisclosureMode(str, Enum):
    """Information disclosure mode for agent-facing responses (AGENTS.md #22).

    DOG: Useful structured information (approval_id, request_id, fingerprint).
    GOD: Minimal opaque response (DMT_403).
    CAT: Structured code (DMT_APPROVAL_REQUIRED) without internal fingerprints.
    """

    DOG = "dog"
    GOD = "god"
    CAT = "cat"


@dataclass(frozen=True)
class MCPToolBinding:
    """Immutable binding mapping one downstream MCP tool to a Dmint capability."""

    tool_name: str
    capability: str
    resource_key: str | None = None
    discovery: DiscoveryMode | str = DiscoveryMode.EXPOSED

    def __post_init__(self) -> None:
        validate_text(self.tool_name, "tool_name")
        validate_text(self.capability, "capability")
        if self.resource_key is not None:
            validate_text(self.resource_key, "resource_key")
        if type(self.discovery) is str:
            try:
                object.__setattr__(self, "discovery", DiscoveryMode(self.discovery))
            except ValueError as exc:
                raise MCPConfigurationError("invalid discovery mode") from exc
        elif type(self.discovery) is not DiscoveryMode:
            raise MCPConfigurationError("invalid discovery mode")


class MCPIntegrationConfig:
    """Trusted server configuration for connecting to one downstream MCP server."""

    __slots__ = (
        "_integration_id",
        "_transport_type",
        "_command",
        "_args",
        "_env",
        "_cwd",
        "_tool_bindings",
        "_default_discovery",
        "_redact_keys",
        "_sealed",
    )

    def __init__(
        self,
        *,
        integration_id: str,
        command: str,
        args: tuple[str, ...] | list[str] = (),
        transport_type: MCPTransportType | str = MCPTransportType.STDIO,
        env: Mapping[str, str] | None = None,
        cwd: str | Path | None = None,
        tool_bindings: Mapping[str, str | MCPToolBinding] | list[MCPToolBinding] | None = None,
        default_discovery: DiscoveryMode | str = DiscoveryMode.HIDDEN,
        redact_keys: Container[str] | None = None,
    ) -> None:
        try:
            integration_id = validate_text(integration_id, "integration_id")
            command = validate_text(command, "command")
        except Exception as exc:
            raise MCPConfigurationError("invalid integration_id or command") from exc

        if type(transport_type) is str:
            try:
                transport_type = MCPTransportType(transport_type)
            except ValueError as exc:
                raise MCPConfigurationError("unsupported MCP transport type") from exc
        elif type(transport_type) is not MCPTransportType:
            raise MCPConfigurationError("invalid transport_type")

        if type(default_discovery) is str:
            try:
                default_discovery = DiscoveryMode(default_discovery)
            except ValueError as exc:
                raise MCPConfigurationError("invalid default discovery mode") from exc
        elif type(default_discovery) is not DiscoveryMode:
            raise MCPConfigurationError("invalid default discovery mode")

        clean_args: list[str] = []
        if isinstance(args, (list, tuple)):
            for item in args:
                if type(item) is not str:
                    raise MCPConfigurationError("command args must be strings")
                clean_args.append(item)
        else:
            raise MCPConfigurationError("args must be a tuple or list of strings")

        clean_env: dict[str, str] = {}
        if env is not None:
            if not isinstance(env, Mapping):
                raise MCPConfigurationError("env must be a mapping of string key-values")
            for k, v in env.items():
                if type(k) is not str or type(v) is not str:
                    raise MCPConfigurationError("env keys and values must be strings")
                clean_env[k] = v

        clean_bindings: dict[str, MCPToolBinding] = {}
        if tool_bindings is not None:
            if isinstance(tool_bindings, Mapping):
                for tool_name, spec in tool_bindings.items():
                    if type(tool_name) is not str:
                        raise MCPConfigurationError("tool_name key must be a string")
                    if type(spec) is str:
                        binding = MCPToolBinding(tool_name=tool_name, capability=spec)
                    elif type(spec) is MCPToolBinding:
                        binding = spec
                    else:
                        raise MCPConfigurationError("tool binding spec must be a capability string or MCPToolBinding")
                    clean_bindings[tool_name] = binding
            elif isinstance(tool_bindings, (list, tuple)):
                for spec in tool_bindings:
                    if type(spec) is not MCPToolBinding:
                        raise MCPConfigurationError("tool binding spec must be an MCPToolBinding")
                    clean_bindings[spec.tool_name] = spec
            else:
                raise MCPConfigurationError("tool_bindings must be a mapping or sequence of MCPToolBinding")

        object.__setattr__(self, "_integration_id", integration_id)
        object.__setattr__(self, "_command", command)
        object.__setattr__(self, "_args", tuple(clean_args))
        object.__setattr__(self, "_transport_type", transport_type)
        object.__setattr__(self, "_env", MappingProxyType(clean_env))
        object.__setattr__(self, "_cwd", str(cwd) if cwd is not None else None)
        object.__setattr__(self, "_tool_bindings", MappingProxyType(clean_bindings))
        object.__setattr__(self, "_default_discovery", default_discovery)
        object.__setattr__(self, "_redact_keys", redact_keys or DEFAULT_SENSITIVE_KEYS)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("MCPIntegrationConfig is immutable")
        object.__setattr__(self, name, value)

    @property
    def integration_id(self) -> str:
        return self._integration_id

    @property
    def command(self) -> str:
        return self._command

    @property
    def args(self) -> tuple[str, ...]:
        return self._args

    @property
    def transport_type(self) -> MCPTransportType:
        return self._transport_type

    @property
    def env(self) -> MappingProxyType[str, str]:
        return self._env

    @property
    def cwd(self) -> str | None:
        return self._cwd

    @property
    def tool_bindings(self) -> MappingProxyType[str, MCPToolBinding]:
        return self._tool_bindings

    @property
    def default_discovery(self) -> DiscoveryMode:
        return self._default_discovery

    @property
    def redact_keys(self) -> Container[str]:
        return self._redact_keys

    def __repr__(self) -> str:
        redacted_env = redact_sensitive_data(dict(self._env), self._redact_keys)
        return (
            f"MCPIntegrationConfig(integration_id={self._integration_id!r}, "
            f"command={self._command!r}, transport={self._transport_type.value!r}, "
            f"env={redacted_env!r})"
        )
