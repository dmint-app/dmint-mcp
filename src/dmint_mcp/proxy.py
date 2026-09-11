"""Agent-facing Dmint MCP proxy server (protocol/session bridge)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
import json
from typing import Any, Callable

import mcp.types as types
from mcp.server import Server
from mcp.server.context import ServerRequestContext
from mcp.server.stdio import stdio_server

from dmint.approvals import ApprovalRecord, ApprovalState, PolicyProvenance
from dmint.authority import ApprovalAssertion, ApprovalVerifier
from dmint.canonicalize import thaw_json
from dmint.enforcement import Dmint
from dmint.errors import (
    ApprovalCredentialInvalidError,
    ApprovalIntegrationMismatchError,
    ApprovalPolicyInvalidError,
    ApprovalRequestMismatchError,
    ApprovalRequiredError,
    AuthorizationError,
)
from .errors import (
    MCPConfigurationError,
    MCPConnectionError,
    MCPError,
    MCPMappingError,
    MCPProtocolError,
)
from dmint.models import Decision, ToolRequest, TrustedContext
from dmint.policy import Policy
from dmint.request_binding import request_binding_fingerprint
from dmint.storage import SQLiteApprovalStore
from .client import DownstreamMCPClient
from .config import DiscoveryMode, DisclosureMode, MCPIntegrationConfig
from .mapper import MCPMappedRequest, MCPRequestMapper


class MCPProxyError(Exception):
    """Marker for a controlled proxy-level error separate from Dmint errors."""


class EnforcementGate:
    """Internal security gate enforcing Dmint policy on MCP tools/call.

    MCP-8 maps every tools/call request to a canonical Dmint ToolRequest and
    evaluates policy. On ALLOW, exact authorized arguments are forwarded downstream.
    On APPROVAL_REQUIRED, a pending approval record is persisted in SQLiteApprovalStore.
    On retry_call(), verified approved credentials atomically consume the record in
    SQLiteApprovalStore and execute the exact authorized request downstream.
    """

    def __init__(
        self,
        client: DownstreamMCPClient,
        integration_config: MCPIntegrationConfig,
        policy: Policy | Dmint | None = None,
        *,
        agent_id: str = "mcp-agent",
        context: TrustedContext | None = None,
        approval_store: SQLiteApprovalStore | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        policy_provenance: PolicyProvenance | None = None,
        approval_ttl: timedelta | None = None,
        clock: Callable[[], datetime] | None = None,
        disclosure_mode: DisclosureMode | str = DisclosureMode.DOG,
    ) -> None:
        if not isinstance(client, DownstreamMCPClient):
            raise MCPConfigurationError("client must be a DownstreamMCPClient")
        if not isinstance(integration_config, MCPIntegrationConfig):
            raise MCPConfigurationError("integration_config must be an MCPIntegrationConfig")
        self._client = client
        self._config = integration_config
        self._context = context or TrustedContext({})

        if type(disclosure_mode) is str:
            try:
                disclosure_mode = DisclosureMode(disclosure_mode)
            except ValueError as exc:
                raise MCPConfigurationError("invalid disclosure_mode") from exc
        elif type(disclosure_mode) is not DisclosureMode:
            raise MCPConfigurationError("invalid disclosure_mode")
        self._disclosure_mode = disclosure_mode

        if isinstance(policy, Dmint):
            self._dmint = policy
        elif isinstance(policy, Policy) or policy is None:
            self._dmint = Dmint(
                policy=policy or Policy(),
                agent_id=agent_id,
                context=self._context,
                integration_id=integration_config.integration_id,
                approval_store=approval_store,
                approval_verifier=approval_verifier,
                policy_provenance=policy_provenance,
                approval_ttl=approval_ttl,
                clock=clock,
            )
        else:
            raise MCPConfigurationError("policy must be a Policy or Dmint instance")

        self._mapper = MCPRequestMapper(
            integration_config,
            agent_id=agent_id,
            context=self._context,
        )
        self._last_mapped_request: MCPMappedRequest | None = None

    @property
    def mapper(self) -> MCPRequestMapper:
        return self._mapper

    @property
    def dmint(self) -> Dmint:
        return self._dmint

    @property
    def disclosure_mode(self) -> DisclosureMode:
        return self._disclosure_mode

    @property
    def last_mapped_request(self) -> MCPMappedRequest | None:
        return self._last_mapped_request

    def _is_visible(self, tool_name: str) -> bool:
        """Apply trusted discovery policy for one downstream tool name."""
        binding = self._config.tool_bindings.get(tool_name)
        if binding is not None:
            return binding.discovery is DiscoveryMode.EXPOSED
        return self._config.default_discovery is DiscoveryMode.EXPOSED

    async def list_tools(self) -> types.ListToolsResult:
        tools = await self._client.list_tools()
        visible = [t for t in tools if self._is_visible(t.name)]
        return types.ListToolsResult(tools=visible)

    async def route_call(
        self,
        *,
        integration_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None,
    ) -> types.CallToolResult:
        """Map the MCP tool call to a Dmint ToolRequest, evaluate policy, and route.

        Only ALLOW requests forward to the downstream MCP server. DENY,
        APPROVAL_REQUIRED, and mapping failures stop execution with ZERO downstream
        tool execution.
        """
        mapped = self._mapper.map(tool_name=tool_name, arguments=arguments)
        self._last_mapped_request = mapped

        decision = self._dmint._evaluate_decision(mapped.tool_request)

        if decision is Decision.DENY:
            raise AuthorizationError(
                "policy denied the request",
                code="DMT_POLICY_DENIED",
                request_id=mapped.tool_request.request_id,
                decision=decision.value,
            )

        if decision is Decision.APPROVAL_REQUIRED:
            if (
                self._dmint._approval_store is not None
                and self._dmint._policy_provenance is not None
                and self._dmint._approval_ttl is not None
            ):
                self._dmint._persist_pending(mapped.tool_request)
            raise AuthorizationError(
                "approval is required for this request",
                code="DMT_APPROVAL_REQUIRED",
                request_id=mapped.tool_request.request_id,
                decision=decision.value,
            )

        if decision is not Decision.ALLOW:
            raise AuthorizationError(
                "authorization returned an invalid decision",
                code="DMT_AUTHORIZATION_ERROR",
                request_id=mapped.tool_request.request_id,
            )

        exact_arguments = thaw_json(mapped.tool_request.arguments)
        return await self._client.call_tool(tool_name, arguments=exact_arguments)

    async def retry_call(
        self,
        *,
        integration_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None,
        approval_credential: ApprovalAssertion | bytes,
    ) -> types.CallToolResult:
        """Verify an approved credential, re-evaluate policy, atomically consume, and execute downstream."""
        if self._dmint._approval_store is None or self._dmint._approval_verifier is None:
            raise AuthorizationError(
                "approval retry is not configured",
                code="DMT_AUTHORIZATION_FAILED",
            )

        if type(approval_credential) is bytes:
            try:
                approval_credential = ApprovalAssertion.from_bytes(approval_credential)
            except Exception as exc:
                raise ApprovalCredentialInvalidError("approval credential is invalid") from exc
        if type(approval_credential) is not ApprovalAssertion:
            raise ApprovalCredentialInvalidError("approval credential is invalid")

        record = self._dmint._approval_store.get(approval_credential.approval_id)
        if record is None:
            raise AuthorizationError("approval not found", code="DMT_APPROVAL_NOT_FOUND")

        if record.integration_id != self._config.integration_id:
            raise ApprovalIntegrationMismatchError("approval integration_id mismatch")

        mapped = self._mapper.map(tool_name=tool_name, arguments=arguments)
        self._last_mapped_request = mapped

        if record.capability_id != mapped.capability:
            raise ApprovalRequestMismatchError("approval capability mismatch")

        expected_request = ToolRequest(
            request_id=record.request.request_id,
            agent_id=self._mapper._agent_id,
            tool=mapped.tool_request.tool,
            action=mapped.tool_request.action,
            resource=mapped.tool_request.resource,
            arguments=dict(thaw_json(mapped.tool_request.arguments)),
            context=self._mapper._context,
        )

        retry_fingerprint = request_binding_fingerprint(
            expected_request,
            integration_id=self._config.integration_id,
            capability_id=mapped.capability,
        )

        if retry_fingerprint != record.request_fingerprint:
            raise ApprovalRequestMismatchError("approval request fingerprint mismatch")

        store_policy_info = self._dmint._approval_store.get_authoritative_policy()
        if store_policy_info is not None:
            store_policy, store_provenance = store_policy_info
            if (
                record.policy_provenance.version_id != store_provenance.version_id
                or record.policy_provenance.policy_digest != store_provenance.policy_digest
            ):
                if record.state is ApprovalState.APPROVED:
                    self._dmint._approval_store.invalidate_approved(
                        record, reason="shared store policy provenance changed"
                    )
                raise ApprovalPolicyInvalidError("approval policy provenance is stale per shared store")
            store_decision = store_policy.evaluate(expected_request)
            if store_decision is Decision.DENY:
                if record.state is ApprovalState.APPROVED:
                    self._dmint._approval_store.invalidate_approved(
                        record, reason="shared store policy denied request"
                    )
                raise ApprovalPolicyInvalidError("current shared store policy denies the approved request")

        if self._dmint._policy_provenance is None:
            raise ApprovalPolicyInvalidError("current policy provenance is unavailable")
        if (
            record.policy_provenance.version_id != self._dmint._policy_provenance.version_id
            or record.policy_provenance.policy_digest != self._dmint._policy_provenance.policy_digest
        ):
            if record.state is ApprovalState.APPROVED:
                self._dmint._approval_store.invalidate_approved(
                    record, reason="policy provenance changed"
                )
            raise ApprovalPolicyInvalidError("approval policy provenance is stale")

        decision = self._dmint._evaluate_decision(expected_request)
        if decision is Decision.DENY:
            if record.state is ApprovalState.APPROVED:
                self._dmint._approval_store.invalidate_approved(
                    record, reason="current policy denied request"
                )
            raise ApprovalPolicyInvalidError("current policy denies the approved request")

        consumed = self._dmint._approval_store.consume_approved(
            approval_id=record.approval_id,
            credential=approval_credential,
            expected_request=expected_request,
            verifier=self._dmint._approval_verifier,
        )

        exact_arguments = thaw_json(expected_request.arguments)
        return await self._client.call_tool(tool_name, arguments=exact_arguments)


class DmintMCPProxy:
    """MCP server that bridges one trusted integration to the agent."""

    def __init__(
        self,
        integration_config: MCPIntegrationConfig,
        policy: Policy | Dmint | None = None,
        *,
        agent_id: str = "mcp-agent",
        context: TrustedContext | None = None,
        approval_store: SQLiteApprovalStore | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        policy_provenance: PolicyProvenance | None = None,
        approval_ttl: timedelta | None = None,
        clock: Callable[[], datetime] | None = None,
        disclosure_mode: DisclosureMode | str = DisclosureMode.DOG,
        server_name: str = "dmint-mcp-proxy",
    ) -> None:
        if not isinstance(integration_config, MCPIntegrationConfig):
            raise MCPConfigurationError("integration_config must be an MCPIntegrationConfig")
        self._integration_config = integration_config
        self._integration_id = integration_config.integration_id
        self._policy = policy
        self._agent_id = agent_id
        self._context = context or TrustedContext({})
        self._approval_store = approval_store
        self._approval_verifier = approval_verifier
        self._policy_provenance = policy_provenance
        self._approval_ttl = approval_ttl
        self._clock = clock
        self._disclosure_mode = disclosure_mode
        self._gate: EnforcementGate | None = None
        self._server = Server(server_name)

    @property
    def integration_id(self) -> str:
        return self._integration_id

    @property
    def gate(self) -> EnforcementGate | None:
        return self._gate

    def _check_ready(self) -> None:
        if self._gate is None:
            raise MCPProxyError("proxy is not connected to downstream server")

    async def connect(self) -> None:
        """Connect to the downstream client and register MCP handlers."""
        if self._gate is not None:
            return
        client = DownstreamMCPClient(self._integration_config)
        await client.connect()
        self._gate = EnforcementGate(
            client,
            self._integration_config,
            policy=self._policy,
            agent_id=self._agent_id,
            context=self._context,
            approval_store=self._approval_store,
            approval_verifier=self._approval_verifier,
            policy_provenance=self._policy_provenance,
            approval_ttl=self._approval_ttl,
            clock=self._clock,
            disclosure_mode=self._disclosure_mode,
        )
        self._server.add_request_handler(
            "tools/list",
            types.PaginatedRequestParams,
            self._handle_list_tools,
        )
        self._server.add_request_handler(
            "tools/call",
            types.CallToolRequestParams,
            self._handle_call_tool,
        )

    async def disconnect(self) -> None:
        """Shut down the proxy and downstream connection."""
        gate = self._gate
        self._gate = None
        if gate is not None:
            client = getattr(gate, "_client", None)
            if client is not None:
                await client.disconnect()

    async def list_tools(self) -> types.ListToolsResult:
        """Public helper to list downstream tools (used by tests)."""
        gate = self._gate
        if gate is None:
            raise MCPProxyError("proxy is not connected to downstream server")
        return await gate.list_tools()

    async def retry_call(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any] | None,
        approval_credential: ApprovalAssertion | bytes,
    ) -> types.CallToolResult:
        """Execute an approved retry for one tool call."""
        self._check_ready()
        assert self._gate is not None
        return await self._gate.retry_call(
            integration_id=self._integration_id,
            tool_name=tool_name,
            arguments=arguments,
            approval_credential=approval_credential,
        )

    async def _handle_list_tools(
        self,
        ctx: ServerRequestContext,
        params: types.PaginatedRequestParams,
    ) -> types.ListToolsResult:
        self._check_ready()
        assert self._gate is not None
        return await self._gate.list_tools()

    def _format_approval_required_result(
        self, exc: ApprovalRequiredError
    ) -> types.CallToolResult:
        mode = getattr(self._gate, "disclosure_mode", DisclosureMode.DOG)
        if mode is DisclosureMode.GOD:
            text = "Dmint enforcement [DMT_403]: access denied"
        elif mode is DisclosureMode.CAT:
            text = f"Dmint enforcement [DMT_APPROVAL_REQUIRED]: approval requested (workflow {exc.request_id})"
        else:  # DOG mode
            payload = {
                "status": "approval_required",
                "code": "DMT_APPROVAL_REQUIRED",
                "request_id": exc.request_id,
                "approval_id": exc.approval_id,
                "request_fingerprint": exc.request_fingerprint,
                "message": "Trusted approval is required for this request.",
            }
            text = json.dumps(payload, sort_keys=True)
        return types.CallToolResult(
            is_error=True,
            content=[types.TextContent(type="text", text=text)],
        )

    def _format_authorization_error_result(
        self, exc: Exception
    ) -> types.CallToolResult:
        mode = getattr(self._gate, "disclosure_mode", DisclosureMode.DOG)
        code = getattr(exc, "code", "DMT_ERROR")
        if mode is DisclosureMode.GOD:
            text = "Dmint enforcement [DMT_403]: access denied"
        else:
            text = f"Dmint enforcement [{code}]: {exc}"
        return types.CallToolResult(
            is_error=True,
            content=[types.TextContent(type="text", text=text)],
        )

    async def _handle_call_tool(
        self,
        ctx: ServerRequestContext,
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        self._check_ready()
        assert self._gate is not None

        tool_name = params.name
        if type(tool_name) is not str or not tool_name:
            raise MCPProtocolError("tools/call requires a tool name")

        arguments = params.arguments
        if arguments is not None and type(arguments) is not dict:
            raise MCPProtocolError("tool arguments must be an object")

        try:
            return await self._gate.route_call(
                integration_id=self._integration_id,
                tool_name=tool_name,
                arguments=arguments,
            )
        except ApprovalRequiredError as exc:
            return self._format_approval_required_result(exc)
        except (AuthorizationError, MCPMappingError) as exc:
            return self._format_authorization_error_result(exc)

    async def serve_stdio(self) -> None:
        """Run the agent-facing MCP server over stdio until shutdown."""
        async with stdio_server() as (read_stream, write_stream):
            if self._gate is None:
                await self.connect()
            await self._server.run(
                read_stream,
                write_stream,
                self._server.create_initialization_options(),
            )
