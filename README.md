# dmint-mcp

> **MCP Proxy Server and Tool Enforcement Gateway for Dmint.**

`dmint-mcp` allows developers to wrap existing Model Context Protocol (MCP) servers with deterministic policy enforcement gates. It intercepts agent `tools/call` requests over stdio, evaluates Dmint security policy, and routes only authorized calls downstream.

```text
┌─────────────────┐
│    AI Client    │
└────────┬────────┘
         │ stdio (tools/list, tools/call)
         ▼
┌─────────────────────────────────┐
│        Dmint MCP Proxy          │
│                                 │
│  ┌───────────────────────────┐  │
│  │     Enforcement Gate      │  │
│  └─────────────┬─────────────┘  │
└────────────────┼────────────────┘
                 │ stdio (authorized call only)
                 ▼
┌─────────────────────────────────┐
│     Downstream MCP Server       │
└─────────────────────────────────┘
```

## Why This Exists

When using external MCP servers that you cannot modify, `dmint-mcp` acts as an out-of-process security proxy between the AI agent and the MCP server.

- **Tool Discovery Control:** Expose or hide tools dynamically from `tools/list` based on configuration.
- **Pre-Call Interception:** Intercepts `tools/call`, maps parameters to a Dmint `ToolRequest`, and enforces `ALLOW`, `DENY`, or `APPROVAL_REQUIRED`.
- **Zero Downstream Leakage:** Unapproved or denied calls never reach the downstream MCP server process.
- **Approved Retries:** Supports Ed25519-signed retry assertion credentials to execute approved workflows over stdio.

## Installation

```bash
pip install dmint-mcp
```

## Quickstart

```python
import anyio
from dmint_mcp import DmintMCPProxy, MCPIntegrationConfig, MCPToolBinding, DiscoveryMode
from dmint.policy import Policy

# 1. Define integration configuration
config = MCPIntegrationConfig(
    integration_id="sqlite-server",
    command="python3",
    args=["-m", "sqlite_server"],
    tool_bindings=[
        MCPToolBinding(tool_name="read_query", capability="db.read", discovery=DiscoveryMode.EXPOSED),
        MCPToolBinding(tool_name="delete_query", capability="db.delete", discovery=DiscoveryMode.HIDDEN),
    ],
)

# 2. Define policy
policy = Policy.from_mapping({
    "rules": [
        {"effect": "allow", "tool": "db", "action": "read", "resource": "*"},
        {"effect": "deny", "tool": "db", "action": "delete", "resource": "*"},
    ]
})

# 3. Instantiate and run proxy over stdio
proxy = DmintMCPProxy(integration_config=config, policy=policy)

async def main():
    await proxy.serve_stdio()

if __name__ == "__main__":
    anyio.run(main)
```

## Disclosure Modes

Control error disclosure returned to the AI client on denied or approval-required requests:

- `DOG` (default): Returns structured recovery JSON containing `request_id`, `approval_id`, and `request_fingerprint`.
- `GOD`: Returns minimal opaque error responses (`DMT_403: access denied`).
- `CAT`: Returns structured error codes without revealing internal request fingerprints.

## Supported Transports

- **Stdio (`stdio`)**: Standard input/output process transport for local MCP servers.

## Testing

Run the MCP integration and unit test suite:

```bash
pytest -v
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
See the [`LICENSE`](LICENSE) file for the complete license text.
