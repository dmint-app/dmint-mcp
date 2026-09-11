# dmint-mcp

`dmint-mcp` provides the MCP proxy transport and enforcement gateway for Dmint.

## Installation

```bash
pip install dmint-mcp
```

## Quickstart

```python
from dmint_mcp import DmintMCPProxy, MCPIntegrationConfig
from dmint.policy import Policy

policy = Policy.from_mapping({...})
config = MCPIntegrationConfig(...)

proxy = DmintMCPProxy(integration_config=config, policy=policy)
```
