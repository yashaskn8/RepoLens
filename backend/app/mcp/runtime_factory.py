"""Construction boundary for scan-scoped MCP v2 runtimes.

Database/authentication ownership stays in the workflow layer.  The factory
accepts an already-authorized canonical registry and binds its immutable
snapshot identity into the protocol bridge; no model-controlled scan or
tenant fields are accepted.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp.server.lowlevel import Server

from app.agent_tools.registry import AgentToolRegistry
from app.mcp.adapter import create_agent_mcp_protocol_server
from app.mcp.agent_bridge import MCPAgentToolBridge


@dataclass(frozen=True, slots=True)
class MCPScanRuntime:
    scan_id: str
    tenant_id: str
    snapshot_id: str
    bridge: MCPAgentToolBridge
    protocol_server: Server


class MCPScanRuntimeFactory:
    """Create a scan-bound protocol runtime from a trusted registry."""

    @staticmethod
    def create(
        *,
        scan_id: str,
        tenant_id: str,
        registry: AgentToolRegistry,
        snapshot_id: str | None = None,
    ) -> MCPScanRuntime:
        if not scan_id or not tenant_id:
            raise ValueError("scan_id and tenant_id are required")
        bound_snapshot = snapshot_id or registry.default_snapshot_id
        if bound_snapshot != registry.default_snapshot_id:
            raise ValueError("snapshot identity does not match the authorized registry")
        bridge = MCPAgentToolBridge(registry, snapshot_id=bound_snapshot)
        server = create_agent_mcp_protocol_server(bridge)
        return MCPScanRuntime(
            scan_id=scan_id,
            tenant_id=tenant_id,
            snapshot_id=bound_snapshot,
            bridge=bridge,
            protocol_server=server,
        )
