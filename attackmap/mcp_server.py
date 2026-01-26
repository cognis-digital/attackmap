"""ATTACKMAP MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from attackmap.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-attackmap[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-attackmap[mcp]'")
        return 1
    app = FastMCP("attackmap")

    @app.tool()
    def attackmap_scan(target: str) -> str:
        """Map findings to MITRE ATT&CK techniques + coverage heatmap. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
