"""ATTACKMAP MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import sys
from attackmap.core import scan, to_json  # noqa: F401 – re-exported aliases


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-attackmap[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import]
    except ImportError:
        print(
            "MCP extra not installed. Run: pip install 'cognis-attackmap[mcp]'",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:  # pragma: no cover
        print(f"Failed to import MCP library: {exc}", file=sys.stderr)
        return 1

    app = FastMCP("attackmap")

    @app.tool()
    def attackmap_scan(target: str) -> str:
        """Map findings to MITRE ATT&CK techniques + coverage heatmap. Returns JSON findings."""
        if not target or not target.strip():
            return '{"error": "target must be a non-empty string"}'
        return to_json(scan(target))

    try:
        app.run()
    except Exception as exc:  # pragma: no cover
        print(f"MCP server error: {exc}", file=sys.stderr)
        return 1
    return 0
