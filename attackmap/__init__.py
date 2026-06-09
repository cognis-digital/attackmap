"""ATTACKMAP -- map free-text security findings to MITRE ATT&CK techniques.

Defensive / detection-engineering use. Ships a real bundled Enterprise
ATT&CK catalog (14 tactics + ~70 curated techniques with detection rules),
maps free-text findings to technique IDs with evidence and confidence,
renders a tactic-by-tactic coverage heatmap, performs gap analysis, and
exports a MITRE ATT&CK Navigator layer. No network, no install.
"""

from __future__ import annotations

from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    ATTACK_VERSION,
    ATTACK_DOMAIN,
    CATALOG,
    BY_ID,
    TACTICS,
    TACTIC_ORDER,
    Technique,
    TechniqueMatch,
    Finding,
    MapResult,
    map_text,
    map_findings,
    map_files,
    lookup,
    heatmap_rows,
    gap_analysis,
    navigator_layer,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "ATTACK_VERSION",
    "ATTACK_DOMAIN",
    "CATALOG",
    "BY_ID",
    "TACTICS",
    "TACTIC_ORDER",
    "Technique",
    "TechniqueMatch",
    "Finding",
    "MapResult",
    "map_text",
    "map_findings",
    "map_files",
    "lookup",
    "heatmap_rows",
    "gap_analysis",
    "navigator_layer",
]
