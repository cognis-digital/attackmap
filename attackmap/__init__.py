"""ATTACKMAP - Map security findings to MITRE ATT&CK techniques + coverage heatmap.

Defensive / authorized-testing analysis tool. Speaks ATT&CK: maps detection or
triage findings to ATT&CK (sub-)techniques and tactics, computes per-tactic
coverage, and emits an ATT&CK Navigator-compatible layer.

Standard library only. No network. No attack capability.
"""
from .core import (
    Finding,
    TECHNIQUES,
    TACTIC_ORDER,
    map_findings,
    coverage_heatmap,
    navigator_layer,
    parse_findings,
    lookup_technique,
    resolve_keywords,
)

TOOL_NAME = "attackmap"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "TECHNIQUES",
    "TACTIC_ORDER",
    "map_findings",
    "coverage_heatmap",
    "navigator_layer",
    "parse_findings",
    "lookup_technique",
    "resolve_keywords",
]
