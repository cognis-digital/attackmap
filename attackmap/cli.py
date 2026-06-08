"""Command-line interface for ATTACKMAP.

Subcommands:
  map       Map findings to ATT&CK techniques.
  heatmap   Per-tactic coverage heatmap with weighted scores.
  navigator Emit an ATT&CK Navigator layer (v4.5).
  techniques List the embedded ATT&CK technique knowledge base.

Exit codes: 0 = clean / no findings mapped; 1 = findings were mapped
(actionable detections present); 2 = usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    TECHNIQUES,
    TACTIC_ORDER,
    map_findings,
    coverage_heatmap,
    navigator_layer,
    parse_findings,
)


def _load(args) -> list:
    if getattr(args, "input", None):
        return parse_findings(path=args.input)
    raw = sys.stdin.read()
    if not raw.strip():
        raise ValueError("no input: provide --input FILE or pipe JSON on stdin")
    return parse_findings(raw=raw)


def _emit(obj, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2, sort_keys=False))
    else:
        _emit_table(obj)


def _emit_table(obj) -> None:
    if "mapped" in obj:  # map result
        for m in obj["mapped"]:
            print(f"[{m['severity'].upper():8}] {m['finding']}")
            for t in m["techniques"]:
                print(f"    -> {t['id']:11} {t['tactic']:22} {t['name']}")
        if obj["unmapped"]:
            print("\nUNMAPPED:")
            for u in obj["unmapped"]:
                print(f"    [{u['severity'].upper():8}] {u['finding']}")
    elif "tactics" in obj:  # heatmap
        for tactic in TACTIC_ORDER:
            data = obj["tactics"][tactic]
            if not data["hit_techniques"]:
                continue
            print(f"{tactic:22} score={data['total_score']:<4} "
                  f"techniques={data['hit_techniques']}")
            for t in data["techniques"]:
                print(f"    {t['id']:11} {t['score']:>3}  {t['name']}")
        print(f"\nTactics covered: {obj['tactics_covered']}/{obj['total_tactics']}  "
              f"Techniques hit: {obj['total_techniques_hit']}")
    elif "techniques" in obj and "versions" in obj:  # navigator
        print(f"Navigator layer: {obj['name']} ({len(obj['techniques'])} techniques)")
        for t in obj["techniques"]:
            print(f"    {t['techniqueID']:11} score={t['score']:<3} {t['comment']}")
    else:
        print(json.dumps(obj, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Map defensive findings to MITRE ATT&CK + coverage heatmap.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_io(sp):
        sp.add_argument("-i", "--input", help="findings JSON file (default: stdin)")
        sp.add_argument("--format", choices=["table", "json"], default="table")

    add_io(sub.add_parser("map", help="map findings to ATT&CK techniques"))
    add_io(sub.add_parser("heatmap", help="per-tactic coverage heatmap"))
    nav = sub.add_parser("navigator", help="emit ATT&CK Navigator layer")
    add_io(nav)
    nav.add_argument("--name", default="ATTACKMAP layer", help="layer name")

    tq = sub.add_parser("techniques", help="list embedded ATT&CK knowledge base")
    tq.add_argument("--format", choices=["table", "json"], default="table")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "techniques":
        obj = {"techniques": [
            {"id": t.tid, "name": t.name, "tactic": t.tactic,
             "keywords": list(t.keywords)}
            for t in TECHNIQUES.values()
        ]}
        if args.format == "json":
            print(json.dumps(obj, indent=2))
        else:
            for t in TECHNIQUES.values():
                print(f"{t.tid:11} {t.tactic:22} {t.name}")
        return 0

    try:
        findings = _load(args)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.cmd == "map":
        result = map_findings(findings)
        _emit(result, args.format)
        return 1 if result["mapped"] else 0
    if args.cmd == "heatmap":
        result = coverage_heatmap(findings)
        _emit(result, args.format)
        return 1 if result["total_techniques_hit"] else 0
    if args.cmd == "navigator":
        result = navigator_layer(findings, name=args.name)
        _emit(result, args.format)
        return 1 if result["techniques"] else 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
