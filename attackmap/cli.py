"""Command-line interface for ATTACKMAP.

Subcommands:
  map        Map findings (files or stdin) to ATT&CK technique IDs.
  heatmap    Render a tactic-by-tactic coverage heatmap from findings.
  gap        Coverage / gap analysis of observed vs bundled techniques.
  navigator  Export a MITRE ATT&CK Navigator layer (JSON) from findings.
  lookup     Look up bundled techniques by id, name, or keyword.
  tactics    List the bundled ATT&CK tactics.

Global: --version, --format {table,json}. JSON output everywhere; non-zero
exit when findings map to techniques (pipeline/CI signal).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    CATALOG,
    TACTICS,
    TACTIC_ORDER,
    MapResult,
    gap_analysis,
    heatmap_rows,
    lookup,
    map_files,
    map_findings,
    navigator_layer,
)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def _render_map_table(result: MapResult) -> str:
    if result.total_findings == 0:
        return "No findings provided."
    lines: list[str] = []
    for f in result.findings:
        snippet = f.text if len(f.text) <= 70 else f.text[:67] + "..."
        if not f.matches:
            lines.append(f"[ -- ] {snippet}")
            continue
        ids = ", ".join(
            f"{m.technique.tid}({m.confidence[0]})" for m in f.matches[:6]
        )
        lines.append(f"[MAP ] {snippet}")
        lines.append(f"       -> {ids}")
    lines.append("")
    uniq = result.unique_techniques()
    lines.append(
        f"findings={result.total_findings} "
        f"mapped={result.mapped_findings} "
        f"techniques={len(uniq)} "
        f"tactics={len(result.as_dict()['tactics_touched'])}"
    )
    return "\n".join(lines)


_GLYPHS = {0: ".", 1: "+", 2: "*", 3: "#"}


def _render_heatmap_table(result: MapResult) -> str:
    rows = heatmap_rows(result)
    width = max(len(r["name"]) for r in rows)
    out: list[str] = []
    out.append(f"{'TACTIC'.ljust(width)}  ID       OBS/CAT  CONF   COVERAGE")
    out.append("-" * (width + 40))
    rank = {None: 0, "low": 1, "medium": 2, "high": 3}
    for r in rows:
        obs = r["techniques_observed"]
        cat = r["techniques_in_catalog"]
        conf = r["max_confidence"] or "-"
        bar_n = min(20, obs)
        bar = _GLYPHS[rank[r["max_confidence"]]] * bar_n if obs else ""
        out.append(
            f"{r['name'].ljust(width)}  {r['tactic_id']}  "
            f"{str(obs).rjust(3)}/{str(cat).ljust(3)}  "
            f"{conf.ljust(6)} {bar}"
        )
    out.append("")
    touched = sum(1 for r in rows if r["techniques_observed"])
    out.append(
        f"tactics_touched={touched}/{len(rows)}  "
        f"unique_techniques={len(result.unique_techniques())}  "
        f"(legend: . none  + low  * medium  # high)"
    )
    return "\n".join(out)


def _render_gap_table(result: MapResult) -> str:
    g = gap_analysis(result)
    out: list[str] = []
    out.append(
        f"coverage: {g['techniques_observed']}/{g['catalog_size']} techniques "
        f"({g['coverage_pct']}%)  |  "
        f"tactics touched: {g['tactics_touched']}/{g['tactics_total']}"
    )
    out.append("")
    if not g["missing_by_tactic"]:
        out.append("No gaps: every bundled technique was observed.")
        return "\n".join(out)
    out.append("Detection gaps (bundled techniques NOT observed), by tactic:")
    out.append("-" * 60)
    for short in TACTIC_ORDER:
        gaps = g["missing_by_tactic"].get(short)
        if not gaps:
            continue
        name = TACTICS[short][1]
        out.append(f"{name} ({TACTICS[short][0]}) - {len(gaps)} gap(s)")
        out.append("    " + ", ".join(gaps))
    out.append("")
    out.append(f"{g['techniques_missing']} technique(s) with no coverage.")
    return "\n".join(out)


def _render_lookup_table(techs) -> str:
    if not techs:
        return "No matching techniques."
    lines = []
    for t in techs:
        tac = ", ".join(TACTICS[s][0] for s in t.tactics)
        lines.append(f"{t.tid:<14} {t.name}")
        lines.append(f"               tactics: {tac}")
        lines.append(f"               keywords: {', '.join(t.keywords[:6])}")
    lines.append("")
    lines.append(f"{len(techs)} technique(s).")
    return "\n".join(lines)


def _render_tactics_table() -> str:
    lines = [f"{'TACTIC':<22} ID       TECHNIQUES"]
    lines.append("-" * 44)
    for short in TACTIC_ORDER:
        tid, name = TACTICS[short]
        n = sum(1 for t in CATALOG if short in t.tactics)
        lines.append(f"{name:<22} {tid}  {n}")
    lines.append("")
    lines.append(f"{len(TACTIC_ORDER)} tactics, {len(CATALOG)} techniques bundled.")
    return "\n".join(lines)


def _emit_json(payload: dict) -> None:
    payload = dict(payload)
    payload["tool"] = TOOL_NAME
    payload["version"] = TOOL_VERSION
    print(json.dumps(payload, indent=2, sort_keys=False))


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Map free-text security findings to MITRE ATT&CK "
                    "techniques and render a coverage heatmap. Defensive use.",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_map = sub.add_parser("map", help="Map findings to ATT&CK technique IDs.")
    p_map.add_argument("paths", nargs="*",
                       help="Input file(s); one finding per line. "
                            "If omitted, reads stdin.")
    p_map.add_argument("--min-score", type=int, default=1,
                       help="Minimum match score to report (default: 1).")
    p_map.add_argument("--format", choices=("table", "json"), default="table")

    p_heat = sub.add_parser("heatmap",
                            help="Tactic-by-tactic coverage heatmap from findings.")
    p_heat.add_argument("paths", nargs="*",
                        help="Input file(s); one finding per line. "
                             "If omitted, reads stdin.")
    p_heat.add_argument("--min-score", type=int, default=1)
    p_heat.add_argument("--format", choices=("table", "json"), default="table")

    p_gap = sub.add_parser("gap",
                           help="Coverage / gap analysis vs the bundled catalog.")
    p_gap.add_argument("paths", nargs="*",
                       help="Input file(s); one finding per line. "
                            "If omitted, reads stdin.")
    p_gap.add_argument("--min-score", type=int, default=1)
    p_gap.add_argument("--format", choices=("table", "json"), default="table")

    p_nav = sub.add_parser("navigator",
                           help="Export a MITRE ATT&CK Navigator layer (JSON).")
    p_nav.add_argument("paths", nargs="*",
                       help="Input file(s); one finding per line. "
                            "If omitted, reads stdin.")
    p_nav.add_argument("--min-score", type=int, default=1)
    p_nav.add_argument("--name", default="attackmap layer",
                       help="Layer name shown in the Navigator.")
    p_nav.add_argument("--out", help="Write layer JSON to this path "
                                     "instead of stdout.")
    # navigator always emits JSON; --format kept for interface symmetry.
    p_nav.add_argument("--format", choices=("json",), default="json")

    p_look = sub.add_parser("lookup",
                            help="Look up bundled techniques by id/name/keyword.")
    p_look.add_argument("query", help="Technique id (e.g. T1059), name, or keyword.")
    p_look.add_argument("--format", choices=("table", "json"), default="table")

    p_tac = sub.add_parser("tactics", help="List bundled ATT&CK tactics.")
    p_tac.add_argument("--format", choices=("table", "json"), default="table")

    return parser


def _load(paths, min_score) -> MapResult:
    if paths:
        return map_files(paths, min_score=min_score)
    try:
        data = sys.stdin.read()
    except (KeyboardInterrupt, EOFError):
        data = ""
    return map_findings(data.splitlines(), min_score=min_score)


def _validate_min_score(value: int, parser: argparse.ArgumentParser) -> None:
    """Abort with a clear message if min_score is out of range."""
    if value < 1:
        parser.error(f"--min-score must be >= 1 (got {value})")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command in ("map", "heatmap", "gap", "navigator"):
        _validate_min_score(args.min_score, parser)
        try:
            result = _load(args.paths, args.min_score)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if args.command == "map":
            if args.format == "json":
                _emit_json(result.as_dict())
            else:
                print(_render_map_table(result))
        elif args.command == "heatmap":
            if args.format == "json":
                _emit_json({
                    "coverage": result.tactic_coverage(),
                    "unique_techniques": len(result.unique_techniques()),
                    "technique_ids": sorted(result.unique_techniques()),
                })
            else:
                print(_render_heatmap_table(result))
        elif args.command == "gap":
            if args.format == "json":
                _emit_json(gap_analysis(result))
            else:
                print(_render_gap_table(result))
        else:  # navigator
            layer = navigator_layer(result, name=args.name)
            text = json.dumps(layer, indent=2)
            if args.out:
                try:
                    with open(args.out, "w", encoding="utf-8") as fh:
                        fh.write(text)
                except OSError as exc:
                    print(f"error: {exc}", file=sys.stderr)
                    return 2
                print(f"wrote {args.out} "
                      f"({len(layer['techniques'])} technique entries)",
                      file=sys.stderr)
            else:
                print(text)

        # Non-zero exit when any finding mapped to a technique.
        return 1 if result.unique_techniques() else 0

    if args.command == "lookup":
        techs = lookup(args.query)
        if args.format == "json":
            _emit_json({"query": args.query,
                        "techniques": [
                            {"id": t.tid, "name": t.name,
                             "tactics": list(t.tactics),
                             "keywords": list(t.keywords)}
                            for t in techs
                        ]})
        else:
            print(_render_lookup_table(techs))
        return 0 if techs else 1

    if args.command == "tactics":
        if args.format == "json":
            _emit_json({"tactics": [
                {"short": s, "id": TACTICS[s][0], "name": TACTICS[s][1],
                 "techniques": sum(1 for t in CATALOG if s in t.tactics)}
                for s in TACTIC_ORDER
            ]})
        else:
            print(_render_tactics_table())
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
