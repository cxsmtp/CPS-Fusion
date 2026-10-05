"""
Command-line interface for the CPS scoring engine.

Usage:
    python -m cps_engine.cli <path-to-checkmarx.json> [options]

Options:
    --all                 Score every finding regardless of severity.
                          Default: Low/Informational only.
    --top N               Show the top N highest-CPS findings (default 20).
    --catalog PATH        Path to a chains_index.json file. When supplied,
                          chain matching is performed after per-finding
                          scoring and a chain report is appended.
    -v, --verbose         Print warnings for unknown query names.

Supported JSON shapes (auto-detected):
    - Checkmarx One results JSON
    - SARIF 2.1.0
    - CxSAST legacy JSON
    - Checkmarx One Improved Project Report (aggregate; chain matching
      operates in best-effort by-name mode)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .chain_matcher import match_chains
from .checkmarx_parser import (
    UnsupportedReportShapeError,
    filter_low_severity,
    is_aggregate_findings,
    parse_checkmarx_json,
    parse_cyclonedx_ai_bom,
)
from .rubric import band
from .scorer import score_findings


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cps_engine.cli",
        description=(
            "Compute Chain Potential Scores for findings in a Checkmarx "
            "JSON export. Low-severity findings only by default. Supports "
            "Checkmarx One results JSON, SARIF, CxSAST legacy JSON, "
            "Checkmarx One Improved Project Report (aggregate), Checkmarx "
            "One Vulnerability Type comprehensive report, and CycloneDX "
            "AI BOM (via --aibom)."
        ),
    )
    parser.add_argument(
        "json_path",
        type=Path,
        help="Path to a Checkmarx JSON export.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "Score all findings, not just Low/Informational. Use only for "
            "sanity-checking; the catalog discipline is Low-only."
        ),
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Show the top N highest-CPS findings (default: 20).",
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=None,
        help=(
            "Path to a chains_index.json file. When supplied, chain "
            "matching runs after per-finding scoring and the chain "
            "report is appended to the output."
        ),
    )
    parser.add_argument(
        "--aibom",
        type=Path,
        default=None,
        help=(
            "Path to a CycloneDX AI BOM file (e.g., from Checkmarx AI "
            "Supply Chain Security). When supplied, AI-BOM components "
            "are parsed into synthesized findings and merged with the "
            "main scan output before scoring."
        ),
    )
    parser.add_argument(
        "--aibom-project-filter",
        default=None,
        help=(
            "Substring matched against AI-BOM components' ProjectName "
            "property. Use this to filter a tenant-wide AI BOM down to a "
            "single project. Always Informational severity, so this "
            "filter is applied before --all/Low filtering."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print warnings for unknown query names.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.WARNING if args.verbose else logging.ERROR,
        format="%(levelname)s: %(message)s",
    )

    try:
        findings = parse_checkmarx_json(args.json_path)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(
            f"error: file is not valid JSON: {exc}",
            file=sys.stderr,
        )
        return 2
    except UnsupportedReportShapeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Optional: parse a separate AI-BOM CycloneDX file and merge.
    ai_findings: list = []
    if args.aibom is not None:
        try:
            ai_findings = parse_cyclonedx_ai_bom(
                args.aibom,
                project_filter=args.aibom_project_filter,
            )
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except json.JSONDecodeError as exc:
            print(
                f"error: AI-BOM file is not valid JSON: {exc}",
                file=sys.stderr,
            )
            return 2
        except UnsupportedReportShapeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if not args.all:
        scope = filter_low_severity(findings)
    else:
        scope = findings

    # AI-BOM findings are always Informational; we include them regardless
    # of the Low filter, because the framework treats AI-BOM as inventory
    # signal, not as severity-rated findings. The chain-matching layer can
    # decide whether they participate in chains.
    if ai_findings:
        scope = list(scope) + ai_findings

    if not scope:
        print(
            "No findings to score after filtering. "
            "(Use --all to include non-Low severities.)",
            file=sys.stderr,
        )
        return 1

    aggregate_mode = is_aggregate_findings(scope)
    if aggregate_mode:
        print(
            "================================================================\n"
            "NOTE: This input is a Checkmarx One Improved Project Report,\n"
            "which carries AGGREGATE counts only — not per-finding records.\n"
            "\n"
            "What this means for scoring:\n"
            "  - We can compute individual CPS per query family.\n"
            "  - We CANNOT identify per-finding file/line locations.\n"
            "  - Chain matching falls back to query-name presence only.\n"
            "  - For full chain analysis (file/line co-occurrence),\n"
            "    re-export your scan as a results-level JSON.\n"
            "================================================================\n",
            file=sys.stderr,
        )

    report = score_findings(scope)

    # Sort by score descending — highest CPS first.
    ranked = sorted(scope, key=lambda f: f.cps_score or 0.0, reverse=True)

    print(report)
    print()

    if aggregate_mode:
        # Aggregate findings have no file/line; collapse them and report
        # a per-query-family summary instead of repeating identical rows.
        print("Per-query-family scores (aggregate report — no file/line data):")
        print(
            f"{'CPS':>6}  {'Band':<10}  {'Severity':<13}  {'Count':>5}  Query"
        )
        print("-" * 78)
        # Group by (query_name, severity) — already 1:1 with score.
        seen: dict[tuple[str, str], tuple[float, int]] = {}
        for f in ranked:
            key = (f.query_name, f.default_severity)
            cps_value = f.cps_score or 0.0
            if key not in seen:
                seen[key] = (cps_value, 1)
            else:
                seen[key] = (cps_value, seen[key][1] + 1)
        for (qname, sev), (cps_value, count) in sorted(
            seen.items(), key=lambda kv: -kv[1][0]
        ):
            print(
                f"{cps_value:>6.2f}  {band(cps_value):<10}  "
                f"{sev:<13}  {count:>5}  {qname}"
            )
    else:
        print(f"Top {min(args.top, len(ranked))} findings by individual CPS:")
        print(f"{'CPS':>6}  {'Band':<10}  {'Severity':<13}  Query  ::  Source")
        print("-" * 78)
        for f in ranked[: args.top]:
            cps_value = f.cps_score or 0.0
            print(
                f"{cps_value:>6.2f}  {band(cps_value):<10}  "
                f"{f.default_severity:<13}  {f.query_name}  ::  "
                f"{f.source_file}:{f.line}"
            )

    # ---- Chain matching (when --catalog supplied) ------------------------
    if args.catalog is not None:
        try:
            match_report = match_chains(scope, args.catalog)
        except FileNotFoundError as exc:
            print(f"\nerror: {exc}", file=sys.stderr)
            return 2
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"\nerror: catalog file invalid: {exc}", file=sys.stderr)
            return 2
        print()
        print(match_report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
