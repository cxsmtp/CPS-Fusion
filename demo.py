#!/usr/bin/env python3
"""Run the four example chains through the CPS engine.

    python demo.py                          # offline, uses fixtures/expected_findings.json
    python demo.py path/to/results.json     # a real scanner results export
    python demo.py --chain CH-104           # one chain only

For each chain it prints every constituent finding with the scanner's own
severity and its individual CPS, then the chain CPS the engine composes from
them. The point to look for: no finding is rated above Medium, yet every
chain lands in the High band.

Exit code is 0 when every selected chain is fully assembled, 1 otherwise,
2 on bad input.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cps_engine import (  # noqa: E402
    AssemblyState,
    UnsupportedReportShapeError,
    match_chains,
    parse_checkmarx_json,
    score_findings,
)

DEFAULT_SCAN = ROOT / "fixtures" / "expected_findings.json"
DEFAULT_CATALOG = ROOT / "catalog" / "chains_index.json"

# Scanner severities, most to least severe. Informational is spelled several
# ways across export formats.
SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "information": 1,
    "informational": 1,
}


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(str(severity).strip().lower(), 0)


def run(scan_path: Path, catalog_path: Path, only: set[str] | None = None):
    """Parse, score and match. Returns (chain results, catalog entries by id)."""
    findings = parse_checkmarx_json(scan_path)
    score_findings(findings)

    if only:
        # match_chains reads the catalog from disk, so narrow it via a temp
        # copy rather than filtering results afterwards: the report then only
        # mentions the chains that were asked for.
        doc = json.loads(catalog_path.read_text(encoding="utf-8"))
        doc["chains"] = [c for c in doc["chains"] if c["id"] in only]
        unknown = only - {c["id"] for c in doc["chains"]}
        if unknown:
            raise ValueError(f"unknown chain id(s): {', '.join(sorted(unknown))}")
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir) / "chains_index.json"
            tmp.write_text(json.dumps(doc), encoding="utf-8")
            report = match_chains(findings, tmp)
    else:
        report = match_chains(findings, catalog_path)
        doc = json.loads(catalog_path.read_text(encoding="utf-8"))

    entries = {c["id"]: c for c in doc["chains"]}
    results = (
        report.fully_assembled + report.partially_assembled + report.not_assembled
    )
    order = list(entries)
    results.sort(key=lambda r: order.index(r.chain_id))
    return results, entries


def print_chain(result, entry) -> str:
    """Print one chain and return the highest scanner severity in it."""
    title = entry.get("short_name") or result.chain_name
    print("=" * 78)
    print(f"{result.chain_id}  {title}")
    print(f"{result.chain_name}")
    print("-" * 78)
    print(f"  {'Scanner sev':<13}{'CPS':>6}  Finding  ::  location")

    worst = ""
    for m in result.matches:
        if not m.matched:
            print(f"  {'MISSING':<13}{'-':>6}  {m.catalog_query_name}")
            continue
        best = max(m.matched_findings, key=lambda f: f.cps_score or 0.0)
        if severity_rank(best.default_severity) > severity_rank(worst):
            worst = best.default_severity
        query = m.catalog_query_name.split("  [in ")[0]
        where = f"{best.source_file.lstrip('/')}:{best.line}"
        print(f"  {best.default_severity:<13}{best.cps_score:>6.2f}  {query}  ::  {where}")

    print("-" * 78)
    print(f"  Highest scanner severity: {worst or 'n/a'}")
    state = result.state.value.replace("_", " ")
    print(
        f"  Chain CPS:                {result.chain_cps:.2f}  ({result.chain_cps_band})"
        f"   [{result.required_matched}/{result.required_total} {state}]"
    )
    if result.terminal_outcome:
        print()
        print(f"  Outcome: {result.terminal_outcome}")
    print()
    return worst


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("scan", nargs="?", type=Path, default=DEFAULT_SCAN,
                    help="scanner results export (default: the offline fixture)")
    ap.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    ap.add_argument("--chain", action="append", metavar="ID",
                    help="limit to a chain id, e.g. CH-101 (repeatable)")
    args = ap.parse_args(argv)

    try:
        results, entries = run(args.scan, args.catalog,
                               set(args.chain) if args.chain else None)
    except (FileNotFoundError, ValueError, json.JSONDecodeError,
            UnsupportedReportShapeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.scan == DEFAULT_SCAN:
        print("Input: offline fixture (expected findings, not a live scan)\n")
    else:
        print(f"Input: {args.scan}\n")

    summary = []
    for result in results:
        worst = print_chain(result, entries[result.chain_id])
        summary.append((result, entries[result.chain_id], worst))

    print("=" * 78)
    print("SUMMARY: severity triage vs chain score")
    print("=" * 78)
    print(f"  {'Chain':<8}{'Example':<28}{'Findings':>9}  {'Max sev':<13}{'Chain CPS':>10}")
    for result, entry, worst in summary:
        print(
            f"  {result.chain_id:<8}{entry.get('short_name', ''):<28}"
            f"{result.required_matched:>4}/{result.required_total:<4}  "
            f"{worst or 'n/a':<13}{result.chain_cps:>6.2f} {result.chain_cps_band}"
        )
    print()
    print("  Triaged one finding at a time, nothing here crosses 'fix now'.")
    print("  Scored as chains, every one of them is High. Fix one link to break each chain.")

    complete = all(r.state is AssemblyState.FULLY_ASSEMBLED for r in results)
    return 0 if complete else 1


if __name__ == "__main__":
    sys.exit(main())
