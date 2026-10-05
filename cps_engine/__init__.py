"""
cps_engine — Chain Potential Score scoring and chain-detection engine.

Public API:
    rubric: dimension definitions, score_finding, score_chain, band, Finding
    checkmarx_parser: parse_checkmarx_json, filter_low_severity,
                      UnsupportedReportShapeError
    scorer: score_findings
    dimension_defaults: DEFAULTS, lookup_defaults

Typical pipeline:

    from cps_engine import (
        parse_checkmarx_json,
        filter_low_severity,
        score_findings,
    )

    findings = parse_checkmarx_json("scan.json")
    low_findings = filter_low_severity(findings)
    report = score_findings(low_findings)
    print(report)
    for f in sorted(low_findings, key=lambda x: -x.cps_score):
        print(f.query_name, f.cps_score)
"""

from .chain_matcher import (
    AssemblyState,
    ChainMatchResult,
    FindingMatch,
    MatchReport,
    load_chain_catalog,
    match_chains,
)
from .checkmarx_parser import (
    UnsupportedReportShapeError,
    filter_low_severity,
    is_aggregate_findings,
    parse_checkmarx_json,
    parse_cyclonedx_ai_bom,
)
from .dimension_defaults import DEFAULTS, lookup_defaults
from .rubric import (
    AILeverage,
    BlastRadius,
    ChainUtility,
    DimensionScores,
    Finding,
    ImpactProximity,
    Prevalence,
    band,
    score_chain,
    score_finding,
)
from .scorer import ScoringReport, score_findings

__all__ = [
    "AILeverage",
    "AssemblyState",
    "BlastRadius",
    "ChainMatchResult",
    "ChainUtility",
    "DEFAULTS",
    "DimensionScores",
    "Finding",
    "FindingMatch",
    "ImpactProximity",
    "MatchReport",
    "Prevalence",
    "ScoringReport",
    "UnsupportedReportShapeError",
    "band",
    "filter_low_severity",
    "is_aggregate_findings",
    "load_chain_catalog",
    "lookup_defaults",
    "match_chains",
    "parse_checkmarx_json",
    "parse_cyclonedx_ai_bom",
    "score_chain",
    "score_finding",
    "score_findings",
]
