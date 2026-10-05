"""
Scoring orchestrator.

Given a list of Finding objects (typically from `checkmarx_parser`), this
module looks up default dimension scores for each, populates the finding's
`cps_dimensions` field, and computes the individual `cps_score`.

It also reports any unknown query names so the analyst can extend the
defaults table.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .dimension_defaults import lookup_defaults
from .rubric import Finding, band

logger = logging.getLogger(__name__)


@dataclass
class ScoringReport:
    """Summary of a scoring run."""
    total_findings: int
    scored_findings: int
    unknown_queries: list[str]

    def __str__(self) -> str:
        lines = [
            f"Scored {self.scored_findings} of {self.total_findings} findings.",
        ]
        if self.unknown_queries:
            unique = sorted(set(self.unknown_queries))
            lines.append(
                f"Warning: {len(unique)} unknown query name(s) used the "
                "conservative fallback. Consider adding entries to "
                "dimension_defaults.DEFAULTS for:"
            )
            for q in unique:
                lines.append(f"  - {q}")
        return "\n".join(lines)


def score_findings(findings: list[Finding]) -> ScoringReport:
    """Populate cps_dimensions and cps_score on each finding in-place.

    The function mutates the input findings rather than returning new objects,
    because Finding is intentionally not frozen — its dimension fields are
    expected to be filled in by this stage of the pipeline.

    Args:
        findings: list of Finding objects from the parser.

    Returns:
        ScoringReport summarizing the run.
    """
    unknown_queries: list[str] = []
    scored = 0

    for f in findings:
        # The language field is a routing hint for AI-BOM findings whose
        # synthesized query names won't match a fixed DEFAULTS key — see
        # lookup_defaults docstring.
        language_hint = f.language if (f.language and f.language.startswith("ai_component_")) else None
        dims, is_known = lookup_defaults(
            f.query_name,
            f.default_severity,
            language_hint=language_hint,
        )
        f.cps_dimensions = dims
        f.compute_score()
        scored += 1
        if not is_known:
            unknown_queries.append(f.query_name)
            logger.warning(
                "Unknown query name %r — using conservative fallback. "
                "Score: %.2f (%s)",
                f.query_name,
                f.cps_score,
                band(f.cps_score) if f.cps_score is not None else "?",
            )

    return ScoringReport(
        total_findings=len(findings),
        scored_findings=scored,
        unknown_queries=unknown_queries,
    )
