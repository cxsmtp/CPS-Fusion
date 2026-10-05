"""
CPS Rubric — implementation of the Chain Potential Score framework.

This module is the authoritative implementation of the CPS rubric as defined
in Section 4 of the research paper. All other modules depend on this one.

The rubric scores individual weaknesses on five orthogonal dimensions, each
0-4 (None / Low / Medium / High / Critical), then computes a weighted sum
normalized to a 0-10 scale.

References:
    - Paper Section 4.2: Dimensions
    - Paper Section 4.3: Scoring Rubric (anchored descriptions)
    - Paper Section 4.4: Aggregate Score formula
    - Paper Section 4.5: Chain-level aggregation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterable


# ---------------------------------------------------------------------------
# Dimension scales
# ---------------------------------------------------------------------------
# Each dimension uses an ordinal 0-4 scale. We use IntEnum so the values
# behave as integers in arithmetic but carry semantic names in code and logs.
# Anchored descriptions live in the docstrings — these are the same anchors
# defined in the paper Section 4.3 and must not drift from them silently.


class Prevalence(IntEnum):
    """How commonly the weakness appears across modern software systems.

    Anchors:
        0 NONE       Rare; <1% of comparable systems or unusual configs.
        1 LOW        Uncommon; 1-10% of comparable systems, legacy/misconfig.
        2 MEDIUM     Moderately common; 10-30%, recognized anti-pattern.
        3 HIGH       Common; 30-60%, regularly identified by scanners.
        4 CRITICAL   Pervasive; >60% or endemic to widely-used platform.
    """
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ChainUtility(IntEnum):
    """Usefulness as a chain building block — bridges to / amplifies steps.

    Anchors:
        0 NONE       Standalone weakness with no documented chain role.
        1 LOW        Minor recon value; no follow-on step enabled.
        2 MEDIUM     Produces primitive used in at least one published chain.
        3 HIGH       Reliable primitive across multiple documented chains.
        4 CRITICAL   Recurring linchpin across many chain families.
    """
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AILeverage(IntEnum):
    """Degree to which AI reduces the cost of discovery / exploitation.

    Anchors:
        0 NONE       No AI advantage; requires non-AI capabilities.
        1 LOW        AI assists with documentation / boilerplate only.
        2 MEDIUM     AI recognizes pattern, drafts steps; human assembles.
        3 HIGH       AI autonomously identifies, exploits, proposes chain.
        4 CRITICAL   AI autonomously discovers + chains across systems.

    For AI-native weaknesses (e.g., prompt injection): score on how reliably
    AI can autonomously identify, weaponize, and chain the weakness across
    deployments, since no pre-AI baseline exists.
    """
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class BlastRadius(IntEnum):
    """How broadly the resulting capability applies.

    Anchors:
        0 NONE       Single session / request / ephemeral state.
        1 LOW        Single user account or single resource.
        2 MEDIUM     Multiple users within one trust boundary.
        3 HIGH       Crosses one trust boundary (tenant, service, role).
        4 CRITICAL   Crosses multiple trust boundaries / org-wide.

    For information-disclosure weaknesses, score based on the breadth of
    follow-on capability the disclosed information enables, not the breadth
    of the disclosure itself.
    """
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ImpactProximity(IntEnum):
    """How few additional steps separate this from business impact.

    Anchors:
        0 NONE       5+ independent steps to business impact.
        1 LOW        3-4 steps to business impact.
        2 MEDIUM     2 steps to business impact.
        3 HIGH       1 step to business impact.
        4 CRITICAL   Directly adjacent; exploitation alone causes harm.
    """
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# ---------------------------------------------------------------------------
# Weights
# ---------------------------------------------------------------------------
# Expert-elicited weights from paper Section 4.4. These sum to 1.0.
# Treated as the framework's starting hypothesis for community calibration.
# If you change these, also change the docstrings in `score_finding()` and
# the documentation in docs/.

WEIGHT_PREVALENCE = 0.15
WEIGHT_CHAIN_UTILITY = 0.30
WEIGHT_AI_LEVERAGE = 0.25
WEIGHT_BLAST_RADIUS = 0.15
WEIGHT_IMPACT_PROXIMITY = 0.15

assert abs(
    WEIGHT_PREVALENCE
    + WEIGHT_CHAIN_UTILITY
    + WEIGHT_AI_LEVERAGE
    + WEIGHT_BLAST_RADIUS
    + WEIGHT_IMPACT_PROXIMITY
    - 1.0
) < 1e-9, "CPS dimension weights must sum to 1.0"


# Chain-level aggregation: alpha controls how much secondary findings
# contribute. See paper Section 4.5.
CHAIN_ALPHA = 0.1


# Score range and interpretive bands
SCORE_MIN = 0.0
SCORE_MAX = 10.0
BAND_NEGLIGIBLE_MAX = 2.5
BAND_LOW_MAX = 5.0
BAND_MODERATE_MAX = 7.5
# Anything above BAND_MODERATE_MAX is High band (capped at SCORE_MAX).


# ---------------------------------------------------------------------------
# Score and finding objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DimensionScores:
    """The five dimension scores for a single finding.

    Use IntEnum members or plain ints in 0..4. Validation runs at construction.
    """
    prevalence: Prevalence
    chain_utility: ChainUtility
    ai_leverage: AILeverage
    blast_radius: BlastRadius
    impact_proximity: ImpactProximity

    def __post_init__(self) -> None:
        # Defensive validation — accept ints, coerce to enum, reject out-of-range.
        for name in (
            "prevalence",
            "chain_utility",
            "ai_leverage",
            "blast_radius",
            "impact_proximity",
        ):
            value = getattr(self, name)
            if not isinstance(value, IntEnum):
                # If a plain int was passed, validate range.
                if not isinstance(value, int) or not 0 <= int(value) <= 4:
                    raise ValueError(
                        f"Dimension {name!r} must be 0..4, got {value!r}"
                    )


def score_finding(scores: DimensionScores) -> float:
    """Compute the CPS for a single finding.

    Formula (paper Section 4.4):
        CPS = (10/4) * sum(weight_i * dimension_i)

    The (10/4) factor normalizes the weighted sum (which lies in [0, 4])
    onto the [0, 10] reporting scale.

    Returns:
        A float in [0.0, 10.0].
    """
    weighted_sum = (
        WEIGHT_PREVALENCE * int(scores.prevalence)
        + WEIGHT_CHAIN_UTILITY * int(scores.chain_utility)
        + WEIGHT_AI_LEVERAGE * int(scores.ai_leverage)
        + WEIGHT_BLAST_RADIUS * int(scores.blast_radius)
        + WEIGHT_IMPACT_PROXIMITY * int(scores.impact_proximity)
    )
    cps = (SCORE_MAX / 4.0) * weighted_sum
    # Clamp defensively — math should never produce out-of-range values
    # given valid inputs, but the clamp protects against future changes.
    return max(SCORE_MIN, min(SCORE_MAX, cps))


def score_chain(individual_scores: Iterable[float]) -> float:
    """Compute chain-level CPS from individual finding CPS values.

    Formula (paper Section 4.5):
        CPS_chain = max(scores) + alpha * sum(scores - max(scores))

    Behavior:
        - Single finding: returns that finding's score unchanged.
        - Empty input: returns 0.0.
        - Result is capped at SCORE_MAX.

    The capping rule follows the convention discussed during catalog stress-
    testing: chains whose composition mathematically exceeds 10.0 are
    reported as 10.0 (saturated), with the saturation noted by callers.

    Args:
        individual_scores: iterable of individual finding CPS values.

    Returns:
        A float in [0.0, 10.0] representing the chain-level CPS.
    """
    scores = list(individual_scores)
    if not scores:
        return 0.0
    if len(scores) == 1:
        return max(SCORE_MIN, min(SCORE_MAX, scores[0]))

    primary = max(scores)
    secondary_sum = sum(scores) - primary
    chain_cps = primary + CHAIN_ALPHA * secondary_sum
    return max(SCORE_MIN, min(SCORE_MAX, chain_cps))


def band(cps: float) -> str:
    """Return the interpretive band for a CPS value.

    Bands per paper Section 4.4:
        0.0 - 2.5   Negligible
        2.6 - 5.0   Low
        5.1 - 7.5   Moderate
        7.6 - 10.0  High
    """
    if cps <= BAND_NEGLIGIBLE_MAX:
        return "Negligible"
    if cps <= BAND_LOW_MAX:
        return "Low"
    if cps <= BAND_MODERATE_MAX:
        return "Moderate"
    return "High"


# ---------------------------------------------------------------------------
# Finding object — the unit of analysis
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single security finding from a SAST/SCA/IaC/Secrets scanner.

    Attributes:
        finding_id: stable identifier within the scan (often SimilarityID).
        query_name: the scanner's query family name (e.g., 'Open_Redirect').
        cwe: CWE identifier as integer (e.g., 601 for CWE-601). 0 if unmapped.
        default_severity: scanner's native severity ('High', 'Medium', etc.).
        language: programming language or 'IaC' / 'Secrets' / etc.
        source_file: path to the file where the finding was detected.
        line: line number (0 if not applicable).
        cps_dimensions: the five-dimension CPS scoring for this finding.
        cps_score: cached individual CPS computed from cps_dimensions.

    The cps_dimensions field is populated by the scoring pipeline. For raw
    findings parsed from scanner output, it starts as None and is filled in
    by the scoring module that maps query_name -> default dimension scores.
    """
    finding_id: str
    query_name: str
    cwe: int
    default_severity: str
    language: str
    source_file: str
    line: int
    cps_dimensions: DimensionScores | None = None
    cps_score: float | None = field(default=None)

    def compute_score(self) -> float:
        """Compute and cache this finding's individual CPS.

        Raises:
            ValueError: if cps_dimensions has not been populated.
        """
        if self.cps_dimensions is None:
            raise ValueError(
                f"Finding {self.finding_id} has no cps_dimensions; "
                "score the finding (via dimension_defaults) first."
            )
        self.cps_score = score_finding(self.cps_dimensions)
        return self.cps_score
