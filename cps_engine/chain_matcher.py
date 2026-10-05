"""
Chain matcher — Section 4.5 of the paper, implemented.

Given:
    - a list of scored Finding objects (from the parser + scorer pipeline)
    - a chains_index.json declaring which findings compose each chain

This module determines which chains are present in the scan output and
computes the chain-level CPS for each.

Three classes of result are produced per chain:

  FULLY_ASSEMBLED — every required finding is present in the scan
                    (and, for results-level scans, in the expected file
                    locations). Chain CPS is computed and reported.

  PARTIALLY_ASSEMBLED — some but not all required findings are present.
                        The missing findings are listed. Partial chain
                        CPS is reported with a clear "incomplete" marker.

  NOT_ASSEMBLED — fewer than half the required findings are present, or
                  zero. Chain is not a meaningful match.

Aggregate-report awareness
--------------------------
When the input findings come from an Improved Project Report (no per-
finding file/line data), the matcher cannot verify co-occurrence. It
falls back to "query name present in scan" matching, and the report
explicitly flags that the chain detection is best-effort under
aggregate-only data.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .checkmarx_parser import is_aggregate_findings
from .dimension_defaults import normalize_query_name
from .rubric import (
    CHAIN_ALPHA,
    Finding,
    band,
    score_chain,
)

logger = logging.getLogger(__name__)


class AssemblyState(Enum):
    """How fully assembled a chain is in the scanned codebase."""
    FULLY_ASSEMBLED = "fully_assembled"
    PARTIALLY_ASSEMBLED = "partially_assembled"
    NOT_ASSEMBLED = "not_assembled"


@dataclass
class FindingMatch:
    """A single scan finding matched against a required-finding declaration.

    Used so the report can show, for each required finding in a chain
    catalog entry, which actual scan finding(s) corresponded to it.
    """
    catalog_query_name: str
    catalog_role: str | None
    matched_findings: list[Finding] = field(default_factory=list)

    @property
    def matched(self) -> bool:
        return bool(self.matched_findings)


@dataclass
class ChainMatchResult:
    """The result of matching one chain catalog entry against scan findings."""
    chain_id: str
    chain_name: str
    engines: list[str]
    real_world_anchor: str | None
    terminal_outcome: str | None

    state: AssemblyState
    required_total: int
    required_matched: int
    completion_percent: float

    matches: list[FindingMatch]
    missing: list[str]
    chain_cps: float
    chain_cps_band: str

    aggregate_mode: bool

    # AI inventory (declared in chains_index.json under ``ai_inventory``).
    # The matcher cross-references this against findings to mark which
    # are present in the scan output.
    ai_inventory: list[dict] = field(default_factory=list)
    ai_inventory_matched: dict[str, bool] = field(default_factory=dict)

    # AI-delta computation (CH-002 AI weaponisation chain). When a chain
    # declares `ai_leverage_findings`, the matcher computes chain CPS
    # twice — once with all matched findings, once with AI-Leverage
    # findings excluded — and reports the delta. None when not applicable.
    chain_cps_without_ai: float | None = None
    ai_delta_claim: str | None = None

    def __str__(self) -> str:
        # Multi-line summary suitable for CLI output.
        header = f"{self.chain_id} — {self.chain_name}"
        lines = [
            "=" * 80,
            header,
            "=" * 80,
            f"State:           {self.state.value.upper()}",
            f"Engines:         {', '.join(self.engines)}",
            f"Required:        {self.required_matched} of {self.required_total} present "
            f"({self.completion_percent:.0f}%)",
            f"Chain CPS:       {self.chain_cps:.2f}  ({self.chain_cps_band})",
        ]
        # Display AI-delta block when applicable.
        if self.chain_cps_without_ai is not None:
            from cps_engine.rubric import band as _band
            without_band = _band(self.chain_cps_without_ai)
            delta = self.chain_cps - self.chain_cps_without_ai
            band_shift = (
                f"{without_band} -> {self.chain_cps_band}"
                if without_band != self.chain_cps_band
                else f"{self.chain_cps_band} (no band shift)"
            )
            lines.append(
                f"Chain CPS (no AI): {self.chain_cps_without_ai:.2f}  "
                f"({without_band})"
            )
            lines.append(
                f"AI delta:        +{delta:.2f}  (band: {band_shift})"
            )
        if self.aggregate_mode:
            lines.append(
                "Mode:            AGGREGATE (no file/line data; matching by "
                "query-name presence only)"
            )
        if self.real_world_anchor:
            lines.append(f"Real-world anchor: {self.real_world_anchor}")
        if self.terminal_outcome:
            lines.append(f"Terminal outcome:  {self.terminal_outcome}")
        lines.append("")
        lines.append("Required findings:")
        for m in self.matches:
            check = "[ok]" if m.matched else "[--]"
            role = f" ({m.catalog_role})" if m.catalog_role else ""
            count = (
                f"  matched: {len(m.matched_findings)}"
                if m.matched
                else "  not found"
            )
            lines.append(f"  {check}  {m.catalog_query_name}{role}{count}")
        if self.missing:
            lines.append("")
            lines.append(f"Missing required findings ({len(self.missing)}):")
            for q in self.missing:
                lines.append(f"  - {q}")
        if self.ai_inventory:
            lines.append("")
            n_present = sum(
                1 for v in self.ai_inventory_matched.values() if v
            )
            lines.append(
                f"AI Inventory Context ({n_present} of "
                f"{len(self.ai_inventory)} components detected in scan):"
            )
            for entry in self.ai_inventory:
                comp = entry.get("component", "?")
                supp = entry.get("supplier", "?")
                ctype = entry.get("type", "?")
                key = f"{ctype}|{supp}|{comp}".lower()
                detected = self.ai_inventory_matched.get(key, False)
                marker = "[ok]" if detected else "[--]"
                target = (
                    " (CHAIN TARGET)" if entry.get("is_chain_target") else ""
                )
                lines.append(
                    f"  {marker}  {comp} ({supp} {ctype}){target}"
                )
        return "\n".join(lines)


@dataclass
class MatchReport:
    """The result of matching every chain catalog entry against scan findings."""
    catalog_path: str
    total_chains: int
    fully_assembled: list[ChainMatchResult]
    partially_assembled: list[ChainMatchResult]
    not_assembled: list[ChainMatchResult]
    aggregate_mode: bool

    def __str__(self) -> str:
        lines = [
            "=" * 80,
            "CHAIN DETECTION REPORT",
            "=" * 80,
            f"Catalog: {self.catalog_path}",
            f"Chains evaluated: {self.total_chains}",
            f"Fully assembled:    {len(self.fully_assembled)}",
            f"Partially assembled: {len(self.partially_assembled)}",
            f"Not assembled:      {len(self.not_assembled)}",
        ]
        if self.aggregate_mode:
            lines.append("")
            lines.append(
                "NOTE: input is an aggregate Checkmarx report; matching is "
                "by query-name presence only."
            )
        lines.append("")
        for chain in (
            self.fully_assembled + self.partially_assembled + self.not_assembled
        ):
            lines.append("")
            lines.append(str(chain))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Catalog loading
# ---------------------------------------------------------------------------


def load_chain_catalog(catalog_path: str | Path) -> dict[str, Any]:
    """Load and minimally validate a chains_index.json catalog file."""
    path = Path(catalog_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Chain catalog not found at {path}. Provide the path to "
            "chains_index.json or set --catalog on the CLI."
        )
    with path.open("r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if "chains" not in doc or not isinstance(doc["chains"], list):
        raise ValueError(
            f"{path} does not look like a chains_index.json file: "
            "missing top-level 'chains' array."
        )
    return doc


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def _match_one_chain(
    chain_entry: dict[str, Any],
    findings_by_normalized_name: dict[str, list[Finding]],
    aggregate_mode: bool,
) -> ChainMatchResult:
    required = chain_entry.get("required_findings", []) or []
    matches: list[FindingMatch] = []
    missing: list[str] = []

    for req in required:
        cat_qname = req.get("query_name", "")
        cat_role = req.get("role")
        normalized = normalize_query_name(cat_qname)
        scan_findings = findings_by_normalized_name.get(normalized, [])

        # Optional path scoping. When a catalog entry sets
        # ``match_file_contains``, only findings whose source file contains
        # that substring satisfy this required finding. This lets one query
        # name occupy several distinct chain positions -- e.g. the same
        # error-disclosure rule firing in an agent framework's MCP path, its
        # tool-execution path and its session-persistence path are different
        # chain participants, not one finding with three instances.
        scope = req.get("match_file_contains")
        if scope:
            needle = str(scope).lower()
            scan_findings = [
                f for f in scan_findings
                if needle in str(f.source_file).lower()
            ]

        label = cat_qname if not scope else f"{cat_qname}  [in {scope}]"
        match = FindingMatch(
            catalog_query_name=label,
            catalog_role=cat_role,
            matched_findings=list(scan_findings),
        )
        matches.append(match)
        if not match.matched:
            missing.append(label)

    required_total = len(required)
    required_matched = sum(1 for m in matches if m.matched)
    completion = (
        100.0 * required_matched / required_total if required_total else 0.0
    )

    # Decide assembly state.
    if required_total == 0:
        state = AssemblyState.NOT_ASSEMBLED
    elif required_matched == required_total:
        state = AssemblyState.FULLY_ASSEMBLED
    elif required_matched >= max(1, required_total // 2):
        state = AssemblyState.PARTIALLY_ASSEMBLED
    else:
        state = AssemblyState.NOT_ASSEMBLED

    # Compute chain CPS using the rubric formula on the *highest-scoring*
    # representative of each matched required finding. (When a query has
    # multiple instances, the highest CPS represents that finding's
    # contribution to the chain.)
    individual_scores: list[float] = []
    for m in matches:
        if not m.matched:
            continue
        best = max(
            (f.cps_score or 0.0 for f in m.matched_findings),
            default=0.0,
        )
        individual_scores.append(best)
    chain_cps = score_chain(individual_scores)

    # AI-delta computation. If the chain entry declares
    # `ai_leverage_findings`, compute chain CPS a second time with those
    # findings' contributions excluded. The delta between the two is the
    # framework's measurement of AI's weaponisation contribution.
    ai_leverage_query_names = chain_entry.get("ai_leverage_findings") or []
    ai_leverage_query_names_set = {
        str(q).lower() for q in ai_leverage_query_names
    }
    chain_cps_without_ai: float | None = None
    if ai_leverage_query_names_set:
        scores_without_ai: list[float] = []
        for m in matches:
            if not m.matched:
                continue
            if m.catalog_query_name.lower() in ai_leverage_query_names_set:
                # Skip — this is an AI-Leverage finding being excluded.
                continue
            best = max(
                (f.cps_score or 0.0 for f in m.matched_findings),
                default=0.0,
            )
            scores_without_ai.append(best)
        chain_cps_without_ai = score_chain(scores_without_ai)

    # AI-inventory presence check.
    ai_inventory = chain_entry.get("ai_inventory") or []
    ai_inventory_matched: dict[str, bool] = {}
    if ai_inventory:
        # Normalize a string so "Claude 3.5 Sonnet" and
        # "claude-3-5-sonnet-20241022" share an overlap. Strategy:
        # lower, collapse runs of non-alphanumeric to single space, strip
        # trailing version-y date suffixes is too aggressive, so we just
        # rely on substring containment after normalization.
        def _norm(s: str) -> str:
            out = []
            prev_sep = True
            for ch in s.lower():
                if ch.isalnum():
                    out.append(ch)
                    prev_sep = False
                else:
                    if not prev_sep:
                        out.append(" ")
                    prev_sep = True
            return "".join(out).strip()

        # Build a set of normalized "ctype||scan_value" strings from any
        # AI-BOM findings in the scan. Each entry is the normalized form
        # of the parser's full query name.
        scan_keys: list[tuple[str, str]] = []
        for fs in findings_by_normalized_name.values():
            for f in fs:
                if not f.query_name.lower().startswith("ai component"):
                    continue
                parts = f.query_name.split(" ", 3)
                if len(parts) >= 4:
                    ctype = parts[2].lower()
                    rest_norm = _norm(parts[3])
                    scan_keys.append((ctype, rest_norm))

        for entry in ai_inventory:
            comp = entry.get("component", "")
            supp = entry.get("supplier", "")
            ctype = entry.get("type", "").lower()
            key = f"{ctype}|{supp}|{comp}".lower()
            comp_n = _norm(comp)
            supp_n = _norm(supp)
            # Match if any scan key (same ctype) contains both the
            # normalized supplier and normalized component name.
            matched = False
            for sk_ctype, sk_norm in scan_keys:
                if sk_ctype != ctype:
                    continue
                # Component-name match: scan value contains the inventory
                # component name. We use up to the *first 4 tokens* of the
                # inventory name to handle BOMs that emit longer model
                # ids ("Claude 3.5 Sonnet" -> first three tokens
                # "claude 3 5" should appear inside
                # "claude 3 5 sonnet 20241022").
                comp_tokens = comp_n.split()
                comp_match_str = " ".join(comp_tokens[:4]) if comp_tokens else ""
                if not comp_match_str or comp_match_str not in sk_norm:
                    continue
                # Supplier match: tolerate naming variation between the
                # inventory declaration (often the PyPI namespace, e.g.
                # "langchain-ai") and the CycloneDX BOM (often the brand
                # name, e.g. "LangChain"). Require at least one shared
                # token between the normalized supplier strings, OR no
                # supplier declared on the inventory side. This prevents
                # both false negatives (the langchain-ai vs LangChain
                # bug seen in v5) and false positives (an unrelated
                # component matching by component name alone).
                if not supp_n:
                    matched = True
                    break
                supp_tokens = set(supp_n.split())
                # Tokens from the BOM-side scan key that aren't part of
                # the component name shouldn't count as shared — this
                # prevents matches where the only shared token is a
                # generic word that happens to also appear in the
                # component name. To keep this implementation simple,
                # we search the WHOLE sk_norm for any supplier token,
                # since the BOM emits "<supplier> <component>" and
                # we've already confirmed component-name match.
                sk_tokens = set(sk_norm.split())
                if supp_tokens & sk_tokens:
                    matched = True
                    break
            ai_inventory_matched[key] = matched

    return ChainMatchResult(
        chain_id=chain_entry.get("id", "?"),
        chain_name=chain_entry.get("name", ""),
        engines=list(chain_entry.get("engines", [])),
        real_world_anchor=chain_entry.get("real_world_anchor"),
        terminal_outcome=chain_entry.get("terminal_outcome"),
        state=state,
        required_total=required_total,
        required_matched=required_matched,
        completion_percent=completion,
        matches=matches,
        missing=missing,
        chain_cps=chain_cps,
        chain_cps_band=band(chain_cps),
        aggregate_mode=aggregate_mode,
        ai_inventory=ai_inventory,
        ai_inventory_matched=ai_inventory_matched,
        chain_cps_without_ai=chain_cps_without_ai,
        ai_delta_claim=chain_entry.get("ai_delta_claim"),
    )


def match_chains(
    findings: list[Finding],
    catalog_path: str | Path,
) -> MatchReport:
    """Match a list of scored findings against a chain catalog.

    Args:
        findings: scored Finding objects (cps_dimensions and cps_score
                  must already be populated — call score_findings first).
        catalog_path: path to a chains_index.json file.

    Returns:
        A MatchReport with one ChainMatchResult per catalog chain.

    Notes on aggregate-report findings: when the input is from an
    aggregate report, file/line data isn't available. The matcher falls
    back to query-name presence matching and flags the result.
    """
    doc = load_chain_catalog(catalog_path)
    chains = doc["chains"]
    aggregate_mode = is_aggregate_findings(findings)

    # Build a query-name -> findings index for fast matching.
    by_name: dict[str, list[Finding]] = {}
    for f in findings:
        key = normalize_query_name(f.query_name)
        by_name.setdefault(key, []).append(f)

    full: list[ChainMatchResult] = []
    partial: list[ChainMatchResult] = []
    none: list[ChainMatchResult] = []
    for chain_entry in chains:
        result = _match_one_chain(chain_entry, by_name, aggregate_mode)
        if result.state == AssemblyState.FULLY_ASSEMBLED:
            full.append(result)
        elif result.state == AssemblyState.PARTIALLY_ASSEMBLED:
            partial.append(result)
        else:
            none.append(result)

    return MatchReport(
        catalog_path=str(catalog_path),
        total_chains=len(chains),
        fully_assembled=full,
        partially_assembled=partial,
        not_assembled=none,
        aggregate_mode=aggregate_mode,
    )
