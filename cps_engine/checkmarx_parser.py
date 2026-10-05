"""
Checkmarx JSON parser.

Reads a Checkmarx scan report in JSON format and produces a list of
`Finding` objects ready for scoring.

Supported input shapes
----------------------
This parser tries each shape in order until one matches the input file:

1. Checkmarx One results JSON
   Top-level ``{"results": [...]}`` with per-finding objects under
   ``results[]``. Each finding has ``data.queryName``, ``severity``,
   ``vulnerabilityDetails.cweId``, ``data.languageName``, ``data.nodes``
   (with file/line), and either ``id`` or ``similarityId``. This is the
   shape produced by Checkmarx One's UI export and report API in
   current versions.

2. SARIF 2.1.0
   Top-level ``{"runs": [{"results": [...], "tool": ...}]}``. Each
   ``results[]`` has ``ruleId`` (the query), ``level`` (mapped to
   severity), ``locations[].physicalLocation.artifactLocation.uri`` and
   ``region.startLine``. CWE is read from rule properties when present.

3. CxSAST legacy JSON (with ``Results`` capitalized)
   Older Checkmarx on-prem exports. Same logical fields, different
   casing and a few different paths.

If your tenant's export does not match any of these shapes, the parser
raises ``UnsupportedReportShapeError`` listing what it tried. Adding a
new shape is one new function plus one entry in ``_PARSERS``.

Required logical fields
-----------------------
For each finding we extract:

    - finding_id     (similarity ID or stable result ID; falls back to
                      a synthesized "row-N" if neither exists)
    - query_name     (e.g., "Open_Redirect")
    - severity       ("Low", "Informational", etc. — kept verbatim)
    - language       (e.g., "Python")
    - cwe            (integer; 0 if unmapped)
    - source_file    (path string; "Unknown" if absent)
    - line           (integer; 0 if absent)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Iterable

from .rubric import Finding


class UnsupportedReportShapeError(ValueError):
    """Raised when the JSON input matches none of the known shapes."""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _get(obj: Any, *path: str, default: Any = None) -> Any:
    """Safe nested dict / list traversal.

    ``_get(obj, "a", "b", default=0)`` returns ``obj["a"]["b"]`` when both
    levels exist, otherwise ``default``. Tolerates non-dict intermediates
    (returns default) so we don't have to wrap every access in try/except.
    """
    cur = obj
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def _coerce_int(value: Any, default: int = 0) -> int:
    """Best-effort int coercion that accepts strings like 'CWE-601'."""
    if value is None:
        return default
    if isinstance(value, bool):
        # Guard: bools are ints in Python but not what we want here.
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        digits = "".join(ch for ch in value if ch.isdigit())
        if digits:
            try:
                return int(digits)
            except ValueError:
                return default
    return default


def _norm_severity(value: Any) -> str:
    """Normalize a severity field to a stable display string.

    Checkmarx and SARIF use slightly different vocabularies. We keep the
    raw form when it's recognisable and translate SARIF levels to
    Checkmarx-style names so the rest of the pipeline doesn't have to
    worry about the difference.
    """
    if not value:
        return "Unknown"
    s = str(value).strip()
    sarif_to_cx = {
        "error": "High",
        "warning": "Medium",
        "note": "Low",
        "none": "Informational",
    }
    return sarif_to_cx.get(s.lower(), s)


# ---------------------------------------------------------------------------
# Shape #1: Checkmarx One results JSON
# ---------------------------------------------------------------------------


def _parse_cxone_results_json(doc: Any) -> list[Finding] | None:
    """Parse Checkmarx One results JSON. Returns None if shape doesn't match."""
    if not isinstance(doc, dict):
        return None

    # Identify the shape: must have a list under "results" whose first
    # element looks Checkmarx-One-shaped (has either "data" or "vulnerabilityDetails").
    results = doc.get("results")
    if not isinstance(results, list) or not results:
        return None
    sample = results[0]
    if not isinstance(sample, dict):
        return None
    if "data" not in sample and "vulnerabilityDetails" not in sample:
        return None

    findings: list[Finding] = []
    for idx, item in enumerate(results, start=1):
        if not isinstance(item, dict):
            continue

        query_name = (
            _get(item, "data", "queryName")
            or _get(item, "data", "ruleName")
            or item.get("queryName")
            or ""
        )
        query_name = str(query_name).strip()
        if not query_name:
            continue

        severity = _norm_severity(item.get("severity"))

        cwe = _coerce_int(
            _get(item, "vulnerabilityDetails", "cweId")
            or _get(item, "data", "cweId")
            or item.get("cwe")
        )

        language = (
            _get(item, "data", "languageName")
            or item.get("language")
            or "Unknown"
        )

        # Locations: Checkmarx One uses "data.nodes" (a list of taint-flow
        # nodes). The first node is typically the source; the last is the
        # sink. We use the sink for reporting purposes since that's where
        # the finding is "raised" — that matches what Checkmarx shows in
        # its UI.
        nodes = _get(item, "data", "nodes", default=None)
        source_file = "Unknown"
        line = 0
        if isinstance(nodes, list) and nodes:
            sink = nodes[-1] if isinstance(nodes[-1], dict) else None
            if sink is not None:
                source_file = (
                    sink.get("fileName")
                    or sink.get("filePath")
                    or sink.get("file")
                    or "Unknown"
                )
                line = _coerce_int(sink.get("line") or sink.get("lineNumber"))
        if source_file == "Unknown":
            # Some exports put a single location at the top level instead.
            source_file = (
                item.get("fileName")
                or _get(item, "location", "filename")
                or "Unknown"
            )
            line = line or _coerce_int(
                item.get("line")
                or _get(item, "location", "line")
            )

        finding_id = (
            item.get("similarityId")
            or item.get("id")
            or _get(item, "data", "resultHash")
            or f"row-{idx}"
        )

        findings.append(
            Finding(
                finding_id=str(finding_id),
                query_name=query_name,
                cwe=cwe,
                default_severity=severity,
                language=str(language),
                source_file=str(source_file),
                line=line,
            )
        )

    return findings if findings else None


# ---------------------------------------------------------------------------
# Shape #2: SARIF 2.1.0
# ---------------------------------------------------------------------------


def _parse_sarif(doc: Any) -> list[Finding] | None:
    """Parse a SARIF 2.1.0 report. Returns None if shape doesn't match."""
    if not isinstance(doc, dict):
        return None
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        return None
    first_run = runs[0]
    if not isinstance(first_run, dict):
        return None
    # Look for the SARIF discriminator keys.
    if "tool" not in first_run and "results" not in first_run:
        return None

    # Build a rule-id -> rule-metadata index so we can resolve CWE etc.
    rule_index: dict[str, dict] = {}
    for run in runs:
        if not isinstance(run, dict):
            continue
        rules = _get(run, "tool", "driver", "rules", default=[]) or []
        if isinstance(rules, list):
            for rule in rules:
                if isinstance(rule, dict) and rule.get("id"):
                    rule_index[rule["id"]] = rule

    findings: list[Finding] = []
    counter = 0
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results", [])
        if not isinstance(results, list):
            continue
        for item in results:
            if not isinstance(item, dict):
                continue
            counter += 1

            rule_id = item.get("ruleId") or ""
            if not rule_id:
                continue

            severity = _norm_severity(item.get("level"))

            # CWE often comes from the rule's properties.tags or
            # properties.cwe field; we look in both.
            cwe = 0
            rule = rule_index.get(rule_id, {})
            tags = _get(rule, "properties", "tags", default=[]) or []
            if isinstance(tags, list):
                for tag in tags:
                    cwe_candidate = _coerce_int(tag)
                    if cwe_candidate:
                        cwe = cwe_candidate
                        break
            if not cwe:
                cwe = _coerce_int(_get(rule, "properties", "cwe"))

            # Location: first physicalLocation only — chained locations
            # in SARIF aren't relevant to per-finding scoring.
            location = (item.get("locations") or [{}])[0] if item.get("locations") else {}
            artifact_uri = _get(
                location, "physicalLocation", "artifactLocation", "uri",
                default="Unknown",
            )
            line = _coerce_int(
                _get(location, "physicalLocation", "region", "startLine")
            )

            finding_id = (
                item.get("guid")
                or item.get("correlationGuid")
                or _get(item, "fingerprints", "primary")
                or f"sarif-{counter}"
            )

            findings.append(
                Finding(
                    finding_id=str(finding_id),
                    query_name=str(rule_id),
                    cwe=cwe,
                    default_severity=severity,
                    language="Unknown",  # SARIF doesn't carry language here
                    source_file=str(artifact_uri),
                    line=line,
                )
            )

    return findings if findings else None


# ---------------------------------------------------------------------------
# Shape #3: CxSAST legacy JSON (capitalized "Results")
# ---------------------------------------------------------------------------


def _parse_cxsast_legacy_json(doc: Any) -> list[Finding] | None:
    """Parse legacy on-prem CxSAST JSON. Returns None if shape doesn't match."""
    if not isinstance(doc, dict):
        return None
    queries = doc.get("Queries") or doc.get("queries")
    if not isinstance(queries, list) or not queries:
        return None
    sample = queries[0]
    if not isinstance(sample, dict):
        return None
    # Discriminator: legacy export groups results under each query.
    if "Results" not in sample and "results" not in sample:
        return None

    findings: list[Finding] = []
    counter = 0
    for query in queries:
        if not isinstance(query, dict):
            continue
        query_name = query.get("QueryName") or query.get("name") or ""
        if not query_name:
            continue
        severity = _norm_severity(query.get("Severity") or query.get("severity"))
        cwe = _coerce_int(query.get("CweId") or query.get("cwe"))
        language = query.get("Language") or query.get("language") or "Unknown"

        results = query.get("Results") or query.get("results") or []
        if not isinstance(results, list):
            continue
        for r in results:
            if not isinstance(r, dict):
                continue
            counter += 1
            source_file = (
                r.get("FileName")
                or r.get("fileName")
                or _get(r, "Path", "FileName")
                or "Unknown"
            )
            line = _coerce_int(
                r.get("Line")
                or r.get("line")
                or _get(r, "Path", "Line")
            )
            finding_id = (
                r.get("SimilarityId")
                or r.get("similarityId")
                or r.get("PathId")
                or f"legacy-{counter}"
            )
            findings.append(
                Finding(
                    finding_id=str(finding_id),
                    query_name=str(query_name),
                    cwe=cwe,
                    default_severity=severity,
                    language=str(language),
                    source_file=str(source_file),
                    line=line,
                )
            )

    return findings if findings else None


# ---------------------------------------------------------------------------
# Shape #4: Checkmarx One Improved Project Report (aggregate)
# ---------------------------------------------------------------------------
# This shape is fundamentally different from the others: it carries
# aggregated counts rather than per-finding records. The export does not
# include source-file/line locations for every finding, only a top-N
# list of vulnerable files and a top-N list of vulnerability types.
#
# We extract what we can: each entry in topTenVulnerabilityType becomes
# one or more synthetic Finding objects (one per (query_name, severity)
# pair, replicated by the count). File locations are best-effort: if the
# query name appears uniquely in topTenVulnerableFiles, we attach that
# path; otherwise the finding is left with source_file="<aggregate>".
#
# Findings produced from this shape have finding_id prefixed with "agg-"
# so downstream code can detect that they are derived from aggregate
# data rather than a per-finding export.


AGGREGATE_FINDING_ID_PREFIX = "agg-"


def _parse_cxone_improved_project_report(doc: Any) -> list[Finding] | None:
    """Parse a Checkmarx One Improved Project Report (aggregate). May return
    None if the shape doesn't match.

    The report's discriminators are the simultaneous presence of
    ``reportType == "Improved Project Report"`` (or similar) and the
    ``topTenVulnerabilityType.vulnerabilitiesList`` aggregation. We
    accept either signal to be tolerant of small report-type-name
    variations across versions.
    """
    if not isinstance(doc, dict):
        return None

    report_type = (doc.get("reportType") or "").lower()
    vuln_block = _get(doc, "topTenVulnerabilityType", "vulnerabilitiesList")
    if not isinstance(vuln_block, list) or not vuln_block:
        return None
    # Discriminator: report_type contains "project report" OR the doc has
    # the unique combination of severityDistribution + topTenVulnerableFiles
    # that this report shape uses.
    looks_like_project_report = (
        "project report" in report_type
        or "topTenVulnerableFiles" in doc
        or "languageOverview" in doc
    )
    if not looks_like_project_report:
        return None

    # Build a (query_name -> file_path) hint map from topTenVulnerableFiles.
    # The report doesn't tell us which queries hit which files directly,
    # so this is an imperfect heuristic — useful when only one file appears
    # for a given query, but we can't fully reconstruct co-locations.
    file_hint: dict[str, str] = {}
    files_block = doc.get("topTenVulnerableFiles") or []
    if isinstance(files_block, list) and len(files_block) == 1:
        # Single-file projects: every finding lives in that one file.
        only = files_block[0]
        if isinstance(only, dict):
            sole_file = only.get("fileName", "")
            if sole_file:
                file_hint["__sole__"] = sole_file

    findings: list[Finding] = []
    counter = 0
    for entry in vuln_block:
        if not isinstance(entry, dict):
            continue
        query_name = entry.get("vulnerabilityType") or ""
        if not query_name:
            continue
        # Each severity bucket inside the entry contributes its count.
        sev_breakdown = entry.get("vulnerabilitySeverities") or []
        if not isinstance(sev_breakdown, list):
            continue
        for sev_entry in sev_breakdown:
            if not isinstance(sev_entry, dict):
                continue
            level = _norm_severity(sev_entry.get("level"))
            count = _coerce_int(sev_entry.get("value"), 0)
            if count <= 0:
                continue
            for instance in range(1, count + 1):
                counter += 1
                source_file = file_hint.get("__sole__", "<aggregate>")
                findings.append(
                    Finding(
                        finding_id=f"{AGGREGATE_FINDING_ID_PREFIX}{counter}",
                        query_name=query_name,
                        cwe=0,  # not present in aggregate report
                        default_severity=level,
                        language=str(
                            _get(doc, "languageOverview", default=[{}])[0].get(
                                "languageName", "Unknown"
                            )
                            if doc.get("languageOverview")
                            else "Unknown"
                        ).strip()
                        or "Unknown",
                        source_file=source_file,
                        line=0,
                    )
                )

    return findings if findings else None


# ---------------------------------------------------------------------------
# Shape #5: Checkmarx One "Vulnerability Type" comprehensive scan report
# ---------------------------------------------------------------------------
# This is the report shape returned by Checkmarx One's report API for
# multi-engine scans. It contains per-engine sections with full per-finding
# detail, including SAST taint-flow nodes, IaC structural pointers, and
# SCA package/CVE breakdowns.
#
# Structure (top-level):
#     reportType        : "Vulnerability Type"
#     reportHeader      : project metadata, severity distribution, scanners
#     scanInformation   : scan ID, LOC counts, duration
#     scanResults       : { resultsList[] }   -- SAST
#     iacScanResults    : { technology[].queries[].resultsList[] }
#     scaScanResults    : { packages[].packageCategory[].categoryResults[] }
#     containerScanResults  : (similar shape; not yet exercised in the lab)
#
# SAST per-finding shape:
#     scanResults.resultsList[*]:
#         queryName    : "Use_Of_Hardcoded_Password"
#         queryId      : 10308959669028119927
#         queryPath    : "Python/Python_Medium_Threat/Use_Of_Hardcoded_Password"
#         cweId        : 259
#         vulnerabilities[*]:
#             severity, sourceFileName, sourceLine,
#             destinationFileName, destinationLine, similarityId
#
# IaC per-finding shape:
#     iacScanResults.technology[*]:
#         name        : "Kubernetes" | "Terraform" | ...
#         queries[*]:
#             queryName, category
#             resultsList[*]:
#                 severity, fileName, status, state
#
# SCA per-finding shape:
#     scaScanResults.packages[*]:
#         packageName, packageVersion, packageId
#         packageCategory[*]:
#             categoryName     : "CWE-539" | "CWE-524" | ...
#             categoryResults[*]:
#                 cve, severity, status, state, resultId


def _parse_cxone_vulnerability_type_report(doc: Any) -> list[Finding] | None:
    """Parse a Checkmarx One Vulnerability Type comprehensive scan report.

    Returns None if the document doesn't match the expected shape.
    """
    if not isinstance(doc, dict):
        return None

    # Discriminator: "reportType": "Vulnerability Type" plus the per-engine
    # section keys. We accept either "Vulnerability Type" verbatim or the
    # presence of all three primary engine sections, to tolerate small
    # report-type-name changes between Checkmarx versions.
    report_type = (doc.get("reportType") or "").strip().lower()
    has_engine_sections = (
        "scanResults" in doc
        or "iacScanResults" in doc
        or "scaScanResults" in doc
    )
    if "vulnerability type" not in report_type and not has_engine_sections:
        return None

    findings: list[Finding] = []
    counter = 0

    # ----- SAST: scanResults.resultsList[*].vulnerabilities[*] ------------
    sast = doc.get("scanResults")
    if isinstance(sast, dict):
        results_list = sast.get("resultsList") or []
        if isinstance(results_list, list):
            for query_entry in results_list:
                if not isinstance(query_entry, dict):
                    continue
                query_name = query_entry.get("queryName") or ""
                cwe = _coerce_int(query_entry.get("cweId"))
                # Language is sometimes embedded in queryPath, e.g.
                # "Python/Python_Medium_Threat/Use_Of_Hardcoded_Password".
                language = "Unknown"
                qpath = query_entry.get("queryPath") or ""
                if isinstance(qpath, str) and "/" in qpath:
                    language = qpath.split("/", 1)[0]
                vulns = query_entry.get("vulnerabilities") or []
                if not isinstance(vulns, list):
                    continue
                for v in vulns:
                    if not isinstance(v, dict):
                        continue
                    counter += 1
                    severity = _norm_severity(v.get("severity"))
                    # Prefer destinationFileName as the sink — that is what
                    # Checkmarx's UI displays as the finding's "file".
                    source_file = (
                        v.get("destinationFileName")
                        or v.get("sourceFileName")
                        or "Unknown"
                    )
                    line = _coerce_int(
                        v.get("destinationLine") or v.get("sourceLine")
                    )
                    finding_id = str(
                        v.get("similarityId")
                        or v.get("resultId")
                        or f"sast-{counter}"
                    )
                    findings.append(
                        Finding(
                            finding_id=finding_id,
                            query_name=str(query_name),
                            cwe=cwe,
                            default_severity=severity,
                            language=str(language),
                            source_file=str(source_file),
                            line=line,
                        )
                    )

    # ----- IaC: iacScanResults.technology[*].queries[*].resultsList[*] ----
    iac = doc.get("iacScanResults")
    if isinstance(iac, dict):
        technologies = iac.get("technology") or []
        if isinstance(technologies, list):
            for tech in technologies:
                if not isinstance(tech, dict):
                    continue
                tech_name = tech.get("name") or "IaC"
                queries = tech.get("queries") or []
                if not isinstance(queries, list):
                    continue
                for query_entry in queries:
                    if not isinstance(query_entry, dict):
                        continue
                    query_name = query_entry.get("queryName") or ""
                    results_list = query_entry.get("resultsList") or []
                    if not isinstance(results_list, list):
                        continue
                    for r in results_list:
                        if not isinstance(r, dict):
                            continue
                        counter += 1
                        severity = _norm_severity(r.get("severity"))
                        source_file = r.get("fileName") or "Unknown"
                        # IaC findings carry no line; the structural pointer
                        # is in actualValue, which we don't try to parse.
                        line = 0
                        finding_id = (
                            r.get("resultViewerLink")
                            or r.get("resultId")
                            or f"iac-{counter}"
                        )
                        # Strip URL prefix from the result-viewer link if
                        # that's what we got — the trailing path is the
                        # actual identifier.
                        if (
                            isinstance(finding_id, str)
                            and finding_id.startswith("http")
                            and "result-id=" in finding_id
                        ):
                            finding_id = finding_id.split("result-id=", 1)[1]
                        findings.append(
                            Finding(
                                finding_id=str(finding_id),
                                query_name=str(query_name),
                                cwe=0,
                                default_severity=severity,
                                language=str(tech_name),
                                source_file=str(source_file),
                                line=line,
                            )
                        )

    # ----- SCA: scaScanResults.packages[*].packageCategory[*]
    #                          .categoryResults[*] -------------------------
    sca = doc.get("scaScanResults")
    if isinstance(sca, dict):
        packages = sca.get("packages") or []
        if isinstance(packages, list):
            for pkg in packages:
                if not isinstance(pkg, dict):
                    continue
                pkg_name = pkg.get("packageName") or "Unknown"
                pkg_version = pkg.get("packageVersion") or ""
                # SCA findings live in the dependency manifest; we don't
                # know which exact manifest from this shape, so we use a
                # synthetic identifier that names the package.
                source_file = f"<dependency:{pkg_name}@{pkg_version}>"
                categories = pkg.get("packageCategory") or []
                if not isinstance(categories, list):
                    continue
                for cat in categories:
                    if not isinstance(cat, dict):
                        continue
                    cwe = _coerce_int(cat.get("categoryName"))
                    cat_results = cat.get("categoryResults") or []
                    if not isinstance(cat_results, list):
                        continue
                    for r in cat_results:
                        if not isinstance(r, dict):
                            continue
                        counter += 1
                        severity = _norm_severity(r.get("severity"))
                        # Use the CVE id as the query name so the engine's
                        # CVE-aware lookup (defaults dispatch via _is_cve_*)
                        # routes to the appropriate _sca_* class.
                        query_name = r.get("cve") or "Unknown_CVE"
                        finding_id = (
                            r.get("resultId") or f"sca-{counter}"
                        )
                        findings.append(
                            Finding(
                                finding_id=str(finding_id),
                                query_name=str(query_name),
                                cwe=cwe,
                                default_severity=severity,
                                language="Python",  # heuristic; pkgs are PyPI
                                source_file=str(source_file),
                                line=0,
                            )
                        )

    # ----- Container Security: containerScanResults --------------------
    # Shape assumption: parallel to iacScanResults — technology[]
    # containing queries[] containing resultsList[]. The "technology"
    # values for Container Security are typically "Dockerfile" (KICS
    # static rules) and "BaseImage" (package CVEs from the base image).
    # If the real tenant shape differs, adapt this block.
    container = doc.get("containerScanResults")
    if isinstance(container, dict):
        technologies = container.get("technology") or []
        if isinstance(technologies, list):
            for tech in technologies:
                if not isinstance(tech, dict):
                    continue
                tech_name = tech.get("name") or "Container"
                queries = tech.get("queries") or []
                if not isinstance(queries, list):
                    continue
                for query_entry in queries:
                    if not isinstance(query_entry, dict):
                        continue
                    query_name = query_entry.get("queryName") or ""
                    results_list = query_entry.get("resultsList") or []
                    if not isinstance(results_list, list):
                        continue
                    for r in results_list:
                        if not isinstance(r, dict):
                            continue
                        counter += 1
                        severity = _norm_severity(r.get("severity"))
                        source_file = r.get("fileName") or "Unknown"
                        finding_id = (
                            r.get("resultId") or f"container-{counter}"
                        )
                        findings.append(
                            Finding(
                                finding_id=str(finding_id),
                                query_name=str(query_name),
                                cwe=0,
                                default_severity=severity,
                                language=str(tech_name),
                                source_file=str(source_file),
                                line=0,
                            )
                        )

    return findings if findings else None


# ---------------------------------------------------------------------------
# Shape #6: CycloneDX 1.x AI Bill of Materials (Checkmarx AI Supply Chain)
# ---------------------------------------------------------------------------
# CycloneDX is an OASIS standard. Checkmarx AI Supply Chain Security
# emits CycloneDX 1.7 documents listing detected AI components — both
# machine-learning-model components (e.g., GPT-4o, Claude, Gemini) and
# library components (e.g., LangChain, Google ADK, Pinecone).
#
# These exports are tenant-wide rather than per-project: all components
# detected across the tenant appear in one document. Each component
# carries `properties[].name == "ProjectName"` identifying its origin.
# The parser filters by project when ``project_filter`` is supplied.
#
# AI-BOM components don't have severity in the CycloneDX schema. We
# synthesize a query name based on component type ("machine-learning-model"
# or "library") and a default severity of "Informational" so the dimension
# defaults table can score them; see the `ai_component_*` entries.


AI_BOM_FINDING_ID_PREFIX = "ai-"


def _parse_cyclonedx_ai_bom(
    doc: Any,
    project_filter: str | None = None,
) -> list[Finding] | None:
    """Parse a CycloneDX 1.x AI BOM. Returns None if shape doesn't match.

    Args:
        doc: parsed JSON document.
        project_filter: optional substring matched against each component's
            ``properties[name=ProjectName].value``. When supplied, only
            components whose ProjectName *contains* this substring are kept.
            Use to filter a tenant-wide BOM down to one project.
    """
    if not isinstance(doc, dict):
        return None

    # Discriminator: bomFormat == "CycloneDX" and components present.
    if (doc.get("bomFormat") or "").lower() != "cyclonedx":
        return None
    components = doc.get("components")
    if not isinstance(components, list):
        return None

    findings: list[Finding] = []
    counter = 0
    for comp in components:
        if not isinstance(comp, dict):
            continue
        ctype = (comp.get("type") or "").lower()

        # Only synthesize findings for AI-relevant component types. CycloneDX
        # uses "machine-learning-model" for models and "library" for SDKs/
        # frameworks. We keep both for AI-BOM purposes; non-AI libraries
        # are filtered later by name pattern (we accept all libraries here
        # because we have no reliable way to distinguish AI from non-AI
        # libraries from the type alone).
        if ctype not in ("machine-learning-model", "library"):
            continue

        # Project filter — match against ProjectName property.
        if project_filter is not None:
            project_name = ""
            for prop in comp.get("properties") or []:
                if (
                    isinstance(prop, dict)
                    and prop.get("name") == "ProjectName"
                ):
                    project_name = str(prop.get("value") or "")
                    break
            if project_filter not in project_name:
                continue

        comp_name = (comp.get("name") or "Unknown").strip()
        supplier = ""
        sup = comp.get("supplier")
        if isinstance(sup, dict):
            supplier = (sup.get("name") or "").strip()

        # Synthesize a query name. The matcher will look up dimension
        # defaults via `ai_component_machine_learning_model` or
        # `ai_component_library` (the normalizer collapses spaces).
        query_name = f"AI Component {ctype} {supplier} {comp_name}".strip()
        normalized_type_key = (
            "ai_component_machine_learning_model"
            if ctype == "machine-learning-model"
            else "ai_component_library"
        )

        # Use the first occurrence's location as the source_file for
        # display purposes.
        source_file = "<ai-component>"
        line = 0
        evidence = comp.get("evidence")
        if isinstance(evidence, dict):
            occs = evidence.get("occurrences")
            if isinstance(occs, list) and occs:
                first_occ = occs[0]
                if isinstance(first_occ, dict):
                    source_file = (
                        first_occ.get("location") or source_file
                    )
                    line = _coerce_int(first_occ.get("line"))

        bom_ref = comp.get("bom-ref") or f"ai-{counter}"
        counter += 1
        findings.append(
            Finding(
                finding_id=f"{AI_BOM_FINDING_ID_PREFIX}{bom_ref}",
                # Two-step name: human-readable query for display, plus
                # a normalized class key in the language field so the
                # scoring lookup can route via the synthetic class.
                query_name=query_name,
                cwe=0,
                default_severity="Informational",
                language=normalized_type_key,
                source_file=str(source_file),
                line=line,
            )
        )

    return findings if findings else None


def parse_cyclonedx_ai_bom(
    json_path: str | Path,
    project_filter: str | None = None,
) -> list[Finding]:
    """Parse a CycloneDX AI BOM file. Public entry point.

    Args:
        json_path: path to the CycloneDX JSON file.
        project_filter: optional substring matched against components'
            ProjectName property to filter a tenant-wide BOM.

    Returns:
        Findings list. Each Finding carries language=ai_component_*
        which the scorer uses to dispatch to the right defaults class.

    Raises:
        FileNotFoundError, json.JSONDecodeError, UnsupportedReportShapeError.
    """
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"CycloneDX AI BOM not found at {path}")
    with path.open("r", encoding="utf-8-sig") as fh:
        doc = json.load(fh)
    findings = _parse_cyclonedx_ai_bom(doc, project_filter=project_filter)
    if findings is None:
        raise UnsupportedReportShapeError(
            f"{path} is not a recognized CycloneDX AI BOM document. "
            "Expected bomFormat=CycloneDX and a top-level components[] array."
        )
    return findings


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


# Order matters: the most specific / most common shape goes first.
_PARSERS: tuple[tuple[str, Callable[[Any], list[Finding] | None]], ...] = (
    ("Checkmarx One Vulnerability Type comprehensive report",
     _parse_cxone_vulnerability_type_report),
    ("Checkmarx One results JSON", _parse_cxone_results_json),
    ("SARIF 2.1.0", _parse_sarif),
    ("CxSAST legacy JSON", _parse_cxsast_legacy_json),
    ("Checkmarx One Improved Project Report (aggregate)",
     _parse_cxone_improved_project_report),
)


def parse_checkmarx_json(json_path: str | Path) -> list[Finding]:
    """Parse a Checkmarx JSON report into a list of Finding objects.

    Args:
        json_path: filesystem path to the JSON file.

    Returns:
        A list of Finding objects without cps_dimensions populated.

    Raises:
        FileNotFoundError: if json_path does not exist.
        json.JSONDecodeError: if the file isn't valid JSON.
        UnsupportedReportShapeError: if no known shape matches.

    Note:
        If the input is an aggregate report (Improved Project Report),
        the returned Findings will have finding_id values prefixed with
        ``agg-`` and source_file values of ``<aggregate>``. Use
        ``is_aggregate_findings()`` to detect this case.
    """
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"Checkmarx JSON not found at {path}")

    with path.open("r", encoding="utf-8-sig") as fh:
        doc = json.load(fh)

    tried: list[str] = []
    for name, fn in _PARSERS:
        tried.append(name)
        result = fn(doc)
        if result is not None:
            return result

    raise UnsupportedReportShapeError(
        f"None of the known JSON shapes matched: tried {', '.join(tried)}. "
        "If your tenant's export uses a different structure, paste a 5-row "
        "anonymized sample so the parser can be extended."
    )


def is_aggregate_findings(findings: Iterable[Finding]) -> bool:
    """True if the findings came from an aggregate-only report shape.

    Aggregate shapes (e.g., Improved Project Report) lack per-finding
    file/line locations, so chain detection is not fully possible from
    them. Callers can use this to display an explanatory warning.

    AI-BOM findings (prefix ``ai-``) are inventory data and are excluded
    from this check — a mixed Vulnerability-Type-report-plus-AI-BOM input
    is not "aggregate" just because the AI-BOM portion is presence-only.
    """
    findings = [
        f for f in findings
        if not f.finding_id.startswith(AI_BOM_FINDING_ID_PREFIX)
    ]
    if not findings:
        return False
    return all(f.finding_id.startswith(AGGREGATE_FINDING_ID_PREFIX) for f in findings)


def filter_low_severity(findings: Iterable[Finding]) -> list[Finding]:
    """Return only findings whose default severity is Low or Informational.

    The Low-only catalog discipline (paper Section 5) restricts attention
    to findings that Checkmarx rates Low or below. This helper isolates
    them from a mixed scan result.
    """
    low_set = {"low", "informational", "information", "info"}
    return [f for f in findings if f.default_severity.strip().lower() in low_set]
