"""
Default CPS dimension scores per Checkmarx query family.

Each entry maps a normalized query name to the default DimensionScores tuple
we assign to it. These defaults reflect the rubric work documented in the
research paper Section 4 and the verification work against the Checkmarx
v9.7.0 query catalog.

A few notes on the discipline used here:

1. All entries below correspond to queries that Checkmarx rates Low or
   Informational by default in v9.7.0. Medium/High queries are intentionally
   absent — this catalog supports the strict Low-only chain discipline
   described in the paper.

2. Where the same conceptual query exists across multiple language packages
   with the same severity (e.g., Log_Forging is Low in CPP, C#, Go, Java,
   Python, etc.), one entry covers all instances. The matcher in
   `cps_engine.scorer` performs case-insensitive lookup.

3. Where a query name varies across languages for the same concept (e.g.,
   Use_of_Insufficiently_Random_Values vs Use_of_Non_Cryptographic_Random
   vs Insecure_Randomness — all CWE-330 Low), each name has its own entry
   so the lookup is direct, but the dimension scores are kept consistent.

4. AI Leverage is set per-finding based on how much current AI tooling
   compresses exploitation cost for that specific weakness. These values
   are starting hypotheses for the framework — community calibration is
   expected to adjust them.

When a query name in a scan result is not in this table, the scorer will
emit a warning and fall back to a conservative default. See
`UNKNOWN_QUERY_DEFAULT` below.
"""

from __future__ import annotations

from .rubric import (
    AILeverage,
    BlastRadius,
    ChainUtility,
    DimensionScores,
    ImpactProximity,
    Prevalence,
)


# ---------------------------------------------------------------------------
# Default dimension scores per query family
# ---------------------------------------------------------------------------
# Lookup is case-insensitive on the query name. The matcher normalizes
# whitespace and casing before lookup.

DEFAULTS: dict[str, DimensionScores] = {
    # ----- Trust boundary / authorization (CWE-501, CWE-285) ----------------
    "trust_boundary_violation_in_session_variables": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.CRITICAL,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    # ----- Information exposure (CWE-200, CWE-209) -------------------------
    "information_exposure_via_headers": DimensionScores(
        prevalence=Prevalence.CRITICAL,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.CRITICAL,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "information_exposure_through_an_error_message": DimensionScores(
        prevalence=Prevalence.CRITICAL,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    # ----- URL handling (CWE-601, CWE-647) ---------------------------------
    "open_redirect": DimensionScores(
        prevalence=Prevalence.CRITICAL,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    # ----- Confirmed tenant-emitted JS query names (CH-003 / CH-004) -------
    # These names were observed firing in the validation tenant's JavaScript
    # preset with the severities noted. Added so chains built from them score
    # against real dimensions rather than the unknown-query fallback.
    "missing_hsts_header": DimensionScores(     # tenant: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,      # enables downgrade/interception
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "httponly_cookie_flag_not_set": DimensionScores(  # tenant: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,        # cookie readable by script
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.HIGH,  # session material is near-terminal
    ),
    "secret_leak_in_error_messages": DimensionScores(  # tenant: Low
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.HIGH,        # leaked key material is chain glue
        ai_leverage=AILeverage.HIGH,            # agents parse error output at scale
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "information_exposure_through_headers": DimensionScores(  # tenant: Low
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,        # version disclosure feeds CVE lookup
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),
    "client_weak_cryptographic_hash": DimensionScores(  # tenant: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,        # forgeable state/CSRF/token values
        ai_leverage=AILeverage.HIGH,            # collision/brute work is automatable
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "use_of_deprecated_or_obsolete_functions": DimensionScores(  # tenant: Low
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "use_of_http_sensitive_data_exposure": DimensionScores(  # tenant: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,        # plaintext channel carries secrets
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "unchecked_input_for_loop_condition": DimensionScores(  # tenant: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    # ----- Path / file-system reach (CWE-22, CWE-23) -----------------------
    "path_traversal": DimensionScores(
        prevalence=Prevalence.CRITICAL,
        chain_utility=ChainUtility.HIGH,      # bridge to arbitrary file I/O
        ai_leverage=AILeverage.HIGH,          # AI-assisted path crafting common
        blast_radius=BlastRadius.HIGH,        # file system surface is broad
        impact_proximity=ImpactProximity.HIGH, # one step from RCE/credential read
    ),
    "improper_limitation_of_a_pathname": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "stored_open_redirect": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "url_canonicalization_issue": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    # ----- Logging-related (CWE-117) ---------------------------------------
    "log_forging": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "stored_log_forging": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "xs_log_injection": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    # ----- Randomness (CWE-330, CWE-338) -----------------------------------
    "use_of_insufficiently_random_values": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.CRITICAL,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "use_of_non_cryptographic_random": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.CRITICAL,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "insecure_randomness": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.CRITICAL,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "client_insecure_randomness": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    # ----- Cookies / session (CWE-1004, CWE-614, CWE-539) ------------------
    "httponly_cookie_flag_not_set": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "secure_cookie_flag_not_set": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "information_leak_through_persistent_cookies": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    # ----- Credentials and secrets (CWE-522, CWE-259, CWE-260, CWE-798) ----
    "insufficiently_protected_credentials": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "use_of_hardcoded_password": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.CRITICAL,
    ),
    "use_of_hardcoded_password_in_config": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.CRITICAL,
    ),
    "hardcoded_aws_credentials": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.CRITICAL,
    ),
    "password_in_comment": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.HIGH,
    ),
    # ----- Cryptography (CWE-327, CWE-328, CWE-329, CWE-780) ---------------
    "use_of_broken_or_risky_cryptographic_algorithm": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.LOW,
    ),
    "reversible_one_way_hash": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "not_using_a_random_iv_with_cbc_mode": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "use_of_rsa_algorithm_without_oaep": DimensionScores(
        prevalence=Prevalence.LOW,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    # ----- CORS / security headers (CWE-346, CWE-1021) ---------------------
    "overly_permissive_cross_origin_resource_sharing_policy": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "missing_content_security_policy": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "permissive_content_security_policy": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "missing_framing_policy": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    # ----- Resource handling (CWE-404, CWE-732) ----------------------------
    "improper_resource_shutdown_or_release": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "incorrect_permission_assignment_for_file_system_resources": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "leaving_temporary_files": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),
    # ----- IaC: Cloud / network configuration ------------------------------
    # KICS-style query names. Stored as lowercase with single underscores
    # (the normalizer maps spaces and underscores into the canonical form).
    "iam_policy_with_resource_wildcard": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "iam_policies_with_full_administrative_privileges": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.CRITICAL,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "instance_metadata_service_v1_allowed": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.CRITICAL,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "imdsv1_enabled": DimensionScores(  # alias used by some KICS versions
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.CRITICAL,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "s3_bucket_without_versioning": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "s3_bucket_logging_disabled": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "cloudwatch_log_group_without_kms": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "resource_without_tags": DimensionScores(
        prevalence=Prevalence.CRITICAL,
        chain_utility=ChainUtility.NONE,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.NONE,
        impact_proximity=ImpactProximity.NONE,
    ),
    "resource_not_using_tags": DimensionScores(  # alias used by current Checkmarx
        prevalence=Prevalence.CRITICAL,
        chain_utility=ChainUtility.NONE,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.NONE,
        impact_proximity=ImpactProximity.NONE,
    ),
    "security_group_rule_without_description": DimensionScores(
        prevalence=Prevalence.CRITICAL,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    # ----- IaC: Kubernetes / container orchestration -----------------------
    "container_running_as_root": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "container_running_with_low_uid": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "privilege_escalation_allowed": DimensionScores(
        # Despite the alarming name, KICS/Checkmarx rates this Low/Medium by
        # default because exploitation requires an attacker already in the
        # container. Per CPS, however, its Chain Utility and Blast Radius
        # are very high, which is exactly why CPS surfaces it above CVSS.
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.CRITICAL,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.CRITICAL,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "container_cpu_limit_not_set": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "container_cpu_limits_are_not_set": DimensionScores(  # alias
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "container_memory_limit_not_set": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "container_memory_limits_are_not_set": DimensionScores(  # alias
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "service_account_token_automount": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "automount_service_account_token": DimensionScores(  # alias
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "service_account_token_automount_not_disabled": DimensionScores(
        # Checkmarx-emitted variant of the service-account-token finding.
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    # ----- IaC: Kubernetes — additional KICS rules from real scans --------
    "seccomp_profile_is_not_configured": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "readiness_probe_is_not_configured": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.NONE,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.NONE,
        impact_proximity=ImpactProximity.NONE,
    ),
    "liveness_probe_is_not_defined": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.NONE,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.NONE,
        impact_proximity=ImpactProximity.NONE,
    ),
    "net_raw_capabilities_not_being_dropped": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "memory_requests_not_defined": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "memory_limits_not_defined": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "cpu_requests_not_set": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "cpu_limits_not_set": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "root_container_not_mounted_read_only": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "pod_or_container_without_security_context": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "pod_or_container_without_resourcequota": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "pod_or_container_without_limitrange": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "no_drop_capabilities_for_containers": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "missing_apparmor_profile": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "image_without_digest": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "image_pull_policy_of_the_container_is_not_set_to_always": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "ensure_administrative_boundaries_between_resources": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    # ----- IaC: Terraform — actual KICS query names from real scans -------
    # NOTE: These IAM findings are emitted by Checkmarx at MEDIUM severity
    # in current tenants. Their chain utility for cloud-credential-reach
    # chains (CH-001) is high, so the CPS dimension scores reflect that
    # role rather than mirroring the tenant severity. The paper section
    # on severity drift cites these as canonical examples.
    "instance_uses_metadata_service_imdsv1": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.CRITICAL,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "iam_policy_allows_for_data_exfiltration": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "iam_policy_grants_assumerole_permission_across_all_services": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.CRITICAL,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "iam_access_analyzer_not_enabled": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "security_group_not_used": DimensionScores(
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.NONE,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.NONE,
        impact_proximity=ImpactProximity.NONE,
    ),
    # ----- SAST: additional Python query names produced by the lab -------
    "cookie_poisoning": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "secure_cookie_flag_not_set_in_config": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    # ----- SCA: generic vulnerable-dependency scoring classes --------------
    # SCA findings come through as raw CVE identifiers (e.g., CVE-2023-25577).
    # We score them by the severity Checkmarx assigns. This is a pragmatic
    # PoC choice — a production engine would map each CVE to its specific
    # chain role via a CVE-to-CWE-to-class table.
    #
    # The lookup() helper recognizes "CVE-XXXX-YYYY" syntax and dispatches
    # to one of these synthetic classes based on the finding's severity.
    "_sca_low": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "_sca_medium": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "_sca_high": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.CRITICAL,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.HIGH,
    ),
    # ----- AI-BOM: synthesized scoring classes for CycloneDX AI components -
    # AI-BOM components don't have severity in the CycloneDX schema. We
    # synthesize Findings from them and route to one of these two classes
    # based on component type. AI Leverage scores are intentionally high
    # because the components ARE the AI surface; if a chain reaches a
    # primitive that affects an AI component, the AI Leverage dimension
    # is by definition fully realized.
    #
    # The CHAIN UTILITY differs between the two types: machine-learning-model
    # components are chain-targets (an attacker wants to subvert the model's
    # behaviour), libraries/frameworks are chain-bridges (orchestration
    # surface that connects models to data and tools).
    "ai_component_machine_learning_model": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,      # chain target
        ai_leverage=AILeverage.CRITICAL,      # by definition
        blast_radius=BlastRadius.HIGH,        # cross-session, cross-user
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "ai_component_library": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,      # bridges models to tools/data
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.LOW,
    ),
    # ----- Container Security: Dockerfile KICS rules (CH-002 chain) --------
    # KICS scans Dockerfiles statically. The rules below are the ones the
    # CH-002 lab is designed to surface; severities are the ones tenants
    # commonly assign. All rated Low or Medium in mainstream Checkmarx
    # installations.
    "add_instead_of_copy": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),
    "use_of_add_instead_of_copy": DimensionScores(  # alias, in case other tenants emit longer form
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),
    "apt_get_not_avoiding_additional_packages": DimensionScores(
        # KICS Low: same family as `apt_get_install_pin_version` —
        # missing --no-install-recommends or similar.
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),
    "apt_get_install_pin_version_not_defined": DimensionScores(
        # KICS Low: package versions not pinned, supply-chain risk.
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),
    "missing_user_instruction": DimensionScores(
        # Container running as root expands every other finding's blast
        # radius — chain-relevant amplifier, not just hygiene.
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "healthcheck_instruction_missing": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.NONE,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.NONE,
        impact_proximity=ImpactProximity.NONE,
    ),
    "apt_get_install_lists_were_not_deleted": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),
    "apt_get_install_pin_version": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),
    "no_install_recommends": DimensionScores(  # alias for the above family
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),
    # ----- IaC: Kubernetes NetworkPolicy / egress (CH-002 chain F6) -------
    # NetworkPolicy missing on a deployment is a chain-relevant Low — it
    # provides the exfiltration path. Several tenants emit this under
    # different query names; aliases below cover the common variants.
    "networkpolicy_missing": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,    # exfiltration path is highly composable
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "pod_has_no_associated_networkpolicy": DimensionScores(  # alias
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "egress_not_restricted": DimensionScores(  # alias
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "egress_open_to_internet": DimensionScores(  # alias
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    # Container Security base-image package CVEs share a profile with
    # SCA Low CVEs but are more chain-relevant because the package runs
    # in the container's runtime context. Map to a synthetic class.
    "_container_cve_low": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "_container_cve_medium": DimensionScores(
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.HIGH,
    ),
    # ===== Verified against real Checkmarx One scans, tenant =============
    # checkmarx-global-services-internal, 2026-08-01. Each entry below was
    # observed firing in a completed scan; the severity in the comment is
    # what Checkmarx actually assigned in that language preset. Severity is
    # preset-dependent, so the same query can differ across languages.

    # ----- PHP (DVWA, scan c389b5e7) ------------------------------------
    "broken_or_risky_hashing_function": DimensionScores(      # PHP: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "insecure_value_of_the_samesite_cookie_attribute": DimensionScores(  # PHP: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "cookie_overly_broad_path": DimensionScores(              # PHP: Low
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "improper_exception_handling": DimensionScores(           # PHP: Low
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),

    # ----- Java (JavaVulnerableLab, scan 382c4fa6) ----------------------
    "csrf": DimensionScores(                                  # Java/PHP: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "parameter_tampering": DimensionScores(                   # Java: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "stored_relative_path_traversal": DimensionScores(        # Java: Medium
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "external_control_of_system_or_config_setting": DimensionScores(  # Java: Medium
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.CRITICAL,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "privacy_violation": DimensionScores(                     # Java: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "information_exposure_through_query_string": DimensionScores(  # Java: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "exposure_of_sensitive_information_to_an_unauthorized_actor": DimensionScores(  # Java/PHP: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "heap_inspection": DimensionScores(                       # Java: Low
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "improper_resource_shutdown_or_release": DimensionScores(  # Java: Low
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),
    "creation_of_temp_file_with_insecure_permissions": DimensionScores(  # Java: Low
        # Name confirmed emitted by the tenant in scan cc434dd7 for the Nexa
        # specimen; the longer variant below appears in other Java codebases.
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "creation_of_temp_file_in_dir_with_incorrect_permissions": DimensionScores(  # Java: Low
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "unsynchronized_access_to_shared_data": DimensionScores(  # Java: Low
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "race_condition": DimensionScores(                        # Java: Low
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),

    # ----- JavaScript / Node (NodeGoat, scan b0fa38ca) ------------------
    "missing_csp_header": DimensionScores(                    # JS: Low
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "unsafe_use_of_target_blank": DimensionScores(            # JS/PHP: Low
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "log_forging": DimensionScores(                           # JS: Low
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),

    # ----- Go (authlab-canary, scan 2e83d245) ---------------------------
    "jwt_no_claims_directives_validation": DimensionScores(   # Go: Low
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.HIGH,
    ),

    # ----- KICS / IaC (NodeGoat + owasp-juice-lab) ----------------------
    "container_capabilities_unrestricted": DimensionScores(   # KICS: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.CRITICAL,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "security_opt_not_set": DimensionScores(                  # KICS: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "memory_not_limited": DimensionScores(                    # KICS: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "container_traffic_not_bound_to_host_interface": DimensionScores(  # KICS: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "healthcheck_not_set": DimensionScores(                   # KICS: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "cpus_not_limited": DimensionScores(                      # KICS: Low
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "chown_flag_exists": DimensionScores(                     # KICS: Low
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "using_unnamed_build_stages": DimensionScores(            # KICS: Low
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.LOW,
        ai_leverage=AILeverage.NONE,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.NONE,
    ),
    "s3_bucket_logging_disabled": DimensionScores(            # KICS: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "rds_without_logging": DimensionScores(                   # KICS: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "container_running_with_low_uid": DimensionScores(        # KICS: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),

    # ----- Informational tier, Java (JavaVulnerableLab, scan 382c4fa6) ---
    # Checkmarx rates these Informational - the tier below Low. They are
    # included because CH-106 tests whether a chain built entirely from
    # Informational findings can still reach the High band.
    "dynamic_sql_queries": DimensionScores(                   # Java: Info
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.HIGH,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.HIGH,
    ),
    "insufficient_logging_of_database_actions": DimensionScores(  # Java: Info
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
    "pages_without_global_error_handler": DimensionScores(    # Java: Info
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "unchecked_error_condition": DimensionScores(             # Java: Info
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "detection_of_error_condition_without_action": DimensionScores(  # Java: Info
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "declaration_of_catch_for_generic_exception": DimensionScores(   # Java: Info
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),
    "use_of_system_output_stream": DimensionScores(           # Java: Info
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.MEDIUM,
        blast_radius=BlastRadius.LOW,
        impact_proximity=ImpactProximity.LOW,
    ),

    # ----- Python / AI agent framework (AISC_openai_agents_python) -------
    "object_access_violation": DimensionScores(               # Python: Medium
        prevalence=Prevalence.MEDIUM,
        chain_utility=ChainUtility.HIGH,
        ai_leverage=AILeverage.CRITICAL,   # agent tool surface
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),

    # ----- Cloud IaC, AWS (owasp-juice-lab, scan b0b1dcd6) --------------
    "rds_with_backup_disabled": DimensionScores(              # KICS: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.HIGH,
        impact_proximity=ImpactProximity.MEDIUM,
    ),
    "using_unrecommended_namespace": DimensionScores(         # KICS: Medium
        prevalence=Prevalence.HIGH,
        chain_utility=ChainUtility.MEDIUM,
        ai_leverage=AILeverage.LOW,
        blast_radius=BlastRadius.MEDIUM,
        impact_proximity=ImpactProximity.LOW,
    ),
}


# ---------------------------------------------------------------------------
# Fallback for unknown queries
# ---------------------------------------------------------------------------
# Conservative default applied when a query name is not recognized. Chosen
# so the score lands in the Low band, and so that an analyst reviewing
# results sees an unmistakable "this needs manual scoring" signal in the
# low-but-not-zero range. The scorer logs a warning whenever this is used.

UNKNOWN_QUERY_DEFAULT = DimensionScores(
    prevalence=Prevalence.MEDIUM,
    chain_utility=ChainUtility.LOW,
    ai_leverage=AILeverage.LOW,
    blast_radius=BlastRadius.LOW,
    impact_proximity=ImpactProximity.LOW,
)


def normalize_query_name(query_name: str) -> str:
    """Return the canonical lowercase form used as the dictionary key.

    Normalization handles real-world variations seen in Checkmarx output
    across engines:
      - Spaces vs underscores. "Container Running As Root" and
        "Container_Running_As_Root" both map to the same key.
      - Mixed casing. "Open_Redirect", "open_redirect", "Open Redirect"
        all collapse to "open_redirect".
      - Hyphens. KICS rule names sometimes use hyphens; treat as
        underscores.
      - Punctuation: apostrophes, periods, commas, parentheses, colons.
        KICS sometimes emits names like "IAM Policy Grants 'AssumeRole'
        Permission Across All Services". The punctuation is dropped so
        the key matches a clean underscore-form entry.
    """
    s = query_name.strip().lower()
    # Drop punctuation that has no semantic meaning for query identity.
    drop_chars = "'\"`.,():;!?[]{}/\\*"
    s = "".join(ch for ch in s if ch not in drop_chars)
    # Collapse runs of whitespace, hyphens, or underscores into one underscore.
    out: list[str] = []
    last_was_sep = False
    for ch in s:
        if ch in (" ", "\t", "_", "-"):
            if not last_was_sep:
                out.append("_")
                last_was_sep = True
        else:
            out.append(ch)
            last_was_sep = False
    canonical = "".join(out).strip("_")
    return canonical


def _is_cve_identifier(query_name: str) -> bool:
    """True if the query name looks like a CVE identifier."""
    s = query_name.strip().upper()
    return s.startswith("CVE-") and any(ch.isdigit() for ch in s)


def _sca_class_for_severity(severity: str | None) -> str:
    """Map a Checkmarx severity to one of the synthetic SCA scoring classes.

    Used when the finding is identified by a raw CVE id rather than a
    semantic query name. See the `_sca_*` entries in DEFAULTS.
    """
    if not severity:
        return "_sca_low"
    s = severity.strip().lower()
    if s in ("critical", "high"):
        return "_sca_high"
    if s == "medium":
        return "_sca_medium"
    # Low, informational, info, unknown, anything else
    return "_sca_low"


def lookup_defaults(
    query_name: str,
    severity: str | None = None,
    language_hint: str | None = None,
) -> tuple[DimensionScores, bool]:
    """Look up default dimension scores for a query name.

    The lookup tries, in order:
      1. Direct normalized lookup against DEFAULTS.
      2. If the query name is a CVE identifier, dispatch to one of the
         synthetic _sca_low / _sca_medium / _sca_high classes based on
         the supplied severity. This is the SCA fallback path.
      3. If a language_hint is supplied AND it is itself a recognized
         DEFAULTS key, use that. This is how AI-BOM findings dispatch:
         the parser sets language=ai_component_machine_learning_model
         (or ai_component_library), and this step routes to the matching
         scoring class without requiring a query-name match.
      4. Conservative UNKNOWN_QUERY_DEFAULT.

    Args:
        query_name: the scanner's query family name or CVE id.
        severity: optional Checkmarx severity, used for SCA dispatch.
        language_hint: optional pre-normalized language/class key, used
            when the parser already knows which scoring class to use
            (e.g., for AI-BOM components).

    Returns:
        (DimensionScores, is_known) where is_known is True for direct,
        CVE, and language-hint matches, False for the conservative fallback.
    """
    key = normalize_query_name(query_name)
    if key in DEFAULTS:
        return DEFAULTS[key], True
    if _is_cve_identifier(query_name):
        sca_class = _sca_class_for_severity(severity)
        return DEFAULTS[sca_class], True
    if language_hint and language_hint in DEFAULTS:
        return DEFAULTS[language_hint], True
    return UNKNOWN_QUERY_DEFAULT, False
