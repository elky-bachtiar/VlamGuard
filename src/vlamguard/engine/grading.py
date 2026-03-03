"""Deterministic security grade calculator (F→A cascade)."""

from vlamguard.models.response import (
    HardeningAction,
    PolicyCheckResult,
    SecretsDetectionResult,
    SecurityGrade,
)

# Check IDs for the extended security checks
_HOST_NAMESPACE = "host_namespace"
_DANGEROUS_VOLUMES = "dangerous_volume_mounts"
_EXCESSIVE_CAPS = "excessive_capabilities"
_SERVICE_ACCOUNT_TOKEN = "service_account_token"
_EXPOSED_SERVICES = "exposed_services"
_EXTENDED_CHECK_IDS = {
    _HOST_NAMESPACE, _DANGEROUS_VOLUMES, _EXCESSIVE_CAPS,
    _SERVICE_ACCOUNT_TOKEN, _EXPOSED_SERVICES,
}


def calculate_security_grade(
    secrets_result: SecretsDetectionResult | None,
    extended_check_results: list[PolicyCheckResult],
    hardening_recommendations: list[HardeningAction],
    environment: str,
) -> SecurityGrade:
    """Calculate security grade using deterministic F→A cascade.

    Grade F: confirmed secret in production OR (host_namespace + dangerous_volume_mounts both fail)
    Grade D: confirmed secret in non-prod OR 2+ extended checks fail OR excessive_capabilities (SYS_ADMIN/ALL)
    Grade C: all hard blocks pass BUT 3+ high-impact hardening recs
    Grade B: max 2 high-impact hardening recs AND secrets clean AND basic securityContext
    Grade A: all checks pass, no secrets, 0-1 low-impact hardening recs
    """
    is_production = environment == "production"
    confirmed_secrets = secrets_result.confirmed_secrets if secrets_result else 0

    # Build lookup of failed extended checks
    failed_ext = {
        r.check_id for r in extended_check_results
        if r.check_id in _EXTENDED_CHECK_IDS and not r.passed
    }

    # Count high-impact hardening recommendations
    high_impact_recs = [r for r in hardening_recommendations if r.impact == "high"]

    # --- Grade F ---
    if is_production and confirmed_secrets > 0:
        return SecurityGrade.F

    if _HOST_NAMESPACE in failed_ext and _DANGEROUS_VOLUMES in failed_ext:
        return SecurityGrade.F

    # --- Grade D ---
    if not is_production and confirmed_secrets > 0:
        return SecurityGrade.D

    if len(failed_ext) >= 2:
        return SecurityGrade.D

    if _EXCESSIVE_CAPS in failed_ext:
        # Check for SYS_ADMIN or ALL specifically
        for r in extended_check_results:
            if r.check_id == _EXCESSIVE_CAPS and not r.passed:
                details = r.details or {}
                violations = details.get("violations", [])
                for v in violations:
                    if "SYS_ADMIN" in v or "ALL" in v:
                        return SecurityGrade.D

    # --- Grade C ---
    if len(high_impact_recs) >= 3:
        return SecurityGrade.C

    if failed_ext:
        return SecurityGrade.C

    # --- Grade B ---
    if len(high_impact_recs) <= 2 and confirmed_secrets == 0:
        if len(high_impact_recs) > 0:
            return SecurityGrade.B

    # --- Grade A ---
    low_impact_recs = [r for r in hardening_recommendations if r.impact == "low"]
    if (
        not failed_ext
        and confirmed_secrets == 0
        and len(high_impact_recs) == 0
        and len(hardening_recommendations) - len(low_impact_recs) == 0
        and len(low_impact_recs) <= 1
    ):
        return SecurityGrade.A

    return SecurityGrade.B
