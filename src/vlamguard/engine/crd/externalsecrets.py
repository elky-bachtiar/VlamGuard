"""External Secrets Operator (ESO) CRD policy checks.

Covers ExternalSecret, SecretStore, and ClusterSecretStore resources from
external-secrets.io/v1beta1 and v1. Checks enforce refresh hygiene,
lifecycle policies, and scope controls to prevent stale credentials and
overly broad cluster-wide secret stores.
"""

from vlamguard.engine.registry import policy_check
from vlamguard.models.response import PolicyCheckResult

# ESO resource kinds
_EXTERNAL_SECRET = "ExternalSecret"
_SECRET_STORE = "SecretStore"
_CLUSTER_SECRET_STORE = "ClusterSecretStore"

# Refresh interval values that disable polling entirely
_DISABLED_REFRESH = {"0", "0s", "0m", "0h"}


# ---------------------------------------------------------------------------
# ExternalSecret checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="eso_external_secret_refresh_interval",
    name="ESO ExternalSecret Refresh Interval",
    severity="medium",
    category="eso-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC7.2"}),
    description=(
        "An ExternalSecret without a refreshInterval (or set to '0') will never pull updated "
        "secret values from the external provider. Rotated credentials will not propagate to the cluster."
    ),
    remediation=(
        "Set spec.refreshInterval to a positive duration (e.g. '1h') so rotated secrets "
        "are automatically synchronised."
    ),
)
def check_eso_external_secret_refresh_interval(manifest: dict) -> PolicyCheckResult:
    """ExternalSecret should have a non-zero refreshInterval."""
    if manifest.get("kind") != _EXTERNAL_SECRET:
        return PolicyCheckResult(
            check_id="eso_external_secret_refresh_interval",
            name="ESO ExternalSecret Refresh Interval",
            passed=True,
            severity="medium",
            message="Not an ExternalSecret, skipped.",
        )

    spec = manifest.get("spec", {})
    refresh_interval = spec.get("refreshInterval")
    name = manifest.get("metadata", {}).get("name", "<unknown>")

    if refresh_interval is None:
        return PolicyCheckResult(
            check_id="eso_external_secret_refresh_interval",
            name="ESO ExternalSecret Refresh Interval",
            passed=False,
            severity="medium",
            message=(
                f"ExternalSecret '{name}' has no spec.refreshInterval. "
                "Secret values will never be refreshed after the initial sync."
            ),
            details={"refreshInterval": None, "recommended": "1h"},
        )

    # Normalise to string for comparison
    refresh_str = str(refresh_interval).strip()
    if refresh_str in _DISABLED_REFRESH:
        return PolicyCheckResult(
            check_id="eso_external_secret_refresh_interval",
            name="ESO ExternalSecret Refresh Interval",
            passed=False,
            severity="medium",
            message=(
                f"ExternalSecret '{name}' has spec.refreshInterval set to '{refresh_str}', "
                "which disables automatic refresh. Rotated credentials will not propagate."
            ),
            details={"refreshInterval": refresh_str, "recommended": "1h"},
        )

    return PolicyCheckResult(
        check_id="eso_external_secret_refresh_interval",
        name="ESO ExternalSecret Refresh Interval",
        passed=True,
        severity="medium",
        message=f"ExternalSecret '{name}' refreshes every '{refresh_str}'.",
    )


@policy_check(
    check_id="eso_external_secret_target_creation",
    name="ESO ExternalSecret Target Creation Policy",
    severity="medium",
    category="eso-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC7.2"}),
    description=(
        "An explicit target creationPolicy makes it clear whether ESO owns the Kubernetes Secret "
        "lifecycle. Without it, the default ('Owner') may conflict with pre-existing Secrets."
    ),
    remediation=(
        "Set spec.target.creationPolicy to 'Owner', 'Orphan', or 'Merge' explicitly."
    ),
)
def check_eso_external_secret_target_creation(manifest: dict) -> PolicyCheckResult:
    """ExternalSecret should declare an explicit target creationPolicy."""
    if manifest.get("kind") != _EXTERNAL_SECRET:
        return PolicyCheckResult(
            check_id="eso_external_secret_target_creation",
            name="ESO ExternalSecret Target Creation Policy",
            passed=True,
            severity="medium",
            message="Not an ExternalSecret, skipped.",
        )

    spec = manifest.get("spec", {})
    target = spec.get("target", {})
    creation_policy = target.get("creationPolicy")
    name = manifest.get("metadata", {}).get("name", "<unknown>")

    if not creation_policy:
        return PolicyCheckResult(
            check_id="eso_external_secret_target_creation",
            name="ESO ExternalSecret Target Creation Policy",
            passed=False,
            severity="medium",
            message=(
                f"ExternalSecret '{name}' has no spec.target.creationPolicy. "
                "ESO defaults to 'Owner', which will delete the Secret when the ExternalSecret is removed. "
                "Set this explicitly to document the intended lifecycle."
            ),
            details={"creationPolicy": None, "accepted": ["Owner", "Orphan", "Merge"]},
        )

    return PolicyCheckResult(
        check_id="eso_external_secret_target_creation",
        name="ESO ExternalSecret Target Creation Policy",
        passed=True,
        severity="medium",
        message=f"ExternalSecret '{name}' has creationPolicy '{creation_policy}'.",
    )


@policy_check(
    check_id="eso_external_secret_deletion_policy",
    name="ESO ExternalSecret Target Deletion Policy",
    severity="medium",
    category="eso-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC7.2"}),
    description=(
        "Without an explicit deletionPolicy, removing an ExternalSecret in production "
        "may delete the backing Kubernetes Secret, causing outages. "
        "'Retain' is safest for production workloads."
    ),
    remediation=(
        "Set spec.target.deletionPolicy to 'Retain' to preserve the Secret when "
        "the ExternalSecret is deleted, preventing accidental outages."
    ),
)
def check_eso_external_secret_deletion_policy(manifest: dict) -> PolicyCheckResult:
    """ExternalSecret should have an explicit target deletionPolicy."""
    if manifest.get("kind") != _EXTERNAL_SECRET:
        return PolicyCheckResult(
            check_id="eso_external_secret_deletion_policy",
            name="ESO ExternalSecret Target Deletion Policy",
            passed=True,
            severity="medium",
            message="Not an ExternalSecret, skipped.",
        )

    spec = manifest.get("spec", {})
    target = spec.get("target", {})
    deletion_policy = target.get("deletionPolicy")
    name = manifest.get("metadata", {}).get("name", "<unknown>")

    if not deletion_policy:
        return PolicyCheckResult(
            check_id="eso_external_secret_deletion_policy",
            name="ESO ExternalSecret Target Deletion Policy",
            passed=False,
            severity="medium",
            message=(
                f"ExternalSecret '{name}' has no spec.target.deletionPolicy. "
                "Deleting this ExternalSecret may remove the Kubernetes Secret and break dependent workloads. "
                "Set to 'Retain' for production safety."
            ),
            details={"deletionPolicy": None, "recommended": "Retain"},
        )

    return PolicyCheckResult(
        check_id="eso_external_secret_deletion_policy",
        name="ESO ExternalSecret Target Deletion Policy",
        passed=True,
        severity="medium",
        message=f"ExternalSecret '{name}' has deletionPolicy '{deletion_policy}'.",
    )


# ---------------------------------------------------------------------------
# SecretStore / ClusterSecretStore checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="eso_secret_store_provider",
    name="ESO SecretStore Provider Configured",
    severity="high",
    category="eso-security",
    risk_points=20,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.4.1", "SOC2-CC6.1"}),
    cis_benchmark="5.4.1",
    description=(
        "A SecretStore or ClusterSecretStore without a provider is non-functional — "
        "all ExternalSecrets referencing it will fail to sync. This is almost always a configuration error."
    ),
    remediation=(
        "Set exactly one provider under spec.provider (e.g. aws, gcp, vault, azurekv, "
        "kubernetes, gitlab, etc.)."
    ),
)
def check_eso_secret_store_provider(manifest: dict) -> PolicyCheckResult:
    """SecretStore/ClusterSecretStore must have at least one provider key configured."""
    kind = manifest.get("kind")
    if kind not in (_SECRET_STORE, _CLUSTER_SECRET_STORE):
        return PolicyCheckResult(
            check_id="eso_secret_store_provider",
            name="ESO SecretStore Provider Configured",
            passed=True,
            severity="high",
            message="Not a SecretStore or ClusterSecretStore, skipped.",
        )

    spec = manifest.get("spec", {})
    provider = spec.get("provider", {})
    name = manifest.get("metadata", {}).get("name", "<unknown>")

    # provider must be a dict with at least one key
    if not provider or not isinstance(provider, dict) or len(provider) == 0:
        return PolicyCheckResult(
            check_id="eso_secret_store_provider",
            name="ESO SecretStore Provider Configured",
            passed=False,
            severity="high",
            message=(
                f"{kind} '{name}' has no provider configured under spec.provider. "
                "All ExternalSecrets referencing this store will fail to sync."
            ),
            details={"provider": provider or None},
        )

    configured_providers = list(provider.keys())
    return PolicyCheckResult(
        check_id="eso_secret_store_provider",
        name="ESO SecretStore Provider Configured",
        passed=True,
        severity="high",
        message=f"{kind} '{name}' has provider configured: {', '.join(configured_providers)}.",
    )


@policy_check(
    check_id="eso_cluster_secret_store_conditions",
    name="ESO ClusterSecretStore Namespace Scope",
    severity="medium",
    category="eso-security",
    risk_points=15,
    prod_behavior="soft_risk",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC6.1"}),
    description=(
        "A ClusterSecretStore with no namespace conditions or namespaceSelector is accessible "
        "from every namespace in the cluster. This violates least-privilege and may allow "
        "workloads in untrusted namespaces to read production secrets."
    ),
    remediation=(
        "Add spec.conditions with a namespaceSelector or specific namespace list "
        "to restrict which namespaces can reference this ClusterSecretStore."
    ),
)
def check_eso_cluster_secret_store_conditions(manifest: dict) -> PolicyCheckResult:
    """ClusterSecretStore should restrict namespace access via conditions or namespaceSelector."""
    if manifest.get("kind") != _CLUSTER_SECRET_STORE:
        return PolicyCheckResult(
            check_id="eso_cluster_secret_store_conditions",
            name="ESO ClusterSecretStore Namespace Scope",
            passed=True,
            severity="medium",
            message="Not a ClusterSecretStore, skipped.",
        )

    spec = manifest.get("spec", {})
    conditions = spec.get("conditions")
    namespace_selector = spec.get("namespaceSelector")
    name = manifest.get("metadata", {}).get("name", "<unknown>")

    has_conditions = bool(conditions)
    has_ns_selector = bool(namespace_selector)

    if not has_conditions and not has_ns_selector:
        return PolicyCheckResult(
            check_id="eso_cluster_secret_store_conditions",
            name="ESO ClusterSecretStore Namespace Scope",
            passed=False,
            severity="medium",
            message=(
                f"ClusterSecretStore '{name}' has no spec.conditions or spec.namespaceSelector. "
                "It is accessible from all namespaces, violating the principle of least privilege."
            ),
            details={"conditions": None, "namespaceSelector": None},
        )

    scope_description = []
    if has_conditions:
        scope_description.append(f"{len(conditions)} condition(s)")
    if has_ns_selector:
        scope_description.append("namespaceSelector")

    return PolicyCheckResult(
        check_id="eso_cluster_secret_store_conditions",
        name="ESO ClusterSecretStore Namespace Scope",
        passed=True,
        severity="medium",
        message=(
            f"ClusterSecretStore '{name}' restricts namespace access via "
            f"{' and '.join(scope_description)}."
        ),
    )
