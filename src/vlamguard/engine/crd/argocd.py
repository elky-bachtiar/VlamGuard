"""Argo CD CRD policy checks — Application and AppProject security and reliability.

These checks cover production-readiness, GitOps safety, and access-control
hardening for Argo CD Application and AppProject resources.
"""

from vlamguard.engine.registry import policy_check
from vlamguard.models.response import PolicyCheckResult

# Argo CD resource kinds
_ARGOCD_APPLICATION = "Application"
_ARGOCD_APP_PROJECT = "AppProject"
_ARGOCD_API_GROUP = "argoproj.io"

# Sentinel values that indicate uncontrolled/default configuration
_IN_CLUSTER_SERVER = "https://kubernetes.default.svc"
_DEFAULT_PROJECT = "default"
_HEAD_REVISION = "HEAD"


# ---------------------------------------------------------------------------
# Application checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="argocd_auto_sync_prune",
    name="Argo CD Auto-Sync Prune Without Self-Heal",
    severity="medium",
    category="argocd-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.5"}),
    description=(
        "Enabling prune without selfHeal can leave the cluster in a split-brain state: "
        "Argo CD will delete resources that diverge from Git but will not restore them if "
        "they are subsequently recreated outside the sync cycle."
    ),
    remediation="Set spec.syncPolicy.automated.selfHeal: true alongside spec.syncPolicy.automated.prune: true.",
)
def check_argocd_auto_sync_prune(manifest: dict) -> PolicyCheckResult:
    """Application with prune=true must also have selfHeal=true."""
    if manifest.get("kind") != _ARGOCD_APPLICATION:
        return PolicyCheckResult(
            check_id="argocd_auto_sync_prune",
            name="Argo CD Auto-Sync Prune Without Self-Heal",
            passed=True,
            severity="medium",
            message="Not an Application, skipped.",
        )

    automated = (
        manifest.get("spec", {})
        .get("syncPolicy", {})
        .get("automated", {})
    )

    if not automated:
        return PolicyCheckResult(
            check_id="argocd_auto_sync_prune",
            name="Argo CD Auto-Sync Prune Without Self-Heal",
            passed=True,
            severity="medium",
            message="No automated sync policy configured.",
        )

    prune = automated.get("prune", False)
    self_heal = automated.get("selfHeal", False)

    if prune and not self_heal:
        return PolicyCheckResult(
            check_id="argocd_auto_sync_prune",
            name="Argo CD Auto-Sync Prune Without Self-Heal",
            passed=False,
            severity="medium",
            message=(
                "Automated sync has prune=true but selfHeal=false. "
                "Resources deleted outside of Git will not be reconciled automatically."
            ),
            details={"prune": prune, "selfHeal": self_heal},
        )

    return PolicyCheckResult(
        check_id="argocd_auto_sync_prune",
        name="Argo CD Auto-Sync Prune Without Self-Heal",
        passed=True,
        severity="medium",
        message="Automated sync prune and selfHeal are consistently configured.",
    )


@policy_check(
    check_id="argocd_sync_retry_configured",
    name="Argo CD Sync Retry Not Configured",
    severity="medium",
    category="argocd-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    description=(
        "Without sync retry, a transient failure (e.g. webhook timeout, brief API server hiccup) "
        "leaves the Application in a degraded OutOfSync state until an operator manually re-syncs."
    ),
    remediation="Add spec.syncPolicy.retry with limit and backoff settings.",
)
def check_argocd_sync_retry_configured(manifest: dict) -> PolicyCheckResult:
    """Application should configure sync retry for resilience against transient failures."""
    if manifest.get("kind") != _ARGOCD_APPLICATION:
        return PolicyCheckResult(
            check_id="argocd_sync_retry_configured",
            name="Argo CD Sync Retry Not Configured",
            passed=True,
            severity="medium",
            message="Not an Application, skipped.",
        )

    sync_policy = manifest.get("spec", {}).get("syncPolicy", {})
    retry = sync_policy.get("retry")

    if not retry:
        return PolicyCheckResult(
            check_id="argocd_sync_retry_configured",
            name="Argo CD Sync Retry Not Configured",
            passed=False,
            severity="medium",
            message=(
                "Application has no sync retry policy. "
                "Transient sync failures will require manual intervention."
            ),
            details={"retry": None},
        )

    return PolicyCheckResult(
        check_id="argocd_sync_retry_configured",
        name="Argo CD Sync Retry Not Configured",
        passed=True,
        severity="medium",
        message=f"Sync retry configured with limit={retry.get('limit', 'unset')}.",
    )


@policy_check(
    check_id="argocd_destination_not_in_cluster",
    name="Argo CD In-Cluster Destination",
    severity="medium",
    category="argocd-security",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    description=(
        "Deploying to 'https://kubernetes.default.svc' (in-cluster) is implicit and error-prone "
        "in multi-cluster setups. Explicit external server URLs make the target cluster unambiguous "
        "and prevent accidental cross-cluster deployments."
    ),
    remediation=(
        "Replace spec.destination.server with the explicit API server URL of the target cluster, "
        "or use spec.destination.name to reference a named cluster."
    ),
)
def check_argocd_destination_not_in_cluster(manifest: dict) -> PolicyCheckResult:
    """Application should use an explicit destination server, not the in-cluster sentinel."""
    if manifest.get("kind") != _ARGOCD_APPLICATION:
        return PolicyCheckResult(
            check_id="argocd_destination_not_in_cluster",
            name="Argo CD In-Cluster Destination",
            passed=True,
            severity="medium",
            message="Not an Application, skipped.",
        )

    destination = manifest.get("spec", {}).get("destination", {})
    server = destination.get("server", "")

    if server == _IN_CLUSTER_SERVER:
        return PolicyCheckResult(
            check_id="argocd_destination_not_in_cluster",
            name="Argo CD In-Cluster Destination",
            passed=False,
            severity="medium",
            message=(
                f"Application destination server is '{_IN_CLUSTER_SERVER}' (in-cluster). "
                "Use an explicit cluster URL or named cluster reference."
            ),
            details={"server": server},
        )

    return PolicyCheckResult(
        check_id="argocd_destination_not_in_cluster",
        name="Argo CD In-Cluster Destination",
        passed=True,
        severity="medium",
        message=f"Destination server is explicitly set to '{server or '(name-based)'}'.",
    )


@policy_check(
    check_id="argocd_project_not_default",
    name="Argo CD Application Uses Default Project",
    severity="high",
    category="argocd-security",
    risk_points=20,
    prod_behavior="soft_risk",
    other_behavior="off",
    description=(
        "The 'default' Argo CD project typically grants broad permissions (wildcard destinations, "
        "wildcard source repos) and is shared by all team members. Applications should be placed "
        "in dedicated projects with scoped RBAC and destination restrictions."
    ),
    remediation="Set spec.project to a dedicated AppProject name with least-privilege destination and source restrictions.",
)
def check_argocd_project_not_default(manifest: dict) -> PolicyCheckResult:
    """Application should not use the shared 'default' Argo CD project."""
    if manifest.get("kind") != _ARGOCD_APPLICATION:
        return PolicyCheckResult(
            check_id="argocd_project_not_default",
            name="Argo CD Application Uses Default Project",
            passed=True,
            severity="high",
            message="Not an Application, skipped.",
        )

    project = manifest.get("spec", {}).get("project", _DEFAULT_PROJECT)

    if project == _DEFAULT_PROJECT:
        return PolicyCheckResult(
            check_id="argocd_project_not_default",
            name="Argo CD Application Uses Default Project",
            passed=False,
            severity="high",
            message=(
                "Application is assigned to the 'default' project. "
                "The default project often has broad permissions; use a dedicated project with scoped RBAC."
            ),
            details={"project": project},
        )

    return PolicyCheckResult(
        check_id="argocd_project_not_default",
        name="Argo CD Application Uses Default Project",
        passed=True,
        severity="high",
        message=f"Application uses project '{project}'.",
    )


@policy_check(
    check_id="argocd_source_target_revision",
    name="Argo CD Source Target Revision Not Pinned",
    severity="high",
    category="argocd-security",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC8.1", "SLSA-L2"}),
    description=(
        "Using 'HEAD' or an empty targetRevision means Argo CD will always deploy whatever is "
        "at the tip of the default branch. This violates supply-chain integrity: a push to main "
        "immediately becomes production without going through a release process."
    ),
    remediation=(
        "Pin spec.source.targetRevision to a specific Git tag (e.g. v1.2.3) or commit SHA. "
        "For Helm charts, use a specific chart version instead of a floating range."
    ),
)
def check_argocd_source_target_revision(manifest: dict) -> PolicyCheckResult:
    """Application must pin targetRevision to a specific tag or SHA, not HEAD."""
    if manifest.get("kind") != _ARGOCD_APPLICATION:
        return PolicyCheckResult(
            check_id="argocd_source_target_revision",
            name="Argo CD Source Target Revision Not Pinned",
            passed=True,
            severity="high",
            message="Not an Application, skipped.",
        )

    source = manifest.get("spec", {}).get("source", {})
    revision = source.get("targetRevision", "")

    # Empty string and "HEAD" both mean "tip of default branch"
    if not revision or revision.upper() == _HEAD_REVISION:
        display = f"'{revision}'" if revision else "(empty)"
        return PolicyCheckResult(
            check_id="argocd_source_target_revision",
            name="Argo CD Source Target Revision Not Pinned",
            passed=False,
            severity="high",
            message=(
                f"targetRevision is {display}. "
                "Applications must pin to a specific tag or SHA to ensure supply-chain integrity."
            ),
            details={"targetRevision": revision or None, "repoURL": source.get("repoURL")},
        )

    return PolicyCheckResult(
        check_id="argocd_source_target_revision",
        name="Argo CD Source Target Revision Not Pinned",
        passed=True,
        severity="high",
        message=f"targetRevision is pinned to '{revision}'.",
    )


# ---------------------------------------------------------------------------
# AppProject checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="argocd_project_wildcard_destination",
    name="Argo CD AppProject Wildcard Destination",
    severity="critical",
    category="argocd-security",
    risk_points=30,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.1.1", "SOC2-CC6.3"}),
    cis_benchmark="5.1.1",
    description=(
        "An AppProject destination of {server: '*', namespace: '*'} grants any Application in "
        "the project the ability to deploy to any cluster and any namespace, including kube-system. "
        "This completely negates multi-tenancy boundaries."
    ),
    remediation=(
        "Replace wildcard destination entries with explicit {server, namespace} pairs "
        "matching only the clusters and namespaces this project should manage."
    ),
)
def check_argocd_project_wildcard_destination(manifest: dict) -> PolicyCheckResult:
    """AppProject must not permit wildcard server+namespace destinations."""
    if manifest.get("kind") != _ARGOCD_APP_PROJECT:
        return PolicyCheckResult(
            check_id="argocd_project_wildcard_destination",
            name="Argo CD AppProject Wildcard Destination",
            passed=True,
            severity="critical",
            message="Not an AppProject, skipped.",
        )

    destinations = manifest.get("spec", {}).get("destinations", [])
    wildcard_entries = [
        d for d in destinations
        if d.get("server") == "*" and d.get("namespace") == "*"
    ]

    if wildcard_entries:
        return PolicyCheckResult(
            check_id="argocd_project_wildcard_destination",
            name="Argo CD AppProject Wildcard Destination",
            passed=False,
            severity="critical",
            message=(
                f"AppProject has {len(wildcard_entries)} wildcard destination(s) "
                "{{server: '*', namespace: '*'}}. This grants unrestricted cluster access to all Applications in the project."
            ),
            details={"wildcard_destinations": len(wildcard_entries), "total_destinations": len(destinations)},
        )

    return PolicyCheckResult(
        check_id="argocd_project_wildcard_destination",
        name="Argo CD AppProject Wildcard Destination",
        passed=True,
        severity="critical",
        message=f"All {len(destinations)} destination(s) are explicitly scoped.",
    )


@policy_check(
    check_id="argocd_project_wildcard_source",
    name="Argo CD AppProject Wildcard Source Repo",
    severity="high",
    category="argocd-security",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC8.1", "SLSA-L2"}),
    description=(
        "A sourceRepos entry of '*' allows Applications in this project to pull manifests "
        "from any Git repository, including attacker-controlled ones. "
        "This bypasses supply-chain controls and enables arbitrary code execution in the cluster."
    ),
    remediation=(
        "Replace '*' in spec.sourceRepos with an explicit allowlist of approved repository URLs."
    ),
)
def check_argocd_project_wildcard_source(manifest: dict) -> PolicyCheckResult:
    """AppProject must not allow '*' as a source repository."""
    if manifest.get("kind") != _ARGOCD_APP_PROJECT:
        return PolicyCheckResult(
            check_id="argocd_project_wildcard_source",
            name="Argo CD AppProject Wildcard Source Repo",
            passed=True,
            severity="high",
            message="Not an AppProject, skipped.",
        )

    source_repos = manifest.get("spec", {}).get("sourceRepos", [])

    if "*" in source_repos:
        return PolicyCheckResult(
            check_id="argocd_project_wildcard_source",
            name="Argo CD AppProject Wildcard Source Repo",
            passed=False,
            severity="high",
            message=(
                "AppProject sourceRepos contains '*'. "
                "Applications in this project may pull manifests from any repository, including untrusted ones."
            ),
            details={"sourceRepos": source_repos},
        )

    return PolicyCheckResult(
        check_id="argocd_project_wildcard_source",
        name="Argo CD AppProject Wildcard Source Repo",
        passed=True,
        severity="high",
        message=f"sourceRepos is restricted to {len(source_repos)} explicit repo(s).",
    )


@policy_check(
    check_id="argocd_project_cluster_resources",
    name="Argo CD AppProject Unrestricted Cluster Resources",
    severity="high",
    category="argocd-security",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.1.3", "SOC2-CC6.3"}),
    cis_benchmark="5.1.3",
    description=(
        "A clusterResourceWhitelist entry of {group: '*', kind: '*'} allows Applications in "
        "the project to create or modify any cluster-scoped resource, including ClusterRoles, "
        "Namespaces, and PersistentVolumes. This is equivalent to granting cluster-admin."
    ),
    remediation=(
        "Replace {group: '*', kind: '*'} with explicit entries for only the cluster-scoped "
        "resource types this project legitimately needs to manage."
    ),
)
def check_argocd_project_cluster_resources(manifest: dict) -> PolicyCheckResult:
    """AppProject must not grant unrestricted cluster-scoped resource access."""
    if manifest.get("kind") != _ARGOCD_APP_PROJECT:
        return PolicyCheckResult(
            check_id="argocd_project_cluster_resources",
            name="Argo CD AppProject Unrestricted Cluster Resources",
            passed=True,
            severity="high",
            message="Not an AppProject, skipped.",
        )

    whitelist = manifest.get("spec", {}).get("clusterResourceWhitelist", [])

    wildcard_entries = [
        entry for entry in whitelist
        if entry.get("group") == "*" and entry.get("kind") == "*"
    ]

    if wildcard_entries:
        return PolicyCheckResult(
            check_id="argocd_project_cluster_resources",
            name="Argo CD AppProject Unrestricted Cluster Resources",
            passed=False,
            severity="high",
            message=(
                "clusterResourceWhitelist contains {group: '*', kind: '*'}. "
                "This grants cluster-admin equivalent access to all Applications in the project."
            ),
            details={
                "wildcard_entries": len(wildcard_entries),
                "total_whitelist_entries": len(whitelist),
            },
        )

    return PolicyCheckResult(
        check_id="argocd_project_cluster_resources",
        name="Argo CD AppProject Unrestricted Cluster Resources",
        passed=True,
        severity="high",
        message=(
            f"clusterResourceWhitelist has {len(whitelist)} entry/entries with no wildcards."
            if whitelist else "clusterResourceWhitelist is empty (no cluster-scoped access granted)."
        ),
    )
