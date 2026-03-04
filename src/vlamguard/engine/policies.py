"""Deterministic policy checks for Kubernetes manifests."""

from vlamguard.engine.registry import policy_check
from vlamguard.models.response import PolicyCheckResult

_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}


def _get_containers(manifest: dict) -> list[dict]:
    """Extract all containers (regular + init) from a workload manifest."""
    if manifest.get("kind") not in _WORKLOAD_KINDS:
        return []
    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
    containers = pod_spec.get("containers", [])
    init_containers = pod_spec.get("initContainers", [])
    return containers + init_containers


@policy_check(
    check_id="image_tag",
    name="Image Tag Policy",
    severity="critical",
    category="security",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.4.1", "NSA-3.1", "SOC2-CC7.1"}),
    cis_benchmark="5.4.1",
    nsa_control="3.1",
)
def check_image_tag(manifest: dict) -> PolicyCheckResult:
    """Check 1: No 'latest' tag, no missing tags. Explicit version required."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="image_tag",
            name="Image Tag Policy",
            passed=True,
            severity="critical",
            message="Not a workload resource, skipped.",
        )

    violations: list[str] = []
    for container in containers:
        image = container.get("image", "")
        name = container.get("name", "unknown")
        if ":" not in image:
            violations.append(f"Container '{name}' image '{image}' has no tag")
        elif image.endswith(":latest"):
            violations.append(f"Container '{name}' uses 'latest' tag")

    if violations:
        return PolicyCheckResult(
            check_id="image_tag",
            name="Image Tag Policy",
            passed=False,
            severity="critical",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="image_tag",
        name="Image Tag Policy",
        passed=True,
        severity="critical",
        message="All images use explicit version tags.",
    )


@policy_check(
    check_id="security_context",
    name="Security Context",
    severity="critical",
    category="security",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.2.1", "CIS-5.2.6", "NSA-3.1", "SOC2-CC6.1"}),
    cis_benchmark="5.2.1",
    nsa_control="3.1",
)
def check_security_context(manifest: dict) -> PolicyCheckResult:
    """Check 2: runAsNonRoot=true, privileged=false for all containers."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="security_context",
            name="Security Context",
            passed=True,
            severity="critical",
            message="Not a workload resource, skipped.",
        )

    violations: list[str] = []
    for container in containers:
        name = container.get("name", "unknown")
        sec_ctx = container.get("securityContext")
        if sec_ctx is None:
            violations.append(f"Container '{name}' has no securityContext")
            continue
        if sec_ctx.get("privileged", False) is True:
            violations.append(f"Container '{name}' runs as privileged")
        if sec_ctx.get("runAsNonRoot") is not True:
            violations.append(f"Container '{name}' does not set runAsNonRoot: true")

    if violations:
        return PolicyCheckResult(
            check_id="security_context",
            name="Security Context",
            passed=False,
            severity="critical",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="security_context",
        name="Security Context",
        passed=True,
        severity="critical",
        message="All containers have proper security context.",
    )


@policy_check(
    check_id="rbac_scope",
    name="RBAC Scope",
    severity="critical",
    category="security",
    risk_points=0,
    prod_behavior="hard_block",
    other_behavior="hard_block",
    compliance_tags=frozenset({"CIS-5.1.1", "CIS-5.1.2", "NSA-2.1", "SOC2-CC6.1", "SOC2-CC6.3"}),
    cis_benchmark="5.1.1",
    nsa_control="2.1",
)
def check_rbac_scope(manifest: dict) -> PolicyCheckResult:
    """Check 3: No ClusterRoleBindings to default ServiceAccounts."""
    if manifest.get("kind") != "ClusterRoleBinding":
        return PolicyCheckResult(
            check_id="rbac_scope",
            name="RBAC Scope",
            passed=True,
            severity="critical",
            message="Not a ClusterRoleBinding, skipped.",
        )

    subjects = manifest.get("subjects", [])
    violations: list[str] = []
    for subject in subjects:
        if (
            subject.get("kind") == "ServiceAccount"
            and subject.get("name") == "default"
        ):
            ns = subject.get("namespace", "unknown")
            violations.append(
                f"ClusterRoleBinding binds to default ServiceAccount in namespace '{ns}'"
            )

    if violations:
        role_ref = manifest.get("roleRef", {}).get("name", "unknown")
        return PolicyCheckResult(
            check_id="rbac_scope",
            name="RBAC Scope",
            passed=False,
            severity="critical",
            message="; ".join(violations),
            details={"roleRef": role_ref, "violations": violations},
        )

    return PolicyCheckResult(
        check_id="rbac_scope",
        name="RBAC Scope",
        passed=True,
        severity="critical",
        message="No ClusterRoleBindings to default ServiceAccounts.",
    )


@policy_check(
    check_id="resource_limits",
    name="Resource Limits",
    severity="high",
    category="reliability",
    risk_points=25,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"CIS-5.4.5", "SOC2-CC7.2"}),
    cis_benchmark="5.4.5",
)
def check_resource_limits(manifest: dict) -> PolicyCheckResult:
    """Check 4: CPU and memory requests + limits required."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="resource_limits",
            name="Resource Limits",
            passed=True,
            severity="high",
            message="Not a workload resource, skipped.",
        )

    violations: list[str] = []
    for container in containers:
        name = container.get("name", "unknown")
        resources = container.get("resources")
        if resources is None:
            violations.append(f"Container '{name}' has no resource definitions")
            continue
        requests = resources.get("requests", {})
        limits = resources.get("limits", {})
        missing: list[str] = []
        if "cpu" not in requests:
            missing.append("requests.cpu")
        if "memory" not in requests:
            missing.append("requests.memory")
        if "cpu" not in limits:
            missing.append("limits.cpu")
        if "memory" not in limits:
            missing.append("limits.memory")
        if missing:
            violations.append(f"Container '{name}' missing: {', '.join(missing)}")

    if violations:
        return PolicyCheckResult(
            check_id="resource_limits",
            name="Resource Limits",
            passed=False,
            severity="high",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="resource_limits",
        name="Resource Limits",
        passed=True,
        severity="high",
        message="All containers have CPU and memory requests and limits.",
    )


@policy_check(
    check_id="replica_count",
    name="Replica Count",
    severity="high",
    category="reliability",
    risk_points=30,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.5"}),
)
def check_replica_count(manifest: dict) -> PolicyCheckResult:
    """Check 5: Minimum 2 replicas (for production use)."""
    if manifest.get("kind") not in {"Deployment", "StatefulSet", "ReplicaSet"}:
        return PolicyCheckResult(
            check_id="replica_count",
            name="Replica Count",
            passed=True,
            severity="high",
            message="Not a scalable workload, skipped.",
        )

    replicas = manifest.get("spec", {}).get("replicas", 1)

    if replicas < 2:
        return PolicyCheckResult(
            check_id="replica_count",
            name="Replica Count",
            passed=False,
            severity="high",
            message=f"Replica count is {replicas}. Minimum 2 required for availability.",
            details={"replicas": replicas, "minimum": 2},
        )

    return PolicyCheckResult(
        check_id="replica_count",
        name="Replica Count",
        passed=True,
        severity="high",
        message=f"Replica count is {replicas}.",
    )


# ---------------------------------------------------------------------------
# Security checks (Phase 2)
# ---------------------------------------------------------------------------


@policy_check(
    check_id="readonly_root_fs",
    name="Read-Only Root Filesystem",
    severity="critical",
    category="security",
    risk_points=20,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.2.8", "NSA-3.1", "SOC2-CC6.1"}),
    cis_benchmark="5.2.8",
    nsa_control="3.1",
)
def check_readonly_root_fs(manifest: dict) -> PolicyCheckResult:
    """readOnlyRootFilesystem: true on all containers."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="readonly_root_fs",
            name="Read-Only Root Filesystem",
            passed=True,
            severity="critical",
            message="Not a workload resource, skipped.",
        )

    violations: list[str] = []
    for container in containers:
        name = container.get("name", "unknown")
        sec_ctx = container.get("securityContext", {})
        if sec_ctx.get("readOnlyRootFilesystem") is not True:
            violations.append(f"Container '{name}' does not set readOnlyRootFilesystem: true")

    if violations:
        return PolicyCheckResult(
            check_id="readonly_root_fs",
            name="Read-Only Root Filesystem",
            passed=False,
            severity="critical",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="readonly_root_fs",
        name="Read-Only Root Filesystem",
        passed=True,
        severity="critical",
        message="All containers have read-only root filesystem.",
    )


@policy_check(
    check_id="run_as_user_group",
    name="Run As User/Group",
    severity="critical",
    category="security",
    risk_points=20,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.2.6", "NSA-3.1", "SOC2-CC6.1"}),
    cis_benchmark="5.2.6",
    nsa_control="3.1",
)
def check_run_as_user_group(manifest: dict) -> PolicyCheckResult:
    """runAsUser > 0 and runAsGroup > 0 (pod-level or container-level)."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="run_as_user_group",
            name="Run As User/Group",
            passed=True,
            severity="critical",
            message="Not a workload resource, skipped.",
        )

    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
    pod_sec = pod_spec.get("securityContext", {})
    pod_uid = pod_sec.get("runAsUser")
    pod_gid = pod_sec.get("runAsGroup")

    violations: list[str] = []
    for container in containers:
        name = container.get("name", "unknown")
        c_sec = container.get("securityContext", {})
        uid = c_sec.get("runAsUser", pod_uid)
        gid = c_sec.get("runAsGroup", pod_gid)

        if uid is None or uid <= 0:
            violations.append(f"Container '{name}' runAsUser is not set or is root (0)")
        if gid is None or gid <= 0:
            violations.append(f"Container '{name}' runAsGroup is not set or is root (0)")

    if violations:
        return PolicyCheckResult(
            check_id="run_as_user_group",
            name="Run As User/Group",
            passed=False,
            severity="critical",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="run_as_user_group",
        name="Run As User/Group",
        passed=True,
        severity="critical",
        message="All containers run as non-root user and group.",
    )


# ---------------------------------------------------------------------------
# Reliability checks (Phase 3)
# ---------------------------------------------------------------------------

_SCALABLE_KINDS = {"Deployment", "StatefulSet", "ReplicaSet"}


@policy_check(
    check_id="liveness_readiness_probes",
    name="Liveness & Readiness Probes",
    severity="high",
    category="reliability",
    risk_points=25,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.5"}),
)
def check_liveness_readiness_probes(manifest: dict) -> PolicyCheckResult:
    """Both liveness and readiness probes required on all containers."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="liveness_readiness_probes",
            name="Liveness & Readiness Probes",
            passed=True,
            severity="high",
            message="Not a workload resource, skipped.",
        )

    violations: list[str] = []
    for container in containers:
        name = container.get("name", "unknown")
        if not container.get("livenessProbe"):
            violations.append(f"Container '{name}' missing livenessProbe")
        if not container.get("readinessProbe"):
            violations.append(f"Container '{name}' missing readinessProbe")

    if violations:
        return PolicyCheckResult(
            check_id="liveness_readiness_probes",
            name="Liveness & Readiness Probes",
            passed=False,
            severity="high",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="liveness_readiness_probes",
        name="Liveness & Readiness Probes",
        passed=True,
        severity="high",
        message="All containers have liveness and readiness probes.",
    )


@policy_check(
    check_id="deployment_strategy",
    name="Deployment Strategy",
    severity="high",
    category="reliability",
    risk_points=20,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.5"}),
)
def check_deployment_strategy(manifest: dict) -> PolicyCheckResult:
    """Deployments must use RollingUpdate strategy (not Recreate)."""
    if manifest.get("kind") != "Deployment":
        return PolicyCheckResult(
            check_id="deployment_strategy",
            name="Deployment Strategy",
            passed=True,
            severity="high",
            message="Not a Deployment, skipped.",
        )

    strategy_type = manifest.get("spec", {}).get("strategy", {}).get("type", "RollingUpdate")

    if strategy_type != "RollingUpdate":
        return PolicyCheckResult(
            check_id="deployment_strategy",
            name="Deployment Strategy",
            passed=False,
            severity="high",
            message=f"Deployment uses '{strategy_type}' strategy. RollingUpdate required.",
            details={"strategy": strategy_type},
        )

    return PolicyCheckResult(
        check_id="deployment_strategy",
        name="Deployment Strategy",
        passed=True,
        severity="high",
        message="Deployment uses RollingUpdate strategy.",
    )


@policy_check(
    check_id="pod_disruption_budget",
    name="Pod Disruption Budget",
    severity="high",
    category="reliability",
    risk_points=15,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.5"}),
)
def check_pod_disruption_budget(manifest: dict) -> PolicyCheckResult:
    """PDB must have minAvailable or maxUnavailable."""
    if manifest.get("kind") != "PodDisruptionBudget":
        return PolicyCheckResult(
            check_id="pod_disruption_budget",
            name="Pod Disruption Budget",
            passed=True,
            severity="high",
            message="Not a PodDisruptionBudget, skipped.",
        )

    spec = manifest.get("spec", {})
    has_min = "minAvailable" in spec
    has_max = "maxUnavailable" in spec

    if not has_min and not has_max:
        return PolicyCheckResult(
            check_id="pod_disruption_budget",
            name="Pod Disruption Budget",
            passed=False,
            severity="high",
            message="PDB has neither minAvailable nor maxUnavailable.",
            details={"spec_keys": list(spec.keys())},
        )

    return PolicyCheckResult(
        check_id="pod_disruption_budget",
        name="Pod Disruption Budget",
        passed=True,
        severity="high",
        message="PDB has disruption constraints configured.",
    )


@policy_check(
    check_id="host_pod_anti_affinity",
    name="Pod Anti-Affinity",
    severity="high",
    category="reliability",
    risk_points=20,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.5"}),
)
def check_host_pod_anti_affinity(manifest: dict) -> PolicyCheckResult:
    """podAntiAffinity required when replicas > 1."""
    if manifest.get("kind") not in _SCALABLE_KINDS:
        return PolicyCheckResult(
            check_id="host_pod_anti_affinity",
            name="Pod Anti-Affinity",
            passed=True,
            severity="high",
            message="Not a scalable workload, skipped.",
        )

    replicas = manifest.get("spec", {}).get("replicas", 1)
    if replicas <= 1:
        return PolicyCheckResult(
            check_id="host_pod_anti_affinity",
            name="Pod Anti-Affinity",
            passed=True,
            severity="high",
            message="Single replica, anti-affinity not required.",
        )

    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
    affinity = pod_spec.get("affinity", {})
    has_anti_affinity = bool(affinity.get("podAntiAffinity"))

    if not has_anti_affinity:
        return PolicyCheckResult(
            check_id="host_pod_anti_affinity",
            name="Pod Anti-Affinity",
            passed=False,
            severity="high",
            message=f"Deployment has {replicas} replicas but no podAntiAffinity configured.",
            details={"replicas": replicas},
        )

    return PolicyCheckResult(
        check_id="host_pod_anti_affinity",
        name="Pod Anti-Affinity",
        passed=True,
        severity="high",
        message="Pod anti-affinity is configured.",
    )


# ---------------------------------------------------------------------------
# Best-practice checks (Phase 4)
# ---------------------------------------------------------------------------

_DEPRECATED_API_VERSIONS = {
    "extensions/v1beta1",
    "apps/v1beta1",
    "apps/v1beta2",
    "networking.k8s.io/v1beta1",
    "policy/v1beta1",
    "rbac.authorization.k8s.io/v1beta1",
    "admissionregistration.k8s.io/v1beta1",
    "apiextensions.k8s.io/v1beta1",
    "storage.k8s.io/v1beta1",
}


@policy_check(
    check_id="image_pull_policy",
    name="Image Pull Policy",
    severity="medium",
    category="best-practice",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"CIS-5.4.2", "NSA-3.1", "SOC2-CC7.1"}),
    cis_benchmark="5.4.2",
    nsa_control="3.1",
)
def check_image_pull_policy(manifest: dict) -> PolicyCheckResult:
    """imagePullPolicy must be Always."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="image_pull_policy",
            name="Image Pull Policy",
            passed=True,
            severity="medium",
            message="Not a workload resource, skipped.",
        )

    violations: list[str] = []
    for container in containers:
        name = container.get("name", "unknown")
        policy = container.get("imagePullPolicy", "")
        if policy != "Always":
            violations.append(f"Container '{name}' imagePullPolicy is '{policy or 'unset'}', expected 'Always'")

    if violations:
        return PolicyCheckResult(
            check_id="image_pull_policy",
            name="Image Pull Policy",
            passed=False,
            severity="medium",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="image_pull_policy",
        name="Image Pull Policy",
        passed=True,
        severity="medium",
        message="All containers use imagePullPolicy: Always.",
    )


@policy_check(
    check_id="service_type",
    name="Service Type",
    severity="medium",
    category="best-practice",
    risk_points=15,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"NSA-4.3", "SOC2-CC6.6"}),
    nsa_control="4.3",
)
def check_service_type(manifest: dict) -> PolicyCheckResult:
    """No NodePort services."""
    if manifest.get("kind") != "Service":
        return PolicyCheckResult(
            check_id="service_type",
            name="Service Type",
            passed=True,
            severity="medium",
            message="Not a Service, skipped.",
        )

    svc_type = manifest.get("spec", {}).get("type", "ClusterIP")

    if svc_type == "NodePort":
        return PolicyCheckResult(
            check_id="service_type",
            name="Service Type",
            passed=False,
            severity="medium",
            message="Service uses NodePort. Use ClusterIP or LoadBalancer instead.",
            details={"type": svc_type},
        )

    return PolicyCheckResult(
        check_id="service_type",
        name="Service Type",
        passed=True,
        severity="medium",
        message=f"Service type is {svc_type}.",
    )


@policy_check(
    check_id="network_policy",
    name="Network Policy",
    severity="medium",
    category="best-practice",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"CIS-5.3.2", "NSA-4.1", "SOC2-CC6.6"}),
    cis_benchmark="5.3.2",
    nsa_control="4.1",
)
def check_network_policy(manifest: dict) -> PolicyCheckResult:
    """NetworkPolicy must have podSelector and ingress or egress rules."""
    if manifest.get("kind") != "NetworkPolicy":
        return PolicyCheckResult(
            check_id="network_policy",
            name="Network Policy",
            passed=True,
            severity="medium",
            message="Not a NetworkPolicy, skipped.",
        )

    spec = manifest.get("spec", {})
    violations: list[str] = []

    if "podSelector" not in spec:
        violations.append("NetworkPolicy missing podSelector")

    has_ingress = bool(spec.get("ingress"))
    has_egress = bool(spec.get("egress"))
    if not has_ingress and not has_egress:
        violations.append("NetworkPolicy has no ingress or egress rules")

    if violations:
        return PolicyCheckResult(
            check_id="network_policy",
            name="Network Policy",
            passed=False,
            severity="medium",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="network_policy",
        name="Network Policy",
        passed=True,
        severity="medium",
        message="NetworkPolicy has podSelector and traffic rules.",
    )


@policy_check(
    check_id="cronjob_deadline",
    name="CronJob Deadline",
    severity="medium",
    category="best-practice",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.2"}),
)
def check_cronjob_deadline(manifest: dict) -> PolicyCheckResult:
    """CronJob must have startingDeadlineSeconds."""
    if manifest.get("kind") != "CronJob":
        return PolicyCheckResult(
            check_id="cronjob_deadline",
            name="CronJob Deadline",
            passed=True,
            severity="medium",
            message="Not a CronJob, skipped.",
        )

    spec = manifest.get("spec", {})
    if "startingDeadlineSeconds" not in spec:
        return PolicyCheckResult(
            check_id="cronjob_deadline",
            name="CronJob Deadline",
            passed=False,
            severity="medium",
            message="CronJob missing startingDeadlineSeconds.",
        )

    return PolicyCheckResult(
        check_id="cronjob_deadline",
        name="CronJob Deadline",
        passed=True,
        severity="medium",
        message=f"CronJob startingDeadlineSeconds is {spec['startingDeadlineSeconds']}.",
    )


@policy_check(
    check_id="stable_api_version",
    name="Stable API Version",
    severity="medium",
    category="best-practice",
    risk_points=15,
    prod_behavior="soft_risk",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC7.1"}),
)
def check_stable_api_version(manifest: dict) -> PolicyCheckResult:
    """No deprecated apiVersions."""
    api_version = manifest.get("apiVersion", "")

    if api_version in _DEPRECATED_API_VERSIONS:
        return PolicyCheckResult(
            check_id="stable_api_version",
            name="Stable API Version",
            passed=False,
            severity="medium",
            message=f"Deprecated apiVersion '{api_version}'. Use a stable version.",
            details={"apiVersion": api_version},
        )

    return PolicyCheckResult(
        check_id="stable_api_version",
        name="Stable API Version",
        passed=True,
        severity="medium",
        message=f"apiVersion '{api_version}' is stable.",
    )


@policy_check(
    check_id="env_var_duplicates",
    name="Env Var Duplicates",
    severity="medium",
    category="best-practice",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC7.2"}),
)
def check_env_var_duplicates(manifest: dict) -> PolicyCheckResult:
    """No duplicate env var keys in containers."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="env_var_duplicates",
            name="Env Var Duplicates",
            passed=True,
            severity="medium",
            message="Not a workload resource, skipped.",
        )

    violations: list[str] = []
    for container in containers:
        name = container.get("name", "unknown")
        env_vars = container.get("env", [])
        seen: dict[str, int] = {}
        for var in env_vars:
            var_name = var.get("name", "")
            seen[var_name] = seen.get(var_name, 0) + 1
        duplicates = [k for k, v in seen.items() if v > 1]
        if duplicates:
            violations.append(f"Container '{name}' has duplicate env vars: {', '.join(duplicates)}")

    if violations:
        return PolicyCheckResult(
            check_id="env_var_duplicates",
            name="Env Var Duplicates",
            passed=False,
            severity="medium",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="env_var_duplicates",
        name="Env Var Duplicates",
        passed=True,
        severity="medium",
        message="No duplicate environment variable keys.",
    )


# ---------------------------------------------------------------------------
# Extended security checks (Phase 5 — Security Scan)
# ---------------------------------------------------------------------------

_DANGEROUS_HOST_PATHS = {"/var/run/docker.sock", "/proc", "/sys", "/etc"}
_DANGEROUS_CAPABILITIES = {"SYS_ADMIN", "NET_ADMIN", "ALL"}


@policy_check(
    check_id="host_namespace",
    name="Host Namespace",
    severity="critical",
    category="security",
    risk_points=30,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.2.2", "CIS-5.2.3", "CIS-5.2.4", "NSA-3.1", "SOC2-CC6.1"}),
    cis_benchmark="5.2.2",
    nsa_control="3.1",
)
def check_host_namespace(manifest: dict) -> PolicyCheckResult:
    """Fail if hostNetwork, hostPID, or hostIPC is true in pod spec."""
    if manifest.get("kind") not in _WORKLOAD_KINDS:
        return PolicyCheckResult(
            check_id="host_namespace",
            name="Host Namespace",
            passed=True,
            severity="critical",
            message="Not a workload resource, skipped.",
        )

    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
    violations: list[str] = []

    for ns_field in ("hostNetwork", "hostPID", "hostIPC"):
        if pod_spec.get(ns_field) is True:
            violations.append(f"{ns_field} is enabled")

    if violations:
        return PolicyCheckResult(
            check_id="host_namespace",
            name="Host Namespace",
            passed=False,
            severity="critical",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="host_namespace",
        name="Host Namespace",
        passed=True,
        severity="critical",
        message="No host namespace sharing.",
    )


@policy_check(
    check_id="dangerous_volume_mounts",
    name="Dangerous Volume Mounts",
    severity="critical",
    category="security",
    risk_points=30,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.2.10", "NSA-3.1", "SOC2-CC6.1"}),
    cis_benchmark="5.2.10",
    nsa_control="3.1",
)
def check_dangerous_volume_mounts(manifest: dict) -> PolicyCheckResult:
    """Fail if hostPath volumes mount dangerous paths."""
    if manifest.get("kind") not in _WORKLOAD_KINDS:
        return PolicyCheckResult(
            check_id="dangerous_volume_mounts",
            name="Dangerous Volume Mounts",
            passed=True,
            severity="critical",
            message="Not a workload resource, skipped.",
        )

    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
    volumes = pod_spec.get("volumes", [])
    violations: list[str] = []

    for volume in volumes:
        host_path = volume.get("hostPath", {}).get("path", "")
        vol_name = volume.get("name", "unknown")
        for dangerous in _DANGEROUS_HOST_PATHS:
            if host_path == dangerous or host_path.startswith(dangerous + "/"):
                violations.append(f"Volume '{vol_name}' mounts dangerous hostPath '{host_path}'")

    if violations:
        return PolicyCheckResult(
            check_id="dangerous_volume_mounts",
            name="Dangerous Volume Mounts",
            passed=False,
            severity="critical",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="dangerous_volume_mounts",
        name="Dangerous Volume Mounts",
        passed=True,
        severity="critical",
        message="No dangerous hostPath volume mounts.",
    )


@policy_check(
    check_id="excessive_capabilities",
    name="Excessive Capabilities",
    severity="high",
    category="security",
    risk_points=20,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"CIS-5.2.7", "CIS-5.2.9", "NSA-3.1", "SOC2-CC6.1"}),
    cis_benchmark="5.2.7",
    nsa_control="3.1",
)
def check_excessive_capabilities(manifest: dict) -> PolicyCheckResult:
    """Fail if SYS_ADMIN, NET_ADMIN, or ALL in capabilities.add."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="excessive_capabilities",
            name="Excessive Capabilities",
            passed=True,
            severity="high",
            message="Not a workload resource, skipped.",
        )

    violations: list[str] = []
    for container in containers:
        name = container.get("name", "unknown")
        caps = (
            container.get("securityContext", {})
            .get("capabilities", {})
            .get("add", [])
        )
        dangerous = [c for c in caps if c in _DANGEROUS_CAPABILITIES]
        if dangerous:
            violations.append(f"Container '{name}' adds dangerous capabilities: {', '.join(dangerous)}")

    if violations:
        return PolicyCheckResult(
            check_id="excessive_capabilities",
            name="Excessive Capabilities",
            passed=False,
            severity="high",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="excessive_capabilities",
        name="Excessive Capabilities",
        passed=True,
        severity="high",
        message="No excessive capabilities granted.",
    )


@policy_check(
    check_id="service_account_token",
    name="Service Account Token",
    severity="medium",
    category="security",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"CIS-5.1.5", "CIS-5.1.6", "NSA-2.1", "SOC2-CC6.1"}),
    cis_benchmark="5.1.5",
    nsa_control="2.1",
)
def check_service_account_token(manifest: dict) -> PolicyCheckResult:
    """Fail if automountServiceAccountToken is not explicitly false."""
    if manifest.get("kind") not in _WORKLOAD_KINDS:
        return PolicyCheckResult(
            check_id="service_account_token",
            name="Service Account Token",
            passed=True,
            severity="medium",
            message="Not a workload resource, skipped.",
        )

    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
    automount = pod_spec.get("automountServiceAccountToken")

    if automount is not False:
        return PolicyCheckResult(
            check_id="service_account_token",
            name="Service Account Token",
            passed=False,
            severity="medium",
            message="automountServiceAccountToken is not explicitly set to false.",
            details={"automountServiceAccountToken": automount},
        )

    return PolicyCheckResult(
        check_id="service_account_token",
        name="Service Account Token",
        passed=True,
        severity="medium",
        message="Service account token auto-mount is disabled.",
    )


@policy_check(
    check_id="exposed_services",
    name="Exposed Services",
    severity="medium",
    category="security",
    risk_points=15,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"NSA-4.3", "SOC2-CC6.6"}),
    nsa_control="4.3",
)
def check_exposed_services(manifest: dict) -> PolicyCheckResult:
    """Fail if Service type is NodePort or LoadBalancer."""
    if manifest.get("kind") != "Service":
        return PolicyCheckResult(
            check_id="exposed_services",
            name="Exposed Services",
            passed=True,
            severity="medium",
            message="Not a Service, skipped.",
        )

    svc_type = manifest.get("spec", {}).get("type", "ClusterIP")

    if svc_type in ("NodePort", "LoadBalancer"):
        return PolicyCheckResult(
            check_id="exposed_services",
            name="Exposed Services",
            passed=False,
            severity="medium",
            message=f"Service uses {svc_type}, which exposes it externally.",
            details={"type": svc_type},
        )

    return PolicyCheckResult(
        check_id="exposed_services",
        name="Exposed Services",
        passed=True,
        severity="medium",
        message=f"Service type is {svc_type} (internal).",
    )


# ---------------------------------------------------------------------------
# Enterprise compliance checks (Phase 6 -- CIS / NSA hardening)
# ---------------------------------------------------------------------------

_PSS_BASELINE_ALLOWED_CAPABILITIES = frozenset({
    "AUDIT_WRITE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "MKNOD",
    "NET_BIND_SERVICE",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
})

_PSS_BASELINE_ALLOWED_SELINUX_TYPES = frozenset({
    "",
    "container_t",
    "container_init_t",
    "container_kvm_t",
})


@policy_check(
    check_id="allow_privilege_escalation",
    name="Allow Privilege Escalation",
    severity="critical",
    category="security",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.2.5", "NSA-3.1"}),
    cis_benchmark="5.2.5",
    nsa_control="3.1",
    description="Containers must explicitly set allowPrivilegeEscalation: false.",
    remediation="Set securityContext.allowPrivilegeEscalation: false on every container.",
)
def check_allow_privilege_escalation(manifest: dict) -> PolicyCheckResult:
    """allowPrivilegeEscalation must be explicitly false on all containers (CIS 5.2.5)."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="allow_privilege_escalation",
            name="Allow Privilege Escalation",
            passed=True,
            severity="critical",
            message="Not a workload resource, skipped.",
        )

    violations: list[str] = []
    for container in containers:
        name = container.get("name", "unknown")
        sec_ctx = container.get("securityContext", {})
        if sec_ctx.get("allowPrivilegeEscalation") is not False:
            violations.append(
                f"Container '{name}' does not set allowPrivilegeEscalation: false"
            )

    if violations:
        return PolicyCheckResult(
            check_id="allow_privilege_escalation",
            name="Allow Privilege Escalation",
            passed=False,
            severity="critical",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="allow_privilege_escalation",
        name="Allow Privilege Escalation",
        passed=True,
        severity="critical",
        message="All containers explicitly disable privilege escalation.",
    )


@policy_check(
    check_id="host_pid",
    name="Host PID Namespace",
    severity="critical",
    category="security",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.2.2"}),
    cis_benchmark="5.2.2",
    description="Pods must not share the host PID namespace.",
    remediation="Remove or set hostPID: false in the pod spec.",
)
def check_host_pid(manifest: dict) -> PolicyCheckResult:
    """hostPID must not be true in pod spec (CIS 5.2.2)."""
    if manifest.get("kind") not in _WORKLOAD_KINDS:
        return PolicyCheckResult(
            check_id="host_pid",
            name="Host PID Namespace",
            passed=True,
            severity="critical",
            message="Not a workload resource, skipped.",
        )

    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})

    if pod_spec.get("hostPID") is True:
        return PolicyCheckResult(
            check_id="host_pid",
            name="Host PID Namespace",
            passed=False,
            severity="critical",
            message="hostPID is enabled; pod shares the host PID namespace.",
            details={"hostPID": True},
        )

    return PolicyCheckResult(
        check_id="host_pid",
        name="Host PID Namespace",
        passed=True,
        severity="critical",
        message="hostPID is not enabled.",
    )


@policy_check(
    check_id="host_ipc",
    name="Host IPC Namespace",
    severity="critical",
    category="security",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.2.3"}),
    cis_benchmark="5.2.3",
    description="Pods must not share the host IPC namespace.",
    remediation="Remove or set hostIPC: false in the pod spec.",
)
def check_host_ipc(manifest: dict) -> PolicyCheckResult:
    """hostIPC must not be true in pod spec (CIS 5.2.3)."""
    if manifest.get("kind") not in _WORKLOAD_KINDS:
        return PolicyCheckResult(
            check_id="host_ipc",
            name="Host IPC Namespace",
            passed=True,
            severity="critical",
            message="Not a workload resource, skipped.",
        )

    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})

    if pod_spec.get("hostIPC") is True:
        return PolicyCheckResult(
            check_id="host_ipc",
            name="Host IPC Namespace",
            passed=False,
            severity="critical",
            message="hostIPC is enabled; pod shares the host IPC namespace.",
            details={"hostIPC": True},
        )

    return PolicyCheckResult(
        check_id="host_ipc",
        name="Host IPC Namespace",
        passed=True,
        severity="critical",
        message="hostIPC is not enabled.",
    )


@policy_check(
    check_id="default_namespace",
    name="Default Namespace",
    severity="medium",
    category="best-practice",
    risk_points=15,
    prod_behavior="soft_risk",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.7.4"}),
    cis_benchmark="5.7.4",
    description="Resources must not be deployed into the 'default' namespace.",
    remediation="Set metadata.namespace to a dedicated, non-default namespace.",
)
def check_default_namespace(manifest: dict) -> PolicyCheckResult:
    """metadata.namespace must not be 'default' or absent (CIS 5.7.4)."""
    namespace = manifest.get("metadata", {}).get("namespace")

    if namespace is None:
        return PolicyCheckResult(
            check_id="default_namespace",
            name="Default Namespace",
            passed=True,
            severity="medium",
            message="Resource has no namespace context, skipped.",
        )

    if namespace == "default" or namespace == "":
        return PolicyCheckResult(
            check_id="default_namespace",
            name="Default Namespace",
            passed=False,
            severity="medium",
            message=f"Resource is deployed in the '{namespace or 'default'}' namespace. Use a dedicated namespace.",
            details={"namespace": namespace or "default"},
        )

    return PolicyCheckResult(
        check_id="default_namespace",
        name="Default Namespace",
        passed=True,
        severity="medium",
        message=f"Resource is deployed in namespace '{namespace}'.",
    )


@policy_check(
    check_id="pod_security_standards",
    name="Pod Security Standards (Baseline)",
    severity="high",
    category="security",
    risk_points=20,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"CIS-5.2", "NSA-3.1"}),
    cis_benchmark="5.2",
    nsa_control="3.1",
    description="Pod spec must conform to Kubernetes Pod Security Standards Baseline level.",
    remediation=(
        "Remove privileged containers, host namespace sharing, non-baseline capabilities, "
        "non-default procMount values, and restricted SELinux types."
    ),
)
def check_pod_security_standards(manifest: dict) -> PolicyCheckResult:
    """Evaluate pod spec against PSS Baseline level (CIS 5.2, NSA Section 3)."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="pod_security_standards",
            name="Pod Security Standards (Baseline)",
            passed=True,
            severity="high",
            message="Not a workload resource, skipped.",
        )

    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
    violations: list[str] = []

    # Pod-level host namespace checks
    for ns_field in ("hostNetwork", "hostPID", "hostIPC"):
        if pod_spec.get(ns_field) is True:
            violations.append(f"Pod spec has {ns_field}: true")

    # Per-container checks
    for container in containers:
        name = container.get("name", "unknown")
        sec_ctx = container.get("securityContext", {})

        # Privileged containers are Baseline-banned
        if sec_ctx.get("privileged") is True:
            violations.append(f"Container '{name}' runs as privileged")

        # Capabilities beyond the PSS Baseline allowed set
        added_caps: list[str] = sec_ctx.get("capabilities", {}).get("add", [])
        disallowed = [cap for cap in added_caps if cap not in _PSS_BASELINE_ALLOWED_CAPABILITIES]
        if disallowed:
            violations.append(
                f"Container '{name}' adds non-baseline capabilities: {', '.join(disallowed)}"
            )

        # procMount must be Default (or unset)
        proc_mount = sec_ctx.get("procMount")
        if proc_mount is not None and proc_mount != "Default":
            violations.append(
                f"Container '{name}' has procMount: {proc_mount!r} (only 'Default' is allowed)"
            )

        # SELinux type must be in the allowed set
        selinux_type = sec_ctx.get("seLinuxOptions", {}).get("type", "")
        if selinux_type not in _PSS_BASELINE_ALLOWED_SELINUX_TYPES:
            violations.append(
                f"Container '{name}' has disallowed seLinuxOptions.type: {selinux_type!r}"
            )

    if violations:
        return PolicyCheckResult(
            check_id="pod_security_standards",
            name="Pod Security Standards (Baseline)",
            passed=False,
            severity="high",
            message="; ".join(violations),
            details={"pss_level": "baseline", "violations": violations},
        )

    return PolicyCheckResult(
        check_id="pod_security_standards",
        name="Pod Security Standards (Baseline)",
        passed=True,
        severity="high",
        message="Pod spec conforms to PSS Baseline level.",
        details={"pss_level": "baseline"},
    )
