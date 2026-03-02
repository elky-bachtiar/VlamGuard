"""5 deterministic policy checks for Kubernetes manifests."""

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
