"""Extended policy checks for Polaris parity (~30 total checks)."""

from vlamguard.engine.policies import _WORKLOAD_KINDS, _get_containers
from vlamguard.engine.registry import policy_check
from vlamguard.models.response import PolicyCheckResult


@policy_check(
    check_id="drop_all_capabilities",
    name="Drop All Capabilities",
    severity="high",
    category="security",
    risk_points=20,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"CIS-5.2.7", "CIS-5.2.9", "NSA-3.1"}),
    cis_benchmark="5.2.7",
    nsa_control="3.1",
)
def check_drop_all_capabilities(manifest: dict) -> PolicyCheckResult:
    """Check containers have capabilities.drop: [ALL] in their securityContext."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="drop_all_capabilities",
            name="Drop All Capabilities",
            passed=True,
            severity="high",
            message="Not a workload resource, skipped.",
        )

    violations: list[str] = []
    for container in containers:
        name = container.get("name", "unknown")
        drop_list = (
            container.get("securityContext", {})
            .get("capabilities", {})
            .get("drop", [])
        )
        # Normalise to upper-case for comparison
        normalised = [cap.upper() for cap in drop_list]
        if "ALL" not in normalised:
            violations.append(
                f"Container '{name}' does not drop ALL capabilities "
                f"(capabilities.drop does not include 'ALL')"
            )

    if violations:
        return PolicyCheckResult(
            check_id="drop_all_capabilities",
            name="Drop All Capabilities",
            passed=False,
            severity="high",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="drop_all_capabilities",
        name="Drop All Capabilities",
        passed=True,
        severity="high",
        message="All containers drop ALL capabilities.",
    )


@policy_check(
    check_id="ingress_tls",
    name="Ingress TLS",
    severity="medium",
    category="security",
    risk_points=15,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC6.6"}),
)
def check_ingress_tls(manifest: dict) -> PolicyCheckResult:
    """Check Ingress resources have TLS configured (spec.tls non-empty)."""
    if manifest.get("kind") != "Ingress":
        return PolicyCheckResult(
            check_id="ingress_tls",
            name="Ingress TLS",
            passed=True,
            severity="medium",
            message="Not an Ingress, skipped.",
        )

    tls = manifest.get("spec", {}).get("tls")
    if not tls:
        name = manifest.get("metadata", {}).get("name", "unknown")
        return PolicyCheckResult(
            check_id="ingress_tls",
            name="Ingress TLS",
            passed=False,
            severity="medium",
            message=f"Ingress '{name}' has no TLS configuration (spec.tls is missing or empty).",
            details={"ingress": name},
        )

    return PolicyCheckResult(
        check_id="ingress_tls",
        name="Ingress TLS",
        passed=True,
        severity="medium",
        message="Ingress has TLS configured.",
    )


@policy_check(
    check_id="host_port_restriction",
    name="Host Port Restriction",
    severity="medium",
    category="security",
    risk_points=15,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"CIS-5.2.2"}),
    cis_benchmark="5.2.2",
)
def check_host_port_restriction(manifest: dict) -> PolicyCheckResult:
    """Check no container ports use hostPort."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="host_port_restriction",
            name="Host Port Restriction",
            passed=True,
            severity="medium",
            message="Not a workload resource, skipped.",
        )

    violations: list[str] = []
    for container in containers:
        c_name = container.get("name", "unknown")
        for port in container.get("ports", []):
            host_port = port.get("hostPort")
            if host_port is not None:
                container_port = port.get("containerPort", "unknown")
                violations.append(
                    f"Container '{c_name}' binds containerPort {container_port} "
                    f"to hostPort {host_port}"
                )

    if violations:
        return PolicyCheckResult(
            check_id="host_port_restriction",
            name="Host Port Restriction",
            passed=False,
            severity="medium",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="host_port_restriction",
        name="Host Port Restriction",
        passed=True,
        severity="medium",
        message="No containers use hostPort.",
    )


@policy_check(
    check_id="rbac_wildcard_permissions",
    name="RBAC Wildcard Permissions",
    severity="critical",
    category="security",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.1.3"}),
    cis_benchmark="5.1.3",
)
def check_rbac_wildcard_permissions(manifest: dict) -> PolicyCheckResult:
    """Check ClusterRole/Role rules do not use wildcard (*) in verbs, resources, or apiGroups."""
    if manifest.get("kind") not in ("ClusterRole", "Role"):
        return PolicyCheckResult(
            check_id="rbac_wildcard_permissions",
            name="RBAC Wildcard Permissions",
            passed=True,
            severity="critical",
            message="Not a ClusterRole or Role, skipped.",
        )

    rules = manifest.get("rules") or []
    violations: list[str] = []
    role_name = manifest.get("metadata", {}).get("name", "unknown")

    for i, rule in enumerate(rules):
        rule_label = f"rule[{i}]"
        for field in ("verbs", "resources", "apiGroups"):
            if "*" in (rule.get(field) or []):
                violations.append(
                    f"{role_name} {rule_label} has wildcard '*' in {field}"
                )

    if violations:
        return PolicyCheckResult(
            check_id="rbac_wildcard_permissions",
            name="RBAC Wildcard Permissions",
            passed=False,
            severity="critical",
            message="; ".join(violations),
            details={"role": role_name, "violations": violations},
        )

    return PolicyCheckResult(
        check_id="rbac_wildcard_permissions",
        name="RBAC Wildcard Permissions",
        passed=True,
        severity="critical",
        message=f"{manifest.get('kind')} '{role_name}' has no wildcard permissions.",
    )


@policy_check(
    check_id="image_registry_allowlist",
    name="Image Registry Allowlist",
    severity="medium",
    category="supply-chain",
    risk_points=15,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC6.1"}),
)
def check_image_registry_allowlist(manifest: dict) -> PolicyCheckResult:
    """Check container images are not bare docker.io images without an explicit org prefix.

    Bare images (e.g. ``nginx:1.25``, ``redis``) resolve to docker.io/library/<image>
    which is the Docker Hub official library — an implicit and uncontrolled registry
    source.  Organisations should pin to a known registry or scoped repository
    (e.g. ``myregistry.example.com/nginx:1.25`` or ``bitnami/nginx:1.25``).
    """
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="image_registry_allowlist",
            name="Image Registry Allowlist",
            passed=True,
            severity="medium",
            message="Not a workload resource, skipped.",
        )

    violations: list[str] = []
    for container in containers:
        c_name = container.get("name", "unknown")
        image = container.get("image", "")
        if not image:
            continue

        # Strip tag/digest to examine the image name only
        image_name = image.split(":")[0].split("@")[0]

        # Bare images have no "/" — they resolve to docker.io/library/<name>
        if "/" not in image_name:
            violations.append(
                f"Container '{c_name}' uses bare image '{image}' "
                f"(resolves to docker.io/library — use an explicit registry or org prefix)"
            )

    if violations:
        return PolicyCheckResult(
            check_id="image_registry_allowlist",
            name="Image Registry Allowlist",
            passed=False,
            severity="medium",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="image_registry_allowlist",
        name="Image Registry Allowlist",
        passed=True,
        severity="medium",
        message="All container images use explicit registry or org-scoped references.",
    )


@policy_check(
    check_id="container_port_name",
    name="Container Port Names",
    severity="medium",
    category="best-practice",
    risk_points=5,
    prod_behavior="soft_risk",
    other_behavior="off",
)
def check_container_port_name(manifest: dict) -> PolicyCheckResult:
    """Check all container port definitions include a name field."""
    containers = _get_containers(manifest)
    if not containers:
        return PolicyCheckResult(
            check_id="container_port_name",
            name="Container Port Names",
            passed=True,
            severity="medium",
            message="Not a workload resource, skipped.",
        )

    violations: list[str] = []
    for container in containers:
        c_name = container.get("name", "unknown")
        for port in container.get("ports", []):
            if not port.get("name"):
                container_port = port.get("containerPort", "unknown")
                violations.append(
                    f"Container '{c_name}' port {container_port} has no name defined"
                )

    if violations:
        return PolicyCheckResult(
            check_id="container_port_name",
            name="Container Port Names",
            passed=False,
            severity="medium",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="container_port_name",
        name="Container Port Names",
        passed=True,
        severity="medium",
        message="All container ports have names defined.",
    )


@policy_check(
    check_id="automount_service_account",
    name="ServiceAccount Automount Token",
    severity="medium",
    category="security",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"CIS-5.1.5"}),
    cis_benchmark="5.1.5",
)
def check_automount_service_account(manifest: dict) -> PolicyCheckResult:
    """Check ServiceAccount resources explicitly set automountServiceAccountToken: false.

    This is complementary to the ``service_account_token`` check, which targets
    workload pod specs.  This check targets the ServiceAccount object itself so
    that all pods using that SA inherit the safe default.
    """
    if manifest.get("kind") != "ServiceAccount":
        return PolicyCheckResult(
            check_id="automount_service_account",
            name="ServiceAccount Automount Token",
            passed=True,
            severity="medium",
            message="Not a ServiceAccount, skipped.",
        )

    sa_name = manifest.get("metadata", {}).get("name", "unknown")
    automount = manifest.get("automountServiceAccountToken")

    if automount is not False:
        return PolicyCheckResult(
            check_id="automount_service_account",
            name="ServiceAccount Automount Token",
            passed=False,
            severity="medium",
            message=(
                f"ServiceAccount '{sa_name}' does not set "
                f"automountServiceAccountToken: false."
            ),
            details={"serviceAccount": sa_name, "automountServiceAccountToken": automount},
        )

    return PolicyCheckResult(
        check_id="automount_service_account",
        name="ServiceAccount Automount Token",
        passed=True,
        severity="medium",
        message=f"ServiceAccount '{sa_name}' disables automount of service account token.",
    )


@policy_check(
    check_id="hpa_target_ref",
    name="HPA Target Reference",
    severity="medium",
    category="reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
)
def check_hpa_target_ref(manifest: dict) -> PolicyCheckResult:
    """Check HorizontalPodAutoscaler has a scaleTargetRef with kind and name."""
    if manifest.get("kind") != "HorizontalPodAutoscaler":
        return PolicyCheckResult(
            check_id="hpa_target_ref",
            name="HPA Target Reference",
            passed=True,
            severity="medium",
            message="Not a HorizontalPodAutoscaler, skipped.",
        )

    hpa_name = manifest.get("metadata", {}).get("name", "unknown")
    scale_target_ref = manifest.get("spec", {}).get("scaleTargetRef", {})
    violations: list[str] = []

    if not scale_target_ref.get("kind"):
        violations.append(f"HPA '{hpa_name}' scaleTargetRef is missing 'kind'")
    if not scale_target_ref.get("name"):
        violations.append(f"HPA '{hpa_name}' scaleTargetRef is missing 'name'")

    if violations:
        return PolicyCheckResult(
            check_id="hpa_target_ref",
            name="HPA Target Reference",
            passed=False,
            severity="medium",
            message="; ".join(violations),
            details={"hpa": hpa_name, "scaleTargetRef": scale_target_ref, "violations": violations},
        )

    target_kind = scale_target_ref.get("kind")
    target_name = scale_target_ref.get("name")
    return PolicyCheckResult(
        check_id="hpa_target_ref",
        name="HPA Target Reference",
        passed=True,
        severity="medium",
        message=f"HPA '{hpa_name}' targets {target_kind}/{target_name}.",
    )


@policy_check(
    check_id="resource_quota",
    name="Resource Quota Hard Limits",
    severity="medium",
    category="best-practice",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.2"}),
)
def check_resource_quota(manifest: dict) -> PolicyCheckResult:
    """Check ResourceQuota has at least one hard limit defined."""
    if manifest.get("kind") != "ResourceQuota":
        return PolicyCheckResult(
            check_id="resource_quota",
            name="Resource Quota Hard Limits",
            passed=True,
            severity="medium",
            message="Not a ResourceQuota, skipped.",
        )

    quota_name = manifest.get("metadata", {}).get("name", "unknown")
    hard = manifest.get("spec", {}).get("hard")

    if not hard:
        return PolicyCheckResult(
            check_id="resource_quota",
            name="Resource Quota Hard Limits",
            passed=False,
            severity="medium",
            message=f"ResourceQuota '{quota_name}' has no hard limits defined (spec.hard is missing or empty).",
            details={"resourceQuota": quota_name},
        )

    return PolicyCheckResult(
        check_id="resource_quota",
        name="Resource Quota Hard Limits",
        passed=True,
        severity="medium",
        message=f"ResourceQuota '{quota_name}' defines {len(hard)} hard limit(s): {', '.join(sorted(hard))}.",
    )
