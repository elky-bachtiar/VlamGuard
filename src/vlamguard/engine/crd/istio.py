"""Istio CRD policy checks — service mesh security and reliability.

Covers VirtualService, DestinationRule, PeerAuthentication, AuthorizationPolicy,
and Gateway resources. Focuses on mTLS enforcement, fault injection hygiene,
traffic resilience, and network security posture.
"""

from vlamguard.engine.registry import policy_check
from vlamguard.models.response import PolicyCheckResult

# Istio resource kinds
_VIRTUAL_SERVICE = "VirtualService"
_DESTINATION_RULE = "DestinationRule"
_PEER_AUTHENTICATION = "PeerAuthentication"
_AUTHORIZATION_POLICY = "AuthorizationPolicy"
_GATEWAY = "Gateway"

# Accepted mTLS modes that enforce encryption
_MTLS_ENFORCING_MODES = {"ISTIO_MUTUAL", "MUTUAL"}


# ---------------------------------------------------------------------------
# VirtualService checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="istio_virtualservice_timeout",
    name="Istio VirtualService Timeout",
    severity="medium",
    category="istio-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.5"}),
    description="VirtualService HTTP routes without a timeout allow unbounded latency to cascade across the mesh.",
    remediation="Set spec.http[].timeout (e.g. '30s') on every HTTP route in the VirtualService.",
)
def check_istio_virtualservice_timeout(manifest: dict) -> PolicyCheckResult:
    """VirtualService HTTP routes should each have an explicit timeout."""
    if manifest.get("kind") != _VIRTUAL_SERVICE:
        return PolicyCheckResult(
            check_id="istio_virtualservice_timeout",
            name="Istio VirtualService Timeout",
            passed=True,
            severity="medium",
            message="Not a VirtualService, skipped.",
        )

    spec = manifest.get("spec", {})
    http_routes = spec.get("http", [])

    if not http_routes:
        return PolicyCheckResult(
            check_id="istio_virtualservice_timeout",
            name="Istio VirtualService Timeout",
            passed=True,
            severity="medium",
            message="No HTTP routes defined, skipped.",
        )

    missing = [
        f"route[{i}]"
        for i, route in enumerate(http_routes)
        if not route.get("timeout")
    ]

    if missing:
        return PolicyCheckResult(
            check_id="istio_virtualservice_timeout",
            name="Istio VirtualService Timeout",
            passed=False,
            severity="medium",
            message=(
                f"{len(missing)} HTTP route(s) have no timeout configured: "
                f"{', '.join(missing)}. Missing timeouts allow cascading failures."
            ),
            details={"routes_without_timeout": missing, "total_routes": len(http_routes)},
        )

    return PolicyCheckResult(
        check_id="istio_virtualservice_timeout",
        name="Istio VirtualService Timeout",
        passed=True,
        severity="medium",
        message=f"All {len(http_routes)} HTTP route(s) have timeout configured.",
    )


@policy_check(
    check_id="istio_virtualservice_retries",
    name="Istio VirtualService Retry Policy",
    severity="medium",
    category="istio-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.5"}),
    description="Routes without retry policies silently drop requests on transient errors instead of recovering.",
    remediation="Add spec.http[].retries with attempts and perTryTimeout to each HTTP route.",
)
def check_istio_virtualservice_retries(manifest: dict) -> PolicyCheckResult:
    """VirtualService HTTP routes should have a retry policy configured."""
    if manifest.get("kind") != _VIRTUAL_SERVICE:
        return PolicyCheckResult(
            check_id="istio_virtualservice_retries",
            name="Istio VirtualService Retry Policy",
            passed=True,
            severity="medium",
            message="Not a VirtualService, skipped.",
        )

    spec = manifest.get("spec", {})
    http_routes = spec.get("http", [])

    if not http_routes:
        return PolicyCheckResult(
            check_id="istio_virtualservice_retries",
            name="Istio VirtualService Retry Policy",
            passed=True,
            severity="medium",
            message="No HTTP routes defined, skipped.",
        )

    missing = [
        f"route[{i}]"
        for i, route in enumerate(http_routes)
        if not route.get("retries")
    ]

    if missing:
        return PolicyCheckResult(
            check_id="istio_virtualservice_retries",
            name="Istio VirtualService Retry Policy",
            passed=False,
            severity="medium",
            message=(
                f"{len(missing)} HTTP route(s) have no retry policy: "
                f"{', '.join(missing)}. Transient errors will not be automatically retried."
            ),
            details={"routes_without_retries": missing, "total_routes": len(http_routes)},
        )

    return PolicyCheckResult(
        check_id="istio_virtualservice_retries",
        name="Istio VirtualService Retry Policy",
        passed=True,
        severity="medium",
        message=f"All {len(http_routes)} HTTP route(s) have retry policy configured.",
    )


@policy_check(
    check_id="istio_virtualservice_fault_injection_production",
    name="Istio VirtualService Fault Injection in Production",
    severity="high",
    category="istio-reliability",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC7.2"}),
    description=(
        "Fault injection (delays or aborts) must not be active in production — "
        "it intentionally degrades traffic and will cause real user impact."
    ),
    remediation="Remove spec.http[].fault from all routes before deploying to production.",
)
def check_istio_virtualservice_fault_injection_production(manifest: dict) -> PolicyCheckResult:
    """Fault injection should not be configured on VirtualService routes in production."""
    if manifest.get("kind") != _VIRTUAL_SERVICE:
        return PolicyCheckResult(
            check_id="istio_virtualservice_fault_injection_production",
            name="Istio VirtualService Fault Injection in Production",
            passed=True,
            severity="high",
            message="Not a VirtualService, skipped.",
        )

    spec = manifest.get("spec", {})
    http_routes = spec.get("http", [])

    routes_with_fault = [
        f"route[{i}]"
        for i, route in enumerate(http_routes)
        if route.get("fault")
    ]

    if routes_with_fault:
        return PolicyCheckResult(
            check_id="istio_virtualservice_fault_injection_production",
            name="Istio VirtualService Fault Injection in Production",
            passed=False,
            severity="high",
            message=(
                f"Fault injection is configured on {len(routes_with_fault)} route(s): "
                f"{', '.join(routes_with_fault)}. This will intentionally degrade live traffic."
            ),
            details={"routes_with_fault": routes_with_fault},
        )

    return PolicyCheckResult(
        check_id="istio_virtualservice_fault_injection_production",
        name="Istio VirtualService Fault Injection in Production",
        passed=True,
        severity="high",
        message="No fault injection configured on any HTTP route.",
    )


# ---------------------------------------------------------------------------
# DestinationRule checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="istio_destination_rule_tls",
    name="Istio DestinationRule mTLS Mode",
    severity="high",
    category="istio-security",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.2.1", "SOC2-CC6.7", "NIST-SC-8"}),
    cis_benchmark="5.2.1",
    nsa_control="NIST-SC-8",
    description=(
        "DestinationRule trafficPolicy.tls.mode must be ISTIO_MUTUAL or MUTUAL to enforce "
        "encrypted, authenticated connections within the mesh. DISABLE or SIMPLE leaves traffic unencrypted."
    ),
    remediation=(
        "Set spec.trafficPolicy.tls.mode to ISTIO_MUTUAL (recommended for Istio-managed certs) "
        "or MUTUAL (for custom certificates)."
    ),
)
def check_istio_destination_rule_tls(manifest: dict) -> PolicyCheckResult:
    """DestinationRule must enforce mTLS via ISTIO_MUTUAL or MUTUAL mode."""
    if manifest.get("kind") != _DESTINATION_RULE:
        return PolicyCheckResult(
            check_id="istio_destination_rule_tls",
            name="Istio DestinationRule mTLS Mode",
            passed=True,
            severity="high",
            message="Not a DestinationRule, skipped.",
        )

    spec = manifest.get("spec", {})
    traffic_policy = spec.get("trafficPolicy", {})
    tls = traffic_policy.get("tls", {})
    mode = tls.get("mode")

    if not mode:
        return PolicyCheckResult(
            check_id="istio_destination_rule_tls",
            name="Istio DestinationRule mTLS Mode",
            passed=False,
            severity="high",
            message=(
                "DestinationRule has no trafficPolicy.tls.mode configured. "
                "Traffic to this destination is not encrypted."
            ),
            details={"tls_mode": None},
        )

    if mode not in _MTLS_ENFORCING_MODES:
        return PolicyCheckResult(
            check_id="istio_destination_rule_tls",
            name="Istio DestinationRule mTLS Mode",
            passed=False,
            severity="high",
            message=(
                f"DestinationRule tls.mode is '{mode}', which does not enforce mTLS. "
                f"Use ISTIO_MUTUAL or MUTUAL."
            ),
            details={"tls_mode": mode, "accepted_modes": sorted(_MTLS_ENFORCING_MODES)},
        )

    return PolicyCheckResult(
        check_id="istio_destination_rule_tls",
        name="Istio DestinationRule mTLS Mode",
        passed=True,
        severity="high",
        message=f"DestinationRule enforces mTLS with mode '{mode}'.",
    )


@policy_check(
    check_id="istio_destination_rule_outlier_detection",
    name="Istio DestinationRule Outlier Detection",
    severity="medium",
    category="istio-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.5"}),
    description=(
        "Outlier detection automatically ejects unhealthy hosts from the load balancing pool, "
        "preventing cascading failures. Without it, traffic continues routing to failing pods."
    ),
    remediation=(
        "Add spec.trafficPolicy.outlierDetection with consecutiveGatewayErrors and interval."
    ),
)
def check_istio_destination_rule_outlier_detection(manifest: dict) -> PolicyCheckResult:
    """DestinationRule should configure outlier detection for circuit-breaking."""
    if manifest.get("kind") != _DESTINATION_RULE:
        return PolicyCheckResult(
            check_id="istio_destination_rule_outlier_detection",
            name="Istio DestinationRule Outlier Detection",
            passed=True,
            severity="medium",
            message="Not a DestinationRule, skipped.",
        )

    spec = manifest.get("spec", {})
    traffic_policy = spec.get("trafficPolicy", {})
    outlier = traffic_policy.get("outlierDetection")

    if not outlier:
        return PolicyCheckResult(
            check_id="istio_destination_rule_outlier_detection",
            name="Istio DestinationRule Outlier Detection",
            passed=False,
            severity="medium",
            message=(
                "DestinationRule has no outlierDetection configured. "
                "Unhealthy hosts will not be automatically ejected from the load balancing pool."
            ),
            details={"outlierDetection": None},
        )

    return PolicyCheckResult(
        check_id="istio_destination_rule_outlier_detection",
        name="Istio DestinationRule Outlier Detection",
        passed=True,
        severity="medium",
        message="DestinationRule has outlier detection configured.",
    )


@policy_check(
    check_id="istio_destination_rule_connection_pool",
    name="Istio DestinationRule Connection Pool",
    severity="medium",
    category="istio-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.2"}),
    description=(
        "Without connection pool limits, a single misbehaving client can exhaust upstream "
        "connections and bring down the destination service."
    ),
    remediation=(
        "Add spec.trafficPolicy.connectionPool with tcp.maxConnections and "
        "http.http1MaxPendingRequests limits appropriate for the service."
    ),
)
def check_istio_destination_rule_connection_pool(manifest: dict) -> PolicyCheckResult:
    """DestinationRule should configure connection pool limits for production resilience."""
    if manifest.get("kind") != _DESTINATION_RULE:
        return PolicyCheckResult(
            check_id="istio_destination_rule_connection_pool",
            name="Istio DestinationRule Connection Pool",
            passed=True,
            severity="medium",
            message="Not a DestinationRule, skipped.",
        )

    spec = manifest.get("spec", {})
    traffic_policy = spec.get("trafficPolicy", {})
    connection_pool = traffic_policy.get("connectionPool")

    if not connection_pool:
        return PolicyCheckResult(
            check_id="istio_destination_rule_connection_pool",
            name="Istio DestinationRule Connection Pool",
            passed=False,
            severity="medium",
            message=(
                "DestinationRule has no connectionPool configured. "
                "Unbounded connections may cause resource exhaustion under load."
            ),
            details={"connectionPool": None},
        )

    return PolicyCheckResult(
        check_id="istio_destination_rule_connection_pool",
        name="Istio DestinationRule Connection Pool",
        passed=True,
        severity="medium",
        message="DestinationRule has connection pool limits configured.",
    )


# ---------------------------------------------------------------------------
# PeerAuthentication checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="istio_peer_auth_strict_mtls",
    name="Istio PeerAuthentication Strict mTLS",
    severity="critical",
    category="istio-security",
    risk_points=30,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.2.2", "SOC2-CC6.7", "NIST-SC-8"}),
    cis_benchmark="5.2.2",
    nsa_control="NIST-SC-8",
    description=(
        "PERMISSIVE mode accepts both plaintext and mTLS traffic, allowing unencrypted "
        "communication within the mesh. STRICT mode must be used in production to enforce "
        "mutual authentication for all pod-to-pod traffic."
    ),
    remediation="Set spec.mtls.mode to STRICT in all PeerAuthentication resources for production namespaces.",
)
def check_istio_peer_auth_strict_mtls(manifest: dict) -> PolicyCheckResult:
    """PeerAuthentication must use STRICT mTLS mode, not PERMISSIVE."""
    if manifest.get("kind") != _PEER_AUTHENTICATION:
        return PolicyCheckResult(
            check_id="istio_peer_auth_strict_mtls",
            name="Istio PeerAuthentication Strict mTLS",
            passed=True,
            severity="critical",
            message="Not a PeerAuthentication, skipped.",
        )

    spec = manifest.get("spec", {})
    mtls = spec.get("mtls", {})
    mode = mtls.get("mode")

    if not mode:
        # No explicit mode means Istio inherits from parent policy.
        # Flag as a risk since the effective mode is ambiguous.
        return PolicyCheckResult(
            check_id="istio_peer_auth_strict_mtls",
            name="Istio PeerAuthentication Strict mTLS",
            passed=False,
            severity="critical",
            message=(
                "PeerAuthentication has no spec.mtls.mode set. "
                "The effective mode is inherited and may be PERMISSIVE."
            ),
            details={"mtls_mode": None},
        )

    if mode != "STRICT":
        return PolicyCheckResult(
            check_id="istio_peer_auth_strict_mtls",
            name="Istio PeerAuthentication Strict mTLS",
            passed=False,
            severity="critical",
            message=(
                f"PeerAuthentication mtls.mode is '{mode}'. "
                "PERMISSIVE allows plaintext traffic within the mesh. Set to STRICT."
            ),
            details={"mtls_mode": mode},
        )

    return PolicyCheckResult(
        check_id="istio_peer_auth_strict_mtls",
        name="Istio PeerAuthentication Strict mTLS",
        passed=True,
        severity="critical",
        message="PeerAuthentication enforces STRICT mTLS.",
    )


# ---------------------------------------------------------------------------
# AuthorizationPolicy checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="istio_authz_no_allow_all",
    name="Istio AuthorizationPolicy Allow-All",
    severity="critical",
    category="istio-security",
    risk_points=30,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.2.4", "SOC2-CC6.1", "NIST-AC-3"}),
    cis_benchmark="5.2.4",
    nsa_control="NIST-AC-3",
    description=(
        "An AuthorizationPolicy with action ALLOW and no rules matches all requests, "
        "effectively disabling authorization checks for the targeted workload."
    ),
    remediation=(
        "Add explicit rules with source principals, namespaces, or request conditions. "
        "Never deploy ALLOW policies with an empty rules list in production."
    ),
)
def check_istio_authz_no_allow_all(manifest: dict) -> PolicyCheckResult:
    """AuthorizationPolicy must not use ALLOW with no rules (implicitly allows everything)."""
    if manifest.get("kind") != _AUTHORIZATION_POLICY:
        return PolicyCheckResult(
            check_id="istio_authz_no_allow_all",
            name="Istio AuthorizationPolicy Allow-All",
            passed=True,
            severity="critical",
            message="Not an AuthorizationPolicy, skipped.",
        )

    spec = manifest.get("spec", {})
    # action defaults to ALLOW when absent per the Istio API
    action = spec.get("action", "ALLOW")
    rules = spec.get("rules")

    if action == "ALLOW" and not rules:
        name = manifest.get("metadata", {}).get("name", "<unnamed>")
        return PolicyCheckResult(
            check_id="istio_authz_no_allow_all",
            name="Istio AuthorizationPolicy Allow-All",
            passed=False,
            severity="critical",
            message=(
                f"AuthorizationPolicy '{name}' has action ALLOW with no rules. "
                "This grants access to all sources without any restriction."
            ),
            details={"action": action, "rules": rules},
        )

    return PolicyCheckResult(
        check_id="istio_authz_no_allow_all",
        name="Istio AuthorizationPolicy Allow-All",
        passed=True,
        severity="critical",
        message=f"AuthorizationPolicy has action '{action}' with explicit rules.",
    )


# ---------------------------------------------------------------------------
# Gateway checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="istio_gateway_tls_required",
    name="Istio Gateway TLS Required",
    severity="high",
    category="istio-security",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.2.3", "SOC2-CC6.7", "NIST-SC-8"}),
    cis_benchmark="5.2.3",
    nsa_control="NIST-SC-8",
    description=(
        "Gateway servers without TLS configuration expose traffic over plaintext HTTP, "
        "allowing interception of data in transit between the client and the ingress gateway."
    ),
    remediation=(
        "Add spec.servers[].tls with mode SIMPLE (for edge TLS termination) or "
        "PASSTHROUGH (for end-to-end TLS) on each server entry."
    ),
)
def check_istio_gateway_tls_required(manifest: dict) -> PolicyCheckResult:
    """Gateway servers should have TLS configured with a non-empty mode."""
    if manifest.get("kind") != _GATEWAY:
        return PolicyCheckResult(
            check_id="istio_gateway_tls_required",
            name="Istio Gateway TLS Required",
            passed=True,
            severity="high",
            message="Not a Gateway, skipped.",
        )

    spec = manifest.get("spec", {})
    servers = spec.get("servers", [])

    if not servers:
        return PolicyCheckResult(
            check_id="istio_gateway_tls_required",
            name="Istio Gateway TLS Required",
            passed=True,
            severity="high",
            message="No servers defined in Gateway, skipped.",
        )

    violations = []
    for i, server in enumerate(servers):
        port = server.get("port", {})
        port_name = port.get("name") or port.get("number") or f"server[{i}]"
        tls = server.get("tls")
        if not tls or not tls.get("mode"):
            violations.append(str(port_name))

    if violations:
        return PolicyCheckResult(
            check_id="istio_gateway_tls_required",
            name="Istio Gateway TLS Required",
            passed=False,
            severity="high",
            message=(
                f"Gateway server(s) missing TLS configuration: {', '.join(violations)}. "
                "Traffic will be served over plaintext HTTP."
            ),
            details={"servers_without_tls": violations, "total_servers": len(servers)},
        )

    return PolicyCheckResult(
        check_id="istio_gateway_tls_required",
        name="Istio Gateway TLS Required",
        passed=True,
        severity="high",
        message=f"All {len(servers)} Gateway server(s) have TLS configured.",
    )


@policy_check(
    check_id="istio_gateway_wildcard_host",
    name="Istio Gateway Wildcard Host",
    severity="medium",
    category="istio-security",
    risk_points=15,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC6.6"}),
    description=(
        "A wildcard host ('*') in a Gateway server matches any incoming hostname, "
        "which can expose internal services to unintended external traffic in production."
    ),
    remediation=(
        "Replace wildcard hosts with explicit FQDNs (e.g. api.example.com) "
        "so only known hostnames are routed through the gateway."
    ),
)
def check_istio_gateway_wildcard_host(manifest: dict) -> PolicyCheckResult:
    """Gateway servers should not use bare wildcard hosts ('*') in production."""
    if manifest.get("kind") != _GATEWAY:
        return PolicyCheckResult(
            check_id="istio_gateway_wildcard_host",
            name="Istio Gateway Wildcard Host",
            passed=True,
            severity="medium",
            message="Not a Gateway, skipped.",
        )

    spec = manifest.get("spec", {})
    servers = spec.get("servers", [])

    wildcard_servers = []
    for i, server in enumerate(servers):
        hosts = server.get("hosts", [])
        if "*" in hosts:
            port = server.get("port", {})
            port_name = port.get("name") or port.get("number") or f"server[{i}]"
            wildcard_servers.append(str(port_name))

    if wildcard_servers:
        return PolicyCheckResult(
            check_id="istio_gateway_wildcard_host",
            name="Istio Gateway Wildcard Host",
            passed=False,
            severity="medium",
            message=(
                f"Gateway server(s) use wildcard host '*': {', '.join(wildcard_servers)}. "
                "Use explicit FQDNs to restrict ingress to known hostnames."
            ),
            details={"wildcard_servers": wildcard_servers},
        )

    return PolicyCheckResult(
        check_id="istio_gateway_wildcard_host",
        name="Istio Gateway Wildcard Host",
        passed=True,
        severity="medium",
        message="No Gateway servers use bare wildcard hosts.",
    )
