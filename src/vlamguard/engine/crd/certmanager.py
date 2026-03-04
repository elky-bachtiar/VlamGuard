"""cert-manager CRD policy checks.

Covers Certificate, ClusterIssuer, and Issuer resources from cert-manager.io/v1.
Checks enforce certificate lifecycle hygiene, key strength, and ACME solver
configuration to prevent silent renewal failures and weak cryptography in production.
"""

from vlamguard.engine.registry import policy_check
from vlamguard.models.response import PolicyCheckResult

# cert-manager resource kinds
_CERT = "Certificate"
_CLUSTER_ISSUER = "ClusterIssuer"
_ISSUER = "Issuer"

# ACME staging/pebble server substrings (not to be used in production)
_STAGING_MARKERS = ("staging", "pebble")

# Acceptable ECDSA key sizes for certmgr_certificate_private_key_algorithm
_ECDSA_VALID_SIZES = {"P256", "P384"}


# ---------------------------------------------------------------------------
# Certificate checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="certmgr_certificate_duration",
    name="cert-manager Certificate Duration",
    severity="medium",
    category="certmgr-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC7.2"}),
    description=(
        "Certificates without an explicit duration use cert-manager's default (90 days). "
        "Setting duration explicitly prevents silent expiry surprises when the default changes."
    ),
    remediation="Set spec.duration (e.g. '8760h' for 1 year) on all Certificate resources.",
)
def check_certmgr_certificate_duration(manifest: dict) -> PolicyCheckResult:
    """Certificate should have an explicit spec.duration."""
    if manifest.get("kind") != _CERT:
        return PolicyCheckResult(
            check_id="certmgr_certificate_duration",
            name="cert-manager Certificate Duration",
            passed=True,
            severity="medium",
            message="Not a Certificate, skipped.",
        )

    spec = manifest.get("spec", {})
    duration = spec.get("duration")

    if not duration:
        name = manifest.get("metadata", {}).get("name", "<unknown>")
        return PolicyCheckResult(
            check_id="certmgr_certificate_duration",
            name="cert-manager Certificate Duration",
            passed=False,
            severity="medium",
            message=(
                f"Certificate '{name}' has no spec.duration. "
                "The cert-manager default (90d) will be used, which may not match your rotation policy."
            ),
            details={"duration": None, "recommended": "8760h"},
        )

    return PolicyCheckResult(
        check_id="certmgr_certificate_duration",
        name="cert-manager Certificate Duration",
        passed=True,
        severity="medium",
        message=f"Certificate duration is explicitly set to '{duration}'.",
    )


@policy_check(
    check_id="certmgr_certificate_renew_before",
    name="cert-manager Certificate RenewBefore",
    severity="medium",
    category="certmgr-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC7.2"}),
    description=(
        "renewBefore determines how early cert-manager starts renewal attempts. "
        "Without it, the cert-manager default (1/3 of duration) may leave too small a renewal window."
    ),
    remediation="Set spec.renewBefore to at least '720h' (30 days before expiry).",
)
def check_certmgr_certificate_renew_before(manifest: dict) -> PolicyCheckResult:
    """Certificate should have an explicit spec.renewBefore."""
    if manifest.get("kind") != _CERT:
        return PolicyCheckResult(
            check_id="certmgr_certificate_renew_before",
            name="cert-manager Certificate RenewBefore",
            passed=True,
            severity="medium",
            message="Not a Certificate, skipped.",
        )

    spec = manifest.get("spec", {})
    renew_before = spec.get("renewBefore")

    if not renew_before:
        name = manifest.get("metadata", {}).get("name", "<unknown>")
        return PolicyCheckResult(
            check_id="certmgr_certificate_renew_before",
            name="cert-manager Certificate RenewBefore",
            passed=False,
            severity="medium",
            message=(
                f"Certificate '{name}' has no spec.renewBefore. "
                "cert-manager defaults to 1/3 of the certificate duration, "
                "which may not provide enough lead time for renewal alerts."
            ),
            details={"renewBefore": None, "recommended": "720h"},
        )

    return PolicyCheckResult(
        check_id="certmgr_certificate_renew_before",
        name="cert-manager Certificate RenewBefore",
        passed=True,
        severity="medium",
        message=f"Certificate renewBefore is explicitly set to '{renew_before}'.",
    )


@policy_check(
    check_id="certmgr_certificate_private_key_algorithm",
    name="cert-manager Certificate Private Key Algorithm",
    severity="high",
    category="certmgr-security",
    risk_points=15,
    prod_behavior="soft_risk",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.4.1", "SOC2-CC6.1"}),
    cis_benchmark="5.4.1",
    description=(
        "Private keys should use RSA 4096 or ECDSA P-256/P-384. "
        "RSA-2048 is still acceptable but approaching end-of-life for long-lived certs."
    ),
    remediation=(
        "Set spec.privateKey.algorithm to 'RSA' with spec.privateKey.size >= 4096, "
        "or set algorithm to 'ECDSA' with spec.privateKey.size 'P256' or 'P384'."
    ),
)
def check_certmgr_certificate_private_key_algorithm(manifest: dict) -> PolicyCheckResult:
    """Certificate private key should use RSA >= 4096 or ECDSA P256/P384."""
    if manifest.get("kind") != _CERT:
        return PolicyCheckResult(
            check_id="certmgr_certificate_private_key_algorithm",
            name="cert-manager Certificate Private Key Algorithm",
            passed=True,
            severity="high",
            message="Not a Certificate, skipped.",
        )

    spec = manifest.get("spec", {})
    private_key = spec.get("privateKey", {})
    name = manifest.get("metadata", {}).get("name", "<unknown>")

    if not private_key:
        return PolicyCheckResult(
            check_id="certmgr_certificate_private_key_algorithm",
            name="cert-manager Certificate Private Key Algorithm",
            passed=False,
            severity="high",
            message=(
                f"Certificate '{name}' has no spec.privateKey configuration. "
                "cert-manager defaults to RSA-2048, which is below the recommended strength."
            ),
            details={"privateKey": None, "recommended_algorithm": "RSA", "recommended_size": 4096},
        )

    algorithm = private_key.get("algorithm", "RSA")
    size = private_key.get("size")

    if algorithm == "RSA":
        if size is None:
            # Default RSA is 2048 — flag it
            return PolicyCheckResult(
                check_id="certmgr_certificate_private_key_algorithm",
                name="cert-manager Certificate Private Key Algorithm",
                passed=False,
                severity="high",
                message=(
                    f"Certificate '{name}' uses RSA without explicit size (defaults to 2048). "
                    "Set spec.privateKey.size to 4096 for stronger security."
                ),
                details={"algorithm": "RSA", "size": None, "recommended_size": 4096},
            )
        if int(size) < 4096:
            return PolicyCheckResult(
                check_id="certmgr_certificate_private_key_algorithm",
                name="cert-manager Certificate Private Key Algorithm",
                passed=False,
                severity="high",
                message=(
                    f"Certificate '{name}' uses RSA-{size}, which is below the recommended 4096 bits."
                ),
                details={"algorithm": "RSA", "size": size, "recommended_size": 4096},
            )
        return PolicyCheckResult(
            check_id="certmgr_certificate_private_key_algorithm",
            name="cert-manager Certificate Private Key Algorithm",
            passed=True,
            severity="high",
            message=f"Certificate '{name}' uses RSA-{size}.",
        )

    if algorithm == "ECDSA":
        # size is a string like "P256" or "P384" for ECDSA
        size_str = str(size) if size else ""
        if size_str not in _ECDSA_VALID_SIZES:
            return PolicyCheckResult(
                check_id="certmgr_certificate_private_key_algorithm",
                name="cert-manager Certificate Private Key Algorithm",
                passed=False,
                severity="high",
                message=(
                    f"Certificate '{name}' uses ECDSA with size '{size_str or 'unset'}'. "
                    f"Accepted sizes: {', '.join(sorted(_ECDSA_VALID_SIZES))}."
                ),
                details={
                    "algorithm": "ECDSA",
                    "size": size_str or None,
                    "accepted_sizes": sorted(_ECDSA_VALID_SIZES),
                },
            )
        return PolicyCheckResult(
            check_id="certmgr_certificate_private_key_algorithm",
            name="cert-manager Certificate Private Key Algorithm",
            passed=True,
            severity="high",
            message=f"Certificate '{name}' uses ECDSA {size_str}.",
        )

    # Unknown algorithm (e.g. Ed25519 — acceptable but flag for awareness)
    return PolicyCheckResult(
        check_id="certmgr_certificate_private_key_algorithm",
        name="cert-manager Certificate Private Key Algorithm",
        passed=True,
        severity="high",
        message=f"Certificate '{name}' uses algorithm '{algorithm}'. Verify it meets your security policy.",
    )


@policy_check(
    check_id="certmgr_certificate_wildcard_production",
    name="cert-manager Wildcard Certificate in Production",
    severity="medium",
    category="certmgr-security",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC6.1"}),
    description=(
        "Wildcard certificates cover all subdomains, increasing blast radius if the private key "
        "is compromised. In production, prefer per-service certificates."
    ),
    remediation=(
        "Replace wildcard dnsNames (*.example.com) with specific hostnames per service, "
        "or document an approved exception for this wildcard."
    ),
)
def check_certmgr_certificate_wildcard_production(manifest: dict) -> PolicyCheckResult:
    """Certificates with wildcard dnsNames should be reviewed."""
    if manifest.get("kind") != _CERT:
        return PolicyCheckResult(
            check_id="certmgr_certificate_wildcard_production",
            name="cert-manager Wildcard Certificate in Production",
            passed=True,
            severity="medium",
            message="Not a Certificate, skipped.",
        )

    spec = manifest.get("spec", {})
    dns_names = spec.get("dnsNames", [])
    name = manifest.get("metadata", {}).get("name", "<unknown>")

    wildcards = [d for d in dns_names if isinstance(d, str) and d.startswith("*.")]

    if wildcards:
        return PolicyCheckResult(
            check_id="certmgr_certificate_wildcard_production",
            name="cert-manager Wildcard Certificate in Production",
            passed=False,
            severity="medium",
            message=(
                f"Certificate '{name}' contains {len(wildcards)} wildcard dnsName(s): "
                f"{', '.join(wildcards)}. Wildcard certs increase blast radius if the key is compromised."
            ),
            details={"wildcard_dns_names": wildcards},
        )

    return PolicyCheckResult(
        check_id="certmgr_certificate_wildcard_production",
        name="cert-manager Wildcard Certificate in Production",
        passed=True,
        severity="medium",
        message=f"Certificate '{name}' uses no wildcard dnsNames.",
    )


# ---------------------------------------------------------------------------
# Issuer / ClusterIssuer checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="certmgr_issuer_solver_configured",
    name="cert-manager Issuer ACME Solver",
    severity="high",
    category="certmgr-reliability",
    risk_points=20,
    prod_behavior="soft_risk",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC7.2"}),
    description=(
        "An ACME Issuer without solvers configured will fail all certificate requests. "
        "At least one HTTP-01 or DNS-01 solver must be present."
    ),
    remediation=(
        "Add at least one entry under spec.acme.solvers with an http01 or dns01 configuration."
    ),
)
def check_certmgr_issuer_solver_configured(manifest: dict) -> PolicyCheckResult:
    """ClusterIssuer/Issuer with ACME must have at least one solver."""
    kind = manifest.get("kind")
    if kind not in (_CLUSTER_ISSUER, _ISSUER):
        return PolicyCheckResult(
            check_id="certmgr_issuer_solver_configured",
            name="cert-manager Issuer ACME Solver",
            passed=True,
            severity="high",
            message="Not a ClusterIssuer or Issuer, skipped.",
        )

    spec = manifest.get("spec", {})
    acme = spec.get("acme")

    if not acme:
        # Not an ACME issuer (may be CA, Vault, etc.) — not applicable
        return PolicyCheckResult(
            check_id="certmgr_issuer_solver_configured",
            name="cert-manager Issuer ACME Solver",
            passed=True,
            severity="high",
            message=f"{kind} does not use ACME, skipped.",
        )

    solvers = acme.get("solvers", [])
    name = manifest.get("metadata", {}).get("name", "<unknown>")

    if not solvers:
        return PolicyCheckResult(
            check_id="certmgr_issuer_solver_configured",
            name="cert-manager Issuer ACME Solver",
            passed=False,
            severity="high",
            message=(
                f"{kind} '{name}' has spec.acme but no solvers configured. "
                "All certificate requests through this issuer will fail."
            ),
            details={"solvers": [], "acme_server": acme.get("server")},
        )

    return PolicyCheckResult(
        check_id="certmgr_issuer_solver_configured",
        name="cert-manager Issuer ACME Solver",
        passed=True,
        severity="high",
        message=f"{kind} '{name}' has {len(solvers)} ACME solver(s) configured.",
    )


@policy_check(
    check_id="certmgr_issuer_staging_in_production",
    name="cert-manager ACME Staging Server",
    severity="high",
    category="certmgr-security",
    risk_points=20,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"SOC2-CC6.1"}),
    description=(
        "The Let's Encrypt staging server and Pebble issue untrusted certificates. "
        "Deploying with a staging server in production causes TLS verification failures for all clients."
    ),
    remediation=(
        "Change spec.acme.server to 'https://acme-v02.api.letsencrypt.org/directory' "
        "or another trusted ACME endpoint."
    ),
)
def check_certmgr_issuer_staging_in_production(manifest: dict) -> PolicyCheckResult:
    """ClusterIssuer/Issuer must not use an ACME staging or Pebble server."""
    kind = manifest.get("kind")
    if kind not in (_CLUSTER_ISSUER, _ISSUER):
        return PolicyCheckResult(
            check_id="certmgr_issuer_staging_in_production",
            name="cert-manager ACME Staging Server",
            passed=True,
            severity="high",
            message="Not a ClusterIssuer or Issuer, skipped.",
        )

    spec = manifest.get("spec", {})
    acme = spec.get("acme")

    if not acme:
        return PolicyCheckResult(
            check_id="certmgr_issuer_staging_in_production",
            name="cert-manager ACME Staging Server",
            passed=True,
            severity="high",
            message=f"{kind} does not use ACME, skipped.",
        )

    server = acme.get("server", "")
    name = manifest.get("metadata", {}).get("name", "<unknown>")

    matched_markers = [m for m in _STAGING_MARKERS if m in server.lower()]

    if matched_markers:
        return PolicyCheckResult(
            check_id="certmgr_issuer_staging_in_production",
            name="cert-manager ACME Staging Server",
            passed=False,
            severity="high",
            message=(
                f"{kind} '{name}' uses ACME server '{server}', which is a staging/test endpoint. "
                "Certificates issued will not be trusted by browsers or standard TLS clients."
            ),
            details={"acme_server": server, "matched_markers": matched_markers},
        )

    return PolicyCheckResult(
        check_id="certmgr_issuer_staging_in_production",
        name="cert-manager ACME Staging Server",
        passed=True,
        severity="high",
        message=f"{kind} '{name}' uses production ACME server '{server}'.",
    )
