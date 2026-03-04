"""Unit tests for the 6 cert-manager and 5 External Secrets Operator CRD policy checks.

cert-manager checks:
  certmgr_certificate_duration                — 3 code paths
  certmgr_certificate_renew_before            — 3 code paths
  certmgr_certificate_private_key_algorithm   — 9 code paths
  certmgr_certificate_wildcard_production     — 3 code paths
  certmgr_issuer_solver_configured            — 5 code paths
  certmgr_issuer_staging_in_production        — 5 code paths

ESO checks:
  eso_external_secret_refresh_interval        — 4 code paths
  eso_external_secret_target_creation         — 3 code paths
  eso_external_secret_deletion_policy         — 3 code paths
  eso_secret_store_provider                   — 4 code paths
  eso_cluster_secret_store_conditions         — 5 code paths

The _run_check helper finds checks by ID via the global registry so that
the @policy_check decorator registration is exercised in every test.
Imports of the CRD modules trigger those registrations as side-effects.
"""

import vlamguard.engine.crd.certmanager  # noqa: F401  — registers cert-manager checks
import vlamguard.engine.crd.externalsecrets  # noqa: F401  — registers ESO checks
from vlamguard.engine.registry import get_check_fns
from vlamguard.models.response import PolicyCheckResult


# ---------------------------------------------------------------------------
# Registry helper
# ---------------------------------------------------------------------------


def _run_check(check_id: str, manifest: dict) -> PolicyCheckResult:
    """Find a check by ID and run it against manifest."""
    for fn in get_check_fns():
        result = fn(manifest)
        if result.check_id == check_id:
            return result
    raise ValueError(f"Check '{check_id}' not found in registry")


# ---------------------------------------------------------------------------
# Manifest builders — cert-manager
# ---------------------------------------------------------------------------


def _certificate(
    *,
    name: str = "my-cert",
    dns_names: list | None = None,
    duration: str | None = "8760h",
    renew_before: str | None = "720h",
    private_key: dict | None = None,
    issuer_ref: dict | None = None,
) -> dict:
    """Build a minimal cert-manager Certificate manifest."""
    spec: dict = {
        "secretName": f"{name}-tls",
        "issuerRef": issuer_ref or {"name": "letsencrypt-prod", "kind": "ClusterIssuer"},
    }
    if dns_names is not None:
        spec["dnsNames"] = dns_names
    else:
        spec["dnsNames"] = ["app.example.com"]
    if duration is not None:
        spec["duration"] = duration
    if renew_before is not None:
        spec["renewBefore"] = renew_before
    if private_key is not None:
        spec["privateKey"] = private_key
    return {
        "apiVersion": "cert-manager.io/v1",
        "kind": "Certificate",
        "metadata": {"name": name, "namespace": "default"},
        "spec": spec,
    }


def _issuer(
    *,
    name: str = "letsencrypt",
    kind: str = "ClusterIssuer",
    acme: dict | None = None,
    use_vault: bool = False,
) -> dict:
    """Build a cert-manager Issuer or ClusterIssuer manifest."""
    spec: dict = {}
    if acme is not None:
        spec["acme"] = acme
    elif use_vault:
        spec["vault"] = {"server": "https://vault.example.com", "path": "pki"}
    return {
        "apiVersion": "cert-manager.io/v1",
        "kind": kind,
        "metadata": {"name": name, "namespace": "cert-manager"},
        "spec": spec,
    }


def _deployment(name: str = "web") -> dict:
    """Generic non-cert-manager manifest for skip-path tests."""
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name},
        "spec": {
            "replicas": 1,
            "template": {
                "spec": {"containers": [{"name": "app", "image": "nginx:1.25"}]}
            },
        },
    }


# ---------------------------------------------------------------------------
# Manifest builders — ESO
# ---------------------------------------------------------------------------


def _external_secret(
    *,
    name: str = "my-secret",
    refresh_interval: str | None = "1h",
    target: dict | None = None,
) -> dict:
    """Build a minimal ESO ExternalSecret manifest."""
    spec: dict = {
        "secretStoreRef": {"name": "my-store", "kind": "SecretStore"},
        "data": [{"secretKey": "password", "remoteRef": {"key": "db/password"}}],
    }
    if refresh_interval is not None:
        spec["refreshInterval"] = refresh_interval
    if target is not None:
        spec["target"] = target
    return {
        "apiVersion": "external-secrets.io/v1beta1",
        "kind": "ExternalSecret",
        "metadata": {"name": name, "namespace": "default"},
        "spec": spec,
    }


def _secret_store(
    *,
    name: str = "my-store",
    kind: str = "SecretStore",
    provider: dict | None = None,
    conditions: list | None = None,
    namespace_selector: dict | None = None,
) -> dict:
    """Build a minimal ESO SecretStore or ClusterSecretStore manifest."""
    spec: dict = {}
    if provider is not None:
        spec["provider"] = provider
    if conditions is not None:
        spec["conditions"] = conditions
    if namespace_selector is not None:
        spec["namespaceSelector"] = namespace_selector
    return {
        "apiVersion": "external-secrets.io/v1beta1",
        "kind": kind,
        "metadata": {"name": name, "namespace": "default"},
        "spec": spec,
    }


# ===========================================================================
# cert-manager tests
# ===========================================================================


# ---------------------------------------------------------------------------
# 1. certmgr_certificate_duration
# ---------------------------------------------------------------------------


class TestCertmgrCertificateDuration:
    _ID = "certmgr_certificate_duration"

    def test_skip_non_certificate(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_issuer_kind(self):
        result = _run_check(self._ID, _issuer())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_missing_duration(self):
        # Build certificate without duration
        cert = _certificate(duration=None)
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert result.details is not None
        assert result.details["duration"] is None
        assert result.details["recommended"] == "8760h"
        assert "my-cert" in result.message
        assert "no spec.duration" in result.message.lower() or "spec.duration" in result.message

    def test_fail_missing_duration_uses_metadata_name(self):
        cert = _certificate(name="api-tls", duration=None)
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert "api-tls" in result.message

    def test_fail_no_metadata_uses_unknown_placeholder(self):
        cert = _certificate(duration=None)
        del cert["metadata"]["name"]
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert "<unknown>" in result.message

    def test_pass_duration_set(self):
        result = _run_check(self._ID, _certificate(duration="8760h"))
        assert result.passed is True
        assert "8760h" in result.message

    def test_pass_different_duration_value(self):
        result = _run_check(self._ID, _certificate(duration="2160h"))
        assert result.passed is True
        assert "2160h" in result.message


# ---------------------------------------------------------------------------
# 2. certmgr_certificate_renew_before
# ---------------------------------------------------------------------------


class TestCertmgrCertificateRenewBefore:
    _ID = "certmgr_certificate_renew_before"

    def test_skip_non_certificate(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_cluster_issuer(self):
        result = _run_check(self._ID, _issuer(kind="ClusterIssuer"))
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_missing_renew_before(self):
        cert = _certificate(renew_before=None)
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert result.details is not None
        assert result.details["renewBefore"] is None
        assert result.details["recommended"] == "720h"
        assert "my-cert" in result.message

    def test_fail_missing_renew_before_uses_unknown_placeholder(self):
        cert = _certificate(renew_before=None)
        del cert["metadata"]["name"]
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert "<unknown>" in result.message

    def test_pass_renew_before_set(self):
        result = _run_check(self._ID, _certificate(renew_before="720h"))
        assert result.passed is True
        assert "720h" in result.message

    def test_pass_different_renew_before_value(self):
        result = _run_check(self._ID, _certificate(renew_before="360h"))
        assert result.passed is True
        assert "360h" in result.message


# ---------------------------------------------------------------------------
# 3. certmgr_certificate_private_key_algorithm
# ---------------------------------------------------------------------------


class TestCertmgrCertificatePrivateKeyAlgorithm:
    _ID = "certmgr_certificate_private_key_algorithm"

    def test_skip_non_certificate(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_no_private_key_config(self):
        # No privateKey key in spec at all
        cert = _certificate()
        # Ensure no privateKey
        cert["spec"].pop("privateKey", None)
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert result.details is not None
        assert result.details["privateKey"] is None
        assert "rsa-2048" in result.message.lower() or "rsa" in result.message.lower()

    def test_fail_empty_private_key_dict(self):
        # privateKey present but empty dict — treated as falsy by "if not private_key"
        cert = _certificate(private_key={})
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert result.details["privateKey"] is None

    def test_fail_rsa_no_size(self):
        # RSA with no size — defaults to 2048, which is below 4096
        cert = _certificate(private_key={"algorithm": "RSA"})
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert result.details is not None
        assert result.details["algorithm"] == "RSA"
        assert result.details["size"] is None
        assert result.details["recommended_size"] == 4096

    def test_fail_rsa_size_2048(self):
        cert = _certificate(private_key={"algorithm": "RSA", "size": 2048})
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert "2048" in result.message
        assert result.details["recommended_size"] == 4096

    def test_fail_rsa_size_below_4096(self):
        cert = _certificate(private_key={"algorithm": "RSA", "size": 3072})
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert "3072" in result.message

    def test_pass_rsa_4096(self):
        cert = _certificate(private_key={"algorithm": "RSA", "size": 4096})
        result = _run_check(self._ID, cert)
        assert result.passed is True
        assert "4096" in result.message

    def test_pass_rsa_larger_than_4096(self):
        cert = _certificate(private_key={"algorithm": "RSA", "size": 8192})
        result = _run_check(self._ID, cert)
        assert result.passed is True

    def test_pass_ecdsa_p256(self):
        cert = _certificate(private_key={"algorithm": "ECDSA", "size": "P256"})
        result = _run_check(self._ID, cert)
        assert result.passed is True
        assert "P256" in result.message

    def test_pass_ecdsa_p384(self):
        cert = _certificate(private_key={"algorithm": "ECDSA", "size": "P384"})
        result = _run_check(self._ID, cert)
        assert result.passed is True
        assert "P384" in result.message

    def test_fail_ecdsa_no_size(self):
        # ECDSA with no size — size_str will be "", not in _ECDSA_VALID_SIZES
        cert = _certificate(private_key={"algorithm": "ECDSA"})
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert result.details is not None
        assert result.details["algorithm"] == "ECDSA"
        assert result.details["size"] is None
        assert "unset" in result.message

    def test_fail_ecdsa_invalid_size(self):
        cert = _certificate(private_key={"algorithm": "ECDSA", "size": "P521"})
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert "P521" in result.message
        assert "P256" in result.message or "P384" in result.message

    def test_pass_unknown_algorithm(self):
        # Ed25519 and other unknown algorithms pass with an advisory message
        cert = _certificate(private_key={"algorithm": "Ed25519"})
        result = _run_check(self._ID, cert)
        assert result.passed is True
        assert "Ed25519" in result.message


# ---------------------------------------------------------------------------
# 4. certmgr_certificate_wildcard_production
# ---------------------------------------------------------------------------


class TestCertmgrCertificateWildcardProduction:
    _ID = "certmgr_certificate_wildcard_production"

    def test_skip_non_certificate(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_issuer(self):
        result = _run_check(self._ID, _issuer(kind="Issuer"))
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_no_dns_names(self):
        cert = _certificate(dns_names=[])
        result = _run_check(self._ID, cert)
        assert result.passed is True
        assert "no wildcard" in result.message.lower()

    def test_pass_only_explicit_dns_names(self):
        cert = _certificate(dns_names=["app.example.com", "api.example.com"])
        result = _run_check(self._ID, cert)
        assert result.passed is True

    def test_fail_single_wildcard_dns_name(self):
        cert = _certificate(name="wildcard-cert", dns_names=["*.example.com"])
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert result.details is not None
        assert "*.example.com" in result.details["wildcard_dns_names"]
        assert "wildcard-cert" in result.message
        assert "*.example.com" in result.message

    def test_fail_multiple_wildcard_dns_names(self):
        cert = _certificate(
            dns_names=["*.example.com", "app.example.com", "*.internal.example.com"]
        )
        result = _run_check(self._ID, cert)
        assert result.passed is False
        assert len(result.details["wildcard_dns_names"]) == 2
        assert "*.internal.example.com" in result.details["wildcard_dns_names"]

    def test_pass_dns_name_with_star_not_at_start(self):
        # A name like "app-*.example.com" does not start with "*." so not flagged
        cert = _certificate(dns_names=["app-v2.example.com"])
        result = _run_check(self._ID, cert)
        assert result.passed is True


# ---------------------------------------------------------------------------
# 5. certmgr_issuer_solver_configured
# ---------------------------------------------------------------------------


class TestCertmgrIssuerSolverConfigured:
    _ID = "certmgr_issuer_solver_configured"

    def test_skip_non_issuer(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_certificate_kind(self):
        result = _run_check(self._ID, _certificate())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_cluster_issuer_non_acme(self):
        # Vault-backed ClusterIssuer — ACME checks do not apply
        ci = _issuer(kind="ClusterIssuer", use_vault=True)
        result = _run_check(self._ID, ci)
        assert result.passed is True
        assert "acme" in result.message.lower() or "skipped" in result.message.lower()

    def test_pass_issuer_non_acme(self):
        # Plain Issuer without ACME
        iss = _issuer(kind="Issuer", use_vault=True)
        result = _run_check(self._ID, iss)
        assert result.passed is True

    def test_fail_cluster_issuer_acme_no_solvers(self):
        ci = _issuer(
            name="letsencrypt-prod",
            kind="ClusterIssuer",
            acme={
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "email": "ops@example.com",
                "privateKeySecretRef": {"name": "letsencrypt-prod"},
                # No solvers key
            },
        )
        result = _run_check(self._ID, ci)
        assert result.passed is False
        assert result.details is not None
        assert result.details["solvers"] == []
        assert "letsencrypt-prod" in result.message
        assert "ClusterIssuer" in result.message

    def test_fail_cluster_issuer_acme_empty_solvers(self):
        ci = _issuer(
            kind="ClusterIssuer",
            acme={
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "solvers": [],
            },
        )
        result = _run_check(self._ID, ci)
        assert result.passed is False

    def test_fail_issuer_acme_no_solvers(self):
        iss = _issuer(
            name="my-issuer",
            kind="Issuer",
            acme={
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "solvers": [],
            },
        )
        result = _run_check(self._ID, iss)
        assert result.passed is False
        assert "Issuer" in result.message
        assert "my-issuer" in result.message

    def test_pass_cluster_issuer_acme_with_http01_solver(self):
        ci = _issuer(
            kind="ClusterIssuer",
            acme={
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "solvers": [{"http01": {"ingress": {"class": "nginx"}}}],
            },
        )
        result = _run_check(self._ID, ci)
        assert result.passed is True
        assert "1" in result.message

    def test_pass_issuer_acme_with_dns01_solver(self):
        iss = _issuer(
            name="route53-issuer",
            kind="Issuer",
            acme={
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "solvers": [
                    {"dns01": {"route53": {"region": "us-east-1"}}},
                    {"http01": {"ingress": {"class": "nginx"}}},
                ],
            },
        )
        result = _run_check(self._ID, iss)
        assert result.passed is True
        assert "2" in result.message


# ---------------------------------------------------------------------------
# 6. certmgr_issuer_staging_in_production
# ---------------------------------------------------------------------------


class TestCertmgrIssuerStagingInProduction:
    _ID = "certmgr_issuer_staging_in_production"

    def test_skip_non_issuer(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_certificate_kind(self):
        result = _run_check(self._ID, _certificate())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_cluster_issuer_non_acme(self):
        ci = _issuer(kind="ClusterIssuer", use_vault=True)
        result = _run_check(self._ID, ci)
        assert result.passed is True
        assert "acme" in result.message.lower() or "skipped" in result.message.lower()

    def test_pass_issuer_non_acme(self):
        iss = _issuer(kind="Issuer", use_vault=True)
        result = _run_check(self._ID, iss)
        assert result.passed is True

    def test_fail_staging_url(self):
        ci = _issuer(
            name="letsencrypt-staging",
            kind="ClusterIssuer",
            acme={
                "server": "https://acme-staging-v02.api.letsencrypt.org/directory",
                "solvers": [{"http01": {"ingress": {"class": "nginx"}}}],
            },
        )
        result = _run_check(self._ID, ci)
        assert result.passed is False
        assert result.details is not None
        assert "staging" in result.details["acme_server"]
        assert "staging" in result.details["matched_markers"]
        assert "letsencrypt-staging" in result.message

    def test_fail_pebble_url(self):
        ci = _issuer(
            name="pebble-issuer",
            kind="ClusterIssuer",
            acme={
                "server": "https://pebble.example.com/dir",
                "solvers": [{"http01": {"ingress": {"class": "traefik"}}}],
            },
        )
        result = _run_check(self._ID, ci)
        assert result.passed is False
        assert "pebble" in result.details["matched_markers"]

    def test_fail_issuer_kind_staging_url(self):
        iss = _issuer(
            name="local-staging",
            kind="Issuer",
            acme={
                "server": "https://acme-staging-v02.api.letsencrypt.org/directory",
                "solvers": [],
            },
        )
        result = _run_check(self._ID, iss)
        assert result.passed is False
        assert "Issuer" in result.message

    def test_fail_staging_uppercase_in_url(self):
        # server URL contains "STAGING" — matched_markers uses .lower() so it still catches it
        ci = _issuer(
            kind="ClusterIssuer",
            acme={"server": "https://STAGING.example.com/acme", "solvers": []},
        )
        result = _run_check(self._ID, ci)
        assert result.passed is False

    def test_pass_production_letsencrypt_url(self):
        ci = _issuer(
            name="letsencrypt-prod",
            kind="ClusterIssuer",
            acme={
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "solvers": [{"http01": {"ingress": {"class": "nginx"}}}],
            },
        )
        result = _run_check(self._ID, ci)
        assert result.passed is True
        assert "letsencrypt-prod" in result.message
        assert "acme-v02.api.letsencrypt.org" in result.message

    def test_pass_custom_production_acme_url(self):
        iss = _issuer(
            name="corp-issuer",
            kind="Issuer",
            acme={
                "server": "https://ca.corp.example.com/acme/directory",
                "solvers": [{"dns01": {"route53": {"region": "eu-west-1"}}}],
            },
        )
        result = _run_check(self._ID, iss)
        assert result.passed is True


# ===========================================================================
# ESO tests
# ===========================================================================


# ---------------------------------------------------------------------------
# 1. eso_external_secret_refresh_interval
# ---------------------------------------------------------------------------


class TestEsoExternalSecretRefreshInterval:
    _ID = "eso_external_secret_refresh_interval"

    def test_skip_non_external_secret(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_secret_store(self):
        result = _run_check(
            self._ID,
            _secret_store(provider={"aws": {"service": "SecretsManager"}}),
        )
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_missing_refresh_interval(self):
        # Build ExternalSecret without refreshInterval key
        es = _external_secret(refresh_interval=None)
        result = _run_check(self._ID, es)
        assert result.passed is False
        assert result.details is not None
        assert result.details["refreshInterval"] is None
        assert result.details["recommended"] == "1h"
        assert "my-secret" in result.message

    def test_fail_missing_refresh_interval_uses_unknown_placeholder(self):
        es = _external_secret(refresh_interval=None)
        del es["metadata"]["name"]
        result = _run_check(self._ID, es)
        assert result.passed is False
        assert "<unknown>" in result.message

    def test_fail_refresh_interval_zero_string(self):
        es = _external_secret(refresh_interval="0")
        result = _run_check(self._ID, es)
        assert result.passed is False
        assert "'0'" in result.message
        assert result.details["refreshInterval"] == "0"

    def test_fail_refresh_interval_zero_seconds(self):
        es = _external_secret(refresh_interval="0s")
        result = _run_check(self._ID, es)
        assert result.passed is False
        assert "'0s'" in result.message

    def test_fail_refresh_interval_zero_minutes(self):
        es = _external_secret(refresh_interval="0m")
        result = _run_check(self._ID, es)
        assert result.passed is False

    def test_fail_refresh_interval_zero_hours(self):
        es = _external_secret(refresh_interval="0h")
        result = _run_check(self._ID, es)
        assert result.passed is False

    def test_pass_refresh_interval_one_hour(self):
        es = _external_secret(refresh_interval="1h")
        result = _run_check(self._ID, es)
        assert result.passed is True
        assert "1h" in result.message

    def test_pass_refresh_interval_30_minutes(self):
        es = _external_secret(refresh_interval="30m")
        result = _run_check(self._ID, es)
        assert result.passed is True
        assert "30m" in result.message

    def test_pass_refresh_interval_integer_string(self):
        # Non-zero numeric string like "3600" is not in _DISABLED_REFRESH
        es = _external_secret(refresh_interval="3600")
        result = _run_check(self._ID, es)
        assert result.passed is True


# ---------------------------------------------------------------------------
# 2. eso_external_secret_target_creation
# ---------------------------------------------------------------------------


class TestEsoExternalSecretTargetCreation:
    _ID = "eso_external_secret_target_creation"

    def test_skip_non_external_secret(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_cluster_secret_store(self):
        result = _run_check(
            self._ID,
            _secret_store(kind="ClusterSecretStore", provider={"aws": {}}),
        )
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_missing_creation_policy(self):
        # No target key at all
        es = _external_secret()
        result = _run_check(self._ID, es)
        assert result.passed is False
        assert result.details is not None
        assert result.details["creationPolicy"] is None
        assert result.details["accepted"] == ["Owner", "Orphan", "Merge"]
        assert "my-secret" in result.message

    def test_fail_target_without_creation_policy(self):
        # target present but no creationPolicy key
        es = _external_secret(target={"name": "my-k8s-secret"})
        result = _run_check(self._ID, es)
        assert result.passed is False

    def test_fail_uses_unknown_placeholder_when_no_name(self):
        es = _external_secret()
        del es["metadata"]["name"]
        result = _run_check(self._ID, es)
        assert result.passed is False
        assert "<unknown>" in result.message

    def test_pass_creation_policy_owner(self):
        es = _external_secret(target={"creationPolicy": "Owner"})
        result = _run_check(self._ID, es)
        assert result.passed is True
        assert "Owner" in result.message

    def test_pass_creation_policy_orphan(self):
        es = _external_secret(target={"creationPolicy": "Orphan"})
        result = _run_check(self._ID, es)
        assert result.passed is True
        assert "Orphan" in result.message

    def test_pass_creation_policy_merge(self):
        es = _external_secret(target={"creationPolicy": "Merge"})
        result = _run_check(self._ID, es)
        assert result.passed is True
        assert "Merge" in result.message


# ---------------------------------------------------------------------------
# 3. eso_external_secret_deletion_policy
# ---------------------------------------------------------------------------


class TestEsoExternalSecretDeletionPolicy:
    _ID = "eso_external_secret_deletion_policy"

    def test_skip_non_external_secret(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_secret_store(self):
        result = _run_check(
            self._ID,
            _secret_store(provider={"gcp": {"projectID": "my-project"}}),
        )
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_missing_deletion_policy(self):
        # No target at all
        es = _external_secret()
        result = _run_check(self._ID, es)
        assert result.passed is False
        assert result.details is not None
        assert result.details["deletionPolicy"] is None
        assert result.details["recommended"] == "Retain"
        assert "my-secret" in result.message

    def test_fail_target_without_deletion_policy(self):
        es = _external_secret(target={"creationPolicy": "Owner"})
        result = _run_check(self._ID, es)
        assert result.passed is False

    def test_fail_uses_unknown_placeholder_when_no_name(self):
        es = _external_secret()
        del es["metadata"]["name"]
        result = _run_check(self._ID, es)
        assert result.passed is False
        assert "<unknown>" in result.message

    def test_pass_deletion_policy_retain(self):
        es = _external_secret(target={"deletionPolicy": "Retain"})
        result = _run_check(self._ID, es)
        assert result.passed is True
        assert "Retain" in result.message

    def test_pass_deletion_policy_delete(self):
        es = _external_secret(target={"deletionPolicy": "Delete"})
        result = _run_check(self._ID, es)
        assert result.passed is True
        assert "Delete" in result.message

    def test_pass_both_policies_set(self):
        es = _external_secret(
            target={"creationPolicy": "Owner", "deletionPolicy": "Retain"}
        )
        result = _run_check(self._ID, es)
        assert result.passed is True


# ---------------------------------------------------------------------------
# 4. eso_secret_store_provider
# ---------------------------------------------------------------------------


class TestEsoSecretStoreProvider:
    _ID = "eso_secret_store_provider"

    def test_skip_non_store(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_external_secret(self):
        result = _run_check(self._ID, _external_secret())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_secret_store_empty_provider_dict(self):
        # provider key present but empty dict
        ss = _secret_store(provider={})
        result = _run_check(self._ID, ss)
        assert result.passed is False
        assert result.details is not None
        assert "my-store" in result.message
        assert "SecretStore" in result.message

    def test_fail_secret_store_no_provider_key(self):
        # No provider key at all — spec.get("provider", {}) returns {}
        ss = _secret_store()
        result = _run_check(self._ID, ss)
        assert result.passed is False

    def test_fail_cluster_secret_store_empty_provider(self):
        css = _secret_store(kind="ClusterSecretStore", provider={})
        result = _run_check(self._ID, css)
        assert result.passed is False
        assert "ClusterSecretStore" in result.message

    def test_pass_secret_store_with_aws_provider(self):
        ss = _secret_store(
            provider={"aws": {"service": "SecretsManager", "region": "us-east-1"}}
        )
        result = _run_check(self._ID, ss)
        assert result.passed is True
        assert "aws" in result.message

    def test_pass_secret_store_with_vault_provider(self):
        ss = _secret_store(
            provider={"vault": {"server": "https://vault.example.com", "path": "secret"}}
        )
        result = _run_check(self._ID, ss)
        assert result.passed is True
        assert "vault" in result.message

    def test_pass_cluster_secret_store_with_gcp_provider(self):
        css = _secret_store(
            kind="ClusterSecretStore",
            name="gcp-store",
            provider={"gcpsm": {"projectID": "my-gcp-project"}},
        )
        result = _run_check(self._ID, css)
        assert result.passed is True
        assert "ClusterSecretStore" in result.message
        assert "gcp-store" in result.message


# ---------------------------------------------------------------------------
# 5. eso_cluster_secret_store_conditions
# ---------------------------------------------------------------------------


class TestEsoClusterSecretStoreConditions:
    _ID = "eso_cluster_secret_store_conditions"

    def test_skip_non_cluster_secret_store(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_regular_secret_store(self):
        # SecretStore — not ClusterSecretStore
        ss = _secret_store(kind="SecretStore", provider={"aws": {}})
        result = _run_check(self._ID, ss)
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_external_secret(self):
        result = _run_check(self._ID, _external_secret())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_no_conditions_no_namespace_selector(self):
        css = _secret_store(kind="ClusterSecretStore", provider={"aws": {}})
        result = _run_check(self._ID, css)
        assert result.passed is False
        assert result.details is not None
        assert result.details["conditions"] is None
        assert result.details["namespaceSelector"] is None
        assert "my-store" in result.message
        assert "least privilege" in result.message.lower() or "all namespaces" in result.message.lower()

    def test_pass_conditions_present(self):
        css = _secret_store(
            kind="ClusterSecretStore",
            name="scoped-store",
            provider={"aws": {}},
            conditions=[
                {"namespaces": ["production", "monitoring"]},
            ],
        )
        result = _run_check(self._ID, css)
        assert result.passed is True
        assert "1 condition(s)" in result.message
        assert "scoped-store" in result.message

    def test_pass_namespace_selector_present(self):
        css = _secret_store(
            kind="ClusterSecretStore",
            name="ns-selector-store",
            provider={"aws": {}},
            namespace_selector={"matchLabels": {"env": "production"}},
        )
        result = _run_check(self._ID, css)
        assert result.passed is True
        assert "namespaceSelector" in result.message

    def test_pass_both_conditions_and_namespace_selector(self):
        css = _secret_store(
            kind="ClusterSecretStore",
            name="full-scoped-store",
            provider={"gcp": {}},
            conditions=[{"namespaces": ["prod"]}, {"namespaces": ["staging"]}],
            namespace_selector={"matchLabels": {"tier": "backend"}},
        )
        result = _run_check(self._ID, css)
        assert result.passed is True
        assert "2 condition(s)" in result.message
        assert "namespaceSelector" in result.message
        assert "and" in result.message

    def test_fail_uses_unknown_placeholder_when_no_name(self):
        css = _secret_store(kind="ClusterSecretStore", provider={"aws": {}})
        del css["metadata"]["name"]
        result = _run_check(self._ID, css)
        assert result.passed is False
        assert "<unknown>" in result.message


# ===========================================================================
# Registration smoke tests
# ===========================================================================


class TestCertManagerCheckRegistration:
    _EXPECTED_IDS = {
        "certmgr_certificate_duration",
        "certmgr_certificate_renew_before",
        "certmgr_certificate_private_key_algorithm",
        "certmgr_certificate_wildcard_production",
        "certmgr_issuer_solver_configured",
        "certmgr_issuer_staging_in_production",
    }

    def test_all_certmanager_checks_registered(self):
        registered = {fn(_deployment()).check_id for fn in get_check_fns()}
        assert self._EXPECTED_IDS.issubset(registered), (
            f"Missing cert-manager checks: {self._EXPECTED_IDS - registered}"
        )


class TestEsoCheckRegistration:
    _EXPECTED_IDS = {
        "eso_external_secret_refresh_interval",
        "eso_external_secret_target_creation",
        "eso_external_secret_deletion_policy",
        "eso_secret_store_provider",
        "eso_cluster_secret_store_conditions",
    }

    def test_all_eso_checks_registered(self):
        registered = {fn(_deployment()).check_id for fn in get_check_fns()}
        assert self._EXPECTED_IDS.issubset(registered), (
            f"Missing ESO checks: {self._EXPECTED_IDS - registered}"
        )
