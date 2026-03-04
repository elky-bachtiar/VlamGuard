"""Unit tests for the 15 KEDA-specific policy checks.

Each check gets three test cases:
  - pass   — correctly configured ScaledObject / ScaledJob / TriggerAuthentication
  - fail   — misconfigured resource that triggers the violation
  - skip   — non-KEDA manifest returns passed=True without inspection

The helper ``_run_check`` finds a check by ID by iterating over
``get_check_fns()``.  The import of ``vlamguard.engine.crd.keda`` is required
to trigger the ``@policy_check`` decorator registrations before the registry
is queried.
"""

import pytest

import vlamguard.engine.crd.keda  # noqa: F401  — registers KEDA checks
from vlamguard.engine.registry import get_check_fns
from vlamguard.models.response import PolicyCheckResult


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _run_check(check_id: str, manifest: dict) -> PolicyCheckResult:
    """Find check by ID and run it against *manifest*."""
    for fn in get_check_fns():
        result = fn(manifest)
        if result.check_id == check_id:
            return result
    raise ValueError(f"Check '{check_id}' not found in registry")


# ---------------------------------------------------------------------------
# Manifest builders — keep test bodies clean
# ---------------------------------------------------------------------------


def _scaled_object(
    *,
    name: str = "worker",
    namespace: str = "default",
    annotations: dict | None = None,
    spec_overrides: dict | None = None,
) -> dict:
    base_spec: dict = {
        "scaleTargetRef": {"name": "worker-deployment"},
        "minReplicaCount": 2,
        "maxReplicaCount": 20,
        "triggers": [],
    }
    if spec_overrides:
        base_spec.update(spec_overrides)
    manifest: dict = {
        "apiVersion": "keda.sh/v1alpha1",
        "kind": "ScaledObject",
        "metadata": {"name": name, "namespace": namespace},
        "spec": base_spec,
    }
    if annotations:
        manifest["metadata"]["annotations"] = annotations
    return manifest


def _scaled_job(
    *,
    name: str = "batch-job",
    spec_overrides: dict | None = None,
) -> dict:
    base_spec: dict = {
        "jobTargetRef": {"template": {"spec": {"containers": [{"name": "job", "image": "worker:1.0"}]}}},
        "triggers": [{"type": "rabbitmq", "metadata": {"queueName": "tasks"}}],
        "successfulJobsHistoryLimit": 5,
        "failedJobsHistoryLimit": 3,
    }
    if spec_overrides:
        base_spec.update(spec_overrides)
    return {
        "apiVersion": "keda.sh/v1alpha1",
        "kind": "ScaledJob",
        "metadata": {"name": name},
        "spec": base_spec,
    }


def _trigger_auth(
    *,
    name: str = "my-auth",
    spec: dict | None = None,
) -> dict:
    return {
        "apiVersion": "keda.sh/v1alpha1",
        "kind": "TriggerAuthentication",
        "metadata": {"name": name},
        "spec": spec or {},
    }


def _deployment(name: str = "web") -> dict:
    """Generic non-KEDA manifest for skip cases."""
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name},
        "spec": {
            "replicas": 2,
            "template": {
                "spec": {"containers": [{"name": "app", "image": "nginx:1.25.3"}]}
            },
        },
    }


# ---------------------------------------------------------------------------
# 1. keda_min_replica_production
# ---------------------------------------------------------------------------


class TestKedaMinReplicaProduction:
    _ID = "keda_min_replica_production"

    def test_pass_min_replica_at_least_one(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"minReplicaCount": 1}))
        assert result.passed is True
        assert "1" in result.message

    def test_pass_min_replica_greater_than_one(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"minReplicaCount": 3}))
        assert result.passed is True

    def test_fail_min_replica_zero(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"minReplicaCount": 0}))
        assert result.passed is False
        assert result.details is not None
        assert result.details["minReplicaCount"] == 0
        assert result.details["recommended"] == 1

    def test_fail_min_replica_absent_defaults_to_zero(self):
        so = _scaled_object()
        del so["spec"]["minReplicaCount"]
        result = _run_check(self._ID, so)
        assert result.passed is False

    def test_skip_non_scaled_object(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_scaled_job(self):
        result = _run_check(self._ID, _scaled_job())
        assert result.passed is True


# ---------------------------------------------------------------------------
# 2. keda_fallback_required
# ---------------------------------------------------------------------------


class TestKedaFallbackRequired:
    _ID = "keda_fallback_required"

    def test_pass_complete_fallback(self):
        result = _run_check(
            self._ID,
            _scaled_object(spec_overrides={"fallback": {"replicas": 3, "failureThreshold": 5}}),
        )
        assert result.passed is True
        assert "3" in result.message
        assert "5" in result.message

    def test_fail_no_fallback(self):
        result = _run_check(self._ID, _scaled_object())
        assert result.passed is False
        assert "fallback" in result.message.lower()

    def test_fail_fallback_missing_replicas(self):
        result = _run_check(
            self._ID,
            _scaled_object(spec_overrides={"fallback": {"failureThreshold": 3}}),
        )
        assert result.passed is False
        assert result.details is not None
        assert any("replicas" in v for v in result.details["violations"])

    def test_fail_fallback_missing_failure_threshold(self):
        result = _run_check(
            self._ID,
            _scaled_object(spec_overrides={"fallback": {"replicas": 2}}),
        )
        assert result.passed is False
        assert any("failureThreshold" in v for v in result.details["violations"])

    def test_fail_fallback_missing_both_fields(self):
        # An empty dict is falsy in Python — the implementation treats it as
        # "no fallback" and returns the simple "no fallback" error branch.
        result = _run_check(
            self._ID,
            _scaled_object(spec_overrides={"fallback": {}}),
        )
        assert result.passed is False
        assert "fallback" in result.message.lower()

    def test_skip_non_scaled_object(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()


# ---------------------------------------------------------------------------
# 3. keda_auth_ref_required
# ---------------------------------------------------------------------------


class TestKedaAuthRefRequired:
    _ID = "keda_auth_ref_required"

    def test_pass_credential_trigger_has_auth_ref(self):
        so = _scaled_object(
            spec_overrides={
                "triggers": [
                    {
                        "type": "kafka",
                        "metadata": {"password": "ignored"},
                        "authenticationRef": {"name": "kafka-auth"},
                    }
                ]
            }
        )
        result = _run_check(self._ID, so)
        assert result.passed is True

    def test_pass_no_credential_fields_no_auth_ref_needed(self):
        so = _scaled_object(
            spec_overrides={
                "triggers": [{"type": "cron", "metadata": {"timezone": "UTC", "start": "0 8 * * 1"}}]
            }
        )
        result = _run_check(self._ID, so)
        assert result.passed is True

    def test_pass_no_triggers(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"triggers": []}))
        assert result.passed is True

    def test_fail_password_metadata_without_auth_ref(self):
        so = _scaled_object(
            spec_overrides={
                "triggers": [{"type": "kafka", "metadata": {"password": "supersecret"}}]
            }
        )
        result = _run_check(self._ID, so)
        assert result.passed is False
        assert "authenticationRef" in result.message

    def test_fail_token_metadata_without_auth_ref(self):
        so = _scaled_object(
            spec_overrides={
                "triggers": [{"type": "github", "metadata": {"token": "ghp_xxxx"}}]
            }
        )
        result = _run_check(self._ID, so)
        assert result.passed is False
        assert result.details is not None
        assert len(result.details["violations"]) >= 1

    def test_skip_trigger_auth_manifest(self):
        result = _run_check(self._ID, _trigger_auth())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_non_scaled_object(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True


# ---------------------------------------------------------------------------
# 4. keda_hpa_ownership_validation
# ---------------------------------------------------------------------------


class TestKedaHpaOwnershipValidation:
    _ID = "keda_hpa_ownership_validation"

    def test_pass_no_annotation(self):
        result = _run_check(self._ID, _scaled_object())
        assert result.passed is True

    def test_pass_annotation_set_to_false(self):
        # Only "true" triggers the block; "false" is absent-equivalent
        result = _run_check(
            self._ID,
            _scaled_object(annotations={"validations.keda.sh/hpa-ownership": "false"}),
        )
        assert result.passed is True

    def test_fail_annotation_set_to_true(self):
        result = _run_check(
            self._ID,
            _scaled_object(annotations={"validations.keda.sh/hpa-ownership": "true"}),
        )
        assert result.passed is False
        assert "bypasses" in result.message.lower() or "disabled" in result.message.lower()
        assert result.details is not None
        assert result.details["value"] == "true"

    def test_skip_non_scaled_object(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()


# ---------------------------------------------------------------------------
# 5. keda_max_replica_bound
# ---------------------------------------------------------------------------


class TestKedaMaxReplicaBound:
    _ID = "keda_max_replica_bound"

    def test_pass_explicit_reasonable_max(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"maxReplicaCount": 50}))
        assert result.passed is True
        assert "50" in result.message

    def test_pass_boundary_value_500(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"maxReplicaCount": 500}))
        assert result.passed is True

    def test_fail_max_replica_absent(self):
        so = _scaled_object()
        del so["spec"]["maxReplicaCount"]
        result = _run_check(self._ID, so)
        assert result.passed is False
        assert result.details is not None
        assert result.details["maxReplicaCount"] is None

    def test_fail_max_replica_exceeds_500(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"maxReplicaCount": 501}))
        assert result.passed is False
        assert "501" in result.message

    def test_fail_max_replica_very_high(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"maxReplicaCount": 9999}))
        assert result.passed is False

    def test_skip_non_scaled_object(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()


# ---------------------------------------------------------------------------
# 6. keda_trigger_auth_secrets
# ---------------------------------------------------------------------------


class TestKedaTriggerAuthSecrets:
    _ID = "keda_trigger_auth_secrets"

    def test_pass_uses_secret_target_ref(self):
        ta = _trigger_auth(
            spec={
                "secretTargetRef": [
                    {"parameter": "password", "name": "kafka-secret", "key": "password"}
                ]
            }
        )
        result = _run_check(self._ID, ta)
        assert result.passed is True

    def test_pass_uses_vault(self):
        ta = _trigger_auth(
            spec={
                "hashiCorpVault": {
                    "address": "https://vault.example.com",
                    "authentication": "token",
                    "secrets": [{"path": "kv/db", "key": "password", "parameter": "password"}],
                }
            }
        )
        result = _run_check(self._ID, ta)
        assert result.passed is True

    def test_pass_empty_spec(self):
        result = _run_check(self._ID, _trigger_auth(spec={}))
        assert result.passed is True

    def test_fail_inline_env_value(self):
        ta = _trigger_auth(
            spec={"env": [{"name": "DB_PASSWORD", "value": "plaintext-secret", "parameter": "password"}]}
        )
        result = _run_check(self._ID, ta)
        assert result.passed is False
        assert "inline" in result.message.lower() or "DB_PASSWORD" in result.message

    def test_fail_multiple_inline_env_values(self):
        ta = _trigger_auth(
            spec={
                "env": [
                    {"name": "API_KEY", "value": "abc123", "parameter": "apiKey"},
                    {"name": "SECRET", "value": "xyz789", "parameter": "secret"},
                ]
            }
        )
        result = _run_check(self._ID, ta)
        assert result.passed is False
        assert result.details is not None
        assert len(result.details["violations"]) == 2

    def test_pass_cluster_trigger_auth_without_inline_values(self):
        manifest = {
            "apiVersion": "keda.sh/v1alpha1",
            "kind": "ClusterTriggerAuthentication",
            "metadata": {"name": "cluster-auth"},
            "spec": {"secretTargetRef": [{"parameter": "token", "name": "my-secret", "key": "token"}]},
        }
        result = _run_check(self._ID, manifest)
        assert result.passed is True

    def test_fail_cluster_trigger_auth_with_inline_values(self):
        manifest = {
            "apiVersion": "keda.sh/v1alpha1",
            "kind": "ClusterTriggerAuthentication",
            "metadata": {"name": "cluster-auth"},
            "spec": {"env": [{"name": "TOKEN", "value": "hardcoded", "parameter": "token"}]},
        }
        result = _run_check(self._ID, manifest)
        assert result.passed is False

    def test_skip_non_trigger_auth(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_scaled_object(self):
        result = _run_check(self._ID, _scaled_object())
        assert result.passed is True


# ---------------------------------------------------------------------------
# 7. keda_cooldown_period
# ---------------------------------------------------------------------------


class TestKedaCooldownPeriod:
    _ID = "keda_cooldown_period"

    def test_pass_explicit_cooldown_at_minimum(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"cooldownPeriod": 120}))
        assert result.passed is True
        assert "120" in result.message

    def test_pass_default_cooldown_used_when_absent(self):
        # KEDA default is 300s — not set means 300s, which passes
        so = _scaled_object()
        so["spec"].pop("cooldownPeriod", None)
        result = _run_check(self._ID, so)
        assert result.passed is True

    def test_pass_high_cooldown(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"cooldownPeriod": 600}))
        assert result.passed is True

    def test_fail_cooldown_below_120(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"cooldownPeriod": 30}))
        assert result.passed is False
        assert "30" in result.message
        assert result.details is not None
        assert result.details["cooldownPeriod"] == 30
        assert result.details["recommended_min"] == 120

    def test_fail_cooldown_of_zero(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"cooldownPeriod": 0}))
        assert result.passed is False

    def test_skip_non_scaled_object(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()


# ---------------------------------------------------------------------------
# 8. keda_polling_interval
# ---------------------------------------------------------------------------


class TestKedaPollingInterval:
    _ID = "keda_polling_interval"

    def test_pass_interval_in_valid_range(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"pollingInterval": 30}))
        assert result.passed is True
        assert "30" in result.message

    def test_pass_interval_at_lower_bound(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"pollingInterval": 10}))
        assert result.passed is True

    def test_pass_interval_at_upper_bound(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"pollingInterval": 300}))
        assert result.passed is True

    def test_pass_default_when_absent(self):
        # KEDA default is 30s
        so = _scaled_object()
        so["spec"].pop("pollingInterval", None)
        result = _run_check(self._ID, so)
        assert result.passed is True

    def test_fail_interval_too_low(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"pollingInterval": 5}))
        assert result.passed is False
        assert "throttling" in result.message.lower() or "5" in result.message
        assert result.details is not None
        assert result.details["range"] == "10-300"

    def test_fail_interval_too_high(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"pollingInterval": 600}))
        assert result.passed is False
        assert "600" in result.message

    def test_skip_non_scaled_object(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()


# ---------------------------------------------------------------------------
# 9. keda_fallback_replica_range
# ---------------------------------------------------------------------------


class TestKedaFallbackReplicaRange:
    _ID = "keda_fallback_replica_range"

    def test_pass_fallback_within_bounds(self):
        result = _run_check(
            self._ID,
            _scaled_object(
                spec_overrides={
                    "minReplicaCount": 2,
                    "maxReplicaCount": 10,
                    "fallback": {"replicas": 5, "failureThreshold": 3},
                }
            ),
        )
        assert result.passed is True
        assert "5" in result.message

    def test_pass_fallback_equals_min(self):
        result = _run_check(
            self._ID,
            _scaled_object(
                spec_overrides={
                    "minReplicaCount": 3,
                    "maxReplicaCount": 10,
                    "fallback": {"replicas": 3, "failureThreshold": 3},
                }
            ),
        )
        assert result.passed is True

    def test_pass_fallback_equals_max(self):
        result = _run_check(
            self._ID,
            _scaled_object(
                spec_overrides={
                    "minReplicaCount": 1,
                    "maxReplicaCount": 10,
                    "fallback": {"replicas": 10, "failureThreshold": 3},
                }
            ),
        )
        assert result.passed is True

    def test_pass_no_fallback_configured_skips(self):
        so = _scaled_object()
        # No fallback key at all
        result = _run_check(self._ID, so)
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_fallback_without_replicas_key_skips(self):
        result = _run_check(
            self._ID,
            _scaled_object(spec_overrides={"fallback": {"failureThreshold": 3}}),
        )
        assert result.passed is True

    def test_fail_fallback_below_min(self):
        result = _run_check(
            self._ID,
            _scaled_object(
                spec_overrides={
                    "minReplicaCount": 5,
                    "maxReplicaCount": 20,
                    "fallback": {"replicas": 2, "failureThreshold": 3},
                }
            ),
        )
        assert result.passed is False
        assert result.details is not None
        assert result.details["fallback_replicas"] == 2
        assert result.details["minReplicaCount"] == 5

    def test_fail_fallback_above_max(self):
        result = _run_check(
            self._ID,
            _scaled_object(
                spec_overrides={
                    "minReplicaCount": 1,
                    "maxReplicaCount": 10,
                    "fallback": {"replicas": 15, "failureThreshold": 3},
                }
            ),
        )
        assert result.passed is False
        assert result.details["fallback_replicas"] == 15
        assert result.details["maxReplicaCount"] == 10

    def test_skip_non_scaled_object(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()


# ---------------------------------------------------------------------------
# 10. keda_restore_replicas_warning
# ---------------------------------------------------------------------------


class TestKedaRestoreReplicasWarning:
    _ID = "keda_restore_replicas_warning"

    def test_pass_restore_true_explicitly(self):
        result = _run_check(
            self._ID,
            _scaled_object(spec_overrides={"advanced": {"restoreToOriginalReplicaCount": True}}),
        )
        assert result.passed is True

    def test_pass_restore_absent_defaults_to_true(self):
        # When the field is absent the implementation treats it as True
        result = _run_check(self._ID, _scaled_object())
        assert result.passed is True

    def test_fail_restore_false(self):
        result = _run_check(
            self._ID,
            _scaled_object(spec_overrides={"advanced": {"restoreToOriginalReplicaCount": False}}),
        )
        assert result.passed is False
        assert result.details is not None
        assert result.details["restoreToOriginalReplicaCount"] is False
        assert "false" in result.message.lower()

    def test_skip_non_scaled_object(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()


# ---------------------------------------------------------------------------
# 11. keda_inline_secret_detection
# ---------------------------------------------------------------------------


class TestKedaInlineSecretDetection:
    _ID = "keda_inline_secret_detection"

    def test_pass_no_credential_keys(self):
        so = _scaled_object(
            spec_overrides={
                "triggers": [{"type": "cron", "metadata": {"timezone": "UTC", "start": "0 6 * * 1-5"}}]
            }
        )
        result = _run_check(self._ID, so)
        assert result.passed is True

    def test_pass_no_triggers(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"triggers": []}))
        assert result.passed is True

    def test_fail_password_key_in_metadata(self):
        so = _scaled_object(
            spec_overrides={
                "triggers": [{"type": "kafka", "metadata": {"password": "mysecret"}}]
            }
        )
        result = _run_check(self._ID, so)
        assert result.passed is False
        assert "password" in result.message.lower()

    def test_fail_api_key_in_metadata(self):
        so = _scaled_object(
            spec_overrides={
                "triggers": [{"type": "http", "metadata": {"apiKey": "sk-abc123"}}]
            }
        )
        result = _run_check(self._ID, so)
        assert result.passed is False
        assert result.details is not None
        assert len(result.details["violations"]) >= 1

    def test_fail_connection_string_key(self):
        so = _scaled_object(
            spec_overrides={
                "triggers": [{"type": "mssql", "metadata": {"connectionString": "Server=db;Password=x"}}]
            }
        )
        result = _run_check(self._ID, so)
        assert result.passed is False

    def test_fail_long_base64_value(self):
        long_b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn0123456789+/abcd"  # 56 chars, base64-like
        so = _scaled_object(
            spec_overrides={
                "triggers": [{"type": "kafka", "metadata": {"cert": long_b64}}]
            }
        )
        result = _run_check(self._ID, so)
        assert result.passed is False

    def test_skip_non_scaled_object(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_trigger_auth_manifest(self):
        result = _run_check(self._ID, _trigger_auth())
        assert result.passed is True


# ---------------------------------------------------------------------------
# 12. keda_initial_cooldown
# ---------------------------------------------------------------------------


class TestKedaInitialCooldown:
    _ID = "keda_initial_cooldown"

    def test_pass_not_set(self):
        # If initialCooldownPeriod is absent the check passes (no concern)
        so = _scaled_object()
        so["spec"].pop("initialCooldownPeriod", None)
        result = _run_check(self._ID, so)
        assert result.passed is True

    def test_pass_at_minimum(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"initialCooldownPeriod": 60}))
        assert result.passed is True

    def test_pass_above_minimum(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"initialCooldownPeriod": 120}))
        assert result.passed is True

    def test_fail_below_minimum(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"initialCooldownPeriod": 30}))
        assert result.passed is False
        assert "30" in result.message
        assert result.details is not None
        assert result.details["initialCooldownPeriod"] == 30
        assert result.details["recommended_min"] == 60

    def test_fail_zero(self):
        result = _run_check(self._ID, _scaled_object(spec_overrides={"initialCooldownPeriod": 0}))
        assert result.passed is False

    def test_skip_non_scaled_object(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()


# ---------------------------------------------------------------------------
# 13. keda_job_history_limits
# ---------------------------------------------------------------------------


class TestKedaJobHistoryLimits:
    _ID = "keda_job_history_limits"

    def test_pass_both_limits_set(self):
        result = _run_check(
            self._ID,
            _scaled_job(spec_overrides={"successfulJobsHistoryLimit": 10, "failedJobsHistoryLimit": 5}),
        )
        assert result.passed is True

    def test_pass_limits_set_to_zero(self):
        result = _run_check(
            self._ID,
            _scaled_job(spec_overrides={"successfulJobsHistoryLimit": 0, "failedJobsHistoryLimit": 0}),
        )
        assert result.passed is True

    def test_fail_both_limits_missing(self):
        spec: dict = {
            "jobTargetRef": {"template": {"spec": {}}},
            "triggers": [],
        }
        manifest = {
            "apiVersion": "keda.sh/v1alpha1",
            "kind": "ScaledJob",
            "metadata": {"name": "bare-job"},
            "spec": spec,
        }
        result = _run_check(self._ID, manifest)
        assert result.passed is False
        assert result.details is not None
        assert len(result.details["violations"]) == 2

    def test_fail_successful_limit_missing(self):
        sj = _scaled_job()
        del sj["spec"]["successfulJobsHistoryLimit"]
        result = _run_check(self._ID, sj)
        assert result.passed is False
        assert any("successfulJobsHistoryLimit" in v for v in result.details["violations"])

    def test_fail_failed_limit_missing(self):
        sj = _scaled_job()
        del sj["spec"]["failedJobsHistoryLimit"]
        result = _run_check(self._ID, sj)
        assert result.passed is False
        assert any("failedJobsHistoryLimit" in v for v in result.details["violations"])

    def test_skip_scaled_object(self):
        result = _run_check(self._ID, _scaled_object())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_non_keda_manifest(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()


# ---------------------------------------------------------------------------
# 14. keda_paused_annotation
# ---------------------------------------------------------------------------


class TestKedaPausedAnnotation:
    _ID = "keda_paused_annotation"

    def test_pass_no_paused_annotation(self):
        result = _run_check(self._ID, _scaled_object())
        assert result.passed is True

    def test_fail_paused_annotation_true(self):
        result = _run_check(
            self._ID,
            _scaled_object(annotations={"autoscaling.keda.sh/paused": "true"}),
        )
        assert result.passed is False
        assert result.details is not None
        assert result.details["paused_value"] == "true"
        assert "paused" in result.message.lower()

    def test_fail_paused_annotation_false_still_pauses(self):
        # KEDA quirk: ANY value including "false" pauses the ScaledObject
        result = _run_check(
            self._ID,
            _scaled_object(annotations={"autoscaling.keda.sh/paused": "false"}),
        )
        assert result.passed is False
        assert result.details["paused_value"] == "false"

    def test_fail_paused_annotation_arbitrary_value(self):
        result = _run_check(
            self._ID,
            _scaled_object(annotations={"autoscaling.keda.sh/paused": "1"}),
        )
        assert result.passed is False

    def test_skip_non_scaled_object(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_trigger_auth(self):
        result = _run_check(self._ID, _trigger_auth())
        assert result.passed is True


# ---------------------------------------------------------------------------
# Cross-check: all 14 KEDA check IDs are registered
# ---------------------------------------------------------------------------


class TestKedaCheckRegistration:
    _EXPECTED_IDS = {
        "keda_min_replica_production",
        "keda_fallback_required",
        "keda_auth_ref_required",
        "keda_hpa_ownership_validation",
        "keda_max_replica_bound",
        "keda_trigger_auth_secrets",
        "keda_cooldown_period",
        "keda_polling_interval",
        "keda_fallback_replica_range",
        "keda_restore_replicas_warning",
        "keda_inline_secret_detection",
        "keda_initial_cooldown",
        "keda_job_history_limits",
        "keda_paused_annotation",
    }

    def test_all_keda_checks_registered(self):
        registered = {fn(_deployment()).check_id for fn in get_check_fns()}
        assert self._EXPECTED_IDS.issubset(registered), (
            f"Missing KEDA checks: {self._EXPECTED_IDS - registered}"
        )

    def test_keda_check_ids_unique(self):
        from vlamguard.engine.registry import get_all_checks

        ids = [c.check_id for c in get_all_checks()]
        assert len(ids) == len(set(ids)), "Duplicate check IDs detected in registry"
