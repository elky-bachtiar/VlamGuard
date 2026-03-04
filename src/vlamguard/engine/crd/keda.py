"""KEDA CRD policy checks — the first CRD-specific policy library.

No competitor offers KEDA-specific policies. These checks cover production
readiness, scaling safety, credential hygiene, and known failure modes
for ScaledObject, ScaledJob, and TriggerAuthentication resources.
"""

import re

from vlamguard.engine.registry import policy_check
from vlamguard.models.response import PolicyCheckResult

# KEDA resource kinds
_KEDA_SCALED_OBJECT = "ScaledObject"
_KEDA_SCALED_JOB = "ScaledJob"
_KEDA_TRIGGER_AUTH = "TriggerAuthentication"
_KEDA_CLUSTER_TRIGGER_AUTH = "ClusterTriggerAuthentication"

# Patterns that suggest credentials in trigger metadata
_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|secret|token|key|credential|api.?key)"),
    re.compile(r"(?i)(connection.?string|conn.?str|dsn|database.?url)"),
    re.compile(r"(?i)(access.?key|secret.?key|private.?key)"),
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}$"),  # Base64-like long strings
]


# ---------------------------------------------------------------------------
# Priority 1 — Must-have checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="keda_min_replica_production",
    name="KEDA Min Replica Count",
    severity="high",
    category="keda-reliability",
    risk_points=25,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.5"}),
    description="ScaledObject minReplicaCount >= 1 prevents cold-start outages in production.",
    remediation="Set spec.minReplicaCount to at least 1 for production workloads.",
)
def check_keda_min_replica_production(manifest: dict) -> PolicyCheckResult:
    """ScaledObject must have minReplicaCount >= 1 in production."""
    if manifest.get("kind") != _KEDA_SCALED_OBJECT:
        return PolicyCheckResult(
            check_id="keda_min_replica_production",
            name="KEDA Min Replica Count",
            passed=True,
            severity="high",
            message="Not a ScaledObject, skipped.",
        )

    spec = manifest.get("spec", {})
    min_replicas = spec.get("minReplicaCount", 0)

    if min_replicas < 1:
        return PolicyCheckResult(
            check_id="keda_min_replica_production",
            name="KEDA Min Replica Count",
            passed=False,
            severity="high",
            message=f"ScaledObject minReplicaCount is {min_replicas}. Must be >= 1 to prevent cold-start outages.",
            details={"minReplicaCount": min_replicas, "recommended": 1},
        )

    return PolicyCheckResult(
        check_id="keda_min_replica_production",
        name="KEDA Min Replica Count",
        passed=True,
        severity="high",
        message=f"ScaledObject minReplicaCount is {min_replicas}.",
    )


@policy_check(
    check_id="keda_fallback_required",
    name="KEDA Fallback Configuration",
    severity="high",
    category="keda-reliability",
    risk_points=20,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.5"}),
    description="Fallback config prevents indeterminate state when external metric sources fail.",
    remediation="Add spec.fallback with replicas and failureThreshold.",
)
def check_keda_fallback_required(manifest: dict) -> PolicyCheckResult:
    """ScaledObject must have fallback configuration for production resilience."""
    if manifest.get("kind") != _KEDA_SCALED_OBJECT:
        return PolicyCheckResult(
            check_id="keda_fallback_required",
            name="KEDA Fallback Configuration",
            passed=True,
            severity="high",
            message="Not a ScaledObject, skipped.",
        )

    spec = manifest.get("spec", {})
    fallback = spec.get("fallback")

    if not fallback:
        return PolicyCheckResult(
            check_id="keda_fallback_required",
            name="KEDA Fallback Configuration",
            passed=False,
            severity="high",
            message="ScaledObject has no fallback configuration. Scaler failures will leave replicas in indeterminate state.",
            details={"fallback": None},
        )

    # Validate fallback has required fields
    violations = []
    if "replicas" not in fallback:
        violations.append("fallback.replicas not set")
    if "failureThreshold" not in fallback:
        violations.append("fallback.failureThreshold not set")

    if violations:
        return PolicyCheckResult(
            check_id="keda_fallback_required",
            name="KEDA Fallback Configuration",
            passed=False,
            severity="high",
            message=f"Fallback configuration incomplete: {'; '.join(violations)}.",
            details={"fallback": fallback, "violations": violations},
        )

    return PolicyCheckResult(
        check_id="keda_fallback_required",
        name="KEDA Fallback Configuration",
        passed=True,
        severity="high",
        message=f"Fallback configured with {fallback.get('replicas')} replicas and threshold {fallback.get('failureThreshold')}.",
    )


@policy_check(
    check_id="keda_auth_ref_required",
    name="KEDA Authentication Reference",
    severity="high",
    category="keda-security",
    risk_points=20,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"CIS-5.4.1", "SOC2-CC6.1"}),
    cis_benchmark="5.4.1",
    description="Triggers with credentials must use TriggerAuthentication, not inline secrets.",
    remediation="Add authenticationRef to triggers that require credentials.",
)
def check_keda_auth_ref_required(manifest: dict) -> PolicyCheckResult:
    """ScaledObject triggers with credentials must reference TriggerAuthentication."""
    if manifest.get("kind") != _KEDA_SCALED_OBJECT:
        return PolicyCheckResult(
            check_id="keda_auth_ref_required",
            name="KEDA Authentication Reference",
            passed=True,
            severity="high",
            message="Not a ScaledObject, skipped.",
        )

    spec = manifest.get("spec", {})
    triggers = spec.get("triggers", [])

    if not triggers:
        return PolicyCheckResult(
            check_id="keda_auth_ref_required",
            name="KEDA Authentication Reference",
            passed=True,
            severity="high",
            message="No triggers defined.",
        )

    violations = []
    for i, trigger in enumerate(triggers):
        metadata = trigger.get("metadata", {})
        auth_ref = trigger.get("authenticationRef")

        # Check if trigger metadata contains credential-like values
        has_credential_fields = False
        for key, value in metadata.items():
            if isinstance(value, str) and any(p.search(key) for p in _SECRET_PATTERNS[:3]):
                has_credential_fields = True
                break

        if has_credential_fields and not auth_ref:
            trigger_type = trigger.get("type", f"trigger[{i}]")
            violations.append(
                f"Trigger '{trigger_type}' has credential-like metadata but no authenticationRef"
            )

    if violations:
        return PolicyCheckResult(
            check_id="keda_auth_ref_required",
            name="KEDA Authentication Reference",
            passed=False,
            severity="high",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="keda_auth_ref_required",
        name="KEDA Authentication Reference",
        passed=True,
        severity="high",
        message="All credential-bearing triggers use authenticationRef.",
    )


@policy_check(
    check_id="keda_hpa_ownership_validation",
    name="KEDA HPA Ownership Validation",
    severity="high",
    category="keda-security",
    risk_points=20,
    prod_behavior="soft_risk",
    other_behavior="off",
    description="Disabling HPA ownership validation bypasses KEDA's admission controls.",
    remediation="Remove the validations.keda.sh/hpa-ownership annotation.",
)
def check_keda_hpa_ownership_validation(manifest: dict) -> PolicyCheckResult:
    """Block disabling of KEDA's HPA ownership admission validation."""
    if manifest.get("kind") != _KEDA_SCALED_OBJECT:
        return PolicyCheckResult(
            check_id="keda_hpa_ownership_validation",
            name="KEDA HPA Ownership Validation",
            passed=True,
            severity="high",
            message="Not a ScaledObject, skipped.",
        )

    annotations = manifest.get("metadata", {}).get("annotations", {})
    hpa_ownership = annotations.get("validations.keda.sh/hpa-ownership")

    if hpa_ownership == "true":
        return PolicyCheckResult(
            check_id="keda_hpa_ownership_validation",
            name="KEDA HPA Ownership Validation",
            passed=False,
            severity="high",
            message="HPA ownership validation is disabled via annotation. This bypasses KEDA's admission controls.",
            details={"annotation": "validations.keda.sh/hpa-ownership", "value": "true"},
        )

    return PolicyCheckResult(
        check_id="keda_hpa_ownership_validation",
        name="KEDA HPA Ownership Validation",
        passed=True,
        severity="high",
        message="HPA ownership validation is not disabled.",
    )


@policy_check(
    check_id="keda_max_replica_bound",
    name="KEDA Max Replica Bound",
    severity="high",
    category="keda-reliability",
    risk_points=20,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC7.2"}),
    description="Explicit maxReplicaCount prevents runaway autoscaling and resource exhaustion.",
    remediation="Set spec.maxReplicaCount to an explicit upper bound.",
)
def check_keda_max_replica_bound(manifest: dict) -> PolicyCheckResult:
    """ScaledObject must have an explicit maxReplicaCount."""
    if manifest.get("kind") != _KEDA_SCALED_OBJECT:
        return PolicyCheckResult(
            check_id="keda_max_replica_bound",
            name="KEDA Max Replica Bound",
            passed=True,
            severity="high",
            message="Not a ScaledObject, skipped.",
        )

    spec = manifest.get("spec", {})
    max_replicas = spec.get("maxReplicaCount")

    if max_replicas is None:
        return PolicyCheckResult(
            check_id="keda_max_replica_bound",
            name="KEDA Max Replica Bound",
            passed=False,
            severity="high",
            message="ScaledObject has no explicit maxReplicaCount. Default (100) may cause resource exhaustion.",
            details={"maxReplicaCount": None, "kedaDefault": 100},
        )

    if max_replicas > 500:
        return PolicyCheckResult(
            check_id="keda_max_replica_bound",
            name="KEDA Max Replica Bound",
            passed=False,
            severity="high",
            message=f"maxReplicaCount is {max_replicas}, which is unusually high. Verify this is intentional.",
            details={"maxReplicaCount": max_replicas},
        )

    return PolicyCheckResult(
        check_id="keda_max_replica_bound",
        name="KEDA Max Replica Bound",
        passed=True,
        severity="high",
        message=f"maxReplicaCount is {max_replicas}.",
    )


@policy_check(
    check_id="keda_trigger_auth_secrets",
    name="KEDA TriggerAuth Inline Secrets",
    severity="critical",
    category="keda-security",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
    compliance_tags=frozenset({"CIS-5.4.1", "SOC2-CC6.1"}),
    cis_benchmark="5.4.1",
    description="TriggerAuthentication should not contain inline secrets; use secretTargetRef or external providers.",
    remediation="Use spec.secretTargetRef, spec.hashiCorpVault, or spec.azureKeyVault instead of inline values.",
)
def check_keda_trigger_auth_secrets(manifest: dict) -> PolicyCheckResult:
    """TriggerAuthentication must not contain hardcoded credentials."""
    kind = manifest.get("kind")
    if kind not in (_KEDA_TRIGGER_AUTH, _KEDA_CLUSTER_TRIGGER_AUTH):
        return PolicyCheckResult(
            check_id="keda_trigger_auth_secrets",
            name="KEDA TriggerAuth Inline Secrets",
            passed=True,
            severity="critical",
            message="Not a TriggerAuthentication, skipped.",
        )

    spec = manifest.get("spec", {})
    violations = []

    # Check for inline env values (these contain plaintext credentials)
    env_entries = spec.get("env", [])
    for entry in env_entries:
        name = entry.get("name", "unknown")
        if "value" in entry:
            # Inline value — potential credential exposure
            violations.append(f"env '{name}' has inline value (use secretTargetRef instead)")

    # Check for secretTargetRef — this is the correct pattern, no violation
    # Check for hashiCorpVault — this is the correct pattern
    # Check for azureKeyVault — this is the correct pattern
    # Check for awsSecretManager — this is the correct pattern
    # Check for gcpSecretManager — this is the correct pattern

    if violations:
        return PolicyCheckResult(
            check_id="keda_trigger_auth_secrets",
            name="KEDA TriggerAuth Inline Secrets",
            passed=False,
            severity="critical",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="keda_trigger_auth_secrets",
        name="KEDA TriggerAuth Inline Secrets",
        passed=True,
        severity="critical",
        message="No inline secrets in TriggerAuthentication.",
    )


# ---------------------------------------------------------------------------
# Priority 2 — Should-have checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="keda_cooldown_period",
    name="KEDA Cooldown Period",
    severity="medium",
    category="keda-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    description="cooldownPeriod controls how long KEDA waits before scaling to zero. Too short risks premature scale-down.",
    remediation="Set spec.cooldownPeriod to at least 120 seconds in production.",
)
def check_keda_cooldown_period(manifest: dict) -> PolicyCheckResult:
    """ScaledObject cooldownPeriod should be >= 120s in production."""
    if manifest.get("kind") != _KEDA_SCALED_OBJECT:
        return PolicyCheckResult(
            check_id="keda_cooldown_period",
            name="KEDA Cooldown Period",
            passed=True,
            severity="medium",
            message="Not a ScaledObject, skipped.",
        )

    spec = manifest.get("spec", {})
    cooldown = spec.get("cooldownPeriod", 300)  # KEDA default is 300s

    if cooldown < 120:
        return PolicyCheckResult(
            check_id="keda_cooldown_period",
            name="KEDA Cooldown Period",
            passed=False,
            severity="medium",
            message=f"cooldownPeriod is {cooldown}s, below recommended minimum of 120s.",
            details={"cooldownPeriod": cooldown, "recommended_min": 120},
        )

    return PolicyCheckResult(
        check_id="keda_cooldown_period",
        name="KEDA Cooldown Period",
        passed=True,
        severity="medium",
        message=f"cooldownPeriod is {cooldown}s.",
    )


@policy_check(
    check_id="keda_polling_interval",
    name="KEDA Polling Interval",
    severity="medium",
    category="keda-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    description="Too-aggressive polling causes API throttling; too-slow polling misses scaling signals.",
    remediation="Set spec.pollingInterval between 10 and 300 seconds.",
)
def check_keda_polling_interval(manifest: dict) -> PolicyCheckResult:
    """ScaledObject pollingInterval should be between 10-300s."""
    if manifest.get("kind") != _KEDA_SCALED_OBJECT:
        return PolicyCheckResult(
            check_id="keda_polling_interval",
            name="KEDA Polling Interval",
            passed=True,
            severity="medium",
            message="Not a ScaledObject, skipped.",
        )

    spec = manifest.get("spec", {})
    interval = spec.get("pollingInterval", 30)  # KEDA default is 30s

    if interval < 10:
        return PolicyCheckResult(
            check_id="keda_polling_interval",
            name="KEDA Polling Interval",
            passed=False,
            severity="medium",
            message=f"pollingInterval is {interval}s, below minimum of 10s. May cause API throttling.",
            details={"pollingInterval": interval, "range": "10-300"},
        )

    if interval > 300:
        return PolicyCheckResult(
            check_id="keda_polling_interval",
            name="KEDA Polling Interval",
            passed=False,
            severity="medium",
            message=f"pollingInterval is {interval}s, above maximum of 300s. May miss scaling signals.",
            details={"pollingInterval": interval, "range": "10-300"},
        )

    return PolicyCheckResult(
        check_id="keda_polling_interval",
        name="KEDA Polling Interval",
        passed=True,
        severity="medium",
        message=f"pollingInterval is {interval}s.",
    )


@policy_check(
    check_id="keda_fallback_replica_range",
    name="KEDA Fallback Replica Range",
    severity="medium",
    category="keda-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    description="Fallback replicas should be within the min/max replica bounds.",
    remediation="Set fallback.replicas between minReplicaCount and maxReplicaCount.",
)
def check_keda_fallback_replica_range(manifest: dict) -> PolicyCheckResult:
    """Fallback replicas must be within minReplicaCount and maxReplicaCount."""
    if manifest.get("kind") != _KEDA_SCALED_OBJECT:
        return PolicyCheckResult(
            check_id="keda_fallback_replica_range",
            name="KEDA Fallback Replica Range",
            passed=True,
            severity="medium",
            message="Not a ScaledObject, skipped.",
        )

    spec = manifest.get("spec", {})
    fallback = spec.get("fallback")

    if not fallback or "replicas" not in fallback:
        return PolicyCheckResult(
            check_id="keda_fallback_replica_range",
            name="KEDA Fallback Replica Range",
            passed=True,
            severity="medium",
            message="No fallback replicas configured, skipped.",
        )

    fb_replicas = fallback["replicas"]
    min_replicas = spec.get("minReplicaCount", 0)
    max_replicas = spec.get("maxReplicaCount", 100)

    violations = []
    if fb_replicas < min_replicas:
        violations.append(
            f"fallback.replicas ({fb_replicas}) is below minReplicaCount ({min_replicas})"
        )
    if fb_replicas > max_replicas:
        violations.append(
            f"fallback.replicas ({fb_replicas}) exceeds maxReplicaCount ({max_replicas})"
        )

    if violations:
        return PolicyCheckResult(
            check_id="keda_fallback_replica_range",
            name="KEDA Fallback Replica Range",
            passed=False,
            severity="medium",
            message="; ".join(violations),
            details={
                "fallback_replicas": fb_replicas,
                "minReplicaCount": min_replicas,
                "maxReplicaCount": max_replicas,
            },
        )

    return PolicyCheckResult(
        check_id="keda_fallback_replica_range",
        name="KEDA Fallback Replica Range",
        passed=True,
        severity="medium",
        message=f"Fallback replicas ({fb_replicas}) is within [{min_replicas}, {max_replicas}].",
    )


@policy_check(
    check_id="keda_restore_replicas_warning",
    name="KEDA Restore Replicas on Delete",
    severity="medium",
    category="keda-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    description="When restoreToOriginalReplicaCount is false, deleting a ScaledObject leaves workload at current scale.",
    remediation="Set spec.advanced.restoreToOriginalReplicaCount to true.",
)
def check_keda_restore_replicas_warning(manifest: dict) -> PolicyCheckResult:
    """Warn if restoreToOriginalReplicaCount is false."""
    if manifest.get("kind") != _KEDA_SCALED_OBJECT:
        return PolicyCheckResult(
            check_id="keda_restore_replicas_warning",
            name="KEDA Restore Replicas on Delete",
            passed=True,
            severity="medium",
            message="Not a ScaledObject, skipped.",
        )

    spec = manifest.get("spec", {})
    advanced = spec.get("advanced", {})
    restore = advanced.get("restoreToOriginalReplicaCount", True)

    if restore is False:
        return PolicyCheckResult(
            check_id="keda_restore_replicas_warning",
            name="KEDA Restore Replicas on Delete",
            passed=False,
            severity="medium",
            message="restoreToOriginalReplicaCount is false. Deleting ScaledObject will leave workload at current scale.",
            details={"restoreToOriginalReplicaCount": False},
        )

    return PolicyCheckResult(
        check_id="keda_restore_replicas_warning",
        name="KEDA Restore Replicas on Delete",
        passed=True,
        severity="medium",
        message="Workload replicas will be restored on ScaledObject deletion.",
    )


# ---------------------------------------------------------------------------
# Priority 3 — Differentiator checks
# ---------------------------------------------------------------------------


@policy_check(
    check_id="keda_inline_secret_detection",
    name="KEDA Inline Secret in Trigger Metadata",
    severity="high",
    category="keda-security",
    risk_points=20,
    prod_behavior="soft_risk",
    other_behavior="off",
    compliance_tags=frozenset({"SOC2-CC6.1"}),
    description="Trigger metadata may contain connection strings, tokens, or other credentials inline.",
    remediation="Move credentials to TriggerAuthentication with secretTargetRef or external secret providers.",
)
def check_keda_inline_secret_detection(manifest: dict) -> PolicyCheckResult:
    """Detect potential secrets in ScaledObject trigger metadata."""
    if manifest.get("kind") != _KEDA_SCALED_OBJECT:
        return PolicyCheckResult(
            check_id="keda_inline_secret_detection",
            name="KEDA Inline Secret in Trigger Metadata",
            passed=True,
            severity="high",
            message="Not a ScaledObject, skipped.",
        )

    spec = manifest.get("spec", {})
    triggers = spec.get("triggers", [])
    violations = []

    for i, trigger in enumerate(triggers):
        trigger_type = trigger.get("type", f"trigger[{i}]")
        metadata = trigger.get("metadata", {})

        for key, value in metadata.items():
            if not isinstance(value, str):
                continue
            # Check key name for credential patterns
            for pattern in _SECRET_PATTERNS[:3]:
                if pattern.search(key):
                    violations.append(
                        f"Trigger '{trigger_type}' metadata key '{key}' looks like a credential"
                    )
                    break
            # Check value for long base64-like strings (potential credentials)
            if len(value) >= 32 and _SECRET_PATTERNS[3].search(value):
                violations.append(
                    f"Trigger '{trigger_type}' metadata '{key}' contains a potential credential value"
                )

    if violations:
        return PolicyCheckResult(
            check_id="keda_inline_secret_detection",
            name="KEDA Inline Secret in Trigger Metadata",
            passed=False,
            severity="high",
            message="; ".join(violations),
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="keda_inline_secret_detection",
        name="KEDA Inline Secret in Trigger Metadata",
        passed=True,
        severity="high",
        message="No credential patterns detected in trigger metadata.",
    )


@policy_check(
    check_id="keda_initial_cooldown",
    name="KEDA Initial Cooldown Period",
    severity="medium",
    category="keda-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    description="initialCooldownPeriod prevents premature scale-down after deployment (e.g., CI/CD workloads).",
    remediation="Set spec.initialCooldownPeriod to at least 60 seconds.",
)
def check_keda_initial_cooldown(manifest: dict) -> PolicyCheckResult:
    """ScaledObject should have initialCooldownPeriod >= 60s for CI/CD workloads."""
    if manifest.get("kind") != _KEDA_SCALED_OBJECT:
        return PolicyCheckResult(
            check_id="keda_initial_cooldown",
            name="KEDA Initial Cooldown Period",
            passed=True,
            severity="medium",
            message="Not a ScaledObject, skipped.",
        )

    spec = manifest.get("spec", {})
    initial_cooldown = spec.get("initialCooldownPeriod")

    if initial_cooldown is not None and initial_cooldown < 60:
        return PolicyCheckResult(
            check_id="keda_initial_cooldown",
            name="KEDA Initial Cooldown Period",
            passed=False,
            severity="medium",
            message=f"initialCooldownPeriod is {initial_cooldown}s, below recommended 60s.",
            details={"initialCooldownPeriod": initial_cooldown, "recommended_min": 60},
        )

    return PolicyCheckResult(
        check_id="keda_initial_cooldown",
        name="KEDA Initial Cooldown Period",
        passed=True,
        severity="medium",
        message=f"initialCooldownPeriod is {initial_cooldown or 'not set (OK)'}.",
    )


@policy_check(
    check_id="keda_job_history_limits",
    name="KEDA ScaledJob History Limits",
    severity="medium",
    category="keda-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="off",
    description="Without history limits, completed/failed jobs accumulate and consume cluster resources.",
    remediation="Set successfulJobsHistoryLimit and failedJobsHistoryLimit.",
)
def check_keda_job_history_limits(manifest: dict) -> PolicyCheckResult:
    """ScaledJob must have job history limits configured."""
    if manifest.get("kind") != _KEDA_SCALED_JOB:
        return PolicyCheckResult(
            check_id="keda_job_history_limits",
            name="KEDA ScaledJob History Limits",
            passed=True,
            severity="medium",
            message="Not a ScaledJob, skipped.",
        )

    spec = manifest.get("spec", {})
    violations = []

    if "successfulJobsHistoryLimit" not in spec:
        violations.append("successfulJobsHistoryLimit not set")
    if "failedJobsHistoryLimit" not in spec:
        violations.append("failedJobsHistoryLimit not set")

    if violations:
        return PolicyCheckResult(
            check_id="keda_job_history_limits",
            name="KEDA ScaledJob History Limits",
            passed=False,
            severity="medium",
            message=f"ScaledJob missing history limits: {'; '.join(violations)}.",
            details={"violations": violations},
        )

    return PolicyCheckResult(
        check_id="keda_job_history_limits",
        name="KEDA ScaledJob History Limits",
        passed=True,
        severity="medium",
        message="Job history limits are configured.",
    )


@policy_check(
    check_id="keda_paused_annotation",
    name="KEDA Paused Annotation",
    severity="medium",
    category="keda-reliability",
    risk_points=10,
    prod_behavior="soft_risk",
    other_behavior="soft_risk",
    description="Any value on autoscaling.keda.sh/paused annotation pauses scaling. Only 'true' is intentional.",
    remediation="Remove the paused annotation or ensure it is not set to an unintended value.",
)
def check_keda_paused_annotation(manifest: dict) -> PolicyCheckResult:
    """Flag autoscaling.keda.sh/paused with any value other than explicitly absent."""
    if manifest.get("kind") != _KEDA_SCALED_OBJECT:
        return PolicyCheckResult(
            check_id="keda_paused_annotation",
            name="KEDA Paused Annotation",
            passed=True,
            severity="medium",
            message="Not a ScaledObject, skipped.",
        )

    annotations = manifest.get("metadata", {}).get("annotations", {})
    paused = annotations.get("autoscaling.keda.sh/paused")

    if paused is not None:
        # Any value (including "false"!) actually pauses the ScaledObject
        if paused != "true":
            return PolicyCheckResult(
                check_id="keda_paused_annotation",
                name="KEDA Paused Annotation",
                passed=False,
                severity="medium",
                message=f"Paused annotation is '{paused}'. Note: ANY value (even 'false') pauses the ScaledObject. Remove the annotation to unpause.",
                details={"paused_value": paused},
            )
        else:
            return PolicyCheckResult(
                check_id="keda_paused_annotation",
                name="KEDA Paused Annotation",
                passed=False,
                severity="medium",
                message="ScaledObject is explicitly paused. Autoscaling is disabled.",
                details={"paused_value": paused},
            )

    return PolicyCheckResult(
        check_id="keda_paused_annotation",
        name="KEDA Paused Annotation",
        passed=True,
        severity="medium",
        message="ScaledObject is not paused.",
    )
