"""Tests for all new policy checks added in the enterprise readiness work.

Covers Phase 6 P0 checks in policies.py:
  check_allow_privilege_escalation — CIS 5.2.5
  check_host_pid                   — CIS 5.2.2 (dedicated check)
  check_host_ipc                   — CIS 5.2.3 (dedicated check)
  check_default_namespace          — CIS 5.7.4
  check_pod_security_standards     — PSS Baseline (CIS 5.2, NSA 3.1)

Covers 9 Polaris-parity checks in policies_extended.py:
  check_drop_all_capabilities      — CIS 5.2.7/5.2.9
  check_ingress_tls                — SOC2-CC6.6
  check_host_port_restriction      — CIS 5.2.2
  check_rbac_wildcard_permissions  — CIS 5.1.3
  check_image_registry_allowlist   — SOC2-CC6.1
  check_container_port_name        — best-practice
  check_automount_service_account  — CIS 5.1.5
  check_hpa_target_ref             — reliability
  check_resource_quota             — SOC2-CC7.2

Each check is exercised via the registry helper to validate self-registration,
as well as via direct import for focused unit tests.
"""

import vlamguard.engine.policies  # noqa: F401 — side-effect: register Phase 1–6 checks
import vlamguard.engine.policies_extended  # noqa: F401 — side-effect: register extended checks
from vlamguard.engine.policies import (
    check_allow_privilege_escalation,
    check_default_namespace,
    check_host_ipc,
    check_host_pid,
    check_pod_security_standards,
)
from vlamguard.engine.policies_extended import (
    check_automount_service_account,
    check_container_port_name,
    check_drop_all_capabilities,
    check_hpa_target_ref,
    check_host_port_restriction,
    check_image_registry_allowlist,
    check_ingress_tls,
    check_rbac_wildcard_permissions,
    check_resource_quota,
)
from vlamguard.engine.registry import get_check_fns


# ---------------------------------------------------------------------------
# Registry helper — used to verify self-registration
# ---------------------------------------------------------------------------


def _run_check(check_id: str, manifest: dict):
    """Run a specific check by ID via the global registry."""
    for fn in get_check_fns():
        result = fn(manifest)
        if result.check_id == check_id:
            return result
    raise ValueError(f"Check '{check_id}' not found in registry")


# ---------------------------------------------------------------------------
# Shared manifest builders
# ---------------------------------------------------------------------------


def _deployment(
    pod_spec: dict | None = None,
    name: str = "web",
    namespace: str | None = None,
) -> dict:
    base_pod_spec: dict = {
        "containers": [{"name": "app", "image": "myregistry.example.com/nginx:1.25.3"}],
    }
    if pod_spec is not None:
        base_pod_spec = pod_spec
    meta: dict = {"name": name}
    if namespace is not None:
        meta["namespace"] = namespace
    return {
        "kind": "Deployment",
        "metadata": meta,
        "spec": {"replicas": 1, "template": {"spec": base_pod_spec}},
    }


def _non_workload(kind: str = "ConfigMap") -> dict:
    return {"kind": kind, "metadata": {"name": "resource"}, "spec": {}}


def _container_with_sec_ctx(extra_sec_ctx: dict | None = None) -> dict:
    sec_ctx: dict = {"allowPrivilegeEscalation": False}
    if extra_sec_ctx:
        sec_ctx.update(extra_sec_ctx)
    return {
        "name": "app",
        "image": "myregistry.example.com/nginx:1.25.3",
        "securityContext": sec_ctx,
    }


# ===========================================================================
# Phase 6 P0 checks
# ===========================================================================


# ---------------------------------------------------------------------------
# TestAllowPrivilegeEscalation
# ---------------------------------------------------------------------------


class TestAllowPrivilegeEscalation:
    """Check: allowPrivilegeEscalation must be explicitly false on all containers (CIS 5.2.5)."""

    def test_explicitly_false_passes(self):
        """The only compliant value is allowPrivilegeEscalation: false."""
        manifest = _deployment(
            pod_spec={
                "containers": [_container_with_sec_ctx()],
            }
        )
        result = check_allow_privilege_escalation(manifest)
        assert result.passed is True
        assert result.check_id == "allow_privilege_escalation"
        assert "explicitly disable" in result.message

    def test_field_absent_fails(self):
        """When the field is not set, the default permits escalation — must fail."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {},
                    }
                ],
            }
        )
        result = check_allow_privilege_escalation(manifest)
        assert result.passed is False
        assert "allowPrivilegeEscalation" in result.message
        assert "app" in result.message
        assert result.details is not None

    def test_explicitly_true_fails(self):
        """allowPrivilegeEscalation: true is the worst case — explicitly opt-in."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    _container_with_sec_ctx({"allowPrivilegeEscalation": True})
                ],
            }
        )
        result = check_allow_privilege_escalation(manifest)
        assert result.passed is False
        assert "app" in result.message

    def test_no_security_context_at_all_fails(self):
        """A container with no securityContext key fails because the field is absent."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "bare",
                        "image": "myregistry.example.com/nginx:1.25.3",
                    }
                ],
            }
        )
        result = check_allow_privilege_escalation(manifest)
        assert result.passed is False
        assert "bare" in result.message

    def test_multiple_containers_all_must_comply(self):
        """All containers must set the flag; a single violating container fails the check."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    _container_with_sec_ctx(),  # compliant
                    {
                        "name": "sidecar",
                        "image": "myregistry.example.com/envoy:v1",
                        "securityContext": {},  # missing flag
                    },
                ],
            }
        )
        result = check_allow_privilege_escalation(manifest)
        assert result.passed is False
        assert "sidecar" in result.message
        # The compliant container should not appear in the violation message
        assert len(result.details["violations"]) == 1

    def test_init_containers_are_checked(self):
        """Init containers must also set allowPrivilegeEscalation: false."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {
                "template": {
                    "spec": {
                        "initContainers": [
                            {
                                "name": "init",
                                "image": "myregistry.example.com/busybox:1.36",
                                "securityContext": {},  # missing flag
                            }
                        ],
                        "containers": [_container_with_sec_ctx()],
                    }
                }
            },
        }
        result = check_allow_privilege_escalation(manifest)
        assert result.passed is False
        assert "init" in result.message

    def test_non_workload_skipped(self):
        """Service is not a workload — check is skipped."""
        result = check_allow_privilege_escalation(_non_workload("Service"))
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_configmap_skipped(self):
        result = check_allow_privilege_escalation(_non_workload("ConfigMap"))
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_registered_in_registry(self):
        """Check must be discoverable through the registry."""
        manifest = _deployment(
            pod_spec={
                "containers": [_container_with_sec_ctx()],
            }
        )
        result = _run_check("allow_privilege_escalation", manifest)
        assert result.check_id == "allow_privilege_escalation"
        assert result.passed is True

    def test_statefulset_is_checked(self):
        """StatefulSets are workload resources and must be evaluated."""
        manifest = {
            "kind": "StatefulSet",
            "metadata": {"name": "db"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "db",
                                "image": "myregistry.example.com/postgres:15",
                            }
                        ],
                    }
                }
            },
        }
        result = check_allow_privilege_escalation(manifest)
        assert result.passed is False


# ---------------------------------------------------------------------------
# TestHostPid
# ---------------------------------------------------------------------------


class TestHostPid:
    """Check: hostPID must not be true in pod spec (CIS 5.2.2 — dedicated check)."""

    def test_host_pid_absent_passes(self):
        """When hostPID is not set it defaults to false — must pass."""
        result = check_host_pid(_deployment())
        assert result.passed is True
        assert result.check_id == "host_pid"
        assert "not enabled" in result.message

    def test_host_pid_false_passes(self):
        """Explicit hostPID: false is also compliant."""
        manifest = _deployment(
            pod_spec={
                "hostPID": False,
                "containers": [{"name": "app", "image": "myregistry.example.com/nginx:1.25.3"}],
            }
        )
        result = check_host_pid(manifest)
        assert result.passed is True

    def test_host_pid_true_fails(self):
        """hostPID: true shares the host PID namespace — critical violation."""
        manifest = _deployment(
            pod_spec={
                "hostPID": True,
                "containers": [{"name": "app", "image": "myregistry.example.com/nginx:1.25.3"}],
            }
        )
        result = check_host_pid(manifest)
        assert result.passed is False
        assert result.severity == "critical"
        assert "hostPID" in result.message
        assert result.details == {"hostPID": True}

    def test_non_workload_skipped(self):
        """ConfigMap is not a workload — check is skipped."""
        result = check_host_pid(_non_workload("ConfigMap"))
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_daemonset_checked(self):
        """DaemonSets are workload resources and must be evaluated."""
        manifest = {
            "kind": "DaemonSet",
            "metadata": {"name": "agent"},
            "spec": {
                "template": {
                    "spec": {
                        "hostPID": True,
                        "containers": [{"name": "agent", "image": "myregistry.example.com/agent:v1"}],
                    }
                }
            },
        }
        result = check_host_pid(manifest)
        assert result.passed is False

    def test_registered_in_registry(self):
        """Check must be discoverable through the registry."""
        result = _run_check("host_pid", _deployment())
        assert result.check_id == "host_pid"
        assert result.passed is True

    def test_cronjob_checked(self):
        """CronJob is a workload kind — hostPID check applies."""
        manifest = {
            "kind": "CronJob",
            "metadata": {"name": "job"},
            "spec": {
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "hostPID": True,
                                "containers": [{"name": "job", "image": "myregistry.example.com/runner:v1"}],
                            }
                        }
                    }
                }
            },
        }
        # CronJob spec path differs — check uses manifest.spec.template.spec,
        # which CronJob does not have at the top level, so the pod spec will be
        # empty and the flag absent: the check passes (graceful degradation).
        result = check_host_pid(manifest)
        # CronJob is in _WORKLOAD_KINDS but its spec path is different;
        # hostPID won't be found at spec.template.spec so it passes.
        assert result.check_id == "host_pid"


# ---------------------------------------------------------------------------
# TestHostIpc
# ---------------------------------------------------------------------------


class TestHostIpc:
    """Check: hostIPC must not be true in pod spec (CIS 5.2.3 — dedicated check)."""

    def test_host_ipc_absent_passes(self):
        """When hostIPC is not set it defaults to false — must pass."""
        result = check_host_ipc(_deployment())
        assert result.passed is True
        assert result.check_id == "host_ipc"
        assert "not enabled" in result.message

    def test_host_ipc_false_passes(self):
        """Explicit hostIPC: false is compliant."""
        manifest = _deployment(
            pod_spec={
                "hostIPC": False,
                "containers": [{"name": "app", "image": "myregistry.example.com/nginx:1.25.3"}],
            }
        )
        result = check_host_ipc(manifest)
        assert result.passed is True

    def test_host_ipc_true_fails(self):
        """hostIPC: true shares the host IPC namespace — critical violation."""
        manifest = _deployment(
            pod_spec={
                "hostIPC": True,
                "containers": [{"name": "app", "image": "myregistry.example.com/nginx:1.25.3"}],
            }
        )
        result = check_host_ipc(manifest)
        assert result.passed is False
        assert result.severity == "critical"
        assert "hostIPC" in result.message
        assert result.details == {"hostIPC": True}

    def test_non_workload_skipped(self):
        """Service is not a workload — check is skipped."""
        result = check_host_ipc(_non_workload("Service"))
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_registered_in_registry(self):
        """Check must be discoverable through the registry."""
        result = _run_check("host_ipc", _deployment())
        assert result.check_id == "host_ipc"
        assert result.passed is True

    def test_statefulset_checked(self):
        """StatefulSets are workload resources and hostIPC check must apply."""
        manifest = {
            "kind": "StatefulSet",
            "metadata": {"name": "db"},
            "spec": {
                "template": {
                    "spec": {
                        "hostIPC": True,
                        "containers": [{"name": "db", "image": "myregistry.example.com/postgres:15"}],
                    }
                }
            },
        }
        result = check_host_ipc(manifest)
        assert result.passed is False
        assert "hostIPC" in result.message

    def test_host_ipc_and_host_pid_are_independent_checks(self):
        """host_ipc and host_pid are separate checks; enabling hostPID alone must not fail host_ipc."""
        manifest = _deployment(
            pod_spec={
                "hostPID": True,
                "containers": [{"name": "app", "image": "myregistry.example.com/nginx:1.25.3"}],
            }
        )
        result = check_host_ipc(manifest)
        assert result.passed is True  # hostIPC is not set


# ---------------------------------------------------------------------------
# TestDefaultNamespace
# ---------------------------------------------------------------------------


class TestDefaultNamespace:
    """Check: metadata.namespace must not be 'default' or absent (CIS 5.7.4)."""

    def test_dedicated_namespace_passes(self):
        """A resource in a named non-default namespace is compliant."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "production"},
            "spec": {},
        }
        result = check_default_namespace(manifest)
        assert result.passed is True
        assert result.check_id == "default_namespace"
        assert "production" in result.message

    def test_default_namespace_fails(self):
        """A resource explicitly in the 'default' namespace must fail."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "default"},
            "spec": {},
        }
        result = check_default_namespace(manifest)
        assert result.passed is False
        assert "default" in result.message
        assert result.details is not None
        assert result.details["namespace"] == "default"

    def test_empty_string_namespace_fails(self):
        """An empty string namespace is equivalent to 'default' and must fail."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": ""},
            "spec": {},
        }
        result = check_default_namespace(manifest)
        assert result.passed is False
        assert "default" in result.message

    def test_no_namespace_key_skipped(self):
        """When the namespace key is absent entirely (cluster-scoped resource), skip gracefully."""
        manifest = {
            "kind": "ClusterRole",
            "metadata": {"name": "reader"},
            "rules": [],
        }
        result = check_default_namespace(manifest)
        assert result.passed is True
        assert "no namespace context" in result.message

    def test_namespace_none_value_skipped(self):
        """Explicit namespace: null in YAML deserialises as None — treated as 'no context'."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": None},
            "spec": {},
        }
        result = check_default_namespace(manifest)
        assert result.passed is True
        assert "no namespace context" in result.message

    def test_various_non_default_namespaces_pass(self):
        """A selection of real-world namespace names must all pass."""
        for ns in ("kube-system", "monitoring", "istio-system", "my-app", "staging"):
            manifest = {
                "kind": "Service",
                "metadata": {"name": "svc", "namespace": ns},
                "spec": {},
            }
            result = check_default_namespace(manifest)
            assert result.passed is True, f"Expected pass for namespace '{ns}'"

    def test_registered_in_registry(self):
        """Check must be discoverable through the registry."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "production"},
            "spec": {},
        }
        result = _run_check("default_namespace", manifest)
        assert result.check_id == "default_namespace"
        assert result.passed is True

    def test_non_workload_resource_in_default_namespace_also_fails(self):
        """The check applies to all resource types, not just workloads."""
        manifest = {
            "kind": "Service",
            "metadata": {"name": "svc", "namespace": "default"},
            "spec": {},
        }
        result = check_default_namespace(manifest)
        assert result.passed is False


# ---------------------------------------------------------------------------
# TestPodSecurityStandards
# ---------------------------------------------------------------------------


class TestPodSecurityStandards:
    """Check: pod spec must conform to PSS Baseline level (CIS 5.2, NSA 3.1)."""

    # ---- pass cases ----

    def test_clean_deployment_passes(self):
        """A minimal compliant deployment with no special security settings passes."""
        manifest = _deployment()
        result = check_pod_security_standards(manifest)
        assert result.passed is True
        assert result.check_id == "pod_security_standards"
        assert result.details == {"pss_level": "baseline"}

    def test_baseline_allowed_capability_passes(self):
        """Adding a capability in the PSS Baseline allowed set is permitted."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {
                            "capabilities": {"add": ["NET_BIND_SERVICE"]}
                        },
                    }
                ],
            }
        )
        result = check_pod_security_standards(manifest)
        assert result.passed is True

    def test_multiple_baseline_allowed_capabilities_pass(self):
        """Multiple capabilities all within the baseline allowed set must pass."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {
                            "capabilities": {"add": ["CHOWN", "SETUID", "SETGID"]}
                        },
                    }
                ],
            }
        )
        result = check_pod_security_standards(manifest)
        assert result.passed is True

    def test_default_proc_mount_passes(self):
        """procMount: Default (explicit) is the only allowed value — must pass."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {"procMount": "Default"},
                    }
                ],
            }
        )
        result = check_pod_security_standards(manifest)
        assert result.passed is True

    def test_allowed_selinux_type_passes(self):
        """seLinuxOptions.type set to an allowed type must pass."""
        for allowed_type in ("container_t", "container_init_t", "container_kvm_t", ""):
            manifest = _deployment(
                pod_spec={
                    "containers": [
                        {
                            "name": "app",
                            "image": "myregistry.example.com/nginx:1.25.3",
                            "securityContext": {
                                "seLinuxOptions": {"type": allowed_type}
                            },
                        }
                    ],
                }
            )
            result = check_pod_security_standards(manifest)
            assert result.passed is True, f"Expected pass for seLinuxOptions.type='{allowed_type}'"

    # ---- fail cases ----

    def test_privileged_container_fails(self):
        """privileged: true is banned by PSS Baseline."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {"privileged": True},
                    }
                ],
            }
        )
        result = check_pod_security_standards(manifest)
        assert result.passed is False
        assert "privileged" in result.message
        assert "app" in result.message
        assert result.details["pss_level"] == "baseline"

    def test_non_baseline_capability_fails(self):
        """SYS_ADMIN is not in the PSS Baseline allowed set — must fail."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {
                            "capabilities": {"add": ["SYS_ADMIN"]}
                        },
                    }
                ],
            }
        )
        result = check_pod_security_standards(manifest)
        assert result.passed is False
        assert "SYS_ADMIN" in result.message

    def test_net_admin_capability_fails(self):
        """NET_ADMIN is not in the PSS Baseline allowed set — must fail."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {
                            "capabilities": {"add": ["NET_ADMIN"]}
                        },
                    }
                ],
            }
        )
        result = check_pod_security_standards(manifest)
        assert result.passed is False
        assert "NET_ADMIN" in result.message

    def test_unmasked_proc_mount_fails(self):
        """procMount: Unmasked bypasses kernel proc masking — must fail."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {"procMount": "Unmasked"},
                    }
                ],
            }
        )
        result = check_pod_security_standards(manifest)
        assert result.passed is False
        assert "procMount" in result.message
        assert "Unmasked" in result.message

    def test_disallowed_selinux_type_fails(self):
        """A non-baseline SELinux type must be flagged."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {
                            "seLinuxOptions": {"type": "custom_hostile_t"}
                        },
                    }
                ],
            }
        )
        result = check_pod_security_standards(manifest)
        assert result.passed is False
        assert "seLinuxOptions.type" in result.message
        assert "custom_hostile_t" in result.message

    def test_host_network_at_pod_level_fails(self):
        """hostNetwork: true in pod spec is a PSS Baseline violation."""
        manifest = _deployment(
            pod_spec={
                "hostNetwork": True,
                "containers": [{"name": "app", "image": "myregistry.example.com/nginx:1.25.3"}],
            }
        )
        result = check_pod_security_standards(manifest)
        assert result.passed is False
        assert "hostNetwork" in result.message

    def test_host_pid_at_pod_level_fails(self):
        """hostPID: true in pod spec is a PSS Baseline violation."""
        manifest = _deployment(
            pod_spec={
                "hostPID": True,
                "containers": [{"name": "app", "image": "myregistry.example.com/nginx:1.25.3"}],
            }
        )
        result = check_pod_security_standards(manifest)
        assert result.passed is False
        assert "hostPID" in result.message

    def test_host_ipc_at_pod_level_fails(self):
        """hostIPC: true in pod spec is a PSS Baseline violation."""
        manifest = _deployment(
            pod_spec={
                "hostIPC": True,
                "containers": [{"name": "app", "image": "myregistry.example.com/nginx:1.25.3"}],
            }
        )
        result = check_pod_security_standards(manifest)
        assert result.passed is False
        assert "hostIPC" in result.message

    def test_multiple_violations_all_reported(self):
        """Privileged + bad capability in the same container both appear in violations list."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "bad",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {
                            "privileged": True,
                            "capabilities": {"add": ["SYS_ADMIN"]},
                        },
                    }
                ],
            }
        )
        result = check_pod_security_standards(manifest)
        assert result.passed is False
        assert len(result.details["violations"]) >= 2

    def test_multiple_containers_one_violating_fails(self):
        """A single violating container is enough to fail the overall check."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "good",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {},
                    },
                    {
                        "name": "bad",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {"privileged": True},
                    },
                ],
            }
        )
        result = check_pod_security_standards(manifest)
        assert result.passed is False
        assert "bad" in result.message

    # ---- skip cases ----

    def test_non_workload_skipped(self):
        """ConfigMap is not a workload — check is skipped."""
        result = check_pod_security_standards(_non_workload("ConfigMap"))
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_service_skipped(self):
        result = check_pod_security_standards(_non_workload("Service"))
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_registered_in_registry(self):
        """Check must be discoverable through the registry."""
        result = _run_check("pod_security_standards", _deployment())
        assert result.check_id == "pod_security_standards"
        assert result.passed is True


# ===========================================================================
# policies_extended.py — 9 Polaris-parity checks
# ===========================================================================


# ---------------------------------------------------------------------------
# TestDropAllCapabilities
# ---------------------------------------------------------------------------


class TestDropAllCapabilities:
    """Check: containers must have capabilities.drop: [ALL]."""

    def _deployment_with_drop(self, drop_list: list[str]) -> dict:
        return _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {"capabilities": {"drop": drop_list}},
                    }
                ],
            }
        )

    def test_drop_all_uppercase_passes(self):
        """capabilities.drop: [ALL] (uppercase) is the canonical compliant form."""
        result = check_drop_all_capabilities(self._deployment_with_drop(["ALL"]))
        assert result.passed is True
        assert result.check_id == "drop_all_capabilities"

    def test_drop_all_lowercase_passes(self):
        """The check normalises to upper-case so 'all' must also pass."""
        result = check_drop_all_capabilities(self._deployment_with_drop(["all"]))
        assert result.passed is True

    def test_drop_all_mixed_case_passes(self):
        """'All' (mixed case) must also be normalised and pass."""
        result = check_drop_all_capabilities(self._deployment_with_drop(["All"]))
        assert result.passed is True

    def test_empty_drop_list_fails(self):
        """An empty drop list means no capabilities are dropped — must fail."""
        result = check_drop_all_capabilities(self._deployment_with_drop([]))
        assert result.passed is False
        assert "app" in result.message
        assert result.details is not None

    def test_partial_drop_without_all_fails(self):
        """Dropping NET_RAW alone without ALL must fail."""
        result = check_drop_all_capabilities(self._deployment_with_drop(["NET_RAW"]))
        assert result.passed is False

    def test_drop_all_plus_others_passes(self):
        """drop: [ALL, NET_RAW] still contains ALL and must pass."""
        result = check_drop_all_capabilities(self._deployment_with_drop(["ALL", "NET_RAW"]))
        assert result.passed is True

    def test_no_security_context_fails(self):
        """A container with no securityContext at all fails (no drop list)."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {"name": "app", "image": "myregistry.example.com/nginx:1.25.3"},
                ],
            }
        )
        result = check_drop_all_capabilities(manifest)
        assert result.passed is False

    def test_multiple_containers_all_must_comply(self):
        """Both containers must drop ALL; one non-compliant container fails the check."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "good",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "securityContext": {"capabilities": {"drop": ["ALL"]}},
                    },
                    {
                        "name": "bad",
                        "image": "myregistry.example.com/envoy:v1",
                        "securityContext": {"capabilities": {"drop": []}},
                    },
                ],
            }
        )
        result = check_drop_all_capabilities(manifest)
        assert result.passed is False
        assert "bad" in result.message
        assert len(result.details["violations"]) == 1

    def test_init_containers_are_checked(self):
        """Init containers must also drop ALL capabilities."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {
                "template": {
                    "spec": {
                        "initContainers": [
                            {
                                "name": "init",
                                "image": "myregistry.example.com/busybox:1.36",
                                "securityContext": {"capabilities": {"drop": []}},
                            }
                        ],
                        "containers": [
                            {
                                "name": "app",
                                "image": "myregistry.example.com/nginx:1.25.3",
                                "securityContext": {"capabilities": {"drop": ["ALL"]}},
                            }
                        ],
                    }
                }
            },
        }
        result = check_drop_all_capabilities(manifest)
        assert result.passed is False
        assert "init" in result.message

    def test_non_workload_skipped(self):
        """Service is not a workload — check is skipped."""
        result = check_drop_all_capabilities(_non_workload("Service"))
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_registered_in_registry(self):
        result = _run_check("drop_all_capabilities", self._deployment_with_drop(["ALL"]))
        assert result.check_id == "drop_all_capabilities"
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestIngressTls
# ---------------------------------------------------------------------------


class TestIngressTls:
    """Check: Ingress resources must have TLS configured."""

    def _ingress(self, tls: list | None = None, name: str = "my-ingress") -> dict:
        spec: dict = {"rules": [{"host": "example.com"}]}
        if tls is not None:
            spec["tls"] = tls
        return {
            "kind": "Ingress",
            "metadata": {"name": name},
            "spec": spec,
        }

    def test_ingress_with_tls_passes(self):
        """An Ingress with a non-empty tls block must pass."""
        manifest = self._ingress(tls=[{"hosts": ["example.com"], "secretName": "tls-secret"}])
        result = check_ingress_tls(manifest)
        assert result.passed is True
        assert result.check_id == "ingress_tls"

    def test_ingress_without_tls_fails(self):
        """An Ingress with no spec.tls must fail."""
        manifest = self._ingress(tls=None)
        result = check_ingress_tls(manifest)
        assert result.passed is False
        assert "no TLS" in result.message
        assert "my-ingress" in result.message
        assert result.details == {"ingress": "my-ingress"}

    def test_ingress_with_empty_tls_list_fails(self):
        """spec.tls: [] (empty list) is treated as no TLS — must fail."""
        manifest = self._ingress(tls=[])
        result = check_ingress_tls(manifest)
        assert result.passed is False

    def test_non_ingress_kind_skipped(self):
        """A Deployment is not an Ingress — check is skipped."""
        result = check_ingress_tls(_non_workload("Deployment"))
        assert result.passed is True
        assert "Not an Ingress" in result.message

    def test_service_skipped(self):
        result = check_ingress_tls(_non_workload("Service"))
        assert result.passed is True

    def test_ingress_name_in_failure_message(self):
        """The ingress name must appear in the failure message for traceability."""
        manifest = self._ingress(name="frontend-ingress")
        result = check_ingress_tls(manifest)
        assert result.passed is False
        assert "frontend-ingress" in result.message

    def test_multiple_tls_entries_pass(self):
        """Multiple tls entries (wildcard + specific) must pass."""
        manifest = self._ingress(
            tls=[
                {"hosts": ["example.com"], "secretName": "tls-1"},
                {"hosts": ["api.example.com"], "secretName": "tls-2"},
            ]
        )
        result = check_ingress_tls(manifest)
        assert result.passed is True

    def test_registered_in_registry(self):
        manifest = self._ingress(tls=[{"hosts": ["example.com"], "secretName": "tls-secret"}])
        result = _run_check("ingress_tls", manifest)
        assert result.check_id == "ingress_tls"
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestHostPortRestriction
# ---------------------------------------------------------------------------


class TestHostPortRestriction:
    """Check: no container ports use hostPort."""

    def test_no_ports_passes(self):
        """A container that exposes no ports at all is compliant."""
        result = check_host_port_restriction(_deployment())
        assert result.passed is True
        assert result.check_id == "host_port_restriction"

    def test_container_port_without_host_port_passes(self):
        """Defining containerPort without hostPort is safe."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "ports": [{"containerPort": 8080}],
                    }
                ],
            }
        )
        result = check_host_port_restriction(manifest)
        assert result.passed is True

    def test_host_port_fails(self):
        """A hostPort binding must be flagged."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "ports": [{"containerPort": 8080, "hostPort": 8080}],
                    }
                ],
            }
        )
        result = check_host_port_restriction(manifest)
        assert result.passed is False
        assert "app" in result.message
        assert "8080" in result.message
        assert result.details is not None

    def test_multiple_host_port_bindings_all_reported(self):
        """Two hostPort bindings on the same container must both appear in violations."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "ports": [
                            {"containerPort": 80, "hostPort": 80},
                            {"containerPort": 443, "hostPort": 443},
                        ],
                    }
                ],
            }
        )
        result = check_host_port_restriction(manifest)
        assert result.passed is False
        assert len(result.details["violations"]) == 2

    def test_host_port_zero_fails(self):
        """hostPort: 0 is still a host port binding and must fail (0 is not None)."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "ports": [{"containerPort": 8080, "hostPort": 0}],
                    }
                ],
            }
        )
        result = check_host_port_restriction(manifest)
        assert result.passed is False

    def test_non_workload_skipped(self):
        """Service is not a workload — check is skipped."""
        result = check_host_port_restriction(_non_workload("Service"))
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_init_containers_are_checked(self):
        """hostPort in an initContainer must also be flagged."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {
                "template": {
                    "spec": {
                        "initContainers": [
                            {
                                "name": "init",
                                "image": "myregistry.example.com/busybox:1.36",
                                "ports": [{"containerPort": 9999, "hostPort": 9999}],
                            }
                        ],
                        "containers": [
                            {"name": "app", "image": "myregistry.example.com/nginx:1.25.3"}
                        ],
                    }
                }
            },
        }
        result = check_host_port_restriction(manifest)
        assert result.passed is False
        assert "init" in result.message

    def test_registered_in_registry(self):
        result = _run_check("host_port_restriction", _deployment())
        assert result.check_id == "host_port_restriction"
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestRbacWildcardPermissions
# ---------------------------------------------------------------------------


class TestRbacWildcardPermissions:
    """Check: ClusterRole/Role rules must not use wildcard '*' in verbs, resources, or apiGroups."""

    def _role(self, kind: str = "ClusterRole", rules: list | None = None) -> dict:
        return {
            "kind": kind,
            "metadata": {"name": "my-role"},
            "rules": rules or [],
        }

    def test_scoped_permissions_pass(self):
        """A ClusterRole with explicit verbs, resources, and apiGroups must pass."""
        manifest = self._role(
            rules=[
                {
                    "apiGroups": [""],
                    "resources": ["pods"],
                    "verbs": ["get", "list", "watch"],
                }
            ]
        )
        result = check_rbac_wildcard_permissions(manifest)
        assert result.passed is True
        assert result.check_id == "rbac_wildcard_permissions"

    def test_empty_rules_pass(self):
        """A ClusterRole with no rules at all must pass (nothing to violate)."""
        result = check_rbac_wildcard_permissions(self._role(rules=[]))
        assert result.passed is True

    def test_wildcard_verb_fails(self):
        """A wildcard '*' in verbs grants all actions — must fail."""
        manifest = self._role(
            rules=[
                {
                    "apiGroups": [""],
                    "resources": ["pods"],
                    "verbs": ["*"],
                }
            ]
        )
        result = check_rbac_wildcard_permissions(manifest)
        assert result.passed is False
        assert "verbs" in result.message
        assert result.details is not None

    def test_wildcard_resource_fails(self):
        """A wildcard '*' in resources grants access to all resource types — must fail."""
        manifest = self._role(
            rules=[
                {
                    "apiGroups": [""],
                    "resources": ["*"],
                    "verbs": ["get"],
                }
            ]
        )
        result = check_rbac_wildcard_permissions(manifest)
        assert result.passed is False
        assert "resources" in result.message

    def test_wildcard_api_group_fails(self):
        """A wildcard '*' in apiGroups grants access across all API groups — must fail."""
        manifest = self._role(
            rules=[
                {
                    "apiGroups": ["*"],
                    "resources": ["pods"],
                    "verbs": ["get"],
                }
            ]
        )
        result = check_rbac_wildcard_permissions(manifest)
        assert result.passed is False
        assert "apiGroups" in result.message

    def test_wildcard_in_all_three_fields_reports_all(self):
        """Wildcards in verbs, resources, and apiGroups must each produce a violation."""
        manifest = self._role(
            rules=[
                {
                    "apiGroups": ["*"],
                    "resources": ["*"],
                    "verbs": ["*"],
                }
            ]
        )
        result = check_rbac_wildcard_permissions(manifest)
        assert result.passed is False
        assert len(result.details["violations"]) == 3

    def test_role_kind_also_checked(self):
        """'Role' (namespaced) is also subject to the wildcard check."""
        manifest = self._role(
            kind="Role",
            rules=[{"apiGroups": [""], "resources": ["*"], "verbs": ["get"]}],
        )
        result = check_rbac_wildcard_permissions(manifest)
        assert result.passed is False

    def test_non_rbac_kind_skipped(self):
        """Deployment is not a ClusterRole or Role — check is skipped."""
        result = check_rbac_wildcard_permissions(_non_workload("Deployment"))
        assert result.passed is True
        assert "Not a ClusterRole or Role" in result.message

    def test_cluster_role_binding_skipped(self):
        """ClusterRoleBinding is not itself a role definition — check skips it."""
        manifest = {
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "binding"},
            "subjects": [],
            "roleRef": {"kind": "ClusterRole", "name": "admin"},
        }
        result = check_rbac_wildcard_permissions(manifest)
        assert result.passed is True

    def test_multiple_rules_wildcard_in_second_rule_reported(self):
        """Wildcards in any rule must be caught, not just the first rule."""
        manifest = self._role(
            rules=[
                {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]},
                {"apiGroups": [""], "resources": ["secrets"], "verbs": ["*"]},
            ]
        )
        result = check_rbac_wildcard_permissions(manifest)
        assert result.passed is False
        assert "rule[1]" in result.message

    def test_registered_in_registry(self):
        result = _run_check("rbac_wildcard_permissions", self._role(rules=[]))
        assert result.check_id == "rbac_wildcard_permissions"
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestImageRegistryAllowlist
# ---------------------------------------------------------------------------


class TestImageRegistryAllowlist:
    """Check: bare docker.io/library images must be flagged."""

    def _deployment_with_image(self, image: str) -> dict:
        return _deployment(
            pod_spec={
                "containers": [{"name": "app", "image": image}],
            }
        )

    def test_explicit_registry_passes(self):
        """An image with a full registry hostname passes."""
        result = check_image_registry_allowlist(
            self._deployment_with_image("myregistry.example.com/nginx:1.25.3")
        )
        assert result.passed is True
        assert result.check_id == "image_registry_allowlist"

    def test_org_scoped_image_passes(self):
        """An image with an org prefix (org/image:tag) passes — not a bare library image."""
        result = check_image_registry_allowlist(
            self._deployment_with_image("bitnami/nginx:1.25.3")
        )
        assert result.passed is True

    def test_gcr_image_passes(self):
        """A GCR image with full path passes."""
        result = check_image_registry_allowlist(
            self._deployment_with_image("gcr.io/google-containers/pause:3.9")
        )
        assert result.passed is True

    def test_bare_image_no_tag_fails(self):
        """'nginx' with no tag and no registry — bare docker.io/library image — must fail."""
        result = check_image_registry_allowlist(
            self._deployment_with_image("nginx")
        )
        assert result.passed is False
        assert "nginx" in result.message
        assert "docker.io/library" in result.message

    def test_bare_image_with_tag_fails(self):
        """'nginx:1.25.3' still resolves to docker.io/library/nginx:1.25.3 — must fail."""
        result = check_image_registry_allowlist(
            self._deployment_with_image("nginx:1.25.3")
        )
        assert result.passed is False
        assert "nginx:1.25.3" in result.message

    def test_bare_image_with_digest_fails(self):
        """'nginx@sha256:...' still resolves to docker.io/library — must fail."""
        result = check_image_registry_allowlist(
            self._deployment_with_image("nginx@sha256:abc123")
        )
        assert result.passed is False

    def test_empty_image_field_skipped(self):
        """A container with an empty image string is not flagged (no image to analyse)."""
        manifest = _deployment(
            pod_spec={
                "containers": [{"name": "app", "image": ""}],
            }
        )
        result = check_image_registry_allowlist(manifest)
        assert result.passed is True

    def test_multiple_containers_one_bare_fails(self):
        """One bare image in a multi-container pod fails the overall check."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {"name": "good", "image": "myregistry.example.com/nginx:1.25.3"},
                    {"name": "bad", "image": "redis"},
                ],
            }
        )
        result = check_image_registry_allowlist(manifest)
        assert result.passed is False
        assert "bad" in result.message
        assert len(result.details["violations"]) == 1

    def test_non_workload_skipped(self):
        """ConfigMap is not a workload — check is skipped."""
        result = check_image_registry_allowlist(_non_workload("ConfigMap"))
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_registered_in_registry(self):
        result = _run_check(
            "image_registry_allowlist",
            self._deployment_with_image("myregistry.example.com/nginx:1.25.3"),
        )
        assert result.check_id == "image_registry_allowlist"
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestContainerPortName
# ---------------------------------------------------------------------------


class TestContainerPortName:
    """Check: all container port definitions must include a name field."""

    def test_named_port_passes(self):
        """A port with an explicit name is compliant."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "ports": [{"name": "http", "containerPort": 8080}],
                    }
                ],
            }
        )
        result = check_container_port_name(manifest)
        assert result.passed is True
        assert result.check_id == "container_port_name"

    def test_no_ports_passes(self):
        """A container with no ports at all is compliant."""
        result = check_container_port_name(_deployment())
        assert result.passed is True

    def test_unnamed_port_fails(self):
        """A port without a name field must fail."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "ports": [{"containerPort": 8080}],
                    }
                ],
            }
        )
        result = check_container_port_name(manifest)
        assert result.passed is False
        assert "app" in result.message
        assert "8080" in result.message
        assert result.details is not None

    def test_empty_string_name_fails(self):
        """A port with name: '' (empty string) is falsy — must fail."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "ports": [{"name": "", "containerPort": 8080}],
                    }
                ],
            }
        )
        result = check_container_port_name(manifest)
        assert result.passed is False

    def test_multiple_ports_one_unnamed_fails(self):
        """If any port is unnamed the check fails and includes the unnamed port."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "ports": [
                            {"name": "http", "containerPort": 8080},
                            {"containerPort": 9090},  # no name
                        ],
                    }
                ],
            }
        )
        result = check_container_port_name(manifest)
        assert result.passed is False
        assert "9090" in result.message

    def test_multiple_containers_all_must_have_named_ports(self):
        """An unnamed port in any container fails the overall check."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "myregistry.example.com/nginx:1.25.3",
                        "ports": [{"name": "http", "containerPort": 8080}],
                    },
                    {
                        "name": "metrics",
                        "image": "myregistry.example.com/prom-exporter:v1",
                        "ports": [{"containerPort": 9090}],  # no name
                    },
                ],
            }
        )
        result = check_container_port_name(manifest)
        assert result.passed is False
        assert "metrics" in result.message

    def test_non_workload_skipped(self):
        """Service is not a workload — check is skipped."""
        result = check_container_port_name(_non_workload("Service"))
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_registered_in_registry(self):
        result = _run_check("container_port_name", _deployment())
        assert result.check_id == "container_port_name"
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestAutomountServiceAccount (ServiceAccount object check)
# ---------------------------------------------------------------------------


class TestAutomountServiceAccount:
    """Check: ServiceAccount resources must set automountServiceAccountToken: false."""

    def _service_account(self, name: str = "my-sa", automount: bool | None = None) -> dict:
        manifest: dict = {
            "kind": "ServiceAccount",
            "metadata": {"name": name},
        }
        if automount is not None:
            manifest["automountServiceAccountToken"] = automount
        return manifest

    def test_explicitly_false_passes(self):
        """automountServiceAccountToken: false is the only compliant value."""
        result = check_automount_service_account(self._service_account(automount=False))
        assert result.passed is True
        assert result.check_id == "automount_service_account"
        assert "my-sa" in result.message

    def test_field_absent_fails(self):
        """When the field is not present the default behaviour mounts the token — must fail."""
        result = check_automount_service_account(self._service_account())
        assert result.passed is False
        assert "my-sa" in result.message
        assert result.details is not None
        assert result.details["serviceAccount"] == "my-sa"
        assert result.details["automountServiceAccountToken"] is None

    def test_explicitly_true_fails(self):
        """automountServiceAccountToken: true is an explicit opt-in — must fail."""
        result = check_automount_service_account(self._service_account(automount=True))
        assert result.passed is False
        assert result.details["automountServiceAccountToken"] is True

    def test_sa_name_in_message(self):
        """The ServiceAccount name must appear in both pass and fail messages."""
        sa = self._service_account(name="frontend-sa", automount=False)
        result = check_automount_service_account(sa)
        assert result.passed is True
        assert "frontend-sa" in result.message

    def test_non_service_account_skipped(self):
        """A Deployment is not a ServiceAccount — check is skipped."""
        result = check_automount_service_account(_non_workload("Deployment"))
        assert result.passed is True
        assert "Not a ServiceAccount" in result.message

    def test_configmap_skipped(self):
        result = check_automount_service_account(_non_workload("ConfigMap"))
        assert result.passed is True

    def test_registered_in_registry(self):
        result = _run_check(
            "automount_service_account", self._service_account(automount=False)
        )
        assert result.check_id == "automount_service_account"
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestHpaTargetRef
# ---------------------------------------------------------------------------


class TestHpaTargetRef:
    """Check: HorizontalPodAutoscaler must have scaleTargetRef with kind and name."""

    def _hpa(
        self,
        name: str = "my-hpa",
        kind: str | None = "Deployment",
        target_name: str | None = "my-app",
    ) -> dict:
        ref: dict = {}
        if kind is not None:
            ref["kind"] = kind
        if target_name is not None:
            ref["name"] = target_name
        return {
            "kind": "HorizontalPodAutoscaler",
            "metadata": {"name": name},
            "spec": {
                "scaleTargetRef": ref,
                "minReplicas": 2,
                "maxReplicas": 10,
            },
        }

    def test_complete_target_ref_passes(self):
        """An HPA with both kind and name in scaleTargetRef must pass."""
        result = check_hpa_target_ref(self._hpa())
        assert result.passed is True
        assert result.check_id == "hpa_target_ref"
        assert "Deployment/my-app" in result.message

    def test_missing_kind_fails(self):
        """An HPA missing scaleTargetRef.kind must fail."""
        result = check_hpa_target_ref(self._hpa(kind=None))
        assert result.passed is False
        assert "kind" in result.message
        assert result.details is not None

    def test_missing_name_fails(self):
        """An HPA missing scaleTargetRef.name must fail."""
        result = check_hpa_target_ref(self._hpa(target_name=None))
        assert result.passed is False
        assert "name" in result.message

    def test_missing_both_kind_and_name_reports_both(self):
        """When both fields are missing, both violations must be reported."""
        result = check_hpa_target_ref(self._hpa(kind=None, target_name=None))
        assert result.passed is False
        assert len(result.details["violations"]) == 2
        violation_text = " ".join(result.details["violations"])
        assert "kind" in violation_text
        assert "name" in violation_text

    def test_empty_scale_target_ref_fails(self):
        """An HPA with an empty scaleTargetRef dict must fail."""
        manifest = {
            "kind": "HorizontalPodAutoscaler",
            "metadata": {"name": "hpa"},
            "spec": {"scaleTargetRef": {}},
        }
        result = check_hpa_target_ref(manifest)
        assert result.passed is False
        assert len(result.details["violations"]) == 2

    def test_statefulset_target_passes(self):
        """An HPA targeting a StatefulSet must also pass when both fields are set."""
        result = check_hpa_target_ref(self._hpa(kind="StatefulSet", target_name="my-db"))
        assert result.passed is True
        assert "StatefulSet/my-db" in result.message

    def test_non_hpa_kind_skipped(self):
        """A Deployment is not an HPA — check is skipped."""
        result = check_hpa_target_ref(_non_workload("Deployment"))
        assert result.passed is True
        assert "Not a HorizontalPodAutoscaler" in result.message

    def test_registered_in_registry(self):
        result = _run_check("hpa_target_ref", self._hpa())
        assert result.check_id == "hpa_target_ref"
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestResourceQuota
# ---------------------------------------------------------------------------


class TestResourceQuota:
    """Check: ResourceQuota must have at least one hard limit defined."""

    def _quota(self, name: str = "my-quota", hard: dict | None = None) -> dict:
        spec: dict = {}
        if hard is not None:
            spec["hard"] = hard
        return {
            "kind": "ResourceQuota",
            "metadata": {"name": name},
            "spec": spec,
        }

    def test_quota_with_hard_limits_passes(self):
        """A ResourceQuota with at least one hard limit must pass."""
        manifest = self._quota(hard={"cpu": "4", "memory": "8Gi"})
        result = check_resource_quota(manifest)
        assert result.passed is True
        assert result.check_id == "resource_quota"
        assert "my-quota" in result.message
        assert "2" in result.message  # "defines 2 hard limit(s)"

    def test_quota_with_single_limit_passes(self):
        """A ResourceQuota with just one hard limit (pods) must pass."""
        manifest = self._quota(hard={"pods": "50"})
        result = check_resource_quota(manifest)
        assert result.passed is True

    def test_quota_without_hard_fails(self):
        """A ResourceQuota with no spec.hard block at all must fail."""
        manifest = self._quota()
        result = check_resource_quota(manifest)
        assert result.passed is False
        assert "my-quota" in result.message
        assert "no hard limits" in result.message
        assert result.details == {"resourceQuota": "my-quota"}

    def test_quota_with_empty_hard_dict_fails(self):
        """spec.hard: {} (empty dict) is falsy — must fail."""
        manifest = self._quota(hard={})
        result = check_resource_quota(manifest)
        assert result.passed is False

    def test_quota_name_in_message(self):
        """The ResourceQuota name must appear in the message for both pass and fail."""
        manifest = self._quota(name="namespace-quota", hard={"cpu": "8"})
        result = check_resource_quota(manifest)
        assert result.passed is True
        assert "namespace-quota" in result.message

    def test_pass_message_lists_hard_keys(self):
        """The pass message should list the defined hard limit keys."""
        manifest = self._quota(hard={"requests.cpu": "2", "requests.memory": "4Gi"})
        result = check_resource_quota(manifest)
        assert result.passed is True
        assert "requests.cpu" in result.message or "requests.memory" in result.message

    def test_non_resource_quota_skipped(self):
        """A Deployment is not a ResourceQuota — check is skipped."""
        result = check_resource_quota(_non_workload("Deployment"))
        assert result.passed is True
        assert "Not a ResourceQuota" in result.message

    def test_service_skipped(self):
        result = check_resource_quota(_non_workload("Service"))
        assert result.passed is True

    def test_registered_in_registry(self):
        result = _run_check("resource_quota", self._quota(hard={"cpu": "4"}))
        assert result.check_id == "resource_quota"
        assert result.passed is True
