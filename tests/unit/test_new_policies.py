"""Tests for the 5 extended security policy checks (Phase 5 — Security Scan).

Covers:
  check_host_namespace          — hostNetwork / hostPID / hostIPC
  check_dangerous_volume_mounts — dangerous hostPath mounts
  check_excessive_capabilities  — SYS_ADMIN / NET_ADMIN / ALL in caps.add
  check_service_account_token   — automountServiceAccountToken not False
  check_exposed_services        — NodePort / LoadBalancer service types
"""

import pytest

from vlamguard.engine.policies import (
    check_dangerous_volume_mounts,
    check_excessive_capabilities,
    check_exposed_services,
    check_host_namespace,
    check_service_account_token,
)


# ---------------------------------------------------------------------------
# Helpers — lightweight manifest builders to keep tests readable
# ---------------------------------------------------------------------------


def _deployment(pod_spec: dict | None = None, name: str = "web") -> dict:
    """Return a minimal Deployment manifest with an optional pod spec override."""
    base_pod_spec: dict = {
        "containers": [{"name": "app", "image": "nginx:1.25.3"}],
    }
    if pod_spec is not None:
        base_pod_spec = pod_spec
    return {
        "kind": "Deployment",
        "metadata": {"name": name},
        "spec": {"replicas": 2, "template": {"spec": base_pod_spec}},
    }


def _service(svc_type: str | None = None) -> dict:
    """Return a minimal Service manifest with an optional type."""
    spec: dict = {"ports": [{"port": 80}]}
    if svc_type is not None:
        spec["type"] = svc_type
    return {"kind": "Service", "metadata": {"name": "svc"}, "spec": spec}


def _non_workload(kind: str = "ConfigMap") -> dict:
    """Return a non-workload manifest (Service, ConfigMap, etc.)."""
    return {"kind": kind, "metadata": {"name": "resource"}, "spec": {}}


# ---------------------------------------------------------------------------
# TestHostNamespace
# ---------------------------------------------------------------------------


class TestHostNamespace:
    def test_no_host_namespaces_passes(self):
        """Pod with no host namespace flags is compliant."""
        manifest = _deployment(
            pod_spec={
                "hostNetwork": False,
                "hostPID": False,
                "hostIPC": False,
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
            }
        )
        result = check_host_namespace(manifest)
        assert result.passed is True
        assert result.message == "No host namespace sharing."

    def test_absent_host_namespace_fields_passes(self):
        """When all three fields are simply absent the check must pass."""
        manifest = _deployment()
        result = check_host_namespace(manifest)
        assert result.passed is True

    def test_host_network_true_fails(self):
        """hostNetwork: true is a critical violation."""
        manifest = _deployment(
            pod_spec={
                "hostNetwork": True,
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
            }
        )
        result = check_host_namespace(manifest)
        assert result.passed is False
        assert "hostNetwork" in result.message
        assert result.details is not None
        assert "hostNetwork is enabled" in result.details["violations"]

    def test_host_pid_true_fails(self):
        """hostPID: true is a critical violation."""
        manifest = _deployment(
            pod_spec={
                "hostPID": True,
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
            }
        )
        result = check_host_namespace(manifest)
        assert result.passed is False
        assert "hostPID" in result.message

    def test_host_ipc_true_fails(self):
        """hostIPC: true is a critical violation."""
        manifest = _deployment(
            pod_spec={
                "hostIPC": True,
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
            }
        )
        result = check_host_namespace(manifest)
        assert result.passed is False
        assert "hostIPC" in result.message

    def test_all_three_enabled_reports_all_violations(self):
        """All three flags set to true must produce three violations."""
        manifest = _deployment(
            pod_spec={
                "hostNetwork": True,
                "hostPID": True,
                "hostIPC": True,
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
            }
        )
        result = check_host_namespace(manifest)
        assert result.passed is False
        assert len(result.details["violations"]) == 3
        violation_text = "; ".join(result.details["violations"])
        assert "hostNetwork" in violation_text
        assert "hostPID" in violation_text
        assert "hostIPC" in violation_text

    def test_non_workload_kind_skipped(self):
        """A Service manifest is not a workload — the check is skipped."""
        result = check_host_namespace(_non_workload("Service"))
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_daemonset_workload_is_checked(self):
        """DaemonSets are workload resources and must be evaluated."""
        manifest = {
            "kind": "DaemonSet",
            "metadata": {"name": "ds"},
            "spec": {
                "template": {
                    "spec": {
                        "hostNetwork": True,
                        "containers": [{"name": "agent", "image": "agent:v1"}],
                    }
                }
            },
        }
        result = check_host_namespace(manifest)
        assert result.passed is False
        assert "hostNetwork" in result.message


# ---------------------------------------------------------------------------
# TestDangerousVolumeMounts
# ---------------------------------------------------------------------------


class TestDangerousVolumeMounts:
    def test_safe_volume_passes(self):
        """An emptyDir volume with no hostPath is compliant."""
        manifest = _deployment(
            pod_spec={
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
                "volumes": [{"name": "tmp", "emptyDir": {}}],
            }
        )
        result = check_dangerous_volume_mounts(manifest)
        assert result.passed is True
        assert result.message == "No dangerous hostPath volume mounts."

    def test_no_volumes_passes(self):
        """A pod with no volumes at all is compliant."""
        result = check_dangerous_volume_mounts(_deployment())
        assert result.passed is True

    def test_docker_sock_hostpath_fails(self):
        """Mounting /var/run/docker.sock is the canonical container escape vector."""
        manifest = _deployment(
            pod_spec={
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
                "volumes": [
                    {"name": "docker-sock", "hostPath": {"path": "/var/run/docker.sock"}}
                ],
            }
        )
        result = check_dangerous_volume_mounts(manifest)
        assert result.passed is False
        assert "/var/run/docker.sock" in result.message
        assert "docker-sock" in result.message

    def test_proc_hostpath_fails(self):
        """Mounting /proc grants direct access to kernel process information."""
        manifest = _deployment(
            pod_spec={
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
                "volumes": [{"name": "proc-vol", "hostPath": {"path": "/proc"}}],
            }
        )
        result = check_dangerous_volume_mounts(manifest)
        assert result.passed is False
        assert "/proc" in result.message

    def test_sys_hostpath_fails(self):
        """/sys hostPath is a known privilege escalation path."""
        manifest = _deployment(
            pod_spec={
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
                "volumes": [{"name": "sys-vol", "hostPath": {"path": "/sys"}}],
            }
        )
        result = check_dangerous_volume_mounts(manifest)
        assert result.passed is False
        assert "/sys" in result.message

    def test_etc_hostpath_fails(self):
        """/etc hostPath exposes sensitive host configuration files."""
        manifest = _deployment(
            pod_spec={
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
                "volumes": [{"name": "etc-vol", "hostPath": {"path": "/etc"}}],
            }
        )
        result = check_dangerous_volume_mounts(manifest)
        assert result.passed is False
        assert "/etc" in result.message

    def test_subpath_of_dangerous_path_fails(self):
        """Mounting a subdirectory of a dangerous path (e.g. /proc/net) must also fail."""
        manifest = _deployment(
            pod_spec={
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
                "volumes": [{"name": "proc-net", "hostPath": {"path": "/proc/net"}}],
            }
        )
        result = check_dangerous_volume_mounts(manifest)
        assert result.passed is False
        assert "/proc/net" in result.message

    def test_safe_hostpath_passes(self):
        """A hostPath to a non-dangerous path like /data must not be flagged."""
        manifest = _deployment(
            pod_spec={
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
                "volumes": [{"name": "data", "hostPath": {"path": "/data/app"}}],
            }
        )
        result = check_dangerous_volume_mounts(manifest)
        assert result.passed is True

    def test_multiple_violations_all_reported(self):
        """Two dangerous volumes must produce two violation entries."""
        manifest = _deployment(
            pod_spec={
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
                "volumes": [
                    {"name": "sock", "hostPath": {"path": "/var/run/docker.sock"}},
                    {"name": "proc", "hostPath": {"path": "/proc"}},
                ],
            }
        )
        result = check_dangerous_volume_mounts(manifest)
        assert result.passed is False
        assert len(result.details["violations"]) == 2

    def test_non_workload_kind_skipped(self):
        """A ConfigMap is not a workload — the check is skipped."""
        result = check_dangerous_volume_mounts(_non_workload("ConfigMap"))
        assert result.passed is True
        assert result.message.endswith("skipped.")


# ---------------------------------------------------------------------------
# TestExcessiveCapabilities
# ---------------------------------------------------------------------------


class TestExcessiveCapabilities:
    def test_no_capabilities_passes(self):
        """A container with no securityContext.capabilities is compliant."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "nginx:1.25.3",
                        "securityContext": {},
                    }
                ],
            }
        )
        result = check_excessive_capabilities(manifest)
        assert result.passed is True
        assert result.message == "No excessive capabilities granted."

    def test_safe_capability_passes(self):
        """Adding a non-dangerous capability (NET_BIND_SERVICE) must pass."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "nginx:1.25.3",
                        "securityContext": {
                            "capabilities": {"add": ["NET_BIND_SERVICE"]}
                        },
                    }
                ],
            }
        )
        result = check_excessive_capabilities(manifest)
        assert result.passed is True

    def test_sys_admin_fails(self):
        """SYS_ADMIN grants near-root host access and must be rejected."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "nginx:1.25.3",
                        "securityContext": {
                            "capabilities": {"add": ["SYS_ADMIN"]}
                        },
                    }
                ],
            }
        )
        result = check_excessive_capabilities(manifest)
        assert result.passed is False
        assert "SYS_ADMIN" in result.message
        assert "app" in result.message

    def test_net_admin_fails(self):
        """NET_ADMIN enables network reconfiguration and must be rejected."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "nginx:1.25.3",
                        "securityContext": {
                            "capabilities": {"add": ["NET_ADMIN"]}
                        },
                    }
                ],
            }
        )
        result = check_excessive_capabilities(manifest)
        assert result.passed is False
        assert "NET_ADMIN" in result.message

    def test_all_capability_fails(self):
        """'ALL' grants every Linux capability and is the worst case."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "nginx:1.25.3",
                        "securityContext": {
                            "capabilities": {"add": ["ALL"]}
                        },
                    }
                ],
            }
        )
        result = check_excessive_capabilities(manifest)
        assert result.passed is False
        assert "ALL" in result.message

    def test_multiple_dangerous_caps_in_one_container(self):
        """Both SYS_ADMIN and NET_ADMIN in a single container must both appear."""
        manifest = _deployment(
            pod_spec={
                "containers": [
                    {
                        "name": "app",
                        "image": "nginx:1.25.3",
                        "securityContext": {
                            "capabilities": {"add": ["SYS_ADMIN", "NET_ADMIN"]}
                        },
                    }
                ],
            }
        )
        result = check_excessive_capabilities(manifest)
        assert result.passed is False
        assert "SYS_ADMIN" in result.message
        assert "NET_ADMIN" in result.message

    def test_dangerous_cap_in_init_container_fails(self):
        """Init containers are also checked — SYS_ADMIN in initContainers must fail."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {
                "template": {
                    "spec": {
                        "initContainers": [
                            {
                                "name": "init",
                                "image": "busybox:1.36",
                                "securityContext": {
                                    "capabilities": {"add": ["SYS_ADMIN"]}
                                },
                            }
                        ],
                        "containers": [{"name": "app", "image": "nginx:1.25.3"}],
                    }
                }
            },
        }
        result = check_excessive_capabilities(manifest)
        assert result.passed is False
        assert "init" in result.message

    def test_non_workload_kind_skipped(self):
        """A Service is not a workload — the check is skipped."""
        result = check_excessive_capabilities(_non_workload("Service"))
        assert result.passed is True
        assert result.message.endswith("skipped.")


# ---------------------------------------------------------------------------
# TestServiceAccountToken
# ---------------------------------------------------------------------------


class TestServiceAccountToken:
    def test_explicitly_false_passes(self):
        """automountServiceAccountToken: false is the only compliant value."""
        manifest = _deployment(
            pod_spec={
                "automountServiceAccountToken": False,
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
            }
        )
        result = check_service_account_token(manifest)
        assert result.passed is True
        assert result.message == "Service account token auto-mount is disabled."

    def test_absent_field_fails(self):
        """When the field is missing the default is to mount the token — must fail."""
        manifest = _deployment()
        result = check_service_account_token(manifest)
        assert result.passed is False
        assert "automountServiceAccountToken" in result.message
        assert result.details["automountServiceAccountToken"] is None

    def test_explicitly_true_fails(self):
        """automountServiceAccountToken: true is an explicit opt-in — must fail."""
        manifest = _deployment(
            pod_spec={
                "automountServiceAccountToken": True,
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
            }
        )
        result = check_service_account_token(manifest)
        assert result.passed is False
        assert result.details["automountServiceAccountToken"] is True

    def test_details_reflect_actual_value(self):
        """The details dict must capture the actual automount value for audit trails."""
        manifest = _deployment(
            pod_spec={
                "automountServiceAccountToken": True,
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
            }
        )
        result = check_service_account_token(manifest)
        assert result.details is not None
        assert result.details["automountServiceAccountToken"] is True

    def test_non_workload_kind_skipped(self):
        """A ConfigMap is not a workload — the check is skipped."""
        result = check_service_account_token(_non_workload("ConfigMap"))
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_statefulset_is_also_checked(self):
        """StatefulSets are workload resources and must be evaluated."""
        manifest = {
            "kind": "StatefulSet",
            "metadata": {"name": "db"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{"name": "db", "image": "postgres:15"}],
                    }
                }
            },
        }
        result = check_service_account_token(manifest)
        assert result.passed is False


# ---------------------------------------------------------------------------
# TestExposedServices
# ---------------------------------------------------------------------------


class TestExposedServices:
    def test_clusterip_passes(self):
        """ClusterIP is internal — this is the safe default."""
        result = check_exposed_services(_service("ClusterIP"))
        assert result.passed is True
        assert "ClusterIP" in result.message
        assert "(internal)" in result.message

    def test_default_no_type_passes(self):
        """When no type is set Kubernetes defaults to ClusterIP — must pass."""
        result = check_exposed_services(_service())
        assert result.passed is True

    def test_nodeport_fails(self):
        """NodePort exposes the service on every node's IP — must be flagged."""
        result = check_exposed_services(_service("NodePort"))
        assert result.passed is False
        assert "NodePort" in result.message
        assert result.details["type"] == "NodePort"

    def test_loadbalancer_fails(self):
        """LoadBalancer provisions an external load balancer — must be flagged."""
        result = check_exposed_services(_service("LoadBalancer"))
        assert result.passed is False
        assert "LoadBalancer" in result.message
        assert result.details["type"] == "LoadBalancer"

    def test_external_name_passes(self):
        """ExternalName is a DNS alias, not externally exposed — must pass."""
        result = check_exposed_services(_service("ExternalName"))
        assert result.passed is True

    def test_non_service_kind_skipped(self):
        """A Deployment manifest is not a Service — the check is skipped."""
        result = check_exposed_services(_non_workload("Deployment"))
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_configmap_skipped(self):
        """A ConfigMap is not a Service — the check is skipped."""
        result = check_exposed_services(_non_workload("ConfigMap"))
        assert result.passed is True
        assert result.message.endswith("skipped.")
