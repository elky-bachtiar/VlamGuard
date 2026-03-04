"""Tests for the deterministic policy checks."""

import pytest

from vlamguard.engine.policies import (
    check_cronjob_deadline,
    check_deployment_strategy,
    check_env_var_duplicates,
    check_host_pod_anti_affinity,
    check_image_pull_policy,
    check_image_tag,
    check_liveness_readiness_probes,
    check_network_policy,
    check_pod_disruption_budget,
    check_rbac_scope,
    check_readonly_root_fs,
    check_replica_count,
    check_resource_limits,
    check_run_as_user_group,
    check_security_context,
    check_service_type,
    check_stable_api_version,
)


class TestImageTagPolicy:
    def test_explicit_tag_passes(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "nginx:1.25.3"}]}}},
        }
        result = check_image_tag(manifest)
        assert result.passed is True

    def test_latest_tag_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "nginx:latest"}]}}},
        }
        result = check_image_tag(manifest)
        assert result.passed is False
        assert "latest" in result.message.lower()

    def test_no_tag_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "nginx"}]}}},
        }
        result = check_image_tag(manifest)
        assert result.passed is False

    def test_multiple_containers_all_checked(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3"},
                {"name": "sidecar", "image": "envoy:latest"},
            ]}}},
        }
        result = check_image_tag(manifest)
        assert result.passed is False

    def test_init_containers_checked(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {
                "initContainers": [{"name": "init", "image": "busybox:latest"}],
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
            }}},
        }
        result = check_image_tag(manifest)
        assert result.passed is False

    def test_non_workload_skipped(self):
        manifest = {"kind": "ConfigMap", "metadata": {"name": "config"}, "data": {"key": "value"}}
        result = check_image_tag(manifest)
        assert result.passed is True


class TestSecurityContext:
    def test_secure_context_passes(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "securityContext": {"runAsNonRoot": True, "privileged": False}},
            ]}}},
        }
        result = check_security_context(manifest)
        assert result.passed is True

    def test_privileged_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "securityContext": {"privileged": True}},
            ]}}},
        }
        result = check_security_context(manifest)
        assert result.passed is False
        assert "privileged" in result.message.lower()

    def test_missing_security_context_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "nginx:1.25.3"}]}}},
        }
        result = check_security_context(manifest)
        assert result.passed is False

    def test_run_as_root_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "securityContext": {"runAsNonRoot": False, "privileged": False}},
            ]}}},
        }
        result = check_security_context(manifest)
        assert result.passed is False

    def test_non_workload_skipped(self):
        manifest = {"kind": "Service", "metadata": {"name": "svc"}, "spec": {"ports": [{"port": 80}]}}
        result = check_security_context(manifest)
        assert result.passed is True


class TestRBACScope:
    def test_custom_sa_passes(self):
        manifest = {
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "admin-binding"},
            "subjects": [{"kind": "ServiceAccount", "name": "custom-sa", "namespace": "kube-system"}],
            "roleRef": {"kind": "ClusterRole", "name": "admin"},
        }
        result = check_rbac_scope(manifest)
        assert result.passed is True

    def test_default_sa_fails(self):
        manifest = {
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "bad-binding"},
            "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "production"}],
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
        }
        result = check_rbac_scope(manifest)
        assert result.passed is False
        assert "default" in result.message.lower()

    def test_non_rbac_resource_skipped(self):
        manifest = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {}}
        result = check_rbac_scope(manifest)
        assert result.passed is True

    def test_role_binding_not_checked(self):
        manifest = {
            "kind": "RoleBinding",
            "metadata": {"name": "local-binding"},
            "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "dev"}],
            "roleRef": {"kind": "Role", "name": "editor"},
        }
        result = check_rbac_scope(manifest)
        assert result.passed is True


class TestResourceLimits:
    def test_full_resources_passes(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "resources": {
                    "requests": {"cpu": "100m", "memory": "128Mi"},
                    "limits": {"cpu": "500m", "memory": "256Mi"},
                }},
            ]}}},
        }
        result = check_resource_limits(manifest)
        assert result.passed is True

    def test_missing_limits_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "resources": {
                    "requests": {"cpu": "100m", "memory": "128Mi"},
                }},
            ]}}},
        }
        result = check_resource_limits(manifest)
        assert result.passed is False

    def test_missing_resources_entirely_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "nginx:1.25.3"}]}}},
        }
        result = check_resource_limits(manifest)
        assert result.passed is False

    def test_non_workload_skipped(self):
        manifest = {"kind": "ConfigMap", "metadata": {"name": "cfg"}, "data": {}}
        result = check_resource_limits(manifest)
        assert result.passed is True


class TestReplicaCount:
    def test_three_replicas_passes(self):
        manifest = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {"replicas": 3}}
        result = check_replica_count(manifest)
        assert result.passed is True

    def test_one_replica_fails(self):
        manifest = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {"replicas": 1}}
        result = check_replica_count(manifest)
        assert result.passed is False
        assert "1" in result.message

    def test_missing_replicas_field_fails(self):
        manifest = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {}}
        result = check_replica_count(manifest)
        assert result.passed is False

    def test_non_workload_skipped(self):
        manifest = {"kind": "Service", "metadata": {"name": "svc"}, "spec": {}}
        result = check_replica_count(manifest)
        assert result.passed is True

    def test_two_replicas_passes(self):
        manifest = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {"replicas": 2}}
        result = check_replica_count(manifest)
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestResourceLimitsMissingFields (lines 203-206)
# ---------------------------------------------------------------------------


class TestResourceLimitsMissingRequestFields:
    """Cover the individual missing-field branches inside resource_limits."""

    def test_missing_requests_cpu_fails(self):
        """A container with only requests.memory (no requests.cpu) must fail (line 204)."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "resources": {
                    "requests": {"memory": "128Mi"},
                    "limits": {"cpu": "500m", "memory": "256Mi"},
                }},
            ]}}},
        }
        result = check_resource_limits(manifest)
        assert result.passed is False
        assert "requests.cpu" in result.message

    def test_missing_requests_memory_fails(self):
        """A container missing requests.memory must fail (line 206)."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "resources": {
                    "requests": {"cpu": "100m"},
                    "limits": {"cpu": "500m", "memory": "256Mi"},
                }},
            ]}}},
        }
        result = check_resource_limits(manifest)
        assert result.passed is False
        assert "requests.memory" in result.message

    def test_missing_multiple_fields_all_listed(self):
        """Both requests.cpu and requests.memory missing must appear in violation message."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "resources": {
                    "requests": {},
                    "limits": {"cpu": "500m", "memory": "256Mi"},
                }},
            ]}}},
        }
        result = check_resource_limits(manifest)
        assert result.passed is False
        assert "requests.cpu" in result.message
        assert "requests.memory" in result.message


# ---------------------------------------------------------------------------
# TestReadonlyRootFsSkip (line 292)
# ---------------------------------------------------------------------------


class TestReadonlyRootFsNonWorkload:
    def test_non_workload_skipped(self):
        """Service is not a workload — readonly_root_fs is skipped (line 292)."""
        manifest = {"kind": "Service", "metadata": {"name": "svc"}, "spec": {"ports": [{"port": 80}]}}
        result = check_readonly_root_fs(manifest)
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_configmap_skipped(self):
        """ConfigMap is not a workload — readonly_root_fs is skipped."""
        manifest = {"kind": "ConfigMap", "metadata": {"name": "cfg"}, "data": {}}
        result = check_readonly_root_fs(manifest)
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_deployment_container_without_readonly_fails(self):
        """A Deployment container without readOnlyRootFilesystem: true must fail."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "securityContext": {}},
            ]}}},
        }
        result = check_readonly_root_fs(manifest)
        assert result.passed is False
        assert "readOnlyRootFilesystem" in result.message

    def test_deployment_container_with_readonly_passes(self):
        """readOnlyRootFilesystem: true must pass."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "securityContext": {"readOnlyRootFilesystem": True}},
            ]}}},
        }
        result = check_readonly_root_fs(manifest)
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestRunAsUserGroupNonWorkload (line 339)
# ---------------------------------------------------------------------------


class TestRunAsUserGroupNonWorkload:
    def test_non_workload_skipped(self):
        """Service is not a workload — run_as_user_group is skipped (line 339)."""
        manifest = {"kind": "Service", "metadata": {"name": "svc"}, "spec": {}}
        result = check_run_as_user_group(manifest)
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_deployment_with_valid_uid_gid_passes(self):
        """runAsUser > 0 and runAsGroup > 0 at pod level must pass."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {
                "securityContext": {"runAsUser": 1000, "runAsGroup": 2000},
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
            }}},
        }
        result = check_run_as_user_group(manifest)
        assert result.passed is True

    def test_deployment_with_root_uid_fails(self):
        """runAsUser: 0 at container level must fail."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {
                "containers": [
                    {"name": "app", "image": "nginx:1.25.3", "securityContext": {"runAsUser": 0, "runAsGroup": 1000}},
                ],
            }}},
        }
        result = check_run_as_user_group(manifest)
        assert result.passed is False
        assert "runAsUser" in result.message


# ---------------------------------------------------------------------------
# TestLivenessReadinessProbesNonWorkload (line 403)
# ---------------------------------------------------------------------------


class TestLivenessReadinessProbesNonWorkload:
    def test_non_workload_skipped(self):
        """ConfigMap is not a workload — liveness_readiness_probes is skipped (line 403)."""
        manifest = {"kind": "ConfigMap", "metadata": {"name": "cfg"}, "data": {}}
        result = check_liveness_readiness_probes(manifest)
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_deployment_without_probes_fails(self):
        """Deployment containers with no probes must fail."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "nginx:1.25.3"}]}}},
        }
        result = check_liveness_readiness_probes(manifest)
        assert result.passed is False
        assert "livenessProbe" in result.message

    def test_deployment_with_both_probes_passes(self):
        """Deployment containers with both probes must pass."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {
                    "name": "app",
                    "image": "nginx:1.25.3",
                    "livenessProbe": {"httpGet": {"path": "/healthz", "port": 8080}},
                    "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
                },
            ]}}},
        }
        result = check_liveness_readiness_probes(manifest)
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestDeploymentStrategyBranches (lines 450, 461)
# ---------------------------------------------------------------------------


class TestDeploymentStrategyBranches:
    def test_non_deployment_skipped(self):
        """StatefulSet is not a Deployment — deployment_strategy is skipped (line 450)."""
        manifest = {
            "kind": "StatefulSet",
            "metadata": {"name": "db"},
            "spec": {"replicas": 1},
        }
        result = check_deployment_strategy(manifest)
        assert result.passed is True
        assert result.message == "Not a Deployment, skipped."

    def test_recreate_strategy_fails(self):
        """Deployment with Recreate strategy must fail (line 461)."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"strategy": {"type": "Recreate"}},
        }
        result = check_deployment_strategy(manifest)
        assert result.passed is False
        assert "Recreate" in result.message
        assert result.details["strategy"] == "Recreate"

    def test_rolling_update_strategy_passes(self):
        """Deployment with RollingUpdate must pass."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"strategy": {"type": "RollingUpdate"}},
        }
        result = check_deployment_strategy(manifest)
        assert result.passed is True

    def test_default_strategy_passes(self):
        """Deployment without explicit strategy defaults to RollingUpdate — must pass."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {},
        }
        result = check_deployment_strategy(manifest)
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestPodDisruptionBudgetBranches (lines 499-513)
# ---------------------------------------------------------------------------


class TestPodDisruptionBudgetBranches:
    def test_non_pdb_skipped(self):
        """Non-PDB manifests are skipped."""
        manifest = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {}}
        result = check_pod_disruption_budget(manifest)
        assert result.passed is True
        assert "Not a PodDisruptionBudget" in result.message

    def test_pdb_without_min_or_max_fails(self):
        """PDB with neither minAvailable nor maxUnavailable must fail (lines 499-511)."""
        manifest = {
            "kind": "PodDisruptionBudget",
            "metadata": {"name": "my-pdb"},
            "spec": {"selector": {"matchLabels": {"app": "web"}}},
        }
        result = check_pod_disruption_budget(manifest)
        assert result.passed is False
        assert "neither minAvailable nor maxUnavailable" in result.message
        assert result.details is not None

    def test_pdb_with_min_available_passes(self):
        """PDB with minAvailable must pass (line 513)."""
        manifest = {
            "kind": "PodDisruptionBudget",
            "metadata": {"name": "my-pdb"},
            "spec": {"minAvailable": 1, "selector": {"matchLabels": {"app": "web"}}},
        }
        result = check_pod_disruption_budget(manifest)
        assert result.passed is True

    def test_pdb_with_max_unavailable_passes(self):
        """PDB with maxUnavailable must pass."""
        manifest = {
            "kind": "PodDisruptionBudget",
            "metadata": {"name": "my-pdb"},
            "spec": {"maxUnavailable": 1, "selector": {"matchLabels": {"app": "web"}}},
        }
        result = check_pod_disruption_budget(manifest)
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestHostPodAntiAffinitySingleReplica (line 534)
# ---------------------------------------------------------------------------


class TestHostPodAntiAffinitySingleReplica:
    def test_single_replica_skipped(self):
        """Deployment with 1 replica — anti-affinity not required (line 534)."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"replicas": 1, "template": {"spec": {
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
            }}},
        }
        result = check_host_pod_anti_affinity(manifest)
        assert result.passed is True
        assert "Single replica" in result.message

    def test_non_scalable_kind_skipped(self):
        """DaemonSet is not in _SCALABLE_KINDS — check is skipped."""
        manifest = {"kind": "DaemonSet", "metadata": {"name": "ds"}, "spec": {}}
        result = check_host_pod_anti_affinity(manifest)
        assert result.passed is True
        assert "Not a scalable workload" in result.message

    def test_multiple_replicas_without_anti_affinity_fails(self):
        """Deployment with 3 replicas and no podAntiAffinity must fail."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"replicas": 3, "template": {"spec": {
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
            }}},
        }
        result = check_host_pod_anti_affinity(manifest)
        assert result.passed is False
        assert "replicas" in result.message

    def test_multiple_replicas_with_anti_affinity_passes(self):
        """Deployment with replicas > 1 and podAntiAffinity must pass."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"replicas": 3, "template": {"spec": {
                "affinity": {"podAntiAffinity": {"preferredDuringSchedulingIgnoredDuringExecution": []}},
                "containers": [{"name": "app", "image": "nginx:1.25.3"}],
            }}},
        }
        result = check_host_pod_anti_affinity(manifest)
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestImagePullPolicyNonWorkload (line 605)
# ---------------------------------------------------------------------------


class TestImagePullPolicyNonWorkload:
    def test_non_workload_skipped(self):
        """ConfigMap is not a workload — image_pull_policy is skipped (line 605)."""
        manifest = {"kind": "ConfigMap", "metadata": {"name": "cfg"}, "data": {}}
        result = check_image_pull_policy(manifest)
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_service_skipped(self):
        """Service is not a workload — image_pull_policy is skipped."""
        manifest = {"kind": "Service", "metadata": {"name": "svc"}, "spec": {}}
        result = check_image_pull_policy(manifest)
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_always_pull_policy_passes(self):
        """imagePullPolicy: Always must pass."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "imagePullPolicy": "Always"},
            ]}}},
        }
        result = check_image_pull_policy(manifest)
        assert result.passed is True

    def test_ifnotpresent_pull_policy_fails(self):
        """imagePullPolicy: IfNotPresent must fail."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "imagePullPolicy": "IfNotPresent"},
            ]}}},
        }
        result = check_image_pull_policy(manifest)
        assert result.passed is False
        assert "IfNotPresent" in result.message

    def test_missing_pull_policy_fails(self):
        """Missing imagePullPolicy must fail with 'unset' in message."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3"},
            ]}}},
        }
        result = check_image_pull_policy(manifest)
        assert result.passed is False
        assert "unset" in result.message


# ---------------------------------------------------------------------------
# TestServiceTypeBranches (lines 659-671)
# ---------------------------------------------------------------------------


class TestServiceTypeBranches:
    def test_non_service_skipped(self):
        """Non-Service kind is skipped."""
        manifest = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {}}
        result = check_service_type(manifest)
        assert result.passed is True
        assert "Not a Service" in result.message

    def test_nodeport_fails(self):
        """NodePort service type must fail (lines 661-669)."""
        manifest = {
            "kind": "Service",
            "metadata": {"name": "svc"},
            "spec": {"type": "NodePort", "ports": [{"port": 80}]},
        }
        result = check_service_type(manifest)
        assert result.passed is False
        assert "NodePort" in result.message
        assert result.details["type"] == "NodePort"

    def test_clusterip_passes(self):
        """ClusterIP service type must pass (line 671)."""
        manifest = {
            "kind": "Service",
            "metadata": {"name": "svc"},
            "spec": {"type": "ClusterIP", "ports": [{"port": 80}]},
        }
        result = check_service_type(manifest)
        assert result.passed is True
        assert "ClusterIP" in result.message

    def test_loadbalancer_passes(self):
        """LoadBalancer is allowed by service_type check (not NodePort)."""
        manifest = {
            "kind": "Service",
            "metadata": {"name": "svc"},
            "spec": {"type": "LoadBalancer", "ports": [{"port": 80}]},
        }
        result = check_service_type(manifest)
        assert result.passed is True

    def test_default_type_passes(self):
        """Service without explicit type defaults to ClusterIP — must pass."""
        manifest = {
            "kind": "Service",
            "metadata": {"name": "svc"},
            "spec": {"ports": [{"port": 80}]},
        }
        result = check_service_type(manifest)
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestNetworkPolicyBranches (lines 700-721)
# ---------------------------------------------------------------------------


class TestNetworkPolicyBranches:
    def test_non_network_policy_skipped(self):
        """Non-NetworkPolicy kinds are skipped."""
        manifest = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {}}
        result = check_network_policy(manifest)
        assert result.passed is True
        assert "Not a NetworkPolicy" in result.message

    def test_missing_pod_selector_fails(self):
        """NetworkPolicy without podSelector must fail (line 703-704)."""
        manifest = {
            "kind": "NetworkPolicy",
            "metadata": {"name": "deny-all"},
            "spec": {
                "ingress": [{}],
            },
        }
        result = check_network_policy(manifest)
        assert result.passed is False
        assert "podSelector" in result.message

    def test_missing_ingress_and_egress_fails(self):
        """NetworkPolicy without ingress or egress rules must fail (lines 708-709)."""
        manifest = {
            "kind": "NetworkPolicy",
            "metadata": {"name": "broken-policy"},
            "spec": {
                "podSelector": {"matchLabels": {"app": "web"}},
            },
        }
        result = check_network_policy(manifest)
        assert result.passed is False
        assert "no ingress or egress rules" in result.message

    def test_both_missing_reports_both_violations(self):
        """NetworkPolicy with both podSelector and rules missing must report both."""
        manifest = {
            "kind": "NetworkPolicy",
            "metadata": {"name": "empty-policy"},
            "spec": {},
        }
        result = check_network_policy(manifest)
        assert result.passed is False
        assert len(result.details["violations"]) == 2
        violation_text = " ".join(result.details["violations"])
        assert "podSelector" in violation_text
        assert "ingress or egress" in violation_text

    def test_valid_network_policy_with_ingress_passes(self):
        """NetworkPolicy with podSelector and ingress rules must pass (line 721)."""
        manifest = {
            "kind": "NetworkPolicy",
            "metadata": {"name": "allow-web"},
            "spec": {
                "podSelector": {"matchLabels": {"app": "web"}},
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": "frontend"}}}]}],
            },
        }
        result = check_network_policy(manifest)
        assert result.passed is True

    def test_valid_network_policy_with_egress_passes(self):
        """NetworkPolicy with podSelector and egress rules must pass."""
        manifest = {
            "kind": "NetworkPolicy",
            "metadata": {"name": "allow-egress"},
            "spec": {
                "podSelector": {"matchLabels": {"app": "backend"}},
                "egress": [{"to": [{"namespaceSelector": {}}]}],
            },
        }
        result = check_network_policy(manifest)
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestCronJobDeadlineBranches (lines 750-760)
# ---------------------------------------------------------------------------


class TestCronJobDeadlineBranches:
    def test_non_cronjob_skipped(self):
        """Non-CronJob kinds are skipped."""
        manifest = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {}}
        result = check_cronjob_deadline(manifest)
        assert result.passed is True
        assert "Not a CronJob" in result.message

    def test_cronjob_without_deadline_fails(self):
        """CronJob missing startingDeadlineSeconds must fail (lines 751-758)."""
        manifest = {
            "kind": "CronJob",
            "metadata": {"name": "cleanup"},
            "spec": {
                "schedule": "0 * * * *",
                "jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "job"}]}}}},
            },
        }
        result = check_cronjob_deadline(manifest)
        assert result.passed is False
        assert "startingDeadlineSeconds" in result.message

    def test_cronjob_with_deadline_passes(self):
        """CronJob with startingDeadlineSeconds set must pass (lines 760-765)."""
        manifest = {
            "kind": "CronJob",
            "metadata": {"name": "cleanup"},
            "spec": {
                "schedule": "0 * * * *",
                "startingDeadlineSeconds": 100,
                "jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "job"}]}}}},
            },
        }
        result = check_cronjob_deadline(manifest)
        assert result.passed is True
        assert "100" in result.message


# ---------------------------------------------------------------------------
# TestStableApiVersionDeprecated (line 783)
# ---------------------------------------------------------------------------


class TestStableApiVersionDeprecated:
    def test_deprecated_api_version_fails(self):
        """Deprecated apiVersion must fail (line 783)."""
        manifest = {
            "apiVersion": "extensions/v1beta1",
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {},
        }
        result = check_stable_api_version(manifest)
        assert result.passed is False
        assert "extensions/v1beta1" in result.message

    def test_apps_v1beta1_deprecated(self):
        """apps/v1beta1 is deprecated and must fail."""
        manifest = {
            "apiVersion": "apps/v1beta1",
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {},
        }
        result = check_stable_api_version(manifest)
        assert result.passed is False
        assert "apps/v1beta1" in result.message

    def test_stable_api_version_passes(self):
        """Stable apiVersion (apps/v1) must pass."""
        manifest = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {},
        }
        result = check_stable_api_version(manifest)
        assert result.passed is True
        assert "apps/v1" in result.message

    def test_missing_api_version_passes(self):
        """Missing apiVersion is not in the deprecated set — must pass."""
        manifest = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {}}
        result = check_stable_api_version(manifest)
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestEnvVarDuplicatesBranches (lines 814, 832, 835)
# ---------------------------------------------------------------------------


class TestEnvVarDuplicatesBranches:
    def test_non_workload_skipped(self):
        """ConfigMap is not a workload — env_var_duplicates is skipped (line 814)."""
        manifest = {"kind": "ConfigMap", "metadata": {"name": "cfg"}, "data": {}}
        result = check_env_var_duplicates(manifest)
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_service_skipped(self):
        """Service is not a workload — env_var_duplicates is skipped."""
        manifest = {"kind": "Service", "metadata": {"name": "svc"}, "spec": {}}
        result = check_env_var_duplicates(manifest)
        assert result.passed is True
        assert result.message.endswith("skipped.")

    def test_no_duplicate_env_vars_passes(self):
        """Container with unique env var names must pass."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {
                    "name": "app",
                    "image": "nginx:1.25.3",
                    "env": [
                        {"name": "FOO", "value": "foo"},
                        {"name": "BAR", "value": "bar"},
                    ],
                },
            ]}}},
        }
        result = check_env_var_duplicates(manifest)
        assert result.passed is True
        assert "No duplicate" in result.message

    def test_duplicate_env_var_in_container_fails(self):
        """Container with duplicate env var key must fail (lines 832, 835)."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {
                    "name": "app",
                    "image": "nginx:1.25.3",
                    "env": [
                        {"name": "DATABASE_URL", "value": "postgres://old"},
                        {"name": "DATABASE_URL", "value": "postgres://new"},
                    ],
                },
            ]}}},
        }
        result = check_env_var_duplicates(manifest)
        assert result.passed is False
        assert "DATABASE_URL" in result.message
        assert result.details is not None

    def test_multiple_duplicates_all_reported(self):
        """Both FOO and BAR duplicated must both appear in violation."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {
                    "name": "app",
                    "image": "nginx:1.25.3",
                    "env": [
                        {"name": "FOO", "value": "1"},
                        {"name": "BAR", "value": "1"},
                        {"name": "FOO", "value": "2"},
                        {"name": "BAR", "value": "2"},
                    ],
                },
            ]}}},
        }
        result = check_env_var_duplicates(manifest)
        assert result.passed is False
        assert "FOO" in result.message
        assert "BAR" in result.message

    def test_duplicate_in_one_container_other_clean(self):
        """Only the container with duplicates triggers a violation; the clean one does not."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {
                    "name": "app",
                    "image": "nginx:1.25.3",
                    "env": [
                        {"name": "DUPE", "value": "a"},
                        {"name": "DUPE", "value": "b"},
                    ],
                },
                {
                    "name": "sidecar",
                    "image": "envoy:v1",
                    "env": [
                        {"name": "UNIQUE_KEY", "value": "v"},
                    ],
                },
            ]}}},
        }
        result = check_env_var_duplicates(manifest)
        assert result.passed is False
        assert "app" in result.message
        # sidecar should not appear in the violation message
        assert "sidecar" not in result.message

    def test_no_env_vars_passes(self):
        """Container with no env vars must pass."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3"},
            ]}}},
        }
        result = check_env_var_duplicates(manifest)
        assert result.passed is True
