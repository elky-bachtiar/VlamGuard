"""Tests for new kube-score-inspired policy checks (Phases 2-4)."""

from vlamguard.engine.policies import (
    check_readonly_root_fs,
    check_run_as_user_group,
    check_liveness_readiness_probes,
    check_deployment_strategy,
    check_pod_disruption_budget,
    check_host_pod_anti_affinity,
    check_image_pull_policy,
    check_service_type,
    check_network_policy,
    check_cronjob_deadline,
    check_stable_api_version,
    check_env_var_duplicates,
)


# ---------------------------------------------------------------------------
# Phase 2: Security Checks
# ---------------------------------------------------------------------------


class TestReadOnlyRootFs:
    def test_readonly_true_passes(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "securityContext": {"readOnlyRootFilesystem": True}},
            ]}}},
        }
        result = check_readonly_root_fs(manifest)
        assert result.passed is True

    def test_readonly_false_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "securityContext": {"readOnlyRootFilesystem": False}},
            ]}}},
        }
        result = check_readonly_root_fs(manifest)
        assert result.passed is False

    def test_readonly_missing_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3"},
            ]}}},
        }
        result = check_readonly_root_fs(manifest)
        assert result.passed is False

    def test_configmap_skipped(self):
        manifest = {"kind": "ConfigMap", "metadata": {"name": "cfg"}, "data": {}}
        result = check_readonly_root_fs(manifest)
        assert result.passed is True

    def test_multiple_containers_all_checked(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "securityContext": {"readOnlyRootFilesystem": True}},
                {"name": "sidecar", "image": "envoy:1.28.0", "securityContext": {"readOnlyRootFilesystem": False}},
            ]}}},
        }
        result = check_readonly_root_fs(manifest)
        assert result.passed is False
        assert "sidecar" in result.message


class TestRunAsUserGroup:
    def test_uid_gid_set_passes(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "securityContext": {"runAsUser": 1000, "runAsGroup": 1000}},
            ]}}},
        }
        result = check_run_as_user_group(manifest)
        assert result.passed is True

    def test_root_uid_zero_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "securityContext": {"runAsUser": 0, "runAsGroup": 1000}},
            ]}}},
        }
        result = check_run_as_user_group(manifest)
        assert result.passed is False
        assert "root" in result.message.lower()

    def test_missing_uid_gid_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3"},
            ]}}},
        }
        result = check_run_as_user_group(manifest)
        assert result.passed is False

    def test_pod_level_fallback(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {
                "securityContext": {"runAsUser": 1000, "runAsGroup": 1000},
                "containers": [
                    {"name": "app", "image": "nginx:1.25.3"},
                ],
            }}},
        }
        result = check_run_as_user_group(manifest)
        assert result.passed is True

    def test_container_overrides_pod(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {
                "securityContext": {"runAsUser": 1000, "runAsGroup": 1000},
                "containers": [
                    {"name": "app", "image": "nginx:1.25.3", "securityContext": {"runAsUser": 0, "runAsGroup": 0}},
                ],
            }}},
        }
        result = check_run_as_user_group(manifest)
        assert result.passed is False

    def test_non_workload_skipped(self):
        manifest = {"kind": "Service", "metadata": {"name": "svc"}, "spec": {"ports": [{"port": 80}]}}
        result = check_run_as_user_group(manifest)
        assert result.passed is True


# ---------------------------------------------------------------------------
# Phase 3: Reliability Checks
# ---------------------------------------------------------------------------


class TestLivenessReadinessProbes:
    def test_both_probes_pass(self):
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

    def test_missing_liveness_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {
                    "name": "app",
                    "image": "nginx:1.25.3",
                    "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
                },
            ]}}},
        }
        result = check_liveness_readiness_probes(manifest)
        assert result.passed is False
        assert "livenessProbe" in result.message

    def test_missing_readiness_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {
                    "name": "app",
                    "image": "nginx:1.25.3",
                    "livenessProbe": {"httpGet": {"path": "/healthz", "port": 8080}},
                },
            ]}}},
        }
        result = check_liveness_readiness_probes(manifest)
        assert result.passed is False
        assert "readinessProbe" in result.message

    def test_missing_both_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3"},
            ]}}},
        }
        result = check_liveness_readiness_probes(manifest)
        assert result.passed is False

    def test_non_workload_skipped(self):
        manifest = {"kind": "ConfigMap", "metadata": {"name": "cfg"}, "data": {}}
        result = check_liveness_readiness_probes(manifest)
        assert result.passed is True


class TestDeploymentStrategy:
    def test_rolling_update_passes(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"strategy": {"type": "RollingUpdate"}},
        }
        result = check_deployment_strategy(manifest)
        assert result.passed is True

    def test_default_no_strategy_field_passes(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {},
        }
        result = check_deployment_strategy(manifest)
        assert result.passed is True

    def test_recreate_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"strategy": {"type": "Recreate"}},
        }
        result = check_deployment_strategy(manifest)
        assert result.passed is False
        assert "Recreate" in result.message

    def test_non_deployment_skipped(self):
        manifest = {"kind": "StatefulSet", "metadata": {"name": "db"}, "spec": {}}
        result = check_deployment_strategy(manifest)
        assert result.passed is True


class TestPodDisruptionBudget:
    def test_min_available_passes(self):
        manifest = {
            "kind": "PodDisruptionBudget",
            "metadata": {"name": "web-pdb"},
            "spec": {"minAvailable": 1, "selector": {"matchLabels": {"app": "web"}}},
        }
        result = check_pod_disruption_budget(manifest)
        assert result.passed is True

    def test_max_unavailable_passes(self):
        manifest = {
            "kind": "PodDisruptionBudget",
            "metadata": {"name": "web-pdb"},
            "spec": {"maxUnavailable": 1, "selector": {"matchLabels": {"app": "web"}}},
        }
        result = check_pod_disruption_budget(manifest)
        assert result.passed is True

    def test_empty_spec_fails(self):
        manifest = {
            "kind": "PodDisruptionBudget",
            "metadata": {"name": "web-pdb"},
            "spec": {"selector": {"matchLabels": {"app": "web"}}},
        }
        result = check_pod_disruption_budget(manifest)
        assert result.passed is False

    def test_non_pdb_skipped(self):
        manifest = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {}}
        result = check_pod_disruption_budget(manifest)
        assert result.passed is True


class TestHostPodAntiAffinity:
    def test_configured_passes(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {
                "replicas": 3,
                "template": {"spec": {
                    "affinity": {
                        "podAntiAffinity": {
                            "preferredDuringSchedulingIgnoredDuringExecution": [],
                        },
                    },
                    "containers": [{"name": "app", "image": "nginx:1.25.3"}],
                }},
            },
        }
        result = check_host_pod_anti_affinity(manifest)
        assert result.passed is True

    def test_multi_replica_no_affinity_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {
                "replicas": 3,
                "template": {"spec": {
                    "containers": [{"name": "app", "image": "nginx:1.25.3"}],
                }},
            },
        }
        result = check_host_pod_anti_affinity(manifest)
        assert result.passed is False

    def test_single_replica_ok(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {
                "replicas": 1,
                "template": {"spec": {
                    "containers": [{"name": "app", "image": "nginx:1.25.3"}],
                }},
            },
        }
        result = check_host_pod_anti_affinity(manifest)
        assert result.passed is True

    def test_non_scalable_skipped(self):
        manifest = {"kind": "Job", "metadata": {"name": "batch"}, "spec": {}}
        result = check_host_pod_anti_affinity(manifest)
        assert result.passed is True


# ---------------------------------------------------------------------------
# Phase 4: Best Practice Checks
# ---------------------------------------------------------------------------


class TestImagePullPolicy:
    def test_always_passes(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3", "imagePullPolicy": "Always"},
            ]}}},
        }
        result = check_image_pull_policy(manifest)
        assert result.passed is True

    def test_if_not_present_fails(self):
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

    def test_missing_policy_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3"},
            ]}}},
        }
        result = check_image_pull_policy(manifest)
        assert result.passed is False

    def test_non_workload_skipped(self):
        manifest = {"kind": "ConfigMap", "metadata": {"name": "cfg"}, "data": {}}
        result = check_image_pull_policy(manifest)
        assert result.passed is True


class TestServiceType:
    def test_clusterip_passes(self):
        manifest = {
            "kind": "Service",
            "metadata": {"name": "svc"},
            "spec": {"type": "ClusterIP", "ports": [{"port": 80}]},
        }
        result = check_service_type(manifest)
        assert result.passed is True

    def test_default_no_type_passes(self):
        manifest = {
            "kind": "Service",
            "metadata": {"name": "svc"},
            "spec": {"ports": [{"port": 80}]},
        }
        result = check_service_type(manifest)
        assert result.passed is True

    def test_loadbalancer_passes(self):
        manifest = {
            "kind": "Service",
            "metadata": {"name": "svc"},
            "spec": {"type": "LoadBalancer", "ports": [{"port": 80}]},
        }
        result = check_service_type(manifest)
        assert result.passed is True

    def test_nodeport_fails(self):
        manifest = {
            "kind": "Service",
            "metadata": {"name": "svc"},
            "spec": {"type": "NodePort", "ports": [{"port": 80, "nodePort": 30080}]},
        }
        result = check_service_type(manifest)
        assert result.passed is False
        assert "NodePort" in result.message

    def test_non_service_skipped(self):
        manifest = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {}}
        result = check_service_type(manifest)
        assert result.passed is True


class TestNetworkPolicy:
    def test_valid_policy_passes(self):
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

    def test_egress_only_passes(self):
        manifest = {
            "kind": "NetworkPolicy",
            "metadata": {"name": "allow-egress"},
            "spec": {
                "podSelector": {"matchLabels": {"app": "web"}},
                "egress": [{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}],
            },
        }
        result = check_network_policy(manifest)
        assert result.passed is True

    def test_no_rules_fails(self):
        manifest = {
            "kind": "NetworkPolicy",
            "metadata": {"name": "empty"},
            "spec": {
                "podSelector": {"matchLabels": {"app": "web"}},
            },
        }
        result = check_network_policy(manifest)
        assert result.passed is False

    def test_missing_pod_selector_fails(self):
        manifest = {
            "kind": "NetworkPolicy",
            "metadata": {"name": "bad"},
            "spec": {
                "ingress": [{"from": [{"podSelector": {}}]}],
            },
        }
        result = check_network_policy(manifest)
        assert result.passed is False
        assert "podSelector" in result.message

    def test_non_network_policy_skipped(self):
        manifest = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {}}
        result = check_network_policy(manifest)
        assert result.passed is True


class TestCronJobDeadline:
    def test_deadline_set_passes(self):
        manifest = {
            "kind": "CronJob",
            "metadata": {"name": "cleanup"},
            "spec": {
                "schedule": "0 2 * * *",
                "startingDeadlineSeconds": 200,
                "jobTemplate": {"spec": {"template": {"spec": {"containers": []}}}},
            },
        }
        result = check_cronjob_deadline(manifest)
        assert result.passed is True

    def test_no_deadline_fails(self):
        manifest = {
            "kind": "CronJob",
            "metadata": {"name": "cleanup"},
            "spec": {
                "schedule": "0 2 * * *",
                "jobTemplate": {"spec": {"template": {"spec": {"containers": []}}}},
            },
        }
        result = check_cronjob_deadline(manifest)
        assert result.passed is False

    def test_non_cronjob_skipped(self):
        manifest = {"kind": "Job", "metadata": {"name": "once"}, "spec": {}}
        result = check_cronjob_deadline(manifest)
        assert result.passed is True


class TestStableApiVersion:
    def test_stable_version_passes(self):
        manifest = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"}}
        result = check_stable_api_version(manifest)
        assert result.passed is True

    def test_v1_passes(self):
        manifest = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "svc"}}
        result = check_stable_api_version(manifest)
        assert result.passed is True

    def test_extensions_v1beta1_fails(self):
        manifest = {"apiVersion": "extensions/v1beta1", "kind": "Deployment", "metadata": {"name": "web"}}
        result = check_stable_api_version(manifest)
        assert result.passed is False
        assert "extensions/v1beta1" in result.message

    def test_apps_v1beta2_fails(self):
        manifest = {"apiVersion": "apps/v1beta2", "kind": "Deployment", "metadata": {"name": "web"}}
        result = check_stable_api_version(manifest)
        assert result.passed is False


class TestEnvVarDuplicates:
    def test_unique_vars_passes(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {
                    "name": "app",
                    "image": "nginx:1.25.3",
                    "env": [
                        {"name": "APP_ENV", "value": "prod"},
                        {"name": "LOG_LEVEL", "value": "info"},
                    ],
                },
            ]}}},
        }
        result = check_env_var_duplicates(manifest)
        assert result.passed is True

    def test_duplicate_var_fails(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {
                    "name": "app",
                    "image": "nginx:1.25.3",
                    "env": [
                        {"name": "APP_ENV", "value": "prod"},
                        {"name": "APP_ENV", "value": "staging"},
                    ],
                },
            ]}}},
        }
        result = check_env_var_duplicates(manifest)
        assert result.passed is False
        assert "APP_ENV" in result.message

    def test_no_env_passes(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "image": "nginx:1.25.3"},
            ]}}},
        }
        result = check_env_var_duplicates(manifest)
        assert result.passed is True

    def test_non_workload_skipped(self):
        manifest = {"kind": "ConfigMap", "metadata": {"name": "cfg"}, "data": {}}
        result = check_env_var_duplicates(manifest)
        assert result.passed is True
