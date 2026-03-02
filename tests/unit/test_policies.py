"""Tests for the 5 deterministic policy checks."""

import pytest

from vlamguard.engine.policies import (
    check_image_tag,
    check_rbac_scope,
    check_replica_count,
    check_resource_limits,
    check_security_context,
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
